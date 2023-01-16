// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "lru.h"

#include <ccf/endpoint_context.h>
#include <ccf/historical_queries_adapter.h>
#include <ccf/http_consts.h>
#include <ccf/odata_error.h>
#include <ccf/rpc_context.h>
#include <ccf/tx_id.h>
#include <mutex>

// Custom version of CCF's historical query adapter that cleans old cached
// states to avoid memory exhaustion using a simple LRU cache. See
// https://github.com/microsoft/CCF/blob/main/src/node/historical_queries_adapter.cpp
// for the original.

namespace scitt::historical
{
  using ccf::endpoints::EndpointContext;
  using ccf::endpoints::EndpointFunction;
  using ccf::historical::AbstractStateCache;
  using ccf::historical::CheckHistoricalTxStatus;
  using ccf::historical::HandleHistoricalQuery;
  using ccf::historical::HistoricalTxStatus;
  using ccf::historical::TxIDExtractor;

  using ActiveHandlesLRU = LRU<ccf::SeqNo, bool>;

  // TODO: move this to constants.h and describe how it influences memory
  // consumption
  constexpr size_t MAX_ACTIVE_HANDLES = 100;
  static ActiveHandlesLRU ACTIVE_HANDLES_LRU(MAX_ACTIVE_HANDLES);
  static std::mutex ACTIVE_HANDLES_MUTEX;

  EndpointFunction adapter(
    const HandleHistoricalQuery& f,
    AbstractStateCache& state_cache,
    const CheckHistoricalTxStatus& available,
    const TxIDExtractor& extractor)
  {
    return [f, &state_cache, available, extractor](EndpointContext& args) {
      // Extract the requested transaction ID
      ccf::TxID target_tx_id;
      {
        const auto tx_id_opt = extractor(args);
        if (tx_id_opt.has_value())
        {
          target_tx_id = tx_id_opt.value();
        }
        else
        {
          return;
        }
      }

      // Check that the requested transaction ID is available
      {
        auto error_reason = fmt::format(
          "Transaction {} is not available.", target_tx_id.to_str());
        auto is_available =
          available(target_tx_id.view, target_tx_id.seqno, error_reason);
        switch (is_available)
        {
          case HistoricalTxStatus::Error:
          {
            args.rpc_ctx->set_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::TransactionPendingOrUnknown,
              std::move(error_reason));
            return;
          }
          case HistoricalTxStatus::PendingOrUnknown:
          {
            // Set header No-Cache
            args.rpc_ctx->set_response_header(
              http::headers::CACHE_CONTROL, "no-cache");
            args.rpc_ctx->set_error(
              HTTP_STATUS_NOT_FOUND,
              ccf::errors::TransactionPendingOrUnknown,
              std::move(error_reason));
            return;
          }
          case HistoricalTxStatus::Invalid:
          {
            args.rpc_ctx->set_error(
              HTTP_STATUS_NOT_FOUND,
              ccf::errors::TransactionInvalid,
              std::move(error_reason));
            return;
          }
          case HistoricalTxStatus::Valid:
          {
          }
        }
      }

      // We need a handle to determine whether this request is the 'same' as a
      // previous one. For simplicity we use target_tx_id.seqno. This means we
      // keep a lot of state around for old requests! It should be cleaned up
      // manually
      const auto historic_request_handle = target_tx_id.seqno;

      ccf::historical::StatePtr historical_state;

      {
        std::unique_lock<std::mutex> guard(ACTIVE_HANDLES_MUTEX);
        ACTIVE_HANDLES_LRU.set_cull_callback(
          [&state_cache](ccf::SeqNo key, bool) {
            CCF_APP_TRACE("Culling state cache handle {}", key);
            state_cache.drop_cached_states(key);
          });
        ACTIVE_HANDLES_LRU.insert(historic_request_handle, true);

        // Get a state at the target version from the cache, if it is present.
        // Note that this must be within the mutex lock, otherwise in busy
        // situations state may be dropped before it was requested.
        historical_state =
          state_cache.get_state_at(historic_request_handle, target_tx_id.seqno);
      }

      if (historical_state == nullptr)
      {
        args.rpc_ctx->set_response_status(HTTP_STATUS_ACCEPTED);
        constexpr size_t retry_after_seconds = 1;
        args.rpc_ctx->set_response_header(
          http::headers::RETRY_AFTER, retry_after_seconds);
        args.rpc_ctx->set_response_header(
          http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
        args.rpc_ctx->set_response_body(fmt::format(
          "Historical transaction {} is not currently available.",
          target_tx_id.to_str()));
        return;
      }

      // Call the provided handler
      f(args, historical_state);
    };
  }

}