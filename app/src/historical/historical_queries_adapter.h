// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include "http_error.h"
#include "lru.h"
#include "tracing.h"

#include <ccf/endpoint_context.h>
#include <ccf/historical_queries_adapter.h>
#include <ccf/http_consts.h>
#include <ccf/json_handler.h>
#include <ccf/odata_error.h>
#include <ccf/rpc_context.h>
#include <ccf/tx_id.h>
#include <mutex>

// Custom version of CCF's historical query adapter that cleans old cached
// states to avoid memory exhaustion using a simple LRU cache. See
// https://github.com/microsoft/CCF/blob/main/src/node/historical_queries_adapter.cpp
// for the original.
//
// It is also adapted to match the rest of the SCITT code base, eg. uses
// exceptions to return HTTP errors.

namespace scitt::historical
{
  using ccf::endpoints::EndpointContext;
  using ccf::endpoints::EndpointFunction;
  using ccf::historical::AbstractStateCache;
  using ccf::historical::CheckHistoricalTxStatus;
  using ccf::historical::HandleHistoricalQuery;
  using ccf::historical::HistoricalTxStatus;
  using ccf::historical::StatePtr;

  // CCF defines a version, but makes it return std::optional instead of using
  // exceptions.
  using TxIDExtractor = std::function<ccf::TxID(EndpointContext& args)>;
  using ActiveHandlesLRU = LRU<ccf::SeqNo, bool>;

  // TODO: move this to constants.h and describe how it influences memory
  // consumption
  constexpr size_t MAX_ACTIVE_HANDLES = 100;
  static ActiveHandlesLRU ACTIVE_HANDLES_LRU(MAX_ACTIVE_HANDLES);
  static std::mutex ACTIVE_HANDLES_MUTEX;

  ccf::TxID get_tx_id_from_request_path(EndpointContext& ctx)
  {
    auto tx_id_str = ctx.rpc_ctx->get_request_path_params().at("txid");

    const auto tx_id = ccf::TxID::from_str(tx_id_str);
    if (!tx_id.has_value())
    {
      throw BadRequestError(
        errors::InvalidInput,
        fmt::format("Invalid transaction ID: {}", tx_id_str));
    }
    return tx_id.value();
  }

  StatePtr get_historical_state(
    AbstractStateCache& state_cache,
    const CheckHistoricalTxStatus& available,
    const TxIDExtractor& extractor,
    EndpointContext& ctx)
  {
    // Extract the requested transaction ID
    ccf::TxID target_tx_id = extractor(ctx);

    // Check that the requested transaction ID is available
    {
      auto error_reason =
        fmt::format("Transaction {} is not available.", target_tx_id.to_str());
      auto is_available =
        available(target_tx_id.view, target_tx_id.seqno, error_reason);
      switch (is_available)
      {
        case HistoricalTxStatus::Error:
        {
          throw InternalServerError(
            ccf::errors::InternalError, std::move(error_reason));
        }
        case HistoricalTxStatus::PendingOrUnknown:
        {
          throw ServiceUnavailableError(
            ccf::errors::TransactionPendingOrUnknown, std::move(error_reason));
        }
        case HistoricalTxStatus::Invalid:
        {
          throw NotFoundError(
            ccf::errors::TransactionInvalid, std::move(error_reason));
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

    StatePtr historical_state;
    {
      std::unique_lock<std::mutex> guard(ACTIVE_HANDLES_MUTEX);
      ACTIVE_HANDLES_LRU.set_cull_callback(
        [&state_cache](ccf::SeqNo key, bool) {
          SCITT_INFO("Dropping cached transaction {}", key);
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
      constexpr uint32_t retry_after_seconds = 1;
      throw ServiceUnavailableError(
        errors::TransactionNotCached,
        fmt::format(
          "Historical transaction {} is not cached.", target_tx_id.to_str()),
        retry_after_seconds);
    }

    return historical_state;
  }

  EndpointFunction adapter(
    const HandleHistoricalQuery& f,
    AbstractStateCache& state_cache,
    const CheckHistoricalTxStatus& available,
    const TxIDExtractor& extractor = get_tx_id_from_request_path)
  {
    return [f, &state_cache, available, extractor](EndpointContext& ctx) {
      auto state = get_historical_state(state_cache, available, extractor, ctx);
      f(ctx, state);
    };
  }

  using HandleJsonHistoricalQuery =
    std::function<ccf::jsonhandler::JsonAdapterResponse(
      EndpointContext& args, StatePtr state, nlohmann::json&& params)>;

  /**
   * A combination of ccf::json_adapter and historical::adapter.
   *
   * Because the signatures are incompatible, the two adapaters don't natively
   * compose. This combined adapter may be used instead.
   */
  EndpointFunction json_adapter(
    const HandleJsonHistoricalQuery& f,
    AbstractStateCache& state_cache,
    const CheckHistoricalTxStatus& available,
    const TxIDExtractor& extractor = get_tx_id_from_request_path)
  {
    return ccf::json_adapter([f, &state_cache, available, extractor](
                               EndpointContext& ctx, nlohmann::json&& params) {
      auto state = get_historical_state(state_cache, available, extractor, ctx);
      return f(ctx, state, std::move(params));
    });
  }
}
