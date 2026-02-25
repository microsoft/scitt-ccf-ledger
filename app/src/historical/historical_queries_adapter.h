// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include "http_error.h"
#include "tracing.h"

#include <ccf/endpoint_context.h>
#include <ccf/historical_queries_adapter.h>
#include <ccf/http_consts.h>
#include <ccf/json_handler.h>
#include <ccf/odata_error.h>
#include <ccf/rpc_context.h>
#include <ccf/tx_id.h>

// Custom version of CCF's historical query adapter.
// Adapted to match the rest of the SCITT code base, eg. uses
// exceptions to return HTTP errors.
//
// Cache eviction is handled by CCF's set_soft_cache_limit(), which should be
// called during initialization.

namespace scitt::historical
{
  using ccf::endpoints::EndpointContext;
  using ccf::endpoints::EndpointFunction;
  using ccf::historical::AbstractStateCache;
  using ccf::historical::CheckHistoricalTxStatus;
  using ccf::historical::HandleHistoricalQuery;
  using ccf::historical::HistoricalTxStatus;
  using ccf::historical::StatePtr;

  static StatePtr get_historical_entry_state(
    AbstractStateCache& state_cache,
    const CheckHistoricalTxStatus& available,
    EndpointContext& ctx)
  {
    // Extract the requested transaction ID
    auto tx_id_str = ctx.rpc_ctx->get_request_path_params().at("txid");
    const auto tx_id = ccf::TxID::from_str(tx_id_str);
    if (!tx_id.has_value())
    {
      throw BadRequestCborError(
        errors::InvalidInput,
        fmt::format("Invalid transaction ID: {}", tx_id_str));
    }
    ccf::TxID target_tx_id = tx_id.value();

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
          throw InternalCborError(std::move(error_reason));
        }
        case HistoricalTxStatus::PendingOrUnknown:
        {
          throw ServiceUnavailableCborError(
            ccf::errors::TransactionPendingOrUnknown, std::move(error_reason));
        }
        case HistoricalTxStatus::Invalid:
        {
          throw NotFoundCborError(
            ccf::errors::TransactionInvalid, std::move(error_reason));
        }
        case HistoricalTxStatus::Valid:
        {
        }
      }
    }

    // We need a handle to determine whether this request is the 'same' as a
    // previous one. For simplicity we use target_tx_id.seqno.
    const auto historic_request_handle = target_tx_id.seqno;

    auto historical_state =
      state_cache.get_state_at(historic_request_handle, target_tx_id.seqno);

    if (historical_state == nullptr)
    {
      constexpr uint32_t retry_after_seconds = 1;
      throw ServiceUnavailableCborError(
        errors::TransactionNotCached,
        fmt::format(
          "Historical transaction {} is not cached.", target_tx_id.to_str()),
        retry_after_seconds);
    }

    return historical_state;
  }

  static EndpointFunction entry_adapter(
    const HandleHistoricalQuery& f,
    AbstractStateCache& state_cache,
    const CheckHistoricalTxStatus& available)
  {
    return [f, &state_cache, available](EndpointContext& ctx) {
      auto state = get_historical_entry_state(state_cache, available, ctx);
      f(ctx, state);
    };
  }
}
