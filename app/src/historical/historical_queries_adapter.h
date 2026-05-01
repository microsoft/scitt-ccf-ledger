// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include "constants.h"
#include "http_error.h"
#include "tracing.h"
#include "util.h"

#include <ccf/endpoint_context.h>
#include <ccf/historical_queries_adapter.h>
#include <ccf/http_consts.h>
#include <ccf/http_query.h>
#include <ccf/json_handler.h>
#include <ccf/odata_error.h>
#include <ccf/rpc_context.h>
#include <ccf/tx_id.h>

// Custom version of CCF's historical query adapter.
// Adapted to match the rest of the SCITT code base, eg. uses
// exceptions to return HTTP errors.
//
// Cache eviction is handled by CCF's historical_cache_soft_limit node
// configuration option. See the CCF documentation for details.

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
      throw ServiceUnavailableCborError(
        errors::TransactionNotCached,
        fmt::format(
          "Historical transaction {} is not cached.", target_tx_id.to_str()));
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

  /**
   * A variant of entry_adapter that returns 302 Found instead of 503
   * when the transaction is pending or not yet cached, per SCRAPI v09
   * section 2.4.1. This is used for the GET /entries/{txid} endpoint
   * to support polling-based registration status queries.
   *
   * When the transaction is ready, the handler is called as normal and
   * returns 200 OK with the receipt (section 2.4.2 / 2.5.1).
   */
  static EndpointFunction entry_adapter_with_polling(
    const HandleHistoricalQuery& f,
    AbstractStateCache& state_cache,
    const CheckHistoricalTxStatus& available)
  {
    return [f, &state_cache, available](EndpointContext& ctx) {
      try
      {
        auto state = get_historical_entry_state(state_cache, available, ctx);
        f(ctx, state);
      }
      catch (const ServiceUnavailableCborError&)
      {
        // Transaction is pending or not yet cached.
        // Check api-version to decide response style.
        bool scrapi = is_scrapi_api_version(ctx);

        if (scrapi)
        {
          // SCRAPI v09 section 2.4.1: return 302 Found with Location
          // pointing to the same URL, so the client can retry.
          auto tx_id_str = ctx.rpc_ctx->get_request_path_params().at("txid");
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_FOUND);
          if (
            auto host =
              ctx.rpc_ctx->get_request_header(ccf::http::headers::HOST))
          {
            ctx.rpc_ctx->set_response_header(
              ccf::http::headers::LOCATION,
              fmt::format("https://{}/entries/{}", host.value(), tx_id_str));
          }
        }
        else
        {
          // Legacy clients expect 503 Service Unavailable.
          throw;
        }
      }
    };
  }
}