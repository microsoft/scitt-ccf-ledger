// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "call_types.h"
#include "constants.h"
#include "http_error.h"
#include "tracing.h"
#include "util.h"

#include <ccf/base_endpoint_registry.h>
#include <ccf/endpoint_context.h>
#include <ccf/http_consts.h>
#include <ccf/odata_error.h>
#include <ccf/tx_id.h>
#include <ccf/tx_status.h>
#include <string>

namespace scitt
{
  /**
   * Look up the status of the operation started by POST /entries.
   *
   * The operation ID is the transaction ID of the registration, so the status
   * follows from the transaction's commit status and no index is needed: the
   * operation is running until the transaction commits, and then it has
   * succeeded with an entry of the same ID. Without an index, a registration
   * can't be told apart from other transactions, so any committed transaction
   * ID is reported as succeeded; GET /entries/{txid} rejects IDs that aren't
   * entries.
   */
  static GetOperation::Out get_operation(
    ccf::BaseEndpointRegistry& registry, const ccf::TxID& operation_id)
  {
    ccf::TxStatus tx_status;
    auto result = registry.get_status_for_txid_v1(
      operation_id.view, operation_id.seqno, tx_status);
    if (result != ccf::ApiResult::OK)
    {
      throw InternalCborError(fmt::format(
        "Failed to get transaction status: {}",
        ccf::api_result_to_str(result)));
    }

    switch (tx_status)
    {
      case ccf::TxStatus::Unknown:
      case ccf::TxStatus::Pending:
        return {
          .operation_id = operation_id,
          .status = OperationStatus::Running,
          .entry_id = {},
          .error = {}};

      case ccf::TxStatus::Invalid:
        // This state can arise even in a well-behaved client if the view
        // changed (eg. because of a Raft election), and the operation's
        // transaction got dropped. It could also be a client giving us
        // garbage txids, but we can't tell the difference so we remain polite
        // and assume the former and say the operation has failed.
        return {
          .operation_id = operation_id,
          .status = OperationStatus::Failed,
          .entry_id = {},
          .error =
            ODataError{
              .code = ccf::errors::TransactionInvalid,
              .message = "Transaction is invalid",
            },
        };

      case ccf::TxStatus::Committed:
        return {
          .operation_id = operation_id,
          .status = OperationStatus::Succeeded,
          .entry_id = operation_id,
          .error = {}};
    }

    throw InternalCborError("Unexpected transaction status");
  }

  /**
   * GET /operations/{txid} is deprecated in SCRAPI v09 but kept for clients
   * of the legacy registration flow, which poll it after POST /entries
   * answers 202 Accepted.
   */
  static void register_operations_endpoints(
    ccf::BaseEndpointRegistry& registry, const ccf::AuthnPolicies& authn_policy)
  {
    auto get_op_with_status = [&registry](
                                ccf::endpoints::EndpointContext& ctx) {
      auto tx_id_str = ctx.rpc_ctx->get_request_path_params().at("txid");
      const auto tx_id = ccf::TxID::from_str(tx_id_str);
      if (!tx_id.has_value())
      {
        throw BadRequestCborError(
          errors::InvalidInput,
          fmt::format("Invalid Operation ID: {}", tx_id_str));
      }

      auto operation = get_operation(registry, tx_id.value());
      if (operation.status == OperationStatus::Running)
      {
        ctx.rpc_ctx->set_response_status(HTTP_STATUS_ACCEPTED);
      }
      else
      {
        std::optional<std::string> host =
          ctx.rpc_ctx->get_request_header(ccf::http::headers::HOST);
        if (
          host.has_value() && operation.status == OperationStatus::Succeeded &&
          operation.entry_id.has_value())
        {
          ctx.rpc_ctx->set_response_header(
            ccf::http::headers::LOCATION,
            fmt::format(
              "https://{}/entries/{}",
              host.value(),
              operation.entry_id.value().to_str()));
        }

        ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        ctx.rpc_ctx->set_response_header(
          ccf::http::headers::CONTENT_TYPE,
          ccf::http::headervalues::contenttype::CBOR);
        ctx.rpc_ctx->set_response_body(operation_to_cbor(operation));
      }
    };

    /**
     * Check Registration, 2.1.3 in
     * https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi/
     */
    registry
      .make_endpoint(
        "/operations/{txid}", HTTP_GET, get_op_with_status, authn_policy)
      .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
      .set_redirection_strategy(ccf::endpoints::RedirectionStrategy::None)
      .install();
  }

  /**
   * Local commit handler for POST /entries.
   *
   * The endpoint handler doesn't have access to its transaction ID, and
   * therefore cannot generate a useful response. This function is therefore
   * necessary to inform the client of the transaction ID.
   *
   * Note that if the endpoint handler failed and set a non-2xx HTTP status
   * code, CCF doesn't apply any of the writes and doesn't call this function.
   * In this case, it is assumed the handler has set a response body when it set
   * the erroneous status code.
   *
   * Per SCRAPI v09 section 2.3.2, async registration returns 303 See Other
   * with Location pointing to /entries/{txid}.
   *
   * For backward compatibility with legacy clients (eg. .NET SDK) that expect
   * 202 Accepted with a CBOR body: if the request does not include
   * api-version=2026-03-26, the old 202 + CBOR response is
   * returned with Location: /operations/{txid}.
   */
  static void operation_locally_committed_func(
    ccf::endpoints::CommandEndpointContext& ctx, const ccf::TxID& tx_id)
  {
    std::string tx_str = tx_id.to_str();
    SCITT_TRACE("New operation was locally committed with tx={}", tx_str);

    ctx.rpc_ctx->set_response_header(ccf::http::headers::CCF_TX_ID, tx_str);

    // Check if the client requested SCRAPI v09 behavior via api-version.
    bool scrapi = is_scrapi_v9(ctx);

    if (!scrapi)
    {
      // Legacy flow: 202 Accepted with CBOR body and Location: /operations/
      GetOperation::Out operation{
        .operation_id = tx_id,
        .status = OperationStatus::Running,
        .entry_id = {},
        .error = {}};

      ctx.rpc_ctx->set_response_header(
        ccf::http::headers::CONTENT_TYPE,
        ccf::http::headervalues::contenttype::CBOR);
      ctx.rpc_ctx->set_response_body(operation_to_cbor(operation));
      ctx.rpc_ctx->set_response_status(HTTP_STATUS_ACCEPTED);

      if (auto host = ctx.rpc_ctx->get_request_header(ccf::http::headers::HOST))
      {
        ctx.rpc_ctx->set_response_header(
          ccf::http::headers::LOCATION,
          fmt::format("https://{}/operations/{}", *host, tx_str));
      }
    }
    else
    {
      // SCRAPI v09 2.3.2: 303 See Other with Location: /entries/{txid}
      if (auto host = ctx.rpc_ctx->get_request_header(ccf::http::headers::HOST))
      {
        ctx.rpc_ctx->set_response_header(
          ccf::http::headers::LOCATION,
          fmt::format("https://{}/entries/{}", *host, tx_str));
      }

      ctx.rpc_ctx->set_response_status(HTTP_STATUS_SEE_OTHER);
    }
  }
}
