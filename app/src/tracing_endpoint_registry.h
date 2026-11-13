// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "tracing.h"

#include <ccf/app_interface.h>

namespace scitt
{
  class TracingEndpointRegistry : public ccf::UserEndpointRegistry
  {
  public:
    using ccf::UserEndpointRegistry::UserEndpointRegistry;

    ccf::endpoints::EndpointDefinitionPtr find_endpoint(
      ccf::kv::Tx& tx, ccf::RpcContext& rpc_ctx) override
    {
      begin_request_tracing(rpc_ctx, [this](timespec& time) {
        return get_untrusted_host_time_v1(time);
      });
      try
      {
        return ccf::UserEndpointRegistry::find_endpoint(tx, rpc_ctx);
      }
      catch (...)
      {
        finish_request_tracing(HTTP_STATUS_INTERNAL_SERVER_ERROR);
        throw;
      }
    }

    std::set<ccf::RESTVerb> get_allowed_verbs(
      ccf::kv::Tx& tx, const ccf::RpcContext& rpc_ctx) override
    {
      try
      {
        return ccf::UserEndpointRegistry::get_allowed_verbs(tx, rpc_ctx);
      }
      catch (...)
      {
        finish_request_tracing(HTTP_STATUS_INTERNAL_SERVER_ERROR);
        throw;
      }
    }

    void execute_endpoint(
      ccf::endpoints::EndpointDefinitionPtr endpoint,
      ccf::endpoints::EndpointContext& ctx) override
    {
      if (const auto scope = get_request_scope(*ctx.rpc_ctx))
      {
        scope->executed_locally = true;
      }
      ccf::UserEndpointRegistry::execute_endpoint(endpoint, ctx);
    }

    void execute_endpoint_locally_committed(
      ccf::endpoints::EndpointDefinitionPtr endpoint,
      ccf::endpoints::CommandEndpointContext& ctx,
      const ccf::TxID& tx_id) override
    {
      const auto scope = get_request_scope(*ctx.rpc_ctx);
      const ScopedTracingContext correlation(scope);
      if (scope != nullptr)
      {
        scope->locally_committed(
          tx_id, ctx.rpc_ctx->get_session_context()->is_forwarded);
      }
      ccf::UserEndpointRegistry::execute_endpoint_locally_committed(
        endpoint, ctx, tx_id);
    }

    void handle_event_request_completed(
      const ccf::endpoints::RequestCompletedEvent& event) override
    {
      if (get_request_scope() == nullptr)
      {
        CCF_APP_INFO(
          "RequestCompletedEvent: status={}, scope=unavailable", event.status);
        return;
      }
      finish_request_tracing(event.status);
    }

    void handle_event_dispatch_failed(
      const ccf::endpoints::DispatchFailedEvent& event) override
    {
      if (get_request_scope() == nullptr)
      {
        CCF_APP_INFO(
          "DispatchFailedEvent: {} {}",
          escape_log_field(event.method, MAX_LOGGED_PATH),
          event.status);
        return;
      }
      finish_request_tracing(event.status, false);
    }
  };
}
