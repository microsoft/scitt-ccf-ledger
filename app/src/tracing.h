// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "constants.h"

#include <ccf/base_endpoint_registry.h>
#include <ccf/endpoint_context.h>
#include <functional>
#include <regex>
#include <sstream>
#include <time.h>

namespace scitt
{
  constexpr std::string_view REQUEST_ID_HEADER = "x-ms-request-id";
  constexpr std::string_view CLIENT_REQUEST_ID_HEADER =
    "x-ms-client-request-id";

  const std::regex CLIENT_REQUEST_ID_REGEX("^[0-9a-zA-Z-]+");

  thread_local std::string request_id;
  thread_local std::optional<std::string> client_request_id;

  struct AppData
  {
    std::string request_id;
    std::optional<std::string> client_request_id;
  };

  void clear_trace_state()
  {
    request_id = "";
    client_request_id = std::nullopt;
  }

  int diff_timespec_ms(
    const struct timespec& time0, const struct timespec& time1)
  {
    return (time1.tv_sec - time0.tv_sec) * 1000 +
      (time1.tv_nsec - time0.tv_nsec) / 1000000;
  }

  std::string create_request_id()
  {
    return fmt::format("{:x}", rand());
  }

#define SCITT_INFO(s, ...) \
  if (client_request_id.has_value()) \
    CCF_APP_INFO( \
      "ClientRequestId={} RequestId={} " s, \
      client_request_id.value(), \
      request_id, \
      ##__VA_ARGS__); \
  else \
    CCF_APP_INFO("RequestId={} " s, request_id, ##__VA_ARGS__)

#define SCITT_FAIL(s, ...) \
  if (client_request_id.has_value()) \
    CCF_APP_FAIL( \
      "ClientRequestId={} RequestId={} " s, \
      client_request_id.value(), \
      request_id, \
      ##__VA_ARGS__); \
  else \
    CCF_APP_FAIL("RequestId={} " s, request_id, ##__VA_ARGS__)

  template <typename Fn, typename Ctx>
  Fn generic_tracing_adapter(
    Fn fn,
    const std::string& method,
    const std::function<ccf::ApiResult(::timespec& time)>& get_time)
  {
    return [fn, method, get_time](Ctx& ctx) {
      auto cleanup = finally(clear_trace_state);

      request_id = create_request_id();
      ctx.rpc_ctx->set_response_header(REQUEST_ID_HEADER, request_id);

      client_request_id =
        ctx.rpc_ctx->get_request_header(CLIENT_REQUEST_ID_HEADER);

      if (client_request_id.has_value())
      {
        // Validate client request id to avoid misinterpretation of the log,
        // e.g. if it contains a space.
        if (!std::regex_match(
              client_request_id.value(), CLIENT_REQUEST_ID_REGEX))
        {
          client_request_id = std::nullopt;
          SCITT_INFO("Code=InvalidInput Invalid client request id");
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_BAD_REQUEST,
            errors::InvalidInput,
            "Invalid client request id.");
          return;
        }
        ctx.rpc_ctx->set_response_header(
          "x-ms-client-request-id", client_request_id.value());
      }

      // The user data is used to propagate the request IDs to the local commit
      // callback
      ctx.rpc_ctx->set_user_data(
        std::make_shared<AppData>(AppData{request_id, client_request_id}));

      auto query = ctx.rpc_ctx->get_request_query();

      SCITT_INFO(
        "Verb={} Path={} URL={}",
        ctx.rpc_ctx->get_request_verb().c_str(),
        method,
        ctx.rpc_ctx->get_request_url());

      ::timespec start;
      ccf::ApiResult result = get_time(start);
      if (result != ccf::ApiResult::OK)
      {
        SCITT_FAIL("Code=InternalError get_untrusted_host_time_v1 failed");
        ctx.rpc_ctx->set_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          errors::InternalError,
          "Failed to get time.");
        return;
      }

      fn(ctx);

      ::timespec end;
      result = get_time(end);
      if (result != ccf::ApiResult::OK)
      {
        SCITT_FAIL("Code=InternalError get_untrusted_host_time_v1 failed");
        ctx.rpc_ctx->set_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          errors::InternalError,
          "Failed to get time.");
        return;
      }

      auto duration_ms = diff_timespec_ms(start, end);

      SCITT_INFO(
        "Verb={} Path={} URL={} Status={} TimeMs={}",
        ctx.rpc_ctx->get_request_verb().c_str(),
        method,
        ctx.rpc_ctx->get_request_url(),
        ctx.rpc_ctx->get_response_status(),
        duration_ms);
    };
  }

  void tracing_local_commit_callback(
    ccf::endpoints::CommandEndpointContext& ctx, const ccf::TxID& txid)
  {
    auto cleanup = finally(clear_trace_state);

    auto user_data = static_cast<AppData*>(ctx.rpc_ctx->get_user_data());
    if (user_data != nullptr)
    {
      request_id = user_data->request_id;
      client_request_id = user_data->client_request_id;
    }

    SCITT_INFO("TxId={}", txid.to_str());

    ccf::endpoints::default_locally_committed_func(ctx, txid);
  }

  /**
   * Create an adapter around an existing EndpointFunction to handle tracing.
   */
  ccf::endpoints::EndpointFunction tracing_adapter(
    ccf::endpoints::EndpointFunction fn,
    const std::string& method,
    const std::function<ccf::ApiResult(::timespec& time)>& get_time)
  {
    return generic_tracing_adapter<
      ccf::endpoints::EndpointFunction,
      ccf::endpoints::EndpointContext>(fn, method, get_time);
  }

  ccf::endpoints::ReadOnlyEndpointFunction tracing_read_only_adapter(
    ccf::endpoints::ReadOnlyEndpointFunction fn,
    const std::string& method,
    const std::function<ccf::ApiResult(::timespec& time)>& get_time)
  {
    return generic_tracing_adapter<
      ccf::endpoints::ReadOnlyEndpointFunction,
      ccf::endpoints::ReadOnlyEndpointContext>(fn, method, get_time);
  }

  ccf::endpoints::CommandEndpointFunction tracing_command_adapter(
    ccf::endpoints::CommandEndpointFunction fn,
    const std::string& method,
    const std::function<ccf::ApiResult(::timespec& time)>& get_time)
  {
    return generic_tracing_adapter<
      ccf::endpoints::CommandEndpointFunction,
      ccf::endpoints::CommandEndpointContext>(fn, method, get_time);
  }
}
