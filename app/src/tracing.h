// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "constants.h"

#include <time.h>
#include <regex>
#include <sstream>
#include <functional>
#include <ccf/endpoint_context.h>
#include <ccf/base_endpoint_registry.h>

namespace scitt
{
  std::string REQUEST_ID_HEADER = "x-ms-request-id";
  std::string CLIENT_REQUEST_ID_HEADER = "x-ms-client-request-id";

  std::regex CLIENT_REQUEST_ID_REGEX("^[0-9a-zA-Z-]+");

  thread_local std::string request_id;
  thread_local std::optional<std::string> client_request_id;

  int diff_timespec_ms(const struct timespec& time0, const struct timespec& time1) {
    return (time1.tv_sec - time0.tv_sec) * 1000
        + (time1.tv_nsec - time0.tv_nsec) / 1000000;
  }

  std::string create_request_id() {
    std::stringstream stream;
    stream << std::hex << rand();
    return stream.str();
  }

  inline void SCITT_INFO(const std::string& msg)
  {
    CCF_APP_INFO("ClientRequestId={} RequestId={} {}",
        client_request_id.value_or(""),
        request_id,
        msg
        );
  }

  inline void SCITT_FAIL(const std::string& msg)
  {
    CCF_APP_FAIL("ClientRequestId={} RequestId={} {}",
        client_request_id.value_or(""),
        request_id,
        msg
        );
  }

  template <typename Fn, typename Ctx>
  Fn generic_tracing_adapter(
    Fn fn, const std::function<ccf::ApiResult(::timespec& time)>& get_time)
  {
    return [fn, get_time](Ctx& ctx) {
      request_id = create_request_id();
      ctx.rpc_ctx->set_response_header(REQUEST_ID_HEADER, request_id);

      client_request_id = ctx.rpc_ctx->get_request_header(CLIENT_REQUEST_ID_HEADER);

      if (client_request_id.has_value())
      {
        std::smatch match;
        if (!std::regex_match(client_request_id.value(), match, CLIENT_REQUEST_ID_REGEX))
        {
          client_request_id = std::nullopt;
          SCITT_INFO("Invalid client request id");
          ctx.rpc_ctx->set_error(HTTP_STATUS_BAD_REQUEST, errors::InvalidInput, "Invalid client request id.");
          return;
        }
        ctx.rpc_ctx->set_response_header("x-ms-client-request-id", client_request_id.value());
      }

      SCITT_INFO(fmt::format("Verb={} Path={} Query={}",
        ctx.rpc_ctx->get_request_verb().c_str(),
        ctx.rpc_ctx->get_request_path(),
        ctx.rpc_ctx->get_request_query()
        ));

      ::timespec start;
      ccf::ApiResult result = get_time(start);
      if (result != ccf::ApiResult::OK)
      {
        SCITT_FAIL("get_untrusted_host_time_v1 failed");
        ctx.rpc_ctx->set_error(HTTP_STATUS_INTERNAL_SERVER_ERROR, errors::InternalError, "Failed to get time.");
        return;
      }

      fn(ctx);

      ::timespec end;
      result = get_time(end);
      if (result != ccf::ApiResult::OK)
      {
        SCITT_FAIL("get_untrusted_host_time_v1 failed");
        ctx.rpc_ctx->set_error(HTTP_STATUS_INTERNAL_SERVER_ERROR, errors::InternalError, "Failed to get time.");
        return;
      }

      auto duration_ms = diff_timespec_ms(start, end);
      
      SCITT_INFO(fmt::format("Verb={} Path={} Query={} Status={} TimeMs={}",
        ctx.rpc_ctx->get_request_verb().c_str(),
        ctx.rpc_ctx->get_request_path(),
        ctx.rpc_ctx->get_request_query(),
        ctx.rpc_ctx->get_response_status(),
        duration_ms
        ));
    };
  }

  /**
   * Create an adapter around an existing EndpointFunction to handle tracing.
   */
  ccf::endpoints::EndpointFunction tracing_adapter(
    ccf::endpoints::EndpointFunction fn, const std::function<ccf::ApiResult(::timespec& time)>& get_time)
  {
    return generic_tracing_adapter<
      ccf::endpoints::EndpointFunction,
      ccf::endpoints::EndpointContext>(fn, get_time);
  }

  ccf::endpoints::ReadOnlyEndpointFunction tracing_read_only_adapter(
    ccf::endpoints::ReadOnlyEndpointFunction fn, const std::function<ccf::ApiResult(::timespec& time)>& get_time)
  {
    return generic_tracing_adapter<
      ccf::endpoints::ReadOnlyEndpointFunction,
      ccf::endpoints::ReadOnlyEndpointContext>(fn, get_time);
  }

  ccf::endpoints::CommandEndpointFunction tracing_command_adapter(
    ccf::endpoints::CommandEndpointFunction fn, const std::function<ccf::ApiResult(::timespec& time)>& get_time)
  {
    return generic_tracing_adapter<
      ccf::endpoints::CommandEndpointFunction,
      ccf::endpoints::CommandEndpointContext>(fn, get_time);
  }
}
