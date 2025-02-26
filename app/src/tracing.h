// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "app_data.h"
#include "constants.h"
#include "util.h"

#include <ccf/base_endpoint_registry.h>
#include <ccf/ds/logger.h>
#include <ccf/endpoint_context.h>
#include <ctime>
#include <functional>
#include <regex>

namespace scitt
{
  constexpr std::string_view REQUEST_ID_HEADER = "x-ms-request-id";
  constexpr std::string_view CLIENT_REQUEST_ID_HEADER =
    "x-ms-client-request-id";

  static const std::regex CLIENT_REQUEST_ID_REGEX("^[0-9a-zA-Z-]+");

  inline thread_local std::optional<std::string> request_id;
  inline thread_local std::optional<std::string> client_request_id;

  static void clear_trace_state()
  {
    request_id = std::nullopt;
    client_request_id = std::nullopt;
  }

  static long diff_timespec_ms(
    const struct timespec& time0, const struct timespec& time1)
  {
    return (time1.tv_sec - time0.tv_sec) * 1000 +
      (time1.tv_nsec - time0.tv_nsec) / 1000000;
  }

  static std::string create_request_id()
  {
    return fmt::format("{:x}", ENTROPY->random64());
  }

  static std::string tracing_context()
  {
    fmt::memory_buffer out;
    if (client_request_id.has_value())
    {
      fmt::format_to(
        std::back_inserter(out),
        "ClientRequestId={} ",
        client_request_id.value());
    }
    if (request_id.has_value())
    {
      fmt::format_to(
        std::back_inserter(out), "RequestId={} ", request_id.value());
    }
    return fmt::to_string(out);
  }

// The ## syntax is GCC extension, for which we need to disable warnings.
// C++20 has a standard alternative, __VA_OPT__, we could use, but clang has a
// bug still throws warnings at the call site. The bug is fixed in clang-14.
// https://github.com/llvm/llvm-project/commit/af971365a2a8b0d982814c0652bb86844fd19cda
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"

// These macros could be invoked from anywhere, including outside of the scitt
// namespace. All references to global symbols must therefore be fully qualified
// (ie. using ::scitt::foo).
#define SCITT_LOG(f, s, ...) \
  f("{}" s, ::scitt::tracing_context(), ##__VA_ARGS__)

#define SCITT_TRACE(s, ...) SCITT_LOG(CCF_APP_TRACE, s, ##__VA_ARGS__)
#define SCITT_DEBUG(s, ...) SCITT_LOG(CCF_APP_DEBUG, s, ##__VA_ARGS__)
#define SCITT_INFO(s, ...) SCITT_LOG(CCF_APP_INFO, s, ##__VA_ARGS__)
#define SCITT_FAIL(s, ...) SCITT_LOG(CCF_APP_FAIL, s, ##__VA_ARGS__)

#pragma clang diagnostic pop

  static void log_request_end(
    const std::shared_ptr<ccf::RpcContext>& rpc_ctx,
    const std::string& path,
    const std::function<ccf::ApiResult(::timespec& time)>& get_time,
    std::optional<ccf::TxID> txid = std::nullopt)
  {
    AppData& app_data = get_app_data(rpc_ctx);

    ::timespec end;
    ccf::ApiResult result = get_time(end);
    // FIXME: should be CBOR or JSON
    if (result != ccf::ApiResult::OK)
    {
      SCITT_FAIL(
        "::END:: Code=InternalError get_untrusted_host_time_v1 failed");
      rpc_ctx->set_error(
        HTTP_STATUS_INTERNAL_SERVER_ERROR,
        errors::InternalError,
        "Failed to get time.");
      return;
    }

    auto duration_ms = diff_timespec_ms(app_data.start_time, end);
    if (duration_ms < 0)
    {
      SCITT_INFO(
        "Computed request duration is negative: {} ms. Ignoring.", duration_ms);
    }

    if (txid.has_value())
    {
      SCITT_INFO(
        "::END:: Verb={} Path={} Query={} URL={} Status={} TxId={} TimeMs={}",
        rpc_ctx->get_request_verb().c_str(),
        path,
        rpc_ctx->get_request_query().c_str(),
        rpc_ctx->get_request_url(),
        rpc_ctx->get_response_status(),
        txid->to_str(),
        std::to_string(duration_ms));
    }
    else
    {
      SCITT_INFO(
        "::END:: Verb={} Path={} Query={} URL={} Status={} TimeMs={}",
        rpc_ctx->get_request_verb().c_str(),
        path,
        rpc_ctx->get_request_query().c_str(),
        rpc_ctx->get_request_url(),
        rpc_ctx->get_response_status(),
        std::to_string(duration_ms));
    }
  }

  /**
   * This tracing adapter is wrapping the main endpoint logic that can fail.
   * In a case of success it will continue executing a local commit handler.
   */
  static ccf::endpoints::EndpointFunction tracing_adapter_first(
    ccf::endpoints::EndpointFunction fn,
    const std::string& path,
    const std::function<ccf::ApiResult(::timespec& time)>& get_time)
  {
    return [fn, path, get_time](ccf::endpoints::EndpointContext& ctx) {
      auto cleanup = finally(clear_trace_state);

      request_id = create_request_id();
      ctx.rpc_ctx->set_response_header(REQUEST_ID_HEADER, request_id.value());

      client_request_id =
        ctx.rpc_ctx->get_request_header(CLIENT_REQUEST_ID_HEADER);

      // The user data is used to propagate the request IDs to the local
      // commit callback
      AppData& app_data = get_app_data(ctx.rpc_ctx);
      app_data.request_id = request_id;
      app_data.client_request_id = client_request_id;

      SCITT_INFO(
        "::START:: Verb={} Path={} Query={} URL={}",
        ctx.rpc_ctx->get_request_verb().c_str(),
        path,
        ctx.rpc_ctx->get_request_query().c_str(),
        ctx.rpc_ctx->get_request_url());

      ::timespec start;
      ccf::ApiResult result = get_time(app_data.start_time);
      if (result != ccf::ApiResult::OK)
      {
        // FIXME: should be CBOR or JSON
        SCITT_FAIL(
          "::END:: Code=InternalError get_untrusted_host_time_v1 failed");
        ctx.rpc_ctx->set_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          errors::InternalError,
          "Failed to get time.");
        return;
      }

      fn(ctx);

      // If the status is 2xx, CCF will later call our local commit handler,
      // which may modify the response. We delay printing the end of request
      // log line until after that point, to get the most accurate status code.
      // Another adapter is used for the local commit handler, see
      // tracing_adapter_last.
      int status = ctx.rpc_ctx->get_response_status();
      if (status < 200 || status >= 300)
      {
        log_request_end(ctx.rpc_ctx, path, get_time);
      }
    };
  }

  /**
   * Locally committed function will be called after the main endpoint logic
   * succeeds. It will not be called if the main endpoint logic fails.
   */
  static ccf::endpoints::LocallyCommittedEndpointFunction tracing_adapter_last(
    ccf::endpoints::LocallyCommittedEndpointFunction fn,
    const std::string& path,
    const std::function<ccf::ApiResult(::timespec& time)>& get_time)
  {
    return
      [fn, path, get_time](
        ccf::endpoints::CommandEndpointContext& ctx, const ccf::TxID& txid) {
        auto cleanup = finally(clear_trace_state);

        AppData& app_data = get_app_data(ctx.rpc_ctx);
        request_id = app_data.request_id;
        client_request_id = app_data.client_request_id;

        fn(ctx, txid);

        log_request_end(ctx.rpc_ctx, path, get_time, txid);
      };
  }
}
