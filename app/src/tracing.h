// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "app_data.h"
#include "cbor.h"
#include "constants.h"
#include "util.h"

#include <algorithm>
#include <ccf/base_endpoint_registry.h>
#include <ccf/ds/logger.h>
#include <ccf/endpoint_context.h>
#include <ctime>
#include <functional>
#include <string_view>

namespace scitt
{
  constexpr std::string_view REQUEST_ID_HEADER = "x-ms-request-id";
  constexpr std::string_view CLIENT_REQUEST_ID_HEADER =
    "x-ms-client-request-id";

  static constexpr auto FN_STAGE_MAIN = "MAIN";
  static constexpr auto FN_STAGE_POSTCOMMIT = "POSTCOMMIT";
  inline constexpr size_t MAX_LOGGED_PATH = 1024;
  inline constexpr size_t MAX_LOGGED_QUERY = 1024;
  inline constexpr size_t MAX_LOGGED_URL = 2048;
  inline constexpr size_t MAX_LOGGED_CLIENT_ID = 128;

  inline std::string escape_log_field(std::string_view value, size_t max_length)
  {
    constexpr char hex[] = "0123456789ABCDEF";
    constexpr std::string_view truncation_marker = "...[truncated]";
    const auto marker = truncation_marker.substr(
      0, std::min(max_length, truncation_marker.size()));
    std::string result;
    result.reserve(std::min(value.size(), max_length));
    size_t truncated_length = 0;
    for (const auto character : value)
    {
      const auto byte = static_cast<unsigned char>(character);
      // Whitespace separates SCITT's key=value fields. Escape it in values,
      // along with control/non-ASCII bytes, without re-encoding URL escapes.
      const bool escaped = byte <= 32 || byte >= 127;
      const size_t encoded_length = escaped ? 3 : 1;
      if (encoded_length > max_length - result.size())
      {
        result.resize(truncated_length);
        result += marker;
        break;
      }
      if (escaped)
      {
        result += '%';
        result += hex[byte >> 4];
        result += hex[byte & 15];
      }
      else
      {
        result += character;
      }
      if (result.size() <= max_length - marker.size())
      {
        truncated_length = result.size();
      }
    }
    return result;
  }

  inline thread_local std::optional<std::string> request_id;
  inline thread_local std::optional<std::string> client_request_id;

  class ScopedTracingContext
  {
  private:
    std::optional<std::string> previous_request_id = request_id;
    std::optional<std::string> previous_client_request_id = client_request_id;

  public:
    explicit ScopedTracingContext(const AppData* scope)
    {
      request_id = scope != nullptr ? scope->request_id : std::nullopt;
      client_request_id =
        scope != nullptr ? scope->client_request_id : std::nullopt;
    }

    explicit ScopedTracingContext(const std::shared_ptr<AppData>& scope) :
      ScopedTracingContext(scope.get())
    {}

    ~ScopedTracingContext()
    {
      request_id = previous_request_id;
      client_request_id = previous_client_request_id;
    }

    ScopedTracingContext(const ScopedTracingContext&) = delete;
    ScopedTracingContext& operator=(const ScopedTracingContext&) = delete;
  };

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
        escape_log_field(*client_request_id, MAX_LOGGED_CLIENT_ID));
    }
    if (request_id.has_value())
    {
      fmt::format_to(
        std::back_inserter(out), "RequestId={} ", request_id.value());
    }
    return fmt::to_string(out);
  }

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"

#define SCITT_LOG(f, s, ...) \
  f(s " {}", ##__VA_ARGS__, ::scitt::tracing_context())

#define SCITT_TRACE(s, ...) SCITT_LOG(CCF_APP_TRACE, s, ##__VA_ARGS__)
#define SCITT_DEBUG(s, ...) SCITT_LOG(CCF_APP_DEBUG, s, ##__VA_ARGS__)
#define SCITT_INFO(s, ...) SCITT_LOG(CCF_APP_INFO, s, ##__VA_ARGS__)
#define SCITT_FAIL(s, ...) SCITT_LOG(CCF_APP_FAIL, s, ##__VA_ARGS__)

#pragma clang diagnostic pop

  using GetHostTime = std::function<ccf::ApiResult(timespec&)>;

  inline void log_request_end(
    const ccf::RpcContext& rpc_ctx,
    const AppData& scope,
    const std::string& stage,
    int status,
    long duration_ms,
    std::optional<ccf::TxID> txid = std::nullopt)
  {
    const auto error_context = scope.error_code.has_value() ?
      fmt::format(" Code={}", *scope.error_code) :
      std::string{};
    const auto tx_context = txid.has_value() ?
      fmt::format(" TxId={}", txid->to_str()) :
      std::string{};
    SCITT_INFO(
      "::END:: Stage={} Verb={} Path={} Query={} URL={} Status={}{}{} "
      "TimeMs={}",
      stage,
      rpc_ctx.get_request_verb().c_str(),
      escape_log_field(scope.path, MAX_LOGGED_PATH),
      escape_log_field(rpc_ctx.get_request_query(), MAX_LOGGED_QUERY),
      escape_log_field(rpc_ctx.get_request_url(), MAX_LOGGED_URL),
      status,
      error_context,
      tx_context,
      duration_ms);
  }

  inline std::shared_ptr<AppData> begin_request_tracing(
    ccf::RpcContext& rpc_ctx, const GetHostTime& get_time)
  {
    const auto scope = begin_request_scope(rpc_ctx);
    if (scope == nullptr)
    {
      const ScopedTracingContext correlation(scope);
      SCITT_FAIL("RPC user_data is already in use; skipping request tracing");
      return nullptr;
    }
    if (!scope->request_id.has_value())
    {
      scope->request_id = create_request_id();
      scope->client_request_id =
        rpc_ctx.get_request_header(CLIENT_REQUEST_ID_HEADER);
      const ScopedTracingContext correlation(scope);
      const auto result = get_time(scope->start_time);
      scope->time_available = result == ccf::ApiResult::OK;
      if (!scope->time_available)
      {
        SCITT_FAIL(
          "get_time failed while recording start time: {}",
          ccf::api_result_to_str(result));
      }
    }
    scope->path = rpc_ctx.get_request_path();
    scope->restore_response_headers = [&rpc_ctx,
                                       id = *scope->request_id,
                                       client_id = scope->client_request_id]() {
      rpc_ctx.set_response_header(REQUEST_ID_HEADER, id);
      if (client_id.has_value())
      {
        rpc_ctx.set_response_header(CLIENT_REQUEST_ID_HEADER, *client_id);
      }
    };
    scope->emit_end = [&rpc_ctx, get_time](const AppData& request, int status) {
      const ScopedTracingContext correlation(&request);
      timespec end{};
      const auto result = get_time(end);
      long duration_ms = -1;
      if (!request.time_available || result != ccf::ApiResult::OK)
      {
        SCITT_FAIL(
          "Request duration unavailable: get_time={}",
          ccf::api_result_to_str(result));
      }
      else
      {
        duration_ms = diff_timespec_ms(request.start_time, end);
        if (duration_ms < 0)
        {
          SCITT_DEBUG(
            "Untrusted host time produced negative request duration: {} ms.",
            duration_ms);
        }
      }
      log_request_end(rpc_ctx, request, FN_STAGE_MAIN, status, duration_ms);
      if (request.tx_id.has_value())
      {
        log_request_end(
          rpc_ctx,
          request,
          FN_STAGE_POSTCOMMIT,
          status,
          duration_ms,
          request.tx_id);
      }
    };
    scope->restore_response_headers();
    return scope;
  }

  inline void finish_request_tracing(int status, bool dispatched = true)
  {
    const ScopedTracingContext correlation(get_request_scope());
    complete_current_request(status, dispatched);
  }

  static ccf::endpoints::EndpointFunction tracing_adapter_first(
    ccf::endpoints::EndpointFunction fn, const std::string& path)
  {
    return [fn, path](ccf::endpoints::EndpointContext& ctx) {
      const auto scope = get_request_scope(*ctx.rpc_ctx);
      const ScopedTracingContext correlation(scope);
      if (scope == nullptr)
      {
        SCITT_FAIL(
          "No request log scope for SCITT endpoint; skipping request tracing");
      }
      else
      {
        scope->path = path;
        if (!scope->start_logged)
        {
          SCITT_INFO(
            "::START:: Stage={} Verb={} Path={} Query={} URL={}",
            FN_STAGE_MAIN,
            ctx.rpc_ctx->get_request_verb().c_str(),
            escape_log_field(path, MAX_LOGGED_PATH),
            escape_log_field(
              ctx.rpc_ctx->get_request_query(), MAX_LOGGED_QUERY),
            escape_log_field(ctx.rpc_ctx->get_request_url(), MAX_LOGGED_URL));
          scope->start_logged = true;
        }
      }
      fn(ctx);
    };
  }

  inline void set_logged_consensus_committed_function(
    ccf::RpcContext& rpc_ctx,
    ccf::endpoints::ConsensusCommittedEndpointFunction callback)
  {
    const auto scope = get_request_scope(rpc_ctx);
    if (scope == nullptr)
    {
      SCITT_FAIL(
        "No request log scope for consensus callback; skipping request "
        "tracing");
    }
    else
    {
      scope->consensus_callback_registered = true;
    }
    rpc_ctx.set_consensus_committed_function(
      [scope,
       callback = std::move(callback)](ccf::endpoints::CommittedTxInfo& info) {
        const ScopedTracingContext correlation(scope);
        try
        {
          callback(info);
        }
        catch (const std::exception& error)
        {
          SCITT_FAIL("Consensus callback failed: {}", error.what());
          info.rpc_ctx->set_response_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
          info.rpc_ctx->set_response_header(
            ccf::http::headers::CONTENT_TYPE, cbor::CBOR_ERROR_CONTENT_TYPE);
          info.rpc_ctx->set_response_body(cbor::cbor_error(
            errors::InternalError,
            "Failed to execute consensus commit callback"));
          if (scope != nullptr)
          {
            scope->error_code = errors::InternalError;
          }
        }
        if (scope != nullptr)
        {
          scope->complete(info.rpc_ctx->get_response_status());
        }
      });
  }
}
