// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once
#include <ccf/rpc_context.h>
#include <ccf/tx_id.h>
#include <functional>
#include <memory>
#include <optional>
#include <string>

namespace scitt
{
  using TriggerAsynchronousOperation =
    std::function<void(std::string callback_url)>;
  struct AsynchronousOperation // NOLINT(bugprone-exception-escape)
  {
    TriggerAsynchronousOperation trigger;
    std::string bind_address;
  };

  /**
   * This structure is used to pass data from the main endpoint handler to the
   * local commit handler.
   *
   * Because we are only allowed to store one pointer in the RPC context, this
   * has to combine bits and bobs from across the code base.
   */
  struct AppData
  {
    // Used by tracing.h
    std::optional<std::string> request_id;
    std::optional<std::string> client_request_id;
    std::optional<std::string> error_code;
    timespec start_time{};
    bool time_available = false;
    std::string path;
    bool executed_locally = false;
    bool start_logged = false;
    bool completion_logged = false;
    bool consensus_callback_registered = false;
    bool awaiting_consensus = false;
    std::optional<ccf::TxID> tx_id;
    std::function<void()> restore_response_headers;
    std::function<void(const AppData&, int)> emit_end;

    void begin_attempt()
    {
      error_code.reset();
      executed_locally = false;
      consensus_callback_registered = false;
      awaiting_consensus = false;
      tx_id.reset();
    }

    void locally_committed(const ccf::TxID& id, bool is_forwarded)
    {
      tx_id = id;
      // Forwarded responses bypass the HTTP session's consensus callback.
      awaiting_consensus = consensus_callback_registered && !is_forwarded;
    }

    void complete(int status)
    {
      if (!completion_logged)
      {
        restore_response_headers();
        emit_end(*this, status);
        completion_logged = true;
      }
    }
  };

  // Registry completion events have no RpcContext. This weak bridge is only
  // used during synchronous dispatch; deferred callbacks capture the scope.
  inline thread_local std::weak_ptr<AppData> current_request_scope;

  inline std::shared_ptr<AppData> get_request_scope()
  {
    return current_request_scope.lock();
  }

  template <typename RpcContext>
  std::shared_ptr<AppData> get_request_scope(const RpcContext& ctx)
  {
    auto scope = get_request_scope();
    if (scope != nullptr && ctx.get_user_data() != scope.get())
    {
      current_request_scope.reset();
      scope.reset();
    }
    return scope;
  }

  template <typename RpcContext>
  std::shared_ptr<AppData> begin_request_scope(RpcContext& ctx)
  {
    auto scope = get_request_scope();
    if (scope == nullptr || ctx.get_user_data() != scope.get())
    {
      current_request_scope.reset();
      if (ctx.get_user_data() != nullptr)
      {
        return nullptr;
      }
      scope = std::make_shared<AppData>();
      ctx.set_user_data(scope);
      current_request_scope = scope;
    }
    scope->begin_attempt();
    return scope;
  }

  inline void complete_current_request(int status, bool dispatched = true)
  {
    const auto scope = get_request_scope();
    current_request_scope.reset();
    if (scope != nullptr)
    {
      // A successful completion without local execution is pending internal
      // forwarding. Dispatch-failed OPTIONS (204) is a real completion.
      const bool forwarded =
        dispatched && !scope->executed_locally && status >= 200 && status < 300;
      if (!forwarded && !scope->awaiting_consensus)
      {
        scope->complete(status);
      }
    }
  }
}
