// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once
#include <ccf/rpc_context.h>
#include <functional>
#include <string>

namespace scitt
{
  using TriggerAsynchronousOperation =
    std::function<void(std::string callback_url)>;
  struct AsynchronousOperation
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
    timespec start_time;

    // Used by operations_endpoints.h
    std::optional<AsynchronousOperation> asynchronous_operation;
  };

  AppData& get_app_data(const std::shared_ptr<ccf::RpcContext>& ctx)
  {
    auto user_data = static_cast<AppData*>(ctx->get_user_data());
    if (user_data != nullptr)
    {
      return *user_data;
    }

    auto data = std::make_shared<AppData>();
    ctx->set_user_data(data);
    return *data;
  }
}
