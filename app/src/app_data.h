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

  struct AppData
  {
    std::optional<std::string> request_id;
    std::optional<std::string> client_request_id;
    std::optional<AsynchronousOperation> asynchronous_operation;
  };

  AppData& get_app_data(std::shared_ptr<ccf::RpcContext>& ctx)
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
