// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "http_error.h"

#include <ccf/ds/json.h>
#include <ccf/json_handler.h>
#include <ccf/rpc_exception.h>
#include <utility>

namespace scitt
{
  static ccf::endpoints::EndpointFunction json_adapter(
    const ccf::HandlerJsonParamsAndForward& fn)
  {
    return [fn](ccf::endpoints::EndpointContext& ctx) {
      nlohmann::json params;
      try
      {
        params = ccf::jsonhandler::get_json_params(ctx.rpc_ctx);
      }
      catch (const ccf::JsonParseError& e)
      {
        throw BadRequestJsonError(errors::InvalidInput, e.describe());
      }
      catch (const nlohmann::json::exception& e)
      {
        throw BadRequestJsonError(errors::InvalidInput, e.what());
      }

      // Handler-internal JSON failures are server errors, not bad input.
      auto response = fn(ctx, std::move(params));
      try
      {
        ccf::jsonhandler::set_response(std::move(response), ctx.rpc_ctx);
      }
      catch (const ccf::RpcException& e)
      {
        throw HTTPError(e.error.status, e.error.code, e.error.msg, false);
      }
    };
  }
}
