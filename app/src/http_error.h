// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

namespace scitt
{
  struct HTTPError : public std::runtime_error
  {
    using Headers = std::unordered_map<std::string, std::string>;
    http_status status_code;
    std::string code;
    Headers headers;
    HTTPError(
      http_status status_code,
      std::string code,
      std::string msg,
      Headers headers = {}) :
      std::runtime_error(msg),
      status_code(status_code),
      code(code),
      headers(headers)
    {}
  };

  struct BadRequestError : public HTTPError
  {
    BadRequestError(std::string code, std::string msg) :
      HTTPError(HTTP_STATUS_BAD_REQUEST, code, msg)
    {}
  };

  struct NotFoundError : public HTTPError
  {
    NotFoundError(std::string code, std::string msg) :
      HTTPError(HTTP_STATUS_NOT_FOUND, code, msg)
    {}
  };

  struct UnauthorizedError : public HTTPError
  {
    UnauthorizedError(std::string code, std::string msg) :
      HTTPError(HTTP_STATUS_UNAUTHORIZED, code, msg)
    {}
  };

  struct ServiceUnavailableError : public HTTPError
  {
    ServiceUnavailableError(
      std::string code,
      std::string msg,
      std::optional<uint32_t> retry_after = std::nullopt) :
      HTTPError(
        HTTP_STATUS_SERVICE_UNAVAILABLE, code, msg, make_headers(retry_after))
    {}

  private:
    static HTTPError::Headers make_headers(std::optional<uint32_t> retry_after)
    {
      if (retry_after)
        return {{"Retry-After", std::to_string(retry_after.value())}};
      else
        return {};
    }
  };

  struct InternalServerError : public HTTPError
  {
    InternalServerError(std::string code, std::string msg) :
      HTTPError(HTTP_STATUS_INTERNAL_SERVER_ERROR, code, msg)
    {}
  };

  struct InternalError : public InternalServerError
  {
    InternalError(std::string msg) :
      InternalServerError(errors::InternalError, msg)
    {}
  };

  template <typename Fn, typename Ctx>
  Fn generic_error_adapter(Fn fn)
  {
    return [fn](Ctx& ctx) {
      try
      {
        fn(ctx);
      }
      catch (const HTTPError& e)
      {
        CCF_APP_INFO("HTTPError: {}", e.what());
        ctx.rpc_ctx->set_error(e.status_code, e.code, e.what());
        for (const auto& [header_name, header_value] : e.headers)
        {
          ctx.rpc_ctx->set_response_header(header_name, header_value);
        }
      }
      catch (const std::exception& e)
      {
        CCF_APP_FAIL("Unhandled exception in endpoint: {}", e.what());
        throw;
      }
    };
  }

  /**
   * Create an adapter around an existing EndpointFunction to handle thrown
   * HTTPError exceptions.
   */
  ccf::endpoints::EndpointFunction error_adapter(
    ccf::endpoints::EndpointFunction fn)
  {
    return generic_error_adapter<
      ccf::endpoints::EndpointFunction,
      ccf::endpoints::EndpointContext>(fn);
  }

  ccf::endpoints::ReadOnlyEndpointFunction error_read_only_adapter(
    ccf::endpoints::ReadOnlyEndpointFunction fn)
  {
    return generic_error_adapter<
      ccf::endpoints::ReadOnlyEndpointFunction,
      ccf::endpoints::ReadOnlyEndpointContext>(fn);
  }

  ccf::endpoints::CommandEndpointFunction error_command_adapter(
    ccf::endpoints::CommandEndpointFunction fn)
  {
    return generic_error_adapter<
      ccf::endpoints::CommandEndpointFunction,
      ccf::endpoints::CommandEndpointContext>(fn);
  }
}
