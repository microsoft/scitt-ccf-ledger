// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "cbor.h"
#include "tracing.h"

#include <qcbor/qcbor_decode.h>
#include <qcbor/qcbor_encode.h>
#include <qcbor/qcbor_spiffy_decode.h>
#include <stdexcept>

namespace scitt
{
  struct HTTPError : public std::runtime_error
  {
    using Headers = std::unordered_map<std::string, std::string>;
    ccf::http_status status_code;
    std::string code;
    Headers headers;
    HTTPError(
      ccf::http_status status_code,
      std::string code,
      std::string msg,
      bool returns_cbor_error = true,
      Headers headers = {}) :
      std::runtime_error(msg),
      status_code(status_code),
      code(code),
      headers(headers)
    {}

    /**
     * Convert the error to a CBOR-encoded byte array.
     * Follow rfc9290 for error encoding but use only
     * title and detail and encode them cbor text.
     */
    std::vector<uint8_t> to_cbor_error() const
    {
      std::string error_mesasge = what();
      // The size of the buffer must be equal or larger than the data,
      // otherwise decodign will fail
      size_t buff_size = QCBOR_HEAD_BUFFER_SIZE + // map
        QCBOR_HEAD_BUFFER_SIZE + // key
        sizeof(cbor::CBOR_ERROR_TITLE) + // key
        QCBOR_HEAD_BUFFER_SIZE + // value
        code.size() + // value
        QCBOR_HEAD_BUFFER_SIZE + // key
        sizeof(cbor::CBOR_ERROR_DETAIL) + // key
        QCBOR_HEAD_BUFFER_SIZE + // value
        error_mesasge.size(); // value
      std::vector<uint8_t> output(buff_size);

      UsefulBuf output_buf{output.data(), output.size()};
      QCBOREncodeContext ectx;
      QCBOREncode_Init(&ectx, output_buf);
      QCBOREncode_OpenMap(&ectx);
      QCBOREncode_AddTextToMapN(
        &ectx, cbor::CBOR_ERROR_TITLE, cbor::from_string(code));
      QCBOREncode_AddTextToMapN(
        &ectx, cbor::CBOR_ERROR_DETAIL, cbor::from_string(error_mesasge));
      QCBOREncode_CloseMap(&ectx);
      UsefulBufC encoded_cbor;
      QCBORError err;
      err = QCBOREncode_Finish(&ectx, &encoded_cbor);
      if (err != QCBOR_SUCCESS)
      {
        throw std::logic_error("Failed to encode CBOR error");
      }
      output.resize(encoded_cbor.len);
      output.shrink_to_fit();
      return output;
    }
  };

  struct BadRequestJsonError : public HTTPError
  {
    BadRequestJsonError(std::string code, std::string msg) :
      HTTPError(HTTP_STATUS_BAD_REQUEST, code, msg, false)
    {}
  };

  struct BadRequestCborError : public HTTPError
  {
    BadRequestJsonError(std::string code, std::string msg) :
      HTTPError(HTTP_STATUS_BAD_REQUEST, code, msg, true)
    {}
  };

  struct NotFoundCborError : public HTTPError
  {
    NotFoundCborError(std::string code, std::string msg) :
      HTTPError(HTTP_STATUS_NOT_FOUND, code, msg, true)
    {}
  };

  struct ServiceUnavailableJsonError : public HTTPError
  {
    ServiceUnavailableJsonError(
      std::string code,
      std::string msg,
      std::optional<uint32_t> retry_after = std::nullopt) :
      HTTPError(
        HTTP_STATUS_SERVICE_UNAVAILABLE,
        code,
        msg,
        false,
        make_headers(retry_after))
    {}

  private:
    static HTTPError::Headers make_headers(std::optional<uint32_t> retry_after)
    {
      if (retry_after)
      {
        return {{"Retry-After", std::to_string(retry_after.value())}};
      }
      else
      {
        return {};
      }
    }
  };

  struct InternalServerError : public HTTPError
  {
    InternalServerError(
      std::string code, std::string msg, bool returns_cbor_error) :
      HTTPError(
        HTTP_STATUS_INTERNAL_SERVER_ERROR, code, msg, returns_cbor_error)
    {}
  };

  struct InternalJsonError : public InternalServerError
  {
    InternalError(std::string msg) :
      InternalServerError(errors::InternalError, msg, false)
    {}
  };

  struct InternalCborError : public InternalServerError
  {
    InternalError(std::string msg) :
      InternalServerError(errors::InternalError, msg, true)
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
        if (e.code == errors::InternalError)
        {
          SCITT_FAIL("Code={} {}", e.code, e.what());
        }
        else
        {
          SCITT_INFO("Code={}", e.code);
        }

        if (e.returns_cbor_error)
        {
          ctx.rpc_ctx->set_response_status(e.status_code);
          ctx.rpc_ctx->set_response_header(
            ccf::http::headers::CONTENT_TYPE, cbor::CBOR_ERROR_CONTENT_TYPE);
          ctx.rpc_ctx->set_response_body(e.to_cbor_error());
        }
        else
        {
          ctx.rpc_ctx->set_error(e.status_code, e.code, e.what());
        }

        for (const auto& [header_name, header_value] : e.headers)
        {
          ctx.rpc_ctx->set_response_header(header_name, header_value);
        }
      }
      catch (const std::exception& e)
      {
        SCITT_FAIL("Unhandled exception in endpoint: {}", e.what());
        throw;
      }
    };
  }

  /**
   * Create an adapter around an existing EndpointFunction to handle thrown
   * HTTPError exceptions.
   */
  static ccf::endpoints::EndpointFunction error_adapter(
    ccf::endpoints::EndpointFunction fn)
  {
    return generic_error_adapter<
      ccf::endpoints::EndpointFunction,
      ccf::endpoints::EndpointContext>(fn);
  }
}
