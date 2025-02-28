// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "call_types.h"

#include <qcbor/UsefulBuf.h>
#include <qcbor/qcbor_decode.h>
#include <qcbor/qcbor_encode.h>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace scitt::cbor
{
  static constexpr int64_t CBOR_ERROR_TITLE = -1;
  static constexpr int64_t CBOR_ERROR_DETAIL = -2;
  static constexpr const char* CBOR_ERROR_CONTENT_TYPE =
    "application/concise-problem-details+cbor";

  inline UsefulBufC from_bytes(std::span<const uint8_t> v)
  {
    return UsefulBufC{v.data(), v.size()};
  }

  inline UsefulBufC from_string(std::string_view v)
  {
    return UsefulBufC{v.data(), v.size()};
  }

  inline std::vector<uint8_t> as_vector(UsefulBufC buf)
  {
    return std::vector<uint8_t>(
      static_cast<const uint8_t*>(buf.ptr),
      static_cast<const uint8_t*>(buf.ptr) + buf.len);
  }

  inline std::span<const uint8_t> as_span(UsefulBufC buf)
  {
    return {static_cast<const uint8_t*>(buf.ptr), buf.len};
  }

  inline std::string_view as_string(UsefulBufC buf)
  {
    return {static_cast<const char*>(buf.ptr), buf.len};
  }

  /**
   * A CBOR-encoded byte array.
   * Follow rfc9290 for error encoding but use only
   * title and detail and encode them cbor text.
   */
  inline std::vector<uint8_t> cbor_error(
    const std::string& code, const std::string& error_message)
  {
    // The size of the buffer must be equal or larger than the data,
    // otherwise decoding will fail
    size_t buff_size = QCBOR_HEAD_BUFFER_SIZE + // map
      QCBOR_HEAD_BUFFER_SIZE + // key
      sizeof(CBOR_ERROR_TITLE) + // key
      QCBOR_HEAD_BUFFER_SIZE + // value
      code.size() + // value
      QCBOR_HEAD_BUFFER_SIZE + // key
      sizeof(CBOR_ERROR_DETAIL) + // key
      QCBOR_HEAD_BUFFER_SIZE + // value
      error_message.size(); // value
    std::vector<uint8_t> output(buff_size);

    UsefulBuf output_buf{output.data(), output.size()};
    QCBOREncodeContext ectx;
    QCBOREncode_Init(&ectx, output_buf);
    QCBOREncode_OpenMap(&ectx);
    QCBOREncode_AddTextToMapN(&ectx, CBOR_ERROR_TITLE, from_string(code));
    QCBOREncode_AddTextToMapN(
      &ectx, CBOR_ERROR_DETAIL, from_string(error_message));
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

  inline std::vector<uint8_t> operation_to_cbor(GetOperation::Out& operation)
  {
    /**
     * QCBOR_HEAD_BUFFER_SIZE is for each map for each key and for each value
     * max 6 key values and 2 maps.
     * The size of data will be less than struct because error keys will shrink
     */
    size_t buff_size = sizeof(operation) + 14 * QCBOR_HEAD_BUFFER_SIZE;
    std::vector<uint8_t> output(buff_size);
    UsefulBuf output_buf{output.data(), output.size()};

    QCBOREncodeContext encode_ctx;
    QCBOREncode_Init(&encode_ctx, output_buf);
    QCBOREncode_OpenMap(&encode_ctx);

    QCBOREncode_AddTextToMap(
      &encode_ctx, "OperationId", from_string(operation.operation_id.to_str()));
    QCBOREncode_AddTextToMap(
      &encode_ctx,
      "Status",
      from_string(operationStatusToString(operation.status)));
    if (operation.entry_id.has_value())
    {
      QCBOREncode_AddTextToMap(
        &encode_ctx,
        "EntryId",
        from_string(operation.entry_id.value().to_str()));
    }
    if (operation.error.has_value())
    {
      QCBOREncode_OpenMapInMap(&encode_ctx, "Error");
      QCBOREncode_AddTextToMapN(
        &encode_ctx,
        CBOR_ERROR_TITLE,
        from_string(operation.error.value().code));
      QCBOREncode_AddTextToMapN(
        &encode_ctx,
        CBOR_ERROR_DETAIL,
        from_string(operation.error.value().message));
      QCBOREncode_CloseMap(&encode_ctx);
    }

    QCBOREncode_CloseMap(&encode_ctx);

    UsefulBufC encoded_cbor;
    QCBORError err;
    err = QCBOREncode_Finish(&encode_ctx, &encoded_cbor);
    if (err != QCBOR_SUCCESS)
    {
      throw std::logic_error("Failed to encode CBOR error");
    }
    output.resize(encoded_cbor.len);
    output.shrink_to_fit();
    return output;
  }
}
