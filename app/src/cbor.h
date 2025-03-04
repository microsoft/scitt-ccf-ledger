// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <optional>
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

  inline std::vector<uint8_t> operation_props_to_cbor(
    const std::string& operation_id,
    const std::string& status,
    const std::optional<std::string>& entry_id,
    const std::optional<std::string>& error_code,
    const std::optional<std::string>& error_message)
  {
    /**
     * QCBOR_HEAD_BUFFER_SIZE is for each map for each key and for each value
     * max 6 key values in operation and 2 maps (outer and submap for error).
     * The size of data will be less than struct because error keys will shrink
     */
    size_t approx_buff_size =
      14 * QCBOR_HEAD_BUFFER_SIZE + operation_id.size() + status.size();
    if (entry_id.has_value())
    {
      approx_buff_size += entry_id.value().size();
    }
    if (error_code.has_value())
    {
      approx_buff_size += error_code.value().size();
    }
    if (error_message.has_value())
    {
      approx_buff_size += error_message.value().size();
    }
    std::vector<uint8_t> output(approx_buff_size);

    UsefulBuf output_buf{output.data(), output.size()};
    QCBOREncodeContext ectx;
    QCBOREncode_Init(&ectx, output_buf);
    QCBOREncode_OpenMap(&ectx);
    QCBOREncode_AddTextToMap(&ectx, "OperationId", from_string(operation_id));
    QCBOREncode_AddTextToMap(&ectx, "Status", from_string(status));
    if (entry_id.has_value())
    {
      QCBOREncode_AddTextToMap(&ectx, "EntryId", from_string(entry_id.value()));
    }
    if (error_code.has_value() || error_message.has_value())
    {
      QCBOREncode_OpenMapInMap(&ectx, "Error");
      if (error_code.has_value())
      {
        QCBOREncode_AddTextToMapN(
          &ectx, CBOR_ERROR_TITLE, from_string(error_code.value()));
      }
      if (error_message.has_value())
      {
        QCBOREncode_AddTextToMapN(
          &ectx, CBOR_ERROR_DETAIL, from_string(error_message.value()));
      }
      QCBOREncode_CloseMap(&ectx);
    }
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
}
