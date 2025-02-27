// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <qcbor/UsefulBuf.h>
#include <qcbor/qcbor_encode.h>
#include <span>
#include <string_view>

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
    std::string code, std::string error_message)
  {
    // The size of the buffer must be equal or larger than the data,
    // otherwise decodign will fail
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
}
