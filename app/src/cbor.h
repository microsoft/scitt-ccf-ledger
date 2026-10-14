// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <optional>
#include <qcbor/UsefulBuf.h>
#include <qcbor/qcbor_encode.h>
#include <span>
#include <stdexcept>
#include <string_view>
#include <tav/cbor.hpp>
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

  inline std::string_view as_string(UsefulBufC buf)
  {
    return {static_cast<const char*>(buf.ptr), buf.len};
  }

  /**
   * A CBOR-encoded byte array.
   * Follow rfc9290 for error encoding but use only
   * title and detail and encode them cbor text.
   * Both must be valid UTF-8 (RFC 8949 section 3.1): callers check unverified
   * text, such as an exception message or a request parameter, with
   * is_valid_utf8 first and do not echo it back otherwise.
   */
  inline std::vector<uint8_t> cbor_error(
    const std::string& code, const std::string& error_message)
  {
    using namespace tav::cbor;
    std::vector<MapItem> fields;
    fields.emplace_back(make_signed(CBOR_ERROR_TITLE), make_string(code));
    fields.emplace_back(
      make_signed(CBOR_ERROR_DETAIL), make_string(error_message));
    return make_map(std::move(fields)).nondet_serialize();
  }

  inline std::vector<uint8_t> operation_props_to_cbor(
    const std::string& operation_id,
    const std::string& status,
    const std::optional<std::string>& entry_id,
    const std::optional<std::string>& error_code,
    const std::optional<std::string>& error_message)
  {
    using namespace tav::cbor;
    // All inputs are valid UTF-8 already: the IDs are TxID strings, the status
    // is an enum name, the error code is an errors:: constant and the error
    // message was JSON-serialised into the operations table, which rejects
    // invalid UTF-8.

    // Entries are serialized in insertion order.
    std::vector<MapItem> fields;
    fields.emplace_back(make_string("OperationId"), make_string(operation_id));
    fields.emplace_back(make_string("Status"), make_string(status));
    if (entry_id.has_value())
    {
      fields.emplace_back(
        make_string("EntryId"), make_string(entry_id.value()));
    }
    if (error_code.has_value() || error_message.has_value())
    {
      std::vector<MapItem> error;
      if (error_code.has_value())
      {
        error.emplace_back(
          make_signed(CBOR_ERROR_TITLE), make_string(error_code.value()));
      }
      if (error_message.has_value())
      {
        error.emplace_back(
          make_signed(CBOR_ERROR_DETAIL), make_string(error_message.value()));
      }
      fields.emplace_back(make_string("Error"), make_map(std::move(error)));
    }
    return make_map(std::move(fields)).nondet_serialize();
  }

  // see https://www.ietf.org/rfc/rfc9679.html#section-4.2
  inline std::vector<uint8_t> ec_cose_key_to_cbor(
    const int64_t kty,
    const int64_t crv,
    const std::vector<uint8_t>& x,
    const std::vector<uint8_t>& y)
  {
    /**
     * QCBOR_HEAD_BUFFER_SIZE is for each map for each key and for each value
     */
    size_t approx_buff_size = (1 + 4 + 4) * QCBOR_HEAD_BUFFER_SIZE +
      sizeof(kty) + sizeof(crv) + x.size() + y.size();
    std::vector<uint8_t> output(approx_buff_size);

    UsefulBuf output_buf{output.data(), output.size()};
    QCBOREncodeContext ectx;
    QCBOREncode_Init(&ectx, output_buf);
    QCBOREncode_OpenMap(&ectx);
    QCBOREncode_AddInt64ToMapN(&ectx, 1, kty);
    QCBOREncode_AddInt64ToMapN(&ectx, -1, crv);
    QCBOREncode_AddBytesToMapN(&ectx, -2, from_bytes(x));
    QCBOREncode_AddBytesToMapN(&ectx, -3, from_bytes(y));
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

  // see https://www.ietf.org/rfc/rfc9679.html#section-4.3
  inline std::vector<uint8_t> rsa_cose_key_to_cbor(
    const int64_t kty,
    const std::vector<uint8_t>& n,
    const std::vector<uint8_t>& e)
  {
    /**
     * QCBOR_HEAD_BUFFER_SIZE is for each map for each key and for each value
     */
    size_t approx_buff_size =
      (1 + 3 + 3) * QCBOR_HEAD_BUFFER_SIZE + sizeof(kty) + n.size() + e.size();
    std::vector<uint8_t> output(approx_buff_size);

    UsefulBuf output_buf{output.data(), output.size()};
    QCBOREncodeContext ectx;
    QCBOREncode_Init(&ectx, output_buf);
    QCBOREncode_OpenMap(&ectx);
    QCBOREncode_AddInt64ToMapN(&ectx, 1, kty);
    QCBOREncode_AddBytesToMapN(&ectx, -1, from_bytes(n));
    QCBOREncode_AddBytesToMapN(&ectx, -2, from_bytes(e));
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

  /**
   * Encode a COSE_Key_Set (array of COSE_Key) to CBOR.
   * See RFC 9052 Section 7.
   */
  inline std::vector<uint8_t> cose_key_set_to_cbor(
    const std::vector<std::vector<uint8_t>>& cose_keys)
  {
    std::vector<tav::cbor::Value> keys;
    keys.reserve(cose_keys.size());
    for (const auto& key : cose_keys)
    {
      keys.push_back(tav::cbor::nondet_parse(key));
    }
    return tav::cbor::make_array(std::move(keys)).nondet_serialize();
  }
}
