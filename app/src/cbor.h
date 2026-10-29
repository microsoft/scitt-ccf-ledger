// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <tav/cbor.hpp>
#include <vector>

namespace scitt::cbor
{
  static constexpr int64_t CBOR_ERROR_TITLE = -1;
  static constexpr int64_t CBOR_ERROR_DETAIL = -2;
  static constexpr const char* CBOR_ERROR_CONTENT_TYPE =
    "application/concise-problem-details+cbor";

  inline std::vector<uint8_t> as_vector(std::span<const uint8_t> bytes)
  {
    return {bytes.begin(), bytes.end()};
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
