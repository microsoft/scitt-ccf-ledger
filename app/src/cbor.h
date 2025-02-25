// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "tracing.h"

#include <ccf/crypto/hash_provider.h>
#include <ccf/crypto/sha256_hash.h>
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
}
