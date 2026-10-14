// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <string_view>
#include <tav/cbor.hpp>

namespace scitt
{
  /**
   * Whether text can be encoded as a CBOR text string, which RFC 8949
   * section 3.1 requires to be UTF-8 (RFC 3629). Unverified text, such as
   * request bytes quoted by an error message, must not be echoed back
   * otherwise. TAV's make_string rejects such text, so it is the reference
   * for what can be encoded.
   */
  inline bool is_valid_utf8(std::string_view text)
  {
    try
    {
      tav::cbor::make_string(text);
      return true;
    }
    catch (const tav::cbor::EncodeError&)
    {
      return false;
    }
  }
}
