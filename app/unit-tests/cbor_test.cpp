// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "cbor.h"

#include "constants.h"
#include "testutils.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <stdexcept>

using namespace testing;
using namespace scitt;
using namespace testutils;

namespace
{
  TEST(CborTest, CoseKeySetToCBOR)
  {
    // Encoded COSE_Keys are copied into the array as they are
    const std::string key1 =
      "a5010202456b69642d31200121582065eda5a12577c2bae829437fe338701a10aaa375e1"
      "bb5b5de108de439c08551d2258201e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0"
      "ca7ca7e9eecd0084d19c";
    const std::string key2 = "a3010320430102032143010001";
    EXPECT_EQ(
      to_hex_string(scitt::cbor::cose_key_set_to_cbor(
        {from_hex_string(key1), from_hex_string(key2)})),
      "82" + key1 + key2);
    EXPECT_EQ(to_hex_string(scitt::cbor::cose_key_set_to_cbor({})), "80");
  }

  TEST(CborTest, ErrorRequiresValidUtf8)
  {
    // cbor_error does not sanitize: callers check unverified text with
    // is_valid_utf8 first, as HTTPError::to_cbor_error does
    EXPECT_THROW(
      scitt::cbor::cbor_error(scitt::errors::InvalidInput, "CN=\xff"),
      tav::cbor::EncodeError);
  }
}
