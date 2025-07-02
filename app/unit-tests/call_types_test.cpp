// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "call_types.h"

#include "cbor.h"
#include "testutils.h"

#include <cstdlib>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <iostream>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>
#include <vector>

using namespace testing;
using namespace scitt;
using namespace testutils;

// The error should look like the one in RFC, OperationId is not shown in RFC
// but we always render it:
// {
//   / id /     "OperationId": "1.2",
//   / status / "Status": "failed",
//   / error /  "Error": {
//     / title /         -1: \
//             "Bad Signature Algorithm",
//     / detail /        -2: \
//             "Signed Statement contained a non supported algorithm"
//   }
// }
const std::string expected_error_hex =
  "a36b4f7065726174696f6e496463312e3266537461747573666661696c6564654572726f72a2"
  "2077426164205369676e617475726520416c676f726974686d2178345369676e656420537461"
  "74656d656e7420636f6e7461696e65642061206e6f6e20737570706f7274656420616c676f72"
  "6974686d";

namespace
{
  TEST(UtilityFunctionTest, bytesToHexToBytes)
  {
    const std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04};
    EXPECT_EQ(to_hex_string(data), "01020304");
    EXPECT_EQ(from_hex_string("01020304"), data);
  }

  TEST(GetOperationOutTest, CBORSerializationWithStatusRunning)
  {
    const GetOperation::Out out{
      .operation_id = ccf::TxID{1, 2},
      .status = OperationStatus::Running,
    };

    const std::vector<uint8_t> cbor_value = operation_to_cbor(out);

    EXPECT_EQ(
      to_hex_string(cbor_value),
      "a26b4f7065726174696f6e496463312e32665374617475736772756e6e696e67");
  }

  TEST(GetOperationOutTest, CBORSerializationWithNestedError)
  {
    const GetOperation::Out out{
      .operation_id = ccf::TxID{1, 2},
      .status = OperationStatus::Failed,
      .error = ODataError{
        .code = "Bad Signature Algorithm",
        .message = "Signed Statement contained a non supported algorithm"}};

    const std::vector<uint8_t> cbor_value = operation_to_cbor(out);

    EXPECT_EQ(to_hex_string(cbor_value), expected_error_hex);
  }
}