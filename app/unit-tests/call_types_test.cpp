// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "call_types.h"

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

namespace
{
  TEST(UtilityFunctionTest, bytesToHexToBytes)
  {
    const std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04};
    EXPECT_EQ(to_hex_string(data), "01020304");
    EXPECT_EQ(from_hex_string("01020304"), data);
  }
}