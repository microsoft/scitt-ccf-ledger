// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "utf8.h"

#include <gtest/gtest.h>

using namespace scitt;

namespace
{
  TEST(Utf8Test, IsValidUtf8)
  {
    EXPECT_TRUE(is_valid_utf8("plain"));
    EXPECT_TRUE(is_valid_utf8("caf\xc3\xa9"));
    EXPECT_FALSE(is_valid_utf8("caf\xc3\xa9 \xff"));
    // Surrogates are not valid UTF-8 either, see RFC 3629 section 3
    EXPECT_FALSE(is_valid_utf8("\xed\xa0\x80"));
  }
}
