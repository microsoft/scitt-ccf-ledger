// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "policy_engine.h"

#include <gtest/gtest.h>
#include <iostream>
#include <sstream>

namespace
{
  class ScopedStreamRedirect
  {
  private:
    std::ostream& stream;
    std::streambuf* original;

  public:
    ScopedStreamRedirect(std::ostream& stream_, std::streambuf* replacement) :
      stream(stream_),
      original(stream.rdbuf(replacement))
    {}

    ~ScopedStreamRedirect()
    {
      stream.rdbuf(original);
    }
  };

  TEST(PolicyEngineTest, InvalidRegoDoesNotWriteDirectlyToStdout)
  {
    std::ostringstream output;
    {
      ScopedStreamRedirect redirect(std::cout, output.rdbuf());

      BundleWrapper bundle;
      EXPECT_THROW(bundle.load_policy("invalid rego"), std::domain_error);
    }
    EXPECT_TRUE(output.str().empty());
  }
}