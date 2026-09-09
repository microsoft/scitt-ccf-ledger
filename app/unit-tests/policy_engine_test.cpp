// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "policy_engine.h"

#include "constants.h"

#include <gtest/gtest.h>
#include <iostream>
#include <sstream>
#include <stdexcept>

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

  // Regression test for a rego policy whose `policy/errors` rule is
  // undefined for a given input (e.g. a complete rule guarded by `if` with
  // no matching branch and no `default`). Previously, extracting the
  // violation message in this case threw an uncaught std::out_of_range
  // ("Index out of range") from rego-cpp's Output::expressions(), which
  // escaped as an HTTP 500 InternalError instead of a clean 400
  // PolicyError response.
  TEST(PolicyEngineTest, RegoPolicyUndefinedErrorsIsReportedGracefully)
  {
    const std::string rego_policy = R"(
package policy

default allow := false

errors := "unreachable" if { false }
)";

    scitt::cose::ProtectedHeader phdr;
    scitt::cose::UnprotectedHeader uhdr;
    std::vector<uint8_t> payload_bytes = {1, 2, 3};
    std::span<uint8_t> payload(payload_bytes);
    constexpr size_t statement_limit = 10000;

    try
    {
      scitt::check_for_policy_violations_rego(
        rego_policy,
        "test_policy",
        phdr,
        uhdr,
        payload,
        std::nullopt,
        statement_limit);
      FAIL() << "Expected a BadRequestCborError to be thrown";
    }
    catch (const scitt::HTTPError& e)
    {
      EXPECT_EQ(e.status_code, HTTP_STATUS_BAD_REQUEST);
      EXPECT_EQ(e.code, scitt::errors::PolicyError);
    }
  }
}
