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
  // no matching branch and no `default`). In that case rego-cpp's
  // run_entrypoint() returns the bare Undefined node instead of a Results
  // node. Previously this was passed straight into rego::Output, whose
  // constructor only expects Results: in release builds this silently led
  // to an uncaught std::out_of_range ("Index out of range") from
  // Output::expressions(), escaping as an HTTP 500 InternalError; in debug
  // builds it instead tripped an assertion, aborting the process. Either
  // way, this should now be reported as a clean 400 PolicyError.
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
