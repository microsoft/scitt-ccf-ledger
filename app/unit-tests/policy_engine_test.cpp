// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Correctness tests for the JS policy engine, with particular focus on the
// thread-local interpreter cache: the cache must transparently recompile when
// the policy source changes, and must keep producing correct accept/reject
// results across repeated invocations of the same policy.

#include "policy_engine.h"

#include "http_error.h"
#include "js_test_setup.h"

#include <gtest/gtest.h>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace
{
  scitt::cose::ProtectedHeader phdr_with_issuer(const std::string& iss)
  {
    scitt::cose::ProtectedHeader phdr;
    phdr.alg = -7; // ES256
    phdr.cwt_claims.iss = iss;
    phdr.cwt_claims.iat = 1622547800;
    return phdr;
  }

  std::optional<std::string> run_policy(
    const std::string& script, const scitt::cose::ProtectedHeader& phdr)
  {
    const scitt::cose::UnprotectedHeader uhdr;
    std::vector<uint8_t> payload_bytes = {'h', 'i'};
    std::span<uint8_t> payload(payload_bytes);
    const std::optional<scitt::verifier::VerifiedSevSnpAttestationDetails>
      details = std::nullopt;
    return scitt::check_for_policy_violations(
      script, "test_policy", phdr, uhdr, payload, details);
  }

  const std::string ACCEPT_ISSUER_A = R"js(
export function apply(phdr) {
  if (phdr.cwt.iss !== "did:example:a") { return "Invalid issuer"; }
  return true;
}
)js";

  const std::string ACCEPT_ISSUER_B = R"js(
export function apply(phdr) {
  if (phdr.cwt.iss !== "did:example:b") { return "Invalid issuer B"; }
  return true;
}
)js";
}

class PolicyEngineTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    testutils::ensure_js_initialised();
  }
};

TEST_F(PolicyEngineTest, AcceptsMatchingIssuer)
{
  auto result = run_policy(ACCEPT_ISSUER_A, phdr_with_issuer("did:example:a"));
  EXPECT_FALSE(result.has_value());
}

TEST_F(PolicyEngineTest, RejectsNonMatchingIssuerWithReason)
{
  auto result = run_policy(ACCEPT_ISSUER_A, phdr_with_issuer("did:example:x"));
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result.value(), "Invalid issuer");
}

// Repeated invocations of the same policy must reuse the cached interpreter and
// keep returning correct, independent results for different inputs.
TEST_F(PolicyEngineTest, RepeatedInvocationsAreConsistent)
{
  for (int i = 0; i < 10; ++i)
  {
    EXPECT_FALSE(run_policy(ACCEPT_ISSUER_A, phdr_with_issuer("did:example:a"))
                   .has_value());
    auto rejected =
      run_policy(ACCEPT_ISSUER_A, phdr_with_issuer("did:example:other"));
    ASSERT_TRUE(rejected.has_value());
    EXPECT_EQ(rejected.value(), "Invalid issuer");
  }
}

// Switching to a different policy source (different digest) must invalidate the
// cache and evaluate the new policy, then switching back must work too.
TEST_F(PolicyEngineTest, RecompilesWhenPolicyChanges)
{
  // Policy A accepts issuer a, rejects b.
  EXPECT_FALSE(
    run_policy(ACCEPT_ISSUER_A, phdr_with_issuer("did:example:a")).has_value());
  auto a_rejects_b =
    run_policy(ACCEPT_ISSUER_A, phdr_with_issuer("did:example:b"));
  ASSERT_TRUE(a_rejects_b.has_value());
  EXPECT_EQ(a_rejects_b.value(), "Invalid issuer");

  // Switch to policy B: now b is accepted and a is rejected with B's message.
  EXPECT_FALSE(
    run_policy(ACCEPT_ISSUER_B, phdr_with_issuer("did:example:b")).has_value());
  auto b_rejects_a =
    run_policy(ACCEPT_ISSUER_B, phdr_with_issuer("did:example:a"));
  ASSERT_TRUE(b_rejects_a.has_value());
  EXPECT_EQ(b_rejects_a.value(), "Invalid issuer B");

  // Switch back to policy A to confirm repeated invalidation works.
  EXPECT_FALSE(
    run_policy(ACCEPT_ISSUER_A, phdr_with_issuer("did:example:a")).has_value());
}

// An invalid policy module must raise a BadRequestCborError and must not poison
// the cache: a subsequent valid policy must still evaluate correctly.
TEST_F(PolicyEngineTest, InvalidPolicyThrowsAndDoesNotPoisonCache)
{
  const std::string invalid_policy = "this is not valid javascript {{{";
  EXPECT_THROW(
    run_policy(invalid_policy, phdr_with_issuer("did:example:a")),
    scitt::BadRequestCborError);

  // The cache must recover and evaluate a valid policy correctly afterwards.
  EXPECT_FALSE(
    run_policy(ACCEPT_ISSUER_A, phdr_with_issuer("did:example:a")).has_value());
}
