// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Micro-benchmark for the JavaScript policy evaluation path
// (scitt::check_for_policy_violations). It measures the per-call cost of
// applying a JS policy to a signed statement's headers, which runs on every
// POST /entries submission.
//
// It is gated behind the SCITT_RUN_POLICY_BENCH environment variable so it does
// not slow down the regular unit-test run. To execute it:
//
//   SCITT_RUN_POLICY_BENCH=1 ./unit_tests \
//     --gtest_filter='PolicyEnginePerf.*'

#include "js_test_setup.h"
#include "policy_engine.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <gtest/gtest.h>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace
{
  // A representative JS policy: validate the CWT issuer, matching the shape of
  // the policies exercised by test/test_perf.py and DEVELOPMENT.md.
  const std::string POLICY_SCRIPT = R"js(
export function apply(phdr) {
  if (phdr.cwt === undefined || phdr.cwt.iss === undefined) {
    return "Issuer not found";
  }
  if (phdr.cwt.iss !== "did:example:issuer") {
    return "Invalid issuer";
  }
  if (phdr.cwt.iat === undefined || phdr.cwt.iat < 0) {
    return "Invalid iat";
  }
  return true;
}
)js";

  scitt::cose::ProtectedHeader make_phdr()
  {
    scitt::cose::ProtectedHeader phdr;
    phdr.alg = -7; // ES256
    phdr.cwt_claims.iss = "did:example:issuer";
    phdr.cwt_claims.sub = "did:example:subject";
    phdr.cwt_claims.iat = 1622547800;
    return phdr;
  }

  double time_policy_calls(size_t iterations)
  {
    const auto phdr = make_phdr();
    const scitt::cose::UnprotectedHeader uhdr;
    std::vector<uint8_t> payload_bytes = {'h', 'e', 'l', 'l', 'o'};
    std::span<uint8_t> payload(payload_bytes);
    const std::optional<scitt::verifier::VerifiedSevSnpAttestationDetails>
      details = std::nullopt;

    const auto start = std::chrono::steady_clock::now();
    for (size_t i = 0; i < iterations; ++i)
    {
      auto violation = scitt::check_for_policy_violations(
        POLICY_SCRIPT, "perf_policy", phdr, uhdr, payload, details);
      // The policy must accept this statement; abort if not, so the benchmark
      // never silently measures an error path.
      if (violation.has_value())
      {
        throw std::runtime_error(
          "Policy unexpectedly rejected statement: " + violation.value());
      }
    }
    const auto end = std::chrono::steady_clock::now();
    const auto total_us =
      std::chrono::duration_cast<std::chrono::microseconds>(end - start)
        .count();
    return static_cast<double>(total_us) / static_cast<double>(iterations);
  }
}

TEST(PolicyEnginePerf, JsPolicyEvaluationLatency)
{
  if (std::getenv("SCITT_RUN_POLICY_BENCH") == nullptr)
  {
    GTEST_SKIP() << "Set SCITT_RUN_POLICY_BENCH=1 to run this benchmark";
  }

  // The JS class IDs are registered exactly once per process during node
  // start-up in production; replicate that here so a JS Context can be built.
  testutils::ensure_js_initialised();

  constexpr size_t WARMUP = 5;
  constexpr size_t ITERATIONS = 200;

  // Warm up (e.g. thread-local lazy initialisation) before measuring.
  time_policy_calls(WARMUP);

  const double mean_us = time_policy_calls(ITERATIONS);

  // Machine-readable line for before/after comparison.
  std::printf(
    "POLICY_BENCH js_policy_mean_us=%.2f iterations=%zu\n",
    mean_us,
    ITERATIONS);
  std::fflush(stdout);
}
