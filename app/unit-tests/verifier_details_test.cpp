// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "testutils.h"
#include "verified_details.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using namespace testing;
using namespace scitt;
using namespace testutils;

namespace
{
  // NOLINTBEGIN(bugprone-unchecked-optional-access)
  TEST(VerifierDetailsTest, CheckIsEmpty)
  {
    verifier::VerifiedSevSnpAttestationDetails details;
    EXPECT_TRUE(details.is_empty());

    details = verifier::VerifiedSevSnpAttestationDetails(
      ccf::pal::PlatformAttestationMeasurement(),
      ccf::pal::PlatformAttestationReportData(),
      std::nullopt);
    EXPECT_TRUE(details.is_empty());

    ccf::pal::AttestationMeasurement<4> measurement("abababab");
    details = verifier::VerifiedSevSnpAttestationDetails(
      ccf::pal::PlatformAttestationMeasurement(measurement),
      ccf::pal::PlatformAttestationReportData(),
      std::nullopt);
    EXPECT_FALSE(details.is_empty());
  }
  // NOLINTEND(bugprone-unchecked-optional-access)

}