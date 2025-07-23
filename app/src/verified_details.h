// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <ccf/pal/attestation.h>
#include <ccf/pal/attestation_sev_snp.h>
#include <ccf/pal/uvm_endorsements.h>

namespace scitt::verifier
{
  class VerifiedSevSnpAttestationDetails
  {
  private:
    ccf::pal::PlatformAttestationMeasurement measurement;
    ccf::pal::PlatformAttestationReportData report_data;
    std::optional<ccf::pal::UVMEndorsements> uvm_endorsements;

  public:
    VerifiedSevSnpAttestationDetails() = default;
    VerifiedSevSnpAttestationDetails(
      ccf::pal::PlatformAttestationMeasurement measurement,
      ccf::pal::PlatformAttestationReportData report_data,
      std::optional<ccf::pal::UVMEndorsements> uvm_endorsements) :
      measurement(measurement),
      report_data(report_data),
      uvm_endorsements(uvm_endorsements)
    {}
    const ccf::pal::PlatformAttestationMeasurement& get_measurement() const
    {
      return measurement;
    }
    const ccf::pal::PlatformAttestationReportData& get_report_data() const
    {
      return report_data;
    }
    const std::optional<ccf::pal::UVMEndorsements>& get_uvm_endorsements() const
    {
      return uvm_endorsements;
    }
  };
}
