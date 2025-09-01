// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <ccf/pal/attestation.h>
#include <ccf/pal/attestation_sev_snp.h>
#include <ccf/pal/uvm_endorsements.h>

namespace scitt::verifier
{
  constexpr size_t HOST_DATA_SIZE = 32;
  using HostData = std::array<uint8_t, HOST_DATA_SIZE>;
  static_assert(
    sizeof(ccf::pal::snp::Attestation::host_data) == HOST_DATA_SIZE,
    "HostData size must match Attestation host_data size");

  class VerifiedSevSnpAttestationDetails
  {
  private:
    ccf::pal::PlatformAttestationMeasurement measurement;
    ccf::pal::PlatformAttestationReportData report_data;
    std::optional<ccf::pal::UVMEndorsements> uvm_endorsements;
    HostData host_data = {0};

  public:
    VerifiedSevSnpAttestationDetails(
      ccf::pal::PlatformAttestationMeasurement measurement,
      ccf::pal::PlatformAttestationReportData report_data,
      std::optional<ccf::pal::UVMEndorsements> uvm_endorsements,
      const uint8_t host_data_[HOST_DATA_SIZE]) :
      measurement(measurement),
      report_data(report_data),
      uvm_endorsements(uvm_endorsements)
    {
      if (host_data_ == nullptr)
      {
        throw std::invalid_argument("host_data cannot be null");
      }
      std::copy(host_data_, host_data_ + HOST_DATA_SIZE, host_data.begin());
    }

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
    const HostData& get_host_data() const
    {
      return host_data;
    }
  };
}
