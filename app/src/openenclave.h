// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <algorithm>
#include <openenclave/attestation/custom_claims.h>
#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/attestation/verifier.h>
#include <regex>
#include <unordered_map>
#include <vector>
#if defined(INSIDE_ENCLAVE) && !defined(VIRTUAL_ENCLAVE)
#  include <openenclave/enclave.h>
#else
#  include <openenclave/host_verify.h>
#endif
#include <fmt/format.h>

namespace scitt::oe
{
  static oe_uuid_t OE_UUID_SGX_ECDSA = {OE_FORMAT_UUID_SGX_ECDSA};

  struct Claims
  {
    oe_claim_t* data = nullptr;
    size_t length = 0;

    ~Claims()
    {
      oe_free_claims(data, length);
    }
  };

  struct CustomClaims
  {
    oe_claim_t* data = nullptr;
    size_t length = 0;

    ~CustomClaims()
    {
      oe_free_custom_claims(data, length);
    }
  };

  struct VerifyEvidenceResult
  {
    std::unordered_map<std::string, std::vector<uint8_t>> claims;
    std::unordered_map<std::string, std::vector<uint8_t>> custom_claims;
  };

  static VerifyEvidenceResult verify_evidence(
    const oe_uuid_t& format_id,
    const std::vector<uint8_t>& evidence,
    const std::vector<uint8_t>& endorsements)
  {
    Claims claims;
    auto rc = oe_verify_evidence(
      &format_id,
      evidence.data(),
      evidence.size(),
      endorsements.data(),
      endorsements.size(),
      nullptr,
      0,
      &claims.data,
      &claims.length);
    if (rc != OE_OK)
    {
      throw std::runtime_error(
        fmt::format("Failed to verify evidence: {}", oe_result_str(rc)));
    }

    VerifyEvidenceResult result;

    for (size_t i = 0; i < claims.length; i++)
    {
      auto& claim = claims.data[i];
      std::string claim_name{claim.name};

      if (claim_name == OE_CLAIM_CUSTOM_CLAIMS_BUFFER)
      {
        CustomClaims custom_claims;
        rc = oe_deserialize_custom_claims(
          claim.value,
          claim.value_size,
          &custom_claims.data,
          &custom_claims.length);
        if (rc != OE_OK)
        {
          throw std::runtime_error(fmt::format(
            "Failed to deserialise custom claims: {}", oe_result_str(rc)));
        }

        for (size_t j = 0; j < custom_claims.length; j++)
        {
          auto& custom_claim = custom_claims.data[j];
          std::string custom_claim_name{custom_claim.name};
          std::vector<uint8_t> custom_claim_value{
            custom_claim.value, custom_claim.value + custom_claim.value_size};
          result.custom_claims.emplace(
            std::move(custom_claim_name), std::move(custom_claim_value));
        }
      }
      else
      {
        std::vector<uint8_t> claim_value{
          claim.value, claim.value + claim.value_size};
        result.claims.emplace(std::move(claim_name), std::move(claim_value));
      }
    }

    return result;
  }
}