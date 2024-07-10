// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "constants.h"
#include "did/resolver.h"
#include "did/web/syntax.h"
#include "generated/constants.h"
#include "openenclave.h"
#include "util.h"

#include <algorithm>
#include <ccf/crypto/sha256_hash.h>
#include <ccf/crypto/verifier.h>
#include <ccf/ds/hex.h>
#include <ccf/ds/json.h>
#include <ccf/ds/logger.h>
#include <ccf/service/tables/cert_bundles.h>
#include <fmt/format.h>
#include <stdexcept>
#include <string>

namespace scitt::did
{
  enum class EvidenceFormat
  {
    ATTESTED_FETCH_OE_SGX_ECDSA_V2 = 0,
    ATTESTED_FETCH_VIRTUAL = 1,
  };

  static std::string to_string(EvidenceFormat format)
  {
    switch (format)
    {
      case EvidenceFormat::ATTESTED_FETCH_OE_SGX_ECDSA_V2:
        return "ATTESTED_FETCH_OE_SGX_ECDSA_V2";
      case EvidenceFormat::ATTESTED_FETCH_VIRTUAL:
        return "ATTESTED_FETCH_VIRTUAL";
      default:
        throw std::runtime_error("Unknown evidence format");
    }
  }

  DECLARE_JSON_ENUM(
    EvidenceFormat,
    {
      {
        EvidenceFormat::ATTESTED_FETCH_OE_SGX_ECDSA_V2,
        "ATTESTED_FETCH_OE_SGX_ECDSA_V2",
      },
      {
        EvidenceFormat::ATTESTED_FETCH_VIRTUAL,
        "ATTESTED_FETCH_VIRTUAL",
      },
    });

  struct AttestedResolution
  {
    EvidenceFormat format;
    std::vector<uint8_t> data;

    std::optional<std::vector<uint8_t>> evidence;
    std::optional<std::vector<uint8_t>> endorsements;

    bool operator==(const AttestedResolution& other) const = default;
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(AttestedResolution);
  DECLARE_JSON_REQUIRED_FIELDS(AttestedResolution, format, data);
  DECLARE_JSON_OPTIONAL_FIELDS(AttestedResolution, evidence, endorsements);

  // "error" field within "data" in AttestedResolution for
  // ATTESTED_FETCH_OE_SGX_ECDSA_V2
  struct AttestedFetchError // NOLINT(bugprone-exception-escape)
  {
    std::string message;

    bool operator==(const AttestedFetchError&) const = default;
  };
  // "result" field within "data" in AttestedResolution for
  // ATTESTED_FETCH_OE_SGX_ECDSA_V2
  struct AttestedFetchResult
  {
    int64_t status;
    std::vector<uint8_t> body;
    std::vector<std::string> certs;

    bool operator==(const AttestedFetchResult&) const = default;
  };
  // "data" field of AttestedResolution for ATTESTED_FETCH_OE_SGX_ECDSA_V2
  struct AttestedFetchData // NOLINT(bugprone-exception-escape)
  {
    std::string url;
    std::string nonce;
    std::optional<AttestedFetchResult> result;
    std::optional<AttestedFetchError> error;
  };

  DECLARE_JSON_TYPE(AttestedFetchResult);
  DECLARE_JSON_REQUIRED_FIELDS(AttestedFetchResult, status, body, certs);
  DECLARE_JSON_TYPE(AttestedFetchError);
  DECLARE_JSON_REQUIRED_FIELDS(AttestedFetchError, message);
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(AttestedFetchData);
  DECLARE_JSON_REQUIRED_FIELDS(AttestedFetchData, url, nonce);
  DECLARE_JSON_OPTIONAL_FIELDS(AttestedFetchData, error, result);

  struct AttestedResolutionError : public std::runtime_error
  {
    AttestedResolutionError(const std::string& msg) : std::runtime_error(msg) {}
  };

  /**
   * Verify the attestation found in a ATTESTED_FETCH_OE_SGX_ECDSA_V2 resolution
   * report.
   */
  static void verify_openenclave_attestation(
    const AttestedResolution& resolution)
  {
    if (
      !resolution.evidence.has_value() || !resolution.endorsements.has_value())
    {
      throw AttestedResolutionError(
        "Evidence or endorsements missing from attestation");
    }

    // Verify evidence and extract claims.
    oe::VerifyEvidenceResult evidence_result;
    try
    {
      evidence_result = oe::verify_evidence(
        oe::OE_UUID_SGX_ECDSA, *resolution.evidence, *resolution.endorsements);
    }
    catch (const std::exception& e)
    {
      throw AttestedResolutionError(
        fmt::format("Failed to verify Open Enclave evidence: {}", e.what()));
    }

    // Match MRENCLAVE claim against known value.
    auto mrenclave = evidence_result.claims.at("unique_id");

    std::vector<uint8_t> expected_mrenclave =
      ccf::ds::from_hex(ATTESTED_FETCH_MRENCLAVE_HEX);
    if (mrenclave != expected_mrenclave)
    {
      throw AttestedResolutionError("MRENCLAVE does not match expected value");
    }

    // Match sgx_report_data custom claim against hash of format and data.
    auto sgx_report_data = evidence_result.custom_claims.at("sgx_report_data");
    auto format_hash = ccf::crypto::Sha256Hash(to_string(resolution.format));
    auto data_hash = ccf::crypto::Sha256Hash(resolution.data);
    auto computed_sgx_report_data =
      ccf::crypto::Sha256Hash(format_hash, data_hash);
    auto computed_sgx_report_data_vec = std::vector<uint8_t>(
      computed_sgx_report_data.h.begin(), computed_sgx_report_data.h.end());
    if (sgx_report_data != computed_sgx_report_data_vec)
    {
      throw AttestedResolutionError(
        "SGX report data does not match computed hash");
    }
  }

  static DidResolutionResult verify_attested_resolution(
    const std::string& did,
    const std::string& nonce,
    ccf::CACertBundlePEMs::ReadOnlyHandle* ca_cert_bundles,
    const AttestedResolution& resolution)
  {
    // Check that the evidence format is supported, and if necessary verify the
    // attestation report.
    switch (resolution.format)
    {
#ifdef VIRTUAL_ENCLAVE
      case EvidenceFormat::ATTESTED_FETCH_VIRTUAL:
        // The "virtual" format comes without any attestation and has no
        // verifiable security guarantee. We only accept it on virtual
        // builds, which are considered insecure anyway.
        break;
#else
      case EvidenceFormat::ATTESTED_FETCH_OE_SGX_ECDSA_V2:
        verify_openenclave_attestation(resolution);
        break;
#endif

      default:
        throw AttestedResolutionError(
          fmt::format("Unsupported evidence format: {}", resolution.format));
    }

    // Parse JSON-encoded data.
    AttestedFetchData fetch_data;
    try
    {
      fetch_data =
        nlohmann::json::parse(resolution.data).get<AttestedFetchData>();
    }
    catch (const std::exception& e)
    {
      throw AttestedResolutionError(
        "Data could not be parsed as JSON according to schema.");
    }

    // Match resolution nonce against KV.
    if (nonce != fetch_data.nonce)
    {
      throw AttestedResolutionError("nonce does not match expected value");
    }

    // Check for an attested error.
    if (fetch_data.error.has_value())
    {
      std::string msg = fetch_data.error->message;
      throw AttestedResolutionError(msg);
    }

    // Else we should have a result.
    if (!fetch_data.result.has_value())
    {
      throw AttestedResolutionError("No fetch data found.");
    }

    int64_t status = fetch_data.result->status;
    if (status < 200 || status >= 300)
    {
      std::string msg =
        fmt::format("DID Resolution failed with status code: {}", status);
      throw AttestedResolutionError(msg);
    }

    // Compute DID from URL in data.
    std::string computed_did;
    try
    {
      computed_did = did::web::get_did_from_did_web_doc_url(fetch_data.url);
    }
    catch (const std::exception& e)
    {
      throw AttestedResolutionError(e.what());
    }

    // Match computed DID against endpoint 'did' URL parameter.
    if (computed_did != did)
    {
      throw AttestedResolutionError(fmt::format(
        "DID in URL does not match DID in data: {} != {}", did, computed_did));
      throw AttestedResolutionError("DID does not match URL");
    }

    // Parse HTTP body as DID document.
    DidDocument did_doc;
    try
    {
      did_doc =
        nlohmann::json::parse(fetch_data.result->body).get<did::DidDocument>();
    }
    catch (const std::exception& e)
    {
      throw AttestedResolutionError(
        "HTTP body could not be parsed as DID document.");
    }

    // Match "id" of DID document against endpoint 'did' URL parameter.
    if (did_doc.id != did)
    {
      throw AttestedResolutionError(
        "DID document ID does not match expected value");
    }

    // Load TLS Root CA certs from KV.
    // TODO: move bundle name to constants and make more specific.
    auto ca_certs = ca_cert_bundles->get("did_web_tls_roots");
    auto trusted_vec = split_x509_cert_bundle(ca_certs.value_or(""));

    // Verify TLS certificate chain against Root CAs.
    std::vector<ccf::crypto::Pem> chain_vec;
    for (auto& cert : fetch_data.result->certs)
    {
      chain_vec.push_back(ccf::crypto::Pem(cert));
    }
    if (chain_vec.empty())
    {
      throw AttestedResolutionError(
        "TLS certificates in evidence must contain at least one certificate");
    }

    auto& target_pem = chain_vec[0];
    std::vector<const ccf::crypto::Pem*> chain_ptr;
    chain_ptr.reserve(chain_vec.size() - 1);
    for (auto it = chain_vec.begin() + 1; it != chain_vec.end(); it++)
    {
      chain_ptr.push_back(&*it);
    }

    std::vector<const ccf::crypto::Pem*> trusted_ptr;
    trusted_ptr.reserve(trusted_vec.size());
    for (auto& pem : trusted_vec)
    {
      trusted_ptr.push_back(&pem);
    }

    auto verifier = ccf::crypto::make_unique_verifier(target_pem);
    if (!verifier->verify_certificate(trusted_ptr, chain_ptr))
    {
      throw AttestedResolutionError("Certificate chain is invalid");
    }

    DidWebResolutionMetadata did_web_resolution_metadata;
    did_web_resolution_metadata.tls_certs = fetch_data.result->certs;

    DidResolutionMetadata did_resolution_metadata;
    did_resolution_metadata.web = did_web_resolution_metadata;

    return {did_doc, did_resolution_metadata};
  }
}
