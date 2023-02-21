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
    ATTESTED_FETCH_OE_SGX_ECDSA = 0
  };

  std::string to_string(EvidenceFormat format)
  {
    switch (format)
    {
      case EvidenceFormat::ATTESTED_FETCH_OE_SGX_ECDSA:
        return "ATTESTED_FETCH_OE_SGX_ECDSA";
      default:
        throw std::runtime_error("Unknown evidence format");
    }
  }

  DECLARE_JSON_ENUM(
    EvidenceFormat,
    {{EvidenceFormat::ATTESTED_FETCH_OE_SGX_ECDSA,
      "ATTESTED_FETCH_OE_SGX_ECDSA"}});

  struct AttestedResolution
  {
    EvidenceFormat format;
    std::string evidence;
    std::string endorsements;
    std::string data;

    bool operator==(const AttestedResolution& other) const = default;
  };

  DECLARE_JSON_TYPE(AttestedResolution);
  DECLARE_JSON_REQUIRED_FIELDS(
    AttestedResolution, format, evidence, endorsements, data);

  // "data" field of AttestedResolution for ATTESTED_FETCH_OE_SGX_ECDSA
  struct AttestedFetchData
  {
    std::string url;
    std::string nonce;
    std::vector<std::string> certs;
    std::string body;
  };
  DECLARE_JSON_TYPE(AttestedFetchData);
  DECLARE_JSON_REQUIRED_FIELDS(AttestedFetchData, url, nonce, certs, body);

  struct AttestedResolutionError : public std::runtime_error
  {
    AttestedResolutionError(const std::string& msg) : std::runtime_error(msg) {}
  };

  DidResolutionResult verify_attested_resolution(
    const std::string& did,
    const std::string& nonce,
    ccf::CACertBundlePEMs::ReadOnlyHandle* ca_cert_bundles,
    const AttestedResolution& resolution)
  {
    // Check that the evidence format is supported.
    // For now, only a single format is supported.
    if (resolution.format != EvidenceFormat::ATTESTED_FETCH_OE_SGX_ECDSA)
    {
      throw AttestedResolutionError(
        fmt::format("Unsupported evidence format: {}", resolution.format));
    }

    // Decode Base64-encoded evidence and endorsements.
    std::vector<uint8_t> evidence;
    std::vector<uint8_t> endorsements;
    try
    {
      evidence = crypto::raw_from_b64(resolution.evidence);
      endorsements = crypto::raw_from_b64(resolution.endorsements);
    }
    catch (const std::exception& e)
    {
      throw AttestedResolutionError(
        "Evidence and/or endorsements are not valid Base64-encoded data.");
    }

    // Verify evidence and extract claims.
    oe::VerifyEvidenceResult evidence_result;
    try
    {
      evidence_result =
        oe::verify_evidence(oe::OE_UUID_SGX_ECDSA, evidence, endorsements);
    }
    catch (const std::exception& e)
    {
      throw AttestedResolutionError(
        fmt::format("Failed to verify Open Enclave evidence: {}", e.what()));
    }

    // Match MRENCLAVE claim against known value.
    auto mrenclave = evidence_result.claims.at("unique_id");

    std::vector<uint8_t> expected_mrenclave =
      ds::from_hex(ATTESTED_FETCH_MRENCLAVE_HEX);
    if (mrenclave != expected_mrenclave)
    {
      throw AttestedResolutionError("MRENCLAVE does not match expected value");
    }

    // Decode Base64-encoded data.
    std::vector<uint8_t> data;
    try
    {
      data = crypto::raw_from_b64(resolution.data);
    }
    catch (const std::exception& e)
    {
      throw AttestedResolutionError("Data is not valid Base64-encoded.");
    }

    // Match sgx_report_data custom claim against hash of format and data.
    auto sgx_report_data = evidence_result.custom_claims.at("sgx_report_data");
    auto format_hash = crypto::Sha256Hash(to_string(resolution.format));
    auto data_hash = crypto::Sha256Hash(data);
    auto computed_sgx_report_data = crypto::Sha256Hash(format_hash, data_hash);
    auto computed_sgx_report_data_vec = std::vector<uint8_t>(
      computed_sgx_report_data.h.begin(), computed_sgx_report_data.h.end());
    if (sgx_report_data != computed_sgx_report_data_vec)
    {
      throw AttestedResolutionError(
        "SGX report data does not match computed hash");
    }

    // Parse JSON-encoded data.
    AttestedFetchData fetch_data;
    try
    {
      fetch_data = nlohmann::json::parse(data).get<AttestedFetchData>();
    }
    catch (const std::exception& e)
    {
      throw AttestedResolutionError(
        "Data could not be parsed as JSON according to schema.");
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

    // Match resolution nonce against KV.
    if (nonce != fetch_data.nonce)
    {
      throw AttestedResolutionError("nonce does not match expected value");
    }

    // Decode Base64-encoded HTTP body in data.
    std::vector<uint8_t> body;
    try
    {
      body = crypto::raw_from_b64(fetch_data.body);
    }
    catch (const std::exception& e)
    {
      throw AttestedResolutionError("HTTP body is not valid Base64-encoded.");
    }

    // Parse HTTP body as DID document.
    DidDocument did_doc;
    try
    {
      did_doc = nlohmann::json::parse(body).get<did::DidDocument>();
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
    if (!ca_certs.has_value())
    {
      // Internal error, not exposed to client.
      throw std::runtime_error(
        "Failed to load TLS Root CA certificates from KV");
    }
    auto trusted_vec = split_x509_cert_bundle(*ca_certs);

    // Verify TLS certificate chain against Root CAs.
    std::vector<crypto::Pem> chain_vec;
    for (auto& cert : fetch_data.certs)
    {
      chain_vec.push_back(crypto::Pem(cert));
    }
    if (chain_vec.empty())
    {
      throw AttestedResolutionError(
        "TLS certificates in evidence must contain at least one certificate");
    }

    auto& target_pem = chain_vec[0];
    std::vector<const crypto::Pem*> chain_ptr;
    for (auto it = chain_vec.begin() + 1; it != chain_vec.end(); it++)
      chain_ptr.push_back(&*it);
    std::vector<const crypto::Pem*> trusted_ptr;
    for (auto& pem : trusted_vec)
      trusted_ptr.push_back(&pem);

    auto verifier = crypto::make_unique_verifier(target_pem);
    if (!verifier->verify_certificate(trusted_ptr, chain_ptr))
      throw AttestedResolutionError("Certificate chain is invalid");

    DidWebResolutionMetadata did_web_resolution_metadata;
    did_web_resolution_metadata.tls_certs = fetch_data.certs;

    DidResolutionMetadata did_resolution_metadata;
    did_resolution_metadata.web = did_web_resolution_metadata;

    return {did_doc, did_resolution_metadata};
  }
}
