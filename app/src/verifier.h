// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "cose.h"
#include "didx509cpp/didx509cpp.h"
#include "kv_types.h"
#include "profiles.h"
#include "public_key.h"
#include "signature_algorithms.h"
#include "tracing.h"
#include "verified_details.h"

#include <ccf/crypto/openssl/openssl_wrappers.h>
#include <ccf/crypto/pem.h>
#include <ccf/crypto/rsa_key_pair.h>
#include <ccf/ds/hex.h>
#include <ccf/ds/quote_info.h>
#include <ccf/pal/attestation.h>
#include <ccf/pal/attestation_sev_snp.h>
#include <ccf/pal/uvm_endorsements.h>
#include <ccf/service/tables/cert_bundles.h>
#include <fmt/format.h>

#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
#  include <openssl/core_names.h>
#  include <openssl/encoder.h>
#  include <openssl/param_build.h>
#endif

namespace scitt::verifier
{
  inline static bool contains_cwt_issuer(const cose::ProtectedHeader& phdr)
  {
    return phdr.cwt_claims.iss.has_value();
  }

  struct VerificationError : public std::runtime_error
  {
    VerificationError(const std::string& msg) : std::runtime_error(msg) {}
  };

  /**
   * The Verifier is resonsible for checking that submitted claims conform to
   * the current acceptance policy, and that their signature is valid.
   *
   * If a claim uses a DID based issuer, a did::Resolver is used to fetch the
   * relevant document and extract the signing key.
   */
  class Verifier
  {
  public:
    Verifier() = default;

    void check_is_accepted_algorithm(
      const cose::ProtectedHeader& phdr, const Configuration& configuration)
    {
      std::string_view algorithm;
      try
      {
        // We use the equivalent JOSE human-readable names in the
        // configuration, rather than the obscure integer values
        // from COSE.
        if (!phdr.alg.has_value())
        {
          throw VerificationError("Missing algorithm in protected header");
        }
        algorithm = get_jose_alg_from_cose_alg(phdr.alg.value());
      }
      catch (const InvalidSignatureAlgorithm& e)
      {
        throw VerificationError(e.what());
      }
      if (!contains(configuration.policy.get_accepted_algorithms(), algorithm))
      {
        throw VerificationError("Unsupported algorithm in protected header");
      }
    }

    std::span<uint8_t> process_signed_statement_with_didx509_issuer(
      const cose::ProtectedHeader& phdr,
      const Configuration& configuration,
      const std::vector<uint8_t>& data)
    {
      check_is_accepted_algorithm(phdr, configuration);

      // Verify the signature using the key of the leaf in the x5chain
      ccf::crypto::OpenSSL::Unique_X509 leaf =
        parse_certificate(phdr.x5chain.value()[0]);
      PublicKey key(leaf, std::nullopt);
      std::span<uint8_t> payload;
      try
      {
        payload = cose::verify(data, key);
      }
      catch (const cose::COSESignatureValidationError& e)
      {
        throw VerificationError(e.what());
      }

      // Then authenticate the did:x509 claim against the x5chain
      std::string pem_chain;
      for (auto const& c : phdr.x5chain.value())
      {
        pem_chain += ccf::crypto::cert_der_to_pem(c).str();
      }
      auto did_document_str = didx509::resolve(
        pem_chain,
        phdr.cwt_claims.iss.value(),
        true /* Do not validate time */);
      scitt::did::alt::DIDDocument did_document =
        nlohmann::json::parse(did_document_str);

      if (did_document.verification_method.empty())
      {
        throw VerificationError(
          "Could not find verification method in resolved DID "
          "document");
      }
      // x5chain has a single leaf certificate, so the verification
      // method should also have a single key
      if (did_document.verification_method.size() != 1)
      {
        throw VerificationError(
          "Unexpected number of verification methods in resolved DID "
          "document");
      }
      auto const& vm = did_document.verification_method[0];
      if (vm.controller != phdr.cwt_claims.iss.value())
      {
        throw VerificationError(
          "Verification method controller does not match issuer");
      }

      if (!vm.public_key_jwk.has_value())
      {
        throw VerificationError(
          "Verification method does not contain a public key");
      }

      auto resolved_jwk =
        vm.public_key_jwk.value().get<ccf::crypto::JsonWebKey>();
      auto signing_key_pem =
        ccf::crypto::make_verifier(phdr.x5chain.value()[0])->public_key_pem();
      ccf::crypto::Pem resolved_pem;

      switch (resolved_jwk.kty)
      {
        case ccf::crypto::JsonWebKeyType::EC:
        {
          {
            auto specific_jwk =
              vm.public_key_jwk.value().get<ccf::crypto::JsonWebKeyECPublic>();
            resolved_pem =
              ccf::crypto::make_public_key(specific_jwk)->public_key_pem();
          }
          break;
        }
        case ccf::crypto::JsonWebKeyType::RSA:
        {
          {
            auto specific_jwk =
              vm.public_key_jwk.value().get<ccf::crypto::JsonWebKeyRSAPublic>();
            resolved_pem =
              ccf::crypto::make_rsa_public_key(specific_jwk)->public_key_pem();
          }
          break;
        }
        default:
        {
          throw VerificationError(fmt::format(
            "Verification method public key (kty: {}) is unsupported",
            resolved_jwk.kty));
        }
      }

      if (resolved_pem != signing_key_pem)
      {
        throw VerificationError(
          "Resolved verification method public key does not match signing key");
      }

      return payload;
    }

    std::tuple<std::span<uint8_t>, VerifiedSevSnpAttestationDetails>
    process_signed_statement_with_didattestedsvc_issuer(
      const cose::ProtectedHeader& phdr,
      const Configuration& configuration,
      const std::vector<uint8_t>& data)
    {
      check_is_accepted_algorithm(phdr, configuration);

      if (!phdr.tss_map.cose_key.has_value())
      {
        throw VerificationError(fmt::format(
          "Signed statement protected header {} must contain a COSE key",
          cose::COSE_HEADER_PARAM_TSS));
      }

      if (!phdr.kid.has_value())
      {
        throw VerificationError("Protected header KID is missing");
      }
      auto cose_key_thumb = phdr.tss_map.cose_key->to_sha256_thumb();
      std::vector<uint8_t> kid_bytes(phdr.kid->begin(), phdr.kid->end());
      if (!std::equal(
            cose_key_thumb.begin(),
            cose_key_thumb.end(),
            kid_bytes.begin(),
            kid_bytes.end()))
      {
        throw VerificationError("COSE key thumbprint does not match KID");
      }

      PublicKey public_key = phdr.tss_map.cose_key->to_public_key();

      // First verify the signature to then trust the structure integrity
      // and the attestation contained in the protected header.
      std::span<uint8_t> payload;
      try
      {
        // ignore unknown critical headers due to the presence of a custom TSS
        // header
        payload = cose::verify(data, public_key, true);
      }
      catch (const cose::COSESignatureValidationError& e)
      {
        throw VerificationError(fmt::format(
          "Failed to validate cose signature using the COSE key: {}",
          e.what()));
      }

      // Verify the attestation report contained in the protected header
      // against the AMD certificate chain contained in “snp_endorsements”.
      // see
      // https://github.com/microsoft/CCF/blob/afc7ef5eca00d413474de47f91a1827f16618de6/src/js/extensions/snp_attestation.cpp#L35
      ccf::QuoteInfo quote_info = {};
      quote_info.format = ccf::QuoteFormat::amd_sev_snp_v1;
      quote_info.quote = phdr.tss_map.attestation.value();
      quote_info.endorsements = phdr.tss_map.snp_endorsements.value();

      ccf::pal::PlatformAttestationMeasurement measurement = {};
      ccf::pal::PlatformAttestationReportData report_data = {};
      std::optional<ccf::pal::UVMEndorsements> parsed_uvm_endorsements;

      try
      {
        ccf::pal::verify_snp_attestation_report(
          quote_info, measurement, report_data);
      }
      catch (const std::exception& e)
      {
        throw VerificationError(fmt::format(
          "Failed to validate SNP attestation report: {}", e.what()));
      }

      if (phdr.tss_map.uvm_endorsements.has_value())
      {
        try
        {
          parsed_uvm_endorsements =
            ccf::pal::verify_uvm_endorsements_descriptor(
              phdr.tss_map.uvm_endorsements.value(), measurement);
        }
        catch (const std::exception& e)
        {
          throw VerificationError(
            fmt::format("Failed to validate UVM endorsements: {}", e.what()));
        }
      }

      const auto* snp_attestation =
        reinterpret_cast<const ccf::pal::snp::Attestation*>(
          quote_info.quote.data());

      VerifiedSevSnpAttestationDetails details(
        measurement,
        report_data,
        parsed_uvm_endorsements,
        snp_attestation->host_data);

      // Now check that the attestation report data matches the cose key
      // This allows us to verify that the enclave knew about the key
      if (report_data.data.size() < 32)
      {
        throw VerificationError(fmt::format(
          "Report data length is less than 32 bytes: {}",
          report_data.data.size()));
      }

      std::vector<uint8_t> cose_key_hash;
      try
      {
        cose_key_hash = phdr.tss_map.cose_key->to_sha256_thumb();
      }
      catch (const std::exception& e)
      {
        throw VerificationError(
          fmt::format("Failed to compute COSE key hash: {}", e.what()));
      }

      // create a span of data which starts with cose_key_hash bytes and then is
      // padded with zeros to match the report data bytes
      if (cose_key_hash.size() > report_data.data.size())
      {
        throw VerificationError(fmt::format(
          "COSE key hash size {} is larger than report data size {}",
          cose_key_hash.size(),
          report_data.data.size()));
      }
      if (cose_key_hash.size() < report_data.data.size())
      {
        cose_key_hash.resize(report_data.data.size(), 0);
      }

      if (!std::equal(
            cose_key_hash.begin(),
            cose_key_hash.end(),
            report_data.data.begin(),
            report_data.data.end()))
      {
        throw VerificationError(fmt::format(
          "COSE key hash does not match report data: "
          "COSE key hash: {}, report data: {}",
          ccf::ds::to_hex(cose_key_hash),
          ccf::ds::to_hex(report_data.data)));
      }

      return {payload, details};
    }

    std::tuple<
      cose::ProtectedHeader,
      cose::UnprotectedHeader,
      std::span<uint8_t>,
      VerifiedSevSnpAttestationDetails>
    verify_signed_statement(
      const std::vector<uint8_t>& signed_statement,
      ccf::kv::ReadOnlyTx& tx,
      ::timespec current_time,
      const Configuration& configuration)
    {
      cose::ProtectedHeader phdr;
      cose::UnprotectedHeader uhdr;
      std::span<uint8_t> payload;
      VerifiedSevSnpAttestationDetails details;
      try
      {
        std::tie(phdr, uhdr) = cose::decode_headers(signed_statement);

        if (contains_cwt_issuer(phdr))
        {
          if (phdr.cwt_claims.iss->starts_with("did:x509"))
          {
            if (!phdr.x5chain.has_value())
            {
              throw VerificationError(
                "Signed statement protected header must contain an x5chain");
            }

            payload = process_signed_statement_with_didx509_issuer(
              phdr, configuration, signed_statement);
          }
          else if (phdr.cwt_claims.iss->starts_with("did:attestedsvc"))
          {
            if (
              !phdr.tss_map.attestation.has_value() ||
              !phdr.tss_map.snp_endorsements.has_value() ||
              !phdr.tss_map.uvm_endorsements.has_value())
            {
              throw VerificationError(fmt::format(
                "Signed statement protected header must contain a {} map with "
                "{}, {}, {}, {}",
                cose::COSE_HEADER_PARAM_TSS,
                cose::COSE_HEADER_PARAM_TSS_ATTESTATION,
                cose::COSE_HEADER_PARAM_TSS_SNP_ENDORSEMENTS,
                cose::COSE_HEADER_PARAM_TSS_UVM_ENDORSEMENTS,
                cose::COSE_HEADER_PARAM_TSS_COSE_KEY));
            }
            std::tie(payload, details) =
              process_signed_statement_with_didattestedsvc_issuer(
                phdr, configuration, signed_statement);
          }
          else
          {
            throw VerificationError("CWT_Claims issuer is unsupported");
          }
        }
        else
        {
          throw VerificationError(
            "Signed statement protected header must contain CWT_Claims with at "
            "least an issuer");
        }
      }
      catch (const cose::COSEDecodeError& e)
      {
        throw VerificationError(e.what());
      }

      return {phdr, uhdr, payload, details};
    }

  private:
    /** Parse a PEM certificate */
    static ccf::crypto::OpenSSL::Unique_X509 parse_certificate(
      const ccf::crypto::Pem& pem)
    {
      ccf::crypto::OpenSSL::Unique_BIO bio(pem);
      ccf::crypto::OpenSSL::Unique_X509 cert(bio, true);
      if (!cert)
      {
        unsigned long ec = ERR_get_error();
        SCITT_INFO(
          "Could not parse PEM certificate: {}",
          ccf::crypto::OpenSSL::error_string(ec));
        throw VerificationError("Could not parse certificate");
      }
      return cert;
    }

    /** Parse a DER certificate */
    static ccf::crypto::OpenSSL::Unique_X509 parse_certificate(
      std::span<const uint8_t> der)
    {
      ccf::crypto::OpenSSL::Unique_BIO bio(der.data(), der.size());
      ccf::crypto::OpenSSL::Unique_X509 cert(bio, false);
      if (!cert)
      {
        unsigned long ec = ERR_get_error();
        SCITT_INFO(
          "Could not parse DER certificate: {}",
          ccf::crypto::OpenSSL::error_string(ec));
        throw VerificationError("Could not parse certificate");
      }
      return cert;
    }
  };
}
