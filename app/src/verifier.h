// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "cose.h"
#include "did/resolver.h"
#include "didx509cpp/didx509cpp.h"
#include "profiles.h"
#include "public_key.h"
#include "signature_algorithms.h"
#include "tracing.h"

#include <ccf/crypto/pem.h>
#include <ccf/crypto/rsa_key_pair.h>
#include <ccf/service/tables/cert_bundles.h>
#include <crypto/openssl/openssl_wrappers.h>
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
    Verifier(std::unique_ptr<did::Resolver> resolver) :
      resolver(std::move(resolver))
    {}

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

    PublicKey process_x509_profile(
      const cose::ProtectedHeader& phdr,
      ccf::kv::ReadOnlyTx& tx,
      const Configuration& configuration)
    {
      // X.509 SCITT profile validation.

      check_is_accepted_algorithm(phdr, configuration);

      if (!phdr.cty.has_value())
      {
        throw cose::COSEDecodeError("Missing cty in protected header");
      }
      if (!phdr.x5chain.has_value())
      {
        throw cose::COSEDecodeError("Missing x5chain in protected header");
      }

      auto x5chain = phdr.x5chain;

      // Verify the chain of certs against the x509 root store.
      auto roots = x509_root_store(tx);
      auto cert = verify_chain(roots, x5chain.value());
      auto key = PublicKey(cert, std::nullopt);

      return key;
    }

    void process_ietf_didx509_subprofile(
      const cose::ProtectedHeader& phdr, const std::vector<uint8_t>& data)
    {
      // NB: In later revisions of SCITT, x5chain is unprotected, and
      // only x5t is. This logic will need to authenticate x5chain[0]
      // against x5t before it can proceed to verify the signature.
      // Verify the signature as early as possible
      ccf::crypto::OpenSSL::Unique_X509 leaf =
        parse_certificate(phdr.x5chain.value()[0]);
      PublicKey key(leaf, std::nullopt);
      try
      {
        cose::verify(data, key);
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
    }

    std::tuple<
      SignedStatementProfile,
      cose::ProtectedHeader,
      cose::UnprotectedHeader>
    verify_signed_statement(
      const std::vector<uint8_t>& data,
      ccf::kv::ReadOnlyTx& tx,
      ::timespec current_time,
      const Configuration& configuration)
    {
      SignedStatementProfile profile;
      cose::ProtectedHeader phdr;
      cose::UnprotectedHeader uhdr;
      try
      {
        std::tie(phdr, uhdr) = cose::decode_headers(data);

        // Validate_profile and retrieve key.
        PublicKey key;
        if (contains_cwt_issuer(phdr))
        {
          if (
            phdr.cwt_claims.iss->starts_with("did:x509") &&
            phdr.x5chain.has_value())
          {
            // IETF SCITT did:x509 claim
            process_ietf_didx509_subprofile(phdr, data);
          }
          else
          {
            throw VerificationError(
              "Payloads with CWT_Claims must have a did:x509 iss and x5chain");
          }

          profile = SignedStatementProfile::IETF;
        }
        else if (phdr.x5chain.has_value())
        {
          // X.509 SCITT claim
          key = process_x509_profile(phdr, tx, configuration);

          try
          {
            cose::verify(data, key);
          }
          catch (const cose::COSESignatureValidationError& e)
          {
            throw VerificationError(e.what());
          }

          profile = SignedStatementProfile::X509;
        }
        else
        {
          SCITT_INFO("Unknown COSE profile");
          throw cose::COSEDecodeError("Unknown COSE profile");
        }
      }
      catch (const cose::COSEDecodeError& e)
      {
        throw VerificationError(e.what());
      }

      return std::make_tuple(profile, phdr, uhdr);
    }

    /**
     * Verify a chain of certificates against a set of trusted roots.
     *
     * The set of trusted roots should be PEM-encoded whereas the chain
     * DER-encoded.
     *
     * If successful, returns the leaf certificate. Otherwise throws a
     * VerificationError.
     */
    static ccf::crypto::OpenSSL::Unique_X509 verify_chain(
      std::span<const ccf::crypto::Pem> trusted,
      std::span<const std::vector<uint8_t>> chain)
    {
      if (chain.empty())
      {
        throw VerificationError(
          "Certificate chain must contain at least one certificate");
      }

      ccf::crypto::OpenSSL::Unique_X509 leaf = parse_certificate(chain[0]);

      ccf::crypto::OpenSSL::Unique_X509_STORE store;
      for (const auto& pem : trusted)
      {
        ccf::crypto::OpenSSL::CHECK1(
          X509_STORE_add_cert(store, parse_certificate(pem)));
      }

      ccf::crypto::OpenSSL::Unique_STACK_OF_X509 chain_stack;
      for (const auto& der : chain.subspan(1))
      {
        ccf::crypto::OpenSSL::Unique_X509 cert = parse_certificate(der);
        ccf::crypto::OpenSSL::CHECK1(sk_X509_push(chain_stack, cert));
        ccf::crypto::OpenSSL::CHECK1(X509_up_ref(cert));
      }

      ccf::crypto::OpenSSL::Unique_X509_STORE_CTX store_ctx;
      ccf::crypto::OpenSSL::CHECK1(
        X509_STORE_CTX_init(store_ctx, store, leaf, chain_stack));

      if (X509_verify_cert(store_ctx) != 1)
      {
        int err = X509_STORE_CTX_get_error(store_ctx);
        SCITT_INFO(
          "Certificate chain is invalid: {}",
          X509_verify_cert_error_string(err));
        throw VerificationError("Certificate chain is invalid");
      }

      check_certificate_policy(chain_stack, leaf);

      return leaf;
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

    /**
     * Get the set of trusted x509 CAs from the KV.
     */
    static std::vector<ccf::crypto::Pem> x509_root_store(
      ccf::kv::ReadOnlyTx& tx)
    {
      // TODO: move bundle name to constants and make more specific.
      auto ca_certs =
        tx.template ro<ccf::CACertBundlePEMs>(ccf::Tables::CA_CERT_BUNDLE_PEMS)
          ->get("x509_roots");
      if (!ca_certs.has_value())
      {
        // Internal error, not exposed to client.
        throw std::runtime_error(
          "Failed to load x509 Root CA certificates from KV");
      }
      return ccf::crypto::split_x509_cert_bundle(*ca_certs);
    }

    /**
     * Assuming a verified chain and leaf certificate, enforce additional
     * policies.
     */
    static void check_certificate_policy(STACK_OF(X509) * chain, X509* leaf)
    {
      if (sk_X509_num(chain) == 0)
      {
        throw VerificationError(
          "Certificate chain must include at least one CA certificate");
      }

      // OpenSSL doesn't require the chain to include the final trust anchor
      // certificate, since it can find it in the trust store. However, for
      // auditability reasons, it is preferable for all claims to be verifiable
      // in isolation. For this reason, we require that the last certificate of
      // the chain be self-signed.
      X509* root = sk_X509_value(chain, sk_X509_num(chain) - 1);
      if (!(X509_get_extension_flags(root) & EXFLAG_SS))
      {
        throw VerificationError("Chain root must be self-signed");
      }

      if (X509_get_extension_flags(leaf) & EXFLAG_CA)
      {
        throw VerificationError("Signing certificate is CA");
      }
    }

    std::unique_ptr<did::Resolver> resolver;
  };
}
