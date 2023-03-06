// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "cose.h"
#include "did/resolver.h"
#include "openssl_wrappers.h"
#include "profiles.h"
#include "public_key.h"
#include "signature_algorithms.h"
#include "tracing.h"

#include <ccf/service/tables/cert_bundles.h>
#include <fmt/format.h>

namespace scitt::verifier
{
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

    PublicKey process_ietf_profile(
      const cose::ProtectedHeader& phdr,
      kv::ReadOnlyTx& tx,
      ::timespec current_time,
      std::chrono::seconds resolution_cache_expiry,
      const Configuration& configuration)
    {
      // IETF SCITT profile validation.

      check_is_accepted_algorithm(phdr, configuration);

      if (!phdr.cty.has_value())
      {
        throw cose::COSEDecodeError("Missing cty in protected header");
      }

      auto issuer = phdr.issuer;
      auto kid = phdr.kid;

      if (!issuer.has_value())
      {
        throw cose::COSEDecodeError("Missing issuer in protected header");
      }
      if (!configuration.policy.is_accepted_issuer(issuer.value()))
      {
        throw VerificationError("Unsupported DID issuer in protected header");
      }

      std::optional<std::string> assertion_method_id;

      if (kid.has_value())
      {
        if (!kid.value().starts_with("#"))
        {
          throw VerificationError("kid must start with '#'.");
        }
        assertion_method_id = fmt::format("{}{}", issuer.value(), kid.value());
      }

      auto resolution_options = did::DidResolutionOptions{
        .current_time = current_time,
        .did_web_options = did::DidWebOptions{
          .tx = tx,
          .max_age = resolution_cache_expiry,
          .if_assertion_method_id_match = assertion_method_id}};

      // Perform DID resolution for the given issuer.
      // Note: Any DIDResolutionError is expected to be handled by the caller.
      auto resolution = resolver->resolve(issuer.value(), resolution_options);

      // Locate the right JWK in the resolved DID document.
      did::Jwk jwk;
      try
      {
        jwk = did::find_assertion_method_jwk_in_did_document(
          resolution.did_doc, assertion_method_id);
      }
      catch (const did::DIDAssertionMethodError& e)
      {
        throw VerificationError(e.what());
      }

      // Convert the JWK into something we can actually use.
      auto key = get_jwk_public_key(jwk);

      return key;
    }

    PublicKey process_x509_profile(
      const cose::ProtectedHeader& phdr,
      kv::ReadOnlyTx& tx,
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

    void validate_notary_protected_header(
      const cose::ProtectedHeader& phdr, const Configuration& configuration)
    {
      auto cty = phdr.cty;
      auto notary_signing_scheme = phdr.notary_signing_scheme;
      auto notary_signing_time = phdr.notary_signing_time;
      auto notary_authentic_signing_time = phdr.notary_authentic_signing_time;
      auto notary_expiry = phdr.notary_expiry;

      // alg, crit, cty, io.cncf.notary.signingScheme are required.

      check_is_accepted_algorithm(phdr, configuration);

      if (!phdr.crit.has_value())
      {
        throw cose::COSEDecodeError("Missing crit in protected header");
      }
      if (!cty.has_value())
      {
        throw cose::COSEDecodeError("Missing cty in protected header");
      }
      if (!notary_signing_scheme.has_value())
      {
        throw cose::COSEDecodeError(
          "Missing io.cncf.notary.signingScheme in protected header");
      }
      auto crit = phdr.crit.value();

      // decode_protected_header checks crit is not empty

      // TODO: Replace all of this critical param checking once t_cose properly
      // supports custom header parameters in crit.
      for (const auto& crit_param : crit)
      {
        if (!phdr.is_known(crit_param, cose::NOTARY_HEADER_PARAMS))
        {
          SCITT_INFO("Unknown critical parameter: {}", crit_param);
          throw cose::COSEDecodeError("Unknown parameter found in crit");
        }
        else if (!phdr.is_present(crit_param))
        {
          SCITT_INFO(
            "Critical parameter {} missing from protected header",
            crit_param);
          throw cose::COSEDecodeError(
            "Critial parameter missing from protected header");
        }
      }

      if (!phdr.is_critical("io.cncf.notary.signingScheme"))
      {
        throw cose::COSEDecodeError(
          "crit must contain 'io.cncf.notary.signingScheme'");
      }

      if (
        !std::holds_alternative<std::string>(cty.value()) ||
        std::get<std::string>(cty.value()) !=
          "application/vnd.cncf.notary.payload.v1+json")
      {
        throw cose::COSEDecodeError(
          "cty must be 'application/vnd.cncf.notary.payload.v1+json' for "
          "Notary claims");
      }

      if (notary_signing_scheme.value() == "notary.x509")
      {
        // notary_signing_time is not critical but is required iff notary.x509
        if (!notary_signing_time.has_value())
        {
          throw cose::COSEDecodeError(
            "Missing io.cncf.notary.signingTime in protected header");
        }
        if (notary_authentic_signing_time.has_value())
        {
          throw cose::COSEDecodeError(
            "io.cncf.notary.authenticSigningTime not allowed in protected "
            "header when io.cncf.notary.signingScheme is `notary.x509`");
        }
      }
      else if (notary_signing_scheme.value() == "notary.x509.signingAuthority")
      {
        // notary_authentic_signing_time is critical and required iff
        // notary.x509.signingAuthority
        if (notary_signing_time.has_value())
        {
          throw cose::COSEDecodeError(
            "Notary io.cncf.notary.signingTime not allowed in protected header "
            "when io.cncf.notary.signingScheme is "
            "`notary.x509.signingAuthority`");
        }
        if (!notary_authentic_signing_time.has_value())
        {
          throw cose::COSEDecodeError(
            "Missing io.cncf.notary.authenticSigningTime in protected header");
        }
        if (!phdr.is_critical("io.cncf.notary.authenticSigningTime"))
        {
          throw cose::COSEDecodeError(
            "Missing io.cncf.notary.authenticSigningTime in crit parameters");
        }
      }
      else
      {
        throw cose::COSEDecodeError(
          "Notary io.cncf.notary.signingScheme must be `notary.x509` or "
          "`notary.x509.signingAuthority`");
      }

      if (notary_expiry.has_value())
      {
        // notary_expiry is critial but not required.
        if (!phdr.is_critical("io.cncf.notary.expiry"))
        {
          throw cose::COSEDecodeError(
            "Missing io.cncf.notary.expiry in crit parameters");
        }
      }
    }

    PublicKey process_notary_profile(
      const cose::ProtectedHeader& phdr,
      const cose::UnprotectedHeader& uhdr,
      kv::ReadOnlyTx& tx,
      const Configuration& configuration)
    {
      // Validate protected header
      validate_notary_protected_header(phdr, configuration);

      std::vector<std::vector<uint8_t>> x5chain{};

      if (phdr.x5chain.has_value() && uhdr.x5chain.has_value())
      {
        throw VerificationError(
          "Notary claim has an x5chain (label 33) "
          "parameter in both its protected and unprotected header.");
      }
      else if (phdr.x5chain.has_value())
      {
        SCITT_INFO("Notary x5chain in protected header.");
        x5chain = phdr.x5chain.value();
      }
      else if (uhdr.x5chain.has_value())
      {
        SCITT_INFO("Notary x5chain in unprotected header.");
        x5chain = uhdr.x5chain.value();
      }
      else
      {
        throw VerificationError(
          "Notary claim is missing an x5chain (label 33) "
          "parameter in its headers.");
      }

      // Verify the chain of certs against the x509 root store.
      auto roots = x509_root_store(tx);
      auto cert = verify_chain(roots, x5chain);
      return PublicKey(cert, std::nullopt);
    }

    ClaimProfile verify_claim(
      const std::vector<uint8_t>& data,
      kv::ReadOnlyTx& tx,
      ::timespec current_time,
      std::chrono::seconds resolution_cache_expiry,
      const Configuration& configuration)
    {
      cose::ProtectedHeader phdr;
      cose::UnprotectedHeader uhdr;
      try
      {
        std::tie(phdr, uhdr) = cose::decode_headers(data);

        // Validate_profile and retrieve key.
        PublicKey key;
        if (phdr.notary_signing_scheme.has_value())
        {
          // Notary claim
          // Verify profile
          key = process_notary_profile(phdr, uhdr, tx, configuration);

          // Verify signature.
          try
          {
            // Note it is okay to allow unknown critical params here because
            // validation of critical parameters has already been done during
            // validation of the protected header in
            // `validate_notary_protected_header`
            cose::verify(data, key, /* allow_unknown_crit */ true);
          }
          catch (const cose::COSESignatureValidationError& e)
          {
            throw VerificationError(e.what());
          }

          return ClaimProfile::Notary;
        }
        else if (phdr.issuer.has_value())
        {
          // IETF SCITT claim
          key = process_ietf_profile(
            phdr, tx, current_time, resolution_cache_expiry, configuration);

          try
          {
            cose::verify(data, key);
          }
          catch (const cose::COSESignatureValidationError& e)
          {
            throw VerificationError(e.what());
          }

          return ClaimProfile::IETF;
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

          return ClaimProfile::X509;
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
    static OpenSSL::Unique_X509 verify_chain(
      std::span<const crypto::Pem> trusted,
      std::span<const std::vector<uint8_t>> chain)
    {
      if (chain.empty())
      {
        throw VerificationError(
          "Certificate chain must contain at least one certificate");
      }

      OpenSSL::Unique_X509 leaf = parse_certificate(chain[0]);

      OpenSSL::Unique_X509_STORE store;
      for (const auto& pem : trusted)
      {
        OpenSSL::CHECK1(X509_STORE_add_cert(store, parse_certificate(pem)));
      }

      OpenSSL::Unique_STACK_OF_X509 chain_stack;
      for (const auto& der : chain.subspan(1))
      {
        OpenSSL::Unique_X509 cert = parse_certificate(der);
        OpenSSL::CHECK1(sk_X509_push(chain_stack, cert));
        OpenSSL::CHECK1(X509_up_ref(cert));
      }

      OpenSSL::Unique_X509_STORE_CTX store_ctx;
      OpenSSL::CHECK1(X509_STORE_CTX_init(store_ctx, store, leaf, chain_stack));

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
    static OpenSSL::Unique_X509 parse_certificate(const crypto::Pem& pem)
    {
      OpenSSL::Unique_BIO bio(pem);
      OpenSSL::Unique_X509 cert(bio, true);
      if (!cert)
      {
        unsigned long ec = ERR_get_error();
        SCITT_INFO(
          "Could not parse PEM certificate: {}", OpenSSL::error_string(ec));
        throw VerificationError("Could not parse certificate");
      }
      return cert;
    }

    /** Parse a DER certificate */
    static OpenSSL::Unique_X509 parse_certificate(std::span<const uint8_t> der)
    {
      OpenSSL::Unique_BIO bio(der);
      OpenSSL::Unique_X509 cert(bio, false);
      if (!cert)
      {
        unsigned long ec = ERR_get_error();
        SCITT_INFO(
          "Could not parse DER certificate: {}", OpenSSL::error_string(ec));
        throw VerificationError("Could not parse certificate");
      }
      return cert;
    }

    /**
     * Get the set of trusted x509 CAs from the KV.
     */
    static std::vector<crypto::Pem> x509_root_store(kv::ReadOnlyTx& tx)
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
      return split_x509_cert_bundle(*ca_certs);
    }

    /**
     * Get a PublicKey out of a JSON Web Key.
     */
    static PublicKey get_jwk_public_key(const scitt::did::Jwk& jwk)
    {
      if (jwk.kty != "EC" && jwk.kty != "RSA" && jwk.kty != "OKP")
      {
        throw VerificationError("JWK has an unsupported key type");
      }

      // TODO: check the `use` and `key_ops` fields of the JWK
      // to ensure the key usage is correct.
      std::optional<int64_t> cose_alg;
      if (jwk.alg.has_value())
      {
        try
        {
          cose_alg = get_cose_alg_from_jose_alg(jwk.alg.value());
        }
        catch (const InvalidSignatureAlgorithm& e)
        {
          throw VerificationError(e.what());
        }
      }

      if (jwk.kty == "RSA" && jwk.n.has_value() && jwk.e.has_value())
      {
        auto n = crypto::raw_from_b64url(jwk.n.value());
        auto e = crypto::raw_from_b64url(jwk.e.value());
        OpenSSL::Unique_BIGNUM n_bn;
        OpenSSL::Unique_BIGNUM e_bn;
        if (BN_bin2bn(n.data(), n.size(), n_bn) == nullptr)
        {
          throw VerificationError("JWK n could not be parsed");
        }
        if (BN_bin2bn(e.data(), e.size(), e_bn) == nullptr)
        {
          throw VerificationError("JWK e could not be parsed");
        }

        OpenSSL::Unique_RSA rsa;
        if (!RSA_set0_key(rsa, n_bn, e_bn, nullptr))
        {
          throw std::runtime_error("RSA key could not be set");
        }
        // Ignore previous pointers, as they're now managed by RSA*.
        (void)n_bn.release();
        (void)e_bn.release();

        return PublicKey(rsa, cose_alg);
      }

      if (jwk.kty == "OKP" && jwk.crv == "Ed25519" && jwk.x.has_value())
      {
        auto x = crypto::raw_from_b64url(jwk.x.value());
        return PublicKey(EVP_PKEY_ED25519, x, cose_alg);
      }

      if (
        jwk.kty == "EC" && jwk.crv.has_value() && jwk.x.has_value() &&
        jwk.y.has_value())
      {
        auto crv = jwk.crv.value();
        auto x = crypto::raw_from_b64url(jwk.x.value());
        auto y = crypto::raw_from_b64url(jwk.y.value());
        OpenSSL::Unique_BIGNUM x_bn;
        OpenSSL::Unique_BIGNUM y_bn;
        if (BN_bin2bn(x.data(), x.size(), x_bn) == nullptr)
        {
          throw VerificationError("JWK x could not be parsed");
        }
        if (BN_bin2bn(y.data(), y.size(), y_bn) == nullptr)
        {
          throw VerificationError("JWK y could not be parsed");
        }
        int nid;
        if (crv == "P-256")
        {
          nid = NID_X9_62_prime256v1;
        }
        else if (crv == "P-384")
        {
          nid = NID_secp384r1;
        }
        else if (crv == "P-521")
        {
          nid = NID_secp521r1;
        }
        else
        {
          throw VerificationError("JWK EC Key has no valid supported curve");
        }
        auto ec_key = OpenSSL::Unique_EC_KEY(nid);
        if (!EC_KEY_set_public_key_affine_coordinates(ec_key, x_bn, y_bn))
        {
          throw std::runtime_error("EC key could not be set");
        }

        return PublicKey(ec_key, cose_alg);
      }

      throw VerificationError("JWK has no valid supported key");
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

      // OpenSSL versions 1.1.1g and older, including the one included in
      // Ubuntu Focal and used by our virtual builds, have a bug that prevent
      // self-signed end-entity certificates from being recognised, even if
      // they are part of the trust store. This is fixed in OpenSSL 1.1.1h.
      //
      // As of Feb 2023, OpenEnclave uses version 1.1.1q. Our SGX builds could
      // therefore support this usecase.
      //
      // However, in order to ensure consistent behaviour across our builds, we
      // outright reject these self-signed end-entity certs. We may revisit
      // this in the future, when our virtual builds switch to a more recent
      // release.
      //
      // See https://github.com/microsoft/scitt-ccf-ledger/pull/104 for context
      // and https://github.com/openssl/openssl/pull/12357 for the OpenSSL fix.
      if (X509_get_extension_flags(leaf) & EXFLAG_SS)
      {
        throw VerificationError("Signing certificate is self-signed");
      }

      if (X509_get_extension_flags(leaf) & EXFLAG_CA)
      {
        throw VerificationError("Signing certificate is CA");
      }
    }

    std::unique_ptr<did::Resolver> resolver;
  };
}
