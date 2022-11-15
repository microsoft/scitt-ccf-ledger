// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "cose.h"
#include "did/resolver.h"
#include "openssl_wrappers.h"
#include "public_key.h"
#include "signature_algorithms.h"

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

    void verify_claim(
      const std::vector<uint8_t>& data,
      kv::Tx& tx,
      ::timespec current_time,
      std::chrono::seconds resolution_cache_expiry,
      const Configuration& configuration)
    {
      cose::ProtectedHeader phdr;
      try
      {
        phdr = cose::decode_protected_header(data);
      }
      catch (const cose::COSEDecodeError& e)
      {
        throw VerificationError(e.what());
      }

      std::string_view algorithm;
      try
      {
        // We use the equivalent JOSE human-readable names in the
        // configuration, rather than the obscure integer values
        // from COSE.
        algorithm = get_jose_alg_from_cose_alg(phdr.alg);
      }
      catch (const InvalidSignatureAlgorithm& e)
      {
        throw VerificationError(e.what());
      }
      if (!contains(configuration.policy.get_accepted_algorithms(), algorithm))
      {
        throw VerificationError("Unsupported algorithm in protected header");
      }

      auto issuer = phdr.issuer;
      auto kid = phdr.kid;
      auto x5chain = phdr.x5chain;

      PublicKey key;
      if (x5chain.has_value())
      {
        // Verify the chain of certs against the x509 root store.
        auto roots = x509_root_store(tx);
        auto cert = verify_chain(roots, x5chain.value());
        key = PublicKey(cert, std::nullopt);
      }
      else
      {
        std::optional<std::string> assertion_method_id;
        if (!issuer.has_value())
        {
          throw VerificationError(
            "Issuer was missing as a part of the decoded header.");
        }

        if (kid.has_value())
        {
          assertion_method_id =
            fmt::format("{}#{}", issuer.value(), kid.value());
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
        key = get_jwk_public_key(jwk);
      }

      try
      {
        cose::verify(data, key);
      }
      catch (const cose::COSESignatureValidationError& e)
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
      OpenSSL::CHECK1(X509_STORE_set_flags(store, X509_V_FLAG_PARTIAL_CHAIN));
      OpenSSL::CHECK1(X509_STORE_CTX_init(store_ctx, store, leaf, chain_stack));

      if (X509_verify_cert(store_ctx) != 1)
      {
        throw VerificationError("Certificate chain is invalid");
      }

      return leaf;
    }

  private:
    /** Parse a PEM certificate */
    static OpenSSL::Unique_X509 parse_certificate(const crypto::Pem& pem)
    {
      OpenSSL::Unique_BIO bio(pem);
      return OpenSSL::Unique_X509(bio, true);
    }

    /** Parse a DER certificate */
    static OpenSSL::Unique_X509 parse_certificate(std::span<const uint8_t> der)
    {
      OpenSSL::Unique_BIO bio(der);
      return OpenSSL::Unique_X509(bio, false);
    }

    /**
     * Get the set of trusted x509 CAs from the KV.
     */
    static std::vector<crypto::Pem> x509_root_store(kv::Tx& tx)
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

    std::unique_ptr<did::Resolver> resolver;
  };
}
