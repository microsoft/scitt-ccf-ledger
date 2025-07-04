// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <ccf/crypto/openssl/openssl_wrappers.h>
#include <optional>

#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
#  include <openssl/core_names.h>
#  include <openssl/encoder.h>
#  include <openssl/evp.h>
#endif

namespace scitt
{
  class PublicKey
  {
  public:
    PublicKey() = default;

    PublicKey(
      const ccf::crypto::OpenSSL::Unique_X509& cert,
      std::optional<int64_t> cose_alg) :
      key(X509_get_pubkey(cert)),
      cose_alg(cose_alg)
    {}

#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
    PublicKey(
      std::vector<uint8_t>& n_raw,
      std::vector<uint8_t>& e_raw,
      std::optional<int64_t> cose_alg) :
      cose_alg(cose_alg)
    {
      OSSL_PARAM params[3];
      params[0] = OSSL_PARAM_construct_BN(
        OSSL_PKEY_PARAM_RSA_N, n_raw.data(), n_raw.size());
      params[1] = OSSL_PARAM_construct_BN(
        OSSL_PKEY_PARAM_RSA_E, e_raw.data(), e_raw.size());
      params[2] = OSSL_PARAM_construct_end();

      ccf::crypto::OpenSSL::Unique_EVP_PKEY_CTX pctx("RSA");
      ccf::crypto::OpenSSL::CHECK1(EVP_PKEY_fromdata_init(pctx));
      ccf::crypto::OpenSSL::CHECK1(
        EVP_PKEY_fromdata(pctx, (EVP_PKEY**)&key, EVP_PKEY_PUBLIC_KEY, params));
    }

    PublicKey(
      std::vector<uint8_t>& buf, int nid, std::optional<int64_t> cose_alg) :
      cose_alg(cose_alg)
    {
      OSSL_PARAM params[3];
      params[0] = OSSL_PARAM_construct_utf8_string(
        OSSL_PKEY_PARAM_GROUP_NAME, (char*)OSSL_EC_curve_nid2name(nid), 0);
      params[1] = OSSL_PARAM_construct_octet_string(
        OSSL_PKEY_PARAM_PUB_KEY, buf.data(), buf.size());
      params[2] = OSSL_PARAM_construct_end();

      ccf::crypto::OpenSSL::Unique_EVP_PKEY_CTX pctx("EC");
      ccf::crypto::OpenSSL::CHECK1(EVP_PKEY_fromdata_init(pctx));
      ccf::crypto::OpenSSL::CHECK1(
        EVP_PKEY_fromdata(pctx, (EVP_PKEY**)&key, EVP_PKEY_PUBLIC_KEY, params));
    }

    PublicKey(
      std::vector<uint8_t>& x,
      std::vector<uint8_t>& y,
      int64_t crv,
      std::optional<int64_t> cose_alg) :
      cose_alg(cose_alg)
    {
      if (crv != 2)
      {
        throw std::runtime_error("Unsupported curve for EC public key");
      }
      if (x.empty() || y.empty())
      {
        throw std::runtime_error("EC public key x or y is empty");
      }
      OSSL_PARAM params[3];
      params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_PKEY_PARAM_EC_PUB_X, x.data(), x.size());
      params[1] = OSSL_PARAM_construct_octet_string(
        OSSL_PKEY_PARAM_EC_PUB_Y, y.data(), y.size());
      params[2] = OSSL_PARAM_construct_end();

      ccf::crypto::OpenSSL::Unique_EVP_PKEY_CTX pctx("EC");
      ccf::crypto::OpenSSL::CHECK1(EVP_PKEY_fromdata_init(pctx));
      ccf::crypto::OpenSSL::CHECK1(
        EVP_PKEY_fromdata(pctx, (EVP_PKEY**)&key, EVP_PKEY_PUBLIC_KEY, params));
    }
#else
    PublicKey(
      const ccf::crypto::OpenSSL::Unique_RSA& rsa_key,
      std::optional<int64_t> cose_alg) :
      cose_alg(cose_alg)
    {
      if (!EVP_PKEY_set1_RSA(key, rsa_key))
      {
        throw std::runtime_error("RSA key could not be set");
      }
    }

    PublicKey(
      const ccf::crypto::OpenSSL::Unique_EC_KEY& ec_key,
      std::optional<int64_t> cose_alg) :
      cose_alg(cose_alg)
    {
      if (!EVP_PKEY_set1_EC_KEY(key, ec_key))
      {
        throw std::runtime_error("EC key could not be set");
      }
    }
#endif

    PublicKey(
      int ossl_type,
      std::span<const uint8_t> raw,
      std::optional<int64_t> cose_alg) :
      key(EVP_PKEY_new_raw_public_key(
        ossl_type, nullptr, raw.data(), raw.size())),
      cose_alg(cose_alg)
    {}

    EVP_PKEY* get_evp_pkey() const
    {
      return key;
    }

    std::optional<int64_t> get_cose_alg() const
    {
      return cose_alg;
    }

  private:
    ccf::crypto::OpenSSL::Unique_EVP_PKEY key;
    std::optional<int64_t> cose_alg;
  };
}
