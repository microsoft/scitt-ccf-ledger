// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <ccf/crypto/openssl/openssl_wrappers.h>
#include <openssl/core_names.h>
#include <openssl/encoder.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <optional>

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

    // RSA public key from n and e
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

      EVP_PKEY* raw_key = nullptr;
      ccf::crypto::OpenSSL::CHECK1(
        EVP_PKEY_fromdata(pctx, &raw_key, EVP_PKEY_PUBLIC_KEY, params));

      key = ccf::crypto::OpenSSL::Unique_EVP_PKEY(raw_key);
    }

    // EC public key pubkey buffer and curve NID
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

    // EC public key from x, y coordinates and curve type
    PublicKey(
      std::vector<uint8_t>& x,
      std::vector<uint8_t>& y,
      int64_t crv,
      std::optional<int64_t> cose_alg) :
      cose_alg(cose_alg)
    {
      // Convert x,y coordinates to uncompressed point format: 0x04 || x || y
      std::vector<uint8_t> pub_key;
      pub_key.reserve(1 + x.size() + y.size());
      pub_key.push_back(0x04); // Uncompressed point
      pub_key.insert(pub_key.end(), x.begin(), x.end());
      pub_key.insert(pub_key.end(), y.begin(), y.end());

      // https://www.rfc-editor.org/rfc/rfc9053#section-7.1
      int curve_nid;
      switch (crv)
      {
        case 1: // P-256
          curve_nid = NID_X9_62_prime256v1;
          break;
        case 2: // P-384
          curve_nid = NID_secp384r1;
          break;
        case 3: // P-521
          curve_nid = NID_secp521r1;
          break;
        default:
          throw std::runtime_error(
            "Unsupported curve type, only P-256, P-384, and P-521 are "
            "supported");
      }
      OSSL_PARAM params[3];
      // https://www.rfc-editor.org/rfc/rfc9053#section-7.1
      params[0] = OSSL_PARAM_construct_utf8_string(
        OSSL_PKEY_PARAM_GROUP_NAME,
        (char*)OSSL_EC_curve_nid2name(curve_nid),
        0);
      params[1] = OSSL_PARAM_construct_octet_string(
        OSSL_PKEY_PARAM_PUB_KEY, pub_key.data(), pub_key.size());
      params[2] = OSSL_PARAM_construct_end();

      ccf::crypto::OpenSSL::Unique_EVP_PKEY_CTX pctx("EC");
      ccf::crypto::OpenSSL::CHECK1(EVP_PKEY_fromdata_init(pctx));

      EVP_PKEY* raw_key = nullptr;
      ccf::crypto::OpenSSL::CHECK1(
        EVP_PKEY_fromdata(pctx, &raw_key, EVP_PKEY_PUBLIC_KEY, params));

      // set the key using the raw pointer
      key = ccf::crypto::OpenSSL::Unique_EVP_PKEY(raw_key);
    }

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

    std::vector<uint8_t> public_key_sha256() const
    {
      ccf::crypto::OpenSSL::Unique_EVP_MD_CTX md_ctx;
      ccf::crypto::OpenSSL::CHECK1(
        EVP_DigestInit_ex(md_ctx, EVP_sha256(), nullptr));
      ccf::crypto::OpenSSL::CHECK1(EVP_DigestUpdate(md_ctx, key, sizeof(key)));
      std::vector<uint8_t> hash(EVP_MD_size(EVP_sha256()));
      unsigned int hash_len = 0;
      ccf::crypto::OpenSSL::CHECK1(
        EVP_DigestFinal_ex(md_ctx, hash.data(), &hash_len));
      hash.resize(hash_len);
      return hash;
    }

  private:
    ccf::crypto::OpenSSL::Unique_EVP_PKEY key;
    std::optional<int64_t> cose_alg;
  };
}
