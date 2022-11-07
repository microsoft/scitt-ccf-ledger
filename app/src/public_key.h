// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "openssl_wrappers.h"

#include <optional>

namespace scitt
{
  class PublicKey
  {
  public:
    PublicKey() = default;

    PublicKey(
      const OpenSSL::Unique_X509& cert, std::optional<int64_t> cose_alg) :
      key(X509_get_pubkey(cert)),
      cose_alg(cose_alg)
    {}

    PublicKey(
      const OpenSSL::Unique_RSA& rsa_key, std::optional<int64_t> cose_alg) :
      cose_alg(cose_alg)
    {
      if (!EVP_PKEY_set1_RSA(key, rsa_key))
      {
        throw std::runtime_error("RSA key could not be set");
      }
    }

    PublicKey(
      const OpenSSL::Unique_EC_KEY& ec_key, std::optional<int64_t> cose_alg) :
      cose_alg(cose_alg)
    {
      if (!EVP_PKEY_set1_EC_KEY(key, ec_key))
      {
        throw std::runtime_error("EC key could not be set");
      }
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

  private:
    OpenSSL::Unique_EVP_PKEY key;
    std::optional<int64_t> cose_alg;
  };
}
