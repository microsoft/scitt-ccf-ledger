// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <ccf/crypto/openssl/openssl_wrappers.h>
#include <ccf/crypto/pem.h>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace scitt
{
  /**
   * Drop-in for ccf::crypto::cert_der_to_pem, which rejects Ed25519
   * certificates. To be replaced by it once CCF accepts them.
   */
  inline ccf::crypto::Pem cert_der_to_pem(const std::vector<uint8_t>& der)
  {
    ccf::crypto::OpenSSL::Unique_BIO der_bio(der.data(), der.size());
    ccf::crypto::OpenSSL::Unique_X509 cert(der_bio, false);
    if (!cert)
    {
      throw std::invalid_argument(fmt::format(
        "OpenSSL error: {}",
        ccf::crypto::OpenSSL::error_string(ERR_get_error())));
    }
    ccf::crypto::OpenSSL::Unique_BIO pem_bio;
    ccf::crypto::OpenSSL::CHECK1(PEM_write_bio_X509(pem_bio, cert));
    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(pem_bio, &mem);
    return ccf::crypto::Pem(std::string(mem->data, mem->length));
  }
}
