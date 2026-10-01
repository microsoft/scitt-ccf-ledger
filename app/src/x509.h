// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <ccf/crypto/openssl/openssl_wrappers.h>
#include <ccf/ds/hex.h>
#include <cstdint>
#include <map>
#include <openssl/x509.h>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace scitt::x509
{
  struct CertificateInfo
  {
    std::map<std::string, std::vector<std::string>> extensions;
    int64_t validity_seconds = 0;
  };

  inline CertificateInfo get_certificate_info(std::span<const uint8_t> der)
  {
    ccf::crypto::OpenSSL::Unique_BIO bio(der.data(), der.size());
    ccf::crypto::OpenSSL::Unique_X509 cert(bio, false);
    if (!cert)
    {
      throw std::invalid_argument("Could not parse X.509 policy certificate");
    }

    CertificateInfo info;
    int days = 0;
    int seconds = 0;
    if (
      ASN1_TIME_diff(
        &days, &seconds, X509_get0_notBefore(cert), X509_get0_notAfter(cert)) !=
      1)
    {
      throw std::invalid_argument("Invalid X.509 certificate validity period");
    }
    info.validity_seconds = static_cast<int64_t>(days) * 86400 + seconds;

    for (int i = 0; i < X509_get_ext_count(cert); ++i)
    {
      auto* extension = X509_get_ext(cert, i);
      const auto* oid = X509_EXTENSION_get_object(extension);
      const auto oid_length = OBJ_obj2txt(nullptr, 0, oid, 1);
      if (oid_length <= 0)
      {
        throw std::invalid_argument("Invalid X.509 extension OID");
      }
      std::string oid_string(static_cast<size_t>(oid_length) + 1, '\0');
      if (OBJ_obj2txt(oid_string.data(), oid_length + 1, oid, 1) != oid_length)
      {
        throw std::invalid_argument("Could not encode X.509 extension OID");
      }
      oid_string.resize(oid_length);

      const auto* value = X509_EXTENSION_get_data(extension);
      const auto length = ASN1_STRING_length(value);
      if (length < 0)
      {
        throw std::invalid_argument("Invalid X.509 extension value");
      }
      info.extensions[oid_string].push_back(
        ccf::ds::to_hex(std::span<const uint8_t>(
          ASN1_STRING_get0_data(value), static_cast<size_t>(length))));
    }
    return info;
  }
}
