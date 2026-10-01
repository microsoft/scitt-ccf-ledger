// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "x509.h"

#include <gtest/gtest.h>
#include <memory>
#include <openssl/evp.h>

namespace
{
  std::vector<uint8_t> certificate(
    const char* not_after,
    const std::vector<std::vector<uint8_t>>& extension_values)
  {
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(
      EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "prime256v1"), EVP_PKEY_free);
    std::unique_ptr<X509, decltype(&X509_free)> cert(X509_new(), X509_free);
    if (
      !key || !cert || X509_set_version(cert.get(), 2) != 1 ||
      ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1) != 1 ||
      X509_set_pubkey(cert.get(), key.get()) != 1 ||
      ASN1_TIME_set_string(
        X509_getm_notBefore(cert.get()), "20250101000000Z") != 1 ||
      ASN1_TIME_set_string(X509_getm_notAfter(cert.get()), not_after) != 1)
    {
      throw std::runtime_error("Could not create test certificate");
    }

    for (const auto& bytes : extension_values)
    {
      std::unique_ptr<ASN1_OBJECT, decltype(&ASN1_OBJECT_free)> oid(
        OBJ_txt2obj("1.3.6.1.4.1.57264.1.15", 1), ASN1_OBJECT_free);
      std::unique_ptr<ASN1_OCTET_STRING, decltype(&ASN1_OCTET_STRING_free)>
        value(ASN1_OCTET_STRING_new(), ASN1_OCTET_STRING_free);
      if (
        !oid || !value ||
        ASN1_OCTET_STRING_set(value.get(), bytes.data(), bytes.size()) != 1)
      {
        throw std::runtime_error("Could not create test extension value");
      }
      std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)> extension(
        X509_EXTENSION_create_by_OBJ(nullptr, oid.get(), 0, value.get()),
        X509_EXTENSION_free);
      if (!extension || X509_add_ext(cert.get(), extension.get(), -1) != 1)
      {
        throw std::runtime_error("Could not add test extension");
      }
    }
    if (X509_sign(cert.get(), key.get(), EVP_sha256()) <= 0)
    {
      throw std::runtime_error("Could not sign test certificate");
    }
    const auto size = i2d_X509(cert.get(), nullptr);
    if (size <= 0)
    {
      throw std::runtime_error("Could not encode test certificate");
    }
    std::vector<uint8_t> der(size);
    auto* position = der.data();
    if (i2d_X509(cert.get(), &position) != size)
    {
      throw std::runtime_error("Could not encode test certificate");
    }
    return der;
  }

  TEST(X509PolicyInfoTest, PreservesRawExtensionValuesAndDuplicates)
  {
    const auto der = certificate(
      "20250101001000Z", {{0x0c, 0x03, '1', '2', '3'}, {0x00, 0xff, 0x82}});
    const auto info = scitt::x509::get_certificate_info(der);
    EXPECT_EQ(info.validity_seconds, 600);
    EXPECT_EQ(
      info.extensions.at("1.3.6.1.4.1.57264.1.15"),
      (std::vector<std::string>{"0c03313233", "00ff82"}));
  }

  TEST(X509PolicyInfoTest, ComputesValidityAcrossDays)
  {
    const auto info =
      scitt::x509::get_certificate_info(certificate("20250103000130Z", {}));
    EXPECT_EQ(info.validity_seconds, 2 * 86400 + 90);
    EXPECT_TRUE(info.extensions.empty());
  }

  TEST(X509PolicyInfoTest, DoesNotEnforceExpiryOrPositiveLifetime)
  {
    const auto info =
      scitt::x509::get_certificate_info(certificate("20241231235900Z", {}));
    EXPECT_EQ(info.validity_seconds, -60);
  }

  TEST(X509PolicyInfoTest, RejectsMalformedCertificate)
  {
    const std::vector<uint8_t> der{1, 2, 3};
    EXPECT_THROW(scitt::x509::get_certificate_info(der), std::invalid_argument);
  }
}
