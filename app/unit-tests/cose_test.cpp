// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "cose.h"

#include "testutils.h"

#include <ccf/crypto/openssl/openssl_wrappers.h>
#include <ccf/crypto/pem.h>
#include <ccf/crypto/rsa_key_pair.h>
#include <ccf/service/tables/cert_bundles.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <openssl/core_names.h>
#include <openssl/encoder.h>
#include <openssl/param_build.h>
#include <stdexcept>

using namespace testing;
using namespace scitt;
using namespace testutils;

namespace
{
  // add a test case to use payloads from test/payloads directory
  // NOLINTBEGIN(bugprone-unchecked-optional-access)
  TEST(CoseTest, DecodeTSSHeaders)
  {
    std::string filepath = "test_payloads/css-attested-cosesign1-20250617.cose";
    std::ifstream file(filepath, std::ios::binary);
    ASSERT_TRUE(file.is_open());

    // Get file size
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);

    // Read file into vector
    std::vector<uint8_t> signed_statement(size);
    file.read(
      reinterpret_cast<char*>(signed_statement.data()),
      static_cast<std::streamsize>(size));
    ASSERT_EQ(file.gcount(), size);

    cose::ProtectedHeader phdr;
    cose::UnprotectedHeader uhdr;
    std::tie(phdr, uhdr) = cose::decode_headers(signed_statement);

    if (!phdr.alg.has_value())
    {
      throw std::runtime_error("Algorithm not found in protected header");
    }
    EXPECT_EQ(phdr.alg.value(), -35);

    if (!phdr.cwt_claims.iss.has_value())
    {
      throw std::runtime_error("Issuer not found in protected header");
    }
    EXPECT_EQ(
      phdr.cwt_claims.iss.value(),
      "did:attestedsvc:msft-css-dev::3d7961c9-84b2-44d2-a9e0-33c040d168b3:test-"
      "account1:profile1");
    EXPECT_TRUE(phdr.tss_map.attestation.has_value());
    EXPECT_TRUE(phdr.tss_map.attestation_type.has_value());
    EXPECT_EQ(
      phdr.tss_map.attestation_type.value(), "SEV-SNP:ContainerPlat-AMD-UVM");
    EXPECT_TRUE(phdr.tss_map.snp_endorsements.has_value());
    EXPECT_TRUE(phdr.tss_map.uvm_endorsements.has_value());
    EXPECT_TRUE(phdr.tss_map.ver.has_value());
    EXPECT_EQ(phdr.tss_map.ver.value(), 0);
    EXPECT_TRUE(phdr.tss_map.cose_key.has_value());
    EXPECT_EQ(phdr.tss_map.cose_key->kty(), 2);
    /*
    cose_key:
      1: 2,
      -1: 2,
      -2:
      h'6D2ECFA295A4FEAB4DF1715E9978B13A335AA3468013A6B1933A20205FB0943C3115EDBA2DADBC6EAC64403904347B23',
      -3:
      h'2D0FFD0127F1C015E1F5D2BA86DE32ECC872EED7F84F9CD96145275632297903CD246D87F29912D0CE19F81C7F6CAB3A'
    */
    EXPECT_TRUE(std::holds_alternative<int64_t>(
      phdr.tss_map.cose_key->crv_n_k_pub().value()));
    auto crv_n_k_pub =
      std::get<int64_t>(phdr.tss_map.cose_key->crv_n_k_pub().value());
    EXPECT_EQ(crv_n_k_pub, 2);

    EXPECT_EQ(phdr.tss_map.cose_key->x_e().has_value(), true);
    EXPECT_EQ(
      phdr.tss_map.cose_key->x_e().value(),
      from_hex_string("6D2ECFA295A4FEAB4DF1715E9978B13A335AA3468013A6B1933A2020"
                      "5FB0943C3115EDBA2DADBC6EAC64403904347B23"));

    EXPECT_EQ(phdr.tss_map.cose_key->y().has_value(), true);
    EXPECT_EQ(
      phdr.tss_map.cose_key->y().value(),
      from_hex_string("2D0FFD0127F1C015E1F5D2BA86DE32ECC872EED7F84F9CD961452756"
                      "32297903CD246D87F29912D0CE19F81C7F6CAB3A"));
  }
  // NOLINTEND(bugprone-unchecked-optional-access)

  TEST(CoseTest, GetHeaders)
  {
    const std::vector<uint8_t>& signed_statement = from_hex_string(
      "d28459041aa4012603706170706c69636174696f6e2f6a736f6e0fa201785f6469643a78"
      "3530393a303a7368613235363a6a4755655375446370646d613562586d646741767a6841"
      "75336a6256352d6a4175533849583858636f6b453a3a7375626a6563743a434e3a436f73"
      "65506c617967726f756e64205369676e6572026464656d6f1821825901e3308201df3082"
      "0186a003020102021100eb423350288849a3d9a008ead7910405300a06082a8648ce3d04"
      "0302303d310b300906035504061302494531153013060355040a130c446f4e6f74547275"
      "73744d65311730150603550403130e436f7365506c617967726f756e64301e170d323530"
      "3532303030333334315a170d3235303532353030333334315a3044310b30090603550406"
      "1302494531153013060355040a130c446f4e6f7454727573744d65311e301c0603550403"
      "1315436f7365506c617967726f756e64205369676e65723059301306072a8648ce3d0201"
      "06082a8648ce3d0301070342000427c9b9cfbd82263ce9bbca66202b873265b6f3a75cef"
      "9c85e70cc7b467c2046bcd6c0893b2f06c99259b274712c8f282126da1bc940ab0c06712"
      "8c9b5e3824b6a360305e300e0603551d0f0101ff040403020780302b0603551d25042430"
      "2206082b06010505070303060a2b060104018237020116060a2b0601040182373d010130"
      "1f0603551d230418301680149e9583c8f1a55b8d8ce2a341b0e517ca6bc48aad300a0608"
      "2a8648ce3d040302034700304402207ebf7f00d05987a298151d25e3b5ab370dbc199d3b"
      "d172875b433cf0b1c067d60220248344c6680405da3ba37818ae351e622fc576bc0df658"
      "ebbb1659108294e6035901af308201ab30820151a003020102020101300a06082a8648ce"
      "3d040302303d310b300906035504061302494531153013060355040a130c446f4e6f7454"
      "727573744d65311730150603550403130e436f7365506c617967726f756e64301e170d32"
      "35303330383134353934315a170d3335303330383134353934315a303d310b3009060355"
      "04061302494531153013060355040a130c446f4e6f7454727573744d6531173015060355"
      "0403130e436f7365506c617967726f756e643059301306072a8648ce3d020106082a8648"
      "ce3d0301070342000453c27150933f683c3003bd52c3eb14a6554d400f2bd3c1c1d8065a"
      "d82528807810b905937cdb4f1f63dd5741bf53e3a3bd6491d07726e42da11dc546ddabbb"
      "a5a3423040300e0603551d0f0101ff040403020186300f0603551d130101ff0405300301"
      "01ff301d0603551d0e041604149e9583c8f1a55b8d8ce2a341b0e517ca6bc48aad300a06"
      "082a8648ce3d040302034800304502201c85a56047202819427b69c2b106a4adff829b99"
      "a88e60bddde43eb5bde58fca0221008a2b642dec9ddbe6e4ee8f0579a7ae09f2c5e01d7e"
      "3775d526730e7fe072baa1a04d7b22666f6f223a22626172227d58409d74bf7a8fe86abe"
      "e6b008de92f69d1e6381d84ccbda95ba4915b1d1f8574eac90c1cb1e04ebdf09ac8a9ec5"
      "a63b500ddacc7acf619d25fe252e6ada39ec09e5");
    cose::ProtectedHeader phdr;
    cose::UnprotectedHeader uhdr;
    std::tie(phdr, uhdr) = cose::decode_headers(signed_statement);

    if (!phdr.alg.has_value())
    {
      throw std::runtime_error("Algorithm not found in protected header");
    }
    EXPECT_EQ(phdr.alg.value(), -7);

    if (!phdr.cwt_claims.iss.has_value())
    {
      throw std::runtime_error("Issuer not found in protected header");
    }
    EXPECT_EQ(
      phdr.cwt_claims.iss.value(),
      "did:x509:0:sha256:jGUeSuDcpdma5bXmdgAvzhAu3jbV5-jAuS8IX8XcokE::subject:"
      "CN:CosePlayground Signer");
    EXPECT_EQ(uhdr.x5chain.has_value(), false);
  }
}