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
  TEST(CoseTest, DecodeAllProtectedHeaders)
  {
    auto phdr_b = create_valid_protected_header_bytes();

    QCBORDecodeContext ctx;
    QCBORDecode_Init(&ctx, cbor::from_bytes(phdr_b), QCBOR_DECODE_MODE_NORMAL);
    EXPECT_NO_THROW(cose::decode_protected_header(ctx));
  }

  // add a test case to use payloads from test/payloads directory
  // NOLINTBEGIN(bugprone-unchecked-optional-access)
  TEST(CoseTest, DecodeTSSHeaders)
  {
    std::string filepath = "test_payloads/css-attested-cosesign1-20250617.cose";
    std::ifstream file(filepath, std::ios::binary);
    ASSERT_TRUE(file.is_open());

    size_t size = std::filesystem::file_size(filepath);

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

  TEST(CoseTest, DecodeTSSHeadersFailsDueToInvalidMap)
  {
    const std::vector<uint8_t>& signed_statement = from_hex_string(
      "D284590103A801382202816C6D7366742D6373732D646576045820A3FC5DF291C866D1AE"
      "7FE90519384EEE2B84D412ED4ABE22C71395B6FDE3057D0FA40178596469643A61747465"
      "737465647376633A6D7366742D6373732D6465763A3A33643739363163392D383462322D"
      "343464322D613965302D3333633034306431363862333A746573742D6163636F756E7431"
      "3A70726F66696C653102716578706572696D656E74616C2F7465737406C11A6852FBB263"
      "73766E001901022F190103706170706C69636174696F6E2F6A736F6E1901047768747470"
      "3A2F2F706174682D746F2D636F6E74656E742F6C6D7366742D6373732D6465766F73686F"
      "756C642062652061206D6170A0A0A0");

    cose::ProtectedHeader phdr;
    cose::UnprotectedHeader uhdr;

    std::string error_message;
    try
    {
      cose::decode_headers(signed_statement);
    }
    catch (const cose::COSEDecodeError& e)
    {
      error_message = e.what();
    }
    EXPECT_THAT(
      error_message,
      HasSubstr(
        "Failed to decode protected header: QCBOR_ERR_UNEXPECTED_TYPE"));
  }

  TEST(CoseTest, DecodeDidX509Headers)
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

  TEST(CoseTest, ECCoseKeyMap)
  {
    // Create a CoseKeyMap with a valid EC key
    cose::CoseKeyMap cose_key = cose::CoseKeyMap();

    EXPECT_ANY_THROW(cose_key.validate());
    EXPECT_ANY_THROW(cose_key.to_public_key());
    EXPECT_ANY_THROW(cose_key.to_sha256_thumb());

    cose_key.set_kty(1); // OKP unsupported key type
    EXPECT_ANY_THROW(cose_key.validate());

    // Valid EC P-256 key parameters
    // from rfc9679 example
    cose_key.set_kty(2); // EC key type
    cose_key.set_crv_n_k_pub(1); // P-256 curve
    cose_key.set_x_e(from_hex_string(
      "65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d"));
    cose_key.set_y(from_hex_string(
      "1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c"));
    EXPECT_NO_THROW(cose_key.validate());
    EXPECT_NO_THROW(cose_key.to_public_key());
    EXPECT_EQ(
      cose_key.to_sha256_thumb(),
      from_hex_string("496bd8afadf307e5b08c64b0421bf9dc01528a344a43bda88fadd166"
                      "9da253ec"));

    // Valid EC P-384 key parameters
    cose_key.set_kty(2); // EC key type
    cose_key.set_crv_n_k_pub(2); // P-384 curve
    cose_key.set_x_e(
      from_hex_string("6D2ECFA295A4FEAB4DF1715E9978B13A335AA3468013A6B1933A2020"
                      "5FB0943C3115EDBA2DADBC6EAC64403904347B23"));
    cose_key.set_y(
      from_hex_string("2D0FFD0127F1C015E1F5D2BA86DE32ECC872EED7F84F9CD961452756"
                      "32297903CD246D87F29912D0CE19F81C7F6CAB3A"));
    EXPECT_NO_THROW(cose_key.validate());
    EXPECT_NO_THROW(cose_key.to_public_key());
    EXPECT_NO_THROW(cose_key.to_sha256_thumb());

    // Valid EC P-521 key parameters
    cose_key.set_kty(2); // EC key type
    cose_key.set_crv_n_k_pub(3); // P-521 curve
    cose_key.set_x_e(from_hex_string(
      "01c3708e226d587482b11d5398c3462d6aba8fa2c48bd0a1004ea0f9c0729f89ac03b966"
      "e53b58aae32ad1d73d926628be99efd4788fb6ac291031be10f209387b29"));
    cose_key.set_y(from_hex_string(
      "010941e39ea4cd64b28c4e4df601faf227188c2c79ccd1640781d4677fafb684ee0cacbd"
      "464fd424187680103899bcf458c7467a023da710acc69ab853f7e291d06c"));
    EXPECT_NO_THROW(cose_key.validate());
    EXPECT_NO_THROW(cose_key.to_public_key());
    EXPECT_NO_THROW(cose_key.to_sha256_thumb());
  }

  TEST(CoseTest, RSACoseKeyMap)
  {
    // Create a CoseKeyMap with a valid EC key
    cose::CoseKeyMap cose_key = cose::CoseKeyMap();

    // Valid RSA 2048 key parameters
    // manually generated using openssl
    cose_key.set_kty(3); // RSA key type
    cose_key.set_crv_n_k_pub(from_hex_string(
      "00d3ee08a208d1f77305370d8caf1573927be7bd07965f386f8b07bff4b489dfad93ed95"
      "b5b48a5e5e1c541970bc8d9a5c32b7c140e70dc84133e730e74ee9563d64772dc35c8bf8"
      "16e4b12b5b91e662fd903f73e5009f48e1c0317658d0fb869e10852af6bfa16564571852"
      "5049ea4425f37e891614957be33aac2fe812d7b2f3cb4bcb3356a4939975427e5bc76b87"
      "1a697729eb81ca80b378492849aeee6aa339e97c853dcba5ce2ced58fd6d4bbadcbd1214"
      "5c7fb24f22ae32078efe8a302d856388a79e86aafc33bc129103b757f26455c82d7fbec6"
      "4318ca9bd74635b5a6601c6cbc9ce128a0c8ba9a50c2ba64d413be21f59dc3f38ece2126"
      "1e0b9362d5"));
    cose_key.set_x_e(from_hex_string("010001"));

    EXPECT_NO_THROW(cose_key.validate());
    EXPECT_NO_THROW(cose_key.to_public_key());
    EXPECT_NO_THROW(cose_key.to_sha256_thumb());
  }
}