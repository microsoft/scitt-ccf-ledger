// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "cose.h"

#include "signature_algorithms.h"
#include "testutils.h"

#include <ccf/crypto/cose_key.h>
#include <ccf/crypto/ec_key_pair.h>
#include <ccf/crypto/ecdsa.h>
#include <ccf/crypto/md_type.h>
#include <ccf/crypto/pem.h>
#include <ccf/crypto/rsa_key_pair.h>
#include <ccf/ds/hex.h>
#include <ccf/service/tables/cert_bundles.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <stdexcept>
#include <tav/cbor.hpp>
#include <tuple>

using namespace testing;
using namespace scitt;
using namespace testutils;

namespace
{
  // Signs payload as a COSE_Sign1 with protected header {alg(1): alg}.
  template <typename Sign>
  std::vector<uint8_t> make_cose_sign1(
    int64_t alg, std::span<const uint8_t> payload, Sign&& sign)
  {
    using namespace tav::cbor;

    std::vector<MapItem> phdr;
    phdr.emplace_back(
      make_signed(cose::COSE_HEADER_PARAM_ALG), make_signed(alg));
    const auto phdr_bytes = make_map(std::move(phdr)).nondet_serialize();

    std::vector<tav::cbor::Value> tbs;
    tbs.push_back(make_string("Signature1"));
    tbs.push_back(make_bytes(phdr_bytes));
    tbs.push_back(make_bytes({}));
    tbs.push_back(make_bytes(payload));
    const auto signature = sign(make_array(std::move(tbs)).nondet_serialize());

    std::vector<tav::cbor::Value> envelope;
    envelope.push_back(make_bytes(phdr_bytes));
    envelope.push_back(make_map({}));
    envelope.push_back(make_bytes(payload));
    envelope.push_back(make_bytes(signature));
    return make_tagged(CBOR_TAG_COSE_SIGN1, make_array(std::move(envelope)))
      .nondet_serialize();
  }

  TEST(CoseTest, DecodeAllProtectedHeaders)
  {
    for (auto iat_is_tagged : {false, true})
    {
      auto phdr_b = create_valid_protected_header_bytes(iat_is_tagged);

      cose::ProtectedHeader phdr;
      EXPECT_NO_THROW(phdr = cose::decode_protected_header(phdr_b));
      EXPECT_EQ(phdr.alg, -35);
      EXPECT_EQ(phdr.cwt_claims.iss, "did:example:issuer");
      EXPECT_EQ(phdr.cwt_claims.iat, 1622547800);
      EXPECT_EQ(phdr.cwt_claims.svn, 1);
      EXPECT_EQ(phdr.svn, 1);
      EXPECT_EQ(phdr.tss_map.svc_id, "msft-css-dev");
      EXPECT_EQ(phdr.tss_map.ver, 0);
      EXPECT_TRUE(phdr.tss_map.cose_key.has_value());
      EXPECT_EQ(
        phdr.crit,
        cose::CritValuesContent{std::string(cose::COSE_HEADER_PARAM_TSS)});
    }
  }

  TEST(CoseTest, DecodeEmptyProtectedHeader)
  {
    // A zero-length protected header stands for an empty map (RFC 9052).
    const auto phdr = cose::decode_protected_header({});
    EXPECT_FALSE(phdr.alg.has_value());
    EXPECT_FALSE(phdr.cwt_claims.iss.has_value());
  }

  TEST(CoseTest, DecodeProtectedHeaderRejectsInvalidIat)
  {
    // {15: {6: value}} with text, bytes, null, or tag 1 wrapping text.
    for (const auto& hex :
         {"a10fa1066161", "a10fa1064161", "a10fa106f6", "a10fa106c16161"})
    {
      SCOPED_TRACE(hex);
      EXPECT_THROW(
        cose::decode_protected_header(from_hex_string(hex)),
        cose::COSEDecodeError);
    }
  }

  // add a test case to use payloads from test/payloads directory
  // NOLINTBEGIN(bugprone-unchecked-optional-access)

  TEST(CoseTest, DecodeTSSHeaders)
  {
    std::string filepath = "test_payloads/css-attested-cosesign1-20250925.cose";
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
    EXPECT_EQ(phdr.alg.value(), -7);

    if (!phdr.cwt_claims.iss.has_value())
    {
      throw std::runtime_error("Issuer not found in protected header");
    }
    EXPECT_EQ(
      phdr.cwt_claims.iss.value(), "did:attestedsvc:msft-css-dev::foo:bar:baz");
    EXPECT_TRUE(phdr.tss_map.attestation.has_value());
    EXPECT_TRUE(phdr.tss_map.attestation_type.has_value());
    EXPECT_EQ(
      phdr.tss_map.attestation_type.value(), "SEV-SNP:ContainerPlat-AMD-UVM");
    EXPECT_TRUE(phdr.tss_map.snp_endorsements.has_value());
    EXPECT_TRUE(phdr.tss_map.uvm_endorsements.has_value());
    EXPECT_TRUE(phdr.tss_map.ver.has_value());
    EXPECT_EQ(phdr.tss_map.ver.value(), 0);
    EXPECT_TRUE(phdr.tss_map.cose_key.has_value());
    EXPECT_EQ(phdr.tss_map.cose_key->kty(), ccf::crypto::COSEKeyType::EC2);
    /*
    cose_key:
      1: 2,
      -1: 1,
      -2:
      h'ED2669A17FD85DC926AD405507877F882F005194EE236A7B6443FD8A1735EC78',
      -3:
      h'44D1BD3B99BB2A185A2FA1060FFFAB37CD25FBEF8E812D89A6BBE36E91F365D9'
    */
    const auto ec2 = phdr.tss_map.cose_key->ec2_parameters();
    ASSERT_TRUE(ec2.has_value());
    EXPECT_EQ(ec2->crv, 1);
    EXPECT_EQ(
      ec2->x,
      from_hex_string(
        "ED2669A17FD85DC926AD405507877F882F005194EE236A7B6443FD8A1735EC78"));
    EXPECT_EQ(
      ec2->y,
      from_hex_string(
        "44D1BD3B99BB2A185A2FA1060FFFAB37CD25FBEF8E812D89A6BBE36E91F365D9"));
  }
  // NOLINTEND(bugprone-unchecked-optional-access)

  TEST(CoseTest, DecodeHeadersRejectsNilPayload)
  {
    // COSE_Sign1 = Tag(18, [bstr({1:-7}), {}, nil, bstr(64 zero bytes)])
    // A nil payload indicates a detached payload which is not supported.
    const std::vector<uint8_t>& signed_statement = from_hex_string(
      "d28443a10126a0f65840"
      "0000000000000000000000000000000000000000000000000000000000000000"
      "0000000000000000000000000000000000000000000000000000000000000000");

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
      error_message, HasSubstr("Detached or empty payloads are not supported"));
  }

  TEST(CoseTest, DecodeHeadersRejectsEmptyPayload)
  {
    // COSE_Sign1 = Tag(18, [bstr({1:-7}), {}, bstr(empty), bstr(64 zero
    // bytes)]) An empty payload is not a valid signed statement.
    const std::vector<uint8_t>& signed_statement = from_hex_string(
      "d28443a10126a0405840"
      "0000000000000000000000000000000000000000000000000000000000000000"
      "0000000000000000000000000000000000000000000000000000000000000000");

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
      error_message, HasSubstr("Detached or empty payloads are not supported"));
  }

  TEST(CoseTest, VerifyWithCoseKey)
  {
    using ccf::crypto::CurveID;
    const std::vector<uint8_t> payload = {'p', 'a', 'y', 'l', 'o', 'a', 'd'};
    const auto key = ccf::crypto::make_ec_key_pair(CurveID::SECP256R1);
    const auto signed_statement = make_cose_sign1(
      COSE_ALGORITHM_ES256, payload, [&](const std::vector<uint8_t>& tbs) {
        return ccf::crypto::ecdsa_sig_der_to_p1363(
          key->sign(tbs, ccf::crypto::MDType::SHA256), CurveID::SECP256R1);
      });
    const auto cose_key_of = [](const ccf::crypto::ECKeyPairPtr& k) {
      return ccf::crypto::COSEKey(
        ccf::crypto::make_ec_public_key(k->public_key_der()));
    };

    const auto verified = cose::verify(signed_statement, cose_key_of(key));
    EXPECT_EQ(std::vector<uint8_t>(verified.begin(), verified.end()), payload);

    EXPECT_THROW(
      cose::verify(
        signed_statement,
        cose_key_of(ccf::crypto::make_ec_key_pair(CurveID::SECP256R1))),
      cose::COSESignatureValidationError);
  }

  TEST(CoseTest, DecodeTSSHeadersFailsDueToInvalidMap)
  {
    const std::vector<uint8_t>& signed_statement = from_hex_string(
      "D284590100A801382202816B6174746573746564737663045820A3FC5DF291C866D1AE7F"
      "E90519384EEE2B84D412ED4ABE22C71395B6FDE3057D0FA40178596469643A6174746573"
      "7465647376633A6D7366742D6373732D6465763A3A33643739363163392D383462322D34"
      "3464322D613965302D3333633034306431363862333A746573742D6163636F756E74313A"
      "70726F66696C653102716578706572696D656E74616C2F74657374061A6852FBB2"
      "6373766E001901022F190103706170706C6963617469"
      "6F6E2F6A736F6E19010477687474703A2F2F706174682D746F2D636F6E74656E742F6B61"
      "747465737465647376636F73686F756C642062652061206D6170A0A0A0");

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
        "Failed to decode protected header: attestedsvc must be a map"));
  }

  // The COSEDecodeError message for a hex-encoded COSE_Sign1, or empty.
  std::string decode_headers_error(const std::string& hex)
  {
    try
    {
      cose::decode_headers(from_hex_string(hex));
    }
    catch (const cose::COSEDecodeError& e)
    {
      return {e.what()};
    }
    return {};
  }

  TEST(CoseTest, DecodeHeadersRejectsMalformedEnvelopes)
  {
    // Untagged [bstr({1:-7}), {}, h'00', h'00']
    EXPECT_THAT(
      decode_headers_error("8443a10126a041004100"),
      HasSubstr("COSE_Sign1 is not tagged"));
    // 55799(18([...])): the COSE_Sign1 tag must be the outermost one
    EXPECT_THAT(
      decode_headers_error("d9d9f7d28443a10126a041004100"),
      HasSubstr("COSE_Sign1 is not tagged"));
    // COSE_Sign1 with three elements
    EXPECT_THAT(
      decode_headers_error("d28343a10126a04100"),
      HasSubstr("Failed to parse COSE_Sign1 outer array"));
    // COSE_Sign1 with a fifth element
    EXPECT_THAT(
      decode_headers_error("d28543a10126a04100410000"),
      HasSubstr("Failed to parse COSE_Sign1 outer array"));
    // Protected header given as a map rather than a byte string
    EXPECT_THAT(
      decode_headers_error("d284a10126a041004100"),
      HasSubstr("Failed to decode protected header: not a byte string"));
    // Text string payload
    EXPECT_THAT(
      decode_headers_error("d28443a10126a061614100"),
      HasSubstr("COSE_Sign1 payload is not a byte string"));
    // COSE_Sign1 with a nil signature
    EXPECT_THAT(
      decode_headers_error("d28443a10126a04100f6"),
      HasSubstr("COSE_Sign1 signature is not a byte string"));
    // Not CBOR
    EXPECT_THAT(
      decode_headers_error("d284ff"), HasSubstr("Failed to decode COSE_Sign1"));
  }

  TEST(CoseTest, DecodeHeadersRejectsDuplicateLabels)
  {
    // Protected header {1: -7, 1: -35}: a repeated label is rejected by the
    // CBOR parser rather than resolved to either value.
    EXPECT_THAT(
      decode_headers_error("d28446a20126013822a041004100"),
      HasSubstr("Failed to decode protected header"));
    // Unprotected header {1: -7, 1: -7}
    EXPECT_THAT(
      decode_headers_error("d28443a10126a20126012641004100"),
      HasSubstr("Failed to decode COSE_Sign1"));
  }

  TEST(CoseTest, DecodeHeadersRejectsExcessiveNesting)
  {
    // An unknown header containing 16 nested single-element arrays.
    const std::string header = "a1008181818181818181818181818181818100";

    EXPECT_THROW(
      cose::decode_protected_header(from_hex_string(header)),
      cose::COSEDecodeError);
    EXPECT_THAT(
      decode_headers_error("d28440" + header + "41004100"),
      HasSubstr("Failed to decode COSE_Sign1"));
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

  TEST(CoseTest, DecodeTSSHeadersCoseKey)
  {
    using namespace tav::cbor;
    // Decode the given COSE_Key from the attestedsvc map of a protected header
    const auto decode = [](std::vector<MapItem>&& cose_key) {
      std::vector<MapItem> tss;
      tss.emplace_back(
        make_string(cose::COSE_HEADER_PARAM_TSS_COSE_KEY),
        make_map(std::move(cose_key)));
      std::vector<MapItem> phdr;
      phdr.emplace_back(
        make_string(cose::COSE_HEADER_PARAM_TSS), make_map(std::move(tss)));
      return cose::decode_protected_header(
               make_map(std::move(phdr)).nondet_serialize())
        .tss_map.cose_key.value();
    };
    const auto error_of = [&decode](std::vector<MapItem>&& cose_key) {
      try
      {
        decode(std::move(cose_key));
      }
      catch (const cose::COSEDecodeError& e)
      {
        return std::string(e.what());
      }
      return std::string();
    };
    // Byte payloads are borrowed by the CBOR values, so they must outlive them
    const auto ec2_key = [](
                           int64_t crv,
                           const std::vector<uint8_t>& x,
                           const std::vector<uint8_t>& y) {
      std::vector<MapItem> key;
      key.emplace_back(make_signed(1), make_signed(2));
      key.emplace_back(make_signed(-1), make_signed(crv));
      key.emplace_back(make_signed(-2), make_bytes(x));
      key.emplace_back(make_signed(-3), make_bytes(y));
      return key;
    };

    // A COSE_Key without kty is rejected, not ignored
    std::vector<MapItem> no_kty;
    no_kty.emplace_back(make_signed(-1), make_signed(1));
    EXPECT_THAT(
      error_of(std::move(no_kty)),
      HasSubstr("Failed to decode protected header: attestedsvc.cose_key: "
                "Invalid COSE_Key: kty is missing"));

    // EC2 coordinates must have the curve's size
    const std::vector<uint8_t> short_coordinate(31, 1);
    EXPECT_THAT(
      error_of(ec2_key(1, short_coordinate, short_coordinate)),
      HasSubstr("attestedsvc.cose_key: Invalid COSE_Key: x and y must be 32 "
                "bytes long"));

    // EC P-256 key from the RFC 9679 example, with its thumbprint
    const auto p256_x = from_hex_string(
      "65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d");
    const auto p256_y = from_hex_string(
      "1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c");
    const auto p256 = decode(ec2_key(1, p256_x, p256_y));
    EXPECT_EQ(p256.kty(), ccf::crypto::COSEKeyType::EC2);
    EXPECT_EQ(
      p256.thumbprint_sha256().hex_str(),
      "496bd8afadf307e5b08c64b0421bf9dc01528a344a43bda88fadd1669da253ec");

    // EC P-384 and P-521 keys
    const auto p384_x = from_hex_string(
      "6D2ECFA295A4FEAB4DF1715E9978B13A335AA3468013A6B1933A20205FB0943C3115EDBA"
      "2DADBC6EAC64403904347B23");
    const auto p384_y = from_hex_string(
      "2D0FFD0127F1C015E1F5D2BA86DE32ECC872EED7F84F9CD96145275632297903CD246D87"
      "F29912D0CE19F81C7F6CAB3A");
    const auto p384 = decode(ec2_key(2, p384_x, p384_y));
    EXPECT_EQ(p384.kty(), ccf::crypto::COSEKeyType::EC2);
    const auto p521_x = from_hex_string(
      "01c3708e226d587482b11d5398c3462d6aba8fa2c48bd0a1004ea0f9c0729f89ac03b966"
      "e53b58aae32ad1d73d926628be99efd4788fb6ac291031be10f209387b29");
    const auto p521_y = from_hex_string(
      "010941e39ea4cd64b28c4e4df601faf227188c2c79ccd1640781d4677fafb684ee0cacbd"
      "464fd424187680103899bcf458c7467a023da710acc69ab853f7e291d06c");
    const auto p521 = decode(ec2_key(3, p521_x, p521_y));
    EXPECT_EQ(p521.kty(), ccf::crypto::COSEKeyType::EC2);

    // RSA 2048 key
    const auto rsa_key =
      [](const std::vector<uint8_t>& n, const std::vector<uint8_t>& e) {
        std::vector<MapItem> key;
        key.emplace_back(make_signed(1), make_signed(3));
        key.emplace_back(make_signed(-1), make_bytes(n));
        key.emplace_back(make_signed(-2), make_bytes(e));
        return key;
      };
    const auto rsa_n = from_hex_string(
      "d3ee08a208d1f77305370d8caf1573927be7bd07965f386f8b07bff4b489dfad93ed95b5"
      "b48a5e5e1c541970bc8d9a5c32b7c140e70dc84133e730e74ee9563d64772dc35c8bf816"
      "e4b12b5b91e662fd903f73e5009f48e1c0317658d0fb869e10852af6bfa165645718525"
      "049ea4425f37e891614957be33aac2fe812d7b2f3cb4bcb3356a4939975427e5bc76b871"
      "a697729eb81ca80b378492849aeee6aa339e97c853dcba5ce2ced58fd6d4bbadcbd12145"
      "c7fb24f22ae32078efe8a302d856388a79e86aafc33bc129103b757f26455c82d7fbec64"
      "318ca9bd74635b5a6601c6cbc9ce128a0c8ba9a50c2ba64d413be21f59dc3f38ece21261"
      "e0b9362d5");
    const auto rsa_e = from_hex_string("010001");
    const auto rsa = decode(rsa_key(rsa_n, rsa_e));
    EXPECT_EQ(rsa.kty(), ccf::crypto::COSEKeyType::RSA);

    // Unlike a DER INTEGER, n must not carry a leading zero octet (RFC 8230)
    std::vector<uint8_t> padded_n = {0};
    padded_n.insert(padded_n.end(), rsa_n.begin(), rsa_n.end());
    EXPECT_THAT(
      error_of(rsa_key(padded_n, rsa_e)),
      HasSubstr("attestedsvc.cose_key: Invalid COSE_Key: n must be non-empty "
                "and have no leading zero octets"));

    // OKP keys are not supported
    static constexpr int64_t COSE_CRV_ED25519 = 6;
    const auto ed25519_x = from_hex_string(
      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    std::vector<MapItem> okp_key;
    okp_key.emplace_back(make_signed(1), make_signed(1));
    okp_key.emplace_back(make_signed(-1), make_signed(COSE_CRV_ED25519));
    okp_key.emplace_back(make_signed(-2), make_bytes(ed25519_x));
    EXPECT_THAT(
      error_of(std::move(okp_key)),
      HasSubstr("attestedsvc.cose_key: Invalid COSE_Key: unsupported kty 1"));
  }
}
