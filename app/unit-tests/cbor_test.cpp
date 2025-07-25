// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "cbor.h"

#include "testutils.h"

#include <ccf/crypto/sha256.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <stdexcept>

using namespace testing;
using namespace scitt;
using namespace testutils;

namespace
{
  TEST(CborTest, ECCoseKeyToCBOR)
  {
    // Values taken from example in rfc
    // https://www.rfc-editor.org/rfc/rfc9679.html#name-example
    auto cose_key = scitt::cbor::ec_cose_key_to_cbor(
      2,
      1,
      from_hex_string(
        "65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d"),
      from_hex_string(
        "1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c"));

    EXPECT_EQ(
      to_hex_string(cose_key),
      "a40102200121582065eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de43"
      "9c08551d2258201e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd00"
      "84d19c");

    std::shared_ptr<ccf::crypto::HashProvider> hash_provider =
      ccf::crypto::make_hash_provider();
    auto thumbprint = hash_provider->Hash(
      cose_key.data(), cose_key.size(), ccf::crypto::MDType::SHA256);

    EXPECT_EQ(
      to_hex_string(thumbprint),
      "496bd8afadf307e5b08c64b0421bf9dc01528a344a43bda88fadd1669da253ec");
  }

  TEST(CborTest, RSACoseKeyToCBOR)
  {
    // Generated pub key
    // openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt
    // rsa_keygen_bits:2048 openssl rsa -in private_key.pem -pubout -out
    // public_key.pem openssl rsa -pubin -in public_key.pem -text -noout
    auto cose_key = scitt::cbor::rsa_cose_key_to_cbor(
      3,
      from_hex_string(
        "00d3ee08a208d1f77305370d8caf1573927be7bd07965f386f8b07bff4b489dfad93ed"
        "95b5b48a5e5e1c541970bc8d9a5c32b7c140e70dc84133e730e74ee9563d64772dc35c"
        "8bf816e4b12b5b91e662fd903f73e5009f48e1c0317658d0fb869e10852af6bfa16564"
        "5718525049ea4425f37e891614957be33aac2fe812d7b2f3cb4bcb3356a4939975427e"
        "5bc76b871a697729eb81ca80b378492849aeee6aa339e97c853dcba5ce2ced58fd6d4b"
        "badcbd12145c7fb24f22ae32078efe8a302d856388a79e86aafc33bc129103b757f264"
        "55c82d7fbec64318ca9bd74635b5a6601c6cbc9ce128a0c8ba9a50c2ba64d413be21f5"
        "9dc3f38ece21261e0b9362d5"),
      from_hex_string("010001"));

    std::shared_ptr<ccf::crypto::HashProvider> hash_provider =
      ccf::crypto::make_hash_provider();
    auto thumbprint = hash_provider->Hash(
      cose_key.data(), cose_key.size(), ccf::crypto::MDType::SHA256);

    EXPECT_EQ(
      to_hex_string(cose_key),
      "a301032059010100d3ee08a208d1f77305370d8caf1573927be7bd07965f386f8b07bff4"
      "b489dfad93ed95b5b48a5e5e1c541970bc8d9a5c32b7c140e70dc84133e730e74ee9563d"
      "64772dc35c8bf816e4b12b5b91e662fd903f73e5009f48e1c0317658d0fb869e10852af6"
      "bfa165645718525049ea4425f37e891614957be33aac2fe812d7b2f3cb4bcb3356a49399"
      "75427e5bc76b871a697729eb81ca80b378492849aeee6aa339e97c853dcba5ce2ced58fd"
      "6d4bbadcbd12145c7fb24f22ae32078efe8a302d856388a79e86aafc33bc129103b757f2"
      "6455c82d7fbec64318ca9bd74635b5a6601c6cbc9ce128a0c8ba9a50c2ba64d413be21f5"
      "9dc3f38ece21261e0b9362d52143010001");

    EXPECT_EQ(
      to_hex_string(thumbprint),
      "f6ac24a26f78f324d165e6cd637b8fd0aba2e42bf10c331fddc046c13d0b6e77");
  }
}