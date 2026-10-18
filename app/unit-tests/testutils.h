// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "cose.h"
#include "signature_algorithms.h"

#include <ccf/crypto/ec_key_pair.h>
#include <cstdint>
#include <cstdlib>
#include <iomanip> // setw
#include <string>
#include <tav/cbor.hpp>
#include <vector>

using namespace scitt;

namespace testutils
{
  // Utility function to convert a vector of bytes to a hex string
  static std::string to_hex_string(const std::vector<uint8_t>& data)
  {
    std::ostringstream oss;
    for (auto byte : data)
    {
      oss << std::hex << std::setw(2) << std::setfill('0')
          << static_cast<int>(byte);
    }
    return oss.str();
  }

  // Utility function to convert hex string to a vector of bytes
  static const int HEX_BASE = 16;
  static std::vector<uint8_t> from_hex_string(const std::string& hex)
  {
    // Check if string length is even
    if (hex.length() % 2 != 0)
    {
      throw std::invalid_argument(
        "Hex string must have an even number of characters");
    }

    // Validate all characters are valid hex digits
    for (char c : hex)
    {
      if (!std::isxdigit(c))
      {
        throw std::invalid_argument("Invalid hex character in string");
      }
    }

    std::vector<uint8_t> bytes;
    bytes.reserve(hex.length() / 2);
    for (size_t i = 0; i < hex.length(); i += 2)
    {
      const std::string byteString = hex.substr(i, 2);
      char* end_ptr = nullptr;
      const long value = std::strtol(byteString.c_str(), &end_ptr, HEX_BASE);
      if (*end_ptr != '\0' || value < 0 || value > 255)
      {
        throw std::invalid_argument("Invalid hex value: " + byteString);
      }
      bytes.push_back(static_cast<uint8_t>(value));
    }
    return bytes;
  }

  // Serialized protected header map, with every parameter that is decoded.
  static std::vector<uint8_t> create_valid_protected_header_bytes(
    bool iat_is_tagged = false)
  {
    using namespace tav::cbor;

    // Payloads are borrowed, so they must outlive serialization.
    const auto kid = from_hex_string(
      "6D2ECFA295A4FEAB4DF1715E9978B13A335AA3468013A6B1933A20"
      "205FB0943C3115EDBA2DADBC6EAC64403904347B23");
    const auto bytes = [](std::string_view text) {
      return make_bytes(
        {reinterpret_cast<const uint8_t*>(text.data()), text.size()});
    };
    constexpr int64_t iat = 1622547800;

    // CWT Claims
    std::vector<MapItem> cwt_claims;
    cwt_claims.emplace_back(
      make_signed(cose::COSE_CWT_CLAIM_ISS), make_string("did:example:issuer"));
    cwt_claims.emplace_back(
      make_signed(cose::COSE_CWT_CLAIM_SUB),
      make_string("did:example:subject"));
    cwt_claims.emplace_back(
      make_signed(cose::COSE_CWT_CLAIM_IAT),
      iat_is_tagged ? make_tagged(cose::CBOR_TAG_EPOCH_DATE, make_signed(iat)) :
                      make_signed(iat));
    cwt_claims.emplace_back(
      make_string(cose::SVN_HEADER_PARAM), make_signed(1));

    // TSS map -> COSE Key, which must be a valid public key
    const auto cose_key =
      ccf::crypto::COSEKey(
        ccf::crypto::make_ec_public_key(
          ccf::crypto::make_ec_key_pair(ccf::crypto::CurveID::SECP384R1)
            ->public_key_der()))
        .to_cbor(COSE_ALGORITHM_ES384);

    // TSS map
    std::vector<MapItem> tss;
    tss.emplace_back(
      make_string(cose::COSE_HEADER_PARAM_TSS_SVC_ID),
      make_string("msft-css-dev"));
    tss.emplace_back(
      make_string(cose::COSE_HEADER_PARAM_TSS_ATTESTATION),
      bytes("attestation data"));
    tss.emplace_back(
      make_string(cose::COSE_HEADER_PARAM_TSS_ATTESTATION_TYPE),
      make_string("SEV-SNP:ContainerPlat-AMD-UVM"));
    tss.emplace_back(
      make_string(cose::COSE_HEADER_PARAM_TSS_SNP_ENDORSEMENTS),
      bytes("snp endoresements data"));
    tss.emplace_back(
      make_string(cose::COSE_HEADER_PARAM_TSS_UVM_ENDORSEMENTS),
      bytes("uvm endoresements data"));
    tss.emplace_back(
      make_string(cose::COSE_HEADER_PARAM_TSS_VER), make_signed(0));
    tss.emplace_back(
      make_string(cose::COSE_HEADER_PARAM_TSS_COSE_KEY),
      nondet_parse(cose_key));

    std::vector<tav::cbor::Value> crit;
    crit.push_back(make_string(cose::COSE_HEADER_PARAM_TSS));

    std::vector<tav::cbor::Value> x5chain;
    x5chain.push_back(make_bytes(kid));

    // main top level headers
    std::vector<MapItem> phdr;
    phdr.emplace_back(
      make_signed(cose::COSE_HEADER_PARAM_ALG), make_signed(-35));
    phdr.emplace_back(
      make_signed(cose::COSE_HEADER_PARAM_ISSUER),
      make_string(
        "did:attestedsvc:msft-css-dev::3d7961c9-84b2-44d2-a9e0-33c040d168b3:"
        "test-account1:profile1"));
    phdr.emplace_back(
      make_signed(cose::COSE_HEADER_PARAM_FEED), make_string("some feed"));
    phdr.emplace_back(make_string(cose::SVN_HEADER_PARAM), make_signed(1));
    phdr.emplace_back(
      make_signed(cose::COSE_HEADER_PARAM_KID), make_bytes(kid));
    phdr.emplace_back(
      make_signed(cose::COSE_HEADER_PARAM_CTY),
      make_string("application/attestedsvc+json"));
    phdr.emplace_back(
      make_signed(cose::COSE_HEADER_PARAM_CRIT), make_array(std::move(crit)));
    phdr.emplace_back(
      make_signed(cose::COSE_HEADER_PARAM_X5CHAIN),
      make_array(std::move(x5chain)));
    phdr.emplace_back(
      make_signed(cose::COSE_HEADER_PARAM_CWT_CLAIMS),
      make_map(std::move(cwt_claims)));
    phdr.emplace_back(
      make_string(cose::COSE_HEADER_PARAM_TSS), make_map(std::move(tss)));

    return make_map(std::move(phdr)).nondet_serialize();
  }
}