// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "cose.h"

#include <cstdint>
#include <cstdlib>
#include <iomanip> // setw
#include <string>
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

  static std::vector<uint8_t> create_valid_protected_header_bytes()
  {
    // create protected header
    std::vector<uint8_t> output(2200);
    UsefulBuf output_buf{output.data(), output.size()};
    QCBOREncodeContext ectx;
    QCBOREncode_Init(&ectx, output_buf);
    QCBOREncode_BstrWrap(&ectx);
    QCBOREncode_OpenMap(&ectx);

    // main top level headers
    // ----------------------
    // alg
    QCBOREncode_AddInt64ToMapN(&ectx, cose::COSE_HEADER_PARAM_ALG, -35);
    // iss
    QCBOREncode_AddTextToMapN(
      &ectx,
      cose::COSE_HEADER_PARAM_ISSUER,
      cbor::from_string(
        "did:attestedsvc:msft-css-dev::3d7961c9-84b2-44d2-a9e0-33c040d168b3:"
        "test-account1:profile1"));
    // feed
    QCBOREncode_AddTextToMapN(
      &ectx, cose::COSE_HEADER_PARAM_FEED, cbor::from_string("some feed"));
    // svn
    QCBOREncode_AddInt64ToMap(&ectx, cose::SVN_HEADER_PARAM, 1);
    // kid
    QCBOREncode_AddBytesToMapN(
      &ectx,
      cose::COSE_HEADER_PARAM_KID,
      cbor::from_bytes(
        from_hex_string("6D2ECFA295A4FEAB4DF1715E9978B13A335AA3468013A6B1933A20"
                        "205FB0943C3115EDBA2DADBC6EAC64403904347B23")));
    // cty
    QCBOREncode_AddTextToMapN(
      &ectx,
      cose::COSE_HEADER_PARAM_CTY,
      cbor::from_string("application/attestedsvc+json"));
    // crit
    QCBOREncode_OpenArrayInMapN(&ectx, cose::COSE_HEADER_PARAM_CRIT);
    QCBOREncode_AddInt64(&ectx, cose::COSE_HEADER_PARAM_ALG);
    QCBOREncode_AddInt64(&ectx, cose::COSE_HEADER_PARAM_KID);
    QCBOREncode_CloseArray(&ectx);

    // X5Chain
    // ----------------------
    QCBOREncode_OpenArrayInMapN(&ectx, cose::COSE_HEADER_PARAM_X5CHAIN);
    QCBOREncode_AddBytes(
      &ectx,
      cbor::from_bytes(
        from_hex_string("6D2ECFA295A4FEAB4DF1715E9978B13A335AA3468013A6B1933A20"
                        "205FB0943C3115EDBA2DADBC6EAC64403904347B23")));
    QCBOREncode_CloseArray(&ectx);

    // CWT Claims
    // ----------------------
    QCBOREncode_OpenMapInMapN(&ectx, cose::COSE_HEADER_PARAM_CWT_CLAIMS);
    QCBOREncode_AddTextToMapN(
      &ectx, cose::COSE_CWT_CLAIM_ISS, cbor::from_string("did:example:issuer"));
    QCBOREncode_AddTextToMapN(
      &ectx,
      cose::COSE_CWT_CLAIM_SUB,
      cbor::from_string("did:example:subject"));
    QCBOREncode_AddDateEpochToMapN(&ectx, cose::COSE_CWT_CLAIM_IAT, 1622547800);
    QCBOREncode_AddInt64ToMap(&ectx, cose::SVN_HEADER_PARAM, 1);
    QCBOREncode_CloseMap(&ectx);

    // TSS map
    // ----------------------
    QCBOREncode_OpenMapInMap(&ectx, cose::COSE_HEADER_PARAM_TSS);
    QCBOREncode_AddBytesToMap(
      &ectx,
      cose::COSE_HEADER_PARAM_TSS_ATTESTATION,
      cbor::from_string("attestation data"));
    QCBOREncode_AddTextToMap(
      &ectx,
      cose::COSE_HEADER_PARAM_TSS_ATTESTATION_TYPE,
      cbor::from_string("SEV-SNP:ContainerPlat-AMD-UVM"));
    QCBOREncode_AddBytesToMap(
      &ectx,
      cose::COSE_HEADER_PARAM_TSS_SNP_ENDORSEMENTS,
      cbor::from_string("snp endoresements data"));
    QCBOREncode_AddBytesToMap(
      &ectx,
      cose::COSE_HEADER_PARAM_TSS_UVM_ENDORSEMENTS,
      cbor::from_string("uvm endoresements data"));
    QCBOREncode_AddInt64ToMap(&ectx, cose::COSE_HEADER_PARAM_TSS_VER, 0);
    // TSS map -> COSE Key
    QCBOREncode_OpenMapInMap(&ectx, cose::COSE_HEADER_PARAM_TSS_COSE_KEY);
    QCBOREncode_AddInt64ToMapN(&ectx, cose::COSE_KEY_KTY, 2); // EC key type
    QCBOREncode_AddInt64ToMapN(
      &ectx, cose::COSE_KEY_CRV_N_K_PUB, 2); // crv: secp384r1
    QCBOREncode_AddBytesToMapN(
      &ectx, cose::COSE_KEY_X_E, cbor::from_string("x value"));
    QCBOREncode_AddBytesToMapN(
      &ectx, cose::COSE_KEY_Y, cbor::from_string("y value"));
    QCBOREncode_CloseMap(&ectx);

    QCBOREncode_CloseMap(&ectx);

    QCBOREncode_CloseMap(&ectx);
    UsefulBufC Wrapped;
    QCBOREncode_CloseBstrWrap(&ectx, &Wrapped);
    UsefulBufC encoded_cbor;
    QCBORError err;
    err = QCBOREncode_Finish(&ectx, &encoded_cbor);
    if (err != QCBOR_SUCCESS)
    {
      throw std::runtime_error(
        fmt::format("Failed to encode protected header: {}", err));
    }
    output.resize(encoded_cbor.len);
    output.shrink_to_fit();

    return output;
  }
}