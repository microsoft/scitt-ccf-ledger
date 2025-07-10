// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "cbor.h"
#include "public_key.h"
#include "tracing.h"
#include "util.h"

#include <ccf/crypto/base64.h>
#include <ccf/crypto/hash_provider.h>
#include <ccf/crypto/key_pair.h>
#include <ccf/crypto/openssl/openssl_wrappers.h>
#include <ccf/crypto/sha256.h>
#include <ccf/crypto/verifier.h>
#include <ccf/ds/logger.h>
#include <openssl/ec.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <optional>
#include <qcbor/qcbor.h>
#include <qcbor/qcbor_spiffy_decode.h>
#include <set>
#include <span>
#include <string>
#include <t_cose/t_cose_sign1_verify.h>
#include <vector>

namespace scitt::cose
{
  static constexpr int64_t COSE_HEADER_PARAM_ALG = 1;
  static constexpr int64_t COSE_HEADER_PARAM_CRIT = 2;
  static constexpr int64_t COSE_HEADER_PARAM_CTY = 3;
  static constexpr int64_t COSE_HEADER_PARAM_KID = 4;
  static constexpr int64_t COSE_HEADER_PARAM_X5CHAIN = 33;
  static constexpr int64_t COSE_HEADER_PARAM_CWT_CLAIMS = 15;

  static constexpr const char* COSE_HEADER_PARAM_TSS = "msft-css-dev";
  static constexpr const char* COSE_HEADER_PARAM_TSS_ATTESTATION =
    "attestation";
  static constexpr const char* COSE_HEADER_PARAM_TSS_ATTESTATION_TYPE =
    "attestation_type";
  static constexpr const char* COSE_HEADER_PARAM_TSS_SNP_ENDORSEMENTS =
    "snp_endorsements";
  static constexpr const char* COSE_HEADER_PARAM_TSS_UVM_ENDORSEMENTS =
    "uvm_endorsements";
  static constexpr const char* COSE_HEADER_PARAM_TSS_COSE_KEY = "cose_key";
  static constexpr const char* COSE_HEADER_PARAM_TSS_VER = "ver";

  static const std::set<std::variant<int64_t, std::string>> BASIC_HEADER_PARAMS{
    COSE_HEADER_PARAM_ALG,
    COSE_HEADER_PARAM_CRIT,
    COSE_HEADER_PARAM_CTY,
    COSE_HEADER_PARAM_KID,
    COSE_HEADER_PARAM_X5CHAIN,
  };

  // Temporary assignments from
  // https://datatracker.ietf.org/doc/draft-ietf-cose-merkle-tree-proofs/09/
  // Section 2
  static constexpr int64_t COSE_HEADER_PARAM_ISSUER = 391;
  static constexpr int64_t COSE_HEADER_PARAM_FEED = 392;
  static constexpr int64_t COSE_HEADER_PARAM_SCITT_RECEIPTS = 394;

  static constexpr int64_t COSE_CWT_CLAIM_ISS = 1;
  static constexpr int64_t COSE_CWT_CLAIM_SUB = 2;
  static constexpr int64_t COSE_CWT_CLAIM_IAT = 6;

  static constexpr int64_t COSE_KEY_KTY = 1;
  static constexpr int64_t COSE_KEY_CRV_N_K_PUB = -1;
  static constexpr int64_t COSE_KEY_X_E = -2;
  static constexpr int64_t COSE_KEY_Y = -3;

  static const std::set<std::variant<int64_t, std::string>> EXTRA_HEADER_PARAMS{
    COSE_HEADER_PARAM_ISSUER,
    COSE_HEADER_PARAM_FEED,
    COSE_HEADER_PARAM_SCITT_RECEIPTS,
  };

  static constexpr const char* SVN_HEADER_PARAM = "svn";

  static std::shared_ptr<ccf::crypto::HashProvider>& get_hash_provider()
  {
    static thread_local std::shared_ptr<ccf::crypto::HashProvider>
      hash_provider;
    if (!hash_provider)
    {
      hash_provider = ccf::crypto::make_hash_provider();
      if (!hash_provider)
      {
        throw std::runtime_error("Failed to create hash provider");
      }
    }
    return hash_provider;
  }

  struct COSEDecodeError : public std::runtime_error
  {
    COSEDecodeError(const std::string& msg) : std::runtime_error(msg) {}
  };

  // Cose Key https://www.rfc-editor.org/rfc/rfc9679.html
  // Presence of values depends on kty
  struct CoseKeyMap
  {
    std::optional<int64_t> kty;
    std::optional<std::variant<int64_t, std::vector<uint8_t>>> crv_n_k_pub;
    std::optional<std::vector<uint8_t>> x_e;
    std::optional<std::vector<uint8_t>> y;
  };

  static void validate_cosekeymap(const CoseKeyMap& key_map)
  {
    if (!key_map.kty.has_value() || key_map.kty.value() != 2)
    {
      throw COSEDecodeError(
        "CoseKeyMap kty is not set or not equal to 2 (EC2).");
    }
    if (
      !key_map.crv_n_k_pub.has_value() ||
      !std::holds_alternative<int64_t>(key_map.crv_n_k_pub.value()))
    {
      throw COSEDecodeError("CoseKeyMap crv is not set or not an int64_t.");
    }
    if (!key_map.x_e.has_value() || key_map.x_e.value().empty())
    {
      throw COSEDecodeError("CoseKeyMap x is not set or empty.");
    }
    if (!key_map.y.has_value() || key_map.y.value().empty())
    {
      throw COSEDecodeError("CoseKeyMap y is not set or empty.");
    }
  }

  static PublicKey to_public_key(const CoseKeyMap& key_map)
  {
    validate_cosekeymap(key_map);
    auto crv = std::get<int64_t>(key_map.crv_n_k_pub.value());
    std::vector<uint8_t> x = key_map.x_e.value();
    std::vector<uint8_t> y = key_map.y.value();
    PublicKey key(x, y, crv, std::nullopt);
    return key;
  }

  // see https://www.ietf.org/rfc/rfc9679.html
  static std::vector<uint8_t> to_sha256_thumb(const CoseKeyMap& key_map)
  {
    validate_cosekeymap(key_map);
    std::vector<uint8_t> key_cbor = cbor::cose_key_to_cbor(
      key_map.kty.value(),
      std::get<int64_t>(key_map.crv_n_k_pub.value()),
      key_map.x_e.value(),
      key_map.y.value());

    auto& hash_provider = get_hash_provider();
    // Hash the CBOR representation of the COSE key using SHA-256
    return hash_provider->Hash(
      key_cbor.data(), key_cbor.size(), ccf::crypto::MDType::SHA256);
  }

  /**
  "attestation": bstr,       ; raw hardware attestation report
  "attestation_type": tstr,  ; "SEV-SNP:ContainerPlat-AMD-UVM"
  "cose_key": { ... },       ; canonical COSE_Key map (embedded directly)
  "snp_endorsements": bstr,  ; concatenated PEM-encoded AMD cert chain
  "uvm_endorsements": bstr,  ; opaque endorsement from Azure or UVM authority
  "ver": int                 ; version number of the format (e.g., 0)
   */
  struct TSSMap
  {
    std::optional<std::vector<uint8_t>> attestation;
    std::optional<std::string> attestation_type;
    std::optional<CoseKeyMap> cose_key;
    std::optional<std::vector<uint8_t>> snp_endorsements;
    std::optional<std::vector<uint8_t>> uvm_endorsements;
    std::optional<int64_t> ver;
  };

  struct CWTClaims
  {
    std::optional<std::string> iss;
    std::optional<std::string> sub;
    std::optional<int64_t> iat;
    std::optional<int64_t> svn;
  };

  struct ProtectedHeader // NOLINT(bugprone-exception-escape)
  {
    // The headers used in this codebase
    std::optional<int64_t> alg;
    std::optional<std::vector<std::variant<int64_t, std::string>>> crit;
    std::optional<std::string> kid;
    std::optional<std::string> issuer;
    std::optional<std::string> feed;
    std::optional<int64_t> iat;
    std::optional<int64_t> svn;
    std::optional<std::variant<int64_t, std::string>> cty;
    std::optional<std::vector<std::vector<uint8_t>>> x5chain;

    // CWT Claims header, as defined in
    // https://datatracker.ietf.org/doc/rfc9597/
    CWTClaims cwt_claims;

    // Microsoft Trusted Signing Service (TSS) parameters
    TSSMap tss_map;
  };

  struct UnprotectedHeader
  {
    std::optional<std::vector<std::vector<uint8_t>>> x5chain;
  };

  static std::vector<std::vector<uint8_t>> decode_x5chain(
    QCBORDecodeContext& ctx, const QCBORItem& x5chain)
  {
    std::vector<std::vector<uint8_t>> parsed;

    if (x5chain.uDataType == QCBOR_TYPE_ARRAY)
    {
      QCBORDecode_EnterArrayFromMapN(&ctx, COSE_HEADER_PARAM_X5CHAIN);
      while (true)
      {
        QCBORItem item;
        auto result = QCBORDecode_GetNext(&ctx, &item);
        if (result == QCBOR_ERR_NO_MORE_ITEMS)
        {
          break;
        }
        if (result != QCBOR_SUCCESS)
        {
          throw COSEDecodeError("Item in x5chain is not well-formed.");
        }
        if (item.uDataType == QCBOR_TYPE_BYTE_STRING)
        {
          parsed.push_back(cbor::as_vector(item.val.string));
        }
        else
        {
          throw COSEDecodeError(
            "Next item in x5chain was not of type byte string.");
        }
      }
      QCBORDecode_ExitArray(&ctx);
      if (parsed.empty())
      {
        throw COSEDecodeError("x5chain array length was 0 in COSE header.");
      }
      if (parsed.size() == 1)
      {
        // IETF-COSE-X509 Draft mandates a single cert is placed in a CBOR
        // byte string, not an array.
        // But other implementations mistakenly serialise single certs as bstrs
        // in arrays, so we are not strict here.
        SCITT_INFO("Single cert found in x5chain array in COSE header.");
      }
    }
    else if (x5chain.uDataType == QCBOR_TYPE_BYTE_STRING)
    {
      parsed.push_back(cbor::as_vector(x5chain.val.string));
    }
    else
    {
      SCITT_FAIL("Type: {}", x5chain.uDataType);
      throw COSEDecodeError(
        "Value type of x5chain in COSE header is not array or byte "
        "string.");
    }

    return parsed;
  }

  static ProtectedHeader decode_protected_header(QCBORDecodeContext& ctx)
  {
    ProtectedHeader parsed;

    // Adapted from parse_cose_header_parameters in t_cose_parameters.c.
    // t_cose doesn't support custom header parameters yet.

    QCBORError qcbor_result;

    QCBORDecode_EnterBstrWrapped(&ctx, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, NULL);
    QCBORDecode_EnterMap(&ctx, NULL);

    enum
    {
      ALG_INDEX,
      CRIT_INDEX,
      ISSUER_INDEX,
      FEED_INDEX,
      SVN_INDEX,
      KID_INDEX,
      CTY_INDEX,
      X5CHAIN_INDEX,
      CWT_CLAIMS_INDEX,
      TSS_INDEX,
      END_INDEX,
    };
    QCBORItem header_items[END_INDEX + 1];

    header_items[ALG_INDEX].label.int64 = COSE_HEADER_PARAM_ALG;
    header_items[ALG_INDEX].uLabelType = QCBOR_TYPE_INT64;
    header_items[ALG_INDEX].uDataType = QCBOR_TYPE_INT64;

    header_items[CRIT_INDEX].label.int64 = COSE_HEADER_PARAM_CRIT;
    header_items[CRIT_INDEX].uLabelType = QCBOR_TYPE_INT64;
    header_items[CRIT_INDEX].uDataType = QCBOR_TYPE_ARRAY;

    header_items[ISSUER_INDEX].label.int64 = COSE_HEADER_PARAM_ISSUER;
    header_items[ISSUER_INDEX].uLabelType = QCBOR_TYPE_INT64;
    header_items[ISSUER_INDEX].uDataType = QCBOR_TYPE_TEXT_STRING;

    header_items[FEED_INDEX].label.int64 = COSE_HEADER_PARAM_FEED;
    header_items[FEED_INDEX].uLabelType = QCBOR_TYPE_INT64;
    header_items[FEED_INDEX].uDataType = QCBOR_TYPE_TEXT_STRING;

    header_items[SVN_INDEX].label.string = UsefulBuf_FromSZ(SVN_HEADER_PARAM);
    header_items[SVN_INDEX].uLabelType = QCBOR_TYPE_TEXT_STRING;
    header_items[SVN_INDEX].uDataType = QCBOR_TYPE_INT64;

    header_items[KID_INDEX].label.int64 = COSE_HEADER_PARAM_KID;
    header_items[KID_INDEX].uLabelType = QCBOR_TYPE_INT64;
    header_items[KID_INDEX].uDataType = QCBOR_TYPE_BYTE_STRING;

    header_items[CTY_INDEX].label.int64 = COSE_HEADER_PARAM_CTY;
    header_items[CTY_INDEX].uLabelType = QCBOR_TYPE_INT64;
    header_items[CTY_INDEX].uDataType = QCBOR_TYPE_ANY;

    header_items[X5CHAIN_INDEX].label.int64 = COSE_HEADER_PARAM_X5CHAIN;
    header_items[X5CHAIN_INDEX].uLabelType = QCBOR_TYPE_INT64;
    header_items[X5CHAIN_INDEX].uDataType = QCBOR_TYPE_ANY;

    header_items[CWT_CLAIMS_INDEX].label.int64 = COSE_HEADER_PARAM_CWT_CLAIMS;
    header_items[CWT_CLAIMS_INDEX].uLabelType = QCBOR_TYPE_INT64;
    header_items[CWT_CLAIMS_INDEX].uDataType = QCBOR_TYPE_MAP;

    enum
    {
      CWT_ISS_INDEX,
      CWT_SUB_INDEX,
      CWT_IAT_INDEX,
      CWT_SVN_INDEX,
      CWT_END_INDEX,
    };
    QCBORItem cwt_items[CWT_END_INDEX + 1];

    cwt_items[CWT_ISS_INDEX].label.int64 = COSE_CWT_CLAIM_ISS;
    cwt_items[CWT_ISS_INDEX].uLabelType = QCBOR_TYPE_INT64;
    cwt_items[CWT_ISS_INDEX].uDataType = QCBOR_TYPE_TEXT_STRING;

    cwt_items[CWT_SUB_INDEX].label.int64 = COSE_CWT_CLAIM_SUB;
    cwt_items[CWT_SUB_INDEX].uLabelType = QCBOR_TYPE_INT64;
    cwt_items[CWT_SUB_INDEX].uDataType = QCBOR_TYPE_TEXT_STRING;

    cwt_items[CWT_IAT_INDEX].label.int64 = COSE_CWT_CLAIM_IAT;
    cwt_items[CWT_IAT_INDEX].uLabelType = QCBOR_TYPE_INT64;
    cwt_items[CWT_IAT_INDEX].uDataType = QCBOR_TYPE_DATE_EPOCH;

    cwt_items[CWT_SVN_INDEX].label.string = UsefulBuf_FromSZ(SVN_HEADER_PARAM);
    cwt_items[CWT_SVN_INDEX].uLabelType = QCBOR_TYPE_TEXT_STRING;
    cwt_items[CWT_SVN_INDEX].uDataType = QCBOR_TYPE_INT64;

    cwt_items[CWT_END_INDEX].uLabelType = QCBOR_TYPE_NONE;

    header_items[TSS_INDEX].label.string =
      UsefulBuf_FromSZ(COSE_HEADER_PARAM_TSS);
    header_items[TSS_INDEX].uLabelType = QCBOR_TYPE_TEXT_STRING;
    header_items[TSS_INDEX].uDataType = QCBOR_TYPE_MAP;

    enum
    {
      TSS_ATTESTATION_INDEX,
      TSS_ATTESTATION_TYPE_INDEX,
      TSS_SNP_ENDORSEMENTS_INDEX,
      TSS_UVM_ENDORSEMENTS_INDEX,
      TSS_VER_INDEX,
      TSS_COSE_KEY_INDEX,
      TSS_END_INDEX,
    };
    QCBORItem tss_items[TSS_END_INDEX + 1];

    tss_items[TSS_ATTESTATION_INDEX].label.string =
      UsefulBuf_FromSZ(COSE_HEADER_PARAM_TSS_ATTESTATION);
    tss_items[TSS_ATTESTATION_INDEX].uLabelType = QCBOR_TYPE_TEXT_STRING;
    tss_items[TSS_ATTESTATION_INDEX].uDataType = QCBOR_TYPE_BYTE_STRING;

    tss_items[TSS_ATTESTATION_TYPE_INDEX].label.string =
      UsefulBuf_FromSZ(COSE_HEADER_PARAM_TSS_ATTESTATION_TYPE);
    tss_items[TSS_ATTESTATION_TYPE_INDEX].uLabelType = QCBOR_TYPE_TEXT_STRING;
    tss_items[TSS_ATTESTATION_TYPE_INDEX].uDataType = QCBOR_TYPE_TEXT_STRING;

    tss_items[TSS_SNP_ENDORSEMENTS_INDEX].label.string =
      UsefulBuf_FromSZ(COSE_HEADER_PARAM_TSS_SNP_ENDORSEMENTS);
    tss_items[TSS_SNP_ENDORSEMENTS_INDEX].uLabelType = QCBOR_TYPE_TEXT_STRING;
    tss_items[TSS_SNP_ENDORSEMENTS_INDEX].uDataType = QCBOR_TYPE_BYTE_STRING;

    tss_items[TSS_UVM_ENDORSEMENTS_INDEX].label.string =
      UsefulBuf_FromSZ(COSE_HEADER_PARAM_TSS_UVM_ENDORSEMENTS);
    tss_items[TSS_UVM_ENDORSEMENTS_INDEX].uLabelType = QCBOR_TYPE_TEXT_STRING;
    tss_items[TSS_UVM_ENDORSEMENTS_INDEX].uDataType = QCBOR_TYPE_BYTE_STRING;

    tss_items[TSS_VER_INDEX].label.string =
      UsefulBuf_FromSZ(COSE_HEADER_PARAM_TSS_VER);
    tss_items[TSS_VER_INDEX].uLabelType = QCBOR_TYPE_TEXT_STRING;
    tss_items[TSS_VER_INDEX].uDataType = QCBOR_TYPE_INT64;

    tss_items[TSS_COSE_KEY_INDEX].label.string =
      UsefulBuf_FromSZ(COSE_HEADER_PARAM_TSS_COSE_KEY);
    tss_items[TSS_COSE_KEY_INDEX].uLabelType = QCBOR_TYPE_TEXT_STRING;
    tss_items[TSS_COSE_KEY_INDEX].uDataType = QCBOR_TYPE_MAP;

    enum
    {
      TSS_COSE_KEY_KTY_INDEX,
      TSS_COSE_KEY_CRV_N_K_PUB_INDEX,
      TSS_COSE_KEY_X_E_INDEX,
      TSS_COSE_KEY_Y_INDEX,
      TSS_COSE_KEY_END_INDEX,
    };
    QCBORItem cose_key_items[TSS_COSE_KEY_END_INDEX + 1];

    cose_key_items[TSS_COSE_KEY_KTY_INDEX].label.int64 = COSE_KEY_KTY;
    cose_key_items[TSS_COSE_KEY_KTY_INDEX].uLabelType = QCBOR_TYPE_INT64;
    cose_key_items[TSS_COSE_KEY_KTY_INDEX].uDataType = QCBOR_TYPE_INT64;

    cose_key_items[TSS_COSE_KEY_CRV_N_K_PUB_INDEX].label.int64 =
      COSE_KEY_CRV_N_K_PUB;
    cose_key_items[TSS_COSE_KEY_CRV_N_K_PUB_INDEX].uLabelType =
      QCBOR_TYPE_INT64;
    cose_key_items[TSS_COSE_KEY_CRV_N_K_PUB_INDEX].uDataType = QCBOR_TYPE_ANY;

    cose_key_items[TSS_COSE_KEY_X_E_INDEX].label.int64 = COSE_KEY_X_E;
    cose_key_items[TSS_COSE_KEY_X_E_INDEX].uLabelType = QCBOR_TYPE_INT64;
    cose_key_items[TSS_COSE_KEY_X_E_INDEX].uDataType = QCBOR_TYPE_BYTE_STRING;

    cose_key_items[TSS_COSE_KEY_Y_INDEX].label.int64 = COSE_KEY_Y;
    cose_key_items[TSS_COSE_KEY_Y_INDEX].uLabelType = QCBOR_TYPE_INT64;
    cose_key_items[TSS_COSE_KEY_Y_INDEX].uDataType = QCBOR_TYPE_BYTE_STRING;

    cose_key_items[TSS_COSE_KEY_END_INDEX].uLabelType = QCBOR_TYPE_NONE;

    tss_items[TSS_END_INDEX].uLabelType = QCBOR_TYPE_NONE;

    header_items[END_INDEX].uLabelType = QCBOR_TYPE_NONE;

    QCBORDecode_GetItemsInMap(&ctx, header_items);

    qcbor_result = QCBORDecode_GetError(&ctx);
    if (qcbor_result != QCBOR_SUCCESS)
    {
      throw COSEDecodeError(
        fmt::format("Failed to decode protected header: {}", qcbor_result));
    }

    if (header_items[ALG_INDEX].uDataType != QCBOR_TYPE_NONE)
    {
      parsed.alg = header_items[ALG_INDEX].val.int64;
    }
    if (header_items[ISSUER_INDEX].uDataType != QCBOR_TYPE_NONE)
    {
      parsed.issuer = cbor::as_string(header_items[ISSUER_INDEX].val.string);
    }
    if (header_items[CRIT_INDEX].uDataType != QCBOR_TYPE_NONE)
    {
      parsed.crit = std::vector<std::variant<int64_t, std::string>>();
      QCBORItem critItem = header_items[CRIT_INDEX];
      QCBORDecode_EnterArrayFromMapN(&ctx, COSE_HEADER_PARAM_CRIT);
      while (true)
      {
        auto result = QCBORDecode_GetNext(&ctx, &critItem);
        if (result == QCBOR_ERR_NO_MORE_ITEMS)
        {
          break;
        }
        if (result != QCBOR_SUCCESS)
        {
          throw COSEDecodeError("Item in crit is not well-formed.");
        }
        if (critItem.uDataType == QCBOR_TYPE_TEXT_STRING)
        {
          parsed.crit->push_back(
            std::string(cbor::as_string(critItem.val.string)));
        }
        else if (critItem.uDataType == QCBOR_TYPE_INT64)
        {
          parsed.crit->push_back(critItem.val.int64);
        }
        else
        {
          throw COSEDecodeError(
            "Next item in crit was not of type text string or "
            "int64.");
        }
      }
      QCBORDecode_ExitArray(&ctx);
      if (parsed.crit->empty())
      {
        throw COSEDecodeError(
          "Cannot have crit array of length 0 in COSE protected header.");
      }
    }
    if (header_items[KID_INDEX].uDataType != QCBOR_TYPE_NONE)
    {
      parsed.kid = cbor::as_string(header_items[KID_INDEX].val.string);
    }
    if (header_items[FEED_INDEX].uDataType != QCBOR_TYPE_NONE)
    {
      parsed.feed = cbor::as_string(header_items[FEED_INDEX].val.string);
    }
    if (header_items[SVN_INDEX].uDataType != QCBOR_TYPE_NONE)
    {
      parsed.svn = header_items[SVN_INDEX].val.int64;
    }

    if (header_items[CTY_INDEX].uDataType == QCBOR_TYPE_TEXT_STRING)
    {
      parsed.cty =
        std::string(cbor::as_string(header_items[CTY_INDEX].val.string));
    }
    else if (header_items[CTY_INDEX].uDataType == QCBOR_TYPE_INT64)
    {
      parsed.cty = header_items[CTY_INDEX].val.int64;
    }
    else if (header_items[CTY_INDEX].uDataType != QCBOR_TYPE_NONE)
    {
      throw COSEDecodeError(
        "Content-type must be of type text string or int64");
    }

    // If a CWT claims map is present, parse it
    if (header_items[CWT_CLAIMS_INDEX].uDataType != QCBOR_TYPE_NONE)
    {
      QCBORDecode_EnterMapFromMapN(&ctx, COSE_HEADER_PARAM_CWT_CLAIMS);
      auto decode_error = QCBORDecode_GetError(&ctx);
      if (decode_error != QCBOR_SUCCESS)
      {
        throw COSEDecodeError(
          fmt::format("Failed to decode CWT claims: {}", decode_error));
      }

      QCBORDecode_GetItemsInMap(&ctx, cwt_items);
      decode_error = QCBORDecode_GetError(&ctx);
      if (decode_error != QCBOR_SUCCESS)
      {
        throw COSEDecodeError(
          fmt::format("Failed to decode CWT claim contents: {}", decode_error));
      }

      if (cwt_items[CWT_ISS_INDEX].uDataType != QCBOR_TYPE_NONE)
      {
        parsed.cwt_claims.iss =
          cbor::as_string(cwt_items[CWT_ISS_INDEX].val.string);
      }
      if (cwt_items[CWT_SUB_INDEX].uDataType != QCBOR_TYPE_NONE)
      {
        parsed.cwt_claims.sub =
          cbor::as_string(cwt_items[CWT_SUB_INDEX].val.string);
      }
      if (cwt_items[CWT_IAT_INDEX].uDataType != QCBOR_TYPE_NONE)
      {
        parsed.cwt_claims.iat = cwt_items[CWT_IAT_INDEX].val.epochDate.nSeconds;
      }
      if (cwt_items[CWT_SVN_INDEX].uDataType != QCBOR_TYPE_NONE)
      {
        parsed.cwt_claims.svn = cwt_items[CWT_SVN_INDEX].val.int64;
      }
      QCBORDecode_ExitMap(&ctx);
    }

    if (header_items[TSS_INDEX].uDataType != QCBOR_TYPE_NONE)
    {
      QCBORDecode_EnterMapFromMapSZ(&ctx, COSE_HEADER_PARAM_TSS);
      auto tss_error = QCBORDecode_GetError(&ctx);
      if (tss_error != QCBOR_SUCCESS)
      {
        throw COSEDecodeError(fmt::format(
          "Failed to decode {} map: {}", COSE_HEADER_PARAM_TSS, tss_error));
      }

      QCBORDecode_GetItemsInMap(&ctx, tss_items);
      tss_error = QCBORDecode_GetError(&ctx);
      if (tss_error != QCBOR_SUCCESS)
      {
        throw COSEDecodeError(fmt::format(
          "Failed to decode {} map contents: {}",
          COSE_HEADER_PARAM_TSS,
          tss_error));
      }

      if (tss_items[TSS_ATTESTATION_INDEX].uDataType != QCBOR_TYPE_NONE)
      {
        parsed.tss_map.attestation =
          cbor::as_vector(tss_items[TSS_ATTESTATION_INDEX].val.string);
      }
      if (tss_items[TSS_ATTESTATION_TYPE_INDEX].uDataType != QCBOR_TYPE_NONE)
      {
        parsed.tss_map.attestation_type =
          cbor::as_string(tss_items[TSS_ATTESTATION_TYPE_INDEX].val.string);
      }
      if (tss_items[TSS_SNP_ENDORSEMENTS_INDEX].uDataType != QCBOR_TYPE_NONE)
      {
        parsed.tss_map.snp_endorsements =
          cbor::as_vector(tss_items[TSS_SNP_ENDORSEMENTS_INDEX].val.string);
      }
      if (tss_items[TSS_UVM_ENDORSEMENTS_INDEX].uDataType != QCBOR_TYPE_NONE)
      {
        parsed.tss_map.uvm_endorsements =
          cbor::as_vector(tss_items[TSS_UVM_ENDORSEMENTS_INDEX].val.string);
      }
      if (tss_items[TSS_VER_INDEX].uDataType != QCBOR_TYPE_NONE)
      {
        parsed.tss_map.ver = tss_items[TSS_VER_INDEX].val.int64;
      }

      if (tss_items[TSS_COSE_KEY_INDEX].uDataType != QCBOR_TYPE_NONE)
      {
        QCBORDecode_EnterMapFromMapSZ(&ctx, COSE_HEADER_PARAM_TSS_COSE_KEY);
        auto cose_key_error = QCBORDecode_GetError(&ctx);
        if (cose_key_error != QCBOR_SUCCESS)
        {
          throw COSEDecodeError(fmt::format(
            "Failed to decode {} map: {}",
            COSE_HEADER_PARAM_TSS_COSE_KEY,
            tss_error));
        }

        QCBORDecode_GetItemsInMap(&ctx, cose_key_items);
        cose_key_error = QCBORDecode_GetError(&ctx);
        if (cose_key_error != QCBOR_SUCCESS)
        {
          throw COSEDecodeError(fmt::format(
            "Failed to decode {} map contents: {}",
            COSE_HEADER_PARAM_TSS_COSE_KEY,
            tss_error));
        }

        if (cose_key_items[TSS_COSE_KEY_KTY_INDEX].uDataType != QCBOR_TYPE_NONE)
        {
          parsed.tss_map.cose_key = CoseKeyMap();
          parsed.tss_map.cose_key->kty =
            cose_key_items[TSS_COSE_KEY_KTY_INDEX].val.int64;

          // save other fields only if KTY is present

          if (
            cose_key_items[TSS_COSE_KEY_CRV_N_K_PUB_INDEX].uDataType ==
            QCBOR_TYPE_BYTE_STRING)
          {
            parsed.tss_map.cose_key->crv_n_k_pub = cbor::as_vector(
              cose_key_items[TSS_COSE_KEY_CRV_N_K_PUB_INDEX].val.string);
          }
          else if (
            cose_key_items[TSS_COSE_KEY_CRV_N_K_PUB_INDEX].uDataType ==
            QCBOR_TYPE_INT64)
          {
            parsed.tss_map.cose_key->crv_n_k_pub =
              cose_key_items[TSS_COSE_KEY_CRV_N_K_PUB_INDEX].val.int64;
          }
          else if (
            cose_key_items[TSS_COSE_KEY_CRV_N_K_PUB_INDEX].uDataType !=
            QCBOR_TYPE_NONE)
          {
            throw COSEDecodeError(fmt::format(
              "Cose Key value must be of type int64 or byte string, got {}",
              cose_key_items[TSS_COSE_KEY_CRV_N_K_PUB_INDEX].uDataType));
          }

          if (
            cose_key_items[TSS_COSE_KEY_X_E_INDEX].uDataType != QCBOR_TYPE_NONE)
          {
            parsed.tss_map.cose_key->x_e = cbor::as_vector(
              cose_key_items[TSS_COSE_KEY_X_E_INDEX].val.string);
          }

          if (cose_key_items[TSS_COSE_KEY_Y_INDEX].uDataType != QCBOR_TYPE_NONE)
          {
            parsed.tss_map.cose_key->y =
              cbor::as_vector(cose_key_items[TSS_COSE_KEY_Y_INDEX].val.string);
          }
        }

        QCBORDecode_ExitMap(&ctx);
      }

      QCBORDecode_ExitMap(&ctx);
    }

    if (header_items[X5CHAIN_INDEX].uDataType != QCBOR_TYPE_NONE)
    {
      parsed.x5chain = decode_x5chain(ctx, header_items[X5CHAIN_INDEX]);
    }

    QCBORDecode_ExitMap(&ctx);
    QCBORDecode_ExitBstrWrapped(&ctx);

    qcbor_result = QCBORDecode_GetError(&ctx);
    if (qcbor_result != QCBOR_SUCCESS)
    {
      throw COSEDecodeError(
        fmt::format("Failed to decode protected header: {}", qcbor_result));
    }

    return parsed;
  }

  static UnprotectedHeader decode_unprotected_header(QCBORDecodeContext& ctx)
  {
    UnprotectedHeader parsed;
    // Adapted from parse_cose_header_parameters in t_cose_parameters.c.
    // t_cose doesn't support custom header parameters yet.

    QCBORError qcbor_result;

    QCBORDecode_EnterMap(&ctx, NULL);

    enum
    {
      X5CHAIN_INDEX,
      END_INDEX,
    };
    QCBORItem header_items[END_INDEX + 1];
    header_items[X5CHAIN_INDEX].label.int64 = COSE_HEADER_PARAM_X5CHAIN;
    header_items[X5CHAIN_INDEX].uLabelType = QCBOR_TYPE_INT64;
    header_items[X5CHAIN_INDEX].uDataType = QCBOR_TYPE_ANY;

    header_items[END_INDEX].uLabelType = QCBOR_TYPE_NONE;

    QCBORDecode_GetItemsInMap(&ctx, header_items);

    qcbor_result = QCBORDecode_GetError(&ctx);
    if (qcbor_result != QCBOR_SUCCESS)
    {
      throw COSEDecodeError(
        fmt::format("Failed to decode unprotected header: {}", qcbor_result));
    }
    if (header_items[X5CHAIN_INDEX].uDataType != QCBOR_TYPE_NONE)
    {
      parsed.x5chain = decode_x5chain(ctx, header_items[X5CHAIN_INDEX]);
    }
    QCBORDecode_ExitMap(&ctx);

    qcbor_result = QCBORDecode_GetError(&ctx);
    if (qcbor_result != QCBOR_SUCCESS)
    {
      throw COSEDecodeError(
        fmt::format("Failed to decode unprotected header: {}", qcbor_result));
    }

    return parsed;
  }

  static std::tuple<ProtectedHeader, UnprotectedHeader> decode_headers(
    const std::vector<uint8_t>& cose_sign1)
  {
    QCBORError qcbor_result;

    QCBORDecodeContext ctx;
    QCBORDecode_Init(
      &ctx, cbor::from_bytes(cose_sign1), QCBOR_DECODE_MODE_NORMAL);

    QCBORDecode_EnterArray(&ctx, nullptr);
    qcbor_result = QCBORDecode_GetError(&ctx);
    if (qcbor_result != QCBOR_SUCCESS)
    {
      throw COSEDecodeError("Failed to parse COSE_Sign1 outer array");
    }

    uint64_t tag = QCBORDecode_GetNthTagOfLast(&ctx, 0);
    if (tag != CBOR_TAG_COSE_SIGN1)
    {
      throw COSEDecodeError("COSE_Sign1 is not tagged");
    }

    auto phdr = decode_protected_header(ctx);
    auto uhdr = decode_unprotected_header(ctx);

    QCBORDecode_ExitArray(&ctx);
    auto error = QCBORDecode_Finish(&ctx);
    if (error)
    {
      throw COSEDecodeError("Failed to decode COSE_Sign1");
    }
    return std::make_tuple(phdr, uhdr);
  }

  struct COSESignatureValidationError : public std::runtime_error
  {
    COSESignatureValidationError(const std::string& msg) :
      std::runtime_error(msg)
    {}
  };

  /**
   * Verify the signature of a COSE Sign1 message using the given public key.
   *
   * Beyond the basic verification of key usage and the signature
   * itself, no particular validation of the message is done.
   */
  static std::span<uint8_t> verify(
    const std::vector<uint8_t>& cose_sign1,
    const PublicKey& key,
    bool allow_unknown_crit = false)
  {
    q_useful_buf_c signed_cose;
    signed_cose.ptr = cose_sign1.data();
    signed_cose.len = cose_sign1.size();

    t_cose_sign1_verify_ctx verify_ctx;

    // Do some preliminary decoding, to get the header parameters and potential
    // auxiliary buffer size.
    t_cose_parameters params;
    uint32_t prelim_options = T_COSE_OPT_TAG_REQUIRED | T_COSE_OPT_DECODE_ONLY;
    if (allow_unknown_crit)
    {
      prelim_options |= T_COSE_OPT_UNKNOWN_CRIT_ALLOWED;
    }
    t_cose_sign1_verify_init(&verify_ctx, prelim_options);
    t_cose_err_t error =
      t_cose_sign1_verify(&verify_ctx, signed_cose, nullptr, &params);
    if (error)
    {
      throw COSESignatureValidationError(
        fmt::format("COSE decoding failed: {}", error));
    }

    auto key_alg = key.get_cose_alg();
    if (key_alg.has_value() && params.cose_algorithm_id != key_alg.value())
    {
      throw COSESignatureValidationError(
        "Algorithm mismatch between protected header and public key");
    }

    size_t auxiliary_buffer_size =
      t_cose_sign1_verify_auxiliary_buffer_size(&verify_ctx);

    t_cose_key cose_key;
    cose_key.crypto_lib = T_COSE_CRYPTO_LIB_OPENSSL;
    EVP_PKEY* evp_key = key.get_evp_pkey();
    cose_key.k.key_ptr = evp_key;

    uint32_t options = T_COSE_OPT_TAG_REQUIRED;
    if (allow_unknown_crit)
    {
      options |= T_COSE_OPT_UNKNOWN_CRIT_ALLOWED;
    }
    t_cose_sign1_verify_init(&verify_ctx, options);
    t_cose_sign1_set_verification_key(&verify_ctx, cose_key);

    // EdDSA signature verification needs an auxiliary buffer.
    // For other algorithms, the buffer size will just be 0.
    std::vector<uint8_t> auxiliary_buffer(auxiliary_buffer_size);
    t_cose_sign1_verify_set_auxiliary_buffer(
      &verify_ctx, {auxiliary_buffer.data(), auxiliary_buffer.size()});

    q_useful_buf_c payload;

    error = t_cose_sign1_verify(&verify_ctx, signed_cose, &payload, nullptr);
    if (error)
    {
      throw COSESignatureValidationError("Signature verification failed");
    }

    return {(uint8_t*)payload.ptr, payload.len};
  }
}
