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
  static constexpr int64_t COSE_HEADER_PARAM_CWT_CNF = 8;

  static const std::set<std::variant<int64_t, std::string>> BASIC_HEADER_PARAMS{
    COSE_HEADER_PARAM_ALG,
    COSE_HEADER_PARAM_CRIT,
    COSE_HEADER_PARAM_CTY,
    COSE_HEADER_PARAM_KID,
    COSE_HEADER_PARAM_X5CHAIN,
  };

  // Temporary assignments from https://datatracker.ietf.org/doc/draft-ietf-cose-merkle-tree-proofs/09/
  // Section 2
  static constexpr int64_t COSE_HEADER_PARAM_ISSUER = 391;
  static constexpr int64_t COSE_HEADER_PARAM_FEED = 392;
  static constexpr int64_t COSE_HEADER_PARAM_SCITT_RECEIPTS = 394;

  static constexpr int64_t COSE_CWT_CLAIM_ISS = 1;
  static constexpr int64_t COSE_CWT_CLAIM_SUB = 2;
  static constexpr int64_t COSE_CWT_CLAIM_IAT = 6;

  static const std::set<std::variant<int64_t, std::string>> EXTRA_HEADER_PARAMS{
    COSE_HEADER_PARAM_ISSUER,
    COSE_HEADER_PARAM_FEED,
    COSE_HEADER_PARAM_SCITT_RECEIPTS,
  };

  static constexpr const char* SVN_HEADER_PARAM = "svn";

  static constexpr const char* ATTESTATION_HEADER_PARAM = "scitt.attestation";

  struct COSEDecodeError : public std::runtime_error
  {
    COSEDecodeError(const std::string& msg) : std::runtime_error(msg) {}
  };

  // cnf from https://www.rfc-editor.org/rfc/rfc8747.html
  struct Confirmation
  {
    std::optional<std::vector<uint8_t>> kid;
  };

  struct CWTClaims
  {
    std::optional<std::string> iss;
    std::optional<std::string> sub;
    std::optional<int64_t> iat;
    std::optional<int64_t> svn;
    std::optional<Confirmation> cnf;
  };

  struct ProtectedHeader // NOLINT(bugprone-exception-escape)
  {
    // All headers are optional here but optionality will later be validated
    // according to the COSE profile of the claim.

    // Vanilla SCITT protected header parameters
    // Issuer is used when verifying with did:web
    // x5chain is used when verification is done with the x509 certificate chain
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

    bool is_present(const std::variant<int64_t, std::string>& label) const
    {
      // Helper function checking if a known label has a value in the protected
      // header.
      // Intended for checking if critical parameters are present in the
      // protected header. Hence this should only be called once it is
      // established that the label is known.
      if (
        label == std::variant<int64_t, std::string>(COSE_HEADER_PARAM_ALG) and
        alg.has_value())
      {
        return true;
      }
      if (
        label == std::variant<int64_t, std::string>(COSE_HEADER_PARAM_CRIT) and
        crit.has_value())
      {
        return true;
      }
      if (
        label == std::variant<int64_t, std::string>(COSE_HEADER_PARAM_CTY) and
        cty.has_value())
      {
        return true;
      }
      if (
        label == std::variant<int64_t, std::string>(COSE_HEADER_PARAM_KID) and
        kid.has_value())
      {
        return true;
      }
      if (
        label ==
          std::variant<int64_t, std::string>(COSE_HEADER_PARAM_X5CHAIN) and
        x5chain.has_value())
      {
        return true;
      }
      if (
        label ==
          std::variant<int64_t, std::string>(COSE_HEADER_PARAM_ISSUER) and
        issuer.has_value())
      {
        return true;
      }
      if (
        label == std::variant<int64_t, std::string>(COSE_HEADER_PARAM_FEED) and
        feed.has_value())
      {
        return true;
      }
      return false;
    }

    bool is_critical(const std::variant<int64_t, std::string>& label) const
    {
      if (!crit.has_value())
      {
        return false;
      }
      for (const auto& crit_label : crit.value())
      {
        if (crit_label == label)
        {
          return true;
        }
      }
      return false;
    }

    // Returns a bool representing whether the input label is a known
    // parameter in the context of a profile.
    bool is_known(
      const std::variant<int64_t, std::string>& label,
      const std::set<std::variant<int64_t, std::string>>& profile_parameters)
      const
    {
      return BASIC_HEADER_PARAMS.contains(label) ||
        EXTRA_HEADER_PARAMS.contains(label) ||
        profile_parameters.contains(label);
    }
  };

  struct UnprotectedHeader
  {
    std::optional<std::vector<std::vector<uint8_t>>> x5chain;
    std::optional<std::string> attestation;
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
      CWT_CNF_INDEX,
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

    cwt_items[CWT_CNF_INDEX].label.int64 = COSE_HEADER_PARAM_CWT_CNF;
    cwt_items[CWT_CNF_INDEX].uLabelType = QCBOR_TYPE_INT64;
    cwt_items[CWT_CNF_INDEX].uDataType = QCBOR_TYPE_MAP;

    cwt_items[CWT_SVN_INDEX].label.string = UsefulBuf_FromSZ(SVN_HEADER_PARAM);
    cwt_items[CWT_SVN_INDEX].uLabelType = QCBOR_TYPE_TEXT_STRING;
    cwt_items[CWT_SVN_INDEX].uDataType = QCBOR_TYPE_INT64;

    cwt_items[CWT_END_INDEX].uLabelType = QCBOR_TYPE_NONE;

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
      if (cwt_items[CWT_CNF_INDEX].uDataType != QCBOR_TYPE_NONE)
      {
        QCBORDecode_EnterMapFromMapN(&ctx, COSE_HEADER_PARAM_CWT_CNF);
        auto cnf_error = QCBORDecode_GetError(&ctx);
        if (cnf_error != QCBOR_SUCCESS)
        {
          throw COSEDecodeError(
            fmt::format("Failed to decode cnf: {}", cnf_error));
        }

        parsed.cwt_claims.cnf = Confirmation{};

        enum
        {
          CWT_CNF_KID_INDEX,
          CWT_CNF_END_INDEX,
        };
        QCBORItem cnf_items[END_INDEX + 1];
        cnf_items[CWT_CNF_KID_INDEX].label.int64 = COSE_HEADER_PARAM_KID;
        cnf_items[CWT_CNF_KID_INDEX].uLabelType = QCBOR_TYPE_INT64;
        cnf_items[CWT_CNF_KID_INDEX].uDataType = QCBOR_TYPE_BYTE_STRING;

        QCBORDecode_GetItemsInMap(&ctx, cnf_items);
        cnf_error = QCBORDecode_GetError(&ctx);
        if (cnf_error != QCBOR_SUCCESS)
        {
          throw COSEDecodeError(
            fmt::format("Failed to decode cnf contents: {}", cnf_error));
        }

        if (cnf_items[CWT_CNF_KID_INDEX].uDataType != QCBOR_TYPE_NONE)
        {
          parsed.cwt_claims.cnf->kid = cbor::as_vector(cnf_items[CWT_CNF_KID_INDEX].val.string);
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
      ATTESTATION_INDEX,
      END_INDEX,
    };
    QCBORItem header_items[END_INDEX + 1];
    header_items[X5CHAIN_INDEX].label.int64 = COSE_HEADER_PARAM_X5CHAIN;
    header_items[X5CHAIN_INDEX].uLabelType = QCBOR_TYPE_INT64;
    header_items[X5CHAIN_INDEX].uDataType = QCBOR_TYPE_ANY;

    header_items[ATTESTATION_INDEX].label.string =
      UsefulBuf_FromSZ(ATTESTATION_HEADER_PARAM);
    header_items[ATTESTATION_INDEX].uLabelType = QCBOR_TYPE_TEXT_STRING;
    header_items[ATTESTATION_INDEX].uDataType = QCBOR_TYPE_TEXT_STRING;

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
    if (header_items[ATTESTATION_INDEX].uDataType != QCBOR_TYPE_NONE)
    {
      parsed.attestation =
        cbor::as_string(header_items[ATTESTATION_INDEX].val.string);
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
      throw COSESignatureValidationError("COSE decoding failed");
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
