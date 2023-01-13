// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "cbor.h"
#include "openssl_wrappers.h"
#include "public_key.h"
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

  // Temporary made up profile label, we don't expect claims to contain a
  // profile header parameter yet, but it's useful to have a label so we can
  // easily act on the absence of a profile.
  static constexpr int64_t COSE_HEADER_PARAM_PROFILE = 6861;

  // Temporary assignments from draft-birkholz-scitt-architecture
  static constexpr int64_t COSE_HEADER_PARAM_ISSUER = 391;
  static constexpr int64_t COSE_HEADER_PARAM_FEED = 392;
  static constexpr int64_t COSE_HEADER_PARAM_SCITT_RECEIPTS = 394;

  // Notary header parameters.
  static constexpr const char* NOTARY_HEADER_PARAM_SIGNING_SCHEME =
    "io.cncf.notary.signingScheme";
  static constexpr const char* NOTARY_HEADER_PARAM_SIGNING_TIME =
    "io.cncf.notary.signingTime";
  static constexpr const char* NOTARY_HEADER_PARAM_AUTHENTIC_SIGNING_TIME =
    "io.cncf.notary.authenticSigningTime";
  static constexpr const char* NOTARY_HEADER_PARAM_EXPIRY =
    "io.cncf.notary.expiry";

  struct COSEDecodeError : public std::runtime_error
  {
    COSEDecodeError(const std::string& msg) : std::runtime_error(msg) {}
  };

  struct UnprotectedHeader
  {
    // We currently expect only notary to use the unprotected header and
    // we expect to find only the x5chain in there.
    std::optional<std::vector<std::vector<uint8_t>>> x5chain;
  };

  UnprotectedHeader decode_unprotected_header(
    const std::vector<uint8_t>& cose_sign1)
  {
    UnprotectedHeader parsed;
    // Adapted from parse_cose_header_parameters in t_cose_parameters.c.
    // t_cose doesn't support custom header parameters yet.

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
    QCBORItem coseItem;
    QCBORDecode_GetNext(&ctx, &coseItem);

    struct q_useful_buf_c unprotected_parameters;
    QCBORDecode_EnterMap(&ctx, NULL);

    enum
    {
      ALG_INDEX,
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
      throw COSEDecodeError("Failed to decode unprotected header");
    }
    if (header_items[X5CHAIN_INDEX].uDataType != QCBOR_TYPE_NONE)
    {
      parsed.x5chain = std::vector<std::vector<uint8_t>>();

      QCBORItem chainItem = header_items[X5CHAIN_INDEX];
      if (chainItem.uDataType == QCBOR_TYPE_ARRAY)
      {
        int lenOfArray = chainItem.val.uCount;
        if (lenOfArray == 0)
        {
          throw COSEDecodeError(
            "x5chain array length was 0 in cose unprotected header.");
        }
        QCBORDecode_EnterArrayFromMapN(&ctx, COSE_HEADER_PARAM_X5CHAIN);
        for (int i = 0; i < lenOfArray; i++)
        {
          QCBORDecode_GetNext(&ctx, &chainItem);
          if (chainItem.uDataType == QCBOR_TYPE_BYTE_STRING)
          {
            parsed.x5chain->push_back(cbor::as_vector(chainItem.val.string));
          }
          else
          {
            throw COSEDecodeError(
              "Next item in chain was not of type qcbor byte string.");
          }
        }
        QCBORDecode_ExitArray(&ctx);
      }
      else if (chainItem.uDataType == QCBOR_TYPE_BYTE_STRING)
      {
        parsed.x5chain->push_back(cbor::as_vector(chainItem.val.string));
      }
      else
      {
        CCF_APP_INFO("x5c type", chainItem.uDataType);
        throw COSEDecodeError(
          "Value type of x5chain in unprotected header is not array or byte "
          "string.");
      }
    }
    QCBORDecode_ExitMap(&ctx);
    QCBORDecode_ExitBstrWrapped(&ctx);

    return parsed;
  }

  struct ProtectedHeader
  {
    // All headers are optional here but optionality will later be validated
    // according to the COSE profile of the claim.
    std::optional<std::string> profile;

    // Vanilla SCITT protected header parameters
    // Issuer is used when verifying with did:web
    // x5chain is used when verification is done with the x509 certificate chain
    std::optional<int64_t> alg;
    std::optional<std::vector<std::variant<int64_t, std::string>>> crit;
    std::optional<std::string> kid;
    std::optional<std::string> issuer;
    std::optional<std::string> feed;
    std::optional<std::string> cty;
    std::optional<std::vector<std::vector<uint8_t>>> x5chain;

    // Extra Notary protected header parameters.
    std::optional<std::string> notary_signing_scheme;
    std::optional<int64_t> notary_signing_time;
    std::optional<int64_t> notary_authentic_signing_time;
    std::optional<int64_t> notary_expiry;
  };

  ProtectedHeader decode_protected_header(
    const std::vector<uint8_t>& cose_sign1)
  {
    ProtectedHeader parsed;

    // Adapted from parse_cose_header_parameters in t_cose_parameters.c.
    // t_cose doesn't support custom header parameters yet.

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

    struct q_useful_buf_c protected_parameters;
    QCBORDecode_EnterBstrWrapped(
      &ctx, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, &protected_parameters);
    QCBORDecode_EnterMap(&ctx, NULL);

    enum
    {
      PROFILE_INDEX,
      ALG_INDEX,
      CRIT_INDEX,
      ISSUER_INDEX,
      FEED_INDEX,
      KID_INDEX,
      CTY_INDEX,
      X5CHAIN_INDEX,
      NOTARY_SIGNING_SCHEME_INDEX,
      NOTARY_SIGNING_TIME_INDEX,
      NOTARY_AUTHENTIC_SIGNING_TIME_INDEX,
      NOTARY_EXPIRY_INDEX,
      END_INDEX,
    };
    QCBORItem header_items[END_INDEX + 1];

    header_items[PROFILE_INDEX].label.int64 = COSE_HEADER_PARAM_PROFILE;
    header_items[PROFILE_INDEX].uLabelType = QCBOR_TYPE_INT64;
    header_items[PROFILE_INDEX].uDataType = QCBOR_TYPE_INT64;

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

    header_items[KID_INDEX].label.int64 = COSE_HEADER_PARAM_KID;
    header_items[KID_INDEX].uLabelType = QCBOR_TYPE_INT64;
    header_items[KID_INDEX].uDataType = QCBOR_TYPE_BYTE_STRING;

    header_items[CTY_INDEX].label.int64 = COSE_HEADER_PARAM_CTY;
    header_items[CTY_INDEX].uLabelType = QCBOR_TYPE_INT64;
    header_items[CTY_INDEX].uDataType = QCBOR_TYPE_ANY;

    header_items[X5CHAIN_INDEX].label.int64 = COSE_HEADER_PARAM_X5CHAIN;
    header_items[X5CHAIN_INDEX].uLabelType = QCBOR_TYPE_INT64;
    header_items[X5CHAIN_INDEX].uDataType = QCBOR_TYPE_ANY;

    header_items[NOTARY_SIGNING_SCHEME_INDEX].label.string =
      UsefulBuf_FromSZ(NOTARY_HEADER_PARAM_SIGNING_SCHEME);
    header_items[NOTARY_SIGNING_SCHEME_INDEX].uLabelType =
      QCBOR_TYPE_TEXT_STRING;
    header_items[NOTARY_SIGNING_SCHEME_INDEX].uDataType =
      QCBOR_TYPE_TEXT_STRING;

    header_items[NOTARY_SIGNING_TIME_INDEX].label.string =
      UsefulBuf_FromSZ(NOTARY_HEADER_PARAM_SIGNING_TIME);
    header_items[NOTARY_SIGNING_TIME_INDEX].uLabelType = QCBOR_TYPE_TEXT_STRING;
    header_items[NOTARY_SIGNING_TIME_INDEX].uDataType = QCBOR_TYPE_DATE_EPOCH;

    header_items[NOTARY_AUTHENTIC_SIGNING_TIME_INDEX].label.string =
      UsefulBuf_FromSZ(NOTARY_HEADER_PARAM_AUTHENTIC_SIGNING_TIME);
    header_items[NOTARY_AUTHENTIC_SIGNING_TIME_INDEX].uLabelType =
      QCBOR_TYPE_TEXT_STRING;
    header_items[NOTARY_AUTHENTIC_SIGNING_TIME_INDEX].uDataType =
      QCBOR_TYPE_DATE_EPOCH;

    header_items[NOTARY_EXPIRY_INDEX].label.string =
      UsefulBuf_FromSZ(NOTARY_HEADER_PARAM_EXPIRY);
    header_items[NOTARY_EXPIRY_INDEX].uLabelType = QCBOR_TYPE_TEXT_STRING;
    header_items[NOTARY_EXPIRY_INDEX].uDataType = QCBOR_TYPE_DATE_EPOCH;

    header_items[END_INDEX].uLabelType = QCBOR_TYPE_NONE;

    QCBORDecode_GetItemsInMap(&ctx, header_items);

    qcbor_result = QCBORDecode_GetError(&ctx);
    if (qcbor_result != QCBOR_SUCCESS)
    {
      throw COSEDecodeError("Failed to decode protected header");
    }

    if (header_items[PROFILE_INDEX].uDataType != QCBOR_TYPE_NONE)
    {
      parsed.kid = cbor::as_string(header_items[PROFILE_INDEX].val.string);
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
      if (critItem.uDataType != QCBOR_TYPE_ARRAY)
      {
        throw COSEDecodeError(
          "Value type of crit in protected header is not of type array");
      }
      int lenOfArray = critItem.val.uCount;
      if (lenOfArray == 0)
      {
        throw COSEDecodeError(
          "Cannot have crit array of length 0 in cose protected header.");
      }
      QCBORDecode_EnterArrayFromMapN(&ctx, COSE_HEADER_PARAM_CRIT);
      for (int i = 0; i < lenOfArray; i++)
      {
        QCBORDecode_GetNext(&ctx, &critItem);
        if (critItem.uDataType == QCBOR_TYPE_TEXT_STRING)
        {
          parsed.crit->push_back(std::variant<int64_t, std::string>(
            std::string(cbor::as_string(critItem.val.string))));
        }
        else if (critItem.uDataType == QCBOR_TYPE_INT64)
        {
          parsed.crit->push_back(
            std::variant<int64_t, std::string>(critItem.val.int64));
        }
        else
        {
          throw COSEDecodeError(
            "Next item in crit was not of type qcbor byte string or qcbor "
            "int64.");
        }
      }
      QCBORDecode_ExitArray(&ctx);
    }
    if (header_items[KID_INDEX].uDataType != QCBOR_TYPE_NONE)
    {
      parsed.kid = cbor::as_string(header_items[KID_INDEX].val.string);
    }
    if (header_items[FEED_INDEX].uDataType != QCBOR_TYPE_NONE)
    {
      parsed.feed = cbor::as_string(header_items[FEED_INDEX].val.string);
    }
    if (header_items[CTY_INDEX].uDataType != QCBOR_TYPE_NONE)
    {
      parsed.cty = cbor::as_string(header_items[CTY_INDEX].val.string);
    }
    if (header_items[X5CHAIN_INDEX].uDataType != QCBOR_TYPE_NONE)
    {
      parsed.x5chain = std::vector<std::vector<uint8_t>>();
      QCBORItem chainItem = header_items[X5CHAIN_INDEX];
      if (chainItem.uDataType == QCBOR_TYPE_ARRAY)
      {
        int lenOfArray = chainItem.val.uCount;
        if (lenOfArray == 0)
        {
          throw COSEDecodeError(
            "x5chain array length was 0 in cose protected header.");
        }
        QCBORDecode_EnterArrayFromMapN(&ctx, COSE_HEADER_PARAM_X5CHAIN);
        for (int i = 0; i < lenOfArray; i++)
        {
          QCBORDecode_GetNext(&ctx, &chainItem);
          if (chainItem.uDataType == QCBOR_TYPE_BYTE_STRING)
          {
            parsed.x5chain->push_back(cbor::as_vector(chainItem.val.string));
          }
          else
          {
            throw COSEDecodeError(
              "Next item in chain was not of type qcbor byte string.");
          }
        }
        QCBORDecode_ExitArray(&ctx);
      }
      else if (chainItem.uDataType == QCBOR_TYPE_BYTE_STRING)
      {
        parsed.x5chain->push_back(cbor::as_vector(chainItem.val.string));
      }
      else
      {
        throw COSEDecodeError(
          "Value type of x5chain in protected header is not array or byte "
          "string.");
      }
    }
    // Extra Notary header parameters.
    if (header_items[NOTARY_SIGNING_SCHEME_INDEX].uDataType != QCBOR_TYPE_NONE)
    {
      parsed.notary_signing_scheme =
        cbor::as_string(header_items[NOTARY_SIGNING_SCHEME_INDEX].val.string);
    }
    if (header_items[NOTARY_SIGNING_TIME_INDEX].uDataType != QCBOR_TYPE_NONE)
    {
      parsed.notary_signing_time =
        header_items[NOTARY_SIGNING_TIME_INDEX].val.epochDate.nSeconds;
    }
    if (
      header_items[NOTARY_AUTHENTIC_SIGNING_TIME_INDEX].uDataType !=
      QCBOR_TYPE_NONE)
    {
      parsed.notary_authentic_signing_time =
        header_items[NOTARY_AUTHENTIC_SIGNING_TIME_INDEX]
          .val.epochDate.nSeconds;
    }
    if (header_items[NOTARY_EXPIRY_INDEX].uDataType != QCBOR_TYPE_NONE)
    {
      parsed.notary_expiry =
        header_items[NOTARY_EXPIRY_INDEX].val.epochDate.nSeconds;
    }

    QCBORDecode_ExitMap(&ctx);
    QCBORDecode_ExitBstrWrapped(&ctx);

    return parsed;
  }

  struct COSESignatureValidationError : public std::runtime_error
  {
    COSESignatureValidationError(const std::string& msg) :
      std::runtime_error(msg)
    {}
  };

  // Temporarily needed for notary_verify().
  std::vector<uint8_t> qcbor_buf_to_vector(const UsefulBufC& buf)
  {
    return std::vector<uint8_t>(
      reinterpret_cast<const uint8_t*>(buf.ptr),
      reinterpret_cast<const uint8_t*>(buf.ptr) + buf.len);
  }

  // Temporarily needed for notary_verify().
  std::vector<uint8_t> get_signature(const std::vector<uint8_t>& cose_sign1)
  {
    UsefulBufC msg{cose_sign1.data(), cose_sign1.size()};

    QCBORDecodeContext ctx;
    QCBORDecode_Init(&ctx, msg, QCBOR_DECODE_MODE_NORMAL);

    QCBORDecode_EnterArray(&ctx, nullptr);

    QCBORItem item;

    // skip body_protected
    QCBORDecode_VGetNextConsume(&ctx, &item);

    // skip unprotected header
    QCBORDecode_VGetNextConsume(&ctx, &item);

    // skip payload
    QCBORDecode_VGetNextConsume(&ctx, &item);

    // signature
    QCBORDecode_GetNext(&ctx, &item);
    auto signature = item.val.string;

    QCBORDecode_ExitArray(&ctx);
    auto error = QCBORDecode_Finish(&ctx);
    if (error)
    {
      throw std::runtime_error("Failed to decode COSE_Sign1");
    }

    return qcbor_buf_to_vector(signature);
  }

  // Temporarily needed for notary_verify().
  bool is_ecdsa_alg(int64_t cose_alg)
  {
    return cose_alg == COSE_ALGORITHM_ES256 ||
      cose_alg == COSE_ALGORITHM_ES384 || cose_alg == COSE_ALGORITHM_ES512;
  }

  // Temporarily needed for notary_verify().
  bool is_rsa_pss_alg(int64_t cose_alg)
  {
    return cose_alg == COSE_ALGORITHM_PS256 ||
      cose_alg == COSE_ALGORITHM_PS384 || cose_alg == COSE_ALGORITHM_PS512;
  }

  // Temporarily needed for notary_verify().
  crypto::MDType get_md_type(int64_t cose_alg)
  {
    switch (cose_alg)
    {
      case COSE_ALGORITHM_ES256:
      case COSE_ALGORITHM_PS256:
        return crypto::MDType::SHA256;
      case COSE_ALGORITHM_ES384:
      case COSE_ALGORITHM_PS384:
        return crypto::MDType::SHA384;
      case COSE_ALGORITHM_ES512:
      case COSE_ALGORITHM_PS512:
        return crypto::MDType::SHA512;
      case COSE_ALGORITHM_EDDSA:
        return crypto::MDType::NONE;
      default:
        throw std::runtime_error("Unsupported COSE algorithm");
    }
  }

  // Temporarily needed for notary_verify().
  const EVP_MD* get_openssl_md_type(crypto::MDType type)
  {
    switch (type)
    {
      case crypto::MDType::NONE:
        return nullptr;
      case crypto::MDType::SHA1:
        return EVP_sha1();
      case crypto::MDType::SHA256:
        return EVP_sha256();
      case crypto::MDType::SHA384:
        return EVP_sha384();
      case crypto::MDType::SHA512:
        return EVP_sha512();
      default:
        throw std::runtime_error("Unsupported hash algorithm");
    }
    return nullptr;
  }

  // Temporarily needed for notary_verify().
  static unsigned ecdsa_key_size(EVP_PKEY* key_evp)
  {
    int key_len_bits;
    unsigned key_len_bytes;

    key_len_bits = EVP_PKEY_bits(key_evp);

    /* Calculation of size per RFC 8152 section 8.1 -- round up to
     * number of bytes. */
    key_len_bytes = (unsigned)key_len_bits / 8;
    if (key_len_bits % 8)
    {
      key_len_bytes++;
    }

    return key_len_bytes;
  }

  // Temporarily needed for notary_verify().
  std::vector<uint8_t> create_tbs(const std::vector<uint8_t>& cose_sign1)
  {
    // Note: This function does not return the hash of the TBS because
    // EdDSA does not support pre-hashed messages as input.

    // Sig_structure = [
    //     context: "Signature1",
    //     body_protected: empty_or_serialized_map,
    //     external_aad: bstr,
    //     payload: bstr
    // ]

    // Extract fields from the COSE_Sign1 message.
    UsefulBufC msg{cose_sign1.data(), cose_sign1.size()};

    QCBORDecodeContext decode_ctx;
    QCBORDecode_Init(&decode_ctx, msg, QCBOR_DECODE_MODE_NORMAL);

    QCBORDecode_EnterArray(&decode_ctx, nullptr);

    QCBORItem item;

    // body_protected
    QCBORDecode_GetNext(&decode_ctx, &item);
    auto body_protected = item.val.string;

    // skip unprotected header
    QCBORDecode_VGetNextConsume(&decode_ctx, &item);

    // payload
    QCBORDecode_GetNext(&decode_ctx, &item);
    auto payload = item.val.string;

    // signature
    QCBORDecode_GetNext(&decode_ctx, &item);
    auto signature = item.val.string;

    QCBORDecode_ExitArray(&decode_ctx);
    auto error = QCBORDecode_Finish(&decode_ctx);
    if (error)
    {
      throw std::runtime_error("Failed to decode COSE_Sign1");
    }

    // Create Sig_structure.
    // Note that hashing the structure incrementally to avoid
    // doubling memory would work for RSA-PSS and ECDSA, but not EdDSA.

    std::vector<uint8_t> sig_structure_buf(cose_sign1.size() + 1024);
    UsefulBuf sig_structure{sig_structure_buf.data(), sig_structure_buf.size()};

    QCBOREncodeContext encode_ctx;
    QCBOREncode_Init(&encode_ctx, sig_structure);

    QCBOREncode_OpenArray(&encode_ctx);

    // context
    QCBOREncode_AddSZString(&encode_ctx, "Signature1");

    // body_protected: The protected header of the message.
    QCBOREncode_AddBytes(&encode_ctx, body_protected);

    // external_aad: always empty.
    QCBOREncode_AddBytes(&encode_ctx, NULLUsefulBufC);

    // payload: The payload of the message.
    QCBOREncode_AddBytes(&encode_ctx, payload);

    QCBOREncode_CloseArray(&encode_ctx);

    UsefulBufC encoded_cbor;
    QCBORError err;
    err = QCBOREncode_Finish(&encode_ctx, &encoded_cbor);
    if (err != QCBOR_SUCCESS)
    {
      throw std::runtime_error("Error encoding CBOR");
    }

    auto cbor = std::vector<uint8_t>(
      (uint8_t*)encoded_cbor.ptr,
      (uint8_t*)encoded_cbor.ptr + encoded_cbor.len);
    return cbor;
  }

  static enum t_cose_err_t ecdsa_signature_cose_to_der(
    EVP_PKEY* key_evp,
    struct q_useful_buf_c cose_signature,
    struct q_useful_buf buffer,
    struct q_useful_buf_c* der_signature)
  {
    unsigned key_len;
    enum t_cose_err_t return_value;
    BIGNUM* signature_r_bn = NULL;
    BIGNUM* signature_s_bn = NULL;
    int ossl_result;
    ECDSA_SIG* signature;
    unsigned char* der_signature_ptr;
    int der_signature_len;

    key_len = ecdsa_key_size(key_evp);

    /* Check the signature length against expected */
    if (cose_signature.len != key_len * 2)
    {
      return_value = T_COSE_ERR_SIG_VERIFY;
      goto Done;
    }

    /* Put the r and the s from the signature into big numbers */
    signature_r_bn =
      BN_bin2bn((const uint8_t*)cose_signature.ptr, (int)key_len, NULL);
    if (signature_r_bn == NULL)
    {
      return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
      goto Done;
    }

    signature_s_bn = BN_bin2bn(
      ((const uint8_t*)cose_signature.ptr) + key_len, (int)key_len, NULL);
    if (signature_s_bn == NULL)
    {
      BN_free(signature_r_bn);
      return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
      goto Done;
    }

    /* Put the signature bytes into an ECDSA_SIG */
    signature = ECDSA_SIG_new();
    if (signature == NULL)
    {
      /* Don't leak memory in error condition */
      BN_free(signature_r_bn);
      BN_free(signature_s_bn);
      return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
      goto Done;
    }

    /* Put the r and s bignums into an ECDSA_SIG. Freeing
     * ossl_sig_to_verify will now free r and s.
     */
    ossl_result = ECDSA_SIG_set0(signature, signature_r_bn, signature_s_bn);
    if (ossl_result != 1)
    {
      BN_free(signature_r_bn);
      BN_free(signature_s_bn);
      return_value = T_COSE_ERR_SIG_FAIL;
      goto Done;
    }

    /* Now output the ECDSA_SIG structure in DER format.
     *
     * Code safety is the priority here.  i2d_ECDSA_SIG() has two
     * output buffer modes, one where it just writes to the buffer
     * given and the other were it allocates memory.  It would be
     * better to avoid the allocation, but the copy mode is not safe
     * because you can't give it a buffer length. This is bad stuff
     * from last century.
     *
     * So the allocation mode is used on the presumption that it is
     * safe and correct even though there is more copying and memory
     * use.
     */
    der_signature_ptr = NULL;
    der_signature_len = i2d_ECDSA_SIG(signature, &der_signature_ptr);
    ECDSA_SIG_free(signature);
    if (der_signature_len < 0)
    {
      return_value = T_COSE_ERR_SIG_FAIL;
      goto Done;
    }

    *der_signature = q_useful_buf_copy_ptr(
      buffer, der_signature_ptr, (size_t)der_signature_len);
    if (q_useful_buf_c_is_null_or_empty(*der_signature))
    {
      return_value = T_COSE_ERR_SIG_FAIL;
      goto Done;
    }

    OPENSSL_free(der_signature_ptr);

    return_value = T_COSE_SUCCESS;

  Done:
    /* All the memory frees happen along the way in the code above. */
    return return_value;
  }

  /**
   * Verify the signature of a Notary COSE Sign1 message using the given public key.
   *
   * Beyond the basic verification of key usage and the signature
   * itself, no particular validation of the message is done.
   *
   * This function is a temporary workaround until t_cose supports custom header parameters
   * in the crit parameter list.
   */
  void notary_verify(
    const std::vector<uint8_t>& cose_sign1, const PublicKey& key)
  {
    CCF_APP_INFO("Verifying notary claim.");
    auto phdr = decode_protected_header(cose_sign1);
    auto header_alg = phdr.alg.value();
    auto key_alg = key.get_cose_alg();
    if (key_alg.has_value() && header_alg != key_alg.value())
    {
      throw COSESignatureValidationError(
        "Algorithm mismatch between protected header and public key");
    }

    auto md_type = get_md_type(header_alg);
    auto ossl_md_type = get_openssl_md_type(md_type);
    auto tbs = create_tbs(cose_sign1);
    auto signature = get_signature(cose_sign1);

    struct q_useful_buf_c openssl_signature;
#define DER_SIG_ENCODE_OVER_HEAD 16
#define T_COSE_MAX_ECDSA_SIG_SIZE 132
    MakeUsefulBufOnStack(
      der_format_buffer, T_COSE_MAX_ECDSA_SIG_SIZE + DER_SIG_ENCODE_OVER_HEAD);

    if (is_ecdsa_alg(header_alg))
    {
      CCF_APP_INFO("Verifying notary claim ECDSA");
      // Convert from IEEE to DER
      enum t_cose_err_t return_value;
      return_value = ecdsa_signature_cose_to_der(
        key.get_evp_pkey(),
        cbor::from_bytes(signature),
        der_format_buffer,
        &openssl_signature);
      if (return_value)
      {
        throw COSESignatureValidationError("ECDSA Signature conversion failed");
      }
      signature = std::vector<uint8_t>(
        (const uint8_t*)openssl_signature.ptr,
        (const uint8_t*)openssl_signature.ptr + openssl_signature.len);
    }

    OpenSSL::Unique_EVP_MD_CTX md_ctx;
    EVP_MD_CTX_init(md_ctx);
    EVP_PKEY_CTX* pctx;
    OpenSSL::CHECK1(EVP_DigestVerifyInit(
      md_ctx, &pctx, ossl_md_type, nullptr, key.get_evp_pkey()));
    if (is_rsa_pss_alg(header_alg))
    {
      OpenSSL::CHECK1(
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING));
    }

    auto valid =
      EVP_DigestVerify(
        md_ctx, signature.data(), signature.size(), tbs.data(), tbs.size()) ==
      1;

    if (!valid)
    {
      throw COSESignatureValidationError("Signature verification failed");
    }
  }

  /**
   * Verify the signature of a COSE Sign1 message using the given public key.
   *
   * Beyond the basic verification of key usage and the signature
   * itself, no particular validation of the message is done.
   */
  void verify(const std::vector<uint8_t>& cose_sign1, const PublicKey& key)
  {
    q_useful_buf_c signed_cose;
    signed_cose.ptr = cose_sign1.data();
    signed_cose.len = cose_sign1.size();

    t_cose_sign1_verify_ctx verify_ctx;

    // Do some preliminary decoding, to get the header parameters and potential
    // auxiliary buffer size.
    t_cose_parameters params;
    t_cose_sign1_verify_init(
      &verify_ctx, T_COSE_OPT_TAG_REQUIRED | T_COSE_OPT_DECODE_ONLY);
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

    t_cose_sign1_verify_init(&verify_ctx, T_COSE_OPT_TAG_REQUIRED);
    t_cose_sign1_set_verification_key(&verify_ctx, cose_key);

    // EdDSA signature verification needs an auxiliary buffer.
    // For other algorithms, the buffer size will just be 0.
    std::vector<uint8_t> auxiliary_buffer(auxiliary_buffer_size);
    t_cose_sign1_verify_set_auxiliary_buffer(
      &verify_ctx, {auxiliary_buffer.data(), auxiliary_buffer.size()});

    error = t_cose_sign1_verify(&verify_ctx, signed_cose, nullptr, nullptr);
    if (error)
    {
      throw COSESignatureValidationError("Signature verification failed");
    }
  }

  /**
   * Extract the bstr fields from a COSE Sign1.
   *
   * Returns an array containing the protected headers, the payload and the
   * signature.
   */
  inline std::array<std::span<const uint8_t>, 3> extract_sign1_fields(
    std::span<const uint8_t> cose_sign1)
  {
    QCBORDecodeContext ctx;
    QCBORDecode_Init(
      &ctx, cbor::from_bytes(cose_sign1), QCBOR_DECODE_MODE_NORMAL);

    QCBORDecode_EnterArray(&ctx, nullptr);

    QCBORItem item;

    // protected headers
    QCBORDecode_GetNext(&ctx, &item);
    auto phdrs = cbor::as_span(item.val.string);

    // skip unprotected header
    QCBORDecode_VGetNextConsume(&ctx, &item);

    // payload
    QCBORDecode_GetNext(&ctx, &item);
    auto payload = cbor::as_span(item.val.string);

    // signature
    QCBORDecode_GetNext(&ctx, &item);
    auto signature = cbor::as_span(item.val.string);

    QCBORDecode_ExitArray(&ctx);
    auto error = QCBORDecode_Finish(&ctx);
    if (error)
    {
      throw std::runtime_error("Failed to decode COSE_Sign1");
    }

    return {phdrs, payload, signature};
  }

  /**
   * Compute the digest of the TBS for a countersignature over a COSE Sign1.
   *
   *  The following structure is hashed incrementally to avoid
   *  serializing it in full. This avoids excessive memory usage
   *  for larger payloads.
   *
   * Countersign_structure = [
   *     context: "CounterSignatureV2",
   *     body_protected: empty_or_serialized_map,
   *     sign_protected: empty_or_serialized_map,
   *     external_aad: bstr,
   *     payload: bstr,
   *     other_fields: [
   *         signature: bstr
   *     ]
   * ]
   */
  inline crypto::Sha256Hash create_countersign_tbs_hash(
    std::span<const uint8_t> cose_sign1,
    std::span<const uint8_t> sign_protected)
  {
    auto [body_protected, payload, signature] =
      extract_sign1_fields(cose_sign1);

    // Hash the Countersign_structure incrementally.
    cbor::hasher hash;
    hash.open_array(6);
    hash.add_text("CounterSignatureV2");

    // body_protected: The protected header of the target message.
    hash.add_bytes(body_protected);
    // sign_protected: The protected header of the countersigner.
    hash.add_bytes(sign_protected);
    // external_aad: always empty.
    hash.add_bytes({});
    // payload: The payload of the target message.
    hash.add_bytes(payload);

    // other_fields: Array holding the signature of the target message.
    hash.open_array(1);
    hash.add_bytes(signature);

    return hash.finalise();
  }

  std::vector<uint8_t> embed_receipt(
    const std::vector<uint8_t>& cose_sign1, const std::vector<uint8_t>& receipt)
  {
    // t_cose doesn't support modifying the unprotected header yet.
    // The following code is a low-level workaround.

    // Extract fields from the COSE_Sign1 message.
    QCBORDecodeContext ctx;
    QCBORDecode_Init(
      &ctx, cbor::from_bytes(cose_sign1), QCBOR_DECODE_MODE_NORMAL);

    QCBORDecode_EnterArray(&ctx, nullptr);

    QCBORItem item;

    // protected header
    QCBORDecode_GetNext(&ctx, &item);
    auto protected_header = item.val.string;

    // skip unprotected header (we'll create a new one)
    QCBORDecode_VGetNextConsume(&ctx, &item);

    // payload
    QCBORDecode_GetNext(&ctx, &item);
    auto payload = item.val.string;

    // signature
    QCBORDecode_GetNext(&ctx, &item);
    auto signature = item.val.string;

    QCBORDecode_ExitArray(&ctx);
    auto error = QCBORDecode_Finish(&ctx);
    if (error)
    {
      throw std::runtime_error("Failed to decode COSE_Sign1");
    }

    // Serialize COSE_Sign1 with new unprotected header.
    cbor::encoder encoder;

    QCBOREncode_AddTag(encoder, CBOR_TAG_COSE_SIGN1);

    QCBOREncode_OpenArray(encoder);

    QCBOREncode_AddBytes(encoder, protected_header);

    // unprotected header
    QCBOREncode_OpenMap(encoder);
    QCBOREncode_OpenArrayInMapN(encoder, COSE_HEADER_PARAM_SCITT_RECEIPTS);
    QCBOREncode_AddEncoded(encoder, cbor::from_bytes(receipt));
    QCBOREncode_CloseArray(encoder);
    QCBOREncode_CloseMap(encoder);

    QCBOREncode_AddBytes(encoder, payload);
    QCBOREncode_AddBytes(encoder, signature);

    QCBOREncode_CloseArray(encoder);

    return encoder.finish();
  }
}
