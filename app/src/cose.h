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
  static constexpr int64_t COSE_HEADER_PARAM_CTY = 3;
  static constexpr int64_t COSE_HEADER_PARAM_KID = 4;
  static constexpr int64_t COSE_HEADER_PARAM_X5CHAIN = 33;

  // Temporary assignments from draft-birkholz-scitt-architecture
  static constexpr int64_t COSE_HEADER_PARAM_ISSUER = 391;
  static constexpr int64_t COSE_HEADER_PARAM_FEED = 392;
  static constexpr int64_t COSE_HEADER_PARAM_SCITT_RECEIPTS = 394;

  struct COSEDecodeError : public std::runtime_error
  {
    COSEDecodeError(const std::string& msg) : std::runtime_error(msg) {}
  };

  struct ProtectedHeader
  {
    // Issuer is used when verifying with did:web
    // x5chain is used when verification is done with the x509 certificate chain
    int64_t alg;
    std::optional<std::string> kid;
    std::optional<std::string> issuer;
    std::optional<std::string> feed;
    std::string cty;
    std::optional<std::vector<std::vector<uint8_t>>> x5chain;
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
      ALG_INDEX,
      ISSUER_INDEX,
      FEED_INDEX,
      KID_INDEX,
      CTY_INDEX,
      X5CHAIN_INDEX,
      END_INDEX,
    };
    QCBORItem header_items[END_INDEX + 1];

    header_items[ALG_INDEX].label.int64 = COSE_HEADER_PARAM_ALG;
    header_items[ALG_INDEX].uLabelType = QCBOR_TYPE_INT64;
    header_items[ALG_INDEX].uDataType = QCBOR_TYPE_INT64;

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

    header_items[END_INDEX].uLabelType = QCBOR_TYPE_NONE;

    QCBORDecode_GetItemsInMap(&ctx, header_items);

    qcbor_result = QCBORDecode_GetError(&ctx);
    if (qcbor_result != QCBOR_SUCCESS)
    {
      throw COSEDecodeError("Failed to decode protected header");
    }

    if (header_items[ALG_INDEX].uDataType == QCBOR_TYPE_NONE)
    {
      throw COSEDecodeError("Missing algorithm in protected header");
    }
    if (header_items[KID_INDEX].uDataType != QCBOR_TYPE_NONE)
    {
      parsed.kid = cbor::as_string(header_items[KID_INDEX].val.string);
    }
    if (header_items[ISSUER_INDEX].uDataType != QCBOR_TYPE_NONE)
    {
      parsed.issuer = cbor::as_string(header_items[ISSUER_INDEX].val.string);
    }
    if (header_items[FEED_INDEX].uDataType != QCBOR_TYPE_NONE)
    {
      parsed.feed = cbor::as_string(header_items[FEED_INDEX].val.string);
    }
    if (header_items[CTY_INDEX].uDataType == QCBOR_TYPE_NONE)
    {
      throw COSEDecodeError("Missing cty in protected header");
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

    parsed.alg = header_items[ALG_INDEX].val.int64;
    parsed.cty = cbor::as_string(header_items[CTY_INDEX].val.string);

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
