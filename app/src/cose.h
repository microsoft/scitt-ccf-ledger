// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "cbor.h"
#include "openssl_wrappers.h"
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

  std::set<std::variant<int64_t, std::string>> BASIC_HEADER_PARAMS{
    COSE_HEADER_PARAM_ALG,
    COSE_HEADER_PARAM_CRIT,
    COSE_HEADER_PARAM_CTY,
    COSE_HEADER_PARAM_KID,
    COSE_HEADER_PARAM_X5CHAIN,
  };

  // Temporary assignments from draft-birkholz-scitt-architecture
  static constexpr int64_t COSE_HEADER_PARAM_ISSUER = 391;
  static constexpr int64_t COSE_HEADER_PARAM_FEED = 392;
  static constexpr int64_t COSE_HEADER_PARAM_SCITT_RECEIPTS = 394;

  std::set<std::variant<int64_t, std::string>> EXTRA_HEADER_PARAMS{
    COSE_HEADER_PARAM_ISSUER,
    COSE_HEADER_PARAM_FEED,
    COSE_HEADER_PARAM_SCITT_RECEIPTS,
  };

  // Notary header parameters.
  static constexpr const char* NOTARY_HEADER_PARAM_SIGNING_SCHEME =
    "io.cncf.notary.signingScheme";
  static constexpr const char* NOTARY_HEADER_PARAM_SIGNING_TIME =
    "io.cncf.notary.signingTime";
  static constexpr const char* NOTARY_HEADER_PARAM_AUTHENTIC_SIGNING_TIME =
    "io.cncf.notary.authenticSigningTime";
  static constexpr const char* NOTARY_HEADER_PARAM_EXPIRY =
    "io.cncf.notary.expiry";

  std::set<std::variant<int64_t, std::string>> NOTARY_HEADER_PARAMS{
    NOTARY_HEADER_PARAM_SIGNING_SCHEME,
    NOTARY_HEADER_PARAM_SIGNING_TIME,
    NOTARY_HEADER_PARAM_AUTHENTIC_SIGNING_TIME,
    NOTARY_HEADER_PARAM_EXPIRY};

  struct COSEDecodeError : public std::runtime_error
  {
    COSEDecodeError(const std::string& msg) : std::runtime_error(msg) {}
  };

  struct ProtectedHeader
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
    std::optional<std::variant<int64_t, std::string>> cty;
    std::optional<std::vector<std::vector<uint8_t>>> x5chain;

    // Extra Notary protected header parameters.
    std::optional<std::string> notary_signing_scheme;
    std::optional<int64_t> notary_signing_time;
    std::optional<int64_t> notary_authentic_signing_time;
    std::optional<int64_t> notary_expiry;

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
      if (
        label ==
          std::variant<int64_t, std::string>(
            NOTARY_HEADER_PARAM_SIGNING_SCHEME) and
        notary_signing_scheme.has_value())
      {
        return true;
      }
      if (
        label ==
          std::variant<int64_t, std::string>(
            NOTARY_HEADER_PARAM_SIGNING_TIME) and
        notary_signing_time.has_value())
      {
        return true;
      }
      if (
        label ==
          std::variant<int64_t, std::string>(
            NOTARY_HEADER_PARAM_AUTHENTIC_SIGNING_TIME) and
        notary_authentic_signing_time.has_value())
      {
        return true;
      }
      if (
        label ==
          std::variant<int64_t, std::string>(NOTARY_HEADER_PARAM_EXPIRY) and
        notary_expiry.has_value())
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
    // parameter in the context of a notary profile.
    bool is_known(
      const std::variant<int64_t, std::string>& label,
      std::set<std::variant<int64_t, std::string>> profile_paramters) const
    {
      if (
        BASIC_HEADER_PARAMS.contains(label) ||
        EXTRA_HEADER_PARAMS.contains(label) ||
        profile_paramters.contains(label))
      {
        return true;
      }
      return false;
    }
  };

  struct UnprotectedHeader
  {
    // We currently expect only notary to use the unprotected header and
    // we expect to find only the x5chain in there.
    std::optional<std::vector<std::vector<uint8_t>>> x5chain;
  };

  std::vector<std::vector<uint8_t>> decode_x5chain(
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

  ProtectedHeader decode_protected_header(QCBORDecodeContext& ctx)
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

    if (header_items[X5CHAIN_INDEX].uDataType != QCBOR_TYPE_NONE)
    {
      parsed.x5chain = decode_x5chain(ctx, header_items[X5CHAIN_INDEX]);
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

    qcbor_result = QCBORDecode_GetError(&ctx);
    if (qcbor_result != QCBOR_SUCCESS)
    {
      throw COSEDecodeError(
        fmt::format("Failed to decode protected header: {}", qcbor_result));
    }

    return parsed;
  }

  UnprotectedHeader decode_unprotected_header(QCBORDecodeContext& ctx)
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

  std::tuple<ProtectedHeader, UnprotectedHeader> decode_headers(
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

    UsefulBufC bstr_item;
    // protected headers
    QCBORDecode_GetByteString(&ctx, &bstr_item);
    auto phdrs = cbor::as_span(bstr_item);

    QCBORItem item;
    // skip unprotected header
    QCBORDecode_VGetNextConsume(&ctx, &item);

    // payload
    QCBORDecode_GetByteString(&ctx, &bstr_item);
    auto payload = cbor::as_span(bstr_item);

    // signature
    QCBORDecode_GetByteString(&ctx, &bstr_item);
    auto signature = cbor::as_span(bstr_item);

    QCBORDecode_ExitArray(&ctx);
    auto error = QCBORDecode_Finish(&ctx);
    if (error)
    {
      throw std::runtime_error("Failed to decode COSE_Sign1");
    }

    return {phdrs, payload, signature};
  }

  /**
   * Verify the signature of a COSE Sign1 message using the given public key.
   *
   * Beyond the basic verification of key usage and the signature
   * itself, no particular validation of the message is done.
   */
  void verify(
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

    error = t_cose_sign1_verify(&verify_ctx, signed_cose, nullptr, nullptr);
    if (error)
    {
      throw COSESignatureValidationError("Signature verification failed");
    }
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
    auto [protected_header, payload, signature] =
      extract_sign1_fields(cose_sign1);

    // Decode unprotected header.
    // TODO: This is a temporary solution to carry over Notary's x5chain
    // parameter. Ideally, the full unprotected header should be preserved
    // but that is more tricky to do in QCBOR.
    UnprotectedHeader uhdr = std::get<1>(cose::decode_headers(cose_sign1));
    auto x5chain = uhdr.x5chain;

    // Serialize COSE_Sign1 with new unprotected header.
    cbor::encoder encoder;

    QCBOREncode_AddTag(encoder, CBOR_TAG_COSE_SIGN1);

    QCBOREncode_OpenArray(encoder);

    QCBOREncode_AddBytes(encoder, cbor::from_bytes(protected_header));

    // unprotected header
    QCBOREncode_OpenMap(encoder);
    QCBOREncode_OpenArrayInMapN(encoder, COSE_HEADER_PARAM_SCITT_RECEIPTS);
    QCBOREncode_AddEncoded(encoder, cbor::from_bytes(receipt));
    QCBOREncode_CloseArray(encoder);
    if (x5chain.has_value())
    {
      auto certs = x5chain.value();
      if (certs.size() == 1)
      {
        // To obey the IETF COSE X509 draft;
        // A single cert MUST be serialized as a single bstr.
        QCBOREncode_AddBytesToMapN(
          encoder, COSE_HEADER_PARAM_X5CHAIN, cbor::from_bytes(certs[0]));
      }
      else
      {
        // And multiple certs MUST be serialized as an array of bstrs.
        QCBOREncode_OpenArrayInMapN(encoder, COSE_HEADER_PARAM_X5CHAIN);
        for (auto& cert : certs)
        {
          QCBOREncode_AddBytes(encoder, cbor::from_bytes(cert));
        }
        QCBOREncode_CloseArray(encoder);
      }
    }
    QCBOREncode_CloseMap(encoder);

    QCBOREncode_AddBytes(encoder, cbor::from_bytes(payload));
    QCBOREncode_AddBytes(encoder, cbor::from_bytes(signature));

    QCBOREncode_CloseArray(encoder);

    return encoder.finish();
  }
}
