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
    std::optional<std::string> cty;
    std::optional<std::vector<std::vector<uint8_t>>> x5chain;

    // Extra Notary protected header parameters.
    std::optional<std::string> notary_signing_scheme;
    std::optional<int64_t> notary_signing_time;
    std::optional<int64_t> notary_authentic_signing_time;
    std::optional<int64_t> notary_expiry;

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
        CCF_APP_INFO("Single cert found in x5chain array in COSE header.");
      }
    }
    else if (x5chain.uDataType == QCBOR_TYPE_BYTE_STRING)
    {
      parsed.push_back(cbor::as_vector(x5chain.val.string));
    }
    else
    {
      CCF_APP_FAIL("Type: {}", x5chain.uDataType);
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
    if (header_items[CTY_INDEX].uDataType != QCBOR_TYPE_NONE)
    {
      parsed.cty = cbor::as_string(header_items[CTY_INDEX].val.string);
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
      throw std::runtime_error("Failed to decode COSE_Sign1");
    }
    return std::make_tuple(phdr, uhdr);
  }

  struct COSESignatureValidationError : public std::runtime_error
  {
    COSESignatureValidationError(const std::string& msg) :
      std::runtime_error(msg)
    {}
  };

  // Temporarily needed for notary_verify().
  bool is_ecdsa_alg(int64_t cose_alg)
  {
    return cose_alg == T_COSE_ALGORITHM_ES256 ||
      cose_alg == T_COSE_ALGORITHM_ES384 || cose_alg == T_COSE_ALGORITHM_ES512;
  }

  // Temporarily needed for notary_verify().
  bool is_rsa_pss_alg(int64_t cose_alg)
  {
    return cose_alg == T_COSE_ALGORITHM_PS256 ||
      cose_alg == T_COSE_ALGORITHM_PS384 || cose_alg == T_COSE_ALGORITHM_PS512;
  }

  // Temporarily needed for notary_verify().
  crypto::MDType get_md_type(int64_t cose_alg)
  {
    switch (cose_alg)
    {
      case T_COSE_ALGORITHM_ES256:
      case T_COSE_ALGORITHM_PS256:
        return crypto::MDType::SHA256;
      case T_COSE_ALGORITHM_ES384:
      case T_COSE_ALGORITHM_PS384:
        return crypto::MDType::SHA384;
      case T_COSE_ALGORITHM_ES512:
      case T_COSE_ALGORITHM_PS512:
        return crypto::MDType::SHA512;
      case T_COSE_ALGORITHM_EDDSA:
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
  std::vector<uint8_t> create_sign1_tbs(
    std::span<const uint8_t> protected_header, std::span<const uint8_t> payload)
  {
    // Note: This function does not return the hash of the TBS because
    // EdDSA does not support pre-hashed messages as input.

    // Sig_structure = [
    //     context: "Signature1",
    //     body_protected: empty_or_serialized_map,
    //     external_aad: bstr,
    //     payload: bstr
    // ]

    cbor::encoder ctx(protected_header.size() + payload.size() + 1024);
    QCBOREncode_OpenArray(ctx);

    // context
    QCBOREncode_AddSZString(ctx, "Signature1");

    // body_protected: The protected header of the message.
    QCBOREncode_AddBytes(ctx, cbor::from_bytes(protected_header));

    // external_aad: always empty.
    QCBOREncode_AddBytes(ctx, NULLUsefulBufC);

    // payload: The payload of the message.
    QCBOREncode_AddBytes(ctx, cbor::from_bytes(payload));

    QCBOREncode_CloseArray(ctx);

    return ctx.finish();
  }

  // Temporarily needed for notary_verify().
  std::vector<uint8_t> ecdsa_sig_from_r_s(
    const uint8_t* r,
    size_t r_size,
    const uint8_t* s,
    size_t s_size,
    bool big_endian = true)
  {
    OpenSSL::Unique_BIGNUM r_bn;
    OpenSSL::Unique_BIGNUM s_bn;
    if (big_endian)
    {
      OpenSSL::CHECKNULL(BN_bin2bn(r, r_size, r_bn));
      OpenSSL::CHECKNULL(BN_bin2bn(s, s_size, s_bn));
    }
    else
    {
      OpenSSL::CHECKNULL(BN_lebin2bn(r, r_size, r_bn));
      OpenSSL::CHECKNULL(BN_lebin2bn(s, s_size, s_bn));
    }
    OpenSSL::Unique_ECDSA_SIG sig;
    OpenSSL::CHECK1(ECDSA_SIG_set0(sig, r_bn, s_bn));
    // Ignore previous pointers, as they're now managed by ECDSA_SIG_set0
    // https://www.openssl.org/docs/man1.1.1/man3/ECDSA_SIG_get0.html
    (void)r_bn.release();
    (void)s_bn.release();
    auto der_size = i2d_ECDSA_SIG(sig, nullptr);
    OpenSSL::CHECK0(der_size);
    std::vector<uint8_t> der_sig(der_size);
    auto der_sig_buf = der_sig.data();
    OpenSSL::CHECK0(i2d_ECDSA_SIG(sig, &der_sig_buf));
    return der_sig;
  }

  // Temporarily needed for notary_verify().
  std::vector<uint8_t> ecdsa_sig_p1363_to_der(
    std::span<const uint8_t> signature)
  {
    auto half_size = signature.size() / 2;
    return ecdsa_sig_from_r_s(
      signature.data(), half_size, signature.data() + half_size, half_size);
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

  // Temporarily needed for notary_verify().
  /**
   * Verify the signature of a Notary COSE Sign1 message using the given public
   * key.
   *
   * Beyond the basic verification of key usage and the signature
   * itself, no particular validation of the message is done.
   *
   * This function is a temporary workaround until t_cose supports custom header
   * parameters in the crit parameter list.
   */
  void notary_verify(
    const std::vector<uint8_t>& cose_sign1,
    const ProtectedHeader& phdr,
    const PublicKey& key)
  {
    auto header_alg = phdr.alg.value();
    auto key_alg = key.get_cose_alg();
    if (key_alg.has_value() && header_alg != key_alg.value())
    {
      throw COSESignatureValidationError(
        "Algorithm mismatch between protected header and public key");
    }

    auto [protected_header, payload, signature] =
      extract_sign1_fields(cose_sign1);

    auto md_type = get_md_type(header_alg);
    auto ossl_md_type = get_openssl_md_type(md_type);
    auto tbs = create_sign1_tbs(protected_header, payload);

    std::vector<uint8_t> signature_tmp;
    if (is_ecdsa_alg(header_alg))
    {
      signature_tmp = ecdsa_sig_p1363_to_der(signature);
      signature = signature_tmp;
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
        QCBOREncode_AddBytes(encoder, cbor::from_bytes(certs[0]));
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
