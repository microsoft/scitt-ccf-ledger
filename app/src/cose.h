// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "cbor.h"
#include "public_key.h"
#include "tracing.h"
#include "util.h"

#include <ccf/crypto/base64.h>
#include <ccf/crypto/cose_key.h>
#include <ccf/crypto/cose_verifier.h>
#include <ccf/crypto/hash_provider.h>
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
#include <stdexcept>
#include <string>
#include <string_view>
#include <tav/cbor.hpp>
#include <tuple>
#include <variant>
#include <vector>

namespace scitt::cose
{
  static constexpr int64_t COSE_HEADER_PARAM_ALG = 1;
  static constexpr int64_t COSE_HEADER_PARAM_CRIT = 2;
  static constexpr int64_t COSE_HEADER_PARAM_CTY = 3;
  static constexpr int64_t COSE_HEADER_PARAM_KID = 4;
  static constexpr int64_t COSE_HEADER_PARAM_X5CHAIN = 33;
  static constexpr int64_t COSE_HEADER_PARAM_CWT_CLAIMS = 15;

  static constexpr const char* COSE_HEADER_PARAM_TSS = "attestedsvc";
  static constexpr const char* COSE_HEADER_PARAM_TSS_SVC_ID = "svc_id";
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
  // https://www.ietf.org/archive/id/draft-ietf-cose-merkle-tree-proofs-14.html#name-new-cose-header-parameters
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

  // https://www.rfc-editor.org/rfc/rfc9052#section-4.2
  static constexpr uint64_t COSE_SIGN1_TAG = 18;
  static constexpr size_t COSE_SIGN1_SIZE = 4;
  static constexpr size_t CBOR_MAX_DEPTH = 15;

  // https://www.rfc-editor.org/rfc/rfc8949#section-3.4.2
  static constexpr uint64_t CBOR_TAG_EPOCH_DATE = 1;

  struct COSEDecodeError : public std::runtime_error
  {
    COSEDecodeError(const std::string& msg) : std::runtime_error(msg) {}
  };

  /**
  "svc_id": tstr,            ; service identifier
  "attestation": bstr,       ; raw hardware attestation report
  "attestation_type": tstr,  ; "SEV-SNP:ContainerPlat-AMD-UVM"
  "cose_key": { ... },       ; canonical COSE_Key map (embedded directly)
  "snp_endorsements": bstr,  ; concatenated PEM-encoded AMD cert chain
  "uvm_endorsements": bstr,  ; opaque endorsement from Azure or UVM authority
  "ver": int                 ; version number of the format (e.g., 0)
   */
  struct TSSMap
  {
    std::optional<std::string> svc_id;
    std::optional<std::vector<uint8_t>> attestation;
    std::optional<std::string> attestation_type;
    std::optional<ccf::crypto::COSEKey> cose_key;
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

  using CritValuesContent = std::vector<std::variant<int64_t, std::string>>;
  using CritValues = std::optional<CritValuesContent>;

  struct ProtectedHeader // NOLINT(bugprone-exception-escape)
  {
    // The headers used in this codebase
    std::optional<int64_t> alg;
    CritValues crit;
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

  namespace detail
  {
    using tav::cbor::Kind;
    using tav::cbor::Value;

    /**
     * Call f(key, value) for each entry of a map, in encoding order. Entries
     * with labels that are not recognised are left to f to ignore.
     */
    template <typename F>
    static void for_each_entry(const Value& map, std::string_view name, F&& f)
    {
      if (map.kind() != Kind::MAP)
      {
        throw COSEDecodeError(fmt::format("{} must be a map", name));
      }
      const auto size = map.size();
      for (size_t i = 0; i < size; ++i)
      {
        f(map.map_key_at(i), map.map_value_at(i));
      }
    }

    static int64_t as_int(const Value& value, std::string_view name)
    {
      if (value.kind() != Kind::SIGNED)
      {
        throw COSEDecodeError(fmt::format("{} must be an integer", name));
      }
      return value.as_signed();
    }

    static std::string as_text(const Value& value, std::string_view name)
    {
      if (value.kind() != Kind::STRING)
      {
        throw COSEDecodeError(fmt::format("{} must be a text string", name));
      }
      return std::string(value.as_string());
    }

    static std::vector<uint8_t> as_bytes(
      const Value& value, std::string_view name)
    {
      if (value.kind() != Kind::BYTES)
      {
        throw COSEDecodeError(fmt::format("{} must be a byte string", name));
      }
      return cbor::as_vector(value.as_bytes());
    }
  }

  static std::vector<std::vector<uint8_t>> decode_x5chain(
    const tav::cbor::Value& x5chain)
  {
    using tav::cbor::Kind;

    if (x5chain.kind() == Kind::BYTES)
    {
      return {cbor::as_vector(x5chain.as_bytes())};
    }
    if (x5chain.kind() != Kind::ARRAY)
    {
      throw COSEDecodeError(
        "Value type of x5chain in COSE header is not array or byte "
        "string.");
    }

    const auto size = x5chain.size();
    std::vector<std::vector<uint8_t>> parsed;
    parsed.reserve(size);
    for (size_t i = 0; i < size; ++i)
    {
      const auto item = x5chain.array_at(i);
      if (item.kind() != Kind::BYTES)
      {
        throw COSEDecodeError(
          "Next item in x5chain was not of type byte string.");
      }
      parsed.push_back(cbor::as_vector(item.as_bytes()));
    }
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
      SCITT_DEBUG("Single cert found in x5chain array in COSE header.");
    }
    return parsed;
  }

  static CritValuesContent decode_crit(const tav::cbor::Value& crit)
  {
    using tav::cbor::Kind;

    if (crit.kind() != Kind::ARRAY)
    {
      throw COSEDecodeError(
        fmt::format("crit({}) must be an array", COSE_HEADER_PARAM_CRIT));
    }

    const auto size = crit.size();
    CritValuesContent parsed;
    parsed.reserve(size);
    for (size_t i = 0; i < size; ++i)
    {
      const auto item = crit.array_at(i);
      if (item.kind() == Kind::STRING)
      {
        parsed.emplace_back(std::string(item.as_string()));
      }
      else if (item.kind() == Kind::SIGNED)
      {
        parsed.emplace_back(item.as_signed());
      }
      else
      {
        throw COSEDecodeError(
          "Next item in crit was not of type text string or int64.");
      }
    }
    if (parsed.empty())
    {
      throw COSEDecodeError(
        "Cannot have crit array of length 0 in COSE protected header.");
    }
    return parsed;
  }

  // The correct expected type for iat(6) is an _untagged_ date epoch,
  // i.e. an integer representing seconds since epoch.
  // https://www.rfc-editor.org/rfc/rfc8392.html#section-3.1.6
  // The "iat" (issued at) claim [...] except that the value is a
  // NumericDate, as defined in Section 2 of this specification.
  // https://www.rfc-editor.org/rfc/rfc8392.html#section-2
  // except that it is represented as a CBOR numeric date
  // (from Section 2.4.1 of [RFC7049])
  // https://www.rfc-editor.org/rfc/rfc7049#section-2.4.1
  // The encoding is modified so that the leading tag 1
  // (epoch-based date/time) MUST be omitted.
  // However, some implementations tag iat(6) as an epoch-based date.
  static int64_t decode_iat(const tav::cbor::Value& iat)
  {
    using tav::cbor::Kind;

    if (iat.kind() == Kind::SIGNED)
    {
      return iat.as_signed();
    }
    if (iat.kind() == Kind::TAGGED && iat.as_tag() == CBOR_TAG_EPOCH_DATE)
    {
      const auto date = iat.tag_at(CBOR_TAG_EPOCH_DATE);
      if (date.kind() == Kind::SIGNED)
      {
        return date.as_signed();
      }
    }
    throw COSEDecodeError(fmt::format(
      "CWT claim iat({}) must be an integer or a tag {}-wrapped integer",
      COSE_CWT_CLAIM_IAT,
      CBOR_TAG_EPOCH_DATE));
  }

  static CWTClaims decode_cwt_claims(const tav::cbor::Value& claims)
  {
    using tav::cbor::Kind;
    using tav::cbor::Value;

    CWTClaims parsed;
    detail::for_each_entry(
      claims,
      fmt::format("CWT claims({})", COSE_HEADER_PARAM_CWT_CLAIMS),
      [&](const Value& label, const Value& value) {
        if (label.kind() == Kind::SIGNED)
        {
          switch (label.as_signed())
          {
            case COSE_CWT_CLAIM_ISS:
              parsed.iss = detail::as_text(
                value, fmt::format("CWT claim iss({})", COSE_CWT_CLAIM_ISS));
              break;
            case COSE_CWT_CLAIM_SUB:
              parsed.sub = detail::as_text(
                value, fmt::format("CWT claim sub({})", COSE_CWT_CLAIM_SUB));
              break;
            case COSE_CWT_CLAIM_IAT:
              parsed.iat = decode_iat(value);
              break;
            default:
              break;
          }
        }
        else if (
          label.kind() == Kind::STRING && label.as_string() == SVN_HEADER_PARAM)
        {
          parsed.svn = detail::as_int(
            value, fmt::format("CWT claim {}", SVN_HEADER_PARAM));
        }
      });
    return parsed;
  }

  static ccf::crypto::COSEKey decode_cose_key(
    const tav::cbor::Value& cose_key, std::string_view name)
  {
    const auto key = [&]() {
      try
      {
        return ccf::crypto::COSEKey::from_cbor(cose_key.nondet_serialize());
      }
      catch (const std::invalid_argument& e)
      {
        throw COSEDecodeError(fmt::format("{}: {}", name, e.what()));
      }
    }();

    // Only EC2 and RSA keys are supported, whatever CCF accepts
    const auto kty = key.kty();
    if (
      kty != ccf::crypto::COSEKeyType::EC2 &&
      kty != ccf::crypto::COSEKeyType::RSA)
    {
      throw COSEDecodeError(fmt::format(
        "{}: Invalid COSE_Key: unsupported kty {}",
        name,
        static_cast<int>(kty)));
    }
    return key;
  }

  static TSSMap decode_tss_map(const tav::cbor::Value& tss)
  {
    using tav::cbor::Kind;
    using tav::cbor::Value;

    TSSMap parsed;
    detail::for_each_entry(
      tss, COSE_HEADER_PARAM_TSS, [&](const Value& label, const Value& value) {
        if (label.kind() != Kind::STRING)
        {
          return;
        }
        const auto name = label.as_string();
        const auto field = fmt::format("{}.{}", COSE_HEADER_PARAM_TSS, name);
        if (name == COSE_HEADER_PARAM_TSS_SVC_ID)
        {
          parsed.svc_id = detail::as_text(value, field);
        }
        else if (name == COSE_HEADER_PARAM_TSS_ATTESTATION)
        {
          parsed.attestation = detail::as_bytes(value, field);
        }
        else if (name == COSE_HEADER_PARAM_TSS_ATTESTATION_TYPE)
        {
          parsed.attestation_type = detail::as_text(value, field);
        }
        else if (name == COSE_HEADER_PARAM_TSS_SNP_ENDORSEMENTS)
        {
          parsed.snp_endorsements = detail::as_bytes(value, field);
        }
        else if (name == COSE_HEADER_PARAM_TSS_UVM_ENDORSEMENTS)
        {
          parsed.uvm_endorsements = detail::as_bytes(value, field);
        }
        else if (name == COSE_HEADER_PARAM_TSS_VER)
        {
          parsed.ver = detail::as_int(value, field);
        }
        else if (name == COSE_HEADER_PARAM_TSS_COSE_KEY)
        {
          parsed.cose_key = decode_cose_key(value, field);
        }
      });
    return parsed;
  }

  /**
   * Decode a serialized protected header map. A zero-length protected header
   * stands for an empty map.
   */
  static ProtectedHeader decode_protected_header(
    std::span<const uint8_t> encoded)
  {
    using tav::cbor::Kind;
    using tav::cbor::Value;

    ProtectedHeader parsed;
    if (encoded.empty())
    {
      return parsed;
    }

    try
    {
      const auto header = tav::cbor::nondet_parse(encoded, CBOR_MAX_DEPTH);
      std::set<std::variant<int64_t, std::string>> labels;
      detail::for_each_entry(
        header,
        "protected header",
        [&](const Value& label, const Value& value) {
          if (label.kind() == Kind::SIGNED)
          {
            labels.insert(label.as_signed());
            switch (label.as_signed())
            {
              case COSE_HEADER_PARAM_ALG:
                parsed.alg = detail::as_int(
                  value, fmt::format("alg({})", COSE_HEADER_PARAM_ALG));
                break;
              case COSE_HEADER_PARAM_CRIT:
                parsed.crit = decode_crit(value);
                break;
              case COSE_HEADER_PARAM_CTY:
                if (value.kind() == Kind::STRING)
                {
                  parsed.cty = std::string(value.as_string());
                }
                else if (value.kind() == Kind::SIGNED)
                {
                  parsed.cty = value.as_signed();
                }
                else
                {
                  throw COSEDecodeError(
                    "Content-type must be of type text string or int64");
                }
                break;
              case COSE_HEADER_PARAM_KID:
              {
                const auto kid = detail::as_bytes(
                  value, fmt::format("kid({})", COSE_HEADER_PARAM_KID));
                parsed.kid = std::string(kid.begin(), kid.end());
                break;
              }
              case COSE_HEADER_PARAM_CWT_CLAIMS:
                parsed.cwt_claims = decode_cwt_claims(value);
                break;
              case COSE_HEADER_PARAM_X5CHAIN:
                parsed.x5chain = decode_x5chain(value);
                break;
              case COSE_HEADER_PARAM_ISSUER:
                parsed.issuer = detail::as_text(
                  value, fmt::format("issuer({})", COSE_HEADER_PARAM_ISSUER));
                break;
              case COSE_HEADER_PARAM_FEED:
                parsed.feed = detail::as_text(
                  value, fmt::format("feed({})", COSE_HEADER_PARAM_FEED));
                break;
              default:
                break;
            }
          }
          else if (label.kind() == Kind::STRING)
          {
            const auto name = label.as_string();
            labels.insert(std::string(name));
            if (name == SVN_HEADER_PARAM)
            {
              parsed.svn = detail::as_int(value, SVN_HEADER_PARAM);
            }
            else if (name == COSE_HEADER_PARAM_TSS)
            {
              parsed.tss_map = decode_tss_map(value);
            }
          }
        });

      // https://www.rfc-editor.org/rfc/rfc9052.html#section-3.1
      // If the "crit" value list includes a label for which the header
      // parameter is not in the protected-header-parameters bucket, this is
      // a fatal error in processing the message.
      if (parsed.crit.has_value())
      {
        for (const auto& critical : *parsed.crit)
        {
          if (!labels.contains(critical))
          {
            const auto repr = std::holds_alternative<int64_t>(critical) ?
              std::to_string(std::get<int64_t>(critical)) :
              fmt::format("\"{}\"", std::get<std::string>(critical));
            throw COSEDecodeError(fmt::format(
              "crit({}) lists label {} which is not present in the protected "
              "header",
              COSE_HEADER_PARAM_CRIT,
              repr));
          }
        }
      }
    }
    catch (const COSEDecodeError& e)
    {
      throw COSEDecodeError(
        fmt::format("Failed to decode protected header: {}", e.what()));
    }
    catch (const tav::cbor::CborError& e)
    {
      throw COSEDecodeError(
        fmt::format("Failed to decode protected header: {}", e.what()));
    }

    return parsed;
  }

  static UnprotectedHeader decode_unprotected_header(
    const tav::cbor::Value& header)
  {
    using tav::cbor::Kind;
    using tav::cbor::Value;

    UnprotectedHeader parsed;
    try
    {
      detail::for_each_entry(
        header,
        "unprotected header",
        [&](const Value& label, const Value& value) {
          if (
            label.kind() == Kind::SIGNED &&
            label.as_signed() == COSE_HEADER_PARAM_X5CHAIN)
          {
            parsed.x5chain = decode_x5chain(value);
          }
        });
    }
    catch (const COSEDecodeError& e)
    {
      throw COSEDecodeError(
        fmt::format("Failed to decode unprotected header: {}", e.what()));
    }
    catch (const tav::cbor::CborError& e)
    {
      throw COSEDecodeError(
        fmt::format("Failed to decode unprotected header: {}", e.what()));
    }
    return parsed;
  }

  static std::tuple<ProtectedHeader, UnprotectedHeader> decode_headers(
    const std::vector<uint8_t>& cose_sign1)
  {
    using tav::cbor::Kind;

    try
    {
      const auto document = tav::cbor::nondet_parse(cose_sign1, CBOR_MAX_DEPTH);
      if (
        document.kind() != Kind::TAGGED || document.as_tag() != COSE_SIGN1_TAG)
      {
        throw COSEDecodeError("COSE_Sign1 is not tagged");
      }

      const auto envelope = document.tag_at(COSE_SIGN1_TAG);
      if (envelope.kind() != Kind::ARRAY || envelope.size() != COSE_SIGN1_SIZE)
      {
        throw COSEDecodeError("Failed to parse COSE_Sign1 outer array");
      }

      const auto phdr = envelope.array_at(0);
      if (phdr.kind() != Kind::BYTES)
      {
        throw COSEDecodeError(
          "Failed to decode protected header: not a byte string");
      }
      auto protected_header = decode_protected_header(phdr.as_bytes());
      auto unprotected_header = decode_unprotected_header(envelope.array_at(1));

      // A COSE_Sign1 payload must be a bstr; a nil value indicates a
      // detached payload which is not supported.
      const auto payload = envelope.array_at(2);
      const bool detached = payload.kind() == Kind::SIMPLE &&
        payload.as_simple() == tav::cbor::SimpleValue::Null;
      if (
        detached ||
        (payload.kind() == Kind::BYTES && payload.as_bytes().empty()))
      {
        throw COSEDecodeError("Detached or empty payloads are not supported");
      }
      if (payload.kind() != Kind::BYTES)
      {
        throw COSEDecodeError("COSE_Sign1 payload is not a byte string");
      }

      if (envelope.array_at(3).kind() != Kind::BYTES)
      {
        throw COSEDecodeError("COSE_Sign1 signature is not a byte string");
      }

      return {std::move(protected_header), std::move(unprotected_header)};
    }
    catch (const tav::cbor::CborError& e)
    {
      throw COSEDecodeError(
        fmt::format("Failed to decode COSE_Sign1: {}", e.what()));
    }
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
   *
   * Critical header checking is not performed here; it is handled
   * at the application level per issuer type.
   */
  static std::span<uint8_t> verify(
    const std::vector<uint8_t>& cose_sign1, const PublicKey& key)
  {
    EVP_PKEY* evp_key = key.get_evp_pkey();
    int der_len = i2d_PUBKEY(evp_key, nullptr);
    if (der_len <= 0)
    {
      throw COSESignatureValidationError(
        "Failed to serialize public key to DER");
    }
    std::vector<uint8_t> der_key(der_len);
    uint8_t* der_ptr = der_key.data();
    i2d_PUBKEY(evp_key, &der_ptr);

    auto verifier = ccf::crypto::make_cose_verifier_from_key(
      std::span<const uint8_t>(der_key.data(), der_key.size()));

    std::span<uint8_t> payload;
    if (!verifier->verify(
          std::span<const uint8_t>(cose_sign1.data(), cose_sign1.size()),
          payload))
    {
      throw COSESignatureValidationError("Signature verification failed");
    }

    return payload;
  }

  /**
   * Verify the signature of a COSE Sign1 message using the given COSE key,
   * and return its payload.
   */
  static std::span<uint8_t> verify(
    const std::vector<uint8_t>& cose_sign1, const ccf::crypto::COSEKey& key)
  {
    auto verifier = ccf::crypto::make_cose_verifier_from_key(key);

    std::span<uint8_t> payload;
    if (!verifier->verify(cose_sign1, payload))
    {
      throw COSESignatureValidationError("Signature verification failed");
    }
    return payload;
  }
}
