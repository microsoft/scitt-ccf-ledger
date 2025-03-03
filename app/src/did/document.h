// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once
#include "util.h"

#include <ccf/ds/json.h>
#include <nlohmann/json.hpp>
#include <optional>
#include <variant>
#include <vector>

namespace scitt::did
{
  struct Jwk // NOLINT(bugprone-exception-escape)
  {
    std::string kty;
    std::optional<std::string> alg;
    std::optional<std::string> n;
    std::optional<std::string> e;
    std::optional<std::string> crv;
    std::optional<std::string> x;
    std::optional<std::string> y;
    std::optional<std::vector<std::string>> x5c;

    bool operator==(const Jwk&) const = default;
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Jwk);
  DECLARE_JSON_REQUIRED_FIELDS(Jwk, kty);
  DECLARE_JSON_OPTIONAL_FIELDS(Jwk, alg, n, e, crv, x, y, x5c);

  struct DidVerificationMethod // NOLINT(bugprone-exception-escape)
  {
    std::string id;
    std::string type;
    std::string controller;
    std::optional<Jwk> public_key_jwk;

    bool operator==(const DidVerificationMethod&) const = default;
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(DidVerificationMethod);
  DECLARE_JSON_REQUIRED_FIELDS(DidVerificationMethod, id, type, controller);
  DECLARE_JSON_OPTIONAL_FIELDS_WITH_RENAMES(
    DidVerificationMethod, public_key_jwk, "publicKeyJwk");

  struct DidDocument // NOLINT(bugprone-exception-escape)
  {
    std::string id;
    std::optional<std::vector<DidVerificationMethod>> verification_method;
    std::vector<std::variant<std::string, DidVerificationMethod>>
      assertion_method;

    bool operator==(const DidDocument&) const = default;
  };

  // nlohmann json has no native support for variants.
  static void to_json(
    nlohmann::json& j,
    const std::variant<std::string, DidVerificationMethod>& v)
  {
    if (std::holds_alternative<std::string>(v))
    {
      j = std::get<std::string>(v);
    }
    else
    {
      j = std::get<DidVerificationMethod>(v);
    }
  }

  static void from_json(
    const nlohmann::json& j,
    std::variant<std::string, DidVerificationMethod>& v)
  {
    if (j.is_string())
    {
      v = j.get<std::string>();
    }
    else
    {
      v = j.get<DidVerificationMethod>();
    }
  }

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(DidDocument);
  DECLARE_JSON_REQUIRED_FIELDS_WITH_RENAMES(
    DidDocument, id, "id", assertion_method, "assertionMethod");
  DECLARE_JSON_OPTIONAL_FIELDS_WITH_RENAMES(
    DidDocument, verification_method, "verificationMethod");
}

// Alternative DID document spec imported from CCF/src/node/did.h
// Unlike scitt::did::DidDocument, this expects a single string for
// assertion_method and leaves the JWK parsing to specific sub-type to the
// caller based on the kty, rather than expose a single merged type where every
// field is optional. This is needed now for compatibility with didx509cpp, but
// the types should be merged eventually if they are still both needed.
namespace scitt::did::alt
{
  // From https://www.w3.org/TR/did-core.
  // Note that the types defined in this file do not exhaustively cover
  // all fields and types from the spec.
  struct DIDDocumentVerificationMethod
  {
    std::string id;
    std::string type;
    std::string controller;
    std::optional<nlohmann::json> public_key_jwk = std::nullopt;

    bool operator==(const DIDDocumentVerificationMethod&) const = default;
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(DIDDocumentVerificationMethod);
  DECLARE_JSON_REQUIRED_FIELDS(
    DIDDocumentVerificationMethod, id, type, controller);
  DECLARE_JSON_OPTIONAL_FIELDS_WITH_RENAMES(
    DIDDocumentVerificationMethod, public_key_jwk, "publicKeyJwk");

  struct DIDDocument
  {
    std::string id;
    std::string context;
    std::string type;
    std::vector<DIDDocumentVerificationMethod> verification_method = {};
    nlohmann::json assertion_method = {};

    bool operator==(const DIDDocument&) const = default;
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(DIDDocument);
  DECLARE_JSON_REQUIRED_FIELDS(DIDDocument, id);
  DECLARE_JSON_OPTIONAL_FIELDS_WITH_RENAMES(
    DIDDocument,
    context,
    "@context",
    type,
    "type",
    verification_method,
    "verificationMethod",
    assertion_method,
    "assertionMethod");
}