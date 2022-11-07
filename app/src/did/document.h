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
  struct Jwk
  {
    std::string kty;
    std::optional<std::string> alg;
    std::optional<std::string> n;
    std::optional<std::string> e;
    std::optional<std::string> crv;
    std::optional<std::string> x;
    std::optional<std::string> y;

    bool operator==(const Jwk&) const = default;
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Jwk);
  DECLARE_JSON_REQUIRED_FIELDS(Jwk, kty);
  DECLARE_JSON_OPTIONAL_FIELDS(Jwk, alg, n, e, crv, x, y);

  struct DidVerificationMethod
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

  struct DidDocument
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

  struct DIDAssertionMethodError : public std::runtime_error
  {
    DIDAssertionMethodError(const std::string& msg) : std::runtime_error(msg) {}
  };
  struct DIDAssertionMethodNotFoundError : public DIDAssertionMethodError
  {
    DIDAssertionMethodNotFoundError(const std::string& msg) :
      DIDAssertionMethodError(msg)
    {}
  };

  struct DIDAssertionMethodUnsupportedError : public DIDAssertionMethodError
  {
    DIDAssertionMethodUnsupportedError(const std::string& msg) :
      DIDAssertionMethodError(msg)
    {}
  };

  static DidVerificationMethod find_assertion_method_in_did_document(
    const DidDocument& did_doc,
    const std::optional<std::string>& assertion_method_id)
  {
    std::unordered_map<std::string, const DidVerificationMethod*> id_to_method;
    if (did_doc.verification_method.has_value())
    {
      for (auto& m : did_doc.verification_method.value())
      {
        id_to_method[m.id] = &m;
      }
    }

    const DidVerificationMethod* method = nullptr;
    std::optional<std::string> method_id;

    if (assertion_method_id.has_value())
    {
      for (auto& m : did_doc.assertion_method)
      {
        if (std::holds_alternative<std::string>(m))
        {
          if (std::get<std::string>(m) == *assertion_method_id)
          {
            method_id = *assertion_method_id;
            break;
          }
        }
        else
        {
          if (std::get<DidVerificationMethod>(m).id == *assertion_method_id)
          {
            method = &std::get<DidVerificationMethod>(m);
            break;
          }
        }
      }
    }
    else
    {
      if (did_doc.assertion_method.size() != 1)
      {
        throw DIDAssertionMethodNotFoundError(
          "DID document must have exactly one assertion method if no assertion "
          "method id is provided");
      }
      auto& m = did_doc.assertion_method[0];
      if (std::holds_alternative<std::string>(m))
      {
        method_id = std::get<std::string>(m);
      }
      else
      {
        method = &std::get<DidVerificationMethod>(m);
      }
    }

    if (method_id.has_value())
    {
      if (!contains(id_to_method, method_id.value()))
      {
        throw DIDAssertionMethodNotFoundError(
          "DID document assertion method references unknown verification "
          "method");
      }
      method = id_to_method[*method_id];
    }

    if (!method)
    {
      throw DIDAssertionMethodNotFoundError(
        "DID document assertion method not found");
    }
    return *method;
  }

  static Jwk find_assertion_method_jwk_in_did_document(
    const DidDocument& did_doc,
    const std::optional<std::string>& assertion_method_id)
  {
    auto method =
      find_assertion_method_in_did_document(did_doc, assertion_method_id);
    if (!method.public_key_jwk.has_value())
    {
      throw DIDAssertionMethodUnsupportedError(
        "DID document assertion method is missing publicKeyJwk");
    }
    return method.public_key_jwk.value();
  }
}
