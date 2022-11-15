// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once
#include "did/document.h"
#include "signature_algorithms.h"

#include <ccf/ds/json.h>
#include <ccf/kv/map.h>
#include <ccf/kv/value.h>
#include <nlohmann/json.hpp>
#include <optional>
#include <vector>

namespace scitt
{
  using Timestamp = int64_t; // seconds since epoch
  using Issuer = std::string; // DID of the issuer
  using Pem = std::string; // PEM-encoded certificate

  struct DidWebResolutionMetadata
  {
    std::vector<Pem> tls_certs;
  };
  DECLARE_JSON_TYPE(DidWebResolutionMetadata);
  DECLARE_JSON_REQUIRED_FIELDS(DidWebResolutionMetadata, tls_certs);

  struct DidResolutionMetadata
  {
    Timestamp updated;
    std::optional<DidWebResolutionMetadata> web;
  };
  DECLARE_JSON_TYPE(DidResolutionMetadata);
  DECLARE_JSON_REQUIRED_FIELDS(DidResolutionMetadata, updated, web);

  struct IssuerInfo
  {
    std::optional<Timestamp> resolution_requested;
    std::optional<std::string> resolution_nonce;
    std::optional<did::DidDocument> did_document;
    std::optional<DidResolutionMetadata> did_resolution_metadata;
  };
  DECLARE_JSON_TYPE(IssuerInfo);
  DECLARE_JSON_REQUIRED_FIELDS(
    IssuerInfo,
    resolution_requested,
    resolution_nonce,
    did_document,
    did_resolution_metadata);

  struct EntryInfo
  {
    /**
     * The COSE protected header of the countersigner (this service).
     */
    std::vector<uint8_t> sign_protected;
  };
  DECLARE_JSON_TYPE(EntryInfo);
  DECLARE_JSON_REQUIRED_FIELDS(EntryInfo, sign_protected);

  /**
   * SCITT Service configuration. This is stored in the KV and updated
   * through a custom governance action.
   */
  struct Configuration
  {
    /**
     * The acceptance policy for claims submitted to the service.
     */
    struct Policy
    {
      /**
       * List of accepted COSE signature algorithms when verifying signatures.
       * The names are case sensitive.
       *
       * Rather than the COSE integer algorithm IDs, we use the equivalent
       * human-friendly JOSE names.
       */
      std::optional<std::vector<std::string>> accepted_algorithms;
      std::optional<std::vector<std::string>> accepted_did_issuers;

      std::vector<std::string> get_accepted_algorithms() const
      {
        if (accepted_algorithms.has_value())
        {
          return accepted_algorithms.value();
        }
        else
        {
          return {
            std::string(JOSE_ALGORITHM_ES256),
            std::string(JOSE_ALGORITHM_ES384),
            std::string(JOSE_ALGORITHM_ES512),
            std::string(JOSE_ALGORITHM_PS256),
            std::string(JOSE_ALGORITHM_PS384),
            std::string(JOSE_ALGORITHM_PS512),
            std::string(JOSE_ALGORITHM_EDDSA)};
        }
      }
      
      bool is_accepted_issuers(std::string issuer) const
      {
        if (!accepted_did_issuers.has_value())
        {
          return true;
        }
        else if (contains(accepted_did_issuers.value(), issuer))
        {
          return true;
        }
        else
        {
          return false;
        }
      }

      bool operator==(const Policy& other) const = default;
    };

    struct Authentication
    {
      struct JWT
      {
        nlohmann::json required_claims;
        bool operator==(const JWT& other) const = default;
      };

      JWT jwt;
      bool allow_unauthenticated = false;

      bool operator==(const Authentication& other) const = default;
    };

    Policy policy = {};
    Authentication authentication = {};
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Configuration::Policy);
  DECLARE_JSON_REQUIRED_FIELDS(Configuration::Policy);
  DECLARE_JSON_OPTIONAL_FIELDS(Configuration::Policy, accepted_algorithms, accepted_did_issuers);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Configuration::Authentication::JWT);
  DECLARE_JSON_REQUIRED_FIELDS(Configuration::Authentication::JWT);
  DECLARE_JSON_OPTIONAL_FIELDS(
    Configuration::Authentication::JWT, required_claims);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Configuration::Authentication);
  DECLARE_JSON_REQUIRED_FIELDS(Configuration::Authentication);
  DECLARE_JSON_OPTIONAL_FIELDS(
    Configuration::Authentication, jwt, allow_unauthenticated);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Configuration);
  DECLARE_JSON_REQUIRED_FIELDS(Configuration);
  DECLARE_JSON_OPTIONAL_FIELDS(Configuration, policy, authentication);

  // Tables

  static constexpr auto ENTRY_TABLE = "public:scitt.entry";
  using EntryTable = kv::RawCopySerialisedValue<std::vector<uint8_t>>;

  static constexpr auto ENTRY_INFO_TABLE = "public:scitt.entry_info";
  using EntryInfoTable = kv::Value<EntryInfo>;

  static constexpr auto ISSUERS_TABLE = "public:scitt.issuers";
  using IssuersTable = kv::Map<Issuer, IssuerInfo>;

  // The `ccf.gov` prefix is necessary to make the table writable
  // through governance.
  static constexpr auto CONFIGURATION_TABLE =
    "public:ccf.gov.scitt.configuration";
  using ConfigurationTable = kv::JsonSerialisedValue<Configuration>;

} // namespace scitt
