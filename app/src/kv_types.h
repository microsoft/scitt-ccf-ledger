// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once
#include "did/document.h"
#include "odata_error.h"
#include "signature_algorithms.h"

#include <ccf/crypto/hash_provider.h>
#include <ccf/ds/json.h>
#include <ccf/kv/map.h>
#include <ccf/kv/value.h>
#include <ccf/tx_id.h>
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

    bool operator==(const DidWebResolutionMetadata&) const = default;
  };
  DECLARE_JSON_TYPE(DidWebResolutionMetadata);
  DECLARE_JSON_REQUIRED_FIELDS(DidWebResolutionMetadata, tls_certs);

  struct DidResolutionMetadata
  {
    Timestamp updated;
    std::optional<DidWebResolutionMetadata> web;

    bool operator==(const DidResolutionMetadata&) const = default;
  };
  DECLARE_JSON_TYPE(DidResolutionMetadata);
  DECLARE_JSON_REQUIRED_FIELDS(DidResolutionMetadata, updated, web);

  struct IssuerInfo
  {
    std::optional<did::DidDocument> did_document;
    std::optional<DidResolutionMetadata> did_resolution_metadata;
    std::optional<ODataError> error;
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(IssuerInfo);
  DECLARE_JSON_REQUIRED_FIELDS(IssuerInfo);
  DECLARE_JSON_OPTIONAL_FIELDS(
    IssuerInfo, did_document, did_resolution_metadata, error);

  struct EntryInfo
  {
    /**
     * The COSE protected header of the countersigner (this service).
     */
    std::vector<uint8_t> sign_protected;
  };
  DECLARE_JSON_TYPE(EntryInfo);
  DECLARE_JSON_REQUIRED_FIELDS(EntryInfo, sign_protected);

  enum class OperationStatus
  {
    Running,
    Failed,
    Succeeded,
  };
  DECLARE_JSON_ENUM(
    OperationStatus,
    {{OperationStatus::Running, "running"},
     {OperationStatus::Failed, "failed"},
     {OperationStatus::Succeeded, "succeeded"}});

  struct OperationLog
  {
    OperationStatus status;

    // This is populated for entries that update an existing operation. When
    // creating a new one, the transaction ID of the entry is used as the new
    // operation's ID.
    std::optional<ccf::TxID> operation_id;

    std::optional<time_t> created_at;
    std::optional<crypto::Sha256Hash> context_digest;
    std::optional<nlohmann::json> error;
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(OperationLog);
  DECLARE_JSON_REQUIRED_FIELDS(OperationLog, status);
  DECLARE_JSON_OPTIONAL_FIELDS(
    OperationLog, operation_id, created_at, context_digest, error);

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
       * Rather than the COSE integer algorithm IDs, we use the equivalent
       * human-friendly JOSE names.
       */
      std::optional<std::vector<std::string>> accepted_algorithms;

      /**
       * List of accepted DID issuer when verifying signatures.
       * The names are case sensitive.
       */
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

      bool is_accepted_issuer(std::string_view issuer) const
      {
        return !accepted_did_issuers.has_value() ||
          contains(accepted_did_issuers.value(), issuer);
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

    // The long-term stable identifier of this service, as a DID.
    // If set, it will be used to populate the issuer field of receipts
    std::optional<std::string> service_identifier;
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Configuration::Policy);
  DECLARE_JSON_REQUIRED_FIELDS(Configuration::Policy);
  DECLARE_JSON_OPTIONAL_FIELDS(
    Configuration::Policy, accepted_algorithms, accepted_did_issuers);

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
  DECLARE_JSON_OPTIONAL_FIELDS(
    Configuration, policy, authentication, service_identifier);

  // Tables

  static constexpr auto ENTRY_TABLE = "public:scitt.entry";
  using EntryTable = kv::RawCopySerialisedValue<std::vector<uint8_t>>;

  static constexpr auto ENTRY_INFO_TABLE = "public:scitt.entry_info";
  using EntryInfoTable = kv::Value<EntryInfo>;

  static constexpr auto ISSUERS_TABLE = "public:scitt.issuers";
  using IssuersTable = kv::Map<Issuer, IssuerInfo>;

  static constexpr auto OPERATIONS_TABLE = "public:scitt.operations";
  using OperationsTable = kv::Value<OperationLog>;

  // The `ccf.gov` prefix is necessary to make the table writable
  // through governance.
  static constexpr auto CONFIGURATION_TABLE =
    "public:ccf.gov.scitt.configuration";
  using ConfigurationTable = kv::JsonSerialisedValue<Configuration>;

} // namespace scitt
