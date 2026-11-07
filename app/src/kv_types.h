// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once
#include "did/document.h"
#include "policy_engine.h"
#include "signature_algorithms.h"

#include <ccf/ds/json.h>
#include <ccf/kv/map.h>
#include <ccf/kv/value.h>
#include <nlohmann/json.hpp>
#include <optional>
#include <vector>

namespace scitt
{
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
       * Script defining executable policy to be applied to each incoming entry.
       */
      std::optional<PolicyScript> policy_script;

      /**
       * Rego policy to be applied to each incoming entry.
       */
      std::optional<PolicyRego> policy_rego;
      /**
       * Optional limit on the number of Rego statements that can be executed
       * during policy evaluation. If not set, a default limit is applied
       * (10,000).
       */
      std::optional<size_t> policy_rego_statement_limit;

      size_t get_policy_rego_statement_limit() const
      {
        return policy_rego_statement_limit.value_or(10'000);
      }

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

      bool operator==(const Policy& other) const = default;
    };

    struct Authentication
    {
      nlohmann::json jwt = nlohmann::json::object();
      bool allow_unauthenticated = false;

      // When set, controls whether selected SCITT retrieval endpoints allow
      // unauthenticated access. When unset, inherits allow_unauthenticated to
      // preserve existing behavior.
      std::optional<bool> allow_unauthenticated_reads;

      bool get_allow_unauthenticated_reads() const
      {
        return allow_unauthenticated_reads.value_or(allow_unauthenticated);
      }

      bool operator==(const Authentication& other) const = default;
    };

    Policy policy = {};
    Authentication authentication = {};

    /**
     * Optional maximum size in bytes for signed statements.
     * If set, overrides the default MAX_ENTRY_SIZE_BYTES_DEFAULT constant.
     * HTTP-unauthenticated registrations are additionally capped by
     * MAX_UNAUTHENTICATED_ENTRY_SIZE_BYTES.
     */
    std::optional<size_t> max_signed_statement_bytes;

    // deprecated
    std::optional<std::string> service_issuer;
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Configuration::Policy);
  DECLARE_JSON_REQUIRED_FIELDS(Configuration::Policy);
  DECLARE_JSON_OPTIONAL_FIELDS_WITH_RENAMES(
    Configuration::Policy,
    accepted_algorithms,
    "acceptedAlgorithms",
    policy_script,
    "policyScript",
    policy_rego,
    "policyRego",
    policy_rego_statement_limit,
    "policyRegoStatementLimit");

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Configuration::Authentication);
  DECLARE_JSON_REQUIRED_FIELDS(Configuration::Authentication);
  DECLARE_JSON_OPTIONAL_FIELDS_WITH_RENAMES(
    Configuration::Authentication,
    jwt,
    "jwt",
    allow_unauthenticated,
    "allowUnauthenticated",
    allow_unauthenticated_reads,
    "allowUnauthenticatedReads");

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Configuration);
  DECLARE_JSON_REQUIRED_FIELDS(Configuration);
  DECLARE_JSON_OPTIONAL_FIELDS_WITH_RENAMES(
    Configuration,
    policy,
    "policy",
    authentication,
    "authentication",
    max_signed_statement_bytes,
    "maxSignedStatementBytes",
    service_issuer,
    "serviceIssuer");

  // Tables
  static constexpr auto ENTRY_TABLE = "public:scitt.entry";
  using EntryTable = ccf::kv::RawCopySerialisedValue<std::vector<uint8_t>>;

  // The `ccf.gov` prefix is necessary to make the table writable
  // through governance.
  static constexpr auto CONFIGURATION_TABLE =
    "public:ccf.gov.scitt.configuration";
  using ConfigurationTable = ccf::kv::JsonSerialisedValue<Configuration>;

} // namespace scitt
