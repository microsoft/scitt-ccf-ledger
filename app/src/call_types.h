// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once
#ifdef VIRTUAL_ENCLAVE
#  include "did/unattested.h"
#else
#  include "did/attested.h"
#endif
#include "kv_types.h"

#include <ccf/ds/json.h>
#include <nlohmann/json.hpp>
#include <unordered_map>
#include <vector>

namespace scitt
{
  struct PostDidResolution
  {
#ifdef VIRTUAL_ENCLAVE
    using In = did::UnattestedResolution;
#else
    using In = did::AttestedResolution;
#endif
  };

  struct GetIssuerInfo
  {
    using Out = IssuerInfo;
  };

  struct GetIssuers
  {
    struct Out
    {
      std::vector<std::string> issuers;
    };
  };

  DECLARE_JSON_TYPE(GetIssuers::Out);
  DECLARE_JSON_REQUIRED_FIELDS(GetIssuers::Out, issuers);

  struct GetServiceParameters
  {
    struct Out
    {
      std::string service_id;
      std::string tree_algorithm;
      std::string signature_algorithm;
      std::string service_certificate;
    };
  };

  DECLARE_JSON_TYPE(GetServiceParameters::Out);
  DECLARE_JSON_REQUIRED_FIELDS_WITH_RENAMES(
    GetServiceParameters::Out,
    service_id,
    "serviceId",
    tree_algorithm,
    "treeAlgorithm",
    signature_algorithm,
    "signatureAlgorithm",
    service_certificate,
    "serviceCertificate");

  struct GetHistoricServiceParameters
  {
    struct Out
    {
      std::vector<GetServiceParameters::Out> parameters;
    };
  };

  DECLARE_JSON_TYPE(GetHistoricServiceParameters::Out);
  DECLARE_JSON_REQUIRED_FIELDS(GetHistoricServiceParameters::Out, parameters);

  struct GetEntriesTransactionIds
  {
    struct Out
    {
      std::vector<std::string> transaction_ids;
      std::optional<std::string> next_link;
    };
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(GetEntriesTransactionIds::Out);
  DECLARE_JSON_REQUIRED_FIELDS_WITH_RENAMES(
    GetEntriesTransactionIds::Out, transaction_ids, "transactionIds");
  DECLARE_JSON_OPTIONAL_FIELDS_WITH_RENAMES(
    GetEntriesTransactionIds::Out, next_link, "nextLink");

  struct GetVersion
  {
    struct Out
    {
      std::string version;
    };
  };

  DECLARE_JSON_TYPE(GetVersion::Out);
  DECLARE_JSON_REQUIRED_FIELDS(GetVersion::Out, version);

} // namespace scitt
