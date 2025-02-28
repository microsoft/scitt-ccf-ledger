// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once
#include "kv_types.h"

#include <ccf/ds/json.h>
#include <nlohmann/json.hpp>
#include <unordered_map>
#include <vector>

namespace scitt
{
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

  struct GetOperation
  {
    struct Out
    {
      ccf::TxID operation_id;
      OperationStatus status;
      std::optional<ccf::TxID> entry_id;
      std::optional<ODataError> error;
    };
  };

} // namespace scitt
