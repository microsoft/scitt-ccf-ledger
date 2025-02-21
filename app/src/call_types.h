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

  struct GetEntry
  {
    struct Out
    {
      ccf::TxID entry_id;
    };
  };

  DECLARE_JSON_TYPE(GetEntry::Out);
  DECLARE_JSON_REQUIRED_FIELDS_WITH_RENAMES(GetEntry::Out, entry_id, "EntryId");

  struct GetOperation
  {
    struct Out
    {
      ccf::TxID operation_id;
      OperationStatus status;
      std::optional<ccf::TxID> entry_id;
      std::optional<nlohmann::json> error;
    };
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(GetOperation::Out);
  DECLARE_JSON_REQUIRED_FIELDS_WITH_RENAMES(
    GetOperation::Out, operation_id, "OperationId", status, "Status");
  DECLARE_JSON_OPTIONAL_FIELDS_WITH_RENAMES(
    GetOperation::Out, entry_id, "EntryId", error, "Error");

  struct GetAllOperations
  {
    struct Out
    {
      std::vector<GetOperation::Out> operations;
    };
  };
  DECLARE_JSON_TYPE(GetAllOperations::Out);
  DECLARE_JSON_REQUIRED_FIELDS(GetAllOperations::Out, operations);

  struct PostOperationCallback
  {
    struct In
    {
      std::vector<uint8_t> context;
      std::optional<nlohmann::json> result;
    };
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(PostOperationCallback::In);
  DECLARE_JSON_REQUIRED_FIELDS(PostOperationCallback::In, context);
  DECLARE_JSON_OPTIONAL_FIELDS(PostOperationCallback::In, result);

} // namespace scitt
