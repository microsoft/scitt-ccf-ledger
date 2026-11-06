// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once
#include "cbor.h"
#include "odata_error.h"

#include <ccf/ds/json.h>
#include <ccf/tx_id.h>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace scitt
{
  struct GetVersion
  {
    struct Out
    {
      std::string version;
    };
  };

  DECLARE_JSON_TYPE(GetVersion::Out);
  DECLARE_JSON_REQUIRED_FIELDS(GetVersion::Out, version);

  enum class OperationStatus
  {
    Running,
    Failed,
    Succeeded,
  };

  static std::string operationStatusToString(OperationStatus status)
  {
    switch (status)
    {
      case OperationStatus::Running:
        return "running";
      case OperationStatus::Failed:
        return "failed";
      case OperationStatus::Succeeded:
        return "succeeded";
      default:
        throw std::invalid_argument("Invalid OperationStatus value");
    }
  }

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

  static std::vector<uint8_t> operation_to_cbor(
    const GetOperation::Out& operation)
  {
    std::optional<std::string> entry_id_opt = operation.entry_id.has_value() ?
      std::optional<std::string>(operation.entry_id.value().to_str()) :
      std::nullopt;
    std::optional<std::string> error_code_opt = operation.error.has_value() ?
      std::optional<std::string>(operation.error.value().code) :
      std::nullopt;
    std::optional<std::string> error_message_opt = operation.error.has_value() ?
      std::optional<std::string>(operation.error.value().message) :
      std::nullopt;

    return cbor::operation_props_to_cbor(
      operation.operation_id.to_str(),
      operationStatusToString(operation.status),
      entry_id_opt,
      error_code_opt,
      error_message_opt);
  }
} // namespace scitt
