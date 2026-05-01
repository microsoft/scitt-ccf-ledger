// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <chrono>
#include <string>
#include <vector>

// When changing any of the values here, make sure to update the corresponding
// entries in test/constants.py
namespace scitt
{
  const uint64_t MAX_ENTRY_SIZE_BYTES_DEFAULT = 1024 * 1024;

  const std::chrono::seconds OPERATION_EXPIRY{60 * 60};

  // IANA-registered SCITT content types
  // https://www.iana.org/assignments/media-types/
  const std::string CT_SCITT_RECEIPT = "application/scitt-receipt+cose";
  const std::string CT_SCITT_STATEMENT = "application/scitt-statement+cose";

  // API versioning for SCITT endpoints.
  // The new version enables SCRAPI v09 behavior (303, 302, new content types).
  // Older versions (or absent api-version) get legacy behavior.
  const std::string SCITT_API_VERSION_2026_03_26 = "2026-03-26";

  namespace errors
  {
    const std::string IndexingInProgressRetryLater =
      "IndexingInProgressRetryLater";
    const std::string InternalError = "InternalError";
    const std::string InvalidInput = "InvalidInput";
    const std::string TransactionNotCached = "TransactionNotCached";
    const std::string QueryParameterError = "QueryParameterError";
    const std::string PayloadTooLarge = "PayloadTooLarge";
    const std::string NotFound = "NotFound";
    const std::string OperationExpired = "OperationExpired";
    const std::string PolicyError = "PolicyError";
    const std::string PolicyFailed = "PolicyFailed";
  } // namespace errors

  namespace indexing
  {
    const size_t SEQNOS_PER_BUCKET = 10000;
    const size_t MAX_BUCKETS = 20;
  }

} // namespace scitt
