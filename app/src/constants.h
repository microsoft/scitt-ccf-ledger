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
  const uint64_t MAX_ENTRY_SIZE_BYTES = 1024 * 1024;

  const std::chrono::seconds OPERATION_EXPIRY{60 * 60};

  const std::chrono::seconds DID_RESOLUTION_CACHE_EXPIRY{60 * 30};

  namespace errors
  {
    const std::string DIDMethodNotSupported = "DIDMethodNotSupported";
    const std::string DIDResolutionError = "DIDResolutionError";
    const std::string IndexingInProgressRetryLater =
      "IndexingInProgressRetryLater";
    const std::string InternalError = "InternalError";
    const std::string InvalidInput = "InvalidInput";
    const std::string TransactionNotCached = "TransactionNotCached";
    const std::string QueryParameterError = "QueryParameterError";
    const std::string PayloadTooLarge = "PayloadTooLarge";
    const std::string UnknownFeed = "UnknownFeed";
    const std::string NoPrefixTree = "NoPrefixTree";
    const std::string NotFound = "NotFound";
    const std::string OperationExpired = "OperationExpired";
  } // namespace errors

} // namespace scitt
