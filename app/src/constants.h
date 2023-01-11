// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "generated/constants.h"

#include <chrono>
#include <string>
#include <vector>

namespace scitt
{
  const uint64_t MAX_ENTRY_SIZE_BYTES = 1024 * 1024;

  const std::chrono::seconds DID_RESOLUTION_REQUEST_EXPIRY{60 * 5};
  const std::chrono::seconds DID_RESOLUTION_CACHE_EXPIRY{60 * 30};

#ifdef VIRTUAL_ENCLAVE
  const std::string DID_WEB_RESOLVER_SCRIPT =
    "/tmp/scitt/fetch-did-web-doc-unattested.sh";
#else
  const std::string DID_WEB_RESOLVER_SCRIPT =
    "/tmp/scitt/fetch-did-web-doc-attested.sh";
#endif

  namespace errors
  {
    const std::string DIDResolutionInProgressRetryLater =
      "DIDResolutionInProgressRetryLater";
    const std::string DIDMethodNotSupported = "DIDMethodNotSupported";
    const std::string IndexingInProgressRetryLater =
      "IndexingInProgressRetryLater";
    const std::string InternalError = "InternalError";
    const std::string InvalidInput = "InvalidInput";
    const std::string QueryParameterError = "QueryParameterError";
    const std::string PayloadTooLarge = "PayloadTooLarge";
    const std::string UnknownFeed = "UnknownFeed";
    const std::string NoPrefixTree = "NoPrefixTree";
    const std::string NotFound = "NotFound";
  } // namespace errors

} // namespace scitt
