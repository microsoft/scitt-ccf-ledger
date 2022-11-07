// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "constants.h"
#include "did/resolver.h"
#include "did/web/method.h"
#include "util.h"

#include <algorithm>
#include <ccf/ds/hex.h>
#include <ccf/ds/json.h>
#include <ccf/ds/logger.h>
#include <fmt/format.h>
#include <stdexcept>
#include <string>

namespace scitt::did
{
  struct UnattestedResolution
  {
    std::string url;
    std::string nonce;
    std::string body;
  };
  DECLARE_JSON_TYPE(UnattestedResolution);
  DECLARE_JSON_REQUIRED_FIELDS(UnattestedResolution, url, nonce, body);

  struct UnattestedResolutionError : public std::runtime_error
  {
    UnattestedResolutionError(const std::string& msg) : std::runtime_error(msg)
    {}
  };

  DidResolutionResult verify_unattested_resolution(
    const std::string& did,
    const std::string& nonce,
    const UnattestedResolution& resolution)
  {
    // Compute DID from URL in data.
    std::string computed_did;
    try
    {
      computed_did = did::web::get_did_from_did_web_doc_url(resolution.url);
    }
    catch (const std::exception& e)
    {
      throw UnattestedResolutionError(e.what());
    }

    // Match computed DID against endpoint 'did' URL parameter.
    if (computed_did != did)
    {
      throw UnattestedResolutionError(fmt::format(
        "DID in URL does not match DID in data: {} != {}", did, computed_did));
      throw UnattestedResolutionError("DID does not match URL");
    }

    // Match resolution nonce against KV.
    if (nonce != resolution.nonce)
    {
      throw UnattestedResolutionError("nonce does not match expected value");
    }

    // Decode Base64-encoded HTTP body in data.
    std::vector<uint8_t> body;
    try
    {
      body = crypto::raw_from_b64(resolution.body);
    }
    catch (const std::exception& e)
    {
      throw UnattestedResolutionError("HTTP body is not valid Base64-encoded.");
    }

    // Parse HTTP body as DID document.
    DidDocument did_doc;
    try
    {
      did_doc = nlohmann::json::parse(body).get<did::DidDocument>();
    }
    catch (const std::exception& e)
    {
      throw UnattestedResolutionError(
        "HTTP body could not be parsed as DID document.");
    }

    // Match "id" of DID document against endpoint 'did' URL parameter.
    if (did_doc.id != did)
    {
      throw UnattestedResolutionError(
        "DID document ID does not match expected value");
    }

    DidResolutionMetadata did_resolution_metadata;
    return {did_doc, did_resolution_metadata};
  }
}
