// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#define FMT_HEADER_ONLY
#include <fmt/format.h>

namespace scitt::did::web
{
  const std::string DID_WEB_PREFIX = "did:web:";
  const std::string DID_WEB_DOC_URL_PREFIX = "https://";
  const std::string DID_WEB_DOC_WELLKNOWN_PATH = "/.well-known";
  const std::string DID_WEB_DOC_URL_SUFFIX = "/did.json";
  const std::string ENCODED_COLON = "%3A";

  void check_did_is_did_web(const std::string& did)
  {
    if (!did.starts_with(DID_WEB_PREFIX))
    {
      throw std::runtime_error(
        fmt::format("DID must start with {}", DID_WEB_PREFIX));
    }
  }

  std::string get_did_web_doc_url_from_did(const std::string& did)
  {
    check_did_is_did_web(did);

    // Strip DID Web prefix.
    auto rest = did.substr(DID_WEB_PREFIX.size());

    // Check if an optional path has been specified.
    auto path_delimiter = rest.find(':');

    // After the prefix, DID web only uses colons as path separaters. Swap any
    // colons for forward slashes.
    std::replace(rest.begin(), rest.end(), ':', '/');

    // DID Web can optionally include a port in the domain delimited by a
    // percentage encoded colon. Decode it.
    auto port_delimiter = rest.find(ENCODED_COLON);
    if (port_delimiter != std::string::npos)
    {
      rest = rest.replace(port_delimiter, ENCODED_COLON.size(), ":");
    }

    if (path_delimiter == std::string::npos)
    {
      // This DID Web has no path specified. Build its URL with the default path
      // from the DID Spec.
      return DID_WEB_DOC_URL_PREFIX + rest + DID_WEB_DOC_WELLKNOWN_PATH +
        DID_WEB_DOC_URL_SUFFIX;
    }
    else
    {
      // This DID Web has a path specified. Build its URL.
      return DID_WEB_DOC_URL_PREFIX + rest + DID_WEB_DOC_URL_SUFFIX;
    }
  }

  std::string get_did_from_did_web_doc_url(const std::string& url)
  {
    // remove cache-busting query param
    auto i = url.find('?');
    std::string url_;
    if (i != std::string::npos)
    {
      url_ = url.substr(0, i);
    }
    else
    {
      url_ = url;
    }
    if (
      !url_.starts_with(DID_WEB_DOC_URL_PREFIX) ||
      !url_.ends_with(DID_WEB_DOC_URL_SUFFIX))
    {
      throw std::runtime_error(fmt::format(
        "URL '{}' invalid, must start with '{}' and end with '{}'",
        url_,
        DID_WEB_DOC_URL_PREFIX,
        DID_WEB_DOC_URL_SUFFIX));
    }

    auto bare = url_.substr(
      DID_WEB_DOC_URL_PREFIX.size(),
      url_.size() - DID_WEB_DOC_URL_PREFIX.size() -
        DID_WEB_DOC_URL_SUFFIX.size());

    // Percentage encode the port delimiter, which will be the first colon in
    // the URL, if any. Note DID Web URLs shouldn't contain colons in the path
    // or domain as the DID Web spec uses them as path delimiters.
    auto port_delimiter = bare.find(':');
    if (port_delimiter != std::string::npos)
    {
      bare.replace(port_delimiter, 1, "%3A");
    }

    if (bare.ends_with(DID_WEB_DOC_WELLKNOWN_PATH))
    {
      bare = bare.substr(0, bare.size() - DID_WEB_DOC_WELLKNOWN_PATH.size());
      if (bare.find('/') != std::string::npos)
      {
        throw std::runtime_error(fmt::format(
          "URL invalid, cannot include path before {}",
          DID_WEB_DOC_WELLKNOWN_PATH));
      }
    }
    else
    {
      std::replace(bare.begin(), bare.end(), '/', ':');
    }

    return DID_WEB_PREFIX + bare;
  }
} // namespace scitt::did::web
