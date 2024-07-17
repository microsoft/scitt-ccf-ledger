// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "kv_types.h"

#include <algorithm>
#include <ccf/tx.h>
#include <chrono>
#include <fmt/format.h>
#include <stdexcept>
#include <string>

namespace scitt::did
{
  static constexpr std::string_view DID_PREFIX = "did:";

  // TODO probably belongs somewhere else
  using Did = std::string;

  struct DIDResolutionError : public std::runtime_error
  {
    DIDResolutionError(const std::string& msg) : std::runtime_error(msg) {}
  };

  struct DIDMethodNotSupportedError : public DIDResolutionError
  {
    DIDMethodNotSupportedError(const std::string& did) :
      DIDResolutionError(fmt::format("DID '{}' is not supported", did))
    {}
  };

  struct DidWebOptions
  {
    ccf::kv::ReadOnlyTx& tx;
    std::optional<std::chrono::seconds> max_age;
    std::optional<std::string> if_assertion_method_id_match;
  };

  struct DidResolutionOptions
  {
    ::timespec current_time;

    std::optional<DidWebOptions> did_web_options;
  };

  struct DidResolutionResult // NOLINT(bugprone-exception-escape)
  {
    DidDocument did_doc;
    DidResolutionMetadata resolution_metadata;
  };

  class Resolver
  {
  public:
    virtual ~Resolver() = default;
    virtual DidResolutionResult resolve(
      const Did& did, const DidResolutionOptions& options) const = 0;
  };

  class MethodResolver : public Resolver
  {
  public:
    virtual std::string_view get_method_prefix() const = 0;
  };

  /**
   * The universal resolver allows multiple method resolvers to be registered,
   * and will dispatch DID resolution to the appropriate resolver, based on the
   * DID's prefix.
   *
   * Method resolvers must implement a `get_method_prefix()` method to return
   * their prefix of interest. The prefix should be of the form `did:name:`,
   * including the generic `did:` part and trailing colon.
   *
   * Sub-method resolvers are allowed, such as a resolver whose prefix would be
   * `did:method:sub:`. It is assumed that prefixes of registered resolvers do
   * not overlap.
   */
  class UniversalResolver : public Resolver
  {
  private:
    std::vector<std::unique_ptr<MethodResolver>> resolvers;

  public:
    DidResolutionResult resolve(
      const Did& did, const DidResolutionOptions& options) const override
    {
      // We are unlikely to support more than a handful of resolvers, so a
      // linear search is fine.
      for (const auto& r : resolvers)
      {
        if (did.starts_with(r->get_method_prefix()))
        {
          return r->resolve(did, options);
        }
      }
      throw DIDMethodNotSupportedError(did);
    }

    void register_resolver(std::unique_ptr<MethodResolver> resolver)
    {
      CCF_ASSERT(
        resolver->get_method_prefix().starts_with(DID_PREFIX),
        "Method resolver prefix must start with `did:`");
      CCF_ASSERT(
        resolver->get_method_prefix().ends_with(':'),
        "Method resolver prefix must end with a colon");

      resolvers.push_back(std::move(resolver));
    }
  };
}
