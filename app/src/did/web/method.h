// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "constants.h"
#include "did/resolver.h"
#include "did/web/syntax.h"
#include "kv_types.h"

#include <algorithm>
#include <ccf/crypto/entropy.h>
#include <ccf/ds/hex.h>
#include <ccf/node/host_processes_interface.h>
#include <ccf/tx.h>
#include <fmt/format.h>
#include <string>

namespace scitt::did::web
{
  const static crypto::EntropyPtr entropy = crypto::create_entropy();

  class DidWebResolver : public MethodResolver
  {
  private:
    std::shared_ptr<ccf::AbstractHostProcesses> host_processes;

    void trigger_fetch_did_web_doc(
      const std::string& did, ::timespec current_time, kv::Tx& tx) const
    {
      check_did_is_did_web(did);

      auto now = current_time.tv_sec;
      auto nonce = ds::to_hex(entropy->random(16));
      // add nonce to query param for cache busting
      // TODO validate if this is fine security-wise
      auto url = get_did_web_doc_url_from_did(did) + "?" + nonce;

      auto issuers = tx.template rw<IssuersTable>(ISSUERS_TABLE);

      auto issuer_info = issuers->get(did);
      if (issuer_info.has_value())
      {
        auto last_requested = issuer_info->resolution_requested;
        if (last_requested.has_value())
        {
          // TODO: move the expiry constant to a parameter
          if (now - *last_requested < DID_RESOLUTION_REQUEST_EXPIRY.count())
            return;
        }
        issuer_info->resolution_requested = now;
        issuer_info->resolution_nonce = nonce;
        issuers->put(did, *issuer_info);
      }
      else
      {
        IssuerInfo issuer_info;
        issuer_info.resolution_requested = now;
        issuer_info.resolution_nonce = nonce;
        issuers->put(did, issuer_info);
      }

      // TODO callback url? for now hard-coded in resolver script

      CCF_APP_INFO("Triggering fetch of DID document for {}", did);
      host_processes->trigger_host_process_launch(
        {DID_WEB_RESOLVER_SCRIPT, did, url, nonce});
    }

    std::optional<DidResolutionResult> lookup(
      const Did& did,
      ::timespec current_time,
      const DidWebOptions& options) const
    {
      auto issuers = options.tx.template rw<IssuersTable>(ISSUERS_TABLE);
      auto issuer_info = issuers->get(did);
      if (!issuer_info.has_value())
      {
        return std::nullopt;
      }

      auto& did_doc = issuer_info->did_document;
      if (!did_doc.has_value())
      {
        return std::nullopt;
      }

      auto& resolution_metadata = issuer_info->did_resolution_metadata.value();
      if (options.max_age.has_value())
      {
        auto last_updated = resolution_metadata.updated;
        if (current_time.tv_sec - last_updated > options.max_age->count())
        {
          return std::nullopt;
        }
      }

      if (options.if_assertion_method_id_match.has_value())
      {
        try
        {
          find_assertion_method_in_did_document(
            did_doc.value(), options.if_assertion_method_id_match.value());
        }
        catch (const DIDAssertionMethodNotFoundError&)
        {
          return std::nullopt;
        }
      }

      return {{did_doc.value(), resolution_metadata}};
    }

  public:
    DidWebResolver(std::shared_ptr<ccf::AbstractHostProcesses> host_processes) :
      host_processes(host_processes)
    {}

    std::string_view get_method_prefix() const
    {
      return DID_WEB_PREFIX;
    }

    DidResolutionResult resolve(
      const Did& did, const DidResolutionOptions& options) const
    {
      if (!options.did_web_options.has_value())
      {
        throw DIDResolutionError("did:web resolver is not enabled");
      }

      auto result = lookup(did, options.current_time, *options.did_web_options);
      if (result)
      {
        return *result;
      }

      trigger_fetch_did_web_doc(
        did, options.current_time, options.did_web_options->tx);
      throw AsyncResolutionInProgress();
    }
  };
} // namespace scitt
