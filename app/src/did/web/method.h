// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#ifdef VIRTUAL_ENCLAVE
#  include "did/unattested.h"
#else
#  include "did/attested.h"
#endif
#include "constants.h"
#include "did/resolver.h"
#include "did/web/syntax.h"
#include "http_error.h"
#include "kv_types.h"
#include "tracing.h"
#include "util.h"

#include <algorithm>
#include <ccf/node/host_processes_interface.h>
#include <fmt/format.h>
#include <string>

namespace scitt::did::web
{
#ifdef VIRTUAL_ENCLAVE
  using ResolutionCallbackData = UnattestedResolution;
  using ResolutionValidationError = UnattestedResolutionError;
#else
  using ResolutionCallbackData = AttestedResolution;
  using ResolutionValidationError = AttestedResolutionError;
#endif

  /**
   * This exception is used to interrupt processing of a claim and ask the
   * caller to schedule an asynchronous resolution, using
   * DidWebResolver::trigger_asynchronous_resolution.
   *
   * If this exception is thrown during the callback of an asynchronous
   * resolution, then the resolution result was unsatisfactory and the operation
   * is marked as failed with the message contained in the exception.
   */
  struct AsyncResolutionNeeded : public BadRequestError
  {
    AsyncResolutionNeeded(std::string did, std::string msg) :
      BadRequestError(errors::DIDResolutionError, msg),
      did(did)
    {}

    AsyncResolutionNeeded(std::string did, std::string code, std::string msg) :
      BadRequestError(code, msg),
      did(did)
    {}

    std::string did;
  };

  class DidWebResolver : public MethodResolver
  {
  public:
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

      auto issuers =
        options.did_web_options->tx.template ro<IssuersTable>(ISSUERS_TABLE);

      auto issuer_info = issuers->get(did);
      if (!issuer_info.has_value())
      {
        throw AsyncResolutionNeeded(did, "Unknown issuer");
      }

      if (issuer_info->error.has_value())
      {
        throw AsyncResolutionNeeded(
          did, issuer_info->error->code, issuer_info->error->message);
      }

      if (
        !issuer_info->did_document.has_value() ||
        !issuer_info->did_resolution_metadata.has_value())
      {
        throw AsyncResolutionNeeded(errors::InternalError, "Empty issuer");
      }

      auto& did_doc = issuer_info->did_document.value();
      auto& resolution_metadata = issuer_info->did_resolution_metadata.value();
      if (options.did_web_options->max_age.has_value())
      {
        auto last_updated = resolution_metadata.updated;
        if (
          options.current_time.tv_sec - last_updated >
          options.did_web_options->max_age->count())
        {
          throw AsyncResolutionNeeded(
            did, "DID document for issuer has expired");
        }
      }

      if (options.did_web_options->if_assertion_method_id_match.has_value())
      {
        try
        {
          find_assertion_method_in_did_document(
            did_doc,
            options.did_web_options->if_assertion_method_id_match.value());
        }
        catch (const DIDAssertionMethodNotFoundError&)
        {
          throw AsyncResolutionNeeded(
            did, "Missing assertion method in DID document");
        }
      }

      return {did_doc, resolution_metadata};
    }

    static void trigger_asynchronous_resolution(
      ccfapp::AbstractNodeContext& context,
      const std::string& callback_url,
      const std::string& did,
      const std::string& nonce)
    {
      // add nonce to query param for cache busting
      auto url = get_did_web_doc_url_from_did(did) + "?" + nonce;

      auto host_processes = context.get_subsystem<ccf::AbstractHostProcesses>();
      host_processes->trigger_host_process_launch(
        {DID_WEB_RESOLVER_SCRIPT, url, nonce, callback_url});
    }

    /**
     * Write a resolution result to the issuers table in the KV.
     *
     * This performs validation of the results, eg. it checks the attestation
     * and TLS certificate chain of the resolution.
     */
    static void update_did_document(
      ::timespec host_time,
      kv::Tx& tx,
      const ResolutionCallbackData& result,
      const std::string& issuer,
      const std::string& expected_nonce)
    {
      DidResolutionResult resolution;
      try
      {
#ifdef VIRTUAL_ENCLAVE
        resolution =
          verify_unattested_resolution(issuer, expected_nonce, result);
#else
        auto ca_cert_bundles = tx.template ro<ccf::CACertBundlePEMs>(
          ccf::Tables::CA_CERT_BUNDLE_PEMS);
        resolution = verify_attested_resolution(
          issuer, expected_nonce, ca_cert_bundles, result);
#endif
      }
      catch (const ResolutionValidationError& e)
      {
        // Generally, the error we write into the KV won't be used: the next
        // time the same issuer is requested we will ignore the error and send
        // out a new request.
        //
        // However, in the case of an aggregated resolution (multiple claims
        // submitted concurrently for the same issuer), we'll get multiple
        // callbacks but only the first one contains the resolution payload.
        // In this case, no re-resolution happens and we'll return the error
        // again.
        auto issuers = tx.template rw<IssuersTable>(ISSUERS_TABLE);
        issuers->put(
          issuer,
          IssuerInfo{
            .error = {{
              .code = errors::DIDResolutionError,
              .message = e.what(),
            }},
          });
        throw BadRequestError(errors::DIDResolutionError, e.what());
      }

      resolution.resolution_metadata.updated = host_time.tv_sec;

      auto issuers = tx.template rw<IssuersTable>(ISSUERS_TABLE);
      IssuerInfo issuer_info{
        .did_document = std::move(resolution.did_doc),
        .did_resolution_metadata = std::move(resolution.resolution_metadata),
      };
      issuers->put(issuer, issuer_info);
    }
  };
} // namespace scitt
