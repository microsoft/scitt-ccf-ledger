// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "call_types.h"
#include "configurable_auth.h"
#include "constants.h"
#include "cose.h"
#include "did/document.h"
#include "generated/constants.h"
#include "historical/historical_queries_adapter.h"
#include "http_error.h"
#include "kv_types.h"
#include "operations_endpoints.h"
#include "policy_engine.h"
#include "service_endpoints.h"
#include "tracing.h"
#include "util.h"
#include "verifier.h"

#include <ccf/app_interface.h>
#include <ccf/base_endpoint_registry.h>
#include <ccf/common_auth_policies.h>
#include <ccf/crypto/base64.h>
#include <ccf/crypto/cose.h>
#include <ccf/ds/logger.h>
#include <ccf/endpoint.h>
#include <ccf/historical_queries_adapter.h>
#include <ccf/historical_queries_interface.h>
#include <ccf/http_query.h>
#include <ccf/json_handler.h>
#include <ccf/kv/value.h>
#include <ccf/node/host_processes_interface.h>
#include <ccf/node/quote.h>
#include <ccf/service/tables/cert_bundles.h>
#include <ccf/service/tables/members.h>
#include <ccf/service/tables/nodes.h>
#include <ccf/service/tables/service.h>
#include <iomanip>
#include <map>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

namespace scitt
{
  using ccf::endpoints::EndpointContext;

  /**
   * This is a re-implementation of CCF's get_query_value, but it throws a
   * BadRequestJsonError if the query parameter cannot be parsed. Also supports
   * boolean parameters as "true" and "false".
   *
   * Returns std::nullopt if the parameter is missing.
   */
  template <typename T>
  std::optional<T> get_query_value(
    const ccf::http::ParsedQuery& pq, std::string_view name)
  {
    SCITT_DEBUG("Get parameter value from parsed query");
    auto it = pq.find(name);
    if (it == pq.end())
    {
      return std::nullopt;
    }

    std::string_view value = it->second;
    if constexpr (std::is_same_v<T, std::string>)
    {
      return value;
    }
    else if constexpr (std::is_same_v<T, bool>)
    {
      if (value == "true")
      {
        return true;
      }
      else if (value == "false")
      {
        return false;
      }
      else
      {
        throw BadRequestJsonError(
          errors::QueryParameterError,
          fmt::format(
            "Invalid value for query parameter '{}': {}", name, value));
      }
    }
    else if constexpr (std::is_integral_v<T>)
    {
      T result;
      const auto [p, ec] = std::from_chars(value.begin(), value.end(), result);
      if (ec != std::errc() || p != value.end())
      {
        throw BadRequestJsonError(
          errors::QueryParameterError,
          fmt::format(
            "Invalid value for query parameter '{}': {}", name, value));
      }
      return result;
    }
    else
    {
      static_assert(ccf::nonstd::dependent_false<T>::value, "Unsupported type");
      return std::nullopt;
    }
  }

  /**
   * Obtain COSE receipt in the format described in
   * https://datatracker.ietf.org/doc/draft-ietf-cose-merkle-tree-proofs/
   * from a CCF TxReceiptImplPtr obtained through a historical query.
   * The proof format is described in
   * https://datatracker.ietf.org/doc/draft-birkholz-cose-receipts-ccf-profile/
   */
  std::vector<uint8_t> get_cose_receipt(
    const ccf::TxReceiptImplPtr& receipt_ptr)
  {
    auto proof = ccf::describe_merkle_proof_v1(*receipt_ptr);
    if (!proof.has_value())
    {
      throw InternalCborError("Failed to get Merkle proof");
    }

    auto signature = describe_cose_signature_v1(*receipt_ptr);
    if (!signature.has_value())
    {
      throw InternalCborError("Failed to get COSE signature");
    }

    // See
    // https://datatracker.ietf.org/doc/draft-ietf-cose-merkle-tree-proofs/
    // Page 11, vdp is the label for verifiable-proods in the unprotected
    // header of the receipt
    const int64_t vdp = 396;
    // -1 is the label for inclusion-proofs
    auto inclusion_proof = ccf::cose::edit::pos::AtKey{-1};
    ccf::cose::edit::desc::Value inclusion_desc{inclusion_proof, vdp, *proof};

    auto cose_receipt =
      ccf::cose::edit::set_unprotected_header(*signature, inclusion_desc);
    return cose_receipt;
  }

  class AppEndpoints : public ccf::UserEndpointRegistry
  {
  private:
    std::unique_ptr<verifier::Verifier> verifier = nullptr;

    /**
     * Create an endpoint with a default locally committed handler.
     */
    ccf::endpoints::Endpoint make_endpoint(
      const std::string& method,
      ccf::RESTVerb verb,
      const ccf::endpoints::EndpointFunction& f,
      const ccf::AuthnPolicies& ap) override
    {
      return make_endpoint_with_local_commit_handler(
        method, verb, f, ccf::endpoints::default_locally_committed_func, ap);
    }

    /**
     * Create an endpoint with a custom locally committed handler.
     * Although the additional handler is supplied it does not
     * guarantee that it will be called.
     */
    ccf::endpoints::Endpoint make_endpoint_with_local_commit_handler(
      const std::string& method,
      ccf::RESTVerb verb,
      const ccf::endpoints::EndpointFunction& f,
      const ccf::endpoints::LocallyCommittedEndpointFunction& l,
      const ccf::AuthnPolicies& ap) override
    {
      const std::function<ccf::ApiResult(timespec & time)> get_time =
        [this](timespec& time) {
          return this->get_untrusted_host_time_v1(time);
        };

      auto endpoint = ccf::UserEndpointRegistry::make_endpoint(
        method,
        verb,
        tracing_adapter_first(error_adapter(f), method, get_time),
        ap);
      endpoint.locally_committed_func =
        tracing_adapter_last(l, method, get_time);
      return endpoint;
    }

  public:
    AppEndpoints(ccf::AbstractNodeContext& context_) :
      ccf::UserEndpointRegistry(context_)
    {
      const ccf::AuthnPolicies authn_policy = {
        std::make_shared<ConfigurableEmptyAuthnPolicy>(),
        std::make_shared<ConfigurableJwtAuthnPolicy>(),
      };

      SCITT_DEBUG("Get historical state from CCF");
      auto& state_cache = context.get_historical_state();
      state_cache.set_soft_cache_limit(HISTORICAL_CACHE_SOFT_LIMIT);

      verifier = std::make_unique<verifier::Verifier>();

      auto register_signed_statement = [this](EndpointContext& ctx) {
        const auto& body = ctx.rpc_ctx->get_request_body();
        SCITT_DEBUG(
          "Signed Statement Registration body size: {} bytes", body.size());

        auto cfg = ctx.tx.template ro<ConfigurationTable>(CONFIGURATION_TABLE)
                     ->get()
                     .value_or(Configuration{});

        const auto max_entry_size =
          cfg.max_signed_statement_bytes.value_or(MAX_ENTRY_SIZE_BYTES_DEFAULT);
        SCITT_DEBUG(
          "Maximum allowed Signed Statement size: {} bytes", max_entry_size);

        if (body.size() > max_entry_size)
        {
          throw BadRequestCborError(
            errors::PayloadTooLarge,
            fmt::format(
              "Entry size {} exceeds maximum allowed size {}",
              body.size(),
              max_entry_size));
        }

        ::timespec host_time;
        auto result = this->get_untrusted_host_time_v1(host_time);
        if (result != ccf::ApiResult::OK)
        {
          throw InternalCborError(fmt::format(
            "Failed to get host time: {}", ccf::api_result_to_str(result)));
        }

        cose::ProtectedHeader phdr;
        cose::UnprotectedHeader uhdr;
        std::span<uint8_t> payload;
        std::optional<verifier::VerifiedSevSnpAttestationDetails> details;
        try
        {
          SCITT_DEBUG("Verify submitted signed statement");
          std::tie(phdr, uhdr, payload, details) =
            verifier->verify_signed_statement(body, ctx.tx, host_time, cfg);
        }
        catch (const verifier::VerificationError& e)
        {
          SCITT_DEBUG("Signed statement verification failed: {}", e.what());
          throw BadRequestCborError(errors::InvalidInput, e.what());
        }

        // Use Rego policy if defined, otherwise use JS policy if defined
        // If neither is defined, do not apply any policy, but reject if
        // CWT issuer is present.
        if (cfg.policy.policy_rego.has_value())
        {
          SCITT_DEBUG("Using Rego Policy");
          auto start = std::chrono::steady_clock::now();
          const auto policy_violation_reason = check_for_policy_violations_rego(
            cfg.policy.policy_rego.value(),
            "configured_policy",
            phdr,
            uhdr,
            payload,
            details,
            cfg.policy.get_policy_rego_statement_limit());
          if (policy_violation_reason.has_value())
          {
            SCITT_DEBUG(
              "Policy check failed: {}", policy_violation_reason.value());
            throw BadRequestCborError(
              errors::PolicyFailed,
              fmt::format(
                "Policy was not met: {}", policy_violation_reason.value()));
          }
          auto end = std::chrono::steady_clock::now();
          auto elapsed =
            std::chrono::duration_cast<std::chrono::microseconds>(end - start);
          CCF_APP_DEBUG("Rego Policy check passed in {}us", elapsed.count());
        }
        else if (cfg.policy.policy_script.has_value())
        {
          SCITT_DEBUG("Using JS Policy");
          auto start = std::chrono::steady_clock::now();
          const auto policy_violation_reason = check_for_policy_violations(
            cfg.policy.policy_script.value(),
            "configured_policy",
            phdr,
            uhdr,
            payload,
            details);
          if (policy_violation_reason.has_value())
          {
            SCITT_DEBUG(
              "Policy check failed: {}", policy_violation_reason.value());
            throw BadRequestCborError(
              errors::PolicyFailed,
              fmt::format(
                "Policy was not met: {}", policy_violation_reason.value()));
          }
          auto end = std::chrono::steady_clock::now();
          auto elapsed =
            std::chrono::duration_cast<std::chrono::microseconds>(end - start);
          CCF_APP_DEBUG("JS Policy check passed in {}us", elapsed.count());
        }
        else
        {
          if (verifier::contains_cwt_issuer(phdr))
          {
            SCITT_DEBUG("No policy applied, but CWT issuer present");
            throw BadRequestCborError(
              errors::PolicyFailed,
              "Policy was not met: CWT issuer present but no policy "
              "configured");
          }
          else
          {
            SCITT_DEBUG("No policy applied");
          }
        }

        // Remove un-authenticated content from payload, and only keep the
        // actual signed statement, i.e. the bytes that are in fact signed.
        const auto signed_statement = ccf::cose::edit::set_unprotected_header(
          body, ccf::cose::edit::desc::Empty{});

        // Bind the digest of the signed statement in the Merkle Tree as a
        // claims digest for this transaction
        ctx.rpc_ctx->set_claims_digest(
          ccf::ClaimsDigest::Digest(signed_statement));

        // Store the original COSE_Sign1 message in the KV, so we can retrieve
        // it later, inject the receipt in it, and serve a transparent
        // statement.
        SCITT_DEBUG("Signed statement stored in the ledger");
        auto* entry_table = ctx.tx.template rw<EntryTable>(ENTRY_TABLE);
        entry_table->put(signed_statement);

        SCITT_INFO("SignedStatementSizeKb={}", body.size() / 1024);

        SCITT_DEBUG("SignedStatement was submitted synchronously");

        record_synchronous_operation(host_time, ctx.tx);
      };

      /**
       * Signed Statement Registration, 2.1.2 in
       * https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi/
       */
      make_endpoint_with_local_commit_handler(
        "/entries",
        HTTP_POST,
        register_signed_statement,
        operation_locally_committed_func,
        authn_policy)
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Always)
        .set_redirection_strategy(
          ccf::endpoints::RedirectionStrategy::ToPrimary)
        .install();

      auto is_tx_committed =
        [this](ccf::View view, ccf::SeqNo seqno, std::string& error_reason) {
          return ccf::historical::is_tx_committed_v2(
            consensus, view, seqno, error_reason);
        };

      static constexpr auto get_entry_receipt_path = "/entries/{txid}";
      auto get_entry_receipt =
        [this](
          EndpointContext& ctx,
          const ccf::historical::StatePtr& historical_state) {
          SCITT_DEBUG("Get transaction historical state");
          auto historical_tx = historical_state->store->create_read_only_tx();

          auto* entries = historical_tx.template ro<EntryTable>(ENTRY_TABLE);
          auto entry = entries->get();
          if (!entry.has_value())
          {
            throw BadRequestCborError(
              errors::InvalidInput,
              fmt::format(
                "Transaction ID {} does not correspond to a submission.",
                historical_state->transaction_id.to_str()));
          }

          SCITT_DEBUG("Get receipt from the ledger");
          auto cose_receipt = get_cose_receipt(historical_state->receipt);

          ctx.rpc_ctx->set_response_body(cose_receipt);
          ctx.rpc_ctx->set_response_header(
            ccf::http::headers::CONTENT_TYPE,
            ccf::http::headervalues::contenttype::COSE);
        };

      /**
       * Resolve Receipt, 2.1.4 in
       * https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi/
       */
      make_endpoint(
        get_entry_receipt_path,
        HTTP_GET,
        scitt::historical::entry_adapter(
          get_entry_receipt, state_cache, is_tx_committed),
        authn_policy)
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .set_redirection_strategy(ccf::endpoints::RedirectionStrategy::None)
        .install();

      static constexpr auto get_entry_statement_path =
        "/entries/{txid}/statement";
      auto get_entry_statement =
        [this](
          EndpointContext& ctx,
          const ccf::historical::StatePtr& historical_state) {
          SCITT_DEBUG("Get transaction historical state");
          auto historical_tx = historical_state->store->create_read_only_tx();

          auto* entries = historical_tx.template ro<EntryTable>(ENTRY_TABLE);
          auto entry = entries->get();
          if (!entry.has_value())
          {
            throw BadRequestCborError(
              errors::InvalidInput,
              fmt::format(
                "Transaction ID {} does not correspond to a submission.",
                historical_state->transaction_id.to_str()));
          }

          SCITT_DEBUG("Get receipt from the ledger");
          auto cose_receipt = get_cose_receipt(historical_state->receipt);

          // See https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/
          // Section 4.4, 394 is the label for an array of receipts in the
          // unprotected header (scitt::cose::COSE_HEADER_PARAM_SCITT_RECEIPTS
          // here)
          const int64_t receipts =
            scitt::cose::COSE_HEADER_PARAM_SCITT_RECEIPTS;
          ccf::cose::edit::desc::Value receipts_desc{
            ccf::cose::edit::pos::InArray{}, receipts, cose_receipt};

          SCITT_DEBUG("Embed receipt into transparent statement");
          auto statement =
            ccf::cose::edit::set_unprotected_header(*entry, receipts_desc);

          ctx.rpc_ctx->set_response_body(statement);
          ctx.rpc_ctx->set_response_header(
            ccf::http::headers::CONTENT_TYPE,
            ccf::http::headervalues::contenttype::COSE);
        };

      /**
       * This endpoint is not part of RFC,
       * but to avoid clients embedding the receipt in the statement
       * we provide a convenience endpoint that does this for them.
       */
      make_endpoint(
        get_entry_statement_path,
        HTTP_GET,
        scitt::historical::entry_adapter(
          get_entry_statement, state_cache, is_tx_committed),
        authn_policy)
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .set_redirection_strategy(ccf::endpoints::RedirectionStrategy::None)
        .install();

      register_service_endpoints(context, *this);

      register_operations_endpoints(context, *this, authn_policy);
    }
  };
} // namespace scitt

namespace ccf
{
  std::unique_ptr<ccf::endpoints::EndpointRegistry> make_user_endpoints(
    ccf::AbstractNodeContext& context)
  {
    return std::make_unique<scitt::AppEndpoints>(context);
  }
} // namespace ccf
