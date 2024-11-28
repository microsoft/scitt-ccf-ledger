// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "call_types.h"
#include "configurable_auth.h"
#include "constants.h"
#include "cose.h"
#include "did/document.h"
#include "did/resolver.h"
#include "generated/constants.h"
#include "historical/historical_queries_adapter.h"
#include "http_error.h"
#include "kv_types.h"
#include "operations_endpoints.h"
#include "policy_engine.h"
#include "receipt.h"
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
#include <ccf/indexing/strategies/seqnos_by_key_bucketed.h>
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

  using EntrySeqnoIndexingStrategy =
    ccf::indexing::strategies::SeqnosForValue_Bucketed<EntryTable>;

  /**
   * This is a re-implementation of CCF's get_query_value, but it throws a
   * BadRequestError if the query parameter cannot be parsed. Also supports
   * boolean parameters as "true" and "false".
   *
   * Returns std::nullopt if the parameter is missing.
   */
  template <typename T>
  static std::optional<T> get_query_value(
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
        throw BadRequestError(
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
        throw BadRequestError(
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
  std::vector<uint8_t> get_cose_receipt(ccf::TxReceiptImplPtr receipt_ptr)
  {
    auto proof = ccf::describe_merkle_proof_v1(*receipt_ptr);
    if (!proof.has_value())
    {
      throw InternalError("Failed to get Merkle proof");
    }

    auto signature = describe_cose_signature_v1(*receipt_ptr);
    if (!signature.has_value())
    {
      throw InternalError("Failed to get COSE signature");
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
    std::shared_ptr<EntrySeqnoIndexingStrategy> entry_seqno_index = nullptr;
    std::unique_ptr<verifier::Verifier> verifier = nullptr;

    std::optional<ccf::TxStatus> get_tx_status(ccf::SeqNo seqno)
    {
      SCITT_DEBUG("Get transaction status");
      ccf::ApiResult result;

      ccf::View view_of_seqno;
      result = get_view_for_seqno_v1(seqno, view_of_seqno);
      if (result == ccf::ApiResult::OK)
      {
        ccf::TxStatus status;
        result = get_status_for_txid_v1(view_of_seqno, seqno, status);
        if (result == ccf::ApiResult::OK)
        {
          SCITT_DEBUG("Transaction status: {}", ccf::tx_status_to_str(status));
          return status;
        }
      }

      SCITT_FAIL("Transaction status could not be retrieved");

      return std::nullopt;
    }

    ccf::endpoints::Endpoint make_endpoint(
      const std::string& method,
      ccf::RESTVerb verb,
      const ccf::endpoints::EndpointFunction& f,
      const ccf::AuthnPolicies& ap) override
    {
      return make_endpoint_with_local_commit_handler(
        method, verb, f, ccf::endpoints::default_locally_committed_func, ap);
    }

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
        method, verb, tracing_adapter(error_adapter(f), method, get_time), ap);
      endpoint.locally_committed_func =
        tracing_local_commit_adapter(l, method, get_time);
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

      SCITT_DEBUG("Install custom indexing strategy");
      entry_seqno_index = std::make_shared<EntrySeqnoIndexingStrategy>(
        ENTRY_TABLE, context, 10000, 20);
      context.get_indexing_strategies().install_strategy(entry_seqno_index);

      auto resolver = std::make_unique<did::UniversalResolver>();
      verifier = std::make_unique<verifier::Verifier>(std::move(resolver));

      auto register_signed_statement = [this](EndpointContext& ctx) {
        auto& body = ctx.rpc_ctx->get_request_body();
        SCITT_DEBUG(
          "Signed Statement Registration body size: {} bytes", body.size());
        if (body.size() > MAX_ENTRY_SIZE_BYTES)
        {
          throw BadRequestError(
            errors::PayloadTooLarge,
            fmt::format(
              "Entry size {} exceeds maximum allowed size {}",
              body.size(),
              MAX_ENTRY_SIZE_BYTES));
        }

        ::timespec host_time;
        auto result = this->get_untrusted_host_time_v1(host_time);
        if (result != ccf::ApiResult::OK)
        {
          throw InternalError(fmt::format(
            "Failed to get host time: {}", ccf::api_result_to_str(result)));
        }

        SCITT_DEBUG("Get service configuration from KV store");
        auto cfg = ctx.tx.template ro<ConfigurationTable>(CONFIGURATION_TABLE)
                     ->get()
                     .value_or(Configuration{});

        SignedStatementProfile signed_statement_profile;
        cose::ProtectedHeader phdr;
        cose::UnprotectedHeader uhdr;
        try
        {
          SCITT_DEBUG("Verify submitted signed statement");
          std::tie(signed_statement_profile, phdr, uhdr) =
            verifier->verify_signed_statement(body, ctx.tx, host_time, cfg);
        }
        catch (const verifier::VerificationError& e)
        {
          SCITT_DEBUG("Signed statement verification failed: {}", e.what());
          throw BadRequestError(errors::InvalidInput, e.what());
        }

        if (cfg.policy.policy_script.has_value())
        {
          const auto policy_violation_reason = check_for_policy_violations(
            cfg.policy.policy_script.value(),
            "configured_policy",
            signed_statement_profile,
            phdr);
          if (policy_violation_reason.has_value())
          {
            SCITT_DEBUG(
              "Policy check failed: {}", policy_violation_reason.value());
            throw BadRequestError(
              errors::PolicyFailed,
              fmt::format(
                "Policy was not met: {}", policy_violation_reason.value()));
          }
          SCITT_DEBUG("Policy check passed");
        }
        else
        {
          if (verifier::contains_cwt_issuer(phdr))
          {
            SCITT_DEBUG("No policy applied, but CWT issuer present");
            throw BadRequestError(
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
        auto entry_table = ctx.tx.template rw<EntryTable>(ENTRY_TABLE);
        entry_table->put(signed_statement);

        SCITT_INFO(
          "SignedStatementProfile={} SignedStatementSizeKb={}",
          signed_statement_profile,
          body.size() / 1024);

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
        .install();

      auto is_tx_committed =
        [this](ccf::View view, ccf::SeqNo seqno, std::string& error_reason) {
          return ccf::historical::is_tx_committed_v2(
            consensus, view, seqno, error_reason);
        };

      static constexpr auto get_entry_path = "/entries/{txid}";
      auto get_entry = [this](
                         EndpointContext& ctx,
                         ccf::historical::StatePtr historical_state) {
        const auto parsed_query =
          ccf::http::parse_query(ctx.rpc_ctx->get_request_query());

        const bool embed_receipt =
          get_query_value<bool>(parsed_query, "embedReceipt").value_or(false);

        SCITT_DEBUG("Get transaction historical state");
        auto historical_tx = historical_state->store->create_read_only_tx();

        auto entries = historical_tx.template ro<EntryTable>(ENTRY_TABLE);
        auto entry = entries->get();
        if (!entry.has_value())
        {
          throw BadRequestError(
            errors::InvalidInput,
            fmt::format(
              "Transaction ID {} does not correspond to a submission.",
              historical_state->transaction_id.to_str()));
        }

        std::vector<uint8_t> entry_out;
        if (embed_receipt)
        {
          SCITT_DEBUG("Get saved SCITT entry");
          auto entry_info_table =
            historical_tx.template ro<EntryInfoTable>(ENTRY_INFO_TABLE);
          auto entry_info = entry_info_table->get().value();

          SCITT_DEBUG("Get CCF receipt");
          auto ccf_receipt_ptr =
            ccf::describe_receipt_v2(*historical_state->receipt);
          std::vector<uint8_t> receipt;
          try
          {
            SCITT_DEBUG("Build SCITT receipt");
            receipt = serialize_receipt(entry_info, ccf_receipt_ptr);

            SCITT_DEBUG("Embed SCITT receipt into the entry response");
            entry_out = cose::embed_receipt(entry.value(), receipt);
          }
          catch (const ReceiptProcessingError& e)
          {
            SCITT_FAIL("Failed to embed receipt: {}", e.what());
            throw InternalError(e.what());
          }
        }
        else
        {
          entry_out = std::move(entry.value());
        }

        ctx.rpc_ctx->set_response_body(entry_out);
        ctx.rpc_ctx->set_response_header(
          ccf::http::headers::CONTENT_TYPE, "application/cose");
      };
      make_endpoint(
        get_entry_path,
        HTTP_GET,
        scitt::historical::adapter(get_entry, state_cache, is_tx_committed),
        authn_policy)
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();

      static constexpr auto get_entry_receipt_path = "/entries/{txid}/receipt";
      auto get_entry_receipt = [this](
                                 EndpointContext& ctx,
                                 ccf::historical::StatePtr historical_state) {
        SCITT_DEBUG("Get transaction historical state");
        auto historical_tx = historical_state->store->create_read_only_tx();

        auto entries = historical_tx.template ro<EntryTable>(ENTRY_TABLE);
        auto entry = entries->get();
        if (!entry.has_value())
        {
          throw BadRequestError(
            errors::InvalidInput,
            fmt::format(
              "Transaction ID {} does not correspond to a submission.",
              historical_state->transaction_id.to_str()));
        }

        SCITT_DEBUG("Get signed statement from the ledger");
        auto cose_receipt = get_cose_receipt(historical_state->receipt);

        ctx.rpc_ctx->set_response_body(cose_receipt);
        ctx.rpc_ctx->set_response_header(
          ccf::http::headers::CONTENT_TYPE,
          ccf::http::headervalues::contenttype::COSE);
      };

      make_endpoint(
        get_entry_receipt_path,
        HTTP_GET,
        scitt::historical::adapter(
          get_entry_receipt, state_cache, is_tx_committed),
        authn_policy)
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();

      static constexpr auto get_entry_statement_path =
        "/entries/{txid}/statement";
      auto get_entry_statement = [this](
                                   EndpointContext& ctx,
                                   ccf::historical::StatePtr historical_state) {
        SCITT_DEBUG("Get transaction historical state");
        auto historical_tx = historical_state->store->create_read_only_tx();

        auto entries = historical_tx.template ro<EntryTable>(ENTRY_TABLE);
        auto entry = entries->get();
        if (!entry.has_value())
        {
          throw BadRequestError(
            errors::InvalidInput,
            fmt::format(
              "Transaction ID {} does not correspond to a submission.",
              historical_state->transaction_id.to_str()));
        }

        auto cose_receipt = get_cose_receipt(historical_state->receipt);

        // See https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/
        // Section 4.4, 394 is the label for an array of receipts in the
        // unprotected header (scitt::cose::COSE_HEADER_PARAM_SCITT_RECEIPTS
        // here)
        const int64_t receipts = scitt::cose::COSE_HEADER_PARAM_SCITT_RECEIPTS;
        ccf::cose::edit::desc::Value receipts_desc{
          ccf::cose::edit::pos::InArray{}, receipts, cose_receipt};

        auto statement =
          ccf::cose::edit::set_unprotected_header(*entry, receipts_desc);

        ctx.rpc_ctx->set_response_body(statement);
        ctx.rpc_ctx->set_response_header(
          ccf::http::headers::CONTENT_TYPE,
          ccf::http::headervalues::contenttype::COSE);
      };

      make_endpoint(
        get_entry_statement_path,
        HTTP_GET,
        scitt::historical::adapter(
          get_entry_statement, state_cache, is_tx_committed),
        authn_policy)
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();

      static constexpr auto get_entries_tx_ids_path = "/entries/txIds";
      auto get_entries_tx_ids =
        [this](EndpointContext& ctx, nlohmann::json&& params) {
          const auto parsed_query =
            ccf::http::parse_query(ctx.rpc_ctx->get_request_query());

          SCITT_DEBUG("Parse input params and determine entries range");
          ccf::SeqNo from_seqno =
            get_query_value<uint64_t>(parsed_query, "from").value_or(1);
          std::optional<ccf::SeqNo> to_seqno_opt =
            get_query_value<uint64_t>(parsed_query, "to");
          ccf::SeqNo to_seqno;

          if (to_seqno_opt.has_value())
          {
            to_seqno = *to_seqno_opt;
          }
          else
          {
            ccf::View view;
            ccf::SeqNo seqno;
            const auto result = get_last_committed_txid_v1(view, seqno);
            if (result != ccf::ApiResult::OK)
            {
              throw InternalError(fmt::format(
                "Failed to get last committed transaction ID: {}",
                ccf::api_result_to_str(result)));
            }
            to_seqno = seqno;
          }

          if (to_seqno < from_seqno)
          {
            throw BadRequestError(
              errors::InvalidInput,
              fmt::format(
                "Invalid range: Starts at {} but ends at {}",
                from_seqno,
                to_seqno));
          }

          const auto tx_status = get_tx_status(to_seqno);
          if (!tx_status.has_value())
          {
            throw InternalError(fmt::format(
              "Failed to get transaction status for seqno {}", to_seqno));
          }

          if (tx_status.value() != ccf::TxStatus::Committed)
          {
            throw BadRequestError(
              errors::InvalidInput,
              fmt::format(
                "Only committed transactions can be queried. Transaction at "
                "seqno {} is {}",
                to_seqno,
                ccf::tx_status_to_str(tx_status.value())));
          }

          const auto indexed_txid = entry_seqno_index->get_indexed_watermark();
          if (indexed_txid.seqno < to_seqno)
          {
            throw ServiceUnavailableError(
              errors::IndexingInProgressRetryLater,
              "Index of requested range not available yet, retry later");
          }

          static constexpr size_t max_seqno_per_page = 10000;
          const auto range_begin = from_seqno;
          const auto range_end =
            std::min(to_seqno, range_begin + max_seqno_per_page);

          const auto interesting_seqnos =
            entry_seqno_index->get_write_txs_in_range(range_begin, range_end);
          if (!interesting_seqnos.has_value())
          {
            throw ServiceUnavailableError(
              errors::IndexingInProgressRetryLater,
              "Index of requested range not available yet, retry later");
          }

          SCITT_DEBUG("Get entries for the target range");
          std::vector<std::string> tx_ids;
          for (auto seqno : interesting_seqnos.value())
          {
            ccf::View view;
            auto result = get_view_for_seqno_v1(seqno, view);
            if (result != ccf::ApiResult::OK)
            {
              throw InternalError(fmt::format(
                "Failed to get view for seqno: {}",
                ccf::api_result_to_str(result)));
            }
            auto tx_id = ccf::TxID{view, seqno}.to_str();
            tx_ids.push_back(tx_id);
          }

          GetEntriesTransactionIds::Out out;
          out.transaction_ids = std::move(tx_ids);

          // If this didn't cover the total requested range, begin fetching the
          // next page and tell the caller how to retrieve it
          if (range_end != to_seqno)
          {
            SCITT_DEBUG("Add next link to retrieve the rest of entries");
            const auto next_page_start = range_end + 1;
            const auto next_range_end =
              std::min(to_seqno, next_page_start + max_seqno_per_page);
            entry_seqno_index->get_write_txs_in_range(
              next_page_start, next_range_end);
            // NB: This path tells the caller to continue to ask until the end
            // of the range, even if the next response is paginated
            out.next_link = fmt::format(
              "/entries/txIds?from={}&to={}", next_page_start, to_seqno);
          }

          return out;
        };

      make_endpoint(
        get_entries_tx_ids_path,
        HTTP_GET,
        ccf::json_adapter(get_entries_tx_ids),
        authn_policy)
        .set_auto_schema<void, GetEntriesTransactionIds::Out>()
        .add_query_parameter<size_t>(
          "from", ccf::endpoints::QueryParamPresence::OptionalParameter)
        .add_query_parameter<size_t>(
          "to", ccf::endpoints::QueryParamPresence::OptionalParameter)
        .install();

      static constexpr auto get_issuers_path = "/did";
      auto get_issuers = [this](EndpointContext& ctx, nlohmann::json&& params) {
        auto issuers = ctx.tx.template ro<IssuersTable>(ISSUERS_TABLE);

        GetIssuers::Out out;

        issuers->foreach_key([&out](const auto& issuer) {
          out.issuers.push_back(issuer);
          return true;
        });

        return out;
      };
      make_endpoint(
        get_issuers_path,
        HTTP_GET,
        ccf::json_adapter(get_issuers),
        authn_policy)
        .install();

      static constexpr auto get_issuer_info_path = "/did/{did}";
      auto get_issuer_info =
        [this](EndpointContext& ctx, nlohmann::json&& params) {
          auto issuers = ctx.tx.template ro<IssuersTable>(ISSUERS_TABLE);

          auto issuer = ctx.rpc_ctx->get_request_path_params().at("did");

          auto issuer_info = issuers->get(issuer);
          if (!issuer_info.has_value())
          {
            throw BadRequestError(
              errors::InvalidInput,
              fmt::format("Issuer {} does not exist.", issuer));
          }

          GetIssuerInfo::Out out;
          out = issuer_info.value();
          return out;
        };
      make_endpoint(
        get_issuer_info_path,
        HTTP_GET,
        ccf::json_adapter(get_issuer_info),
        authn_policy)
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
