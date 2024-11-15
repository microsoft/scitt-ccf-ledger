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

  struct DIDFetchContext
  {
    std::vector<uint8_t> body;
    std::string nonce;
    std::string issuer;
  };
  DECLARE_JSON_TYPE(DIDFetchContext);
  DECLARE_JSON_REQUIRED_FIELDS(DIDFetchContext, body, nonce, issuer);

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

      auto post_entry = [this](EndpointContext& ctx) {
        auto& body = ctx.rpc_ctx->get_request_body();
        SCITT_DEBUG("Entry body size: {} bytes", body.size());
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

        SCITT_DEBUG("Get SCITT configuration from KV store");
        auto cfg = ctx.tx.template ro<ConfigurationTable>(CONFIGURATION_TABLE)
                     ->get()
                     .value_or(Configuration{});

        ClaimProfile claim_profile;
        cose::ProtectedHeader phdr;
        cose::UnprotectedHeader uhdr;
        try
        {
          SCITT_DEBUG("Verify submitted claim");
          std::tie(claim_profile, phdr, uhdr) = verifier->verify_claim(
            body, ctx.tx, host_time, DID_RESOLUTION_CACHE_EXPIRY, cfg);
        }
        catch (const verifier::VerificationError& e)
        {
          SCITT_DEBUG("Claim verification failed: {}", e.what());
          throw BadRequestError(errors::InvalidInput, e.what());
        }
        // Retrieve current enclave measurement of this node
        // See ccf logic in `/quotes/self`
        std::string measurement;
        auto nodes = ctx.tx.ro<ccf::Nodes>(ccf::Tables::NODES);
        auto node_info = nodes->get(context.get_node_id());
        if (node_info.has_value() && node_info->code_digest.has_value())
        {
          measurement = node_info->code_digest.value();
        }
        else
        {
#if defined(INSIDE_ENCLAVE) && !defined(VIRTUAL_ENCLAVE)
          // Node should always get a valid cached measurement on startup
          throw InternalError("Unexpected state - node has no code id");
#else
          measurement =
            "0000000000000000000000000000000000000000000000000000000000000000";
#endif
        }

        if (cfg.policy.policy_script.has_value())
        {
          const auto policy_violation_reason = check_for_policy_violations(
            cfg.policy.policy_script.value(),
            "configured_policy",
            claim_profile,
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

        auto service = ctx.tx.template ro<ccf::Service>(ccf::Tables::SERVICE);
        auto service_info = service->get().value();
        auto service_cert = service_info.cert;
        auto service_cert_der = ccf::crypto::cert_pem_to_der(service_cert);
        auto service_cert_digest =
          ccf::crypto::Sha256Hash(service_cert_der).hex_str();

        // Take the service's DID from the configuration, if present.
        SCITT_DEBUG("Create protected header with countersignature");
        std::vector<uint8_t> sign_protected;
        if (cfg.service_identifier.has_value())
        {
          // The kid is the same as the service certificate hash (prefixed with
          // a # to make it a relative DID-url). Eventually, this may change to
          // become eg. an RFC7638 JWK thumbprint.
          std::string kid = fmt::format("#{}", service_cert_digest);
          std::span<const uint8_t> kid_bytes(
            reinterpret_cast<const uint8_t*>(kid.data()), kid.size());

          sign_protected = create_countersign_protected_header(
            host_time,
            *cfg.service_identifier,
            kid_bytes,
            service_cert_digest,
            measurement);
        }
        else
        {
          sign_protected = create_countersign_protected_header(
            host_time,
            std::nullopt,
            std::nullopt,
            service_cert_digest,
            measurement);
        }

        // Compute the hash of the to-be-signed countersigning structure
        // and set it as CCF transaction claim for use in receipt validation.
        SCITT_DEBUG("Add countersignature as CCF application claim for the tx");
        auto claims_digest =
          cose::create_countersign_tbs_hash(body, sign_protected);
        ctx.rpc_ctx->set_claims_digest(std::move(claims_digest));

        // Store the original COSE_Sign1 message in the KV.
        SCITT_DEBUG("Store submitted claim in KV store");
        auto entry_table = ctx.tx.template rw<EntryTable>(ENTRY_TABLE);
        entry_table->put(body);

        // Store the protected headers in a separate table, so the
        // receipt can be reconstructed.
        SCITT_DEBUG("Store claim protected headers in KV store");
        auto entry_info_table =
          ctx.tx.template rw<EntryInfoTable>(ENTRY_INFO_TABLE);
        entry_info_table->put(EntryInfo{
          .sign_protected = sign_protected,
        });

        SCITT_INFO(
          "ClaimProfile={} ClaimSizeKb={}", claim_profile, body.size() / 1024);

        SCITT_DEBUG("Claim was submitted synchronously");
      };

      make_endpoint("/entries", HTTP_POST, post_entry, authn_policy).install();

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

        bool embed_receipt =
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
        }
        catch (const ReceiptProcessingError& e)
        {
          throw InternalError(e.what());
        }
        ctx.rpc_ctx->set_response_body(receipt);
        ctx.rpc_ctx->set_response_header(
          ccf::http::headers::CONTENT_TYPE, "application/cbor");
      };

      make_endpoint(
        get_entry_receipt_path,
        HTTP_GET,
        scitt::historical::adapter(
          get_entry_receipt, state_cache, is_tx_committed),
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
