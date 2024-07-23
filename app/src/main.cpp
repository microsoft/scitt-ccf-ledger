// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "call_types.h"
#include "configurable_auth.h"
#include "constants.h"
#include "cose.h"
#include "did/document.h"
#include "did/resolver.h"
#include "did/web/method.h"
#include "generated/constants.h"
#include "historical/historical_queries_adapter.h"
#include "http_error.h"
#include "kv_types.h"
#include "operations_endpoints.h"
#include "receipt.h"
#include "service_endpoints.h"
#include "tracing.h"
#include "util.h"
#include "verifier.h"

#ifdef ENABLE_PREFIX_TREE
#  include "prefix_tree/frontend.h"
#endif

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
#include <ccf/js/core/context.h>
#include <ccf/js/extensions/console.h>
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

static constexpr auto sample_js_policy = R"!!!(
const x = 2;
const y = 3;
console.log(`x = ${x}, y = ${y}`);
console.log(`x+y = ${x+y}`);
)!!!";

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

    void apply_js_policy()
    {
      auto interpreter = ccf::js::core::Context(ccf::js::TxAccess::APP_RO);
      interpreter.add_extension(
        std::make_shared<ccf::js::extensions::ConsoleExtension>());

      SCITT_INFO("About to eval");

      auto val = interpreter.eval(
        sample_js_policy,
        strlen(sample_js_policy),
        "sample",
        JS_EVAL_TYPE_GLOBAL);

      SCITT_INFO("Called eval");

      if (val.is_error())
      {
        SCITT_INFO("Result of eval is an error");
      }
      else if (val.is_exception())
      {
        SCITT_INFO("Result of eval is an exception");
        auto [reason, trace] = interpreter.error_message();
        SCITT_INFO("Reason: {}", reason);
        SCITT_INFO("Trace: {}", trace.value_or("<no trace>"));
      }
      else if (val.is_undefined())
      {
        SCITT_INFO("Result of eval is undefined");
      }
      else if (val.is_str())
      {
        SCITT_INFO("Result of eval is string");
        SCITT_INFO("Result: {}", interpreter.to_str(val));
      }
      else
      {
        SCITT_INFO("Result of eval is some other value");
      }
    }

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
      std::function<ccf::ApiResult(timespec & time)> get_time =
        [this](timespec& time) {
          return this->get_untrusted_host_time_v1(time);
        };

      auto endpoint = ccf::UserEndpointRegistry::make_endpoint(
        method, verb, tracing_adapter(error_adapter(f), method, get_time), ap);
      endpoint.locally_committed_func =
        tracing_local_commit_adapter(l, method, get_time);
      return endpoint;
    }

    /**
     * This function is called from two different contexts:
     * - When a client makes a POST /entries. This may raise a
     *   did::AsyncResolutionNeeded exception (as part of verification), in
     *   which case the caller triggers an asynchronous resolution.
     *
     * - A second time, with the same payload, when the asynchronous resolution
     *   completes and the attested-fetch script calls the
     *   /operations/<id>/callback endpoint.
     */
    void post_entry_common(
      EndpointContext& ctx,
      ::timespec host_time,
      const std::vector<uint8_t>& body)
    {
      SCITT_DEBUG("Get SCITT configuration from KV store");
      auto cfg = ctx.tx.template ro<ConfigurationTable>(CONFIGURATION_TABLE)
                   ->get()
                   .value_or(Configuration{});

      ClaimProfile claim_profile;
      try
      {
        SCITT_DEBUG("Verify submitted claim");
        claim_profile = verifier->verify_claim(
          body, ctx.tx, host_time, DID_RESOLUTION_CACHE_EXPIRY, cfg);
      }
      catch (const did::DIDMethodNotSupportedError& e)
      {
        SCITT_DEBUG("Unsupported DID method: {}", e.what());
        throw BadRequestError(errors::DIDMethodNotSupported, e.what());
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

      // TODO: Apply further acceptance policies.
      apply_js_policy();

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
    }

    /**
     * Start an asynchronous claim registration, by triggering a DID resolution
     * for the specified issuer. When the resolution completes, the claim will
     * be registered on the ledger.
     *
     * This works by creating an asynchronous operation with a callback, and
     * starting an external subprocess to do the actual resolution. When the
     * subprocess completes, it invokes the callback URL with the result.
     * Additionally, the subprocess carries a context bytestring which we use to
     * carry over some data.
     */
    void start_asynchronous_registration(
      EndpointContext& ctx,
      timespec host_time,
      const std::string& issuer,
      const std::vector<uint8_t>& body)
    {
      auto nonce = ccf::ds::to_hex(ENTROPY->random(16));

      DIDFetchContext callback_context{
        .body = body,
        .nonce = nonce,
        .issuer = issuer,
      };
      std::string context_json = nlohmann::json(callback_context).dump();
      std::vector<uint8_t> context_bytes(
        context_json.begin(), context_json.end());
      ccf::crypto::Sha256Hash context_digest(context_bytes);

      auto trigger =
        [this, issuer, nonce, context_bytes](const std::string& callback_url) {
          SCITT_INFO(
            "Triggering asynchronous DID fetch for {}, callback {}",
            issuer,
            callback_url);

          did::web::DidWebResolver::trigger_asynchronous_resolution(
            context, callback_url, context_bytes, issuer, nonce);
        };

      start_asynchronous_operation(
        host_time, context, ctx, context_digest, trigger);
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

      SCITT_DEBUG("Register DID:web resolver");
      auto resolver = std::make_unique<did::UniversalResolver>();
      resolver->register_resolver(std::make_unique<did::web::DidWebResolver>());

      verifier = std::make_unique<verifier::Verifier>(std::move(resolver));

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

        try
        {
          post_entry_common(ctx, host_time, body);
        }
        catch (const did::web::AsyncResolutionNeeded& e)
        {
          start_asynchronous_registration(ctx, host_time, e.did, body);
          return;
        }

        SCITT_DEBUG("Claim was submitted synchronously");
        record_synchronous_operation(host_time, ctx.tx);
      };

      auto post_entry_continuation =
        [this](
          EndpointContext& ctx,
          nlohmann::json callback_context,
          std::optional<nlohmann::json> callback_result) {
          auto post_entry_context = callback_context.get<DIDFetchContext>();

          ::timespec host_time;
          auto result = get_untrusted_host_time_v1(host_time);
          if (result != ccf::ApiResult::OK)
          {
            throw InternalError(
              fmt::format("Failed to retrieve host time: {}", result));
          }

          if (callback_result.has_value())
          {
            auto resolution = callback_result->get<did::AttestedResolution>();
            SCITT_INFO(
              "Updating DID document for {}", post_entry_context.issuer);
            did::web::DidWebResolver::update_did_document(
              host_time,
              ctx.tx,
              resolution,
              post_entry_context.issuer,
              post_entry_context.nonce);
          }

          // We intentionally don't catch AsyncResolutionNeeded this time
          // around. If resolution fails despite the updated DID document then
          // the exception will lead to the operation failing, and the
          // exception's message will be stored in the KV.
          post_entry_common(ctx, host_time, post_entry_context.body);
        };

      make_endpoint_with_local_commit_handler(
        "/entries",
        HTTP_POST,
        post_entry,
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
      register_operations_endpoints(
        context, *this, authn_policy, post_entry_continuation);

#ifdef ENABLE_PREFIX_TREE
      PrefixTreeFrontend::init_handlers(context, *this);
#endif
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
