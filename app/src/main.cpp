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
#include "receipt.h"
#include "tracing.h"
#include "util.h"
#include "verifier.h"

#ifdef VIRTUAL_ENCLAVE
#  include "did/unattested.h"
#else
#  include "did/attested.h"
#endif

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
    const http::ParsedQuery& pq, std::string_view name)
  {
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
      static_assert(nonstd::dependent_false<T>::value, "Unsupported type");
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
      ccf::ApiResult result;

      ccf::View view_of_seqno;
      result = get_view_for_seqno_v1(seqno, view_of_seqno);
      if (result == ccf::ApiResult::OK)
      {
        ccf::TxStatus status;
        result = get_status_for_txid_v1(view_of_seqno, seqno, status);
        if (result == ccf::ApiResult::OK)
        {
          return status;
        }
      }

      return std::nullopt;
    }

  public:
    AppEndpoints(ccfapp::AbstractNodeContext& context_) :
      ccf::UserEndpointRegistry(context_)
    {
      const ccf::AuthnPolicies no_authn_policy = {ccf::empty_auth_policy};
      const ccf::AuthnPolicies authn_policy = {
        std::make_shared<ConfigurableEmptyAuthnPolicy>(),
        std::make_shared<ConfigurableJwtAuthnPolicy>(),
      };

      auto& state_cache = context.get_historical_state();

      entry_seqno_index = std::make_shared<EntrySeqnoIndexingStrategy>(
        ENTRY_TABLE, context, 10000, 20);
      context.get_indexing_strategies().install_strategy(entry_seqno_index);

      auto resolver = std::make_unique<did::UniversalResolver>();
      resolver->register_resolver(
        std::make_unique<did::web::DidWebResolver>(context));

      verifier = std::make_unique<verifier::Verifier>(std::move(resolver));

      timespec untrusted_host_time;
      const auto result = get_untrusted_host_time_v1(untrusted_host_time);
      if (result == ccf::ApiResult::OK)
      {
        srand(untrusted_host_time.tv_sec);
      }

      std::function<ccf::ApiResult(timespec & time)> get_time =
        [this](timespec& time) {
          return this->get_untrusted_host_time_v1(time);
        };

      static constexpr auto post_entry_path = "/entries";
      auto post_entry = [this](EndpointContext& ctx) {
        auto& body = ctx.rpc_ctx->get_request_body();
        if (body.size() > MAX_ENTRY_SIZE_BYTES)
        {
          throw BadRequestError(
            errors::PayloadTooLarge,
            fmt::format(
              "Entry size {} exceeds maximum allowed size {}",
              body.size(),
              MAX_ENTRY_SIZE_BYTES));
        }

        ::timespec time;
        auto result = this->get_untrusted_host_time_v1(time);
        if (result != ccf::ApiResult::OK)
        {
          throw InternalError(fmt::format(
            "Failed to get host time: {}", ccf::api_result_to_str(result)));
        }

        // Asynchronous DID resolution responds with 5xx HTTP status which would
        // prevent writing to the KV by default.
        ctx.rpc_ctx->set_apply_writes(true);

        auto cfg = ctx.tx.template ro<ConfigurationTable>(CONFIGURATION_TABLE)
                     ->get()
                     .value_or(Configuration{});

        try
        {
          verifier->verify_claim(
            body, ctx.tx, time, DID_RESOLUTION_CACHE_EXPIRY, cfg);
        }
        catch (const did::DIDMethodNotSupportedError& e)
        {
          throw BadRequestError(errors::DIDMethodNotSupported, e.what());
        }
        catch (const did::AsyncResolutionInProgress& e)
        {
          throw ServiceUnavailableError(
            errors::DIDResolutionInProgressRetryLater, e.what(), 5);
        }
        catch (const verifier::VerificationError& e)
        {
          throw BadRequestError(errors::InvalidInput, e.what());
        }

        // TODO: Apply further acceptance policies.

        auto service = ctx.tx.template ro<ccf::Service>(ccf::Tables::SERVICE);
        auto service_info = service->get().value();
        auto service_cert = service_info.cert;
        auto service_cert_der = crypto::cert_pem_to_der(service_cert);
        auto service_cert_digest =
          crypto::Sha256Hash(service_cert_der).hex_str();

        // Take the service's DID from the configuration, if present. For the
        // time being, the kid is the same as the service certificate hash.
        // Eventually, this may change to become eg. an RFC7638 JWK thumbprint.
        std::vector<uint8_t> sign_protected;
        if (cfg.service_identifier.has_value())
        {
          // TODO: clarify the format of KID. We currently use the hex digest,
          // encoded in ASCII. Since the COSE field is a bstr, we could skip the
          // hex/ASCII encoding part of it and embed the digest directly, but
          // this would not be valid as-is in the corresponding JWK.
          std::span<const uint8_t> kid = {
            reinterpret_cast<const uint8_t*>(service_cert_digest.data()),
            service_cert_digest.size(),
          };

          sign_protected = create_countersign_protected_header(
            time, *cfg.service_identifier, kid, service_cert_digest);
        }
        else
        {
          sign_protected = create_countersign_protected_header(
            time, std::nullopt, std::nullopt, service_cert_digest);
        }

        // Compute the hash of the to-be-signed countersigning structure
        // and set it as CCF transaction claim for use in receipt validation.
        auto claims_digest =
          cose::create_countersign_tbs_hash(body, sign_protected);
        ctx.rpc_ctx->set_claims_digest(std::move(claims_digest));

        // Store the original COSE_Sign1 message in the KV.
        auto entry_table = ctx.tx.template rw<EntryTable>(ENTRY_TABLE);
        entry_table->put(body);

        // Store the protected headers in a separate table, so the
        // receipt can be reconstructed.
        auto entry_info_table =
          ctx.tx.template rw<EntryInfoTable>(ENTRY_INFO_TABLE);
        entry_info_table->put(EntryInfo{
          .sign_protected = sign_protected,
        });

        ctx.rpc_ctx->set_response_status(HTTP_STATUS_CREATED);
      };

      make_endpoint(
        post_entry_path,
        HTTP_POST,
        tracing_adapter(error_adapter(post_entry), get_time),
        authn_policy)
        .install();

      auto is_tx_committed =
        [this](ccf::View view, ccf::SeqNo seqno, std::string& error_reason) {
          return ccf::historical::is_tx_committed_v2(
            consensus, view, seqno, error_reason);
        };

      auto get_tx_id_from_request_path = [](EndpointContext& ctx) {
        auto tx_id_str = ctx.rpc_ctx->get_request_path_params().at("txid");
        const auto tx_id_opt = ccf::TxID::from_str(tx_id_str);
        if (!tx_id_opt.has_value())
        {
          throw BadRequestError(
            errors::InvalidInput,
            fmt::format("Invalid transaction ID: {}", tx_id_str));
        }
        return tx_id_opt;
      };

      static constexpr auto get_entry_path = "/entries/{txid}";
      auto get_entry = [this](
                         EndpointContext& ctx,
                         ccf::historical::StatePtr historical_state) {
        const auto parsed_query =
          http::parse_query(ctx.rpc_ctx->get_request_query());

        bool embed_receipt =
          get_query_value<bool>(parsed_query, "embedReceipt").value_or(false);

        auto historical_tx = historical_state->store->create_read_only_tx();

        auto entries = historical_tx.template ro<EntryTable>(ENTRY_TABLE);
        auto entry = entries->get();
        if (!entry.has_value())
        {
          auto tx_id = ctx.rpc_ctx->get_request_path_params().at("txid");
          throw BadRequestError(
            errors::InvalidInput,
            fmt::format(
              "Transaction ID {} does not correspond to a submission.", tx_id));
        }

        std::vector<uint8_t> entry_out;
        if (embed_receipt)
        {
          auto entry_info_table =
            historical_tx.template ro<EntryInfoTable>(ENTRY_INFO_TABLE);
          auto entry_info = entry_info_table->get().value();

          auto ccf_receipt_ptr =
            ccf::describe_receipt_v2(*historical_state->receipt);
          std::vector<uint8_t> receipt;
          try
          {
            receipt = serialize_receipt(entry_info, ccf_receipt_ptr);
          }
          catch (const ReceiptProcessingError& e)
          {
            throw InternalError(e.what());
          }
          entry_out = cose::embed_receipt(entry.value(), receipt);
        }
        else
        {
          entry_out = std::move(entry.value());
        }

        ctx.rpc_ctx->set_response_body(entry_out);
        ctx.rpc_ctx->set_response_header(
          http::headers::CONTENT_TYPE, "application/cose");
      };
      make_endpoint(
        get_entry_path,
        HTTP_GET,
        tracing_adapter(
          error_adapter(scitt::historical::adapter(
            get_entry,
            state_cache,
            is_tx_committed,
            get_tx_id_from_request_path)),
          get_time),
        authn_policy)
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();

      static constexpr auto get_entry_receipt_path = "/entries/{txid}/receipt";
      auto get_entry_receipt = [this](
                                 EndpointContext& ctx,
                                 ccf::historical::StatePtr historical_state) {
        auto historical_tx = historical_state->store->create_read_only_tx();

        auto entries = historical_tx.template ro<EntryTable>(ENTRY_TABLE);
        auto entry = entries->get();
        if (!entry.has_value())
        {
          auto tx_id = ctx.rpc_ctx->get_request_path_params().at("txid");
          throw BadRequestError(
            errors::InvalidInput,
            fmt::format(
              "Transaction ID {} does not correspond to a submission.", tx_id));
        }

        auto entry_info_table =
          historical_tx.template ro<EntryInfoTable>(ENTRY_INFO_TABLE);
        auto entry_info = entry_info_table->get().value();

        auto ccf_receipt_ptr =
          ccf::describe_receipt_v2(*historical_state->receipt);
        std::vector<uint8_t> receipt;
        try
        {
          receipt = serialize_receipt(entry_info, ccf_receipt_ptr);
        }
        catch (const ReceiptProcessingError& e)
        {
          throw InternalError(e.what());
        }
        ctx.rpc_ctx->set_response_body(receipt);
        ctx.rpc_ctx->set_response_header(
          http::headers::CONTENT_TYPE, "application/cbor");
      };

      make_endpoint(
        get_entry_receipt_path,
        HTTP_GET,
        tracing_adapter(
          error_adapter(scitt::historical::adapter(
            get_entry_receipt,
            state_cache,
            is_tx_committed,
            get_tx_id_from_request_path)),
          get_time),
        authn_policy)
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();

      static constexpr auto get_entries_tx_ids_path = "/entries/txIds";
      auto get_entries_tx_ids =
        [this](EndpointContext& ctx, nlohmann::json&& params) {
          const auto parsed_query =
            http::parse_query(ctx.rpc_ctx->get_request_query());

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
        tracing_adapter(
          error_adapter(ccf::json_adapter(get_entries_tx_ids)), get_time),
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
        tracing_adapter(
          error_adapter(ccf::json_adapter(get_issuers)), get_time),
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
        tracing_adapter(
          error_adapter(ccf::json_adapter(get_issuer_info)), get_time),
        authn_policy)
        .install();

      static constexpr auto update_did_doc_path = "/did/{did}/doc";
      auto update_did_doc = [this](
                              EndpointContext& ctx, nlohmann::json&& params) {
        const auto in = params.get<PostDidResolution::In>();

        auto issuers = ctx.tx.template rw<IssuersTable>(ISSUERS_TABLE);

        // Retrieve host time.
        ::timespec host_time;
        auto result = get_untrusted_host_time_v1(host_time);
        if (result != ccf::ApiResult::OK)
        {
          throw InternalError(
            fmt::format("Failed to retrieve host time: {}", result));
        }

        // Get issuer from URL path parameter.
        auto issuer = ctx.rpc_ctx->get_request_path_params().at("did");

        // Check whether the issuer exists.
        auto issuer_info = issuers->get(issuer);
        if (!issuer_info.has_value())
        {
          throw BadRequestError(
            errors::InvalidInput,
            fmt::format("Issuer {} does not exist.", issuer));
        }

        // Check whether a fresh DID resolution request exists for the issuer.
        // Note: The resolution nonce is checked during verification below.
        if (!issuer_info->resolution_requested.has_value())
        {
          throw BadRequestError(
            errors::InvalidInput,
            fmt::format(
              "No DID resolution request found for issuer {}", issuer));
        }
        if (
          host_time.tv_sec - issuer_info->resolution_requested.value_or(0) >
          DID_RESOLUTION_REQUEST_EXPIRY.count())
        {
          throw BadRequestError(
            errors::InvalidInput,
            fmt::format(
              "DID resolution request for issuer {} has expired", issuer));
        }

        auto& nonce = issuer_info->resolution_nonce.value();

#ifdef VIRTUAL_ENCLAVE
        auto resolution = did::verify_unattested_resolution(issuer, nonce, in);
#else
        auto ca_cert_bundles = ctx.tx.template ro<ccf::CACertBundlePEMs>(
          ccf::Tables::CA_CERT_BUNDLE_PEMS);
        auto resolution =
          did::verify_attested_resolution(issuer, nonce, ca_cert_bundles, in);
#endif
        resolution.resolution_metadata.updated = host_time.tv_sec;

        issuer_info->resolution_requested = std::nullopt;
        issuer_info->resolution_nonce = std::nullopt;
        issuer_info->did_document = std::move(resolution.did_doc);
        issuer_info->did_resolution_metadata =
          std::move(resolution.resolution_metadata);

        issuers->put(issuer, issuer_info.value());
        SCITT_INFO(fmt::format("Updated DID document for issuer {}", issuer));

        return ccf::make_success();
      };

      make_endpoint(
        update_did_doc_path,
        HTTP_POST,
        tracing_adapter(
          error_adapter(ccf::json_adapter(update_did_doc)), get_time),
        no_authn_policy)
        .set_auto_schema<PostDidResolution::In, void>()
        .install();

      static constexpr auto get_ca_certs_path = "/ca_certs";
      auto get_ca_certs = [this](
                            EndpointContext& ctx, nlohmann::json&& params) {
        auto ca_cert_bundles = ctx.tx.template ro<ccf::CACertBundlePEMs>(
          ccf::Tables::CA_CERT_BUNDLE_PEMS);

        std::map<std::string, std::string> out;

        ca_cert_bundles->foreach([&out](const auto& name, const auto& bundle) {
          out.emplace(name, bundle);
          return true;
        });

        return out;
      };
      make_endpoint(
        get_ca_certs_path,
        HTTP_GET,
        tracing_adapter(
          error_adapter(ccf::json_adapter(get_ca_certs)), get_time),
        no_authn_policy)
        .install();

      auto service_info_to_parameters =
        [](const ccf::ServiceInfo& service_info) {
          auto service_cert_pem = service_info.cert;
          auto service_cert_der = crypto::cert_pem_to_der(service_cert_pem);
          auto service_cert_der_b64 = crypto::b64_from_raw(service_cert_der);

          auto service_id = crypto::Sha256Hash(service_cert_der).hex_str();

          // TODO: extend to support multiple tree hash algorithms once CCF
          // supports them

          GetServiceParameters::Out out;
          out.service_id = service_id;
          out.tree_algorithm = TREE_ALGORITHM_CCF;
          out.signature_algorithm = JOSE_ALGORITHM_ES256;
          out.service_certificate = service_cert_der_b64;
          return out;
        };

      static constexpr auto get_service_parameters_path = "/parameters";
      auto get_service_parameters =
        [&](EndpointContext& ctx, nlohmann::json&& params) {
          auto service = ctx.tx.template ro<ccf::Service>(ccf::Tables::SERVICE);
          auto service_info = service->get().value();
          GetServiceParameters::Out out =
            service_info_to_parameters(service_info);
          return out;
        };

      make_endpoint(
        get_service_parameters_path,
        HTTP_GET,
        tracing_adapter(
          error_adapter(ccf::json_adapter(get_service_parameters)), get_time),
        no_authn_policy)
        .set_auto_schema<void, GetServiceParameters::Out>()
        .install();

      static constexpr auto get_historic_service_parameters_path =
        "/parameters/historic";
      auto get_historic_service_parameters =
        [&](EndpointContext& ctx, nlohmann::json&& params) {
          auto& state_cache = context.get_historical_state();
          auto service = ctx.tx.template ro<ccf::Service>(ccf::Tables::SERVICE);

          GetHistoricServiceParameters::Out out;

          ccf::ServiceInfo hservice_info = service->get().value();
          out.parameters.push_back(service_info_to_parameters(hservice_info));

          ccf::SeqNo i = -1;
          while (true)
          {
            if (!hservice_info.previous_service_identity_version)
            {
              break;
            }
            i = hservice_info.previous_service_identity_version.value();
            CCF_APP_TRACE("historical service identity search at: {}", i);
            auto hstate = state_cache.get_state_at(i, i);
            if (!hstate)
            {
              throw ServiceUnavailableError(
                errors::IndexingInProgressRetryLater,
                fmt::format("Historical data is not ready yet (seq: {})", 1));
            }
            auto htx = hstate->store->create_read_only_tx();
            auto hservice = htx.ro<ccf::Service>(ccf::Tables::SERVICE);
            hservice_info = hservice->get().value();
            out.parameters.push_back(service_info_to_parameters(hservice_info));
          }

          return out;
        };

      make_endpoint(
        get_historic_service_parameters_path,
        HTTP_GET,
        tracing_adapter(
          error_adapter(ccf::json_adapter(get_historic_service_parameters)),
          get_time),
        no_authn_policy)
        .set_auto_schema<void, GetHistoricServiceParameters::Out>()
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();

      static constexpr auto get_configuration_path = "/configuration";
      auto get_configuration =
        [&](EndpointContext& ctx, nlohmann::json&& params) {
          return ctx.tx.template ro<ConfigurationTable>(CONFIGURATION_TABLE)
            ->get()
            .value_or(Configuration{});
        };
      make_endpoint(
        get_configuration_path,
        HTTP_GET,
        tracing_adapter(
          error_adapter(ccf::json_adapter(get_configuration)), get_time),
        no_authn_policy)
        .set_auto_schema<void, Configuration>()
        .install();

      static constexpr auto get_version_path = "/version";
      auto get_version = [this](EndpointContext& ctx, nlohmann::json&& params) {
        GetVersion::Out out;

        out.scitt_version = SCITT_VERSION;

        return out;
      };

      make_endpoint(
        get_version_path,
        HTTP_GET,
        tracing_adapter(
          error_adapter(ccf::json_adapter(get_version)), get_time),
        no_authn_policy)
        .set_auto_schema<void, GetVersion::Out>()
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();

#ifdef ENABLE_PREFIX_TREE
      // TODO add tracing_adapter() to all endpoints
      PrefixTreeFrontend::init_handlers(context, *this);
#endif
    }
  };
} // namespace scitt

namespace ccfapp
{
  std::unique_ptr<ccf::endpoints::EndpointRegistry> make_user_endpoints(
    ccfapp::AbstractNodeContext& context)
  {
    return std::make_unique<scitt::AppEndpoints>(context);
  }
} // namespace ccfapp
