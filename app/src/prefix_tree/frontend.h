// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "prefix_tree/indexing_strategy.h"
#include "prefix_tree/read_receipt.h"

#include <ccf/app_interface.h>
#include <ccf/common_auth_policies.h>
#include <ccf/endpoint.h>
#include <ccf/endpoint_registry.h>
#include <ccf/json_handler.h>
#include <ccf/service/tables/service.h>

namespace scitt
{
  /**
   * Create an std::function that takes shared ownership of its receiver, and
   * calls a method on it.
   *
   * In C++20 this is equivalent to std::bind_front, but that doesn't seem
   * available yet.
   */
  template <typename R, typename T, typename... Args>
  std::function<R(Args...)> bind_shared_ptr(
    std::shared_ptr<T> self, R (T::*f)(Args...))
  {
    return [f, self = std::move(self)](Args&&... args) {
      return (self.get()->*f)(std::forward<Args>(args)...);
    };
  }

  class PrefixTreeFrontend
  {
  public:
    static void init_handlers(
      ccfapp::AbstractNodeContext& context, ccf::BaseEndpointRegistry& registry)
    {
      auto self = std::make_shared<PrefixTreeFrontend>(context, registry);
      const ccf::AuthnPolicies no_authn_policy = {ccf::empty_auth_policy};

      registry
        .make_read_only_endpoint(
          "/prefix_tree",
          HTTP_GET,
          error_read_only_adapter(
            bind_shared_ptr(self, &PrefixTreeFrontend::current)),
          no_authn_policy)
        .install();

      registry
        .make_command_endpoint(
          "/prefix_tree/debug",
          HTTP_GET,
          error_command_adapter(ccf::json_command_adapter(
            bind_shared_ptr(self, &PrefixTreeFrontend::debug))),
          no_authn_policy)
        .install();

      registry
        .make_endpoint(
          "/prefix_tree/flush",
          HTTP_POST,
          error_adapter(ccf::json_adapter(
            bind_shared_ptr(self, &PrefixTreeFrontend::flush))),
          no_authn_policy)
        .install();

      registry
        .make_read_only_endpoint(
          "/read_receipt/{issuer}/{feed}",
          HTTP_GET,
          error_read_only_adapter(
            bind_shared_ptr(self, &PrefixTreeFrontend::get)),
          no_authn_policy)
        .install();
    }

    // This is only public to allow make_shared to work.
    // In practice, init_handlers should be used instead.
    PrefixTreeFrontend(
      ccfapp::AbstractNodeContext& context,
      ccf::BaseEndpointRegistry& registry) :
      context(context),
      registry(registry),
      index(std::make_shared<PrefixTreeIndexingStrategy>())
    {
      context.get_indexing_strategies().install_strategy(index);
    }

  private:
    void get(ccf::endpoints::ReadOnlyEndpointContext& ctx)
    {
      auto issuer = ctx.rpc_ctx->get_request_path_params().at("issuer");
      auto feed = ctx.rpc_ctx->get_request_path_params().at("feed");
      auto entry = index->get(issuer, feed);
      if (!entry)
      {
        throw NotFoundError(
          errors::UnknownFeed, "No claim found for given issuer and feed");
      }

      auto info = fetch_tree_receipt(*ctx.rpc_ctx, entry->prefix_tree_seqno);
      if (!info)
      {
        return;
      }

      const auto& [protected_headers, receipt] = *info;
      auto body = create_read_receipt(
        protected_headers, entry->headers, entry->proof, receipt);

      ctx.rpc_ctx->set_response_body(body);
      ctx.rpc_ctx->set_response_header(
        http::headers::CONTENT_TYPE, "application/cbor");
    }

    void current(ccf::endpoints::ReadOnlyEndpointContext& ctx)
    {
      auto current = index->current();
      if (!current)
      {
        throw NotFoundError(
          errors::NoPrefixTree, "No prefix tree has been committed yet.");
      }

      auto [seqno, tree] = *current;

      auto info = fetch_tree_receipt(*ctx.rpc_ctx, seqno);
      if (!info)
      {
        return;
      }

      const auto& [protected_headers, receipt] = *info;
      auto body = create_tree_receipt(protected_headers, tree.hash, receipt);

      ctx.rpc_ctx->set_response_body(body);
      ctx.rpc_ctx->set_response_header(
        http::headers::CONTENT_TYPE, "application/cbor");
    }

    nlohmann::json debug(
      ccf::endpoints::CommandEndpointContext& ctx, nlohmann::json&& params)
    {
      return index->debug();
    }

    nlohmann::json flush(
      ccf::endpoints::EndpointContext& ctx, nlohmann::json&& params)
    {
      auto table = ctx.tx.template rw<PrefixTreeTable>(PREFIX_TREE_TABLE);

      auto tree = index->prepare_flush();

      // It's possible for a flush to have been written to the KV, with an
      // upper bound sequence number that has not been indexed yet. This
      // happens for example during a leader election, where the old leader may
      // have flushed the prefix tree, written the tree info to the KV and
      // replicated these changes to followers. The new leader would see the
      // up-to-date KV, but its indexer may still be lagging behind the last
      // flush.
      //
      // This call to get() also introduces an important read dependency.
      // Without it, the following sequence could happen, where t1 and t2 are
      // two concurrent transactions issuing a flush.
      // - The last tree to have been flushed had upper bound 4.
      // - t1 calls prepare_flush(), gets upper bound 7
      // - An existing claim with seqno 8 is processed by the indexer
      // - t2 calls prepare_flush(), gets upper bound 9
      // - t2 gets committed, writing upper bound 9 to the table
      // - t1 gets committed, writing upper bound 7 to the table
      // Now the in-memory prefix tree includes all claims up to seqno 9, but
      // the ledger claims the tree only goes up to 7.
      //
      // Unfortunately it is hard to write tests for either scenarios until
      // https://github.com/microsoft/CCF/issues/4263 is fixed.
      auto previous = table->get();
      if (previous.has_value() && previous->upper_bound > tree.upper_bound)
      {
        throw ServiceUnavailableError(
          errors::IndexingInProgressRetryLater,
          "Prefix tree index is still being built.");
      }

      ::timespec time;
      auto result = registry.get_untrusted_host_time_v1(time);
      if (result != ccf::ApiResult::OK)
      {
        throw InternalError(fmt::format(
          "Failed to get host time: {}", ccf::api_result_to_str(result)));
      }

      auto service = ctx.tx.template ro<ccf::Service>(ccf::Tables::SERVICE);
      auto service_info = service->get().value();
      auto service_cert = service_info.cert;
      auto service_cert_der = crypto::cert_pem_to_der(service_cert);
      auto service_id = crypto::Sha256Hash(service_cert_der).hex_str();

      PrefixTreeInfo entry;
      entry.upper_bound = tree.upper_bound;
      entry.protected_headers =
        create_prefix_tree_protected_header(time, tree.upper_bound, service_id);

      auto digest =
        create_prefix_tree_tbs_hash(entry.protected_headers, tree.hash);

      table->put(entry);
      ctx.rpc_ctx->set_claims_digest(std::move(digest));
      return entry;
    }

    /**
     * Fetch the receipt for a committed prefix tree, using the given sequence
     * number.
     *
     * If found, returns a pair with the tree's protected headers and the
     * corresponding CCF receipt. The function may return std::nullopt if the
     * historical query is not available yet. In this cases, the RpcContext will
     * be updated with a status code and headers informing the client to retry
     * later.
     *
     * Note, because this accepts a SeqNo rather than a TxID, the caller must
     * ensure the relevant transaction has been committed globally first.
     *
     * The main reason this is needed is because the indexer does not have
     * access to receipts. If it did we could cache the receipt there and not
     * have to perform a historical query every time.
     * https://github.com/microsoft/CCF/issues/4247
     */
    std::optional<std::pair<std::vector<uint8_t>, ccf::ReceiptPtr>>
    fetch_tree_receipt(ccf::RpcContext& ctx, ccf::SeqNo seqno)
    {
      auto state = context.get_historical_state().get_state_at(0, seqno);
      if (!state)
      {
        ctx.set_response_status(HTTP_STATUS_ACCEPTED);
        constexpr size_t retry_after_seconds = 3;
        ctx.set_response_header(
          http::headers::RETRY_AFTER, retry_after_seconds);
        ctx.set_response_header(
          http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
        ctx.set_response_body(fmt::format(
          "Historical transaction {} is not currently available.", seqno));
        return std::nullopt;
      }

      auto tx = state->store->create_read_only_tx();
      auto info = tx.template ro<PrefixTreeTable>(PREFIX_TREE_TABLE)->get();
      if (!info.has_value())
      {
        // This seqno does not match a transaction to the prefix tree table.
        // Since tree seqno are tracked by the indexer rather than provided by
        // the client, we consided this an internal error rather than just a
        // 404.
        throw InternalError(
          "fetch_tree_receipt called with an invalid transaction");
      }

      auto receipt = ccf::describe_receipt_v2(*state->receipt);
      return {{info->protected_headers, receipt}};
    }

    ccfapp::AbstractNodeContext& context;

    // The only reason we need a reference to the registry is to gain access to
    // get_untrusted_host_time_v1 function, which is unfortunate for a few
    // reasons:
    // - The registry owns endpoints, which have (shared) ownership of the
    //   PrefixTreeFrontend, which now has a reference to the registry, creating
    //   a cyclic dependency with non-obvious lifetimes and destruction order.
    // - The implementation doesn't actually use the registry
    // - Semantically, AbstractNodeContext seems like a more suited place for
    //   this function anyway.
    ccf::BaseEndpointRegistry& registry;

    std::shared_ptr<PrefixTreeIndexingStrategy> index;
  };
}
