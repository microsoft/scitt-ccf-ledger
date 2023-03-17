// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "app_data.h"
#include "historical/historical_queries_adapter.h"
#include "odata_error.h"
#include "visit_each_entry_in_value.h"

#include <ccf/json_handler.h>
#include <ccf/node_context.h>
#include <ccf/service/tables/nodes.h>

namespace scitt
{
  using OperationCallback = std::function<void(
    ccf::endpoints::EndpointContext& context,
    nlohmann::json callback_context,
    std::optional<nlohmann::json> result)>;

  /**
   * An indexing strategy which maintains a map from Operation ID to state.
   *
   * The state can be one of "running", "failed" or "succeeded". In the last
   * case, the transaction ID which completed the operation is recorded.
   */
  class OperationsIndexingStrategy
    : public VisitEachEntryInValueTyped<OperationsTable>
  {
  public:
    OperationsIndexingStrategy(ccf::BaseEndpointRegistry& registry) :
      OperationsIndexingStrategy(
        [&registry](timespec& time) {
          return registry.get_untrusted_host_time_v1(time);
        },
        [&registry](
          ccf::View view, ccf::SeqNo seqno, ccf::TxStatus& tx_status) {
          return registry.get_status_for_txid_v1(view, seqno, tx_status);
        })
    {}

    OperationsIndexingStrategy(
      std::function<ccf::ApiResult(timespec& time)> get_time,
      std::function<ccf::ApiResult(
        ccf::View view, ccf::SeqNo seqno, ccf::TxStatus& tx_status)>
        get_status_for_txid) :
      VisitEachEntryInValueTyped(OPERATIONS_TABLE),
      get_time(get_time),
      get_status_for_txid(get_status_for_txid)
    {}

    /**
     * Get the list of all operations whose state is known by the indexing
     * strategy.
     *
     * The function isn't intended to be used in normal situations, but can
     * serve as a convenient debugging endpoint into the state of the indexing
     * strategy.
     */
    std::vector<GetOperation::Out> operations() const
    {
      std::lock_guard guard(lock);
      std::vector<GetOperation::Out> result;
      for (const auto& it : operations_)
      {
        result.push_back(GetOperation::Out{
          .operation_id = ccf::TxID{it.second.view, it.first},
          .status = it.second.status,
          .entry_id = it.second.completion_tx,
          .error = it.second.error,
        });
      }
      return result;
    }

    /**
     * Look up an operation by its transaction ID.
     *
     * If the transaction ID is unknown, this function generally returns an
     * operation in the "running" state anyway, since it would not be possible
     * to distinguish between whether this is an invalid transaction ID or if
     * the transaction that created the operation has not been globally
     * committed and indexed yet.
     *
     * In some cases however, we can be confident that this transaction ID is
     * invalid now and forever in the future. In these cases, an appropriate
     * HTTPError exception is thrown.
     */
    GetOperation::Out lookup(const ccf::TxID& operation_id) const
    {
      std::lock_guard guard(lock);

      ccf::TxStatus tx_status;
      auto result =
        get_status_for_txid(operation_id.view, operation_id.seqno, tx_status);
      if (result != ccf::ApiResult::OK)
      {
        throw InternalError(fmt::format(
          "Failed to get transaction status: {}",
          ccf::api_result_to_str(result)));
      }

      switch (tx_status)
      {
        case ccf::TxStatus::Unknown:
        case ccf::TxStatus::Pending:
          return {
            .operation_id = operation_id,
            .status = OperationStatus::Running,
          };

        case ccf::TxStatus::Invalid:
          // This state can arise even in a well-behaved client if the view
          // changed (eg. because of a Raft election), and the operation's
          // transaction got dropped. It could also be a client giving us
          // garbage txids, but we can't tell the difference so we remain polite
          // and assume the former and say the operation has failed.
          return {
            .operation_id = operation_id,
            .status = OperationStatus::Failed,
            .error =
              ODataError{
                .code = ccf::errors::TransactionInvalid,
                .message = "Transaction is invalid",
              },
          };

        case ccf::TxStatus::Committed:
          // This is the main case, when the client is referring to a
          // transaction that has been committed to the ledger. From now on, it
          // is safe to consider the SeqNo only and compare it to what has been
          // indexed.
          break;
      }

      if (operation_id.seqno < lower_bound)
      {
        throw NotFoundError(
          errors::OperationExpired, "Operation ID is too old");
      }
      else if (operation_id.seqno >= upper_bound)
      {
        // This is a SeqNo we have not indexed yet, so we can't yet tell if such
        // an operation with that sequence number will exist or not yet, so
        // pretend like it does and it is "running".
        //
        // This is possible even though the TxStatus is Committed, because the
        // indexer could be behind the consensus.
        return {
          .operation_id = operation_id,
          .status = OperationStatus::Running,
        };
      }
      else if (auto it = operations_.find(operation_id.seqno);
               it != operations_.end())
      {
        CCF_ASSERT(
          operation_id.view == it->second.view,
          "Operation ID has inconsistent view");
        return {
          .operation_id = operation_id,
          .status = it->second.status,
          .entry_id = it->second.completion_tx,
          .error = it->second.error,
        };
      }
      else
      {
        // The transaction number is within our indexing range, yet doesn't
        // match any valid operation. The client must have sent us a transaction
        // ID for something completely different.
        throw NotFoundError(errors::NotFound, "Invalid operation ID");
      }
    }

    /**
     * Get the context digest for a currently running operation.
     *
     * This is used in the operation callback to check the integrity of the
     * context.
     *
     * Throws an HTTPError if the operation's state cannot be retrieved. If the
     * operation state is likely to be available at a later point, a
     * ServiceUnavailableError is thrown, allowing the caller to try again
     * later. Otherwise a BadRequestError or NotFoundError is thrown.
     */
    crypto::Sha256Hash get_context_digest(const ccf::TxID& operation_id) const
    {
      std::lock_guard guard(lock);

      // Before we can look up the operation ID in the operations map, we must
      // check whether this is a valid committed transaction or not. Otherwise
      // we risk confusing sequence numbers across different views.
      ccf::TxStatus tx_status;
      auto result =
        get_status_for_txid(operation_id.view, operation_id.seqno, tx_status);
      if (result != ccf::ApiResult::OK)
      {
        throw InternalError(fmt::format(
          "Failed to get transaction status: {}",
          ccf::api_result_to_str(result)));
      }

      std::string tx_str = operation_id.to_str();
      switch (tx_status)
      {
        case ccf::TxStatus::Unknown:
        case ccf::TxStatus::Pending:
          // This can happen when the transaction hasn't been globally
          // committed to the ledger yet. No point looking up in the map yet,
          // but we throw a transient error since eventually the transaction ID
          // could be valid.
          throw ServiceUnavailableError(
            ccf::errors::TransactionPendingOrUnknown,
            fmt::format("Transaction {} is not available.", tx_str));

        case ccf::TxStatus::Invalid:
          // Either the client passed in a garbage TX ID, or it was a real
          // transaction that got rolled back. Either way, there's no point
          // retrying it since it will never become valid in the future.
          throw NotFoundError(
            ccf::errors::TransactionInvalid,
            fmt::format("Transaction {} is invalid.", tx_str));

        case ccf::TxStatus::Committed:
          break;
      }

      if (operation_id.seqno < lower_bound)
      {
        throw NotFoundError(
          errors::OperationExpired,
          fmt::format("Transaction {} is too old", tx_str));
      }
      else if (operation_id.seqno >= upper_bound)
      {
        throw ServiceUnavailableError(
          errors::IndexingInProgressRetryLater,
          fmt::format("Transaction {} is not available.", tx_str));
      }
      else if (auto it = operations_.find(operation_id.seqno);
               it != operations_.end())
      {
        CCF_ASSERT(
          operation_id.view == it->second.view,
          "Operation ID has inconsistent view");
        if (it->second.status == OperationStatus::Running)
        {
          CCF_ASSERT_FMT(
            it->second.context_digest.has_value(),
            "No context digest for operation {}",
            tx_str);
          return it->second.context_digest.value();
        }
        else
        {
          throw BadRequestError(
            errors::InvalidInput,
            fmt::format(
              "Operation is in an invalid state: {}",
              nlohmann::json(it->second.status).dump()));
        }
      }
      else
      {
        // For a well-behaved client, this shouldn't ever happen.
        throw NotFoundError(errors::NotFound, "Invalid operation ID");
      }
    }

  protected:
    void visit_entry(const ccf::TxID& tx_id, const OperationLog& log) override
    {
      std::lock_guard guard(lock);

      handle_transition(tx_id, log);
      purge_operations();

      upper_bound = tx_id.seqno + 1;
    }

  private:
    void handle_transition(const ccf::TxID& tx_id, const OperationLog& log)
    {
      ccf::TxID operation_id = log.operation_id.value_or(tx_id);
      if (operation_id.seqno < lower_bound)
      {
        return;
      }

      auto it = operations_.find(operation_id.seqno);
      CCF_ASSERT(
        (it == operations_.end()) || (operation_id.view == it->second.view),
        "Operation ID has inconsistent view");

      auto current_status = it != operations_.end() ?
        std::optional(it->second.status) :
        std::nullopt;
      if (!check_transition(tx_id, operation_id, current_status, log))
      {
        return;
      }

      if (it == operations_.end())
      {
        it = operations_.emplace(operation_id.seqno, OperationState{}).first;
        it->second.view = operation_id.view;
        it->second.created_at = log.created_at.value();
      }

      it->second.status = log.status;
      switch (log.status)
      {
        case OperationStatus::Running:
          it->second.context_digest = log.context_digest;
          break;
        case OperationStatus::Failed:
          it->second.error = log.error;
          break;
        case OperationStatus::Succeeded:
          it->second.completion_tx = tx_id;
          break;
      }
    }

    /**
     * Each operation can be modelled as a state machine, with transactions in
     * the operations table representing state transitions.
     *
     * Not all transitions are valid. The valid ones are summarised in the
     * diagram below:
     *
     * Non existent -> Running -> Failed
     *      |             |
     *      |             v
     *      |-------> Succeeded
     *
     * This function compares a current and future state and returns true if the
     * transition is allowed. Some of the invalid transactions are logic errors
     * in the implementation. Others (ie. completing an operation twice) are
     * just undesirable but unavoidable, and shouldn't be treated as hard
     * errors.
     */
    bool check_transition(
      const ccf::TxID& tx_id,
      const ccf::TxID& operation_id,
      std::optional<OperationStatus> current_status,
      const OperationLog& log)
    {
      constexpr auto Running = OperationStatus::Running;
      constexpr auto Succeeded = OperationStatus::Succeeded;
      constexpr auto Failed = OperationStatus::Failed;

      bool valid = false;
      if (!current_status.has_value())
      {
        // This is a new operation. They can only be created in the Running or
        // Succeeded states.
        valid = (log.status == Running) || (log.status == Succeeded);
        valid = valid && log.created_at.has_value();
      }
      else if (current_status == Running)
      {
        valid = (log.status == Succeeded) || (log.status == Failed);
      }
      else if (current_status == Succeeded || current_status == Failed)
      {
        if (log.status == Succeeded || log.status == Failed)
        {
          // This is a less severe invalid transition. We just log it as INFO
          // and don't abort. We still return false, to stop the indexing
          // strategy from proceeding further.
          SCITT_INFO(
            "Repeated completion of operation {} at {}, from {} to {}",
            operation_id.to_str(),
            tx_id.to_str(),
            nlohmann::json(current_status).dump(),
            nlohmann::json(log.status).dump());
          return false;
        }
        valid = false;
      }

      if (!valid)
      {
        if (current_status.has_value())
        {
          SCITT_FAIL(
            "Got unexpected event {} at {} for existing operation {} in state",
            nlohmann::json(log.status).dump(),
            tx_id.to_str(),
            operation_id.to_str(),
            nlohmann::json(*current_status).dump());
        }
        else
        {
          SCITT_FAIL(
            "Got unexpected event {} at {} for unknown operation {}",
            nlohmann::json(log.status).dump(),
            tx_id.to_str(),
            operation_id.to_str());
        }
      }
      CCF_ASSERT(valid, "Invalid operation transition");
      return valid;
    }

    /**
     * Remove operations that are past their expiration.
     *
     * This helps limit the memory consumption of the indexing strategy, by
     * keeping a bound on how many operations we keep around.
     *
     * Because operation IDs are monotonically increasing, and we keep them
     * ordered in an std::map, we can scan from the front and stop as soon as a
     * non-expired entry is found.
     */
    void purge_operations()
    {
      timespec current_time;
      auto result = get_time(current_time);
      if (result != ccf::ApiResult::OK)
      {
        SCITT_FAIL(
          "Failed to get host time: {}", ccf::api_result_to_str(result));
      }

      auto it = operations_.begin();
      while (it != operations_.end())
      {
        double age = difftime(current_time.tv_sec, it->second.created_at);
        if (age > OPERATION_EXPIRY.count())
        {
          it++;
        }
        else
        {
          break;
        }
      }

      if (it != operations_.begin())
      {
        SCITT_INFO(
          "Removing {} operations from indexing strategy",
          std::distance(operations_.begin(), it));

        lower_bound = std::prev(it)->first + 1;
        operations_.erase(operations_.begin(), it);
      }
    }

    const std::function<ccf::ApiResult(timespec& time)> get_time;
    const std::function<ccf::ApiResult(
      ccf::View view, ccf::SeqNo seqno, ccf::TxStatus& tx_status)>
      get_status_for_txid;

    struct OperationState
    {
      // The std::map uses SeqNo as its key because TxIDs aren't totally
      // ordered.
      ccf::View view;
      OperationStatus status;
      time_t created_at;
      std::optional<ccf::TxID> completion_tx;
      std::optional<ODataError> error;
      std::optional<crypto::Sha256Hash> context_digest;
    };

    // It might be worth replacing this with a deque. Entries are only ever
    // inserted in monotonically increasing sequence numbers, which would
    // make them sorted and amenable to binary searches.
    std::map<ccf::SeqNo, OperationState> operations_;

    // These represent the ranges covered by the indexing strategy.
    // The lower bound is inclusive and the upper bound exclusive.
    //
    // Anything lower than the lower bound has been purged from the indexing
    // strategy. Anything greater or equal to the upper bound has not yet been
    // indexed.
    ccf::SeqNo lower_bound = 0;
    ccf::SeqNo upper_bound = 0;

    mutable std::mutex lock;
  };

  namespace endpoints
  {
    static GetAllOperations::Out get_all_operations(
      const std::shared_ptr<OperationsIndexingStrategy>& index,
      ccf::endpoints::EndpointContext& ctx,
      nlohmann::json&& params)
    {
      return {
        .operations = index->operations(),
      };
    }

    static GetOperation::Out get_operation(
      const std::shared_ptr<OperationsIndexingStrategy>& index,
      ccf::endpoints::EndpointContext& ctx,
      nlohmann::json&& params)
    {
      auto txid = historical::get_tx_id_from_request_path(ctx);
      return index->lookup(txid);
    }

    /**
     * This is the request handler for when an external process completes and
     * invokes an operation's callback URL. It uses a historical query to get
     * the operation's original metadata.
     *
     * This function will invoke the operation callback function, passing it
     * both the original context and the callback payload.
     *
     * If the callback function completes successfully, we mark the operation as
     * complete. The callback function should write its results to other tables
     * of the KV. At a later point, the operation indexing strategy can be used
     * to map from the operation ID to the transaction that completed it.
     *
     * If the callback function throws an HTTPError exception, details of the
     * error are recorded in the operations table. The error details will be
     * returned to future clients polling for the operation's status.
     */
    static auto post_operation_callback(
      const std::shared_ptr<OperationsIndexingStrategy>& index,
      OperationCallback& callback,
      ccf::endpoints::EndpointContext& ctx,
      nlohmann::json&& params)
    {
      auto txid = historical::get_tx_id_from_request_path(ctx);
      auto expected_context_digest = index->get_context_digest(txid);

      auto input = params.get<PostOperationCallback::In>();
      if (crypto::Sha256Hash(input.context) != expected_context_digest)
      {
        throw BadRequestError(errors::InvalidInput, "Invalid context");
      }

      auto context = nlohmann::json::parse(input.context);
      try
      {
        callback(ctx, std::move(context), std::move(input.result));
      }
      catch (const HTTPError& e)
      {
        if (e.code == errors::InternalError)
        {
          SCITT_FAIL("Callback error code={} {}", e.code, e.what());
        }
        else
        {
          SCITT_INFO("Callback error code={}", e.code);
        }

        auto operations_table =
          ctx.tx.template rw<OperationsTable>(OPERATIONS_TABLE);
        operations_table->put(OperationLog{
          .status = OperationStatus::Failed,
          .operation_id = txid,
          .error =
            ODataError{
              .code = e.code,
              .message = e.what(),
            },
        });

        // We consider any errors that are raised as part of the callback as
        // being errors of the entire operation, not of the sole callback.
        //
        // Because of this, we return a success to the process that invoked the
        // callback to stop it from retrying the callback.
        return ccf::make_success();
      }

      auto operations_table =
        ctx.tx.template rw<OperationsTable>(OPERATIONS_TABLE);
      operations_table->put(OperationLog{
        .status = OperationStatus::Succeeded,
        .operation_id = txid,
      });

      return ccf::make_success();
    }
  }

  static void register_operations_endpoints(
    ccfapp::AbstractNodeContext& context,
    ccf::BaseEndpointRegistry& registry,
    const ccf::AuthnPolicies& authn_policy,
    OperationCallback callback)
  {
    using namespace std::placeholders;

    auto operations_index =
      std::make_shared<OperationsIndexingStrategy>(registry);
    context.get_indexing_strategies().install_strategy(operations_index);

    registry
      .make_endpoint(
        "/operations",
        HTTP_GET,
        ccf::json_adapter(
          std::bind(endpoints::get_all_operations, operations_index, _1, _2)),
        authn_policy)
      .set_auto_schema<void, GetAllOperations::Out>()
      .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
      .install();

    registry
      .make_endpoint(
        "/operations/{txid}",
        HTTP_GET,
        ccf::json_adapter(
          std::bind(endpoints::get_operation, operations_index, _1, _2)),
        authn_policy)
      .set_auto_schema<void, GetOperation::Out>()
      .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
      .install();

    // The callback endpoint is specifically left open because it is called by
    // the attested fetch script. The use of a nonce and checking the
    // attestation on the payload make this ok.
    const ccf::AuthnPolicies no_authn_policy = {ccf::empty_auth_policy};
    registry
      .make_endpoint(
        "/operations/{txid}/callback",
        HTTP_POST,
        ccf::json_adapter(std::bind(
          endpoints::post_operation_callback,
          operations_index,
          callback,
          _1,
          _2)),
        no_authn_policy)
      .install();
  }

  /**
   * Get the address and port number on which the RPC interface is listening.
   * This forms the base of the callback URL used by the external process to
   * submit asynchronous operations' results.
   *
   * We use the node table to determine what port the service is listening on.
   * This works even if cchost was given port 0 in its configuration, as it
   * will have updated the node information after the port is bound.
   */
  static std::string get_bind_address(
    ccfapp::AbstractNodeContext& context, kv::ReadOnlyTx& tx)
  {
    auto nodes = tx.ro<ccf::Nodes>(ccf::Tables::NODES);
    ccf::NodeId node_id = context.get_node_id();
    std::optional<ccf::NodeInfo> node_info = nodes->get(node_id);

    if (node_info.has_value() && !node_info->rpc_interfaces.empty())
    {
      // cchost can listen on multiple interfaces. This arbitrarily uses the
      // first one, in alphabetical order.
      const auto& primary_interface = node_info->rpc_interfaces.begin()->second;

      // Note that bind_address can be 0.0.0.0. This is fine here
      // as Linux routes that address to localhost.
      return primary_interface.bind_address;
    }
    else
    {
      throw std::runtime_error("Could not callback URL");
    }
  }

  /**
   * Mark the start of an asynchronous operation.
   *
   * Asynchronous operations are useful for tasks which depend on an external
   * process to execute. This transaction will record the start of the operation
   * and set its status to "running". When the external process completes, it
   * must invoke a callback URL, at which point more processing will happen
   * inside the ledger.
   *
   * Ideally we'd kick-off the background process here, but we need access
   * to the operation ID to construct the callback URL, and we don't know it
   * yet. We use a local commit handler (operation_locally_committed_func)
   * to run code after the transaction has been committed. The trigger argument
   * is saved and will be called from the commit handler.
   *
   * The callback_context object may be used to preserve information about the
   * asynchronous operation, and will be available to the handler when the
   * background process completes and invokes the callback URL.
   */
  static void start_asynchronous_operation(
    timespec current_time,
    ccfapp::AbstractNodeContext& node_context,
    ccf::endpoints::EndpointContext& endpoint_context,
    crypto::Sha256Hash context_digest,
    TriggerAsynchronousOperation trigger)
  {
    auto table =
      endpoint_context.tx.template rw<OperationsTable>(OPERATIONS_TABLE);

    table->put(OperationLog{
      .status = OperationStatus::Running,
      .created_at = current_time.tv_sec,
      .context_digest = context_digest,
    });

    // The AppData allows us to propagate data to the handler. We use it to keep
    // a reference to the trigger lambda and the bind address. The latter is
    // needed to build the callback URL, but needs read access to the KV, which
    // we won't have later on in the commit handler.
    get_app_data(endpoint_context.rpc_ctx).asynchronous_operation =
      AsynchronousOperation{
        .trigger = trigger,
        .bind_address = get_bind_address(node_context, endpoint_context.tx),
      };
  }

  /**
   * Mark this transaction as having executed a synchronous operation.
   */
  static void record_synchronous_operation(timespec current_time, kv::Tx& tx)
  {
    auto operations_table = tx.template rw<OperationsTable>(OPERATIONS_TABLE);
    operations_table->put(OperationLog{
      .status = OperationStatus::Succeeded,
      .created_at = current_time.tv_sec,
    });
  }

  /**
   * Local commit handler for endpoints which create new operations.
   *
   * The endpoint handlers don't have access to their transaction ID, and
   * therefore cannot generate useful responses. This function is therefore
   * necessary to inform the client of the operation ID.
   *
   * This is called for both synchronous and asynchronous operations. In the
   * case of synchronous operations, the operation's status has already been set
   * to "succeeded" in the KV, and once signed, globally committed and
   * witnessed by the indexing strategy, will be available to the client.
   *
   * For asynchronous operations, we must trigger the external process, as
   * recorded as a lambda in the AppData. Again, we can only do this now that we
   * know the operation ID, since we need it for the callback URL.
   *
   * Note that if the endpoint handlers failed and set a non-2xx HTTP status
   * code, CCF doesn't apply any of the writes and doesn't call this function.
   * In this case, it is assumed the handler has set a response body when it set
   * the erroneous status code.
   *
   */
  static void operation_locally_committed_func(
    ccf::endpoints::CommandEndpointContext& ctx, const ccf::TxID& tx_id)
  {
    std::string tx_str = tx_id.to_str();
    SCITT_DEBUG("New operation was locally committed with tx={}", tx_str);

    // Even though synchronous operations are set to "Succeeded" in the KV,
    // they still need to go through consensus, so we tell the client it is
    // still "running".
    GetOperation::Out operation{
      .operation_id = tx_id,
      .status = OperationStatus::Running,
    };

    ctx.rpc_ctx->set_response_header(http::headers::CCF_TX_ID, tx_str);
    ctx.rpc_ctx->set_response_header(
      http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);
    ctx.rpc_ctx->set_response_body(serdes::pack(operation, serdes::Pack::Text));
    ctx.rpc_ctx->set_response_status(HTTP_STATUS_ACCEPTED);

    if (auto host = ctx.rpc_ctx->get_request_header(http::headers::HOST))
    {
      ctx.rpc_ctx->set_response_header(
        http::headers::LOCATION,
        fmt::format("https://{}/operations/{}", *host, tx_str));
    }

    AppData& app_data = get_app_data(ctx.rpc_ctx);
    if (app_data.asynchronous_operation.has_value())
    {
      app_data.asynchronous_operation->trigger(fmt::format(
        "https://{}/operations/{}/callback",
        app_data.asynchronous_operation->bind_address,
        tx_str));
    }
  }
}
