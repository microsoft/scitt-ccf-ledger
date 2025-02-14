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
        if (operation_id.view != it->second.view)
        {
          throw std::invalid_argument("Operation ID has inconsistent view");
        }
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
      if (!(it == operations_.end()) || (operation_id.view == it->second.view))
      {
        throw std::invalid_argument("Operation ID has inconsistent view");
      }

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
      if (!valid)
      {
        throw std::logic_error("Invalid operation transition");
      }
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
      std::optional<ccf::crypto::Sha256Hash> context_digest;
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
  }

  static void register_operations_endpoints(
    ccf::AbstractNodeContext& context,
    ccf::BaseEndpointRegistry& registry,
    const ccf::AuthnPolicies& authn_policy)
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
  }

  /**
   * Mark this transaction as having executed a synchronous operation.
   */
  static void record_synchronous_operation(
    timespec current_time, ccf::kv::Tx& tx)
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

    ctx.rpc_ctx->set_response_header(ccf::http::headers::CCF_TX_ID, tx_str);
    ctx.rpc_ctx->set_response_header(
      ccf::http::headers::CONTENT_TYPE,
      ccf::http::headervalues::contenttype::JSON);
    auto body = nlohmann::json(operation).dump();
    ctx.rpc_ctx->set_response_body(std::move(body));
    ctx.rpc_ctx->set_response_status(HTTP_STATUS_ACCEPTED);

    if (auto host = ctx.rpc_ctx->get_request_header(ccf::http::headers::HOST))
    {
      ctx.rpc_ctx->set_response_header(
        ccf::http::headers::LOCATION,
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