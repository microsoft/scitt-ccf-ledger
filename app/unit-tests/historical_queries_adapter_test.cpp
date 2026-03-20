// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Unit tests for the custom historical queries adapter, specifically verifying
// that the cache eviction strategy in entry_adapter() drops completed states
// promptly so that in-flight fetches are not starved of cache budget.

#include "historical/historical_queries_adapter.h"

#include <ccf/tx.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

using namespace testing;
using namespace scitt;
using namespace scitt::historical;

namespace
{
  // ---------------------------------------------------------------------------
  // Mock AbstractStateCache
  //
  // AbstractStateCache is a pure-virtual interface in CCF. We mock it to
  // observe when get_state_at / drop_cached_states are called and to control
  // what each call returns.
  // ---------------------------------------------------------------------------
  class MockStateCache : public ccf::historical::AbstractStateCache
  {
  public:
    MOCK_METHOD(
      void,
      set_default_expiry_duration,
      (ccf::historical::ExpiryDuration),
      (override));

    MOCK_METHOD(
      void,
      set_soft_cache_limit,
      (ccf::historical::CacheSize),
      (override));

    MOCK_METHOD(void, track_deletes_on_missing_keys, (bool), (override));

    // get_store_at overloads
    MOCK_METHOD(
      ccf::kv::ReadOnlyStorePtr,
      get_store_at,
      (ccf::historical::RequestHandle, ccf::SeqNo, ccf::historical::ExpiryDuration),
      (override));
    MOCK_METHOD(
      ccf::kv::ReadOnlyStorePtr,
      get_store_at,
      (ccf::historical::RequestHandle, ccf::SeqNo),
      (override));

    // get_state_at overloads
    MOCK_METHOD(
      ccf::historical::StatePtr,
      get_state_at,
      (ccf::historical::RequestHandle,
       ccf::SeqNo,
       ccf::historical::ExpiryDuration),
      (override));
    MOCK_METHOD(
      ccf::historical::StatePtr,
      get_state_at,
      (ccf::historical::RequestHandle, ccf::SeqNo),
      (override));

    // get_store_range overloads
    MOCK_METHOD(
      std::vector<ccf::kv::ReadOnlyStorePtr>,
      get_store_range,
      (ccf::historical::RequestHandle,
       ccf::SeqNo,
       ccf::SeqNo,
       ccf::historical::ExpiryDuration),
      (override));
    MOCK_METHOD(
      std::vector<ccf::kv::ReadOnlyStorePtr>,
      get_store_range,
      (ccf::historical::RequestHandle, ccf::SeqNo, ccf::SeqNo),
      (override));

    // get_state_range overloads
    MOCK_METHOD(
      std::vector<ccf::historical::StatePtr>,
      get_state_range,
      (ccf::historical::RequestHandle,
       ccf::SeqNo,
       ccf::SeqNo,
       ccf::historical::ExpiryDuration),
      (override));
    MOCK_METHOD(
      std::vector<ccf::historical::StatePtr>,
      get_state_range,
      (ccf::historical::RequestHandle, ccf::SeqNo, ccf::SeqNo),
      (override));

    // get_stores_for overloads
    MOCK_METHOD(
      std::vector<ccf::kv::ReadOnlyStorePtr>,
      get_stores_for,
      (ccf::historical::RequestHandle,
       const ccf::SeqNoCollection&,
       ccf::historical::ExpiryDuration),
      (override));
    MOCK_METHOD(
      std::vector<ccf::kv::ReadOnlyStorePtr>,
      get_stores_for,
      (ccf::historical::RequestHandle, const ccf::SeqNoCollection&),
      (override));

    // get_states_for overloads
    MOCK_METHOD(
      std::vector<ccf::historical::StatePtr>,
      get_states_for,
      (ccf::historical::RequestHandle,
       const ccf::SeqNoCollection&,
       ccf::historical::ExpiryDuration),
      (override));
    MOCK_METHOD(
      std::vector<ccf::historical::StatePtr>,
      get_states_for,
      (ccf::historical::RequestHandle, const ccf::SeqNoCollection&),
      (override));

    MOCK_METHOD(
      bool,
      drop_cached_states,
      (ccf::historical::RequestHandle),
      (override));
  };

  // ---------------------------------------------------------------------------
  // Mock RpcContext
  //
  // Provides the path parameter {"txid": "..."} needed by
  // get_historical_entry_state() and stubs everything else.
  // ---------------------------------------------------------------------------
  class MockRpcContext : public ccf::RpcContext
  {
  public:
    ccf::PathParams path_params;
    int response_status = 0;
    std::vector<uint8_t> response_body;
    std::map<std::string, std::string> response_headers;

    explicit MockRpcContext(const std::string& txid)
    {
      path_params["txid"] = txid;
    }

    // --- Request accessors ---
    std::shared_ptr<ccf::SessionContext> get_session_context() const override
    {
      return nullptr;
    }
    void set_user_data(std::shared_ptr<void>) override {}
    void* get_user_data() const override
    {
      return nullptr;
    }
    const std::vector<uint8_t>& get_request_body() const override
    {
      static const std::vector<uint8_t> empty;
      return empty;
    }
    const std::string& get_request_query() const override
    {
      static const std::string empty;
      return empty;
    }
    const ccf::RESTVerb& get_request_verb() const override
    {
      static const auto verb = ccf::RESTVerb("GET");
      return verb;
    }
    std::string get_request_path() const override
    {
      return "/entries/" + path_params.at("txid");
    }
    std::string get_method() const override
    {
      return get_request_path();
    }
    std::shared_ptr<ccf::http::HTTPResponder> get_responder() const override
    {
      return nullptr;
    }
    const ccf::PathParams& get_request_path_params() override
    {
      return path_params;
    }
    const ccf::PathParams& get_decoded_request_path_params() override
    {
      return path_params;
    }
    const ccf::http::HeaderMap& get_request_headers() const override
    {
      static const ccf::http::HeaderMap empty;
      return empty;
    }
    std::optional<std::string> get_request_header(
      const std::string_view&) const override
    {
      return std::nullopt;
    }
    const std::string& get_request_url() const override
    {
      static const std::string empty;
      return empty;
    }
    ccf::FrameFormat frame_format() const override
    {
      return ccf::FrameFormat::http;
    }

    // --- Response setters ---
    void set_response_body(const std::vector<uint8_t>& body) override
    {
      response_body = body;
    }
    void set_response_body(std::vector<uint8_t>&& body) override
    {
      response_body = std::move(body);
    }
    void set_response_body(std::string&& body) override
    {
      response_body.assign(body.begin(), body.end());
    }
    const std::vector<uint8_t>& get_response_body() const override
    {
      return response_body;
    }
    void set_response_status(int status) override
    {
      response_status = status;
    }
    int get_response_status() const override
    {
      return response_status;
    }
    void set_response_header(
      const std::string_view& name, const std::string_view& value) override
    {
      response_headers[std::string(name)] = std::string(value);
    }
    void clear_response_headers() override
    {
      response_headers.clear();
    }
    void set_response_trailer(
      const std::string_view&, const std::string_view&) override
    {}
    void set_response_json(
      const nlohmann::json&, ccf::http_status) override
    {}
    void set_error(
      ccf::http_status,
      const std::string&,
      std::string&&,
      const std::vector<nlohmann::json>&) override
    {}
    void set_error(ccf::ErrorDetails&&) override {}
    void set_apply_writes(bool) override {}
    void set_claims_digest(ccf::ClaimsDigest::Digest&&) override {}
  };

  // ---------------------------------------------------------------------------
  // Helper: Create a minimal State for a given seqno.
  // ---------------------------------------------------------------------------
  ccf::historical::StatePtr make_state(ccf::SeqNo seqno)
  {
    return std::make_shared<ccf::historical::State>(
      nullptr, nullptr, ccf::TxID{2, seqno});
  }

  // ---------------------------------------------------------------------------
  // Helper: Always-valid CheckHistoricalTxStatus callback.
  // ---------------------------------------------------------------------------
  CheckHistoricalTxStatus always_valid()
  {
    return [](ccf::View, ccf::SeqNo, std::string&) {
      return HistoricalTxStatus::Valid;
    };
  }

  // ---------------------------------------------------------------------------
  // Test: After a successful handler call, drop_cached_states is invoked.
  // ---------------------------------------------------------------------------
  TEST(EntryAdapterTest, DropsCachedStateAfterSuccessfulHandler)
  {
    MockStateCache cache;
    constexpr ccf::SeqNo seqno = 42;

    auto state = make_state(seqno);

    // get_state_at returns the state, then drop_cached_states cleans it up.
    EXPECT_CALL(
      cache,
      get_state_at(
        Matcher<ccf::historical::RequestHandle>(Eq(seqno)),
        Matcher<ccf::SeqNo>(Eq(seqno))))
      .WillOnce(Return(state));
    EXPECT_CALL(cache, drop_cached_states(seqno)).WillOnce(Return(true));

    bool handler_called = false;
    auto handler =
      [&](ccf::endpoints::EndpointContext&,
          const ccf::historical::StatePtr& s) {
        handler_called = true;
        EXPECT_EQ(s->transaction_id.seqno, seqno);
      };

    auto endpoint_fn = entry_adapter(handler, cache, always_valid());

    // Build a minimal EndpointContext.
    auto rpc = std::make_shared<MockRpcContext>("2.42");
    ccf::kv::Tx tx(nullptr);
    ccf::endpoints::EndpointContext ctx(rpc, tx);

    endpoint_fn(ctx);
    EXPECT_TRUE(handler_called);
  }

  // ---------------------------------------------------------------------------
  // Test: If the handler throws, drop_cached_states is NOT called. The state
  // remains cached so a retry can use it without re-fetching from the ledger.
  // ---------------------------------------------------------------------------
  TEST(EntryAdapterTest, DoesNotDropCachedStateWhenHandlerThrows)
  {
    MockStateCache cache;
    constexpr ccf::SeqNo seqno = 10;

    EXPECT_CALL(
      cache,
      get_state_at(
        Matcher<ccf::historical::RequestHandle>(Eq(seqno)),
        Matcher<ccf::SeqNo>(Eq(seqno))))
      .WillOnce(Return(make_state(seqno)));
    EXPECT_CALL(cache, drop_cached_states(_)).Times(0);

    auto handler =
      [](ccf::endpoints::EndpointContext&,
         const ccf::historical::StatePtr&) {
        throw std::runtime_error("simulated handler failure");
      };

    auto endpoint_fn = entry_adapter(handler, cache, always_valid());

    auto rpc = std::make_shared<MockRpcContext>("2.10");
    ccf::kv::Tx tx(nullptr);
    ccf::endpoints::EndpointContext ctx(rpc, tx);

    EXPECT_THROW(endpoint_fn(ctx), std::runtime_error);
  }

  // ---------------------------------------------------------------------------
  // Test: Cache returns nullptr → ServiceUnavailableCborError (503) with the
  // TransactionNotCached code. drop_cached_states must NOT be called.
  // ---------------------------------------------------------------------------
  TEST(EntryAdapterTest, ThrowsWhenCacheReturnsNullptr)
  {
    MockStateCache cache;
    constexpr ccf::SeqNo seqno = 99;

    EXPECT_CALL(
      cache,
      get_state_at(
        Matcher<ccf::historical::RequestHandle>(Eq(seqno)),
        Matcher<ccf::SeqNo>(Eq(seqno))))
      .WillOnce(Return(nullptr));
    EXPECT_CALL(cache, drop_cached_states(_)).Times(0);

    auto handler =
      [](ccf::endpoints::EndpointContext&,
         const ccf::historical::StatePtr&) {
        FAIL() << "Handler should not be reached when cache returns nullptr";
      };

    auto endpoint_fn = entry_adapter(handler, cache, always_valid());

    auto rpc = std::make_shared<MockRpcContext>("2.99");
    ccf::kv::Tx tx(nullptr);
    ccf::endpoints::EndpointContext ctx(rpc, tx);

    EXPECT_THROW(endpoint_fn(ctx), ServiceUnavailableCborError);
  }

  // ---------------------------------------------------------------------------
  // Test: Multiple sequential requests each drop their state after completion.
  //
  // This verifies the fix for the production starvation cycle: without
  // drop_cached_states, completed states linger in the LRU cache and push out
  // in-flight fetches. Under load, new fetches are evicted before they finish,
  // causing perpetual 503 TransactionNotCached errors.
  //
  // The test simulates N requests hitting the endpoint sequentially. Each must
  // release its cached state before the next one proceeds. We verify that
  // drop_cached_states is called exactly N times with the correct handles and
  // that the cache never accumulates stale entries.
  // ---------------------------------------------------------------------------
  TEST(EntryAdapterTest, SequentialRequestsDropStatesEagerly)
  {
    MockStateCache cache;

    constexpr size_t num_requests = 20;
    std::vector<ccf::SeqNo> seqnos;
    seqnos.reserve(num_requests);
    for (size_t i = 1; i <= num_requests; ++i)
    {
      seqnos.push_back(static_cast<ccf::SeqNo>(100 + i));
    }

    // Track the order of drop_cached_states calls to verify FIFO ordering.
    std::vector<ccf::historical::RequestHandle> dropped_handles;

    for (auto seqno : seqnos)
    {
      EXPECT_CALL(
        cache,
        get_state_at(
          Matcher<ccf::historical::RequestHandle>(Eq(seqno)),
          Matcher<ccf::SeqNo>(Eq(seqno))))
        .WillOnce(Return(make_state(seqno)));
    }
    EXPECT_CALL(cache, drop_cached_states(_))
      .Times(static_cast<int>(num_requests))
      .WillRepeatedly(
        [&dropped_handles](ccf::historical::RequestHandle handle) {
          dropped_handles.push_back(handle);
          return true;
        });

    size_t handler_call_count = 0;
    auto handler =
      [&](ccf::endpoints::EndpointContext&,
          const ccf::historical::StatePtr&) { handler_call_count++; };

    auto endpoint_fn = entry_adapter(handler, cache, always_valid());

    for (auto seqno : seqnos)
    {
      auto txid_str = fmt::format("2.{}", seqno);
      auto rpc = std::make_shared<MockRpcContext>(txid_str);
      ccf::kv::Tx tx(nullptr);
      ccf::endpoints::EndpointContext ctx(rpc, tx);

      endpoint_fn(ctx);
    }

    EXPECT_EQ(handler_call_count, num_requests);
    ASSERT_EQ(dropped_handles.size(), num_requests);

    // Verify each seqno was dropped in the order it was processed.
    for (size_t i = 0; i < num_requests; ++i)
    {
      EXPECT_EQ(
        dropped_handles[i], static_cast<ccf::historical::RequestHandle>(seqnos[i]))
        << "Handle at position " << i << " should match seqno " << seqnos[i];
    }
  }

  // ---------------------------------------------------------------------------
  // Test: Simulated full-cache scenario.
  //
  // Models a cache that is at capacity. The first request succeeds because the
  // state is already fetched. After the handler completes, drop_cached_states
  // is called, freeing budget. The second request's fetch (get_state_at) then
  // succeeds because budget was freed by the first drop.
  //
  // Without the fix (no drop_cached_states), the second get_state_at would
  // return nullptr because the finished state from request 1 still occupies
  // the cache and the new fetch is immediately evicted by LRU pressure.
  // ---------------------------------------------------------------------------
  TEST(EntryAdapterTest, CacheEvictionPreventsStarvation)
  {
    MockStateCache cache;

    constexpr ccf::SeqNo first_seqno = 50;
    constexpr ccf::SeqNo second_seqno = 51;

    // Simulate: first request's state is ready.
    EXPECT_CALL(
      cache,
      get_state_at(
        Matcher<ccf::historical::RequestHandle>(Eq(first_seqno)),
        Matcher<ccf::SeqNo>(Eq(first_seqno))))
      .WillOnce(Return(make_state(first_seqno)));

    // After the first handler completes, its state is dropped.
    // This frees cache budget so the second fetch succeeds.
    bool first_dropped = false;
    EXPECT_CALL(cache, drop_cached_states(first_seqno))
      .WillOnce([&first_dropped](ccf::historical::RequestHandle) {
        first_dropped = true;
        return true;
      });

    // Second request: state is available only if the first was dropped first.
    EXPECT_CALL(
      cache,
      get_state_at(
        Matcher<ccf::historical::RequestHandle>(Eq(second_seqno)),
        Matcher<ccf::SeqNo>(Eq(second_seqno))))
      .WillOnce([&first_dropped, second_seqno](
                  ccf::historical::RequestHandle,
                  ccf::SeqNo) -> ccf::historical::StatePtr {
        // If the first state was not dropped, the cache is full and returns
        // nullptr — which triggers a 503 in production.
        if (!first_dropped)
        {
          return nullptr;
        }
        return make_state(second_seqno);
      });

    EXPECT_CALL(cache, drop_cached_states(second_seqno))
      .WillOnce(Return(true));

    size_t handler_call_count = 0;
    auto handler =
      [&](ccf::endpoints::EndpointContext&,
          const ccf::historical::StatePtr&) { handler_call_count++; };

    auto endpoint_fn = entry_adapter(handler, cache, always_valid());

    // First request
    {
      auto rpc = std::make_shared<MockRpcContext>("2.50");
      ccf::kv::Tx tx(nullptr);
      ccf::endpoints::EndpointContext ctx(rpc, tx);
      endpoint_fn(ctx);
    }

    // Second request — succeeds only because the first state was dropped.
    {
      auto rpc = std::make_shared<MockRpcContext>("2.51");
      ccf::kv::Tx tx(nullptr);
      ccf::endpoints::EndpointContext ctx(rpc, tx);
      endpoint_fn(ctx);
    }

    EXPECT_EQ(handler_call_count, 2u);
  }

  // ---------------------------------------------------------------------------
  // Test: A burst of requests where some cache fetches are not yet ready
  // (nullptr), interspersed with successful ones. Verifies that drop is only
  // called for requests that actually completed, and the ones that got 503s
  // do not trigger drops.
  // ---------------------------------------------------------------------------
  TEST(EntryAdapterTest, MixedReadyAndNotReadyRequests)
  {
    MockStateCache cache;

    // Seqno 200: ready → handler runs → drop called
    // Seqno 201: NOT ready (nullptr) → 503 thrown → no drop
    // Seqno 202: ready → handler runs → drop called

    EXPECT_CALL(
      cache,
      get_state_at(
        Matcher<ccf::historical::RequestHandle>(Eq(200)),
        Matcher<ccf::SeqNo>(Eq(200))))
      .WillOnce(Return(make_state(200)));
    EXPECT_CALL(
      cache,
      get_state_at(
        Matcher<ccf::historical::RequestHandle>(Eq(201)),
        Matcher<ccf::SeqNo>(Eq(201))))
      .WillOnce(Return(nullptr));
    EXPECT_CALL(
      cache,
      get_state_at(
        Matcher<ccf::historical::RequestHandle>(Eq(202)),
        Matcher<ccf::SeqNo>(Eq(202))))
      .WillOnce(Return(make_state(202)));

    // drop_cached_states should be called exactly twice: for seqno 200 and 202.
    EXPECT_CALL(cache, drop_cached_states(200)).WillOnce(Return(true));
    EXPECT_CALL(cache, drop_cached_states(201)).Times(0);
    EXPECT_CALL(cache, drop_cached_states(202)).WillOnce(Return(true));

    size_t handler_call_count = 0;
    auto handler =
      [&](ccf::endpoints::EndpointContext&,
          const ccf::historical::StatePtr&) { handler_call_count++; };

    auto endpoint_fn = entry_adapter(handler, cache, always_valid());

    // Request 200 — succeeds
    {
      auto rpc = std::make_shared<MockRpcContext>("2.200");
      ccf::kv::Tx tx(nullptr);
      ccf::endpoints::EndpointContext ctx(rpc, tx);
      endpoint_fn(ctx);
    }

    // Request 201 — cache miss, ServiceUnavailableCborError
    {
      auto rpc = std::make_shared<MockRpcContext>("2.201");
      ccf::kv::Tx tx(nullptr);
      ccf::endpoints::EndpointContext ctx(rpc, tx);
      EXPECT_THROW(endpoint_fn(ctx), ServiceUnavailableCborError);
    }

    // Request 202 — succeeds
    {
      auto rpc = std::make_shared<MockRpcContext>("2.202");
      ccf::kv::Tx tx(nullptr);
      ccf::endpoints::EndpointContext ctx(rpc, tx);
      endpoint_fn(ctx);
    }

    EXPECT_EQ(handler_call_count, 2u);
  }

  // ---------------------------------------------------------------------------
  // Test: Transaction status is Invalid → NotFoundCborError, no cache
  // interaction beyond the availability check.
  // ---------------------------------------------------------------------------
  TEST(EntryAdapterTest, InvalidTransactionThrowsNotFound)
  {
    MockStateCache cache;

    // get_state_at should never be called because the availability check fails.
    EXPECT_CALL(
      cache,
      get_state_at(
        Matcher<ccf::historical::RequestHandle>(_),
        Matcher<ccf::SeqNo>(_)))
      .Times(0);
    EXPECT_CALL(cache, drop_cached_states(_)).Times(0);

    auto invalid_status = [](ccf::View, ccf::SeqNo, std::string&) {
      return HistoricalTxStatus::Invalid;
    };

    auto handler =
      [](ccf::endpoints::EndpointContext&,
         const ccf::historical::StatePtr&) {
        FAIL() << "Handler must not be called for invalid transactions";
      };

    auto endpoint_fn = entry_adapter(handler, cache, invalid_status);

    auto rpc = std::make_shared<MockRpcContext>("2.77");
    ccf::kv::Tx tx(nullptr);
    ccf::endpoints::EndpointContext ctx(rpc, tx);

    EXPECT_THROW(endpoint_fn(ctx), NotFoundCborError);
  }

  // ---------------------------------------------------------------------------
  // Test: Repeated requests for the SAME txid. Each invocation gets a fresh
  // state and drops it on completion. This ensures the adapter is stateless
  // and idempotent.
  // ---------------------------------------------------------------------------
  TEST(EntryAdapterTest, RepeatedRequestsForSameTxid)
  {
    MockStateCache cache;
    constexpr ccf::SeqNo seqno = 30;

    constexpr int repeat_count = 5;

    EXPECT_CALL(
      cache,
      get_state_at(
        Matcher<ccf::historical::RequestHandle>(Eq(seqno)),
        Matcher<ccf::SeqNo>(Eq(seqno))))
      .Times(repeat_count)
      .WillRepeatedly(Return(make_state(seqno)));
    EXPECT_CALL(cache, drop_cached_states(seqno))
      .Times(repeat_count)
      .WillRepeatedly(Return(true));

    size_t handler_call_count = 0;
    auto handler =
      [&](ccf::endpoints::EndpointContext&,
          const ccf::historical::StatePtr&) { handler_call_count++; };

    auto endpoint_fn = entry_adapter(handler, cache, always_valid());

    for (int i = 0; i < repeat_count; ++i)
    {
      auto rpc = std::make_shared<MockRpcContext>("2.30");
      ccf::kv::Tx tx(nullptr);
      ccf::endpoints::EndpointContext ctx(rpc, tx);
      endpoint_fn(ctx);
    }

    EXPECT_EQ(handler_call_count, static_cast<size_t>(repeat_count));
  }
}
