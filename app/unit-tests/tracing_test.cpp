// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "configurable_auth.h"
#include "http_error.h"
#include "tracing_endpoint_registry.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace
{
  using namespace scitt;
  using namespace testing;

  class MockRpcContext : public ccf::RpcContext
  {
  public:
    std::shared_ptr<void> user_data;
    ccf::http::HeaderMap request_headers;
    ccf::http::HeaderMap response_headers;
    std::string path = "/entries";
    std::string query = "waitForCommit=true";
    std::string url = "/entries?waitForCommit=true";
    ccf::RESTVerb verb = HTTP_POST;
    int status = HTTP_STATUS_OK;
    ccf::endpoints::ConsensusCommittedEndpointFunction callback;
    std::vector<uint8_t> body;
    std::shared_ptr<ccf::SessionContext> session =
      std::make_shared<ccf::SessionContext>(0, std::vector<uint8_t>{});

    void set_user_data(std::shared_ptr<void> data) override
    {
      user_data = std::move(data);
    }

    void* get_user_data() const override
    {
      return user_data.get();
    }

    std::shared_ptr<ccf::SessionContext> get_session_context() const override
    {
      return session;
    }

    const std::string& get_request_query() const override
    {
      return query;
    }

    const ccf::RESTVerb& get_request_verb() const override
    {
      return verb;
    }

    std::string get_request_path() const override
    {
      return path;
    }

    const std::string& get_request_url() const override
    {
      return url;
    }

    const ccf::http::HeaderMap& get_request_headers() const override
    {
      return request_headers;
    }

    std::optional<std::string> get_request_header(
      const std::string_view& name) const override
    {
      const auto it = request_headers.find(name);
      return it != request_headers.end() ?
        std::optional<std::string>(it->second) :
        std::nullopt;
    }

    void set_response_header(
      const std::string_view& name, const std::string_view& value) override
    {
      response_headers[std::string(name)] = value;
    }

    void clear_response_headers() override
    {
      response_headers.clear();
    }

    void set_response_status(int value) override
    {
      status = value;
    }

    int get_response_status() const override
    {
      return status;
    }

    void set_response_body(const std::vector<uint8_t>& value) override
    {
      body = value;
    }

    void set_response_body(std::vector<uint8_t>&& value) override
    {
      body = std::move(value);
    }

    void set_response_body(std::string&& value) override
    {
      body.assign(value.begin(), value.end());
    }

    const std::vector<uint8_t>& get_response_body() const override
    {
      return body;
    }

    std::vector<uint8_t>&& take_response_body() override
    {
      return std::move(body);
    }

    void set_consensus_committed_function(
      ccf::endpoints::ConsensusCommittedEndpointFunction fn) override
    {
      callback = std::move(fn);
    }

    MOCK_METHOD(std::string, get_method, (), (const, override));
    MOCK_METHOD(
      const std::vector<uint8_t>&, get_request_body, (), (const, override));
    MOCK_METHOD(
      const ccf::PathParams&, get_request_path_params, (), (override));
    MOCK_METHOD(
      const ccf::PathParams&, get_decoded_request_path_params, (), (override));
    MOCK_METHOD(ccf::FrameFormat, frame_format, (), (const, override));
    MOCK_METHOD(
      void,
      set_response_trailer,
      (const std::string_view&, const std::string_view&),
      (override));
    MOCK_METHOD(
      void,
      set_response_json,
      (const nlohmann::json&, ccf::http_status),
      (override));
    MOCK_METHOD(
      void,
      set_error,
      (ccf::http_status,
       const std::string&,
       std::string&&,
       const std::vector<nlohmann::json>&),
      (override));
    MOCK_METHOD(void, set_error, (ccf::ErrorDetails &&), (override));
    MOCK_METHOD(void, set_apply_writes, (bool), (override));
    MOCK_METHOD(
      void, set_claims_digest, (ccf::ClaimsDigest::Digest &&), (override));
  };

  class CapturedLogs : public ccf::logger::AbstractLogger
  {
  public:
    std::vector<std::string> entries;

    void write(const ccf::logger::LogLine& line) override
    {
      entries.push_back(line.msg);
    }

    std::vector<std::string> matching(std::string_view text) const
    {
      std::vector<std::string> result;
      for (const auto& entry : entries)
      {
        if (entry.find(text) != std::string::npos)
        {
          result.push_back(entry);
        }
      }
      return result;
    }
  };

  class TracingTest : public Test
  {
  protected:
    ccf::LoggerLevel previous_level = ccf::logger::config::level();
    CapturedLogs* logs = nullptr;
    std::shared_ptr<NiceMock<MockRpcContext>> rpc =
      std::make_shared<NiceMock<MockRpcContext>>();
    ccf::kv::Tx tx{nullptr};
    ccf::endpoints::EndpointContext ctx{rpc, tx};
    ccf::AbstractNodeContext node;
    TracingEndpointRegistry registry{node};
    size_t clock_ticks = 0;
    GetHostTime get_time = [this](timespec& time) {
      time = {1, static_cast<long>(clock_ticks++ * 1000000)};
      return ccf::ApiResult::OK;
    };

    void SetUp() override
    {
      current_request_scope.reset();
      request_id.reset();
      client_request_id.reset();
      ccf::logger::config::level() = ccf::LoggerLevel::TRACE;
      auto capture = std::make_unique<CapturedLogs>();
      logs = capture.get();
      ccf::logger::config::loggers().push_back(std::move(capture));
      rpc->request_headers[std::string(CLIENT_REQUEST_ID_HEADER)] = "client-7";
      ON_CALL(*rpc, get_method()).WillByDefault([this]() { return rpc->path; });
    }

    void TearDown() override
    {
      current_request_scope.reset();
      request_id.reset();
      client_request_id.reset();
      auto& loggers = ccf::logger::config::loggers();
      std::erase_if(
        loggers, [this](const auto& entry) { return entry.get() == logs; });
      ccf::logger::config::level() = previous_level;
    }

    auto begin()
    {
      return begin_request_tracing(*rpc, get_time);
    }

    void run(ccf::endpoints::EndpointFunction fn)
    {
      auto endpoint =
        std::make_shared<ccf::endpoints::Endpoint>(registry.make_endpoint(
          "/entries", HTTP_POST, tracing_adapter_first(fn, "/entries"), {}));
      registry.execute_endpoint(endpoint, ctx);
    }

    void completed(int status)
    {
      ccf::endpoints::RequestCompletedEvent event;
      event.status = status;
      registry.handle_event_request_completed(event);
    }
  };

  TEST_F(TracingTest, RetriesShareIdsAndStartButOnlyLogFinalStatus)
  {
    const auto scope = begin();
    const auto id = scope->request_id;
    for (int attempt = 0; attempt < 3; ++attempt)
    {
      EXPECT_EQ(begin(), scope);
      run([&](auto&) {
        EXPECT_EQ(request_id, id);
        scope->error_code = "DiscardedAttempt";
      });
    }
    EXPECT_TRUE(logs->matching("::END::").empty());
    EXPECT_EQ(scope->request_id, id);
    EXPECT_EQ(clock_ticks, 1);
    scope->error_code.reset();
    rpc->clear_response_headers();
    rpc->status = 500;
    completed(500);
    EXPECT_EQ(logs->matching("::START::").size(), 1);
    const auto ends = logs->matching("::END:: Stage=MAIN");
    ASSERT_EQ(ends.size(), 1);
    EXPECT_THAT(ends[0], HasSubstr("Status=500 TimeMs=1"));
    EXPECT_THAT(ends[0], Not(HasSubstr("DiscardedAttempt")));
    EXPECT_EQ(rpc->response_headers.at(std::string(REQUEST_ID_HEADER)), *id);
    EXPECT_EQ(
      rpc->response_headers.at(std::string(CLIENT_REQUEST_ID_HEADER)),
      "client-7");
    EXPECT_FALSE(get_request_scope());
    EXPECT_FALSE(request_id);
    scope->complete(200);
    EXPECT_EQ(logs->matching("::END:: Stage=MAIN").size(), 1);
  }

  TEST_F(TracingTest, AttemptsResetErrorsAndDeferredCommitState)
  {
    const auto scope = begin();
    scope->error_code = "Stale";
    scope->consensus_callback_registered = true;
    scope->locally_committed({2, 3}, false);
    EXPECT_EQ(begin(), scope);
    EXPECT_FALSE(scope->error_code);
    EXPECT_FALSE(scope->tx_id);
    EXPECT_FALSE(scope->awaiting_consensus);
    EXPECT_FALSE(scope->consensus_callback_registered);
    completed(503);
    EXPECT_EQ(logs->matching("::END:: Stage=MAIN").size(), 1);
  }

  TEST_F(TracingTest, EscapingHandlerExceptionStillGetsFrameworkCompletion)
  {
    const auto scope = begin();
    EXPECT_THROW(
      run([](auto&) { throw std::runtime_error("handler failure"); }),
      std::runtime_error);
    EXPECT_FALSE(request_id);
    EXPECT_TRUE(logs->matching("::END::").empty());
    rpc->clear_response_headers();
    rpc->status = 400;
    completed(400);
    EXPECT_EQ(logs->matching("::START::").size(), 1);
    const auto ends = logs->matching("::END:: Stage=MAIN");
    ASSERT_EQ(ends.size(), 1);
    EXPECT_THAT(ends[0], HasSubstr("Status=400"));
    EXPECT_EQ(
      rpc->response_headers.at(std::string(REQUEST_ID_HEADER)),
      *scope->request_id);
  }

  TEST_F(TracingTest, ConsensusCompletionUsesFinalStatusAndRetainsStages)
  {
    const auto scope = begin();
    run([&](auto&) {
      set_logged_consensus_committed_function(*rpc, [&](auto& info) {
        EXPECT_EQ(request_id, scope->request_id);
        info.rpc_ctx->clear_response_headers();
        info.rpc_ctx->set_response_status(503);
      });
    });
    scope->locally_committed({2, 3}, false);
    completed(200);
    EXPECT_TRUE(logs->matching("::END::").empty());
    EXPECT_FALSE(get_request_scope());
    auto other = std::make_shared<AppData>();
    other->request_id = "another-request";
    const ScopedTracingContext outer(other);
    ccf::endpoints::CommittedTxInfo info{};
    info.rpc_ctx = rpc;
    rpc->callback(info);
    EXPECT_EQ(request_id, "another-request");
    const auto ends = logs->matching("::END::");
    ASSERT_EQ(ends.size(), 2);
    EXPECT_THAT(ends[0], HasSubstr("Stage=MAIN"));
    EXPECT_THAT(ends[1], HasSubstr("Stage=POSTCOMMIT"));
    EXPECT_THAT(ends[1], HasSubstr("TxId=2.3"));
    for (const auto& end : ends)
    {
      EXPECT_THAT(end, HasSubstr("Status=503"));
      EXPECT_THAT(end, HasSubstr("RequestId=" + *scope->request_id));
    }
    EXPECT_EQ(
      rpc->response_headers.at(std::string(REQUEST_ID_HEADER)),
      *scope->request_id);
  }

  TEST_F(TracingTest, ConsensusExceptionBecomesCorrelatedInternalError)
  {
    const auto scope = begin();
    run([&](auto&) {
      set_logged_consensus_committed_function(
        *rpc, [](auto&) { throw std::runtime_error("callback failure"); });
    });
    scope->locally_committed({2, 3}, false);
    completed(200);
    ccf::endpoints::CommittedTxInfo info{};
    info.rpc_ctx = rpc;
    rpc->callback(info);
    EXPECT_EQ(rpc->status, 500);
    EXPECT_EQ(
      rpc->response_headers.at("content-type"), cbor::CBOR_ERROR_CONTENT_TYPE);
    const auto error = tav::cbor::nondet_parse(rpc->body);
    EXPECT_EQ(error.map_value_at(0).as_string(), errors::InternalError);
    EXPECT_EQ(logs->matching("Consensus callback failed:").size(), 1);
    const auto ends = logs->matching("::END:: Stage=MAIN");
    ASSERT_EQ(ends.size(), 1);
    EXPECT_THAT(ends[0], HasSubstr("Status=500 Code=InternalError"));
  }

  TEST_F(TracingTest, ForwardedWaitForCommitCompletesSynchronously)
  {
    const auto scope = begin();
    run([&](auto&) {
      set_logged_consensus_committed_function(
        *rpc, [](auto&) { FAIL() << "Forwarded callback must not run"; });
    });
    scope->locally_committed({2, 3}, true);
    completed(200);
    EXPECT_TRUE(scope->completion_logged);
    EXPECT_EQ(logs->matching("::END:: Stage=MAIN").size(), 1);
  }

  TEST_F(TracingTest, PendingForwardingHasNoFollowerCompletion)
  {
    const auto scope = begin();
    completed(200);
    EXPECT_FALSE(scope->completion_logged);
    EXPECT_TRUE(logs->matching("::END::").empty());
    EXPECT_FALSE(get_request_scope());
  }

  TEST_F(TracingTest, RoutingAndRedirectFailuresHaveEndWithoutStart)
  {
    for (const int status : {204, 307, 400, 401, 404, 405, 500, 503})
    {
      rpc->user_data.reset();
      const auto scope = begin();
      ccf::endpoints::DispatchFailedEvent event;
      event.status = status;
      registry.handle_event_dispatch_failed(event);
      EXPECT_TRUE(scope->completion_logged);
      EXPECT_FALSE(get_request_scope());
    }
    EXPECT_TRUE(logs->matching("::START::").empty());
    EXPECT_EQ(logs->matching("::END:: Stage=MAIN").size(), 8);
  }

  TEST_F(TracingTest, AuthenticationFailureUsesExistingCodeField)
  {
    begin();
    std::string reason = "Missing claim aud";
    ConfigurableJwtAuthnPolicy::log_auth_error(rpc, reason);
    completed(401);
    EXPECT_TRUE(logs->matching("::START::").empty());
    const auto ends = logs->matching("::END:: Stage=MAIN");
    ASSERT_EQ(ends.size(), 1);
    EXPECT_THAT(
      ends[0], HasSubstr("Status=401 Code=InvalidAuthenticationInfo"));
    EXPECT_EQ(
      logs->matching("JWT authentication failed: Missing claim aud").size(), 1);
    EXPECT_TRUE(logs->matching("Reason=").empty());
  }

  TEST_F(TracingTest, UnwrappedEndpointStillCompletes)
  {
    const auto scope = begin();
    auto endpoint = std::make_shared<ccf::endpoints::Endpoint>(
      registry.make_endpoint("/unwrapped", HTTP_POST, [](auto&) {}, {}));
    registry.execute_endpoint(endpoint, ctx);
    completed(403);
    EXPECT_TRUE(scope->completion_logged);
    EXPECT_TRUE(logs->matching("::START::").empty());
    EXPECT_EQ(logs->matching("::END:: Stage=MAIN").size(), 1);
  }

  TEST_F(TracingTest, LocalCommitHookExceptionDoesNotLogPrematureSuccess)
  {
    const auto scope = begin();
    run([](auto&) {});
    auto endpoint = std::make_shared<ccf::endpoints::Endpoint>(
      registry.make_endpoint("/entries", HTTP_POST, [](auto&) {}, {}));
    endpoint->set_locally_committed_function([](auto&, const auto&) {
      throw std::runtime_error("local commit failure");
    });
    EXPECT_THROW(
      registry.execute_endpoint_locally_committed(endpoint, ctx, {2, 3}),
      std::runtime_error);
    EXPECT_TRUE(logs->matching("::END::").empty());
    rpc->clear_response_headers();
    completed(500);
    EXPECT_TRUE(scope->completion_logged);
    EXPECT_EQ(logs->matching("Status=500").size(), 2);
  }

  TEST_F(TracingTest, UnscopedEventsDoNotInventCorrelation)
  {
    registry.handle_event_dispatch_failed({"/bad\npath", 503});
    completed(500);
    EXPECT_EQ(logs->matching("DispatchFailedEvent: /bad%0Apath 503").size(), 1);
    EXPECT_EQ(
      logs->matching("RequestCompletedEvent: status=500, scope=unavailable")
        .size(),
      1);
    EXPECT_TRUE(logs->matching("::END::").empty());
  }

  TEST_F(TracingTest, MissingOrForeignScopeDoesNotSkipHandlersOrCallbacks)
  {
    for (int fault = 0; fault < 3; ++fault)
    {
      current_request_scope.reset();
      rpc->user_data.reset();
      const auto foreign = std::make_shared<int>(17);
      if (fault == 1)
      {
        rpc->set_user_data(foreign);
        EXPECT_FALSE(begin());
      }
      auto other = std::make_shared<NiceMock<MockRpcContext>>();
      std::shared_ptr<AppData> other_scope;
      if (fault == 2)
      {
        other_scope = begin_request_tracing(*other, get_time);
      }
      int calls = 0;
      run([&](auto&) {
        ++calls;
        EXPECT_FALSE(request_id);
        set_logged_consensus_committed_function(*rpc, [&](auto&) {
          ++calls;
          EXPECT_FALSE(request_id);
          rpc->status = 201;
        });
      });
      ccf::endpoints::CommittedTxInfo info{};
      info.rpc_ctx = rpc;
      rpc->callback(info);
      EXPECT_EQ(calls, 2);
      EXPECT_EQ(rpc->status, 201);
      if (fault == 1)
      {
        EXPECT_EQ(rpc->get_user_data(), foreign.get());
      }
      if (other_scope != nullptr)
      {
        EXPECT_FALSE(other_scope->start_logged);
        EXPECT_FALSE(other_scope->completion_logged);
      }
    }
    EXPECT_TRUE(logs->matching("::START::").empty());
    EXPECT_TRUE(logs->matching("::END::").empty());
    EXPECT_EQ(
      logs->matching("No request log scope for SCITT endpoint").size(), 3);
    EXPECT_EQ(
      logs->matching("No request log scope for consensus callback").size(), 3);
  }

  TEST_F(TracingTest, LookupExceptionCompletesAndClearsBridgeBeforeRethrow)
  {
    EXPECT_CALL(*rpc, get_method())
      .WillOnce(Throw(std::runtime_error("lookup")));
    EXPECT_THROW(registry.find_endpoint(tx, *rpc), std::runtime_error);
    EXPECT_FALSE(get_request_scope());
    ASSERT_EQ(logs->matching("::END:: Stage=MAIN").size(), 1);
    EXPECT_THAT(
      logs->matching("::END:: Stage=MAIN")[0], HasSubstr("Status=500"));
  }

  TEST_F(TracingTest, AllowedVerbLookupExceptionCompletesAndClearsBridge)
  {
    begin();
    EXPECT_CALL(*rpc, get_method())
      .WillOnce(Throw(std::runtime_error("verbs")));
    EXPECT_THROW(registry.get_allowed_verbs(tx, *rpc), std::runtime_error);
    EXPECT_FALSE(get_request_scope());
    ASSERT_EQ(logs->matching("::END:: Stage=MAIN").size(), 1);
    EXPECT_THAT(
      logs->matching("::END:: Stage=MAIN")[0], HasSubstr("Status=500"));
  }

  TEST_F(TracingTest, ClockFailureIsDiagnosedWithoutChangingResponse)
  {
    const auto scope = begin_request_tracing(
      *rpc, [](timespec&) { return ccf::ApiResult::InternalError; });
    run([](auto&) {});
    rpc->status = 403;
    completed(403);
    EXPECT_TRUE(scope->completion_logged);
    EXPECT_EQ(rpc->status, 403);
    ASSERT_EQ(logs->matching("::END:: Stage=MAIN").size(), 1);
    EXPECT_THAT(
      logs->matching("::END:: Stage=MAIN")[0],
      HasSubstr("Status=403 TimeMs=-1"));
    EXPECT_EQ(logs->matching("Request duration unavailable").size(), 1);
  }

  TEST_F(TracingTest, LogMetadataIsBoundedButEchoedClientIdIsUnchanged)
  {
    const std::string id = "client RequestId=forged\n" + std::string(200, 'a');
    rpc->request_headers[std::string(CLIENT_REQUEST_ID_HEADER)] = id;
    rpc->query = std::string(1500, 'q');
    rpc->url = rpc->path + "?" + rpc->query;
    begin();
    run([](auto&) {});
    completed(400);
    EXPECT_EQ(
      rpc->response_headers.at(std::string(CLIENT_REQUEST_ID_HEADER)), id);
    const auto ends = logs->matching("::END:: Stage=MAIN");
    ASSERT_EQ(ends.size(), 1);
    EXPECT_THAT(
      ends[0], HasSubstr("ClientRequestId=client%20RequestId=forged%0A"));
    EXPECT_THAT(ends[0], Not(HasSubstr(" RequestId=forged")));
    EXPECT_THAT(ends[0], HasSubstr("...[truncated] URL="));
    EXPECT_THAT(ends[0], Not(HasSubstr("\n")));
  }

  TEST(LogFieldTest, EscapingAndTruncationPreserveEncodedBoundaries)
  {
    EXPECT_EQ(
      escape_log_field("/myfn:execute?q=a%20b", 128), "/myfn:execute?q=a%20b");
    EXPECT_EQ(
      escape_log_field("a b\r\n\t\x7f\xff", 128), "a%20b%0D%0A%09%7F%FF");
    EXPECT_EQ(
      escape_log_field(std::string(100, '\n'), 19), "%0A...[truncated]");
    EXPECT_EQ(escape_log_field("abc", 0), "");
    EXPECT_EQ(escape_log_field("abc", 1), ".");
    EXPECT_EQ(escape_log_field(std::string(1024, 'x'), 1024).size(), 1024);
    EXPECT_THAT(
      escape_log_field(std::string(1025, 'x'), 1024),
      EndsWith("...[truncated]"));
  }
}
