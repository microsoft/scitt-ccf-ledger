// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "cbor.h"
#include "http_error.h"

#include <algorithm>
#include <cstdint>
#include <functional>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using namespace testing;
using namespace scitt;

namespace
{
  // Mock classes to simulate the context and RPC context
  class MockRpcContext
  {
  public:
    MOCK_METHOD(void, set_response_status, (ccf::http_status));
    MOCK_METHOD(
      void, set_response_header, (const std::string&, const std::string&));
    MOCK_METHOD(void, set_response_body, (const std::vector<uint8_t>&));
    MOCK_METHOD(
      void,
      set_error,
      (ccf::http_status, const std::string&, const std::string&));
  };

  class MockContext
  {
  public:
    std::shared_ptr<MockRpcContext> rpc_ctx =
      std::make_shared<MockRpcContext>();
  };

  using EndpointFunction = std::function<void(MockContext& args)>;

  class CapturingLogger : public ccf::logger::AbstractLogger
  {
  private:
    std::vector<ccf::LoggerLevel> levels_;

  public:
    void write(const ccf::logger::LogLine& line) override
    {
      levels_.push_back(line.log_level);
    }

    [[nodiscard]] const std::vector<ccf::LoggerLevel>& levels() const
    {
      return levels_;
    }
  };

  class ScopedLogger
  {
  private:
    ccf::LoggerLevel previous_level_;
    CapturingLogger* logger_;

  public:
    ScopedLogger() : previous_level_(ccf::logger::config::level())
    {
      ccf::logger::config::level() = ccf::LoggerLevel::TRACE;
      auto capturing_logger = std::make_unique<CapturingLogger>();
      logger_ = capturing_logger.get();
      ccf::logger::config::loggers().emplace_back(std::move(capturing_logger));
    }

    ~ScopedLogger()
    {
      auto& loggers = ccf::logger::config::loggers();
      const auto it = std::find_if(
        loggers.begin(), loggers.end(), [this](const auto& candidate) {
          return candidate.get() == logger_;
        });
      if (it != loggers.end())
      {
        loggers.erase(it);
      }
      ccf::logger::config::level() = previous_level_;
    }

    [[nodiscard]] const std::vector<ccf::LoggerLevel>& levels() const
    {
      return logger_->levels();
    }
  };

  // Test function that throws an HTTPError
  void test_function(MockContext& ctx)
  {
    (void)ctx;
    throw BadRequestCborError("BadRequest", "This is a bad request");
  }

  void test_unhandled_exception(MockContext& ctx)
  {
    (void)ctx;
    throw std::runtime_error("Unexpected failure");
  }

  void test_policy_error(MockContext& ctx)
  {
    (void)ctx;
    throw BadRequestCborError(errors::PolicyError, "Invalid configured policy");
  }

  // Unit test for generic_error_adapter
  TEST(GenericErrorAdapterTest, HandlesHTTPError)
  {
    ScopedLogger logs;
    std::optional<std::string> error_code;
    auto adapted_function =
      generic_error_adapter<EndpointFunction, MockContext>(
        test_function, [&error_code](MockContext&, const std::string& code) {
          error_code = code;
        });

    MockContext ctx;

    EXPECT_CALL(*ctx.rpc_ctx, set_response_status(HTTP_STATUS_BAD_REQUEST));
    EXPECT_CALL(
      *ctx.rpc_ctx,
      set_response_header(
        ccf::http::headers::CONTENT_TYPE, cbor::CBOR_ERROR_CONTENT_TYPE));
    EXPECT_CALL(*ctx.rpc_ctx, set_response_body(_))
      .WillOnce([](const std::vector<uint8_t>& body) {
        // Decode the CBOR body and check its contents
        QCBORDecodeContext decode_ctx;
        const UsefulBufC input_buf{body.data(), body.size()};
        QCBORDecode_Init(&decode_ctx, input_buf, QCBOR_DECODE_MODE_NORMAL);
        QCBORDecode_EnterMap(&decode_ctx, nullptr);
        QCBORItem item;
        QCBORDecode_GetNext(&decode_ctx, &item);
        EXPECT_EQ(item.uLabelType, QCBOR_TYPE_INT64);
        EXPECT_EQ(item.label.int64, -1);
        EXPECT_EQ(item.uDataType, QCBOR_TYPE_TEXT_STRING);
        EXPECT_STREQ(
          std::string(cbor::as_string(item.val.string)).c_str(), "BadRequest");
        QCBORDecode_GetNext(&decode_ctx, &item);
        EXPECT_EQ(item.uLabelType, QCBOR_TYPE_INT64);
        EXPECT_EQ(item.label.int64, -2);
        EXPECT_EQ(item.uDataType, QCBOR_TYPE_TEXT_STRING);
        EXPECT_STREQ(
          std::string(cbor::as_string(item.val.string)).c_str(),
          "This is a bad request");
        QCBORDecode_ExitMap(&decode_ctx);
        QCBORError err = QCBORDecode_Finish(&decode_ctx);
        EXPECT_EQ(err, QCBOR_SUCCESS);
      });

    adapted_function(ctx);
    EXPECT_EQ(error_code, "BadRequest");
    EXPECT_THAT(logs.levels(), ElementsAre(ccf::LoggerLevel::DEBUG));
  }

  TEST(GenericErrorAdapterTest, HandlesUnhandledException)
  {
    ScopedLogger logs;
    std::optional<std::string> error_code;
    auto adapted_function =
      generic_error_adapter<EndpointFunction, MockContext>(
        test_unhandled_exception,
        [&error_code](MockContext&, const std::string& code) {
          error_code = code;
        });

    MockContext ctx;

    EXPECT_CALL(
      *ctx.rpc_ctx, set_response_status(HTTP_STATUS_INTERNAL_SERVER_ERROR));
    EXPECT_CALL(
      *ctx.rpc_ctx,
      set_response_header(
        ccf::http::headers::CONTENT_TYPE, cbor::CBOR_ERROR_CONTENT_TYPE));
    EXPECT_CALL(*ctx.rpc_ctx, set_response_body(_));

    adapted_function(ctx);
    EXPECT_EQ(error_code, errors::InternalError);
    EXPECT_THAT(logs.levels(), ElementsAre(ccf::LoggerLevel::FAIL));
  }

  TEST(GenericErrorAdapterTest, LogsPolicyErrorAsFailure)
  {
    ScopedLogger logs;
    auto adapted_function =
      generic_error_adapter<EndpointFunction, MockContext>(test_policy_error);
    MockContext ctx;

    EXPECT_CALL(*ctx.rpc_ctx, set_response_status(HTTP_STATUS_BAD_REQUEST));
    EXPECT_CALL(
      *ctx.rpc_ctx,
      set_response_header(
        ccf::http::headers::CONTENT_TYPE, cbor::CBOR_ERROR_CONTENT_TYPE));
    EXPECT_CALL(*ctx.rpc_ctx, set_response_body(_));

    adapted_function(ctx);
    EXPECT_THAT(logs.levels(), ElementsAre(ccf::LoggerLevel::FAIL));
  }

}