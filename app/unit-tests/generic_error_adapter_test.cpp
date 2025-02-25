#include "http_error.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

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
  };

  class MockContext
  {
  public:
    std::shared_ptr<MockRpcContext> rpc_ctx =
      std::make_shared<MockRpcContext>();
  };

  using EndpointFunction = std::function<void(MockContext& args)>;

  // Test function that throws an HTTPError
  void test_function(MockContext& ctx)
  {
    throw BadRequestError("BadRequest", "This is a bad request");
  }

  // Unit test for generic_error_adapter
  TEST(GenericErrorAdapterTest, HandlesHTTPError)
  {
    auto adapted_function =
      generic_error_adapter<EndpointFunction, MockContext>(test_function);

    MockContext ctx;

    EXPECT_CALL(*ctx.rpc_ctx, set_response_status(HTTP_STATUS_BAD_REQUEST));
    EXPECT_CALL(
      *ctx.rpc_ctx,
      set_response_header(
        ccf::http::headers::CONTENT_TYPE,
        ccf::http::headervalues::contenttype::CBOR));
    EXPECT_CALL(*ctx.rpc_ctx, set_response_body(_))
      .WillOnce([](const std::vector<uint8_t>& body) {
        // Decode the CBOR body and check its contents
        QCBORError err;
        QCBORDecodeContext decode_ctx;
        UsefulBufC input_buf{body.data(), body.size()};
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
        err = QCBORDecode_Finish(&decode_ctx);
        EXPECT_EQ(err, QCBOR_SUCCESS);
      });

    adapted_function(ctx);
  }

}