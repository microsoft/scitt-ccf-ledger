// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// call_types.h and generated/constants.h must be included before
// service_endpoints.h since it relies on types (GetServiceParameters, etc.)
// and constants (SCITT_VERSION) defined in those headers.
#include "call_types.h"
#include "generated/constants.h"
#include "service_endpoints.h"

#include <ccf/crypto/key_pair.h>
#include <ccf/crypto/pem.h>
#include <ccf/service/tables/service.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

using namespace testing;
using namespace scitt;

namespace
{
  /**
   * A subclass of ServiceKeyIndexingStrategy that exposes the protected
   * visit_entry method for testing.
   */
  class TestableServiceKeyIndexingStrategy : public ServiceKeyIndexingStrategy
  {
  public:
    void add_cert(const ccf::ServiceInfo& service_info)
    {
      // Use an arbitrary TxID; the value does not affect ServiceKeyIndexingStrategy.
      ccf::TxID tx_id{1, 1};
      visit_entry(tx_id, service_info);
    }
  };

  static ccf::crypto::Pem make_test_cert()
  {
    auto kp = ccf::crypto::make_key_pair();
    return kp->self_sign("CN=test");
  }

  TEST(ServiceKeyIndexingStrategyTest, HasCertReturnsFalseWhenEmpty)
  {
    TestableServiceKeyIndexingStrategy index;
    auto cert = make_test_cert();
    EXPECT_FALSE(index.has_cert(cert));
  }

  TEST(ServiceKeyIndexingStrategyTest, HasCertReturnsTrueAfterVisit)
  {
    TestableServiceKeyIndexingStrategy index;
    auto cert = make_test_cert();

    ccf::ServiceInfo service_info;
    service_info.cert = cert;
    index.add_cert(service_info);

    EXPECT_TRUE(index.has_cert(cert));
  }

  TEST(ServiceKeyIndexingStrategyTest, HasCertReturnsFalseForDifferentCert)
  {
    TestableServiceKeyIndexingStrategy index;
    auto cert1 = make_test_cert();
    auto cert2 = make_test_cert();

    ccf::ServiceInfo service_info;
    service_info.cert = cert1;
    index.add_cert(service_info);

    EXPECT_TRUE(index.has_cert(cert1));
    EXPECT_FALSE(index.has_cert(cert2));
  }

  TEST(ServiceKeyIndexingStrategyTest, GetJwksIncludesIndexedCert)
  {
    TestableServiceKeyIndexingStrategy index;
    auto cert = make_test_cert();

    ccf::ServiceInfo service_info;
    service_info.cert = cert;
    index.add_cert(service_info);

    auto jwks = index.get_jwks();
    ASSERT_TRUE(jwks.contains("keys"));
    EXPECT_EQ(jwks["keys"].size(), 1);
  }

  TEST(ServiceKeyIndexingStrategyTest, GetJwksIsEmptyWhenNoEntriesVisited)
  {
    TestableServiceKeyIndexingStrategy index;
    auto jwks = index.get_jwks();
    ASSERT_TRUE(jwks.contains("keys"));
    EXPECT_EQ(jwks["keys"].size(), 0);
  }

} // namespace
