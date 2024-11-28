// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "did/resolver.h"

#include "did/mock_resolver.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using namespace scitt::did;
// NOLINTNEXTLINE
using ::testing::_;

namespace
{
  TEST(UniversalResolverTest, EmptyResolver)
  {
    const UniversalResolver resolver;
    EXPECT_THROW(
      { resolver.resolve("did:web:example.com", {}); },
      DIDMethodNotSupportedError);
  }

  TEST(UniversalResolverTest, UnsupportedMethod)
  {
    UniversalResolver resolver;
    auto x509_resolver = std::make_unique<MockMethodResolver>("did:x509:");

    EXPECT_CALL(*x509_resolver, resolve(_, _)).Times(0);

    resolver.register_resolver(std::move(x509_resolver));

    EXPECT_THROW(
      { resolver.resolve("did:web:example.com", {}); },
      DIDMethodNotSupportedError);
  }

  TEST(UniversalResolverTest, Resolve)
  {
    UniversalResolver resolver;
    auto x509_resolver = std::make_unique<MockMethodResolver>("did:x509:");
    auto web_resolver = std::make_unique<MockMethodResolver>("did:web:");

    EXPECT_CALL(*x509_resolver, resolve(_, _)).Times(0);
    EXPECT_CALL(*web_resolver, resolve("did:web:example.com", _)).Times(1);

    resolver.register_resolver(std::move(x509_resolver));
    resolver.register_resolver(std::move(web_resolver));

    resolver.resolve("did:web:example.com", {});
  }

  TEST(UniversalResolverTest, Submethod)
  {
    UniversalResolver resolver;
    auto first_method =
      std::make_unique<MockMethodResolver>("did:scitt:first:");
    auto second_method =
      std::make_unique<MockMethodResolver>("did:scitt:second:");

    EXPECT_CALL(*first_method, resolve("did:scitt:first:stuff", _)).Times(1);
    EXPECT_CALL(*second_method, resolve(_, _)).Times(0);

    resolver.register_resolver(std::move(first_method));
    resolver.register_resolver(std::move(second_method));

    resolver.resolve("did:scitt:first:stuff", {});
  }
}
