// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "configurable_auth.h"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

using namespace scitt;

namespace
{
  bool check_claims(std::string_view claims, std::string_view required_claims)
  {
    std::string error_reason;
    return ConfigurableJwtAuthnPolicy::check_claims(
      nlohmann::json::parse(claims),
      nlohmann::json::parse(required_claims),
      error_reason);
  }

  bool check_one_of_claims(
    std::string_view claims, std::string_view one_of_claims)
  {
    std::string error_reason;
    return ConfigurableJwtAuthnPolicy::check_one_of_claims(
      nlohmann::json::parse(claims),
      nlohmann::json::parse(one_of_claims),
      error_reason);
  }

  TEST(ConfigurableJwtAuthnPolicy, CheckClaims)
  {
    // The trailing comments on every assertion forces clang-format's hand into
    // making this readable.

    // These are all okay: the token has at least all the required ones
    EXPECT_TRUE(check_claims( //
      R"({ })",
      R"({ })"));
    EXPECT_TRUE(check_claims( //
      R"({ "aud": "foo" })",
      R"({ })"));
    EXPECT_TRUE(check_claims( //
      R"({ "aud": "foo" })",
      R"({ "aud": "foo" })"));
    EXPECT_TRUE(check_claims( //
      R"({ "aud": "foo", "iat": 1234567 })",
      R"({ "aud": "foo" })"));

    // The tokens are missing some or all of the required claims.
    EXPECT_FALSE(check_claims( //
      R"({ })",
      R"({ "aud": "foo" })"));
    EXPECT_FALSE(check_claims( //
      R"({ "aud": "foo" })",
      R"({ "aud": "bar" })"));
    EXPECT_FALSE(check_claims( //
      R"({ "aud": "foo", "iat": "1234567" })",
      R"({ "aud": "foo", "iss": "baz" })"));

    // Claims can be of any type.
    EXPECT_TRUE(check_claims( //
      R"({ "data": null })",
      R"({ "data": null })"));
    EXPECT_TRUE(check_claims( //
      R"({ "data": 42 })",
      R"({ "data": 42 })"));
    EXPECT_TRUE(check_claims( //
      R"({ "data": [ ] })",
      R"({ "data": [ ] })"));
    EXPECT_TRUE(check_claims( //
      R"({ "data": { } })",
      R"({ "data": { } })"));
    EXPECT_TRUE(check_claims( //
      R"({ "data": [ "foo" ] })",
      R"({ "data": [ "foo" ] })"));
    EXPECT_TRUE(check_claims( //
      R"({ "data": { "foo": "bar" } })",
      R"({ "data": { "foo": "bar" } })"));

    // No type coercion when comparing claims
    EXPECT_FALSE(check_claims( //
      R"({ "data": 42 })",
      R"({ "data": "42" })"));
    EXPECT_FALSE(check_claims( //
      R"({ "data": { } })",
      R"({ "data": null })"));
    EXPECT_FALSE(check_claims( //
      R"({ "data": [ ] })",
      R"({ "data": null })"));
    EXPECT_FALSE(check_claims( //
      R"({ "data": [ ] })",
      R"({ "data": { } })"));
    EXPECT_FALSE(check_claims( //
      R"({ "data": "foo" })",
      R"({ "data": [ "foo" ] })"));
    EXPECT_FALSE(check_claims( //
      R"({ "data": [ "foo" ] })",
      R"({ "data": "foo" })"));

    // Individual claims are matched by equality exactly
    EXPECT_FALSE(check_claims( //
      R"({ "data": { "foo": "bar" } })",
      R"({ "data": { } })"));
    EXPECT_FALSE(check_claims( //
      R"({ "data": { } })",
      R"({ "data": { "foo": "bar" } })"));
    EXPECT_FALSE(check_claims( //
      R"({ "data": [ "foo" ] })",
      R"({ "data": [ "foo", "bar" ] })"));
    EXPECT_FALSE(check_claims( //
      R"({ "data": [ "foo", "bar" ] })",
      R"({ "data": [ "foo" ] })"));
  }

  TEST(ConfigurableJwtAuthnPolicy, CheckOneOfClaims)
  {
    EXPECT_TRUE(check_one_of_claims(
      R"({ "appid": "identity-a", "aud": "scitt" })",
      R"({ "appid": ["identity-a", "identity-b"], "aud": ["scitt"] })"));
    EXPECT_TRUE(check_one_of_claims(
      R"({ "appid": "identity-b", "aud": "scitt" })",
      R"({ "appid": ["identity-a", "identity-b"], "aud": ["scitt"] })"));
    EXPECT_TRUE(check_one_of_claims(R"({})", R"({})"));

    EXPECT_FALSE(check_one_of_claims(
      R"({ "appid": "identity-c", "aud": "scitt" })",
      R"({ "appid": ["identity-a", "identity-b"], "aud": ["scitt"] })"));
    EXPECT_FALSE(check_one_of_claims(
      R"({ "appid": "identity-a", "aud": "other" })",
      R"({ "appid": ["identity-a", "identity-b"], "aud": ["scitt"] })"));
    EXPECT_FALSE(check_one_of_claims(
      R"({ "aud": "scitt" })", R"({ "appid": ["identity-a", "identity-b"] })"));
    EXPECT_FALSE(check_one_of_claims(
      R"({ "appid": ["identity-a"] })",
      R"({ "appid": ["identity-a", "identity-b"] })"));
    EXPECT_FALSE(check_one_of_claims(
      R"({ "appid": "identity-a" })", R"({ "appid": [] })"));
    EXPECT_FALSE(check_one_of_claims(
      R"({ "appid": "identity-a" })", R"({ "appid": "identity-a" })"));
    EXPECT_FALSE(check_one_of_claims(
      R"({ "appid": "identity-a" })", R"({ "appid": [null, "identity-a"] })"));
    EXPECT_FALSE(check_one_of_claims(R"({ "appid": "identity-a" })", R"([])"));
  }

  TEST(ConfigurableJwtAuthnPolicy, OneOfClaimsConfiguration)
  {
    using JWT = Configuration::Authentication::JWT;
    const auto old_config =
      nlohmann::json::parse(R"({ "requiredClaims": { "aud": "scitt" } })")
        .get<JWT>();
    EXPECT_FALSE(old_config.one_of_claims.has_value());

    const auto config =
      nlohmann::json::parse(
        R"({ "requiredClaims": { "aud": "scitt" }, "oneOfClaims": { "appid": ["identity-a", "identity-b"] } })")
        .get<JWT>();
    ASSERT_TRUE(config.one_of_claims.has_value());
    EXPECT_EQ(
      *config.one_of_claims,
      nlohmann::json::parse(R"({ "appid": ["identity-a", "identity-b"] })"));
    EXPECT_EQ(
      nlohmann::json(config),
      nlohmann::json::parse(
        R"({ "requiredClaims": { "aud": "scitt" }, "oneOfClaims": { "appid": ["identity-a", "identity-b"] } })"));
  }
}
