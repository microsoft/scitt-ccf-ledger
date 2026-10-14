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

  bool check_any_of_claims(
    std::string_view claims, std::string_view any_of_claims)
  {
    std::string error_reason;
    return ConfigurableJwtAuthnPolicy::check_any_of_claims(
      nlohmann::json::parse(claims),
      nlohmann::json::parse(any_of_claims),
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

  TEST(ConfigurableJwtAuthnPolicy, CheckAnyOfClaims)
  {
    const std::string_view alternatives =
      R"([{ "appid": "identity-a", "tid": "tenant-a" }, { "appid": "identity-b", "tid": "tenant-b" }])";
    EXPECT_TRUE(check_any_of_claims(
      R"({ "appid": "identity-a", "tid": "tenant-a", "extra": true })",
      alternatives));
    EXPECT_TRUE(check_any_of_claims(
      R"({ "appid": "identity-b", "tid": "tenant-b" })", alternatives));
    EXPECT_FALSE(check_any_of_claims(
      R"({ "appid": "identity-a", "tid": "tenant-b" })", alternatives));
    EXPECT_FALSE(check_any_of_claims(
      R"({ "appid": "identity-b", "tid": "tenant-a" })", alternatives));
    EXPECT_FALSE(
      check_any_of_claims(R"({ "appid": "identity-a" })", alternatives));
    EXPECT_FALSE(check_any_of_claims(
      R"({ "appid": "identity-c", "tid": "tenant-a" })", alternatives));
    EXPECT_TRUE(check_any_of_claims(
      R"({ "appid": "identity-a", "tid": "tenant-a" })",
      R"([{ "appid": "identity-a" }, { "tid": "tenant-a" }])"));

    EXPECT_FALSE(check_any_of_claims(R"({ "appid": "identity-a" })", R"([])"));
    EXPECT_FALSE(check_any_of_claims(R"({ "appid": "identity-a" })", R"({})"));
    EXPECT_FALSE(
      check_any_of_claims(R"({ "appid": "identity-a" })", R"([{}])"));
    EXPECT_FALSE(check_any_of_claims(
      R"({ "appid": "identity-a" })", R"([[ "identity-a" ]])"));
    EXPECT_FALSE(
      check_any_of_claims(R"({ "appid": "identity-a" })", R"([null])"));
    EXPECT_FALSE(check_any_of_claims(
      R"({ "appid": "identity-a" })", R"([{ "appid": "identity-a" }, {}])"));
  }

  TEST(ConfigurableJwtAuthnPolicy, AnyOfClaimsConfiguration)
  {
    using JWT = Configuration::Authentication::JWT;
    const auto old_config =
      nlohmann::json::parse(R"({ "requiredClaims": { "aud": "scitt" } })")
        .get<JWT>();
    EXPECT_FALSE(old_config.any_of_claims.has_value());

    const auto config =
      nlohmann::json::parse(
        R"({ "requiredClaims": { "aud": "scitt" }, "anyOfClaims": [{ "appid": "identity-a", "tid": "tenant-a" }, { "appid": "identity-b", "tid": "tenant-b" }] })")
        .get<JWT>();
    EXPECT_EQ(
      config.any_of_claims,
      nlohmann::json::parse(
        R"([{ "appid": "identity-a", "tid": "tenant-a" }, { "appid": "identity-b", "tid": "tenant-b" }])"));
    EXPECT_EQ(
      nlohmann::json(config),
      nlohmann::json::parse(
        R"({ "requiredClaims": { "aud": "scitt" }, "anyOfClaims": [{ "appid": "identity-a", "tid": "tenant-a" }, { "appid": "identity-b", "tid": "tenant-b" }] })"));
  }
}
