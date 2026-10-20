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

  bool check_jwt_claims(std::string_view claims, std::string_view jwt_config)
  {
    std::string error_reason;
    return ConfigurableJwtAuthnPolicy::check_jwt_claims(
      nlohmann::json::parse(claims),
      nlohmann::json::parse(jwt_config),
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

  TEST(ConfigurableJwtAuthnPolicy, CheckClaimsSchema)
  {
    const std::string_view schema =
      R"({"$schema":"http://json-schema.org/draft-07/schema#","type":"object","properties":{"aud":{"const":"scitt"}},"required":["aud"],"anyOf":[{"type":"object","properties":{"appid":{"const":"identity-a"},"tid":{"const":"tenant-a"}},"required":["appid","tid"]},{"type":"object","properties":{"appid":{"const":"identity-b"},"tid":{"const":"tenant-b"}},"required":["appid","tid"]}]})";
    EXPECT_TRUE(check_jwt_claims(
      R"({"aud":"scitt","appid":"identity-a","tid":"tenant-a","extra":true})",
      schema));
    EXPECT_TRUE(check_jwt_claims(
      R"({"aud":"scitt","appid":"identity-b","tid":"tenant-b"})", schema));
    EXPECT_FALSE(check_jwt_claims(
      R"({"aud":"scitt","appid":"identity-a","tid":"tenant-b"})", schema));
    EXPECT_FALSE(check_jwt_claims(
      R"({"aud":"scitt","appid":"identity-b","tid":"tenant-a"})", schema));
    EXPECT_FALSE(
      check_jwt_claims(R"({"aud":"scitt","appid":"identity-a"})", schema));
    EXPECT_FALSE(check_jwt_claims(
      R"({"aud":"other","appid":"identity-a","tid":"tenant-a"})", schema));

    const std::string_view updated_schema =
      R"({"$schema":"http://json-schema.org/draft-07/schema#","type":"object","properties":{"appid":{"const":"identity-c"}},"required":["appid"]})";
    EXPECT_TRUE(check_jwt_claims(R"({"appid":"identity-c"})", updated_schema));
    EXPECT_FALSE(check_jwt_claims(
      R"({"aud":"scitt","appid":"identity-a","tid":"tenant-a"})",
      updated_schema));
    EXPECT_TRUE(check_jwt_claims(
      R"({"aud":"scitt","appid":"identity-a","tid":"tenant-a"})", schema));
    EXPECT_FALSE(check_jwt_claims(
      R"({"aud":"scitt","appid":"identity-a","tid":"tenant-a"})",
      R"({"$schema":"http://json-schema.org/draft-07/schema#","type":"object","properties":{"aud":{"const":"scitt"},"appid":{"const":"identity-b"}},"required":["aud","appid"]})"));
  }

  TEST(ConfigurableJwtAuthnPolicy, LegacyAndInvalidConfiguration)
  {
    EXPECT_TRUE(check_jwt_claims(
      R"({"aud":"scitt","extra":true})",
      R"({"requiredClaims":{"aud":"scitt"}})"));
    EXPECT_FALSE(check_jwt_claims(
      R"({"aud":"other"})", R"({"requiredClaims":{"aud":"scitt"}})"));
    EXPECT_TRUE(check_jwt_claims(R"({})", R"({"requiredClaims":{}})"));
    EXPECT_FALSE(check_jwt_claims(R"({})", R"({})"));
    EXPECT_FALSE(check_jwt_claims(
      R"({"aud":"scitt"})",
      R"({"requiredClaims":{"aud":"scitt"},"anyOfClaims":[{"appid":"a"}]})"));
    EXPECT_FALSE(check_jwt_claims(
      R"({"aud":"scitt"})",
      R"({"requiredClaims":{"aud":"scitt"},"$schema":"http://json-schema.org/draft-07/schema#"})"));
    EXPECT_FALSE(check_jwt_claims(
      R"({"aud":"scitt"})",
      R"({"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"})"));
    EXPECT_FALSE(check_jwt_claims(
      R"({"aud":"scitt"})",
      R"({"requiredClaims":{},"anyOf":[{"type":"object"}]})"));
    EXPECT_FALSE(check_jwt_claims(
      R"({"aud":"scitt"})", R"({"$schema":null,"requiredClaims":{}})"));

    const auto jwt = nlohmann::json::parse(
      R"({"$schema":"http://json-schema.org/draft-07/schema#","type":"object","properties":{"aud":{"const":"scitt"}},"required":["aud"]})");
    auto auth = nlohmann::json::parse(R"({"jwt":{}})")
                  .get<Configuration::Authentication>();
    auth.jwt = jwt;
    EXPECT_EQ(nlohmann::json(auth).at("jwt"), jwt);
    EXPECT_EQ(
      nlohmann::json(auth).get<Configuration::Authentication>().jwt, jwt);
  }
}
