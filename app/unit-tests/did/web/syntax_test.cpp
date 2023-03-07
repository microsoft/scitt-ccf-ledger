// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "did/web/syntax.h"

#include <gtest/gtest.h>

namespace
{
  // Test check_did_is_did_web().
  TEST(DIDWebSyntaxTest, CheckDIDIsDIDWeb)
  {
    // Expect no error as this is a DID Web URI.
    const std::string did_web = "did:web:w3c-ccg.github.io";
    scitt::did::web::check_did_is_did_web(did_web);

    // Expect error as this is not a DID Web URI.
    // First check the correct error is thrown.
    const std::string did_dns = "did:dns:support.examplecompany.com";
    EXPECT_THROW(
      { scitt::did::web::check_did_is_did_web(did_dns); }, std::runtime_error);

    // Now check the error has the correct message.
    try
    {
      scitt::did::web::check_did_is_did_web(did_dns);
    }
    catch (const std::runtime_error& e)
    {
      std::string actual_msg = e.what();
      std::string expected_msg = "DID must start with did:web:";
      EXPECT_EQ(expected_msg, actual_msg);
    }
  }

  // Test get_did_web_doc_url_from_did().
  TEST(DIDWebSyntaxTest, DIDToURL)
  {
    // Test DIDWeb URIs are resolved to URLs correctly.
    std::map<std::string, std::string> tests = {
      // Test without ports or paths.
      {"did:web:w3c-ccg.github.io",
       "https://w3c-ccg.github.io/.well-known/did.json"},
      // Test with optional paths.
      {"did:web:w3c-ccg.github.io:user:alice",
       "https://w3c-ccg.github.io/user/alice/did.json"},
      // Test with only optional ports.
      {"did:web:example.com%3A3000",
       "https://example.com:3000/.well-known/did.json"},
      // Test with optional ports and paths.
      {"did:web:example.com%3A3000:user:alice",
       "https://example.com:3000/user/alice/did.json"}};
    for (auto const& [did, expected_url] : tests)
    {
      std::string actual_url =
        scitt::did::web::get_did_web_doc_url_from_did(did);
      EXPECT_EQ(expected_url, actual_url);
    }
  }

  // Test get_did_from_did_web_doc_url().
  TEST(DIDWebSyntaxTest, URLtoDID)
  {
    // Test URLs are resolved to DIDWeb URIs correctly.
    std::map<std::string, std::string> tests = {
      // Test without ports or paths.
      {"did:web:w3c-ccg.github.io",
       "https://w3c-ccg.github.io/.well-known/did.json"},
      // Test with optional paths.
      {"did:web:w3c-ccg.github.io:user:alice",
       "https://w3c-ccg.github.io/user/alice/did.json"},
      // Test with only optional ports.
      {"did:web:example.com%3A3000",
       "https://example.com:3000/.well-known/did.json"},
      // Test with optional ports and paths.
      {"did:web:example.com%3A3000:user:alice",
       "https://example.com:3000/user/alice/did.json"},
      // Test with unnecessary query parameter.
      {"did:web:example.com%3A3000:user:alice",
       "https://example.com:3000/user/alice/did.json?foobar"}};
    for (auto const& [expected_did, url] : tests)
    {
      std::string actual_did =
        scitt::did::web::get_did_from_did_web_doc_url(url);
      EXPECT_EQ(expected_did, actual_did);
    }
  }
} // namespace
