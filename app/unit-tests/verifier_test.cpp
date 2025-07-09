// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "cose.h"

#include "testutils.h"

#include <ccf/crypto/openssl/openssl_wrappers.h>
#include <ccf/crypto/pem.h>
#include <ccf/crypto/rsa_key_pair.h>
#include <ccf/service/tables/cert_bundles.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <openssl/core_names.h>
#include <openssl/encoder.h>
#include <openssl/param_build.h>
#include <stdexcept>
#include "verifier.h"

using namespace testing;
using namespace scitt;
using namespace testutils;

namespace
{
  TEST(VerifierTest, VerifyTSSStatement)
  {
    std::string filepath = "test_payloads/css-attested-cosesign1-20250617.cose";
    std::ifstream file(filepath, std::ios::binary);
    ASSERT_TRUE(file.is_open());

    // Get file size
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);

    // Read file into vector
    std::vector<uint8_t> signed_statement(size);
    file.read(
      reinterpret_cast<char*>(signed_statement.data()),
      static_cast<std::streamsize>(size));
    ASSERT_EQ(file.gcount(), size);
    
    auto verifier = std::make_unique<scitt::verifier::Verifier>();
    
    // Create a mock or test transaction - adjust based on your test framework
    ccf::kv::ReadOnlyTx* tx_ptr = nullptr; // Or use your test framework's mock
    timespec time = {0, 0}; // Use a fixed time for testing
    scitt::Configuration configuration; // Use a default or mock configuration
    verifier->verify_signed_statement(signed_statement, *tx_ptr, time, configuration);
  }

}