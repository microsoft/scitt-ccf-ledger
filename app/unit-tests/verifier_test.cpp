// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "verifier.h"

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

    size_t size = std::filesystem::file_size(filepath);

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
    cose::ProtectedHeader phdr;
    cose::UnprotectedHeader uhdr;
    std::span<uint8_t> payload;
    std::tie(phdr, uhdr, payload) = verifier->verify_signed_statement(
      signed_statement, *tx_ptr, time, configuration);

    EXPECT_TRUE(phdr.tss_map.attestation.has_value());
    EXPECT_TRUE(phdr.tss_map.snp_endorsements.has_value());
    EXPECT_TRUE(phdr.tss_map.uvm_endorsements.has_value());
    EXPECT_TRUE(phdr.tss_map.cose_key.has_value());
    EXPECT_TRUE(phdr.alg.has_value());
  }

}