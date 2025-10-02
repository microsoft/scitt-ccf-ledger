// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "verifier.h"

#include "cose.h"
#include "testutils.h"
#include "verified_details.h"

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
  // NOLINTBEGIN(bugprone-unchecked-optional-access)
  TEST(VerifierTest, VerifyTSSStatement)
  {
    std::string filepath = "test_payloads/css-attested-cosesign1-20250925.cose";
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
    std::optional<verifier::VerifiedSevSnpAttestationDetails> details;
    std::tie(phdr, uhdr, payload, details) = verifier->verify_signed_statement(
      signed_statement, *tx_ptr, time, configuration);

    EXPECT_TRUE(phdr.tss_map.attestation.has_value());
    EXPECT_TRUE(phdr.tss_map.snp_endorsements.has_value());
    EXPECT_TRUE(phdr.tss_map.uvm_endorsements.has_value());
    EXPECT_TRUE(phdr.tss_map.cose_key.has_value());
    EXPECT_TRUE(phdr.alg.has_value());

    EXPECT_TRUE(details.has_value());
    EXPECT_EQ(
      details->get_measurement().hex_str(),
      "5feee30d6d7e1a29f403d70a4198237ddfb13051a2d6976439487c609388ed7f98189887"
      "920ab2fa0096903a0c23fca1");
    EXPECT_EQ(
      details->get_report_data().hex_str(),
      "460dce07b03a0a4f3a42cf93f2010595e7a8da0677b3a01a1bf08821a48bdfaf00000000"
      "00000000000000000000000000000000000000000000000000000000");
    EXPECT_TRUE(details->get_uvm_endorsements().has_value());
    EXPECT_EQ(
      details->get_uvm_endorsements().value().did,
      "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3."
      "6.1.4.1.311.76.59.1.2");
    EXPECT_EQ(
      details->get_uvm_endorsements().value().feed, "ContainerPlat-AMD-UVM");
    EXPECT_EQ(details->get_uvm_endorsements().value().svn, "101");
    auto host_data = details->get_host_data();
    auto host_data_str = ccf::ds::to_hex(host_data);
    EXPECT_EQ(
      host_data_str,
      "73973b78d70cc68353426de188db5dfc57e5b766e399935fb73a61127ea26d20");
    EXPECT_EQ(details->get_product_name(), ccf::pal::snp::ProductName::Milan);
    EXPECT_EQ(details->get_tcb_version_policy().microcode, 219);
    EXPECT_EQ(details->get_tcb_version_policy().snp, 24);
    EXPECT_EQ(details->get_tcb_version_policy().tee, 0);
    EXPECT_EQ(details->get_tcb_version_policy().boot_loader, 4);
    EXPECT_EQ(details->get_tcb_version_policy().fmc, std::nullopt);
    EXPECT_EQ(details->get_tcb_version_policy().hexstring, "db18000000000004");
  }
  // NOLINTEND(bugprone-unchecked-optional-access)

}