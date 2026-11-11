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
#include <openssl/err.h>
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

    timespec time = {0, 0}; // Use a fixed time for testing
    scitt::Configuration configuration; // Use a default or mock configuration
    cose::ProtectedHeader phdr;
    cose::UnprotectedHeader uhdr;
    std::span<uint8_t> payload;
    std::optional<verifier::VerifiedSevSnpAttestationDetails> details;
    std::tie(phdr, uhdr, payload, details) =
      verifier->verify_signed_statement(signed_statement, time, configuration);

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

  TEST(VerifierTest, TestAttestSvcCritValidation)
  {
    auto valid = std::make_optional<cose::CritValuesContent>(
      {cose::COSE_HEADER_PARAM_TSS});

    EXPECT_NO_THROW(
      scitt::verifier::throw_if_invalid_crit_for_attestedsvc(valid));

    cose::CritValues invalid_missing = {};
    EXPECT_THROW(
      scitt::verifier::throw_if_invalid_crit_for_attestedsvc(invalid_missing),
      scitt::verifier::VerificationError);

    auto invalid_empty = std::make_optional<cose::CritValuesContent>({});
    EXPECT_THROW(
      scitt::verifier::throw_if_invalid_crit_for_attestedsvc(invalid_empty),
      scitt::verifier::VerificationError);

    cose::CritValues invalid_values =
      std::make_optional<cose::CritValuesContent>({"invalid", "values"});
    EXPECT_THROW(
      scitt::verifier::throw_if_invalid_crit_for_attestedsvc(invalid_values),
      scitt::verifier::VerificationError);
  }

  TEST(VerifierTest, TestX509CritValidation)
  {
    auto just_cwt = std::make_optional<cose::CritValuesContent>(
      {cose::COSE_HEADER_PARAM_CWT_CLAIMS});
    EXPECT_NO_THROW(scitt::verifier::throw_if_invalid_crit_for_x509(just_cwt));

    auto just_x5chain = std::make_optional<cose::CritValuesContent>(
      {cose::COSE_HEADER_PARAM_X5CHAIN});
    EXPECT_NO_THROW(
      scitt::verifier::throw_if_invalid_crit_for_x509(just_x5chain));

    auto both = std::make_optional<cose::CritValuesContent>(
      {cose::COSE_HEADER_PARAM_CWT_CLAIMS, cose::COSE_HEADER_PARAM_X5CHAIN});
    EXPECT_NO_THROW(scitt::verifier::throw_if_invalid_crit_for_x509(both));

    // OK to have no crit at all for x509
    cose::CritValues valid_missing = {};
    EXPECT_NO_THROW(
      scitt::verifier::throw_if_invalid_crit_for_x509(valid_missing));

    // But empty is always invalid
    auto invalid_empty = std::make_optional<cose::CritValuesContent>({});
    EXPECT_THROW(
      scitt::verifier::throw_if_invalid_crit_for_x509(invalid_empty),
      scitt::verifier::VerificationError);

    // Unexpected values
    auto invalid =
      std::make_optional<cose::CritValuesContent>({"invalid", "values"});
    EXPECT_THROW(
      scitt::verifier::throw_if_invalid_crit_for_x509(invalid),
      scitt::verifier::VerificationError);
  }

  std::vector<uint8_t> read_test_payload(const std::string& filepath)
  {
    std::ifstream file(filepath, std::ios::binary);
    EXPECT_TRUE(file.is_open());
    return {std::istreambuf_iterator<char>(file), {}};
  }

  // NOLINTBEGIN(bugprone-unchecked-optional-access)
  TEST(VerifierTest, VerifyDidX509Statement)
  {
    const auto signed_statement =
      read_test_payload("test_payloads/cts-hashv-cwtclaims-b64url.cose");

    scitt::verifier::Verifier verifier;
    scitt::Configuration configuration;
    cose::ProtectedHeader phdr;
    std::tie(phdr, std::ignore, std::ignore, std::ignore) =
      verifier.verify_signed_statement(signed_statement, {0, 0}, configuration);

    ASSERT_TRUE(phdr.x5chain.has_value());
    EXPECT_GT(phdr.x5chain->size(), 1);
    EXPECT_TRUE(phdr.x5chain_is_valid_der);

    // The PEM written without parsing must be what parsing would have written
    for (const auto& cert : phdr.x5chain.value())
    {
      EXPECT_EQ(
        scitt::der_to_pem_certificate(cert),
        ccf::crypto::cert_der_to_pem(cert).str());
    }
  }

  TEST(VerifierTest, ParseX5ChainDetectsInvalidDer)
  {
    const auto signed_statement =
      read_test_payload("test_payloads/cts-hashv-cwtclaims-b64url.cose");
    auto x5chain = std::get<0>(cose::decode_headers(signed_statement)).x5chain;
    ASSERT_TRUE(x5chain.has_value());

    bool is_valid_der = false;
    auto chain =
      scitt::verifier::Verifier::parse_x5chain(*x5chain, is_valid_der);
    EXPECT_EQ(chain.size(), x5chain->size());
    EXPECT_TRUE(is_valid_der);

    // Trailing bytes are ignored by the parser, as they always were, but the
    // certificate is then no longer its own DER encoding.
    auto with_trailing_bytes = *x5chain;
    with_trailing_bytes.back().push_back(0);
    chain = scitt::verifier::Verifier::parse_x5chain(
      with_trailing_bytes, is_valid_der);
    EXPECT_EQ(chain.size(), x5chain->size());
    EXPECT_FALSE(is_valid_der);
    EXPECT_NE(
      scitt::der_to_pem_certificate(with_trailing_bytes.back()),
      ccf::crypto::cert_der_to_pem(with_trailing_bytes.back()).str());

    const std::vector<uint8_t> not_a_certificate = {0xde, 0xad, 0xbe, 0xef};
    auto with_garbage = *x5chain;
    with_garbage.back() = not_a_certificate;
    is_valid_der = true;
    ERR_clear_error();
    EXPECT_THROW(
      scitt::verifier::Verifier::parse_x5chain(with_garbage, is_valid_der),
      std::invalid_argument);
    // Not left set by the certificates which parsed before the failure
    EXPECT_FALSE(is_valid_der);
    // Nor are errors left queued for later OpenSSL calls on this thread
    EXPECT_EQ(ERR_peek_error(), 0UL);

    is_valid_der = true;
    chain = scitt::verifier::Verifier::parse_x5chain({}, is_valid_der);
    EXPECT_EQ(chain.size(), 0);
    EXPECT_FALSE(is_valid_der);
  }
  // NOLINTEND(bugprone-unchecked-optional-access)
}