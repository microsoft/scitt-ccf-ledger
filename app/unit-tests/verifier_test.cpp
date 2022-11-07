// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "verifier.h"

#include <gtest/gtest.h>

using namespace scitt::verifier;

namespace
{
  /**
   * Create a key pair and certificate.
   *
   * If `parent` is non-null, it is used to sign the certificate. Otherwise
   * the certificate will be self-signed.
   */
  std::pair<crypto::Pem, crypto::KeyPairPtr> create_cert(
    const std::string& subject_name,
    const std::pair<crypto::Pem, crypto::KeyPairPtr>* parent = nullptr)
  {
    std::string valid_from = "19700101000000Z";
    std::string valid_to = "20991231000000Z";

    auto kp = crypto::make_key_pair();
    if (parent)
    {
      auto csr = kp->create_csr(subject_name);
      auto cert =
        parent->second->sign_csr(parent->first, csr, valid_from, valid_to);

      return {cert, std::move(kp)};
    }
    else
    {
      auto cert = kp->self_sign(subject_name, valid_from, valid_to);
      return {cert, std::move(kp)};
    }
  }
}

TEST(Verifier, VerifyValidChain)
{
  auto root = create_cert("CN=root");
  auto leaf = create_cert("CN=leaf", &root);

  auto leaf_der = crypto::cert_pem_to_der(leaf.first);
  EXPECT_NO_THROW(Verifier::verify_chain({{root.first}}, {{leaf_der}}));
}

TEST(Verifier, VerifyUntrustedChain)
{
  auto trusted = create_cert("CN=trusted");

  auto root = create_cert("CN=root");
  auto leaf = create_cert("CN=leaf", &root);

  auto leaf_der = crypto::cert_pem_to_der(leaf.first);
  EXPECT_THROW(
    Verifier::verify_chain({{trusted.first}}, {{leaf_der}}), VerificationError);
}

TEST(Verifier, VerifyGarbage)
{
  auto root = create_cert("CN=root");
  std::vector<uint8_t> leaf = {0xde, 0xad, 0xbe, 0xef};

  EXPECT_THROW(
    Verifier::verify_chain({{root.first}}, {{leaf}}), VerificationError);
}

TEST(Verifier, VerifyEmptyChain)
{
  auto root = create_cert("CN=root");

  EXPECT_THROW(Verifier::verify_chain({{root.first}}, {}), VerificationError);
}
