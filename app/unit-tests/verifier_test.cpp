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
  std::pair<ccf::crypto::Pem, ccf::crypto::KeyPairPtr> create_cert(
    const std::string& subject_name,
    bool ca,
    const std::pair<ccf::crypto::Pem, ccf::crypto::KeyPairPtr>* parent =
      nullptr)
  {
    const std::string valid_from = "19700101000000Z";
    const std::string valid_to = "20991231000000Z";

    auto kp = ccf::crypto::make_key_pair();
    if (parent)
    {
      auto csr = kp->create_csr(subject_name);
      auto cert =
        parent->second->sign_csr(parent->first, csr, valid_from, valid_to, ca);

      return {cert, std::move(kp)};
    }
    else
    {
      auto cert =
        kp->self_sign(subject_name, valid_from, valid_to, std::nullopt, ca);
      return {cert, std::move(kp)};
    }
  }

  /**
   * Call the Verifier::verify_chain method.
   *
   * This function has a peculiar signature, designed to work together with
   * create_cert. In particular, is takes in the private key even though it
   * doesn't use it.
   */
  void verify_chain(
    std::initializer_list<std::reference_wrapper<
      std::pair<ccf::crypto::Pem, ccf::crypto::KeyPairPtr>>> store,
    std::initializer_list<std::reference_wrapper<
      std::pair<ccf::crypto::Pem, ccf::crypto::KeyPairPtr>>> chain)
  {
    std::vector<ccf::crypto::Pem> store_certs;
    for (const auto& c : store)
    {
      store_certs.push_back(c.get().first);
    }
    std::vector<std::vector<uint8_t>> chain_certs;
    for (const auto& c : chain)
    {
      chain_certs.push_back(ccf::crypto::cert_pem_to_der(c.get().first));
    }
    Verifier::verify_chain(store_certs, chain_certs);
  }
}

TEST(Verifier, ValidChain)
{
  auto root = create_cert("CN=root", true);
  auto leaf = create_cert("CN=leaf", false, &root);

  EXPECT_NO_THROW(verify_chain({root}, {leaf, root}));
}

// Temporarily disabled because CCF's certificate generation helpers
// started enforcing a pathlen of 0, which means that we can't create a valid
// chain with an intermediate.
// See https://github.com/microsoft/CCF/pull/4995
TEST(Verifier, DISABLED_ValidChainWithIntermediate)
{
  auto root = create_cert("CN=root", true);
  auto intermediate = create_cert("CN=intermediate", true, &root);
  auto leaf = create_cert("CN=leaf", false, &intermediate);

  EXPECT_NO_THROW(verify_chain({root}, {leaf, intermediate, root}));
}

TEST(Verifier, SelfSigned)
{
  auto cert = create_cert("CN=self-signed", false);
  EXPECT_THROW(verify_chain({cert}, {cert}), VerificationError);
}

TEST(Verifier, SelfSignedCA)
{
  auto cert = create_cert("CN=self-signed", true);
  EXPECT_THROW(verify_chain({cert}, {cert}), VerificationError);
}

TEST(Verifier, MissingRoot)
{
  auto root = create_cert("CN=root", true);
  auto intermediate = create_cert("CN=intermediate", true, &root);
  auto leaf = create_cert("CN=leaf", false, &intermediate);

  EXPECT_THROW(verify_chain({root}, {leaf, intermediate}), VerificationError);
}

TEST(Verifier, MissingIntermediate)
{
  auto root = create_cert("CN=root", true);
  auto intermediate = create_cert("CN=intermediate", true, &root);
  auto leaf = create_cert("CN=leaf", false, &intermediate);

  EXPECT_THROW(verify_chain({root}, {leaf, root}), VerificationError);
}

TEST(Verifier, EmptyTrustStore)
{
  auto root = create_cert("CN=root", true);
  auto leaf = create_cert("CN=leaf", false, &root);

  EXPECT_THROW(verify_chain({}, {leaf, root}), VerificationError);
}

TEST(Verifier, UntrustedChain)
{
  auto trusted = create_cert("CN=trusted", true);

  auto untrusted = create_cert("CN=untrusted", true);
  auto leaf = create_cert("CN=leaf", false, &untrusted);

  EXPECT_THROW(verify_chain({trusted}, {leaf, untrusted}), VerificationError);
}

TEST(Verifier, NonCARoot)
{
  auto root = create_cert("CN=root", false);
  auto leaf = create_cert("CN=leaf", false, &root);

  EXPECT_THROW(verify_chain({root}, {leaf, root}), VerificationError);
}

TEST(Verifier, CALeaf)
{
  auto root = create_cert("CN=root", true);
  auto leaf = create_cert("CN=leaf", true, &root);

  EXPECT_THROW(verify_chain({root}, {leaf, root}), VerificationError);
}

TEST(Verifier, EmptyChain)
{
  auto root = create_cert("CN=root", true);

  EXPECT_THROW(verify_chain({root}, {}), VerificationError);
}

TEST(Verifier, GarbageCert)
{
  auto root = create_cert("CN=root", true);
  auto leaf = create_cert("CN=leaf", false, &root);
  const std::vector<uint8_t> garbage = {0xde, 0xad, 0xbe, 0xef};

  EXPECT_THROW(
    Verifier::verify_chain(
      {{root.first}},
      {{
        garbage,
        ccf::crypto::cert_pem_to_der(root.first),
      }}),
    VerificationError);

  EXPECT_THROW(
    Verifier::verify_chain(
      {{root.first}},
      {{
        ccf::crypto::cert_pem_to_der(leaf.first),
        garbage,
      }}),
    VerificationError);
}
