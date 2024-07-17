// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "cbor.h"

#include "cbor_test_utils.h"

#include <gtest/gtest.h>
#include <rapidcheck.h>
#include <rapidcheck/gtest.h>

using namespace scitt;

namespace
{
  RC_GTEST_PROP(CborHasher, hash_text, ())
  {
    ccf::crypto::openssl_sha256_init();
    auto text = *rc::gen::arbitrary<std::string>();

    cbor::hasher hasher;
    hasher.add_text(text);
    auto h1 = hasher.finalise();

    cbor::encoder encoder;
    QCBOREncode_AddText(encoder, cbor::from_string(text));
    auto h2 = ccf::crypto::Sha256Hash(encoder.finish());

    RC_ASSERT(h1 == h2);
    ccf::crypto::openssl_sha256_shutdown();
  }

  RC_GTEST_PROP(Cbor, hash_bytes, ())
  {
    ccf::crypto::openssl_sha256_init();
    auto bytes = *rc::gen::arbitrary<std::vector<uint8_t>>();

    cbor::hasher hasher;
    hasher.add_bytes(bytes);
    auto h1 = hasher.finalise();

    cbor::encoder encoder;
    QCBOREncode_AddBytes(encoder, cbor::from_bytes(bytes));
    auto h2 = ccf::crypto::Sha256Hash(encoder.finish());

    RC_ASSERT(h1 == h2);
    ccf::crypto::openssl_sha256_shutdown();
  }

  RC_GTEST_PROP(Cbor, hash_array, ())
  {
    ccf::crypto::openssl_sha256_init();
    auto fields = *rc::gen::arbitrary<std::vector<std::vector<uint8_t>>>();

    cbor::hasher hasher;
    hasher.open_array(fields.size());
    for (auto f : fields)
    {
      hasher.add_bytes(f);
    }
    auto h1 = hasher.finalise();

    cbor::encoder encoder;
    QCBOREncode_OpenArray(encoder);
    for (auto f : fields)
    {
      QCBOREncode_AddBytes(encoder, cbor::from_bytes(f));
    }
    QCBOREncode_CloseArray(encoder);
    auto h2 = ccf::crypto::Sha256Hash(encoder.finish());

    RC_ASSERT(h1 == h2);
    ccf::crypto::openssl_sha256_shutdown();
  }
}
