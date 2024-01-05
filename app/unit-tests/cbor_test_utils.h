// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

// These are functions implemented in CCF (see
// https://github.com/microsoft/CCF/blob/8f06c5fa00e5dae51e5b489ef9d312aa7f2496e4/src/crypto/openssl/hash.cpp#L43-L81).
// They are used to create and destroy a thread-local cache of contexts for
// OpenSSL operations. Calling these functions before using ccf::crypto objects
// (e.g., crypto::Sha256Hash) is not required in the context of a CCF
// application (CCF already takes care of that). However, calling them when
// running unit tests (or, in general, outside the context of the CCF
// application) is needed, otherwise an exception will be thrown. Since the two
// functions are not currently exposed in the CCF library, we define the headers
// here as a simple workaround to be able to call them and let the unit tests
// run successfully.
namespace crypto
{
  void openssl_sha256_init();
  void openssl_sha256_shutdown();
}
