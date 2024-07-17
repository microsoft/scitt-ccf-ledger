// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "tracing.h"

#include <ccf/ccf_assert.h>
#include <ccf/crypto/hash_provider.h>
#include <ccf/crypto/sha256_hash.h>
#include <qcbor/UsefulBuf.h>
#include <qcbor/qcbor_encode.h>
#include <span>
#include <string_view>

namespace scitt::cbor
{
  inline UsefulBufC from_bytes(std::span<const uint8_t> v)
  {
    return UsefulBufC{v.data(), v.size()};
  }

  inline UsefulBufC from_string(std::string_view v)
  {
    return UsefulBufC{v.data(), v.size()};
  }

  inline UsefulBufC from_sha256_hash(const ccf::crypto::Sha256Hash& v)
  {
    return UsefulBufC{v.h.data(), v.h.size()};
  }

  inline std::vector<uint8_t> as_vector(UsefulBufC buf)
  {
    return std::vector<uint8_t>(
      static_cast<const uint8_t*>(buf.ptr),
      static_cast<const uint8_t*>(buf.ptr) + buf.len);
  }

  inline std::span<const uint8_t> as_span(UsefulBufC buf)
  {
    return {static_cast<const uint8_t*>(buf.ptr), buf.len};
  }

  inline std::string_view as_string(UsefulBufC buf)
  {
    return {static_cast<const char*>(buf.ptr), buf.len};
  }

  /**
   * A wrapper around a QCBOREncodeContext to simplify buffer management.
   *
   * The encoder owns the backing byte array, and initializes the
   * QCBOREncodeContext to use it. When calling finish(), ownership of the
   * buffer is transferred to the caller.
   *
   * The encoder can be implicitly converted into a QCBOREncodeContext*, such
   * that the usual QCBOR functions may be called.
   */
  struct encoder
  {
  public:
    explicit encoder(size_t size = 10 * 1024) : buffer(size)
    {
      QCBOREncode_Init(&context, UsefulBuf{buffer.data(), buffer.size()});
    }

    // The QCBOREncodeContext holds a raw pointer into the buffer, which means
    // we can't rely on the default copy. Since we don't ever need it anyway, no
    // point in implementating a safe version.
    encoder(const encoder& other) = delete;
    encoder& operator=(const encoder& other) = delete;

    std::vector<uint8_t> finish()
    {
      UsefulBufC result;
      QCBORError err = QCBOREncode_Finish(&context, &result);
      if (err != QCBOR_SUCCESS)
      {
        SCITT_FAIL(
          "Failed encoding CBOR with QCBOR error code {}. Refer to the QCBOR "
          "documentation for more details on this error code.",
          err);
        throw std::runtime_error("Error encoding CBOR");
      }
      buffer.resize(result.len);

      // After this function return, we have relinquished ownership of the
      // buffer. We don't want the context to keep pointing into it, as that
      // could lead to accidental use-after-free. We re-init the context with a
      // null buffer to ensure any subsequent operation on the context fails
      // cleanly.
      QCBOREncode_Init(&context, NULLUsefulBuf);

      return std::move(buffer);
    }

    operator QCBOREncodeContext*()
    {
      return &context;
    }

  private:
    std::vector<uint8_t> buffer;
    QCBOREncodeContext context;
  };

  /**
   * Allows incremental hashing of a CBOR message, without the need to serialize
   * the entire message first.
   *
   * Canonical CBOR encoding, as described in Section 3.9 of RFC7049, is used,
   * making this helper suitable for hashing COSE TBS structures.
   */
  struct hasher
  {
    hasher() : h(ccf::crypto::make_incremental_sha256()) {}

    void open_array(size_t size)
    {
      hash_head(CBOR_MAJOR_TYPE_ARRAY, size);
    }

    void add_bytes(std::span<const uint8_t> bytes)
    {
      hash_head(CBOR_MAJOR_TYPE_BYTE_STRING, bytes.size());
      h->update_hash(bytes);
    }

    void add_text(std::string_view str)
    {
      hash_head(CBOR_MAJOR_TYPE_TEXT_STRING, str.size());
      h->update_hash(
        {reinterpret_cast<const uint8_t*>(str.data()), str.size()});
    }

    ccf::crypto::Sha256Hash finalise()
    {
      return h->finalise();
    }

  private:
    void hash_head(uint8_t major, uint64_t value)
    {
      UsefulBuf_MAKE_STACK_UB(buffer, QCBOR_HEAD_BUFFER_SIZE);
      UsefulBufC out = QCBOREncode_EncodeHead(buffer, major, 0, value);
      h->update_hash(as_span(out));
    }

    std::shared_ptr<ccf::crypto::ISha256Hash> h;
  };
}
