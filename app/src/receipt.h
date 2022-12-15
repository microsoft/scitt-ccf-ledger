// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "cbor.h"
#include "cose.h"

#include <ccf/crypto/pem.h>
#include <ccf/crypto/verifier.h>
#include <ccf/receipt.h>
#include <qcbor/qcbor_encode.h>

namespace scitt
{
  // Receipt header parameter to specify the type of tree. For now CCF is the
  // only defined algorithm.
  static constexpr const char* COSE_HEADER_PARAM_TREE_ALGORITHM = "tree_alg";
  static constexpr std::string_view TREE_ALGORITHM_CCF = "CCF";

  static constexpr const char* COSE_HEADER_PARAM_REGISTRATION_TIME =
    "registration_time";

  // TODO: At some point, this will probably be replaced by an iss + kid
  static constexpr const char* COSE_HEADER_PARAM_SERVICE_ID = "service_id";

  struct ReceiptProcessingError : public std::runtime_error
  {
    ReceiptProcessingError(const std::string& msg) : std::runtime_error(msg) {}
  };

  /**
   * Create the protected header for the countersignature
   * receipt.
   */
  std::vector<uint8_t> create_countersign_protected_header(
    ::timespec registration_time,
    std::optional<std::string_view> issuer,
    std::optional<std::span<const uint8_t>> kid,
    std::string_view service_id)
  {
    cbor::encoder encoder;

    QCBOREncode_OpenMap(encoder);
    QCBOREncode_AddTextToMap(
      encoder,
      COSE_HEADER_PARAM_TREE_ALGORITHM,
      cbor::from_string(TREE_ALGORITHM_CCF));

    if (issuer.has_value())
    {
      QCBOREncode_AddTextToMapN(
        encoder, cose::COSE_HEADER_PARAM_ISSUER, cbor::from_string(*issuer));
    }
    if (kid.has_value())
    {
      QCBOREncode_AddBytesToMapN(
        encoder, cose::COSE_HEADER_PARAM_KID, cbor::from_bytes(*kid));
    }

    // This is the legacy header parameter, currently specified by
    // draft-birkholz-scitt-receipts. Eventually this will be phased out in
    // favour of the iss/kid headers above.
    QCBOREncode_AddTextToMap(
      encoder, COSE_HEADER_PARAM_SERVICE_ID, cbor::from_string(service_id));

    QCBOREncode_AddUInt64ToMap(
      encoder, COSE_HEADER_PARAM_REGISTRATION_TIME, registration_time.tv_sec);
    QCBOREncode_CloseMap(encoder);

    return encoder.finish();
  }

  /**
   * Serialize a CCF receipt into a CBOR encoder.
   *
   * The receipt has the following format:
   * ```
   * ReceiptContents = [
   *   signature: bstr
   *   node_certificate: bstr
   *   inclusion_proof: [+ ProofElement]
   *   leaf_info: [
   *     internal_hash: bstr
   *     internal_data: bstr
   *   ]
   * ]
   * ProofElement = [
   *   left: bool
   *   hash: bstr
   * ]
   * ```
   */
  void encode_receipt_contents(
    QCBOREncodeContext* ctx, const ccf::ReceiptPtr& receipt)
  {
    if (receipt->is_signature_transaction())
    {
      throw ReceiptProcessingError("Signature transactions are not supported");
    }

    auto proof_receipt = std::dynamic_pointer_cast<ccf::ProofReceipt>(receipt);
    auto& write_set_digest = proof_receipt->leaf_components.write_set_digest;
    auto& commit_evidence = proof_receipt->leaf_components.commit_evidence;
    auto node_cert_der = crypto::cert_pem_to_der(proof_receipt->cert);

    // Contents array: [signature, node_certificate, inclusion_proof, leaf_info]
    QCBOREncode_OpenArray(ctx);

    QCBOREncode_AddBytes(ctx, cbor::from_bytes(proof_receipt->signature));
    QCBOREncode_AddBytes(ctx, cbor::from_bytes(node_cert_der));

    // Inclusion proof array: [left, hash]*
    QCBOREncode_OpenArray(ctx);

    for (auto& step : proof_receipt->proof)
    {
      auto left = step.direction == ccf::ProofReceipt::ProofStep::Left;
      QCBOREncode_OpenArray(ctx);
      QCBOREncode_AddBool(ctx, left);
      QCBOREncode_AddBytes(ctx, cbor::from_sha256_hash(step.hash));
      QCBOREncode_CloseArray(ctx);
    }

    // End of inclusion proof array
    QCBOREncode_CloseArray(ctx);

    // Leaf info array: [write_set_digest, commit_evidence]
    QCBOREncode_OpenArray(ctx);
    QCBOREncode_AddBytes(ctx, cbor::from_sha256_hash(write_set_digest));
    QCBOREncode_AddBytes(ctx, cbor::from_string(commit_evidence));
    QCBOREncode_CloseArray(ctx);

    // End of contents array
    QCBOREncode_CloseArray(ctx);
  }

  /**
   * Serialize an EntryInfo and its associated CCF receipt into a
   * Receipt structure.
   *
   * ```
   * Receipt = [
   *   protected: empty_or_serialized_map,
   *   contents: ReceiptContents
   * ]
   * ```
   */
  std::vector<uint8_t> serialize_receipt(
    const EntryInfo& entry_info, const ccf::ReceiptPtr& ccf_receipt_ptr)
  {
    auto sign_protected = entry_info.sign_protected;

    cbor::encoder encoder;

    // [ protected, contents ]
    QCBOREncode_OpenArray(encoder);
    QCBOREncode_AddBytes(encoder, cbor::from_bytes(sign_protected));

    encode_receipt_contents(encoder, ccf_receipt_ptr);

    QCBOREncode_CloseArray(encoder);

    return encoder.finish();
  }
} // namespace scitt
