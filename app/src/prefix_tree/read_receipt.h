// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "cbor.h"
#include "receipt.h"

/**
 * This file is responsible for encoding read receipts.
 *
 * The overall format of the receipts is defined below:
 * ```
 * ReadReceipt = [
 *   tree_headers: .bstr cbor {
 *     tree_alg: tstr,
 *     service_id: ttr,
 *     upper_bound_seqno: int,
 *     timestamp: int,
 *     * label => value
 *   },
 *   leaf_headers: .bstr cbor {
 *     claim_seqno: int,
 *     * label => value
 *   },
 *   inclusion_proof: [
 *     positions: bstr,
 *     hashes: [ *bstr ],
 *   ],
 *   receipt_contents: any
 * ]
 * ```
 *
 * where tree_alg refers to the ledger algorithm, as defined in
 * draft-birkholz-scitt-receipts, and determines the type of receipt_contents.
 * In the case of the `CCF` tree algorithm, receipt_contents is a
 * ReceiptContents structure.
 *
 */
namespace scitt
{
  static std::vector<uint8_t> create_prefix_tree_protected_header(
    ::timespec time, ccf::SeqNo upper_bound, const std::string& service_id)
  {
    cbor::encoder encoder;
    QCBOREncode_OpenMap(encoder);
    QCBOREncode_AddTextToMap(
      encoder,
      COSE_HEADER_PARAM_TREE_ALGORITHM,
      cbor::from_string(TREE_ALGORITHM_CCF));
    QCBOREncode_AddTextToMap(
      encoder, COSE_HEADER_PARAM_SERVICE_ID, cbor::from_string(service_id));
    QCBOREncode_AddUInt64ToMap(encoder, "time", time.tv_sec);
    QCBOREncode_AddUInt64ToMap(encoder, "upper_bound_seqno", upper_bound);
    QCBOREncode_CloseMap(encoder);
    return encoder.finish();
  }

  static std::vector<uint8_t> create_read_receipt_protected_header(
    ccf::SeqNo seqno)
  {
    cbor::encoder encoder;
    QCBOREncode_OpenMap(encoder);
    QCBOREncode_AddUInt64ToMap(encoder, "claim_seqno", seqno);
    QCBOREncode_CloseMap(encoder);
    return encoder.finish();
  }

  /**
   * Compute the digest of the TBS for the prefix tree root.
   *
   * The is the following structure, using canonical CBOR encoding:
   *
   * PrefixTree_structure = [
   *     context: "SCITT",
   *     protected: bstr,
   *     root: bstr,
   * ]
   *
   * where root is the hash of the root of the tree.
   */
  static crypto::Sha256Hash create_prefix_tree_tbs_hash(
    std::span<const uint8_t> protected_headers, const crypto::Sha256Hash& root)
  {
    cbor::hasher hasher;
    hasher.open_array(3);
    hasher.add_text("SCITT");
    hasher.add_bytes(protected_headers);
    hasher.add_bytes(root.h);
    return hasher.finalise();
  }

  static std::vector<uint8_t> create_read_receipt(
    std::span<const uint8_t> tree_headers,
    std::span<const uint8_t> leaf_headers,
    const pt::path<>& proof,
    const ccf::ReceiptPtr& ccf_receipt)
  {
    cbor::encoder encoder;
    QCBOREncode_OpenArray(encoder);

    QCBOREncode_AddBytes(encoder, cbor::from_bytes(tree_headers));
    QCBOREncode_AddBytes(encoder, cbor::from_bytes(leaf_headers));

    // [ prefixes: bstr, hashes: [ *bstr ] ]
    QCBOREncode_OpenArray(encoder);
    QCBOREncode_AddBytes(encoder, cbor::from_bytes(proof.prefixes.data()));
    QCBOREncode_OpenArray(encoder);
    for (auto& h : proof.hashes)
    {
      QCBOREncode_AddBytes(encoder, cbor::from_sha256_hash(h));
    }
    QCBOREncode_CloseArray(encoder);
    QCBOREncode_CloseArray(encoder);

    encode_receipt_contents(encoder, ccf_receipt);

    QCBOREncode_CloseArray(encoder);

    return encoder.finish();
  }

  /**
   * TreeReceipt = [
   *    protected : empty_or_serialized_map,
   *    root: bstr,
   *    receipt: ReceiptContents,
   * ]
   */
  static std::vector<uint8_t> create_tree_receipt(
    std::span<const uint8_t> protected_headers,
    const crypto::Sha256Hash& root,
    ccf::ReceiptPtr ccf_receipt)
  {
    cbor::encoder encoder;
    QCBOREncode_OpenArray(encoder);

    QCBOREncode_AddBytes(encoder, cbor::from_bytes(protected_headers));
    QCBOREncode_AddBytes(encoder, cbor::from_sha256_hash(root));
    encode_receipt_contents(encoder, ccf_receipt);

    QCBOREncode_CloseArray(encoder);
    return encoder.finish();
  }
}
