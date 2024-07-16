// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "cose.h"
#include "prefix_tree/batched_prefix_tree.h"
#include "prefix_tree/kv_types.h"
#include "prefix_tree/prefix_tree.h"
#include "prefix_tree/read_receipt.h"

#include <ccf/crypto/hash_provider.h>
#include <ccf/indexing/strategy.h>
#include <ccf/tx_id.h>
#include <deque>
#include <shared_mutex>

namespace scitt
{
  /**
   * Compute the index used to look up in the prefix tree.
   *
   * It is defined as sha256(cbor_encode([ issuer, feed ])), where cbor_encode
   * uses canonical encoding, and issue and feed are text strings.
   */
  static pt::bitvector<32> hash_key(
    std::string_view issuer, std::string_view feed)
  {
    cbor::hasher hasher;
    hasher.open_array(2);
    hasher.add_text(issuer);
    hasher.add_text(feed);
    return hasher.finalise().h;
  }

  /**
   * Compute the hash of a prefix tree leaf.
   *
   * This is defined as sha256(index || digest), where digest is the hash of the
   * COSE TBS bytes of the entry.
   */
  static ccf::crypto::Sha256Hash hash_leaf(
    pt::bitvector<32> index, const ccf::crypto::Sha256Hash& digest)
  {
    auto h = ccf::crypto::make_incremental_sha256();
    h->update_hash(index.data());
    h->update_hash(digest.h);
    return h->finalise();
  }

  /**
   * An indexing strategy over the ledger that keeps the latest entry for a
   * given issuer and claim in a prefix tree. The root of the prefix tree itself
   * gets committed to the ledger, producing a typical CCF receipt. From the
   * prefix tree receipt and an inclusion proof, a "read receipt" can be
   * derived, providing cryptographic evidence about what the latest claim for a
   * given issuer and claim is.
   *
   * The indexing strategy works by hooking up into CCF and getting notified any
   * time a new transaction is globally committed to the ledger.
   *
   * When a claim is submitted to SCITT, it is written to the ledger and is
   * eventually committed globally (barring any leadership election or
   * conflicting writes). When this happens, a reference to the claim is added
   * to a queue of pending entries, waiting to be inserted to the prefix tree.
   *
   * An external trigger can start the flushing process, in which an updated
   * prefix tree root hash is computed and written to the ledger. The actual
   * in-memory prefix tree is not modified yet, as the ledger transaction could
   * still fail. Only once the indexing strategy witnesses the root hash having
   * been globally committed does it update the prefix tree.
   *
   * If a new node joins the network, or a disaster recovery is performed, the
   * entire ledger must be replayed in order to reconstruct the indexing
   * strategy's state. Eventually, we should add a snapshotting mechanism by
   * serializing the prefix tree to disk.
   *
   * This class performs synchronization internally, and is safe to call
   * concurrently.
   */
  class PrefixTreeIndexingStrategy : public ccf::indexing::Strategy
  {
  public:
    PrefixTreeIndexingStrategy() : Strategy("PrefixTreeIndexingStrategy") {}

    /**
     * Start the process of flushing pending entries to the prefix tree.
     * Returns the tree's would-be root hash and upper bound.
     *
     * This method does not have any side effects: the caller is responsible for
     * writing the returned hash to the ledger and setting an appropriate claims
     * digest for this transaction. Only once the transaction is globally
     * committed will the tree be modified.
     */
    pt::summary<> prepare_flush() const
    {
      std::shared_lock l1(pending_mutex_);
      std::unique_lock l2(tree_mutex_);

      return tree.prepare_flush();
    }

    /**
     * Get the sequence number and summary of the last prefix tree root to have
     * been indexed. The caller may use the sequence number to fetch a CCF
     * receipt for the relevant transaction.
     *
     * Returns std::nullopt if no prefix tree commit has been indexed yet.
     */
    std::optional<std::pair<ccf::SeqNo, pt::summary<>>> current() const
    {
      std::shared_lock l(tree_mutex_);

      if (prefix_tree_seqno_ == 0)
      {
        return std::nullopt;
      }
      else
      {
        return {{prefix_tree_seqno_, tree.current()}};
      }
    }

    nlohmann::json debug() const
    {
      std::shared_lock l1(pending_mutex_);
      std::shared_lock l2(tree_mutex_);

      return tree.debug();
    }

    struct Entry
    {
      // Header parameters associated with this entry.
      // This will include the seqno of the tx that submitted the claim.
      std::vector<uint8_t> headers;

      // The sequence number of the commit that wrote the tree root to the
      // ledger. A historical query may be used to retrieve a CCF receipt for
      // this transaction.
      ccf::SeqNo prefix_tree_seqno;

      // An prefix-tree inclusion proof, connecting the entry to the tree's root
      // hash.
      pt::path<> proof;
    };

    /**
     * Look up an entry in the prefix-tree by issuer and feed, and return
     * components necessary to derive a read receipt.
     */
    std::optional<Entry> get(std::string_view issuer, std::string_view feed)
    {
      std::shared_lock l(tree_mutex_);

      pt::bitvector<32> index = hash_key(issuer, feed);
      auto result = tree.find(index);
      if (!result.has_value())
      {
        return std::nullopt;
      }

      Entry e;
      e.prefix_tree_seqno = prefix_tree_seqno_;
      e.proof = result->first;
      e.headers = result->second;
      return e;
    }

    std::optional<ccf::SeqNo> next_requested() override
    {
      return last_seqno_ + 1;
    }

    /**
     * This method is part of the indexing strategy interface, and gets called
     * by CCF whenever a transaction is committed globally.
     *
     * Unintuitively, `store` is a materialization of that particular
     * transaction only, and does not include any previously written key-values.
     *
     * CCF does not apply any filtering and will call this method no matter what
     * transaction was committed, even if unrelated to the prefix tree
     * operation. We check for the presence of KVs in tables of interest to
     * determine whether the transaction is relevant to us or not.
     */
    void handle_committed_transaction(
      const ccf::TxID& tx_id, const ccf::kv::ReadOnlyStorePtr& store) override
    {
      last_seqno_ = tx_id.seqno;

      auto tx = store->create_read_only_tx();
      auto entry = tx.template ro<EntryTable>(ENTRY_TABLE)->get();
      if (entry.has_value())
      {
        CCF_APP_INFO("Found SCITT entry at {}", tx_id.seqno);
        cose::ProtectedHeader phdr;
        try
        {
          phdr = std::get<0>(cose::decode_headers(*entry));
        }
        catch (const cose::COSEDecodeError& e)
        {
          CCF_APP_INFO(
            "Could not decode entry at {}: {}", tx_id.seqno, e.what());
          return;
        }

        if (phdr.issuer.has_value())
        {
          submit(tx_id.seqno, *entry, *phdr.issuer, phdr.feed.value_or(""));
        }
        else
        {
          CCF_APP_INFO(
            "SCITT entry at {} does not have an issuer", tx_id.seqno);
          return;
        }
      }

      // A new prefix tree root hash was globally committed. We update our
      // in-memory representation to the new version.
      auto info = tx.template ro<PrefixTreeTable>(PREFIX_TREE_TABLE)->get();
      if (info.has_value())
      {
        flush(tx_id, *info);
      }
    }

  private:
    /**
     * Submit a new entry to be included in the prefix tree. The entry is added
     * to the set of pending entries.
     *
     * This method is called by `handle_committed_transaction` when a write to
     * the claims table is globally committed.
     */
    void submit(
      ccf::SeqNo seqno,
      std::span<const uint8_t> claim,
      std::string_view issuer,
      std::string_view feed)
    {
      std::unique_lock l(pending_mutex_);

      pt::bitvector<32> index = hash_key(issuer, feed);
      CCF_APP_INFO(
        "Submitting entry to PT seqno={} issuer={} feed={} hash={}",
        seqno,
        issuer,
        feed,
        ccf::ds::to_hex(index.data()));

      auto headers = create_read_receipt_protected_header(seqno);
      auto digest = cose::create_countersign_tbs_hash(claim, headers);
      pt::leaf<std::vector<uint8_t>> leaf{
        index,
        headers,
        hash_leaf(index, digest),
      };
      tree.submit(seqno, leaf);
    }

    /**
     * Flush pending entries to the prefix tree.
     *
     * This method is called by `handle_committed_transaction` when a write to
     * the prefix tree table is globally committed.
     */
    void flush(ccf::TxID tx_id, const PrefixTreeInfo& info)
    {
      std::unique_lock l1(pending_mutex_);
      std::unique_lock l2(tree_mutex_);

      tree.flush(info.upper_bound);
      prefix_tree_seqno_ = tx_id.seqno;

      CCF_APP_INFO(
        "Flushed prefix tree seqno={} upper_bound={}",
        tx_id.seqno,
        info.upper_bound);
    }

    pt::batched_prefix_tree<std::vector<uint8_t>> tree;

    // The seqno of the latest globally committed prefix tree root.
    // This will be zero until at least one PT flush gets indexed.
    ccf::SeqNo prefix_tree_seqno_ = 0;

    // This is the latest seqno witnessed by this indexing strategy.
    // We don't use this in any clever way, it's only purpose is for CCF to know
    // what to feed us.
    ccf::SeqNo last_seqno_ = 0;

    // Pair of read-write mutexes used to synchronize access to the prefix tree.
    // See `batched_prefix_tree.h` for a discussion on what locks each operation
    // needs.
    //
    // To prevent deadlocks, if both mutexes need to be acquired, then
    // pending_mutex_ is always acquired first (this is arbitrary but needs to
    // be consistent throughout).
    mutable std::shared_mutex pending_mutex_;
    mutable std::shared_mutex tree_mutex_;
  };
}
