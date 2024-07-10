// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "prefix_tree/prefix_tree.h"

#include <ccf/tx_id.h>
#include <set>

namespace scitt::pt
{
  template <
    typename SeqNoT = ccf::SeqNo,
    typename HashT = ccf::crypto::Sha256Hash>
  struct summary
  {
    SeqNoT upper_bound;
    HashT hash;
    bool operator==(const summary&) const = default;
  };

  /**
   * A wrapper around a prefix tree which allows leaves to be added in batches.
   *
   * When a new entry is added by called `submit()`, it is added to a queue of
   * pending entries. As long as the batched tree isn't flushed, the underlying
   * tree is unmodified, and lookup operations done by calling the `find()`
   * method will be unaffected by the pending entries.
   *
   * At any point, `prepare_flush()` may be called to determine what the root
   * hash would be if a flush were issued, without actually changing the
   * underlying tree.
   *
   * Eventually, `flush()` may be called, moving entries from the pending
   * queue to the actual prefix tree. In order for the operation of
   * `prepare_flush()` and `flush()` to be consistent, `prepare_flush` also
   * returns the upper bound of all pending sequence numbers, and `flush`
   * accepts an upper bound as an argument. Only entries with a lower sequence
   * number will be flushed.
   *
   * The batched_prefix_tree does not perform any synchronization to prevent
   * data-races. It is up to the caller to perform the appropriate
   * synchronization, using a pair a read-writer locks, one for the pending
   * queue and one for the underlying prefix tree. The table below summarizes
   * which resources are used by each method.
   *
   *            | Pending Queue | Prefix Tree
   * -----------------------------------------
   *  submit    |  read-write   |
   *  prepare   |  read-only    |  read-only
   *  flush     |  read-write   |  read-write
   *  find      |               |  read-only
   *  current   |               |  read-only
   *  debug     |  read-only    |  read-only
   *
   */
  template <
    typename ValueT,
    typename SeqNoT = ccf::SeqNo,
    typename HashT = ccf::crypto::Sha256Hash,
    size_t SIZE = 32>
  struct batched_prefix_tree
  {
    typedef prefix_tree<ValueT, HashT, SIZE> tree_t;
    typedef typename tree_t::leaf_t leaf_t;

    /**
     * Add a new entry to the pending queue.
     */
    void submit(SeqNoT seqno, leaf_t leaf)
    {
      CCF_ASSERT(
        seqno >= pending_upper_bound,
        "Sequence numbers must be strictly monotonically increasing");

      pending_upper_bound = seqno + 1;
      auto [_, inserted] = pending.insert({leaf, seqno});
      CCF_ASSERT(inserted, "Pending entries should be unique");
    }

    /**
     * Compute what the hash of the tree would be, if all pending
     * entries were added to it.
     *
     * In order for the hash to be reproducible through a call to `flush`, the
     * upper bound seqno of all pending entries is returned as well.
     */
    summary<SeqNoT, HashT> prepare_flush() const
    {
      auto i = tree.prospective_insert();
      for (const auto& entry : pending)
      {
        i.add(entry.leaf);
      }

      auto h = i.hash();
      return {pending_upper_bound, h};
    }

    /**
     * Move entries from the pending queue to the actual tree.
     *
     * Only entries whose seqno is strictly smaller than the given upper bound
     * will be flushed.
     */
    void flush(SeqNoT upper_bound)
    {
      CCF_ASSERT(
        upper_bound >= flushed_upper_bound, "Flushes must happen in order");

      // We use a batched insertion to avoid recomputing intermediate hashes
      // over and over again. This works because the pending entries are ordered
      // by index already.
      auto i = tree.start_insert();
      for (auto it = pending.begin(); it != pending.end();)
      {
        CCF_ASSERT(
          it->seqno >= flushed_upper_bound,
          "Pending entry is older than already flushed tree");

        if (it->seqno < upper_bound)
        {
          i.add(it->leaf);
          it = pending.erase(it);
        }
        else
        {
          it++;
        }
      }
      i.finish();
      flushed_upper_bound = upper_bound;
    }

    summary<SeqNoT, HashT> current() const
    {
      return {flushed_upper_bound, tree.hash()};
    }

    /**
     * Lookup a leaf by its index. Pending entries are not searched.
     */
    std::optional<
      std::pair<typename tree_t::path_t, std::reference_wrapper<const ValueT>>>
    find(const bitvector<SIZE>& index) const
    {
      return tree.find(index);
    }

    /**
     * Get an implementation-specific but structured representation of this
     * tree. This should be used for debugging purposes, and should not be
     * parsed as the format is subject to change.
     */
    nlohmann::json debug() const
    {
      nlohmann::json result;
      result["tree"] = tree.debug();
      result["pending"] = std::vector<nlohmann::json>();
      for (const auto& [key, value] : pending)
      {
        nlohmann::json entry;
        result["pending"].push_back({
          {"index", key.index.bitstring()},
          {"value", value},
        });
      }
      return result;
    }

  private:
    // We use an std::set to keep the pending entries, as this keeps them
    // ordered by index, a requirement for the prospective inserter.
    //
    // If a new leaf is submitted while a pending entry already existed for the
    // same index, we need to keep track of both entries, and cannot just
    // overwrite the older pending entry. This is because it is possible for a
    // flush operation's upper bound to only include the older one of the
    // entries. We still need to keep leaves with the same index ordered by
    // seqno to make sure they are added in the right order.
    struct pending_entry
    {
      leaf_t leaf;
      SeqNoT seqno;

      bool operator<(const pending_entry& other) const
      {
        return std::tie(leaf.index, seqno) <
          std::tie(other.leaf.index, other.seqno);
      }
    };
    std::set<pending_entry> pending;

    tree_t tree;

    SeqNoT pending_upper_bound = 0;
    SeqNoT flushed_upper_bound = 0;
  };
}
