// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "prefix_tree/batched_prefix_tree.h"

#include "prefix_tree/test_common.h"

#include <gtest/gtest.h>
#include <rapidcheck/gtest.h>
#include <rapidcheck/state.h>

using namespace scitt::pt;
namespace
{
  static constexpr size_t INDEX_SIZE = 2;
  typedef bitvector<INDEX_SIZE> index_t;
  typedef batched_prefix_tree<
    uint64_t,
    ccf::SeqNo,
    crypto::Sha256Hash,
    INDEX_SIZE>
    tree_t;

  /**
   * Unit testing for the batched prefix tree uses RapidCheck's stateful testing
   * facilities.
   *
   * We define a Model, which is a simplified representation of our system.
   *
   * A handful of `Command` subclasses are defined. Each command defines methods
   * to mutate both the Model and the actual system, and assert that the two
   * react equivalently.
   */
  struct Model
  {
    ccf::SeqNo next_seqno = 1;
    ccf::SeqNo flushed_upper_bound = 0;

    // The set of entries that are contained in the prefix tree.
    std::map<index_t, tree_t::leaf_t> entries;

    // Entries that are waiting to be flushed, with the seqno of the transaction
    // that created them.
    std::deque<std::pair<ccf::SeqNo, tree_t::leaf_t>> pending;

    // Pending flushes. This represents the CCF commit queue.
    // When a flush transaction is executed, it is added to the queue.
    // When the transaction is globally committed, it is removed.
    // Ordering is preserved, but transactions may be dropped (eg. a leader
    // election happened).
    std::deque<summary<>> flushes;

    /**
     * Compute the hash of the prefix tree formed by the entries.
     * Optionally includes the pending entries.
     */
    crypto::Sha256Hash hash(bool include_pending) const
    {
      prefix_tree<uint64_t, crypto::Sha256Hash, INDEX_SIZE> t;
      for (const auto& [_, leaf] : entries)
      {
        t.insert(leaf);
      }
      if (include_pending)
      {
        for (const auto& [_, leaf] : pending)
        {
          t.insert(leaf);
        }
      }
      return t.hash();
    }

    summary<> summary(bool include_pending) const
    {
      if (include_pending && !pending.empty())
      {
        // Seqnos are monotonic. The maximum is always the last element of the
        // pending queue.
        return {pending.back().first + 1, hash(true)};
      }
      else
      {
        return {flushed_upper_bound, hash(false)};
      }
    }
  };

  /**
   * Submit represents a new claim being globally committed.
   */
  struct Submit : public rc::state::Command<Model, tree_t>
  {
    explicit Submit() : leaf(*rc::gen::arbitrary<tree_t::leaf_t>()) {}

    void run(const Model& model, tree_t& tree) const override
    {
      tree.submit(model.next_seqno, leaf);
    }

    void apply(Model& model) const override
    {
      model.pending.push_back({model.next_seqno, leaf});
      model.next_seqno++;
    }

  private:
    tree_t::leaf_t leaf;
  };

  /**
   * PrepareFlush represents an external trigger to the `flush` endpoint.
   * This creates a flush transaction and adds it to the CCF commit queue.
   *
   * Having this command decoupled from the CommitFlush command allows a window
   * during which Submit and Get commands can be executed, as well as further
   * PrepareFlush commands.
   *
   * In practice this window represents the time it takes for CCF to replicate
   * and commit the transaction globally.
   */
  struct PrepareFlush : public rc::state::Command<Model, tree_t>
  {
    void run(const Model& model, tree_t& tree) const override
    {
      auto info = tree.prepare_flush();
      RC_ASSERT(model.summary(true) == info);
    }

    void apply(Model& model) const override
    {
      auto info = model.summary(true);
      model.flushes.push_back(info);
    }
  };

  /**
   * CommitFlush represents a flush transaction having been globally committed,
   * and observed by the indexing strategy. It pulls a transaction off the
   * commit queue and applies it to the batched prefix.
   */
  struct CommitFlush : public rc::state::Command<Model, tree_t>
  {
    void checkPreconditions(const Model& model) const override
    {
      RC_PRE(!model.flushes.empty());
    }

    void run(const Model& model, tree_t& tree) const override
    {
      auto info = model.flushes.front();
      tree.flush(info.upper_bound);
      RC_ASSERT(tree.current() == info);
    }

    void apply(Model& model) const override
    {
      auto info = model.flushes.front();
      model.flushes.pop_front();

      while (!model.pending.empty() &&
             model.pending.front().first < info.upper_bound)
      {
        auto [_, leaf] = model.pending.front();
        model.pending.pop_front();
        model.entries[leaf.index] = leaf;
      }
      model.flushed_upper_bound = info.upper_bound;
    }
  };

  /**
   * Rollback drops a transaction from the commit queue.
   *
   * This can represent situations such as a leader election or a write
   * conflict, where CCF just drops the transaction.
   */
  struct Rollback : public rc::state::Command<Model, tree_t>
  {
    void checkPreconditions(const Model& model) const override
    {
      RC_PRE(!model.flushes.empty());
    }

    void apply(Model& model) const override
    {
      model.flushes.pop_front();
    }
  };

  /**
   * Get looks up an arbitrary entry from the prefix tree and checks
   * consistency against the model.
   */
  struct Get : public rc::state::Command<Model, tree_t>
  {
    void run(const Model& model, tree_t& tree) const override
    {
      auto [index, leaf] = *rc::gen::elementOf(model.entries);
      auto result = tree.find(index);

      RC_ASSERT(result.has_value());
      RC_ASSERT(result->second == leaf.value);
      RC_ASSERT(result->first.hash(index, leaf.hash) == model.hash(false));
    }
  };

  /**
   * GetMissing looks up an inexistent entry from the prefix tree.
   */
  struct GetMissing : public rc::state::Command<Model, tree_t>
  {
    void run(const Model& model, tree_t& tree) const override
    {
      auto index = *rc::gen::suchThat<index_t>(
        [&](auto i) { return !model.entries.contains(i); });

      auto result = tree.find(index);
      RC_ASSERT(!result.has_value());
    }
  };

  /**
   * Perform stateful testing against a batched_prefix_tree.
   *
   * It will generate a stream of arbitrary commands to be executed against
   * the tree and the model.
   */
  RC_GTEST_PROP(BatchingPrefixTreeTest, BatchingPrefixTreeTest, ())
  {
    Model model;
    tree_t tree;

    auto commands = rc::state::gen::execOneOfWithArgs<
      Submit,
      PrepareFlush,
      CommitFlush,
      Rollback,
      Get,
      GetMissing>();

    rc::state::check(model, tree, commands);
  }
}
