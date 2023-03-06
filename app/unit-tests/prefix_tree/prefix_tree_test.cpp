// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "prefix_tree/prefix_tree.h"

#include "prefix_tree/test_common.h"

#include <ccf/crypto/hash_provider.h>
#include <gtest/gtest.h>
#include <rapidcheck.h>
#include <rapidcheck/gtest.h>

using namespace scitt::pt;

namespace
{
  constexpr size_t INDEX_SIZE = 2;
  typedef prefix_tree<uint64_t, crypto::Sha256Hash, INDEX_SIZE> tree_t;

  RC_GTEST_PROP(PrefixTreeTest, BatchInsertIsEquivalent, ())
  {
    auto entries = *rc::gen::arbitrary<std::vector<tree_t::leaf_t>>();

    tree_t t1;
    for (auto l : entries)
    {
      t1.insert(l);
    }
    auto h1 = t1.hash();

    sort_leaves(entries);
    tree_t t2;
    t2.insert(entries);
    auto h2 = t2.hash();

    RC_LOG() << t1.debug().dump(2);
    RC_LOG() << t2.debug().dump(2);
    RC_ASSERT(h1 == h2);
  }

  RC_GTEST_PROP(PrefixTreeTest, StreamIsEquivalent, ())
  {
    auto entries = *rc::gen::arbitrary<std::vector<tree_t::leaf_t>>();
    sort_leaves(entries);

    tree_t t;
    t.insert(entries);
    auto h1 = t.hash();

    tree_t::stream s;
    for (const auto& e : entries)
    {
      s.add(e);
    }
    auto h2 = s.hash();

    RC_LOG() << t.debug().dump(2);
    RC_ASSERT(h1 == h2);
  }

  RC_GTEST_PROP(PrefixTreeTest, ProspectiveInserterIsEquivalent, ())
  {
    auto initial = *rc::gen::arbitrary<std::vector<tree_t::leaf_t>>();
    auto additional = *rc::gen::arbitrary<std::vector<tree_t::leaf_t>>();
    sort_leaves(initial);
    sort_leaves(additional);

    tree_t t;
    t.insert(initial);
    RC_LOG() << t.debug().dump(2);

    auto i = t.prospective_insert();
    for (const auto& e : additional)
    {
      i.add(e);
    }
    auto h1 = i.hash();

    t.insert(additional);
    auto h2 = t.hash();

    RC_LOG() << t.debug().dump(2);
    RC_ASSERT(h1 == h2);
  }

  RC_GTEST_PROP(PrefixTreeTest, PathHasSameHash, ())
  {
    auto leaves = *rc::gen::arbitrary<std::vector<tree_t::leaf_t>>();
    sort_leaves(leaves);

    tree_t t;
    t.insert(leaves);
    RC_LOG() << t.debug().dump(2);

    // Pick an arbitrary index among the leaves that we have inserted
    bitvector<INDEX_SIZE> index = (*rc::gen::elementOf(leaves)).index;

    // We can't just use the value from the leaf that was picked, as a later
    // insertion in the tree may have overwritten it. Search in `leaves` in
    // reverse order for the last entry with that index.
    auto it = std::find_if(leaves.rbegin(), leaves.rend(), [&](const auto& l) {
      return l.index == index;
    });
    RC_ASSERT(it != leaves.rend());

    auto result = t.find(index);
    RC_ASSERT(result.has_value());
    RC_ASSERT(result->second == it->value);

    tree_t::path_t p = result->first;
    RC_LOG() << p.debug().dump(2);
    RC_ASSERT(p.hashes.size() == p.prefixes.count_ones());

    // Recompute the root's hash from the leaf hash and the inclusion proof.
    // This should match the tree's root.
    auto h1 = p.hash(index, it->hash);
    auto h2 = t.hash();

    RC_ASSERT(h1 == h2);
  }

  RC_GTEST_PROP(PrefixTreeTest, FindReturnsNullWhenMissing, ())
  {
    auto leaves = *rc::gen::arbitrary<std::vector<tree_t::leaf_t>>();
    sort_leaves(leaves);

    tree_t t;
    t.insert(leaves);

    auto index = *rc::gen::suchThat<bitvector<INDEX_SIZE>>(
      [&](const auto& index) { return !contains_index(leaves, index); });

    auto result = t.find(index);
    RC_ASSERT(!result.has_value());
  }
}
