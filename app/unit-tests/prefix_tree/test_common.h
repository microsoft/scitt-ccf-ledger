// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "prefix_tree/batched_prefix_tree.h"
#include "prefix_tree/prefix_tree.h"

#include <random>
#include <rapidcheck.h>

namespace scitt::pt
{
  template <typename ValueT, typename HashT, size_t SIZE>
  void sort_leaves(std::vector<leaf<ValueT, HashT, SIZE>>& leaves)
  {
    std::stable_sort(
      leaves.begin(), leaves.end(), [](const auto& l, const auto& r) {
        return l.index < r.index;
      });
  }

  /**
   * Returns true if a list of leaves contain the given index.
   */
  template <typename ValueT, typename HashT, size_t SIZE>
  bool contains_index(
    const std::vector<leaf<ValueT, HashT, SIZE>>& leaves,
    const bitvector<SIZE>& index)
  {
    auto it = std::find_if(leaves.begin(), leaves.end(), [&](const auto& l) {
      return l.index == index;
    });
    return it != leaves.end();
  }

  /**
   * The leaf hashing function used throughout unit tests.
   *
   * It assumes a uint64_t leaf value, and hashes over the key and value only.
   */
  template <size_t SIZE>
  crypto::Sha256Hash hash_leaf(
    const bitvector<SIZE>& key, const uint64_t& value)
  {
    auto h = crypto::make_incremental_sha256();
    h->update_hash(key.data());
    // This will be endian-specific. That's okay for unit tests, but should
    // not be used for production uses.
    h->update_hash({(const uint8_t*)&value, sizeof(value)});
    return h->finalise();
  }

  // Overloads for RapidCheck to be able to pretty-print these values.
  template <size_t SIZE, IsPrefix IsPrefix>
  void showValue(const bitvector<SIZE, IsPrefix>& b, std::ostream& os)
  {
    os << '\'' << b.bitstring() << '\'';
  }

  template <typename ValueT, typename HashT, size_t SIZE>
  void showValue(const leaf<ValueT, HashT, SIZE>& l, std::ostream& os)
  {
    os << "(";
    rc::show(l.index, os);
    os << ", ";
    rc::show(l.value, os);
    os << ", ";
    rc::show(l.hash, os);
    os << ")";
  }

  template <typename SeqNoT, typename HashT>
  void showValue(const summary<SeqNoT, HashT>& s, std::ostream& os)
  {
    os << "(" << s.upper_bound << ", " << s.hash << ")";
  }
}

namespace rc
{
  // Generate an arbitrary bitvector.
  template <size_t SIZE>
  struct Arbitrary<scitt::pt::bitvector<SIZE>>
  {
    static auto arbitrary()
    {
      return gen::construct<scitt::pt::bitvector<SIZE>>(
        gen::arbitrary<std::array<uint8_t, SIZE>>());
    }
  };

  // Generate an arbitrary bitprefix.
  // It will have an arbitrary length between 0 and 8*SIZE-1.
  template <size_t SIZE>
  struct Arbitrary<scitt::pt::bitprefix<SIZE>>
  {
    static auto arbitrary()
    {
      return gen::construct<scitt::pt::bitprefix<SIZE>>(
        gen::arbitrary<std::array<uint8_t, SIZE>>(),
        gen::inRange<size_t>(0, 8 * SIZE));
    }
  };

  // Generate an arbitrary leaf, assuming the leaf value is a uint64_t.
  template <size_t SIZE>
  struct Arbitrary<scitt::pt::leaf<uint64_t, crypto::Sha256Hash, SIZE>>
  {
    static auto arbitrary()
    {
      auto make_leaf = [](auto index, auto value) {
        return scitt::pt::leaf<uint64_t, crypto::Sha256Hash, SIZE>{
          index,
          value,
          scitt::pt::hash_leaf(index, value),
        };
      };

      return gen::apply(
        make_leaf,
        gen::arbitrary<scitt::pt::bitvector<SIZE>>(),
        gen::arbitrary<uint64_t>());
    }
  };
}
