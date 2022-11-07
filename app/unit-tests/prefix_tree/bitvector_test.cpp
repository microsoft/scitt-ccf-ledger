// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "prefix_tree/bitvector.h"

#include "prefix_tree/test_common.h"

#include <gtest/gtest.h>
#include <rapidcheck.h>
#include <rapidcheck/gtest.h>

using namespace scitt::pt;
namespace
{
  static constexpr size_t SIZE = 4;

  // This is equivalent to `cmp == std::partial_ordering::unordered`.
  // Our version of libc++ doesn't implement that operator yet.
  bool is_unordered(std::partial_ordering cmp)
  {
    return !std::is_eq(cmp) && !std::is_lt(cmp) && !std::is_gt(cmp);
  }

  RC_GTEST_PROP(Bitvector, PrefixSize, ())
  {
    auto bits = *rc::gen::arbitrary<bitvector<SIZE>>();
    auto n = *rc::gen::inRange<size_t>(0, bits.size());
    auto prefix = bits.first(n);

    RC_ASSERT(prefix.size() == n);
  }

  RC_GTEST_PROP(Bitvector, PrefixBits, ())
  {
    auto bits = *rc::gen::arbitrary<bitvector<SIZE>>();
    auto n = *rc::gen::inRange<size_t>(0, bits.size());
    auto prefix = bits.first(n);

    for (size_t i = 0; i < n; i++)
    {
      RC_ASSERT(bits.bit(i) == prefix.bit(i));
    }
  }

  RC_GTEST_PROP(Bitvector, StartsWithPrefix, ())
  {
    auto bits = *rc::gen::arbitrary<bitvector<SIZE>>();
    auto n = *rc::gen::inRange<size_t>(0, bits.size());
    auto prefix = bits.first(n);

    RC_ASSERT(bits.bitstring().starts_with(prefix.bitstring()));
  }

  RC_GTEST_PROP(Bitvector, StrictPrefixIsUnordered, ())
  {
    auto bits = *rc::gen::arbitrary<bitvector<SIZE>>();
    auto n = *rc::gen::inRange<size_t>(0, bits.size());
    auto prefix = bits.first(n);

    RC_ASSERT(is_unordered(prefix <=> bits));
    RC_ASSERT(is_unordered(bits <=> prefix));
  }

  RC_GTEST_PROP(Bitvector, CommonPrefix, ())
  {
    auto bits1 = *rc::gen::arbitrary<bitvector<SIZE>>();
    auto bits2 = *rc::gen::arbitrary<bitvector<SIZE>>();

    size_t n = common_prefix(bits1, bits2);
    for (size_t i = 0; i < n; i++)
    {
      RC_ASSERT(bits1.bit(i) == bits2.bit(i));
    }

    if (n < bits1.size())
    {
      RC_ASSERT(bits1.bit(n) != bits2.bit(n));
    }
  }

  RC_GTEST_PROP(Bitvector, BijectivePrefixEncoding, ())
  {
    // bits1 and bits2 may have different lengths
    auto bits1 = *rc::gen::arbitrary<bitprefix<SIZE>>();
    auto bits2 = *rc::gen::arbitrary<bitprefix<SIZE>>();

    // Given two prefixes, they have the same encoding (padding included) if and
    // only if they are equal.
    RC_ASSERT((bits1 == bits2) == (bits1.data() == bits2.data()));
  }

  RC_GTEST_PROP(Bitvector, OrderingIsConsistent, ())
  {
    auto bits1 = *rc::gen::arbitrary<bitvector<SIZE>>();
    auto bits2 = *rc::gen::arbitrary<bitvector<SIZE>>();

    // This is a handy property to have, since it means you can sort leaf
    // indices by sorting their encoding instead.
    RC_ASSERT((bits1 < bits2) == (bits1.data() < bits2.data()));

    // This works because '0' < '1', both as bits and in ASCII.
    RC_ASSERT((bits1 < bits2) == (bits1.bitstring() < bits2.bitstring()));
  }
}
