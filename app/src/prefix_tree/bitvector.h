// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <ccf/ccf_assert.h>
#include <compare>

namespace scitt::pt
{
  enum class IsPrefix
  {
    No,
    Yes,
    Maybe,
  };

  /**
   * A vector of bits.
   *
   * The vector has a compile-time constant capacity, measured in bytes.
   *
   * Depending on the IsPrefix parameter, a vector may either have a constant
   * length, equal to the capacity (IsPrefix::No), a dynamic length that is
   * strictly less than the capacity (IsPrefix::Yes), or a dynamic length that
   * is less than or equal to the capacity (IsPrefix::Maybe).
   */
  template <size_t CAPACITY, IsPrefix IsPrefix = IsPrefix::No>
  struct bitvector
  {
    bitvector() requires(IsPrefix == IsPrefix::No) = default;

    bitvector(std::array<uint8_t, CAPACITY> data) requires(
      IsPrefix == IsPrefix::No) :
      data_(data)
    {}

    /**
     * Construct a strict prefix. Any data past the given size will be ignored,
     * and replaced by a deterministic and injective padding.
     */
    explicit bitvector(
      std::array<uint8_t, CAPACITY> data,
      size_t size) requires(IsPrefix == IsPrefix::Yes) :
      size_(size)
    {
      CCF_ASSERT_FMT(
        size < CAPACITY * 8,
        "bitslice size overflow: {} >= {}",
        size,
        CAPACITY * 8);

      size_t bytes = size / 8;
      size_t bits = size % 8;
      for (size_t i = 0; i < bytes; i++)
      {
        data_[i] = data[i];
      }

      // We need to add a trailing 1 and zero out the rest.
      // This ensures the padding is injective.
      uint8_t padding = 0x80 >> bits;
      uint8_t mask = ~(padding - 1);
      data_[bytes] = (data[bytes] & mask) | padding;
    }

    explicit bitvector(
      std::array<uint8_t, CAPACITY> data,
      size_t size) requires(IsPrefix == IsPrefix::Maybe) :
      data_(data),
      size_(size)
    {
      CCF_ASSERT_FMT(
        size <= CAPACITY * 8,
        "bitslice size overflow: {} >= {}",
        size,
        CAPACITY * 8);
    }

    bool bit(uint8_t index) const
    {
      CCF_ASSERT_FMT(
        index < size(),
        "bitvector out-of-range access: {} >= {}",
        index,
        size());

      uint8_t mask = 0x80 >> (index % 8);
      return data_[index / 8] & mask;
    }

    void set_bit(uint8_t index, bool value)
    {
      CCF_ASSERT_FMT(
        index < size(),
        "bitvector out-of-range access: {} >= {}",
        index,
        size());

      uint8_t mask = 0x80 >> (index % 8);
      if (value)
      {
        data_[index / 8] |= mask;
      }
      else
      {
        data_[index / 8] &= ~mask;
      }
    }

    /**
     * Count the number of set bits.
     */
    size_t count_ones() const
    {
      size_t n = 0;
      for (size_t i = 0; i < size(); i++)
      {
        if (bit(i))
        {
          n++;
        }
      }
      return n;
    }

    /**
     * Return the underlying data.
     *
     * If this is a prefix, the data will have a deterministic, injective
     * padding, consisting of a 1 followed by as many zeros as necessary. This
     * property ensures that distinct prefixes have distinct encodings, guarding
     * against collision attacks, even when one prefix is a sub-prefix of the
     * other. For example, '01' and '010' are respectively encoded as '01100000'
     * and '01010000'
     *
     * This method is disabled if this may or may not be a prefix. In those
     * cases, the encoding alone (without the size) would be ambiguous.
     */
    const std::array<uint8_t, CAPACITY>& data() const
      requires(IsPrefix != IsPrefix::Maybe)
    {
      return data_;
    }

    /**
     * Return the size of the bitvector, in number of bits.
     */
    size_t size() const
    {
      if constexpr (IsPrefix == IsPrefix::No)
      {
        return 8 * CAPACITY;
      }
      else
      {
        return size_;
      }
    }

    /**
     * Return a prefix of the bitvector.
     *
     * This must always form a valid prefix, that is count must be strictly less
     * than the total capacity.
     */
    bitvector<CAPACITY, IsPrefix::Yes> first(size_t count) const
    {
      CCF_ASSERT_FMT(count < 8 * CAPACITY, "must be a valid prefix");
      CCF_ASSERT_FMT(
        count <= size(),
        "bitslice out-of-range access: {} > {}",
        count,
        size());

      return bitvector<CAPACITY, IsPrefix::Yes>(data_, count);
    }

    /**
     * Equality operator, automatically derived by directly comparing the
     * encodings.
     *
     * This is not defined for IsPrefix::Maybe, as the padding in that case is
     * not deterministic. We would have to restrict the comparison to the actual
     * prefix.
     */
    bool operator==(const bitvector<CAPACITY, IsPrefix>&) const
      requires(IsPrefix != IsPrefix::Maybe) = default;

    /**
     * Three-way comparison of bitvectors, using lexicographic order.
     * Bit 0 is the most significant.
     *
     * The two vectors need not have the same length.
     * For example, 000 < 0010 < 010.
     *
     * In the general case, this is a partial ordering: if one bitvector is a
     * strict prefix of the other then the two are unordered.
     * If neither bitvectors could be a prefix, then a strong_ordering is
     * returned.
     *
     * TODO: For IsPrefix::No, we should be able to produce the same result be
     * comparing the encoding directly (the ordering is consistent). Need to
     * benchmark to see if there are any benefits to this.
     */
    template <enum IsPrefix Other>
    std::conditional_t<
      (IsPrefix == IsPrefix::No) && (Other == IsPrefix::No),
      std::strong_ordering,
      std::partial_ordering>
    operator<=>(const bitvector<CAPACITY, Other>& other) const
    {
      for (size_t i = 0; i < std::min(size(), other.size()); i++)
      {
        if (!bit(i) && other.bit(i))
        {
          return std::strong_ordering::less;
        }
        else if (bit(i) && !other.bit(i))
        {
          return std::strong_ordering::greater;
        }
      }

      if constexpr ((IsPrefix == IsPrefix::No) && (Other == IsPrefix::No))
      {
        return std::strong_ordering::equal;
      }
      else if (size() == other.size())
      {
        return std::strong_ordering::equivalent;
      }
      else
      {
        return std::partial_ordering::unordered;
      }
    }

    /**
     * Returns a textual representation of the bitvector.
     *
     * This is intended for displaying and debugging purposes, not as a stable
     * interchange format.
     */
    std::string bitstring() const
    {
      std::string s;
      for (size_t i = 0; i < size(); i++)
      {
        if (bit(i))
        {
          s += '1';
        }
        else
        {
          s += '0';
        }
      }
      return s;
    }

    operator bitvector<CAPACITY, IsPrefix::Maybe>() const
    {
      return bitvector<CAPACITY, IsPrefix::Maybe>(data(), size());
    }

  private:
    std::array<uint8_t, CAPACITY> data_ = {};

    // If this is definitely not a prefix, the size is constant and equal to
    // the capacity. The size field can be just a monostate.
    //
    // We use the no_unique_address annotation to make sure the monostate
    // doesn't occupy any space. There is a static_assert further down that
    // check that a bitvector<32> is in fact just 32 bytes.
    //
    // TODO: For IsPrefix::Yes, we could actually infer the size by counting the
    // number of trailing zeros in the padding. Need to benchmark whether the
    // overhead is worth the space savings.
    [[no_unique_address]] std::
      conditional_t<IsPrefix == IsPrefix::No, std::monostate, size_t>
        size_;
  };

  template <size_t CAPACITY>
  bitvector(std::array<uint8_t, CAPACITY>) -> bitvector<CAPACITY>;

  template <size_t CAPACITY>
  using bitprefix = bitvector<CAPACITY, IsPrefix::Yes>;

  template <size_t CAPACITY>
  using bitslice = bitvector<CAPACITY, IsPrefix::Maybe>;

  // This ensures the [[no_unique_address]] optimisation is working as intended,
  // and we are using just the right amount of space.
  static_assert(sizeof(bitvector<32>) == 32);

  /**
   * Compute the number of common prefix bits between two bitvectors.
   *
   * For simplicity, we only consider the case where the bitvectors are
   * non-prefixes themselves.
   */
  template <size_t SIZE>
  size_t common_prefix(const bitvector<SIZE>& lhs, const bitvector<SIZE>& rhs)
  {
    size_t i = 0;
    while (i < SIZE * 8 && lhs.bit(i) == rhs.bit(i))
    {
      i++;
    }
    return i;
  }
}
