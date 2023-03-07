// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "historical/lru.h"

#include <gtest/gtest.h>
#include <iostream>
#include <nlohmann/json.hpp>
#include <rapidcheck.h>
#include <rapidcheck/gtest.h>
#include <span>
#include <unordered_map>
#include <vector>

// Defining this in the std namespace is bad form, but it seems to be required
// because RapidCheck uses ADL to find showValue.
// NOLINTNEXTLINE(cert-dcl58-cpp)
namespace std
{
  template <typename T>
  void showValue(optional<T> value, ostream& os)
  {
    if (value.has_value())
    {
      os << "optional(" << rc::toString(*value) << ")";
    }
    else
    {
      os << "nullopt";
    }
  }
}

namespace
{
  /**
   * Take a history of insertions into the cache, and compute what the current
   * state of the cache should be, as well as whether a key was evicted during
   * the last insertion.
   */
  template <typename K, typename V>
  std::pair<std::map<K, V>, std::optional<std::pair<K, V>>> recent_keys(
    size_t n, std::span<const std::pair<K, V>> history)
  {
    bool update = false;
    std::map<K, V> result;

    // Iterate over the history backwards, until we find N+1 unique keys.
    // The last one we found is the entry that was evicted.
    auto it = history.rbegin();
    for (; it != history.rend(); it++)
    {
      // The last element to have been inserted already existed earlier in the
      // history: this was an in-place update and did not cause any eviction.
      if (it != history.rbegin() && it->first == history.rbegin()->first)
      {
        update = true;
      }

      if (result.size() == n && update)
      {
        return {result, std::nullopt};
      }
      else if (result.size() == n && !result.contains(it->first))
      {
        // This is the N+1th unique key, ie. the one that got evicted.
        return {result, *it};
      }
      else
      {
        // This does not overwrite the entry if it is already present.
        // This matches our expectation since entries later in the history (ie.
        // earlier in iteration order) take precedence.
        result.emplace(it->first, it->second);
      }
    }

    // If we reach this point then there are not enough keys in the history to
    // fill the cache. Nothing gets evicted.
    return {result, std::nullopt};
  }

  RC_GTEST_PROP(
    LRUTest,
    lru_cache,
    (size_t capacity, const std::vector<std::pair<int, int>>& insertions))
  {
    RC_PRE(capacity > 0);
    LRU<int, int> cache(capacity);
    std::optional<std::pair<int, int>> last_culled;

    cache.set_cull_callback([&last_culled](int k, int v) {
      last_culled = {{k, v}};
    });

    for (size_t i = 0; i < insertions.size(); i++)
    {
      last_culled.reset();
      auto [k, v] = insertions.at(i);
      cache[k] = v;

      auto history = std::span(insertions).first(i + 1);
      auto [expected_state, expected_victim] = recent_keys(capacity, history);

      RC_LOG() << "i=" << i << " insert=" << rc::toString(std::make_pair(k, v))
               << " expected_state=" << rc::toString(expected_state)
               << " expected_evicted=" << rc::toString(expected_victim)
               << " last_culled=" << rc::toString(last_culled) << std::endl;

      RC_ASSERT(expected_victim == last_culled);
      RC_ASSERT(expected_state.size() == cache.size());
      for (const auto& [k, v] : expected_state)
      {
        // Thankfully, lookups in the cache have no side effect.
        auto it = cache.find(k);
        RC_ASSERT(it != cache.end());
        RC_ASSERT(it->second == v);
      }
    }
  }
}
