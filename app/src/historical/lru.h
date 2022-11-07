// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include <list>
#include <map>

/**
 * A variant of CCF's LRU cache implementation that calls a user-defined
 * function whenever an element is evicted from the cache.
 *
 * See https://github.com/microsoft/CCF/blob/main/src/ds/lru.h for the original.
 *
 * The search methods (begin, end, find, contains) do _not_ count as access and
 * do not alter the recently used order. Only insert() and operator[] modify the
 * order.
 */
template <typename K, typename V>
class LRU
{
public:
  using Entry = std::pair<const K, V>;
  using List = std::list<Entry>;
  using Map = std::map<K, typename List::iterator>;
  using Iterator = typename List::iterator;
  using ConstIterator = typename List::const_iterator;

private:
  // Entries are ordered by when they were most recently accessed, with most
  // recent at the front
  List entries_list;

  // Maps from keys to iterators from entries_list, which must remain valid even
  // when entries_list is modified
  Map iter_map;

  size_t max_size;

  std::function<void(const K&, const V&)> cull_callback_fn;

  void cull()
  {
    while (entries_list.size() > max_size)
    {
      const auto& least_recent_entry = entries_list.back();
      iter_map.erase(least_recent_entry.first);
      entries_list.pop_back();
      if (cull_callback_fn)
      {
        cull_callback_fn(least_recent_entry.first, least_recent_entry.second);
      }
    }
  }

public:
  LRU(size_t max_size) : max_size(max_size) {}

  void set_cull_callback(std::function<void(const K&, const V&)> fn)
  {
    cull_callback_fn = fn;
  }

  size_t size() const
  {
    return iter_map.size();
  }

  void set_max_size(size_t ms)
  {
    max_size = ms;
    cull();
  }

  size_t get_max_size() const
  {
    return max_size;
  }

  Iterator begin()
  {
    return entries_list.begin();
  }

  Iterator end()
  {
    return entries_list.end();
  }

  ConstIterator begin() const
  {
    return entries_list.begin();
  }

  ConstIterator end() const
  {
    return entries_list.end();
  }

  Iterator find(const K& k)
  {
    const auto it = iter_map.find(k);
    if (it != iter_map.end())
    {
      return it->second;
    }

    return entries_list.end();
  }

  bool contains(const K& k) const
  {
    const auto it = iter_map.find(k);
    return it != iter_map.end();
  }

  Iterator insert(const K& k, V&& v)
  {
    auto it = iter_map.find(k);
    if (it != iter_map.end())
    {
      // If it already exists, move to the front
      auto& list_it = it->second;
      entries_list.splice(entries_list.begin(), entries_list, list_it);
    }
    else
    {
      // Else add a new entry to both containers, and cull if necessary
      entries_list.push_front(std::make_pair(k, std::forward<V>(v)));
      const auto list_it = entries_list.begin();
      iter_map.emplace_hint(it, k, list_it);
      cull();
    }

    return entries_list.begin();
  }

  V& operator[](K&& k)
  {
    auto it = insert(std::forward<K>(k), V{});
    return it->second;
  }

  void clear()
  {
    entries_list.clear();
    iter_map.clear();
  }
};
