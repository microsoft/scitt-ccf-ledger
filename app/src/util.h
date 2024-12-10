// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <ccf/crypto/entropy.h>
#include <ccf/crypto/pem.h>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace scitt
{
  const static ccf::crypto::EntropyPtr ENTROPY = ccf::crypto::get_entropy();

  template <typename T, typename U>
  bool contains(const std::vector<T>& v, const U& e)
  {
    return std::find(v.begin(), v.end(), e) != v.end();
  }

  template <typename K, typename T>
  bool contains(const std::unordered_map<K, T>& v, const K& e)
  {
    return v.find(e) != v.end();
  }

  // From Microsoft's GSL utilities.
  template <class F>
  class final_action
  {
  public:
    explicit final_action(const F& ff) noexcept : f{ff} {}
    explicit final_action(F&& ff) noexcept : f{std::move(ff)} {}

    ~final_action() noexcept
    {
      if (invoke)
      {
        f();
      }
    }

    final_action(final_action&& other) noexcept :
      f(std::move(other.f)),
      invoke(std::exchange(other.invoke, false))
    {}

    final_action(const final_action&) = delete;
    void operator=(const final_action&) = delete;
    void operator=(final_action&&) = delete;

  private:
    F f;
    bool invoke = true;
  };

  template <class F>
  [[nodiscard]] auto finally(F&& f) noexcept
  {
    return final_action<std::decay_t<F>>{std::forward<F>(f)};
  }
}
