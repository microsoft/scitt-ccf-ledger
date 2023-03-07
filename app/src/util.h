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
  const static crypto::EntropyPtr ENTROPY = crypto::create_entropy();

  static std::vector<crypto::Pem> split_x509_cert_bundle(
    const std::string_view& pem)
  {
    std::string separator("-----END CERTIFICATE-----");
    std::vector<crypto::Pem> pems;
    auto separator_end = 0;
    auto next_separator_start = pem.find(separator);
    while (next_separator_start != std::string_view::npos)
    {
      pems.emplace_back(std::string(
        pem.substr(separator_end, next_separator_start + separator.size())));
      separator_end = next_separator_start + separator.size();
      next_separator_start = pem.find(separator, separator_end);
    }
    return pems;
  }

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
