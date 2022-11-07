// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <ccf/crypto/pem.h>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace scitt
{
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
}
