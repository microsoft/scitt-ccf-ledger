// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <ccf/kv/value.h>
#include <ccf/tx_id.h>
#include <vector>

namespace scitt
{
  struct PrefixTreeInfo
  {
    ccf::SeqNo upper_bound;
    std::vector<uint8_t> protected_headers;
  };
  DECLARE_JSON_TYPE(PrefixTreeInfo);
  DECLARE_JSON_REQUIRED_FIELDS(PrefixTreeInfo, upper_bound, protected_headers);

  static constexpr auto PREFIX_TREE_TABLE = "public:scitt.prefix_tree";
  using PrefixTreeTable = ccf::kv::Value<PrefixTreeInfo>;
}
