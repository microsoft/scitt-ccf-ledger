// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <ccf/indexing/strategies/visit_each_entry_in_map.h>

namespace scitt
{
  /**
   * A wrapper around VisitEachEntryInMap that works with any kv::TypedValue,
   * providing access to the deserialized value.
   */
  template <typename M>
  class VisitEachEntryInValueTyped
    : public ccf::indexing::strategies::VisitEachEntryInMap
  {
  public:
    using VisitEachEntryInMap::VisitEachEntryInMap;

  protected:
    void visit_entry(
      const ccf::TxID& tx_id,
      const ccf::ByteVector& k,
      const ccf::ByteVector& v) final
    {
      visit_entry(tx_id, M::ValueSerialiser::from_serialised(v));
    }

    virtual void visit_entry(
      const ccf::TxID& tx_id, const typename M::Value& value) = 0;
  };
}
