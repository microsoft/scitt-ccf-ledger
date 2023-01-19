// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <fmt/format.h>

namespace scitt
{
  enum class ClaimProfile
  {
    IETF,
    X509,
    Notary
  };
}

FMT_BEGIN_NAMESPACE
template <>
struct formatter<scitt::ClaimProfile>
{
  template <typename ParseContext>
  constexpr auto parse(ParseContext& ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(const scitt::ClaimProfile& cs, FormatContext& ctx) const
  {
    char const* s = "Unknown";
    switch (cs)
    {
      case (scitt::ClaimProfile::IETF):
      {
        s = "IETF";
        break;
      }
      case (scitt::ClaimProfile::X509):
      {
        s = "X509";
        break;
      }
      case (scitt::ClaimProfile::Notary):
      {
        s = "Notary";
        break;
      }
    }
    return format_to(ctx.out(), "{}", s);
  }
};
FMT_END_NAMESPACE
