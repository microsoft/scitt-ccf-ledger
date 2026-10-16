// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <ccf/ds/json.h>
#include <string>

namespace scitt
{
  struct GetVersion
  {
    struct Out
    {
      std::string version;
    };
  };

  DECLARE_JSON_TYPE(GetVersion::Out);
  DECLARE_JSON_REQUIRED_FIELDS(GetVersion::Out, version);
} // namespace scitt
