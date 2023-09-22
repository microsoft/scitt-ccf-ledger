// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "ccf/ds/json.h"

namespace scitt
{
  // CCF already defines an equivalent definition, but unfortunately it lacks a
  // operator==, which makes it impossible to use in an optional field.
  struct ODataError // NOLINT(bugprone-exception-escape)
  {
    std::string code;
    std::string message;

    bool operator==(const ODataError&) const = default;
  };

  DECLARE_JSON_TYPE(ODataError);
  DECLARE_JSON_REQUIRED_FIELDS(ODataError, code, message);
}
