// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "did/resolver.h"

#include <gmock/gmock.h>

namespace scitt::did
{
  class MockMethodResolver : public MethodResolver
  {
  public:
    MockMethodResolver(std::string prefix) : prefix(prefix) {}
    std::string_view get_method_prefix() const override
    {
      return prefix;
    }

    MOCK_METHOD(
      DidResolutionResult,
      resolve,
      (const Did& did, const DidResolutionOptions& options),
      (const, override));

  private:
    std::string prefix;
  };
}
