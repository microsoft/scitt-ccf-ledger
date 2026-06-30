// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <ccf/_private/js/global_class_ids.h>
#include <mutex>

namespace testutils
{
  // CCF registers its JavaScript class IDs exactly once per process during node
  // start-up. Unit tests that build a JS interpreter must replicate this. The
  // function-local once_flag guarantees registration happens exactly once even
  // when several test translation units call this helper.
  inline void ensure_js_initialised()
  {
    static std::once_flag js_init_flag;
    std::call_once(js_init_flag, []() { ccf::js::register_class_ids(); });
  }
}
