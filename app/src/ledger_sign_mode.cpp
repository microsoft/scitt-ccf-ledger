// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <ccf/node/ledger_sign_mode.h>

namespace ccf
{
  LedgerSignMode get_ledger_sign_mode()
  {
    return LedgerSignMode::CoseAllowDualJoin;
  }
}