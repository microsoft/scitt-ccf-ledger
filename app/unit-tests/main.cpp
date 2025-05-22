// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <ccf/ds/logger.h>
#include <gmock/gmock.h>

int main(int argc, char** argv) // NOLINT(bugprone-exception-escape)
{
  testing::InitGoogleMock(&argc, argv);

  // Initialise the CCF logging.
  ccf::logger::config::default_init();

  return RUN_ALL_TESTS();
}
