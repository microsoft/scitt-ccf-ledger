# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

include(${CCF_DIR}/cmake/cpack_ccfapp.cmake)

set(CPACK_RPM_PACKAGE_REQUIRES "${CPACK_CCF_RUNTIME_REQUIRES}")
set(CPACK_RPM_FILE_NAME "scitt")
set(CPACK_PACKAGING_INSTALL_PREFIX "/opt/scitt")
set(
  CPACK_RPM_SPEC_MORE_DEFINE
  "%define _buildhost scitthost
%define use_source_date_epoch_as_buildtime Y
%define clamp_mtime_to_source_date_epoch Y
"
)

include(CPack)
