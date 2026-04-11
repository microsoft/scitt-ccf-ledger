# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

include(${CCF_DIR}/cmake/cpack_ccfapp.cmake)

set(CPACK_RPM_PACKAGE_REQUIRES "${CPACK_CCF_RUNTIME_REQUIRES}")
set(CPACK_RPM_FILE_NAME "scitt")
set(CPACK_PACKAGING_INSTALL_PREFIX "/opt/scitt")

include(CPack)
