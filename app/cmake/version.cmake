# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

unset(SCITT_VERSION)
unset(SCITT_RELEASE_VERSION)
unset(SCITT_VERSION_SUFFIX)

# Deduce project version from git environment
find_package(Git)

execute_process(
  COMMAND "bash" "-c" "${GIT_EXECUTABLE} describe --tags --match=\"*.*.*\""
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
  OUTPUT_VARIABLE "SCITT_VERSION"
  OUTPUT_STRIP_TRAILING_WHITESPACE
  RESULT_VARIABLE RETURN_CODE
)
if(NOT RETURN_CODE STREQUAL "0")
  message(FATAL_ERROR "Error calling git describe")
endif()

file(WRITE ${CMAKE_BINARY_DIR}/VERSION "${SCITT_VERSION}")
install(FILES ${CMAKE_BINARY_DIR}/VERSION DESTINATION share)
