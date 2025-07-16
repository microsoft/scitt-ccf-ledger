# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

unset(SCITT_VERSION)

if (SCITT_VERSION_OVERRIDE)
  set(SCITT_VERSION "${SCITT_VERSION_OVERRIDE}")
else()
  # Deduce project version from git environment
  find_package(Git)

  execute_process(
    # use the long version in the form of <tag>-<commits since tag>-g<commit hash>
    COMMAND "bash" "-c" "${GIT_EXECUTABLE} describe --tags --long --always"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    OUTPUT_VARIABLE "SCITT_VERSION"
    OUTPUT_STRIP_TRAILING_WHITESPACE
    RESULT_VARIABLE RETURN_CODE
  )
  if(NOT RETURN_CODE STREQUAL "0")
    message(FATAL_ERROR "Error getting version from git")
  endif()
endif()

file(WRITE ${CMAKE_BINARY_DIR}/VERSION "${SCITT_VERSION}")
install(FILES ${CMAKE_BINARY_DIR}/VERSION DESTINATION share)
