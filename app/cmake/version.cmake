# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
include(CMakePrintHelpers)
cmake_print_variables(CMAKE_CURRENT_SOURCE_DIR)
cmake_print_variables(GIT_EXECUTABLE)

unset(SCITT_VERSION)

if (SCITT_VERSION_OVERRIDE)
  set(SCITT_VERSION "${SCITT_VERSION_OVERRIDE}")
else()
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
endif()

file(WRITE ${CMAKE_BINARY_DIR}/VERSION "${SCITT_VERSION}")
install(FILES ${CMAKE_BINARY_DIR}/VERSION DESTINATION share)
