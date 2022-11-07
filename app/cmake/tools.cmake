# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function(scitt_add_san name)
  add_san(${name})
  if(SAN)
    target_compile_options(${name} PRIVATE -fsanitize-blacklist=${CMAKE_SOURCE_DIR}/ubsan.suppressions)
    target_link_libraries(${name} PRIVATE -fsanitize-blacklist=${CMAKE_SOURCE_DIR}/ubsan.suppressions)
  endif()
endfunction()
