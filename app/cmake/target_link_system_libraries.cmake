# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# This is a variant of target_link_libraries which will adds the
# libraries as SYSTEM, ignoring warnings found in them.
function(target_link_system_libraries target scope)
  foreach(lib ${ARGN})
    get_target_property(lib_include_dirs ${lib} INTERFACE_INCLUDE_DIRECTORIES)
    if (lib_include_dirs)
      target_include_directories(${target} SYSTEM ${scope} ${lib_include_dirs})
    endif()
    target_link_libraries(${target} ${scope} ${lib})
  endforeach()
endfunction()
