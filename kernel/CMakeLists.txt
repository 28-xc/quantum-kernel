cmake_minimum_required(VERSION 3.24)
project(LatticeCore LANGUAGES NONE)
find_package(Python3 3.10 REQUIRED COMPONENTS Interpreter)
set(LC_BUILD_MODE hosted CACHE STRING "hosted, pruned or canonical")
set_property(CACHE LC_BUILD_MODE PROPERTY STRINGS hosted pruned canonical)
set(LC_CONFIGURATION compact-rate CACHE STRING "Algorithm configuration; default compact-rate")
set(LC_BACKEND portable CACHE STRING "portable, aarch64 or x86_64")
set_property(CACHE LC_BACKEND PROPERTY STRINGS portable aarch64 x86_64)
set(LC_PARAMETERS all CACHE STRING "all, kem, dsa, or comma-separated subset (pruned mode)")
set(LC_OPT Os CACHE STRING "O3 or Os")
option(LC_LTO "Link-time optimization" ON)
set(LC_PROBE_COUNT 100 CACHE STRING "Per-parameter functional iterations, not timing")
find_program(LC_CC NAMES gcc REQUIRED)
find_program(LC_AR NAMES gcc-ar ar REQUIRED)
find_program(LC_NM NAMES nm REQUIRED)
find_program(LC_OBJDUMP NAMES objdump REQUIRED)
find_program(LC_SIZE NAMES size REQUIRED)
set(_lto --no-lto)
if(LC_LTO)
  set(_lto --lto)
endif()
execute_process(COMMAND "${Python3_EXECUTABLE}" -B "${CMAKE_SOURCE_DIR}/tools/build.py" plan
  --mode "${LC_BUILD_MODE}" --configuration "${LC_CONFIGURATION}" --backend "${LC_BACKEND}"
  --parameters "${LC_PARAMETERS}" --opt "${LC_OPT}" ${_lto} --probe-count "${LC_PROBE_COUNT}"
  --cc "${LC_CC}" --ar "${LC_AR}" --nm "${LC_NM}" --objdump "${LC_OBJDUMP}" --size "${LC_SIZE}"
  --output "${CMAKE_BINARY_DIR}/build_plan.xml" --cmake-dependencies "${CMAKE_BINARY_DIR}/source_dependencies.cmake"
  RESULT_VARIABLE _result OUTPUT_VARIABLE _identity OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT _result EQUAL 0)
  message(FATAL_ERROR "Source or configuration validation failed")
endif()
include("${CMAKE_BINARY_DIR}/source_dependencies.cmake")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${LC_SOURCE_DEPENDENCIES})
set(_output "${CMAKE_BINARY_DIR}/build_${_identity}")
set(_stamp "${CMAKE_BINARY_DIR}/checked_${_identity}.stamp")
add_custom_command(OUTPUT "${_stamp}"
  COMMAND "${Python3_EXECUTABLE}" -B "${CMAKE_SOURCE_DIR}/tools/build.py" build
    --plan "${CMAKE_BINARY_DIR}/build_plan.xml" --output "${_output}"
  COMMAND "${CMAKE_COMMAND}" -E touch "${_stamp}"
  DEPENDS "${CMAKE_BINARY_DIR}/build_plan.xml"
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}" COMMENT "Build algorithm library and run functional checks"
  VERBATIM USES_TERMINAL)
add_custom_target(latticecore ALL DEPENDS "${_stamp}")
message(STATUS "Algorithm library output: ${_output}")
