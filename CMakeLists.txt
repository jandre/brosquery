cmake_minimum_required(VERSION 2.8.12)

set(CMAKE_C_COMPILER "clang")
set(CMAKE_CXX_COMPILER "clang++")
set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/third-party/osquery/CMake)

include_directories("${CMAKE_SOURCE_DIR}/third-party/osquery/include")
string(TOLOWER "${CMAKE_SYSTEM_NAME}" LOWER_PLATFORM)
include_directories("third-party/osquery/build/${LOWER_PLATFORM}/third-party/glog/include")

add_compile_options(
  -Wall
  -Wextra
  -Wstrict-aliasing
  -Wno-unused-parameter
  -Wno-unused-result
  -Wno-missing-field-initializers
  -Wno-sign-compare
  -Wnon-virtual-dtor
  -Wchar-subscripts
  -Wpointer-arith
  -Woverloaded-virtual
  -Wformat
  -Wformat-security
  -Werror=format-security
  -fstack-protector-all
  -fPIE
)
set(CXX_COMPILE_FLAGS "")

# Set non-C compile flags and whole-loading linker flags.
# osquery needs ALL symbols in the libraries it includes for relaxed ctors
# late-loading modules and SQLite introspection utilities.
if(APPLE)
  set(APPLE_MIN_ABI "10.9")
  set(CXX_COMPILE_FLAGS "${CXX_COMPILE_FLAGS} -std=c++11 -stdlib=libc++")
  set(CXX_COMPILE_FLAGS "${CXX_COMPILE_FLAGS} -mmacosx-version-min=${APPLE_MIN_ABI}")
  set(OS_WHOLELINK_PRE "-Wl,-force_load")
  set(OS_WHOLELINK_POST "")
  # Special compile flags for Objective-C++
  set(OBJCXX_COMPILE_FLAGS
    "-x objective-c++ -fobjc-arc -Wno-c++11-extensions -mmacosx-version-min=${APPLE_MIN_ABI}")
elseif(${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
  set(FREEBSD TRUE)
  set(CXX_COMPILE_FLAGS "${CXX_COMPILE_FLAGS} -std=c++11 -stdlib=libc++")
  set(OS_WHOLELINK_PRE "")
  set(OS_WHOLELINK_POST "")
else()
  set(LINUX TRUE)
  # Do not use the shared linker flags for modules.
  set(CXX_COMPILE_FLAGS "${CXX_COMPILE_FLAGS} -std=c++11")
  set(OS_WHOLELINK_PRE "-Wl,-whole-archive")
  set(OS_WHOLELINK_POST "-Wl,-no-whole-archive")
endif()

# Use osquery language to set platform/os
execute_process(
  COMMAND "${CMAKE_SOURCE_DIR}/third-party/osquery/tools/provision.sh" get_platform
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  OUTPUT_VARIABLE PLATFORM
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

list(GET PLATFORM 0 OSQUERY_BUILD_PLATFORM)
list(GET PLATFORM 1 OSQUERY_BUILD_DISTRO)
string(REPLACE "." "_" PLATFORM "${PLATFORM}")
string(TOUPPER "${PLATFORM}" PLATFORM)
list(GET PLATFORM 0 OSQUERY_BUILD_PLATFORM_DEFINE)
list(GET PLATFORM 1 OSQUERY_BUILD_DISTRO_DEFINE)

# RHEL6 uses a different gcc 4.9 runtime
if(${OSQUERY_BUILD_DISTRO} STREQUAL "rhel6")
  set(GCC_RUNTIME "/opt/rh/devtoolset-3/root/usr/")
  message("-- Setting RHEL6 GCC runtime: ${GCC_RUNTIME}")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --gcc-toolchain=${GCC_RUNTIME}")
endif()

include(CMakeLibs)
add_subdirectory(src)

