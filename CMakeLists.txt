cmake_minimum_required(VERSION 3.5.1)  # Adjust the version as needed
project(QCLPVSS VERSION 0.0.1 LANGUAGES CXX)  # Change "your_project_name" to your actual project name
set (QCLPVSS_DESCRIPTION "QCLPVSS Implements a PVSS over Class Group Cryptography,
    using the external library BIBYCL")

################################################################################
# Add cmake.utils to the list of CMAKE_MODULE_PATH
################################################################################
set (MODULE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/cmake.utils")
list (APPEND CMAKE_MODULE_PATH "${MODULE_DIR}")


##############################################################################
# Set C++ standard to c++11
##############################################################################
set (CMAKE_CXX_STANDARD 11)
set (CMAKE_CXX_STANDARD_REQUIRED ON)

##############################################################################
# Check version of compiler
##############################################################################
if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "6.1")
    message (FATAL_ERROR "${CMAKE_PROJECT_NAME} requires g++ version >= 6.1")
  endif()
endif ()

##############################################################################
# Set flags and build type (release or debug)
##############################################################################
if (NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message (STATUS "Setting build type to 'Debug' as none was specified.")
  set (CMAKE_BUILD_TYPE "Debug" CACHE STRING "Choose type of build" FORCE)
  set_property (CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release")
  set (CMAKE_CXX_FLAGS_DEBUG "-O3 -g -Wall -Wextra -DDEBUG")
endif ()

# if(NOT MSVC)
#   set (CMAKE_CXX_FLAGS_RELEASE "-O3 -Wall -Wextra -DNDEBUG")
#   set (CMAKE_CXX_FLAGS_DEBUG "-O3 -g -Wall -Wextra -DDEBUG")
# endif()

################################################################################
# Looking for GMP and OpenSSL
################################################################################
find_package (gmp REQUIRED)
find_package (OpenSSL REQUIRED)

# Add the bicycl library
add_subdirectory(lib/include)

# Add your own source code in the "src" folder
add_subdirectory(src)
add_subdirectory(tests)
add_subdirectory(benchmarks)

# Add any additional targets or configurations here if needed