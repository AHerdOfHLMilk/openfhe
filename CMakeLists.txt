cmake_minimum_required (VERSION 3.5.1)
project(fhe_llm)
cmake_policy(SET CMP0079 NEW)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -ffast-math -Wno-error")
set(CMAKE_BUILD_TYPE Release)

include(FindPackageHandleStandardArgs)

find_package(OpenMP)
if(OPENMP_FOUND)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
endif()

add_subdirectory(3rdparty)

include_directories(${GTEST_INCLUDE_DIRS})
include_directories(${OPENFHE_INCLUDE})
include_directories(${OPENFHE_INCLUDE_CORE})
include_directories(${OPENFHE_INCLUDE_PKE})
include_directories(${OPENFHE_INCLUDE_BIN})
add_library(OPENFHE_CORE STATIC IMPORTED)
set_target_properties(OPENFHE_CORE PROPERTIES IMPORTED_LOCATION ${OPENFHE_LIBDIR_CORE})
add_library(OPENFHE_PKE STATIC IMPORTED)
set_target_properties(OPENFHE_PKE PROPERTIES IMPORTED_LOCATION ${OPENFHE_LIBDIR_PKE})
add_library(OPENFHE_BIN STATIC IMPORTED)
set_target_properties(OPENFHE_BIN PROPERTIES IMPORTED_LOCATION ${OPENFHE_LIBDIR_BIN})

add_subdirectory(source)
add_subdirectory(run)
enable_testing()
add_subdirectory(test)