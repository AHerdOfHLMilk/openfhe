# Download and install OpenFHE
INCLUDE(ExternalProject)
ExternalProject_Add(
	build-openfhe
	# URL ${CMAKE_CURRENT_SOURCE_DIR}/openfhe_11.6.tar.gz
	GIT_REPOSITORY https://github.com/openfheorg/openfhe-development.git
	GIT_TAG main
	CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR> -DBUILD_BENCHMARKS=OFF -DBUILD_UNITTESTS=OFF -DBUILD_EXAMPLES=OFF -DGIT_SUBMOD_AUTO=OFF -DBUILD_STATIC=ON -DBUILD_SHARED=OFF
)

ExternalProject_Get_Property(build-openfhe INSTALL_DIR)
set(OPENFHE_INCLUDE ${INSTALL_DIR}/include/openfhe CACHE PATH "OPENFHE include directory")
set(OPENFHE_INCLUDE_CORE ${INSTALL_DIR}/include/openfhe/core CACHE PATH "OPENFHE core directory")
set(OPENFHE_INCLUDE_PKE ${INSTALL_DIR}/include/openfhe/pke CACHE PATH "OPENFHE pke directory")
set(OPENFHE_INCLUDE_BIN ${INSTALL_DIR}/include/openfhe/binfhe CACHE PATH "OPENFHE bin directory")
set(OPENFHE_LIBDIR_CORE "${INSTALL_DIR}/lib/libOPENFHEcore_static.a" CACHE PATH "OPENFHE core library")
set(OPENFHE_LIBDIR_PKE "${INSTALL_DIR}/lib/libOPENFHEpke_static.a" CACHE PATH "OPENFHE pke library")
set(OPENFHE_LIBDIR_BIN "${INSTALL_DIR}/lib/libOPENFHEbinfhe_static.a" CACHE PATH "OPENFHE bin library")

# Download and install googletest
include(FetchContent)
FetchContent_Declare(
	googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
	# Specify the commit you depend on and update it regularly.
	GIT_TAG        v1.14.0
)

# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)