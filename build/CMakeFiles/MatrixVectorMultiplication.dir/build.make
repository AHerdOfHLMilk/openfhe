# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /mnt/d/Work/astar/openfhetest

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /mnt/d/Work/astar/openfhetest/build

# Include any dependencies generated for this target.
include CMakeFiles/MatrixVectorMultiplication.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/MatrixVectorMultiplication.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/MatrixVectorMultiplication.dir/flags.make

CMakeFiles/MatrixVectorMultiplication.dir/MatrixVectorMultiplication.cpp.o: CMakeFiles/MatrixVectorMultiplication.dir/flags.make
CMakeFiles/MatrixVectorMultiplication.dir/MatrixVectorMultiplication.cpp.o: ../MatrixVectorMultiplication.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/d/Work/astar/openfhetest/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/MatrixVectorMultiplication.dir/MatrixVectorMultiplication.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/MatrixVectorMultiplication.dir/MatrixVectorMultiplication.cpp.o -c /mnt/d/Work/astar/openfhetest/MatrixVectorMultiplication.cpp

CMakeFiles/MatrixVectorMultiplication.dir/MatrixVectorMultiplication.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/MatrixVectorMultiplication.dir/MatrixVectorMultiplication.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /mnt/d/Work/astar/openfhetest/MatrixVectorMultiplication.cpp > CMakeFiles/MatrixVectorMultiplication.dir/MatrixVectorMultiplication.cpp.i

CMakeFiles/MatrixVectorMultiplication.dir/MatrixVectorMultiplication.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/MatrixVectorMultiplication.dir/MatrixVectorMultiplication.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /mnt/d/Work/astar/openfhetest/MatrixVectorMultiplication.cpp -o CMakeFiles/MatrixVectorMultiplication.dir/MatrixVectorMultiplication.cpp.s

# Object files for target MatrixVectorMultiplication
MatrixVectorMultiplication_OBJECTS = \
"CMakeFiles/MatrixVectorMultiplication.dir/MatrixVectorMultiplication.cpp.o"

# External object files for target MatrixVectorMultiplication
MatrixVectorMultiplication_EXTERNAL_OBJECTS =

MatrixVectorMultiplication: CMakeFiles/MatrixVectorMultiplication.dir/MatrixVectorMultiplication.cpp.o
MatrixVectorMultiplication: CMakeFiles/MatrixVectorMultiplication.dir/build.make
MatrixVectorMultiplication: /usr/local/lib/libOPENFHEpke.so.1.1.4
MatrixVectorMultiplication: /usr/local/lib/libOPENFHEbinfhe.so.1.1.4
MatrixVectorMultiplication: /usr/local/lib/libOPENFHEcore.so.1.1.4
MatrixVectorMultiplication: CMakeFiles/MatrixVectorMultiplication.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/mnt/d/Work/astar/openfhetest/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable MatrixVectorMultiplication"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/MatrixVectorMultiplication.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/MatrixVectorMultiplication.dir/build: MatrixVectorMultiplication

.PHONY : CMakeFiles/MatrixVectorMultiplication.dir/build

CMakeFiles/MatrixVectorMultiplication.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/MatrixVectorMultiplication.dir/cmake_clean.cmake
.PHONY : CMakeFiles/MatrixVectorMultiplication.dir/clean

CMakeFiles/MatrixVectorMultiplication.dir/depend:
	cd /mnt/d/Work/astar/openfhetest/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /mnt/d/Work/astar/openfhetest /mnt/d/Work/astar/openfhetest /mnt/d/Work/astar/openfhetest/build /mnt/d/Work/astar/openfhetest/build /mnt/d/Work/astar/openfhetest/build/CMakeFiles/MatrixVectorMultiplication.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/MatrixVectorMultiplication.dir/depend

