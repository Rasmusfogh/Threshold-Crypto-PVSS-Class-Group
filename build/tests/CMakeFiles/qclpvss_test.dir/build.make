# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
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
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/rasmus/thesis/repos/qclpvss

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/rasmus/thesis/repos/qclpvss/build

# Include any dependencies generated for this target.
include tests/CMakeFiles/qclpvss_test.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include tests/CMakeFiles/qclpvss_test.dir/compiler_depend.make

# Include the progress variables for this target.
include tests/CMakeFiles/qclpvss_test.dir/progress.make

# Include the compile flags for this target's objects.
include tests/CMakeFiles/qclpvss_test.dir/flags.make

tests/CMakeFiles/qclpvss_test.dir/qclpvss_test.cpp.o: tests/CMakeFiles/qclpvss_test.dir/flags.make
tests/CMakeFiles/qclpvss_test.dir/qclpvss_test.cpp.o: ../tests/qclpvss_test.cpp
tests/CMakeFiles/qclpvss_test.dir/qclpvss_test.cpp.o: tests/CMakeFiles/qclpvss_test.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/rasmus/thesis/repos/qclpvss/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object tests/CMakeFiles/qclpvss_test.dir/qclpvss_test.cpp.o"
	cd /home/rasmus/thesis/repos/qclpvss/build/tests && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT tests/CMakeFiles/qclpvss_test.dir/qclpvss_test.cpp.o -MF CMakeFiles/qclpvss_test.dir/qclpvss_test.cpp.o.d -o CMakeFiles/qclpvss_test.dir/qclpvss_test.cpp.o -c /home/rasmus/thesis/repos/qclpvss/tests/qclpvss_test.cpp

tests/CMakeFiles/qclpvss_test.dir/qclpvss_test.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/qclpvss_test.dir/qclpvss_test.cpp.i"
	cd /home/rasmus/thesis/repos/qclpvss/build/tests && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/rasmus/thesis/repos/qclpvss/tests/qclpvss_test.cpp > CMakeFiles/qclpvss_test.dir/qclpvss_test.cpp.i

tests/CMakeFiles/qclpvss_test.dir/qclpvss_test.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/qclpvss_test.dir/qclpvss_test.cpp.s"
	cd /home/rasmus/thesis/repos/qclpvss/build/tests && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/rasmus/thesis/repos/qclpvss/tests/qclpvss_test.cpp -o CMakeFiles/qclpvss_test.dir/qclpvss_test.cpp.s

# Object files for target qclpvss_test
qclpvss_test_OBJECTS = \
"CMakeFiles/qclpvss_test.dir/qclpvss_test.cpp.o"

# External object files for target qclpvss_test
qclpvss_test_EXTERNAL_OBJECTS =

tests/qclpvss_test: tests/CMakeFiles/qclpvss_test.dir/qclpvss_test.cpp.o
tests/qclpvss_test: tests/CMakeFiles/qclpvss_test.dir/build.make
tests/qclpvss_test: src/libproject.a
tests/qclpvss_test: /usr/lib/x86_64-linux-gnu/libgmp.so
tests/qclpvss_test: /usr/lib/x86_64-linux-gnu/libgmpxx.so
tests/qclpvss_test: /usr/lib/x86_64-linux-gnu/libcrypto.so
tests/qclpvss_test: tests/CMakeFiles/qclpvss_test.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/rasmus/thesis/repos/qclpvss/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable qclpvss_test"
	cd /home/rasmus/thesis/repos/qclpvss/build/tests && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/qclpvss_test.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
tests/CMakeFiles/qclpvss_test.dir/build: tests/qclpvss_test
.PHONY : tests/CMakeFiles/qclpvss_test.dir/build

tests/CMakeFiles/qclpvss_test.dir/clean:
	cd /home/rasmus/thesis/repos/qclpvss/build/tests && $(CMAKE_COMMAND) -P CMakeFiles/qclpvss_test.dir/cmake_clean.cmake
.PHONY : tests/CMakeFiles/qclpvss_test.dir/clean

tests/CMakeFiles/qclpvss_test.dir/depend:
	cd /home/rasmus/thesis/repos/qclpvss/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/rasmus/thesis/repos/qclpvss /home/rasmus/thesis/repos/qclpvss/tests /home/rasmus/thesis/repos/qclpvss/build /home/rasmus/thesis/repos/qclpvss/build/tests /home/rasmus/thesis/repos/qclpvss/build/tests/CMakeFiles/qclpvss_test.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : tests/CMakeFiles/qclpvss_test.dir/depend

