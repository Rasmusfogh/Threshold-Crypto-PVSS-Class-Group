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

# Utility rule file for ContinuousCoverage.

# Include any custom commands dependencies for this target.
include tests/CMakeFiles/ContinuousCoverage.dir/compiler_depend.make

# Include the progress variables for this target.
include tests/CMakeFiles/ContinuousCoverage.dir/progress.make

tests/CMakeFiles/ContinuousCoverage:
	cd /home/rasmus/thesis/repos/qclpvss/build/tests && /usr/bin/ctest -D ContinuousCoverage

ContinuousCoverage: tests/CMakeFiles/ContinuousCoverage
ContinuousCoverage: tests/CMakeFiles/ContinuousCoverage.dir/build.make
.PHONY : ContinuousCoverage

# Rule to build all files generated by this target.
tests/CMakeFiles/ContinuousCoverage.dir/build: ContinuousCoverage
.PHONY : tests/CMakeFiles/ContinuousCoverage.dir/build

tests/CMakeFiles/ContinuousCoverage.dir/clean:
	cd /home/rasmus/thesis/repos/qclpvss/build/tests && $(CMAKE_COMMAND) -P CMakeFiles/ContinuousCoverage.dir/cmake_clean.cmake
.PHONY : tests/CMakeFiles/ContinuousCoverage.dir/clean

tests/CMakeFiles/ContinuousCoverage.dir/depend:
	cd /home/rasmus/thesis/repos/qclpvss/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/rasmus/thesis/repos/qclpvss /home/rasmus/thesis/repos/qclpvss/tests /home/rasmus/thesis/repos/qclpvss/build /home/rasmus/thesis/repos/qclpvss/build/tests /home/rasmus/thesis/repos/qclpvss/build/tests/CMakeFiles/ContinuousCoverage.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : tests/CMakeFiles/ContinuousCoverage.dir/depend

