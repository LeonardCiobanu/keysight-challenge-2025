# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.28

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
CMAKE_SOURCE_DIR = /root/keysight-challenge-2025

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /root/keysight-challenge-2025/build

# Include any dependencies generated for this target.
include src/CMakeFiles/gpu-router.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include src/CMakeFiles/gpu-router.dir/compiler_depend.make

# Include the progress variables for this target.
include src/CMakeFiles/gpu-router.dir/progress.make

# Include the compile flags for this target's objects.
include src/CMakeFiles/gpu-router.dir/flags.make

src/CMakeFiles/gpu-router.dir/gpu-router.cpp.o: src/CMakeFiles/gpu-router.dir/flags.make
src/CMakeFiles/gpu-router.dir/gpu-router.cpp.o: /root/keysight-challenge-2025/src/gpu-router.cpp
src/CMakeFiles/gpu-router.dir/gpu-router.cpp.o: src/CMakeFiles/gpu-router.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/root/keysight-challenge-2025/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object src/CMakeFiles/gpu-router.dir/gpu-router.cpp.o"
	cd /root/keysight-challenge-2025/build/src && /opt/intel/oneapi/compiler/2025.1/bin/icpx $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT src/CMakeFiles/gpu-router.dir/gpu-router.cpp.o -MF CMakeFiles/gpu-router.dir/gpu-router.cpp.o.d -o CMakeFiles/gpu-router.dir/gpu-router.cpp.o -c /root/keysight-challenge-2025/src/gpu-router.cpp

src/CMakeFiles/gpu-router.dir/gpu-router.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/gpu-router.dir/gpu-router.cpp.i"
	cd /root/keysight-challenge-2025/build/src && /opt/intel/oneapi/compiler/2025.1/bin/icpx $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/keysight-challenge-2025/src/gpu-router.cpp > CMakeFiles/gpu-router.dir/gpu-router.cpp.i

src/CMakeFiles/gpu-router.dir/gpu-router.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/gpu-router.dir/gpu-router.cpp.s"
	cd /root/keysight-challenge-2025/build/src && /opt/intel/oneapi/compiler/2025.1/bin/icpx $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/keysight-challenge-2025/src/gpu-router.cpp -o CMakeFiles/gpu-router.dir/gpu-router.cpp.s

# Object files for target gpu-router
gpu__router_OBJECTS = \
"CMakeFiles/gpu-router.dir/gpu-router.cpp.o"

# External object files for target gpu-router
gpu__router_EXTERNAL_OBJECTS =

src/gpu-router: src/CMakeFiles/gpu-router.dir/gpu-router.cpp.o
src/gpu-router: src/CMakeFiles/gpu-router.dir/build.make
src/gpu-router: src/CMakeFiles/gpu-router.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=/root/keysight-challenge-2025/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable gpu-router"
	cd /root/keysight-challenge-2025/build/src && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/gpu-router.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
src/CMakeFiles/gpu-router.dir/build: src/gpu-router
.PHONY : src/CMakeFiles/gpu-router.dir/build

src/CMakeFiles/gpu-router.dir/clean:
	cd /root/keysight-challenge-2025/build/src && $(CMAKE_COMMAND) -P CMakeFiles/gpu-router.dir/cmake_clean.cmake
.PHONY : src/CMakeFiles/gpu-router.dir/clean

src/CMakeFiles/gpu-router.dir/depend:
	cd /root/keysight-challenge-2025/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /root/keysight-challenge-2025 /root/keysight-challenge-2025/src /root/keysight-challenge-2025/build /root/keysight-challenge-2025/build/src /root/keysight-challenge-2025/build/src/CMakeFiles/gpu-router.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : src/CMakeFiles/gpu-router.dir/depend

