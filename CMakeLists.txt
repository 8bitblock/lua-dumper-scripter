cmake_minimum_required(VERSION 3.10)
project(LuaTool)

set(CMAKE_CXX_STANDARD 17)

# External: ImGui
# We'll expect imgui to be in external/imgui
include_directories(external/imgui)
include_directories(external/imgui/backends)

# Find dependencies
find_package(SDL2 REQUIRED)
find_package(OpenGL REQUIRED)
find_package(Threads REQUIRED)

# Subprojects
add_subdirectory(src/common)
add_subdirectory(src/target)
add_subdirectory(src/agent)
add_subdirectory(src/injector)
add_subdirectory(src/gui)
