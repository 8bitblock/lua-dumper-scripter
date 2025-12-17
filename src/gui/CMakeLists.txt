add_executable(luatool main.cpp)
target_include_directories(luatool PRIVATE ${CMAKE_SOURCE_DIR}/src/common)
target_link_libraries(luatool injector SDL2::SDL2 GL Threads::Threads dl)
# Add imgui sources
target_sources(luatool PRIVATE
    ../../external/imgui/imgui.cpp
    ../../external/imgui/imgui_draw.cpp
    ../../external/imgui/imgui_tables.cpp
    ../../external/imgui/imgui_widgets.cpp
    ../../external/imgui/backends/imgui_impl_sdl2.cpp
    ../../external/imgui/backends/imgui_impl_opengl3.cpp
)
