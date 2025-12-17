add_library(agent SHARED main.cpp)
target_link_libraries(agent dl pthread common)
target_include_directories(agent PRIVATE ${CMAKE_SOURCE_DIR}/src/common)
