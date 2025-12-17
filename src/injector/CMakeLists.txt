add_library(injector STATIC injector.cpp)
target_include_directories(injector PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
