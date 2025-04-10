cmake_minimum_required(VERSION 3.4 FATAL_ERROR)

option(MEM_TEST "Generate the test target." OFF)

project(mem CXX)

if(NOT TARGET mem)
    add_library(mem INTERFACE)
endif()

target_include_directories(mem INTERFACE include)

if (MEM_TEST)
    enable_testing()

    add_subdirectory(tests)
    add_subdirectory(examples)
endif ()
