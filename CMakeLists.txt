cmake_minimum_required(VERSION 3.4 FATAL_ERROR)

option(MEM_TEST "Generate the test target." OFF)

project(overseer_mem CXX)

add_library(${PROJECT_NAME} INTERFACE)
add_library(overseer::mem ALIAS ${PROJECT_NAME})

target_include_directories(${PROJECT_NAME} INTERFACE include)

if (MEM_TEST)
    enable_testing()

    add_subdirectory(tests)
    add_subdirectory(examples)
endif ()
