cmake_minimum_required(VERSION 3.10)
project("pe_lib" VERSION 1.0.0 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_EXTENSIONS OFF)

# clangd插件
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# 编译参数
message("+ Generator: ${CMAKE_GENERATOR}")
message("+ Architecture: ${BUILD_ARCHITECTURE}")
message("+ BuildType: ${CMAKE_BUILD_TYPE}")

if(${CMAKE_GENERATOR} MATCHES "Makefiles")
    if(${BUILD_ARCHITECTURE} STREQUAL "x86")
        set(CMAKE_C_FLAGS "-m32 -g -static")
        set(CMAKE_CXX_FLAGS "-m32 -g -static")
    elseif(${BUILD_ARCHITECTURE} STREQUAL "x64")
        set(CMAKE_C_FLAGS "-m64 -g -static")
        set(CMAKE_CXX_FLAGS "-m64 -g -static")
    else()
        message(FATAL_ERROR "Invalid BUILD_ARCHITECTURE value. Please choose either x86 or x64.")
    endif()
elseif(${CMAKE_GENERATOR} MATCHES "Visual Studio")
    if(${BUILD_ARCHITECTURE} STREQUAL "x86")
        set(CMAKE_GENERATOR_PLATFORM "Win32")
    elseif(${BUILD_ARCHITECTURE} STREQUAL "x64")
        set(CMAKE_GENERATOR_PLATFORM "x64")
    else()
    message(FATAL_ERROR "- Invalid BUILD_ARCHITECTURE value. Please choose either x86 or x64.")
    endif()
endif()

# 定义输入变量
file(GLOB PROJECT_INCLUDE_DIR "${PROJECT_SOURCE_DIR}/include/pe_lib")
if(NOT EXISTS "${PROJECT_INCLUDE_DIR}")
    message(FATAL_ERROR "- Target include path is not find: ${PROJECT_INCLUDE_DIR}")
endif()

file(GLOB PROJECT_SRC_DIR "${PROJECT_SOURCE_DIR}/src")
if(NOT EXISTS "${PROJECT_SRC_DIR}")
    message(FATAL_ERROR "- Target src path is not find:${PROJECT_SRC_DIR}")
endif()

file(GLOB PROJECT_3RD_DIR "${PROJECT_SOURCE_DIR}/3rd")
if(NOT EXISTS "${PROJECT_3RD_DIR}")
    message(FATAL_ERROR "- Target 3rd path is not find:${PROJECT_3RD_DIR}")
endif()

# 子目录
add_subdirectory(src)
add_subdirectory(3rd)
add_subdirectory(tests)