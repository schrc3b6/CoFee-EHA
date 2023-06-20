cmake_minimum_required(VERSION 3.4.3)

project(GBRStaticAnalyzers LANGUAGES C CXX)

find_package(LLVM REQUIRED CONFIG)
set(CMAKE_MODULE_PATH ${LLVM_CMAKE_DIR})
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_CMAKE_DIR}")
include(AddLLVM)

find_package(Clang REQUIRED CONFIG)

include_directories(${LLVM_INCLUDE_DIRS} ${CLANG_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})
message(STATUS "LLVM_DEFINITIONS:   ${LLVM_DEFINITIONS}")
message(STATUS "LLVM_INCLUDE_DIRS:  ${LLVM_INCLUDE_DIRS}")
message(STATUS "CLANG_INCLUDE_DIRS: ${CLANG_INCLUDE_DIRS}")
execute_process(COMMAND /usr/bin/bash -c "clang -Wp,-v -x c - -fsyntax-only < /dev/null 2>&1 | grep /clang/" OUTPUT_VARIABLE CLANG_INTERNAL_INCLUDE_DIR OUTPUT_STRIP_TRAILING_WHITESPACE)
string(REPLACE " " "" CLANG_INTERNAL_INCLUDE_DIR "${CLANG_INTERNAL_INCLUDE_DIR}")
message(STATUS "CLANG_INTERNAL_INCLUDE_DIR: ${CLANG_INTERNAL_INCLUDE_DIR}")
enable_testing()

add_llvm_library(GenericErrorCodeChecker MODULE GenericErrorCodeChecker.cpp PLUGIN_TOOL clang)

