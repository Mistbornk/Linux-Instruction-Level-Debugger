cmake_minimum_required(VERSION 3.21)
project(sdb VERSION 0.2.0 LANGUAGES C CXX ASM)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux" OR
   NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$")
    message(FATAL_ERROR "SDB requires Linux x86-64. Use the project's x86-64 Colima container on macOS.")
endif()
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build configuration" FORCE)
endif()

option(SDB_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
find_path(CAPSTONE_INCLUDE_DIR capstone/capstone.h REQUIRED)
find_library(CAPSTONE_LIBRARY capstone REQUIRED)

add_library(sdb_build_options INTERFACE)
target_compile_features(sdb_build_options INTERFACE cxx_std_17)
target_compile_options(sdb_build_options INTERFACE -Wall -Wextra -Wpedantic)
if(SDB_SANITIZERS)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        message(FATAL_ERROR "SDB_SANITIZERS requires GCC or Clang")
    endif()
    # Keep sanitizer shadow-memory placement stable in the x86-64 Colima VM.
    target_compile_options(sdb_build_options INTERFACE
        -fsanitize=address,undefined -fno-omit-frame-pointer -fno-pie)
    target_link_options(sdb_build_options INTERFACE -fsanitize=address,undefined -no-pie)
endif()

add_library(sdb_core
    src/breakpoint.cpp src/cli_options.cpp src/command.cpp src/command_input.cpp
    src/debugger.cpp src/disassembler.cpp src/elf_image.cpp src/memory.cpp src/tracee.cpp)
target_include_directories(sdb_core PUBLIC include "${CAPSTONE_INCLUDE_DIR}")
target_link_libraries(sdb_core PUBLIC sdb_build_options "${CAPSTONE_LIBRARY}")
add_executable(sdb src/main.cpp)
target_link_libraries(sdb PRIVATE sdb_core)

include(CTest)
if(BUILD_TESTING)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    find_program(SDB_TEST_CC gcc REQUIRED)
    find_program(SDB_TEST_NM nm REQUIRED)

    add_executable(command_test tests/command_test.cpp)
    target_link_libraries(command_test PRIVATE sdb_core)
    add_test(NAME command_parser_and_options COMMAND command_test)
    set_tests_properties(command_parser_and_options PROPERTIES TIMEOUT 30 LABELS unit)
    add_test(NAME test_runner COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/runner_test.py")
    set_tests_properties(test_runner PROPERTIES TIMEOUT 30 LABELS unit)

    # The probe and tracee fixtures are intentionally not sanitizer-instrumented.
    add_executable(ptrace_probe tests/ptrace_probe.cpp)
    target_compile_features(ptrace_probe PRIVATE cxx_std_17)
    target_compile_options(ptrace_probe PRIVATE -Wall -Wextra -Wpedantic)
    add_executable(loop_fixture tests/fixtures/loop.S)
    target_link_options(loop_fixture PRIVATE -nostdlib -no-pie)
    add_executable(memory_transaction tests/memory_transaction.cpp)
    target_link_libraries(memory_transaction PRIVATE sdb_core)
    target_link_options(memory_transaction PRIVATE -Wl,--wrap=pwrite)

    function(add_ptrace_test name)
        add_test(NAME ${name} COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/run_checked.py"
            "$<TARGET_FILE:ptrace_probe>" ${ARGN})
        set_tests_properties(${name} PROPERTIES TIMEOUT 180 SKIP_RETURN_CODE 77 LABELS integration)
    endfunction()
    foreach(suite baseline regression stage2)
        add_ptrace_test(${suite} "${Python3_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/${suite}.py" "$<TARGET_FILE:sdb>")
    endforeach()
    add_ptrace_test(memory_transaction "$<TARGET_FILE:memory_transaction>" "$<TARGET_FILE:loop_fixture>")
    set_tests_properties(command_parser_and_options baseline regression stage2 memory_transaction
        PROPERTIES ENVIRONMENT "ASAN_OPTIONS=detect_leaks=1:halt_on_error=1;UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1")
endif()
