cmake_minimum_required(VERSION 3.20...3.28)
project(llnet CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Header-only library — no compilation of its own.
# When used as a subdirectory the consumer must provide the wolfssl target.
# When built standalone (tests) we fall back to system OpenSSL.
if(NOT TARGET wolfssl)
    find_package(OpenSSL REQUIRED)
    add_library(wolfssl INTERFACE)
    target_link_libraries(wolfssl INTERFACE OpenSSL::SSL OpenSSL::Crypto)
endif()

add_library(llnet INTERFACE)
target_include_directories(llnet INTERFACE include)
target_compile_features(llnet INTERFACE cxx_std_23)
target_link_libraries(llnet INTERFACE wolfssl)

# ── tests (only when built standalone, not as a subdirectory) ─────────────────
if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    include(FetchContent)
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_Declare(
        googletest
        URL                    https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    FetchContent_MakeAvailable(googletest)

    enable_testing()
    add_executable(llnet_tests test/ws_socket_test.cpp)
    target_link_libraries(llnet_tests PRIVATE llnet GTest::gtest_main)

    include(GoogleTest)
    gtest_discover_tests(llnet_tests)
endif()
