cmake_minimum_required(VERSION 3.20...3.28)
project(llnet CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── llnet: header-only, SSL-agnostic ─────────────────────────────────────────
# Consumers link their own SSL backend (OpenSSL or wolfSSL + USE_WOLFSSL).
# Subdirectory use: if no 'wolfssl' target exists, fall back to system OpenSSL
# so existing consumers keep working without changes.
add_library(llnet INTERFACE)
target_include_directories(llnet INTERFACE include)
target_compile_features(llnet INTERFACE cxx_std_23)

if(NOT CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    if(NOT TARGET wolfssl)
        find_package(OpenSSL REQUIRED)
        add_library(wolfssl INTERFACE)
        target_link_libraries(wolfssl INTERFACE OpenSSL::SSL OpenSSL::Crypto)
    endif()
    target_link_libraries(llnet INTERFACE wolfssl)
endif()

# ── standalone build: unit tests + examples ───────────────────────────────────
if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    include(FetchContent)

    # Build options — set OFF for offline or OpenSSL-only builds.
    #   -DLLNET_WOLFSSL=OFF   skip wolfSSL fetch/example (tests still build via OpenSSL)
    #   -DLLNET_EXAMPLES=OFF  skip live examples and simdjson fetch
    option(LLNET_WOLFSSL   "Build wolfSSL backend and live example (fetches wolfSSL if not installed)" ON)
    option(LLNET_EXAMPLES  "Build live Binance BBO examples (fetches simdjson if not installed)"       ON)

    # ── OpenSSL (system) ──────────────────────────────────────────────────────
    find_package(OpenSSL REQUIRED)

    # ── wolfSSL (system or fetched, only when LLNET_WOLFSSL=ON) ──────────────
    # WOLFSSL_OPENSSLEXTRA enables the OpenSSL compatibility layer that llnet uses
    # (SSL_CTX_new, BIO_new, SSL_write, etc.).
    if(LLNET_WOLFSSL)
        find_package(wolfssl QUIET)
        if(NOT TARGET wolfssl)
            set(WOLFSSL_OPENSSLEXTRA yes CACHE STRING "" FORCE)
            set(WOLFSSL_SNI          yes CACHE STRING "" FORCE)
            set(WOLFSSL_EXAMPLES     no  CACHE STRING "" FORCE)
            set(WOLFSSL_CERTS_TEST   no  CACHE STRING "" FORCE)
            set(BUILD_SHARED_LIBS    OFF CACHE BOOL   "" FORCE)
            FetchContent_Declare(
                wolfssl
                GIT_REPOSITORY https://github.com/wolfSSL/wolfssl.git
                GIT_TAG        v5.7.6-stable
                GIT_SHALLOW    TRUE
            )
            FetchContent_MakeAvailable(wolfssl)
        endif()
    endif()

    # ── SSL-backed interface targets ──────────────────────────────────────────
    add_library(llnet_openssl INTERFACE)
    target_link_libraries(llnet_openssl INTERFACE llnet OpenSSL::SSL OpenSSL::Crypto)

    if(LLNET_WOLFSSL)
        add_library(llnet_wolfssl INTERFACE)
        target_link_libraries(llnet_wolfssl INTERFACE llnet wolfssl)
        target_compile_definitions(llnet_wolfssl INTERFACE USE_WOLFSSL)
    endif()

    # ── unit tests (OpenSSL) ──────────────────────────────────────────────────
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    find_package(GTest QUIET)
    if(NOT TARGET GTest::gtest_main)
        FetchContent_Declare(
            googletest
            URL                    https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
            DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        )
        FetchContent_MakeAvailable(googletest)
    endif()

    enable_testing()
    add_executable(llnet_tests unit_tests/ws_socket_test.cpp)
    target_link_libraries(llnet_tests PRIVATE llnet_openssl GTest::gtest_main)
    include(GoogleTest)
    gtest_discover_tests(llnet_tests)

    # ── examples (only when LLNET_EXAMPLES=ON) ────────────────────────────────
    if(LLNET_EXAMPLES)
        # simdjson: used for zero-copy SIMD parsing on the aligned recv buffer
        # (WsSocket constructed with SIMDJSON_PADDING extra bytes).
        find_package(simdjson QUIET)
        if(NOT TARGET simdjson)
            set(SIMDJSON_JUST_LIBRARY ON  CACHE BOOL "" FORCE)
            set(SIMDJSON_BUILD_STATIC ON  CACHE BOOL "" FORCE)
            FetchContent_Declare(
                simdjson
                GIT_REPOSITORY https://github.com/simdjson/simdjson.git
                GIT_TAG        v3.10.1
                GIT_SHALLOW    TRUE
            )
            FetchContent_MakeAvailable(simdjson)
        endif()

        add_executable(llnet_live_binance_bbo_openssl examples/live_binance_bbo.cpp)
        target_link_libraries(llnet_live_binance_bbo_openssl PRIVATE llnet_openssl simdjson)

        if(LLNET_WOLFSSL)
            add_executable(llnet_live_binance_bbo_wolfssl examples/live_binance_bbo.cpp)
            target_link_libraries(llnet_live_binance_bbo_wolfssl PRIVATE llnet_wolfssl simdjson)
        endif()
    endif()
endif()
