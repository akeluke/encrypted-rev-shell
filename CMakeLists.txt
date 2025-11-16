cmake_minimum_required(VERSION 4.0)
project(encrypted_rev_shell)

set(CMAKE_CXX_STANDARD 20)

add_executable(encrypted_rev_shell main.cpp
        utils.h
        args_parser.h
        client.h
        server.h)

# preparing to make binary static
if(${CMAKE_BUILD_TYPE} STREQUAL "Release")
    set(BUILD_SHARED_LIBS OFF)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
    set(OPENSSL_ROOT_DIR "${CMAKE_SOURCE_DIR}/openssl-static")
    set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT_DIR}/include")
    set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_ROOT_DIR}/lib64/libcrypto.a")
    set(OPENSSL_SSL_LIBRARY "${OPENSSL_ROOT_DIR}/lib64/libssl.a")
endif()


find_package(OpenSSL REQUIRED)

target_link_libraries(encrypted_rev_shell PRIVATE OpenSSL::SSL OpenSSL::Crypto)