cmake_minimum_required(VERSION 4.0)
project(encrypted_rev_shell)

set(CMAKE_CXX_STANDARD 20)

add_executable(encrypted_rev_shell main.cpp
        utils.h)
