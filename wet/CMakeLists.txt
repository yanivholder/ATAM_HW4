cmake_minimum_required(VERSION 3.17)
project(wet C)

set(CMAKE_C_STANDARD 99)

add_executable(wet main.c debugee.c small_debuger.c)
add_executable(wet2 small_debuger.c debugee.c)

