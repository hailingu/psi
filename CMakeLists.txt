cmake_minimum_required(VERSION 3.23)
project(psi C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_BUILD_TYPE "Release")

include_directories(include)
include_directories(src/psi)

FILE(GLOB crypto_src include/*.c)
FILE(GLOB psi_src src/psi/*.c)

add_executable(psi ${crypto_src} ${psi_src} src/main.c)
