cmake_minimum_required(VERSION 3.22)
project(RSASign)

set(CMAKE_CXX_STANDARD 14)

add_executable(RSASign main.cpp RSA.h)

target_link_libraries(RSASign gmp)
target_link_libraries(RSASign gmpxx)
