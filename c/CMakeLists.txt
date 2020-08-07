cmake_minimum_required(VERSION 3.15)
project(dac_hg_sigs LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS "-O3" )
set(CMAKE_C_COMPILER /usr/bin/gcc)

add_subdirectory(miracl_core_c_bn254/)
add_executable(dac_hg_sigs mercurial_signature_scheme.c)

target_link_libraries(dac_hg_sigs miracl_core_c_bn254)
