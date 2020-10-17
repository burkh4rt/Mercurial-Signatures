cmake_minimum_required(VERSION 3.13)
project(dac_hg_sigs LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "-O3" )

add_subdirectory(miracl_core_cpp_bn254/)
add_executable(dac_hg_sigs mercurial_signature_scheme.cpp)

target_link_libraries(dac_hg_sigs miracl_core_cpp_bn254)