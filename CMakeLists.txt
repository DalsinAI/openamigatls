cmake_minimum_required(VERSION 3.16)
project(OpenTLS C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_library(opencrypto STATIC src/opencrypto_sha256.c)
target_include_directories(opencrypto PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_executable(test_opencrypto tests/test_opencrypto.c)
target_link_libraries(test_opencrypto PRIVATE opencrypto)

enable_testing()
add_test(NAME opencrypto_vectors COMMAND test_opencrypto)
