cmake_minimum_required(VERSION 3.16)
project(OpenTLS C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_library(opencrypto STATIC
    src/opencrypto_sha256.c src/opencrypto_sha512.c
    src/opencrypto_x25519.c src/opencrypto_ed25519.c
    src/opencrypto_sntrup761.c src/opencrypto_chacha20.c
    src/opencrypto_aes.c src/opencrypto_pubkey.c)
target_include_directories(opencrypto PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_executable(test_opencrypto tests/test_opencrypto.c)
target_link_libraries(test_opencrypto PRIVATE opencrypto)

add_executable(test_ssh_primitives tests/test_ssh_primitives.c)
target_include_directories(test_ssh_primitives PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
target_link_libraries(test_ssh_primitives PRIVATE opencrypto)

add_executable(oc_cli tests/oc_cli.c)
target_link_libraries(oc_cli PRIVATE opencrypto)

enable_testing()
add_test(NAME opencrypto_vectors COMMAND test_opencrypto)
add_test(NAME opencrypto_ssh_vectors COMMAND test_ssh_primitives)
# against Python's cryptography package (OpenSSL), when it is installed
find_package(Python3 COMPONENTS Interpreter)
if(Python3_FOUND)
    execute_process(COMMAND ${Python3_EXECUTABLE} -c "import cryptography"
                    RESULT_VARIABLE HAVE_PYCRYPTOGRAPHY OUTPUT_QUIET ERROR_QUIET)
    if(HAVE_PYCRYPTOGRAPHY EQUAL 0)
        add_test(NAME opencrypto_differential
                 COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/differential.py $<TARGET_FILE:oc_cli> 100)
    endif()
endif()
