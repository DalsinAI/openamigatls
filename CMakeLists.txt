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

# ---- OpenTLS on BearSSL (third_party/bearssl, MIT), for the host tests ----
file(GLOB BEARSSL_SRC ${CMAKE_CURRENT_SOURCE_DIR}/third_party/bearssl/src/*/*.c
                      ${CMAKE_CURRENT_SOURCE_DIR}/third_party/bearssl/src/*.c)
add_library(bearssl STATIC ${BEARSSL_SRC})
target_include_directories(bearssl PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/third_party/bearssl/inc
                                   PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/third_party/bearssl/src)

add_library(opentls STATIC
    src/opentls/ot_core.c src/opentls/ot_glue.c src/opentls/ot_platform.c
    src/opentls/ot_random.c src/opentls/ot_trust.c src/opentls/ot_x509.c)
target_include_directories(opentls PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/host/include
                                          ${CMAKE_CURRENT_SOURCE_DIR}/include
                                   PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/third_party/bearssl/src)
target_compile_options(opentls PRIVATE -Wall -Wextra -Werror)
target_link_libraries(opentls PUBLIC bearssl opencrypto)

add_executable(opentls_client tests/opentls_client.c)
target_link_libraries(opentls_client PRIVATE opentls)
add_executable(opentls_ftps_get tests/opentls_ftps_get.c)
target_link_libraries(opentls_ftps_get PRIVATE opentls)
add_executable(test_opentls_units tests/test_opentls_units.c)
target_include_directories(test_opentls_units PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/opentls
                                                      ${CMAKE_CURRENT_SOURCE_DIR}/third_party/bearssl/src)
target_link_libraries(test_opentls_units PRIVATE opentls)

add_test(NAME opentls_units COMMAND test_opentls_units)
if(Python3_FOUND)
    add_test(NAME opentls_ca_bundle
             COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_ca_bundle.py
                     $<TARGET_FILE:opentls_client> ${CMAKE_CURRENT_BINARY_DIR}/ca-bundle)
    add_test(NAME opentls_local_servers
             COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_tls_local.py
                     $<TARGET_FILE:opentls_client> $<TARGET_FILE:opentls_ftps_get>)
endif()
