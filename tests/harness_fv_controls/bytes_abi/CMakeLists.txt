# Control c50: the ByteArray oracle ABI (LeanOracle.cmake BYTES), tested under ASan/LSan.
cmake_minimum_required(VERSION 3.20)
project(bytes_abi_control LANGUAGES C CXX)
set(FV_HARNESS_DIR "" CACHE PATH "Harness checkout")
set(LEAN_PROJECT "" CACHE PATH "Copy of the control's Lean project")
set(LEAN_BIN_DIR "" CACHE PATH "Lean toolchain bin directory")
include("${FV_HARNESS_DIR}/fuzz/LeanOracle.cmake")
lean_oracle_library(bytes_oracle_static LEAN_PROJECT "${LEAN_PROJECT}" LEAN_BIN_DIR "${LEAN_BIN_DIR}"
  PACKAGE fv_bytes_abi LEAN_LIB BytesOracle INIT_MODULES BytesOracle.Oracle)
lean_oracle_shared(bytes_oracle ORACLE bytes_oracle_static BYTES fv_rev)
lean_oracle_shared(bytes_oracle_plain ORACLE bytes_oracle_static)  # no BYTES: the stub must stay the old one
add_executable(bytes_abi_test bytes_abi_test.c)
target_compile_options(bytes_abi_test PRIVATE -fsanitize=address -fno-omit-frame-pointer -g)
target_link_options(bytes_abi_test PRIVATE -fsanitize=address)
target_link_libraries(bytes_abi_test PRIVATE bytes_oracle)
get_target_property(lean_prefix bytes_oracle_static FV_LEAN_PREFIX)
target_include_directories(bytes_abi_test PRIVATE "${lean_prefix}/include")
target_link_libraries(bytes_abi_test PRIVATE "${lean_prefix}/lib/lean/libleanshared.so")
target_link_options(bytes_abi_test PRIVATE "-Wl,-rpath,${lean_prefix}/lib/lean")
