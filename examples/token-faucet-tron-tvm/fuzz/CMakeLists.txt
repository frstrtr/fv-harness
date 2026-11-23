# Builds only the Lean oracle, as a shared library, for the Python driver (fuzz/run_fuzz.sh
# --lang tron-tvm passes a trusted copy of the spec project built from spec/challenge only).
cmake_minimum_required(VERSION 3.20)
project(token_faucet_tron_tvm_oracle LANGUAGES C CXX)

set(FV_HARNESS_DIR "" CACHE PATH "Harness checkout (provides fuzz/LeanOracle.cmake)")
set(LEAN_PROJECT "" CACHE PATH "Trusted copy of the spec project")
set(LEAN_BIN_DIR "" CACHE PATH "Lean toolchain bin directory")

include("${FV_HARNESS_DIR}/fuzz/LeanOracle.cmake")

lean_oracle_library(faucet_oracle_static
  LEAN_PROJECT "${LEAN_PROJECT}"
  LEAN_BIN_DIR "${LEAN_BIN_DIR}"
  PACKAGE fv_token_faucet
  LEAN_LIB FaucetSpec
  INIT_MODULES FaucetSpec.Oracle)

# run_fuzz.sh --lang tron-tvm builds the target <fuzz target>_oracle.
lean_oracle_shared(diff_faucet_oracle ORACLE faucet_oracle_static)
