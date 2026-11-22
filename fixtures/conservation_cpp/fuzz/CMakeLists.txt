# Differential fuzzer for the ledger transfer: production C++ (impl/) vs the Lean oracle exported
# from the locked spec project. Configured by the harness (fuzz/run_fuzz.sh), which passes a
# trusted copy of the spec project built from spec/challenge only.
cmake_minimum_required(VERSION 3.20)
project(conservation_diff_fuzz LANGUAGES CXX)

set(FV_HARNESS_DIR "" CACHE PATH "Harness checkout (provides fuzz/LeanOracle.cmake)")
set(LEAN_PROJECT "" CACHE PATH "Trusted copy of the spec project")
set(LEAN_BIN_DIR "" CACHE PATH "Lean toolchain bin directory")
set(IMPL_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../impl" CACHE PATH "Production implementation headers")

include("${FV_HARNESS_DIR}/fuzz/LeanOracle.cmake")

lean_oracle_library(conservation_oracle
  LEAN_PROJECT "${LEAN_PROJECT}"
  LEAN_BIN_DIR "${LEAN_BIN_DIR}"
  PACKAGE fv_conservation
  LEAN_LIB FVSpec
  INIT_MODULES FVSpec.Oracle)

add_diff_fuzzer(diff_transfer
  BINDING "${CMAKE_CURRENT_SOURCE_DIR}/binding.hpp"
  ORACLE conservation_oracle
  INCLUDE_DIRS "${IMPL_DIR}")
