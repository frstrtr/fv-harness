# Differential fuzzer for the pre-trade risk check: production C++ (impl/) vs the Lean oracle
# exported from the locked spec project. Configured by the harness (fuzz/run_fuzz.sh), which
# passes a trusted copy of the spec project built from spec/challenge only.
cmake_minimum_required(VERSION 3.20)
project(risk_limit_diff_fuzz LANGUAGES CXX)

set(FV_HARNESS_DIR "" CACHE PATH "Harness checkout (provides fuzz/LeanOracle.cmake)")
set(LEAN_PROJECT "" CACHE PATH "Trusted copy of the spec project")
set(LEAN_BIN_DIR "" CACHE PATH "Lean toolchain bin directory")
set(IMPL_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../impl" CACHE PATH "Production implementation headers")

include("${FV_HARNESS_DIR}/fuzz/LeanOracle.cmake")

lean_oracle_library(risk_oracle
  LEAN_PROJECT "${LEAN_PROJECT}"
  LEAN_BIN_DIR "${LEAN_BIN_DIR}"
  PACKAGE fv_risk_limit
  LEAN_LIB RiskSpec
  INIT_MODULES RiskSpec.Oracle)

add_diff_fuzzer(diff_risk
  BINDING "${CMAKE_CURRENT_SOURCE_DIR}/binding.hpp"
  ORACLE risk_oracle
  INCLUDE_DIRS "${IMPL_DIR}")
