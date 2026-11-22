# Builds only the Lean oracle, as a shared library, for the EVM fuzz target (fuzz/run_fuzz.sh
# --lang evm passes a trusted copy of the spec project built from spec/challenge only).
cmake_minimum_required(VERSION 3.20)
project(risk_limit_evm_oracle LANGUAGES C CXX)

set(FV_HARNESS_DIR "" CACHE PATH "Harness checkout (provides fuzz/LeanOracle.cmake)")
set(LEAN_PROJECT "" CACHE PATH "Trusted copy of the spec project")
set(LEAN_BIN_DIR "" CACHE PATH "Lean toolchain bin directory")

include("${FV_HARNESS_DIR}/fuzz/LeanOracle.cmake")

lean_oracle_library(risk_oracle_static
  LEAN_PROJECT "${LEAN_PROJECT}"
  LEAN_BIN_DIR "${LEAN_BIN_DIR}"
  PACKAGE fv_risk_limit
  LEAN_LIB RiskSpec
  INIT_MODULES RiskSpec.Oracle)

# run_fuzz.sh --lang evm builds the target <fuzz target>_oracle.
lean_oracle_shared(diff_risk_oracle ORACLE risk_oracle_static)
