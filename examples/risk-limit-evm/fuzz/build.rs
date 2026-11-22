// build.rs — wires the compiled contract, the harness files and the Lean oracle into the fuzz target.
//   FV_EVM_CREATION, FV_EVM_RUNTIME  the contract's creation and runtime bytecode (raw bytes),
//                      compiled by fuzz/run_fuzz.sh --lang evm with the pinned solc
//   FV_EVM_SPEC        the evmVersion it was compiled for
//   FV_ORACLE_LIB_DIR  directory holding lib<FV_ORACLE_LIB>.so (the oracle from the locked spec)
//   FV_ORACLE_LIB      library name (default diff_risk_oracle)
//   FV_DIFF_RS, FV_EVM_RS  the harness's driver and EVM executor (default: vendored copies here)
use std::env;
use std::path::PathBuf;

fn pass(var: &str, default: Option<PathBuf>) {
    let p = env::var(var).map(PathBuf::from).ok().or(default)
        .unwrap_or_else(|| panic!("{var} is not set (run through fuzz/run_fuzz.sh --lang evm)"));
    let p = p.canonicalize().unwrap_or_else(|_| panic!("{var}: {} not found", p.display()));
    println!("cargo:rustc-env={var}={}", p.display());
    println!("cargo:rerun-if-env-changed={var}");
    println!("cargo:rerun-if-changed={}", p.display());
}

fn main() {
    let here = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    println!("cargo::rustc-check-cfg=cfg(fv_classify)");
    pass("FV_DIFF_RS", Some(here.join("fv_diff.rs")));
    pass("FV_EVM_RS", Some(here.join("fv_evm.rs")));
    pass("FV_EVM_CREATION", None);
    pass("FV_EVM_RUNTIME", None);
    let spec = env::var("FV_EVM_SPEC").expect("FV_EVM_SPEC is not set (run through fuzz/run_fuzz.sh --lang evm)");
    println!("cargo:rustc-env=FV_EVM_SPEC={spec}");
    println!("cargo:rerun-if-env-changed=FV_EVM_SPEC");

    let lib_dir = env::var("FV_ORACLE_LIB_DIR").expect("FV_ORACLE_LIB_DIR is not set (run through fuzz/run_fuzz.sh --lang evm)");
    let lib = env::var("FV_ORACLE_LIB").unwrap_or_else(|_| "diff_risk_oracle".into());
    println!("cargo:rustc-link-search=native={lib_dir}");
    println!("cargo:rustc-link-lib=dylib={lib}");
    println!("cargo:rustc-link-arg=-Wl,-rpath,{lib_dir}");
    println!("cargo:rerun-if-env-changed=FV_ORACLE_LIB_DIR");
    println!("cargo:rerun-if-env-changed=FV_ORACLE_LIB");
}
