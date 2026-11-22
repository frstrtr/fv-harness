// build.rs — wires the implementation under test and the Lean oracle into the fuzz target.
//   FV_IMPL_DIR        directory holding lib.rs, the implementation under test (default ../impl)
//   FV_ORACLE_LIB_DIR  directory holding lib<FV_ORACLE_LIB>.so, built by fuzz/run_fuzz.sh from the
//                      locked spec only (lean_oracle_shared in CMakeLists.txt)
//   FV_ORACLE_LIB      library name (default diff_risk_oracle)
//   FV_DIFF_RS         the harness's Rust driver, fuzz/rust/fv_diff.rs (default: vendored ./fv_diff.rs)
use std::env;
use std::path::PathBuf;

fn main() {
    let here = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let impl_dir = env::var("FV_IMPL_DIR").map(PathBuf::from).unwrap_or_else(|_| here.join("../impl"));
    let lib_rs = impl_dir.join("lib.rs").canonicalize().expect("FV_IMPL_DIR/lib.rs not found");
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    std::fs::write(out.join("impl.rs"), format!("include!({:?});\n", lib_rs)).unwrap();
    println!("cargo:rerun-if-env-changed=FV_IMPL_DIR");
    println!("cargo:rerun-if-changed={}", lib_rs.display());

    // The harness-owned driver: fuzz/run_fuzz.sh points FV_DIFF_RS at the harness copy; without it
    // (standalone builds) the vendored copy next to Cargo.toml is used, which
    // fuzz/check_vendored.sh pins against the harness release it names.
    let driver = env::var("FV_DIFF_RS").map(PathBuf::from).unwrap_or_else(|_| here.join("fv_diff.rs"));
    let driver = driver.canonicalize().expect("fv_diff.rs not found (FV_DIFF_RS or a vendored fuzz/fv_diff.rs)");
    println!("cargo:rustc-env=FV_DIFF_RS={}", driver.display());
    println!("cargo:rerun-if-env-changed=FV_DIFF_RS");
    println!("cargo:rerun-if-changed={}", driver.display());

    let lib_dir = env::var("FV_ORACLE_LIB_DIR").expect("FV_ORACLE_LIB_DIR is not set (run through fuzz/run_fuzz.sh --lang rust)");
    let lib = env::var("FV_ORACLE_LIB").unwrap_or_else(|_| "diff_risk_oracle".into());
    println!("cargo:rustc-link-search=native={lib_dir}");
    println!("cargo:rustc-link-lib=dylib={lib}");
    println!("cargo:rustc-link-arg=-Wl,-rpath,{lib_dir}");
    println!("cargo:rerun-if-env-changed=FV_ORACLE_LIB_DIR");
    println!("cargo:rerun-if-env-changed=FV_ORACLE_LIB");
}
