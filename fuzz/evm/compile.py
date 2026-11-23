"""compile.py — compile the contract under test with the pinned solc (fuzz/run_fuzz.sh --lang evm).

    compile.py --solc SOLC --src-dir DIR --fv-toml FILE --out DIR [--section evm|tron-tvm]

Reads [evm] (or [tron-tvm], for the TRON compiler) from fv.toml: contract, source, evm_version, optimizer, optimizer_runs and, optionally,
expect_runtime_sha256. Every *.sol file in DIR is compiled together through solc's standard JSON
interface; no import callback, so nothing outside DIR is read and nothing is fetched. Writes
OUT/creation.bin and OUT/runtime.bin (raw bytes) and OUT/solc-output.json, and prints a JSON
summary (compiler version, settings, sha256 of the sources and of both bytecodes, and of the runtime
bytecode with its CBOR metadata trailer stripped, which compares builds whose metadata differs).

Exit: 0 compiled; 3 configuration or compiler error (message on stderr).
"""
import argparse
import hashlib
import json
import pathlib
import subprocess
import sys
import tomllib


def die(msg):
    sys.stderr.write(f"compile.py: {msg}\n")
    sys.exit(3)


def strip_metadata(code: bytes) -> bytes:
    """Runtime code without the compiler's CBOR metadata trailer (a CBOR map, then its 2-byte length)."""
    if len(code) < 2:
        return code
    n = int.from_bytes(code[-2:], "big")
    if n + 2 <= len(code) and 0xa1 <= code[-(n + 2)] <= 0xa5:
        return code[:-(n + 2)]
    return code


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--solc", required=True)
    ap.add_argument("--src-dir", required=True)
    ap.add_argument("--fv-toml", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--section", default="evm", choices=("evm", "tron-tvm"))
    a = ap.parse_args()
    try:
        cfg = tomllib.load(open(a.fv_toml, "rb")).get(a.section, {})
    except OSError as e:
        die(f"cannot read {a.fv_toml}: {e}")
    for k in ("contract", "source", "evm_version"):
        if not isinstance(cfg.get(k), str) or not cfg[k]:
            die(f"[{a.section}] {k} is required in {a.fv_toml}")
    optimizer = cfg.get("optimizer", False)
    runs = cfg.get("optimizer_runs", 200)
    if not isinstance(optimizer, bool) or not isinstance(runs, int) or runs < 1:
        die(f"[{a.section}] optimizer must be true/false and optimizer_runs a positive integer")
    src = pathlib.Path(a.src_dir)
    files = sorted(p for p in src.glob("*.sol") if p.is_file())
    if not any(p.name == cfg["source"] for p in files):
        die(f"{cfg['source']} not found in {src}")
    sources = {p.name: {"content": p.read_text()} for p in files}
    settings = {
        "optimizer": {"enabled": optimizer, "runs": runs},
        "evmVersion": cfg["evm_version"],
        "outputSelection": {cfg["source"]: {cfg["contract"]: ["evm.bytecode.object", "evm.deployedBytecode.object",
                                                              "evm.deployedBytecode.immutableReferences",
                                                              "evm.deployedBytecode.sourceMap"]}},
    }
    req = {"language": "Solidity", "sources": sources, "settings": settings}
    r = subprocess.run([a.solc, "--standard-json"], input=json.dumps(req), capture_output=True, text=True, timeout=600)
    out = pathlib.Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "solc-output.json").write_text(r.stdout)
    (out / "src").mkdir(exist_ok=True)  # the sources as compiled, for source-mapped reports
    for n, src_ in sources.items():
        (out / "src" / n).write_text(src_["content"])
    try:
        res = json.loads(r.stdout)
    except json.JSONDecodeError:
        die(f"solc produced no JSON (exit {r.returncode}): {r.stderr.strip()[:300]}")
    errs = [e for e in res.get("errors", []) if e.get("severity") == "error"]
    if errs:
        die("solc: " + " | ".join(e.get("formattedMessage", e.get("message", "")).strip().splitlines()[0] for e in errs)[:500])
    try:
        evm = res["contracts"][cfg["source"]][cfg["contract"]]["evm"]
    except KeyError:
        die(f"contract {cfg['contract']} not found in {cfg['source']}")
    if evm["deployedBytecode"].get("immutableReferences"):  # (0.5.x compilers do not report it)
        die("the contract has immutables: its runtime code is only known after deployment (not supported)")
    creation = bytes.fromhex(evm["bytecode"]["object"])
    runtime = bytes.fromhex(evm["deployedBytecode"]["object"])
    if not creation or not runtime:
        die("empty bytecode (abstract contract or interface?)")
    (out / "creation.bin").write_bytes(creation)
    (out / "runtime.bin").write_bytes(runtime)
    ver = subprocess.run([a.solc, "--version"], capture_output=True, text=True).stdout.strip().splitlines()[-1]
    sha = lambda b: hashlib.sha256(b).hexdigest()
    summary = {
        "solc_version": ver.removeprefix("Version: "),
        "contract": cfg["contract"], "source": cfg["source"],
        "settings": {"optimizer": optimizer, "optimizer_runs": runs, "evm_version": cfg["evm_version"]},
        "sources_sha256": {n: sha(s["content"].encode()) for n, s in sources.items()},
        "creation_sha256": sha(creation), "creation_bytes": len(creation),
        "runtime_sha256": sha(runtime), "runtime_bytes": len(runtime),
        "runtime_stripped_sha256": sha(strip_metadata(runtime)), "runtime_stripped_bytes": len(strip_metadata(runtime)),
        "expect_runtime_sha256": cfg.get("expect_runtime_sha256", ""),
        "warnings": sum(1 for e in res.get("errors", []) if e.get("severity") == "warning"),
    }
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
