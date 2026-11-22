"""compile.py — compile the contract under test with the pinned solc (fuzz/run_fuzz.sh --lang evm).

    compile.py --solc SOLC --src-dir DIR --fv-toml FILE --out DIR

Reads [evm] from fv.toml: contract, source, evm_version, optimizer, optimizer_runs and, optionally,
expect_runtime_sha256. Every *.sol file in DIR is compiled together through solc's standard JSON
interface; no import callback, so nothing outside DIR is read and nothing is fetched. Writes
OUT/creation.bin and OUT/runtime.bin (raw bytes) and OUT/solc-output.json, and prints a JSON
summary (compiler version, settings, sha256 of the sources and of both bytecodes).

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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--solc", required=True)
    ap.add_argument("--src-dir", required=True)
    ap.add_argument("--fv-toml", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    try:
        cfg = tomllib.load(open(a.fv_toml, "rb")).get("evm", {})
    except OSError as e:
        die(f"cannot read {a.fv_toml}: {e}")
    for k in ("contract", "source", "evm_version"):
        if not isinstance(cfg.get(k), str) or not cfg[k]:
            die(f"[evm] {k} is required in {a.fv_toml}")
    optimizer = cfg.get("optimizer", False)
    runs = cfg.get("optimizer_runs", 200)
    if not isinstance(optimizer, bool) or not isinstance(runs, int) or runs < 1:
        die("[evm] optimizer must be true/false and optimizer_runs a positive integer")
    src = pathlib.Path(a.src_dir)
    files = sorted(p for p in src.glob("*.sol") if p.is_file())
    if not any(p.name == cfg["source"] for p in files):
        die(f"{cfg['source']} not found in {src}")
    sources = {p.name: {"content": p.read_text()} for p in files}
    settings = {
        "optimizer": {"enabled": optimizer, "runs": runs},
        "evmVersion": cfg["evm_version"],
        "outputSelection": {cfg["source"]: {cfg["contract"]: ["evm.bytecode.object", "evm.deployedBytecode.object",
                                                              "evm.deployedBytecode.immutableReferences"]}},
    }
    req = {"language": "Solidity", "sources": sources, "settings": settings}
    r = subprocess.run([a.solc, "--standard-json"], input=json.dumps(req), capture_output=True, text=True, timeout=600)
    out = pathlib.Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "solc-output.json").write_text(r.stdout)
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
    if evm["deployedBytecode"].get("immutableReferences"):
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
        "expect_runtime_sha256": cfg.get("expect_runtime_sha256", ""),
        "warnings": sum(1 for e in res.get("errors", []) if e.get("severity") == "warning"),
    }
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
