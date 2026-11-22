"""verdict.py RUN VERDICT EXIT PROJECT LOCK — print the gate's verdict.json for one run."""
import hashlib
import json
import pathlib
import sys

run, verdict, code, project, lock = sys.argv[1:6]
run_p = pathlib.Path(run)
stages = {}
for st in sorted((run_p / "stages").glob("*.status")):
    stages[st.stem] = st.read_text().strip()


def sha(p):
    p = pathlib.Path(p)
    return hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None


exports = {n: sha(run_p / "exports" / f"{n}.ndjson") for n in ("challenge", "solution")}
prov = run_p / "provenance.txt"
signer = {}
sf = run_p / "signer.txt"
if sf.is_file():  # "SIGNER principal=... fingerprint=... pinned=... match=..."
    signer = dict(kv.split("=", 1) for kv in sf.read_text().split()[1:] if "=" in kv)
print(json.dumps({
    # First key on purpose: the operator compares this fingerprint with the one they stated.
    "spec_lock_signer": signer,
    "verdict": verdict,
    "exit": int(code),
    "project": project,
    "lock_file": lock,
    "lock_digest": sha(lock),
    "stages": stages,
    "exports_sha256": exports,
    "provenance": prov.read_text().splitlines() if prov.is_file() else [],
    "run_dir": str(run_p),
}, indent=2))
