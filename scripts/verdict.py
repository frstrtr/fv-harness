"""verdict.py RUN VERDICT EXIT PROJECT LOCK [LOCK_COPY] — print the gate's verdict.json for one run (the digest is the
copy's: the file the gate checked)."""
import hashlib
import json
import pathlib
import sys

run, verdict, code, project, lock = sys.argv[1:6]
lock_copy = sys.argv[6] if len(sys.argv) > 6 and sys.argv[6] else None
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
    "lock_digest": sha(lock_copy) if lock_copy else None,   # the copy the gate checked, never the file as it is now
    "stages": stages,
    "exports_sha256": exports,
    "provenance": prov.read_text().splitlines() if prov.is_file() else [],
    "run_dir": str(run_p),
    # Test hooks (FV_TEST_HOOK_*) set during the run: controls only; CLOSE refuses a run with any.
    "test_hooks": (run_p / "test_hooks.txt").read_text().split() if (run_p / "test_hooks.txt").is_file() else [],
}, indent=2))
