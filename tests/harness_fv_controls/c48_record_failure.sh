#!/usr/bin/env bash
# c48_record_failure.sh RUN_FUZZ OUTDIR — control c48: the fuzz.json record is part of the verdict. A jq
# that fails only on the call that writes fuzz.json (a PATH shim; every other jq call is the real one)
# must turn both a run that would PASS and one that would FAIL into ERROR (exit 3), never exit 0 or 1
# with a missing or empty record. Prints "c48_record_failure OK|WRONG ..."; exit 0 iff OK.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RF="${1:?}"; X="${2:?}"; rm -rf "${X:?}"; mkdir -p "$X/bin"
REAL=$(command -v jq)
python3 -I - "$X/bin/jq" "$REAL" <<'PY'
import sys
# the shim fails only the fuzz.json writer (the one jq call given --arg draft); others run the real jq
p, real = sys.argv[1], sys.argv[2]
open(p, "w").write(f"""#!/bin/sh
prev=""
for a in "$@"; do
  if [ "$prev" = "--arg" ] && [ "$a" = "draft" ]; then echo "jq: injected failure" >&2; exit 5; fi
  prev="$a"
done
exec {real} "$@"
""")
PY
chmod +x "$X/bin/jq"
FIX="$ROOT/fixtures/conservation"; LOCK="$ROOT/locks/conservation.sha256"; CPP="$ROOT/fixtures/conservation_cpp/fuzz"
run() { # run NAME IMPL ARGS...
  local n="$1" impl="$2"; shift 2; cp -r "$CPP/corpus" "$X/$n.corpus"
  PATH="$X/bin:$PATH" "$RF" --lean-project "$FIX" --lock "$LOCK" --cmake-dir "$CPP" --target diff_transfer --impl-dir "$impl" \
    --corpus "$X/$n.corpus" --no-merge --out "$X/$n" "$@" > "$X/$n.out" 2>&1
}
run pass "$ROOT/fixtures/conservation_cpp/impl" --runs 2000; rp=$?
run fail "$ROOT/tests/harness_fv_controls/variants/c6_drift" --time 10; rf=$?
dp=$(jq -r .verdict "$X/pass/fuzz.json" 2>/dev/null); df=$(jq -r .verdict "$X/fail/fuzz.json" 2>/dev/null)
if [ $rp -eq 3 ] && [ $rf -eq 3 ] && [ "$dp" = ERROR ] && [ "$df" = ERROR ] && grep -q 'intended verdict was PASS' "$X/pass.out" \
   && grep -q 'intended verdict was FAIL' "$X/fail.out"; then
  echo "c48_record_failure OK fuzz.json writer failing: a run that would PASS and one that would FAIL each end ERROR (exit 3), record says ERROR"
else
  echo "c48_record_failure WRONG would-pass exit=$rp record=[${dp:-empty}] would-fail exit=$rf record=[${df:-empty}]"; exit 1
fi
