#!/usr/bin/env bash
# c50_bytes_abi.sh OUTDIR — control c50: the ByteArray oracle ABI (LeanOracle.cmake BYTES).
# Builds tests/harness_fv_controls/bytes_abi (a one-function Lean project + a C driver with ASan for the
# harness-side buffers). Lean's runtime heap is mimalloc, which ASan/LSan cannot see, so the Lean side
# is checked by memory growth and reference counts instead:
#   (a) leak: 1,000 warm-up calls, then 100,000 calls with 8 KiB inputs, TWICE: every result correct and
#       VmRSS growth under 8 MiB in both runs (the plateau is printed); red: the wrapper not releasing
#       its result, 10,000 calls: growth over 60 MiB;
#   (b) ownership: an input with two extra references goes through the wrapper, which must consume
#       exactly one (shared afterwards, exclusive after one release); never reads freed memory; red:
#       the wrapper also releasing the input: no longer shared; and the generated wrapper source never
#       releases the input itself;
#   (c) a declared length one byte short: rc 1 (ERROR), output untouched;
#   (d) without BYTES the generated stub is the old one line, unchanged;
#   (e) the Python side (fuzz/python/fv_oracle_bytes.py) on the same oracle: 1,000 correct results; a
#       declared length one byte short ends the process with "diff-oracle: ORACLE ERROR" and exit 87
#       (which run_fuzz.sh reports as ERROR); a declared length of 0 is refused.
# Prints "c50_bytes_abi OK|WRONG ..."; exit 0 iff OK.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT/scripts/lib.sh"
X="${1:?}"; rm -rf "${X:?}"; mkdir -p "$X"
cp -r "$ROOT/tests/harness_fv_controls/bytes_abi" "$X/src"; rm -rf "$X/src/lean/.lake"
B="$X/build"
capped cmake -S "$X/src" -B "$B" -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DFV_HARNESS_DIR="$ROOT" \
  -DLEAN_PROJECT="$X/src/lean" -DLEAN_BIN_DIR="$LEAN_TC/bin" > "$X/cmake.log" 2>&1 \
  && capped cmake --build "$B" -j "$FV_JOBS" >> "$X/cmake.log" 2>&1 \
  || { echo "c50_bytes_abi WRONG build failed (see $X/cmake.log): $(grep -m2 -i error "$X/cmake.log" | tr '\n' ' ' | cut -c1-200)"; exit 1; }
T="$B/bytes_abi_test"; export ASAN_OPTIONS=detect_leaks=0   # LSan is blind to Lean's heap (mimalloc); see (a)
growth() { grep -oE 'rss_growth_kb=-?[0-9]+' "$1" | grep -oE -- '-?[0-9]+$'; }
capped "$T" good 100000 8192 > "$X/a1.out" 2>&1; ra1=$?
capped "$T" good 100000 8192 > "$X/a2.out" 2>&1; ra2=$?
capped "$T" short 1 64 > "$X/c.out" 2>&1; rcs=$?
capped "$T" rc 1 8192 > "$X/b.out" 2>&1; rb=$?
plain=$(cat "$B/bytes_oracle_plain_stub.c" 2>/dev/null)
inrel=$(grep -c 'lean_dec(a)' "$B/bytes_oracle_stub.c")
cp "$B/bytes_oracle_stub.c" "$X/stub.orig.c"
variant() { # variant NAME OLD NEW MODE N : rebuild the driver with one change in the generated wrapper, run it
  cp "$X/stub.orig.c" "$B/bytes_oracle_stub.c"
  python3 -I - "$B/bytes_oracle_stub.c" "$2" "$3" <<'PY' || return 9
import sys
p, old, new = sys.argv[1], sys.argv[2].replace("\\n", "\n"), sys.argv[3].replace("\\n", "\n")
s = open(p).read()
if s.count(old) != 1:
    sys.exit("c50 setup: wrapper text not found: " + old)
open(p, "w").write(s.replace(old, new))
PY
  touch "$B/bytes_oracle_stub.c"; capped cmake --build "$B" --target bytes_abi_test -j "$FV_JOBS" >> "$X/cmake.log" 2>&1
  capped "$T" "$4" "$5" 8192 > "$X/$1.out" 2>&1
}
variant red-leak '  if (m) memcpy(out, lean_sarray_cptr(r), m);\n  lean_dec(r);\n  return 0;' \
                 '  if (m) memcpy(out, lean_sarray_cptr(r), m);\n  return 0;' good 10000; rl=$?
variant red-rc '  lean_object* r = fv_rev(a);  /* the function owns and releases a */' \
               '  lean_object* r = fv_rev(a);  lean_dec(a);' rc 1; rr=$?
cp "$X/stub.orig.c" "$B/bytes_oracle_stub.c"; touch "$B/bytes_oracle_stub.c"
capped cmake --build "$B" -j "$FV_JOBS" >> "$X/cmake.log" 2>&1
SO=$(find "$B" -maxdepth 2 -name 'libbytes_oracle.so' | head -1)
PYB="${FV_PY:-$FV_ROOT/py/venv/bin/python}"; [ -x "$PYB" ] || PYB=python3
pyp() { env -u ASAN_OPTIONS "$PYB" -I "$ROOT/tests/harness_fv_controls/bytes_abi/py_path.py" "$SO" "$ROOT/fuzz/python" "$1" > "$X/py-$1.out" 2>&1; }
pyp good; pg=$?; pyp short; ps=$?; pyp zero; pz=$?
g1=$(growth "$X/a1.out"); g2=$(growth "$X/a2.out"); gl=$(growth "$X/red-leak.out")
ok=1; r=""
if [ $ra1 -eq 0 ] && [ $ra2 -eq 0 ] && [ -n "$g1" ] && [ -n "$g2" ] && [ "$g1" -lt 8192 ] && [ "$g2" -lt 8192 ]; then
  r+="(a) 2 x 100000 calls x 8 KiB correct, RSS growth ${g1} kB and ${g2} kB (< 8 MiB; plateau $(grep -oE 'rss_after_kb=[0-9]+' "$X/a1.out" | cut -d= -f2) kB); "
else ok=0; r+="(a) WRONG exits $ra1/$ra2 growth ${g1:-?}/${g2:-?} kB [$(head -1 "$X/a1.out")]; "; fi
if [ $rl -eq 0 ] && [ -n "$gl" ] && [ "$gl" -gt 61440 ]; then r+="(a) red, result not released: +${gl} kB over 10000 calls; "
else ok=0; r+="(a) red WRONG exit=$rl growth=${gl:-?} kB (leak not seen); "; fi
if [ $rb -eq 0 ] && grep -q "rc: call=0 shared=1 exclusive=1" "$X/b.out" && [ "$inrel" = 0 ]; then
  r+="(b) one reference consumed (shared, then exclusive), wrapper never releases the input; "
else ok=0; r+="(b) WRONG exit=$rb [$(head -1 "$X/b.out")] input releases in stub=$inrel; "; fi
if [ $rr -ne 0 ] && [ $rr -ne 9 ] && grep -q "rc: call=0 shared=0" "$X/red-rc.out"; then r+="(b) red, input also released by the wrapper: not shared; "
else ok=0; r+="(b) red WRONG exit=$rr [$(head -1 "$X/red-rc.out")]; "; fi
if [ $rcs -eq 0 ] && grep -q "short: rc=1 got=65 untouched=1" "$X/c.out"; then r+="(c) length 1 short: rc=1, output untouched; "
else ok=0; r+="(c) WRONG exit=$rcs [$(head -1 "$X/c.out")]; "; fi
if [ "$plain" = "/* Generated by LeanOracle.cmake: the oracle as a shared library. */" ]; then r+="(d) no-BYTES stub unchanged"
else ok=0; r+="(d) WRONG stub: [${plain:0:120}]"; fi
if [ $pg -eq 0 ] && grep -q '^py good ok 1000$' "$X/py-good.out" && [ $ps -eq 87 ] && grep -q '^diff-oracle: ORACLE ERROR: fv_rev returned 65 bytes, the binding declares 64' "$X/py-short.out" \
   && ! grep -q 'py short returned' "$X/py-short.out" && [ $pz -eq 0 ] && grep -q '^py zero refused' "$X/py-zero.out"; then
  r+="; (e) Python path: 1000 results correct, 1 byte short: ORACLE ERROR exit 87, length 0 refused"
else ok=0; r+="; (e) Python path WRONG good=$pg [$(head -1 "$X/py-good.out")] short=$ps [$(head -1 "$X/py-short.out" | cut -c1-100)] zero=$pz [$(head -1 "$X/py-zero.out")]"; fi
[ $ok -eq 1 ] && echo "c50_bytes_abi OK $r" || { echo "c50_bytes_abi WRONG $r"; exit 1; }
