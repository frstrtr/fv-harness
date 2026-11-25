#!/usr/bin/env bash
# c88_sysroot_lock.sh OUTDIR — fuzz/sysroot/make_lock.py reads only what gpgv verified.
#
# A local mirror (file://) for the three pockets, each InRelease clear-signed by a throwaway test key
# (FV_SYSROOT_MIRROR / FV_SYSROOT_KEYRING, the test-only overrides), with eight fake package stanzas:
#   (a) honest mirror: a lock is written, naming the indexed .deb sha256s, and --check passes;
#   (b) an unsigned SHA256 list placed before the signed block of noble-updates' InRelease (gpgv still
#       says "Good signature") that names an attacker's Packages.xz, which the mirror serves: refused;
#   (c) noble's signed InRelease served as noble-updates' (a replay of another suite): refused;
#   (d) --check on a lock whose libc6 sha256 was changed: exit 1, MISMATCH named.
# Prints one line "c88_sysroot_lock OK|WRONG|SKIPPED ..."; needs gpg, gpgv, dpkg (SKIPPED without them).
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$1"; mkdir -p "$OUT"
for t in gpg gpgv dpkg; do command -v "$t" > /dev/null || { echo "c88_sysroot_lock SKIPPED $t is absent"; exit 0; }; done
W=$(mktemp -d "$OUT/c88.XXXX")
export GNUPGHOME="$W/gnupg"; mkdir -m 700 "$GNUPGHOME"
gpg --batch --quiet --passphrase '' --quick-gen-key "fv c88 test <nobody@nonexistent.invalid>" ed25519 sign never > /dev/null 2>&1
gpg --batch --export > "$W/test-keyring.gpg"
python3 -I - "$W" <<'PY' || { echo "c88_sysroot_lock WRONG setup failed"; exit 1; }
import hashlib, lzma, os, subprocess, sys
w = sys.argv[1]
pk = ("libc6", "libc6-dev", "libgcc-13-dev", "libstdc++-13-dev", "libgcc-s1", "linux-libc-dev", "libcrypt-dev", "libcrypt1")
def packages(tag):
    st = []
    for i, p in enumerate(pk):
        h = hashlib.sha256(f"{tag}-{p}".encode()).hexdigest()
        rev = {"noble": 1, "noble-security": 2, "upd": 3, "evil": 4}[tag]   # noble-updates is the highest
        st.append(f"Package: {p}\nArchitecture: amd64\nVersion: 1.{i}-{rev}\nFilename: pool/main/{p}_{tag}.deb\nSize: {1000 + i}\nSHA256: {h}\n")
    return lzma.compress("\n".join(st).encode())
def release(suite, idx):
    return (f"Origin: Test\nSuite: {suite}\nSHA256:\n {hashlib.sha256(idx).hexdigest()} {len(idx)} main/binary-amd64/Packages.xz\n").encode()
def sign(path, text):
    open(path + ".txt", "wb").write(text)
    subprocess.run(["gpg", "--batch", "--quiet", "--yes", "--clearsign", "-o", path, path + ".txt"], check=True)
    os.unlink(path + ".txt")
for m in ("honest", "inject", "replay"):
    for s in ("noble", "noble-updates", "noble-security"):
        d = f"{w}/{m}/dists/{s}/main/binary-amd64"; os.makedirs(d)
        idx = packages(s if s != "noble-updates" else "upd")
        open(f"{d}/Packages.xz", "wb").write(idx)
        sign(f"{w}/{m}/dists/{s}/InRelease", release(s, idx))
evil = packages("evil")
open(f"{w}/inject/dists/noble-updates/main/binary-amd64/Packages.xz", "wb").write(evil)
signed = open(f"{w}/inject/dists/noble-updates/InRelease", "rb").read()
head = f"SHA256:\n {hashlib.sha256(evil).hexdigest()} {len(evil)} main/binary-amd64/Packages.xz\n\n".encode()
open(f"{w}/inject/dists/noble-updates/InRelease", "wb").write(head + signed)
os.replace(f"{w}/replay/dists/noble/InRelease", f"{w}/replay/dists/noble-updates/InRelease")
sign(f"{w}/replay/dists/noble/InRelease", release("noble", open(f"{w}/replay/dists/noble/main/binary-amd64/Packages.xz", "rb").read()))
PY
ml() { local m="$1"; shift; FV_SYSROOT_MIRROR="file://$W/$m" FV_SYSROOT_KEYRING="$W/test-keyring.gpg" python3 -I "$ROOT/fuzz/sysroot/make_lock.py" "$@"; }
r=""
ml honest "$W/a.lock" > "$W/a.out" 2>&1; ra=$?
want=$(printf 'upd-libc6' | sha256sum | cut -d' ' -f1)
ml honest --check "$W/a.lock" > "$W/a-check.out" 2>&1; rac=$?
{ [ $ra -eq 0 ] && grep -q "^libc6 1.0-3 noble-updates file://$W/honest/pool/main/libc6_upd.deb $want 1000$" "$W/a.lock" \
  && [ $rac -eq 0 ] && [ "$(grep -c 'matches the verified index' "$W/a-check.out")" -eq 8 ]; } \
  || r+="(a) write=$ra check=$rac [$(tail -1 "$W/a.out")]; "
ml inject "$W/b.lock" > "$W/b.out" 2>&1; rb=$?
evil=$(printf 'evil-libc6' | sha256sum | cut -d' ' -f1)
{ [ $rb -ne 0 ] && [ ! -e "$W/b.lock" ] && grep -q 'differs from the verified InRelease' "$W/b.out"; } \
  || r+="(b) exit=$rb lock=$([ -e "$W/b.lock" ] && { grep -q "$evil" "$W/b.lock" && echo attacker-hash || echo written; } || echo none) [$(tail -1 "$W/b.out")]; "
ml replay "$W/c.lock" > "$W/c.out" 2>&1; rc=$?
{ [ $rc -ne 0 ] && [ ! -e "$W/c.lock" ] && grep -q 'is not for suite noble-updates' "$W/c.out"; } \
  || r+="(c) exit=$rc lock=$([ -e "$W/c.lock" ] && echo written || echo none) [$(tail -1 "$W/c.out")]; "
sed "s/ $want / $(printf '%064d' 0) /" "$W/a.lock" > "$W/d.lock"
ml honest --check "$W/d.lock" > "$W/d.out" 2>&1; rd=$?
{ [ $rd -eq 1 ] && grep -q '^\[TEST MIRROR/KEYRING, not the Ubuntu archive\] libc6 1.0-3 (noble-updates): MISMATCH' "$W/d.out"; } \
  || r+="(d) exit=$rd [$(grep -m1 libc6 "$W/d.out")]; "
if [ -z "$r" ]; then
  echo "c88_sysroot_lock OK (a) honest test mirror: lock written, --check 8/8 match; (b) unsigned SHA256 list before the signed block: refused ($(grep -o 'differs from the verified InRelease[^;]*' "$W/b.out" | head -1)); (c) another suite's InRelease: refused; (d) a changed sha256: --check exit 1, MISMATCH"
else
  echo "c88_sysroot_lock WRONG $r"
fi
