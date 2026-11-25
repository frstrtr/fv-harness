"""make_lock.py OUT_LOCK | --check LOCK — pin the packages of the Ubuntu 24.04 (noble, glibc 2.39) build sysroot.

Run once, by a person, to create or refresh fuzz/sysroot/noble-2.39.lock; the lock is reviewed and
committed, and fuzz/sysroot/install_sysroot.sh installs exactly what it names.

The chain of trust: each pocket's InRelease (noble, noble-updates, noble-security) is verified with
gpgv against the Ubuntu archive keyring, and only the text gpgv verified (gpgv --output -) is read,
never the downloaded bytes around it; its Suite must be the pocket asked for. The Packages index is
checked against the sha256 that verified text lists for it; every .deb's url, sha256 and size come
from that index. For each package the highest version across the three pockets is pinned. Nothing is
installed or executed here.

--check LOCK re-derives the same from the archive today and compares every line of a committed lock:
a package whose pinned version is still in its pocket's verified index must match it exactly (url,
sha256, size), else exit 1; a version the index no longer lists (superseded by an update) cannot be
re-verified that way and is reported as such, with the version the index lists now.
"""
import gzip
import hashlib
import lzma
import os
import re
import subprocess
import sys
import tempfile
import urllib.request

# FV_SYSROOT_MIRROR / FV_SYSROOT_KEYRING exist for control c88 only (a local mirror signed by a test key);
# when either is set every line of output says so, and such a lock is never the committed one.
MIRROR = os.environ.get("FV_SYSROOT_MIRROR", "http://archive.ubuntu.com/ubuntu")
POCKETS = ("noble", "noble-updates", "noble-security")
KEYRING = os.environ.get("FV_SYSROOT_KEYRING", "/usr/share/keyrings/ubuntu-archive-keyring.gpg")
TEST = "FV_SYSROOT_MIRROR" in os.environ or "FV_SYSROOT_KEYRING" in os.environ
PACKAGES = ("libc6", "libc6-dev", "libgcc-13-dev", "libstdc++-13-dev", "libgcc-s1", "linux-libc-dev",
            "libcrypt-dev", "libcrypt1")


def fetch(url):
    with urllib.request.urlopen(url, timeout=120) as r:
        return r.read()


def verlt(a, b):  # dpkg version order, by dpkg itself
    return subprocess.run(["dpkg", "--compare-versions", a, "lt", b]).returncode == 0


def verified_release(pocket):
    """The text of the pocket's InRelease that gpgv verified against the archive keyring."""
    inrel = fetch(f"{MIRROR}/dists/{pocket}/InRelease")
    with tempfile.NamedTemporaryFile(delete=False) as t:
        t.write(inrel)
    try:
        r = subprocess.run(["gpgv", "--keyring", KEYRING, "--output", "-", t.name], capture_output=True)
    finally:
        os.unlink(t.name)
    if r.returncode != 0:
        sys.exit(f"{pocket}: InRelease signature does not verify: {r.stderr.decode(errors='replace').strip()[:300]}")
    text = r.stdout.decode()
    if not re.search(rf"^Suite: {re.escape(pocket)}$", text, re.M):
        sys.exit(f"{pocket}: the verified InRelease is not for suite {pocket}")
    return text


def index(pocket):
    """{(package, version): stanza} from the pocket's Packages index, checked against the verified InRelease."""
    text = verified_release(pocket)
    if "SHA256:" not in text:
        sys.exit(f"{pocket}: no SHA256 list in the verified InRelease")
    sha = text[text.index("SHA256:"):]
    m = re.search(r"^ ([0-9a-f]{64}) +(\d+) main/binary-amd64/Packages\.xz$", sha, re.M)
    if not m:
        sys.exit(f"{pocket}: no main/binary-amd64/Packages.xz in the verified InRelease")
    idx = fetch(f"{MIRROR}/dists/{pocket}/main/binary-amd64/Packages.xz")
    if hashlib.sha256(idx).hexdigest() != m.group(1) or len(idx) != int(m.group(2)):
        sys.exit(f"{pocket}: Packages.xz differs from the verified InRelease (sha256 or size)")
    out = {}
    for stanza in lzma.decompress(idx).decode().split("\n\n"):
        f = dict(re.findall(r"^([A-Za-z0-9-]+): (.*)$", stanza, re.M))
        if f.get("Package") in PACKAGES and f.get("Architecture") in ("amd64", "all"):
            out[(f["Package"], f["Version"])] = dict(f, Pocket=pocket)
    return out


def say(line):
    print(("[TEST MIRROR/KEYRING, not the Ubuntu archive] " if TEST else "") + line)


def check(lock):
    idx = {}
    for pocket in POCKETS:
        idx[pocket] = index(pocket)
    bad = 0
    for line in open(lock):
        if line.startswith("#") or not line.strip():
            continue
        p, ver, pocket, url, sha, size = line.split()
        f = idx.get(pocket, {}).get((p, ver))
        if f is None:
            now = sorted((v for (q, v) in idx.get(pocket, {}) if q == p))
            say(f"{p} {ver} ({pocket}): not in today's verified index (superseded; it lists {now or 'nothing'}); not re-verifiable from it")
        elif (url, sha, size) != (f"{MIRROR}/{f['Filename']}", f["SHA256"], f["Size"]):
            say(f"{p} {ver} ({pocket}): MISMATCH with the verified index: lock {url} {sha} {size}, "
                  f"index {MIRROR}/{f['Filename']} {f['SHA256']} {f['Size']}")
            bad += 1
        else:
            say(f"{p} {ver} ({pocket}): matches the verified index")
    sys.exit(1 if bad else 0)


def main():
    if sys.argv[1] == "--check":
        check(sys.argv[2])
    out = sys.argv[1]
    best = {}
    for pocket in POCKETS:
        for (p, _), f in index(pocket).items():
            cur = best.get(p)
            if cur is None or verlt(cur["Version"], f["Version"]):
                best[p] = f
    missing = [p for p in PACKAGES if p not in best]
    if missing:
        sys.exit(f"not found: {missing}")
    with open(out, "w") as o:
        o.write("# Ubuntu 24.04 (noble) build sysroot: package version pocket url sha256 size\n")
        o.write("# Generated by fuzz/sysroot/make_lock.py from gpgv-verified InRelease files; review, then commit.\n")
        if TEST:
            o.write(f"# TEST: mirror {MIRROR}, keyring {KEYRING}; not a lock to commit\n")
        for p in PACKAGES:
            f = best[p]
            o.write(f"{p} {f['Version']} {f['Pocket']} {MIRROR}/{f['Filename']} {f['SHA256']} {f['Size']}\n")
    say(f"wrote {out}: {len(PACKAGES)} packages")


if __name__ == "__main__":
    main()
