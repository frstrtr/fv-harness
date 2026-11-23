"""unpack_out.py TAR DEST — unpack the out/ directory a remote worker sends back (fuzz/run_fuzz.sh).

The worker is not trusted with the gate's file system: every member must be a regular file or a
directory, named out or out/<name>... with no '..' and no absolute path, and no name may occur twice.
Anything else (a symbolic or hard link, a device, a FIFO, a member outside out/) refuses the whole
archive before anything is written, and so do more than FV_OUT_MAX_MEMBERS members (default 2,000,000)
or more than FV_OUT_MAX_BYTES bytes of file content (default 16 GiB). Files are written with fresh
permissions (0644 / 0755 dirs), never the archive's owner or mode. Exit 0 on success; 3 with the reason
on stderr otherwise, whatever went wrong (an unexpected error included).
"""
import os
import sys
import tarfile


def refuse(msg):
    sys.stderr.write(f"unpack_out: {msg}\n")
    sys.exit(3)


def main():
    tar, dest = sys.argv[1], sys.argv[2]
    try:
        tf = tarfile.open(tar, "r:")
    except (tarfile.TarError, OSError) as e:
        refuse(f"not a readable tar archive: {e}")
    seen = set()
    max_members = int(os.environ.get("FV_OUT_MAX_MEMBERS", 2_000_000))
    max_bytes = int(os.environ.get("FV_OUT_MAX_BYTES", 16 << 30))
    members, total = [], 0
    for m in tf:
        members.append(m)
        total += m.size if m.isreg() else 0
        if len(members) > max_members:
            refuse(f"more than {max_members} members")
        if total > max_bytes:
            refuse(f"more than {max_bytes} bytes of file content")
    for m in members:
        n = m.name.rstrip("/")
        parts = n.split("/")
        if n.startswith("/") or ".." in parts or "" in parts or parts[0] != "out":
            refuse(f"member outside out/: {m.name!r}")
        if not (m.isreg() or m.isdir()):
            refuse(f"member is not a regular file or directory: {m.name!r} (type {m.type!r})")
        if n in seen:
            refuse(f"member occurs twice: {m.name!r}")
        seen.add(n)
    for m in members:
        p = os.path.join(dest, m.name.rstrip("/"))
        if m.isdir():
            os.makedirs(p, mode=0o755, exist_ok=True)
            continue
        os.makedirs(os.path.dirname(p), mode=0o755, exist_ok=True)
        src = tf.extractfile(m)
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, "wb") as f:
            while True:
                b = src.read(1 << 20)
                if not b:
                    break
                f.write(b)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except BaseException as e:  # never a traceback and exit 1: the gate expects 0 or 3
        refuse(f"unexpected error: {type(e).__name__}: {e}")
