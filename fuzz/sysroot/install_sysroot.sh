#!/usr/bin/env bash
# install_sysroot.sh LOCK DEST — install the pinned build sysroot (no root, no package manager).
# Every .deb named in LOCK is downloaded, checked against its sha256 (refused otherwise) and extracted
# with dpkg-deb -x into DEST, a new directory. DEST/SYSROOT.lock is the lock it came from, and
# DEST/SYSROOT.sha256 the sha256 of its file and link list, which config/pins.env pins.
set -euo pipefail
LOCK="${1:?usage: $0 LOCK DEST}"; DEST="${2:?usage: $0 LOCK DEST}"
[ ! -e "$DEST" ] || { echo "install_sysroot: $DEST exists; install into a new directory" >&2; exit 3; }
DL=$(mktemp -d); trap 'rm -rf -- "$DL"' EXIT
mkdir -p "$DEST.partial"
while read -r pkg ver pocket url sha size; do
  case "$pkg" in ''|'#'*) continue ;; esac
  f="$DL/$(basename "$url")"
  curl -sSfL --max-time 600 -o "$f" "$url"
  got=$(sha256sum < "$f" | cut -d' ' -f1)
  [ "$got" = "$sha" ] || { echo "install_sysroot: $pkg $ver: sha256 $got, pinned $sha" >&2; exit 3; }
  dpkg-deb -x "$f" "$DEST.partial"
  echo "  $pkg $ver ($pocket) ok"
done < "$LOCK"
# Ubuntu's merged /usr: /lib, /lib64, /bin and /sbin are links into /usr (the libc linker scripts name
# /lib/x86_64-linux-gnu/...).
for d in lib lib64 bin sbin; do [ -e "$DEST.partial/$d" ] || ln -s "usr/$d" "$DEST.partial/$d"; done
cp "$LOCK" "$DEST.partial/SYSROOT.lock"
(cd "$DEST.partial" && { find . -type f ! -name SYSROOT.sha256 -print0 | LC_ALL=C sort -z | xargs -0 sha256sum
                         find . -type l -printf 'link %p -> %l\n' | LC_ALL=C sort; }) | sha256sum | cut -d' ' -f1 > "$DEST.partial/SYSROOT.sha256"
mv "$DEST.partial" "$DEST"
echo "sysroot $DEST: $(cat "$DEST/SYSROOT.sha256")"
