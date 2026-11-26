#!/usr/bin/env bash
# classes_check.sh OUTDIR — one line per fuzz.json under OUTDIR (a control run's output): whether its
# edge-case classification is complete (classes_ok, lib_classes.sh), the verdict, and the reason.
#   OK|NO <TAB> verdict <TAB> path relative to OUTDIR <TAB> reason
# Labels only: it never changes a control's result; the clean controls make the same check themselves.
set -u
. "$(cd "$(dirname "$0")" && pwd)/lib_classes.sh"
D="${1:?usage: classes_check.sh OUTDIR}"
find "$D" -name fuzz.json -type f -print0 | LC_ALL=C sort -z | while IFS= read -r -d '' f; do
  if classes_ok "$f"; then s=OK; else s=NO; fi
  printf '%s\t%s\t%s\t%s\n' "$s" "$(jq -r '.verdict // "none"' "$f" 2>/dev/null || echo unreadable)" "${f#"$D"/}" "$(classes_why "$f")"
done
