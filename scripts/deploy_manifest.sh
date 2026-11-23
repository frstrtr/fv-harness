#!/usr/bin/env bash
# deploy_manifest.sh COMMIT — run in a freshly extracted harness deployment (git archive of COMMIT),
# before any deployment data (config/hosts.env, extra locks) is added. Writes DEPLOYED_COMMIT and
# DEPLOYED_MANIFEST.sha256 (every file, sorted); formal_task.py's closure then reports the harness as
# clean, or DIRTY with the files that differ, and lists files added later as deployment data.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -n "${1:-}" ] || { echo "usage: $0 COMMIT" >&2; exit 2; }
echo "$1" > DEPLOYED_COMMIT
find . -type f ! -name DEPLOYED_COMMIT ! -name DEPLOYED_MANIFEST.sha256 -printf '%P\0' | LC_ALL=C sort -z \
  | xargs -0 sha256sum > DEPLOYED_MANIFEST.sha256
echo "deployment $1: $(wc -l < DEPLOYED_MANIFEST.sha256) files in DEPLOYED_MANIFEST.sha256"
