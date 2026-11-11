#!/usr/bin/env bash
#
# Installs apt packages, retrying when the package index or a download fails.
#
# Usage: apt_install.sh <apt-get install arguments>
set -eo pipefail

attempts=4
for attempt in $(seq 1 "$attempts"); do
  if sudo apt-get update && sudo apt-get install --yes "$@"; then
    exit 0
  fi
  if [ "$attempt" -lt "$attempts" ]; then
    delay=$((attempt * 15))
    echo "apt-get failed (attempt $attempt of $attempts), retrying in ${delay}s" >&2
    sleep "$delay"
  fi
done

echo "apt-get failed after $attempts attempts" >&2
exit 1
