#!/usr/bin/env bash
set -euo pipefail

base_ref="${COOLDOWN_BASE_REF:-main}"
head_sha="${COOLDOWN_HEAD_SHA:-HEAD}"

git fetch --no-tags origin "refs/heads/${base_ref}:refs/remotes/origin/${base_ref}"
base_rev="refs/remotes/origin/${base_ref}"
merge_base="$(git merge-base "${base_rev}" "${head_sha}")"

if git diff --quiet "${merge_base}" "${head_sha}" -- Cargo.lock; then
  echo "Cargo.lock did not change; skipping cargo-cooldown."
  exit 0
fi

tmpdir="$(mktemp -d)"
cp Cargo.lock "${tmpdir}/pr.Cargo.lock"
cp cooldown.toml "${tmpdir}/cooldown.toml"
cleanup() {
  status=$?
  cp "${tmpdir}/pr.Cargo.lock" Cargo.lock
  cp "${tmpdir}/cooldown.toml" cooldown.toml
  rm -rf "${tmpdir}"
  exit "${status}"
}
trap cleanup EXIT

git show "${merge_base}:Cargo.lock" > "${tmpdir}/base.Cargo.lock"
# Versions already present at the merge base are allowed regardless of publish age.
awk '
  function exempt() {
    if (source ~ /^registry\+/) {
      print ""
      print "[[allow.exact]]"
      print "crate = \"" name "\""
      print "version = \"" version "\""
    }
  }

  /^\[\[package\]\]$/ {
    exempt()
    name = version = source = ""
    next
  }
  /^name = "/ { name = substr($0, 9, length($0) - 9) }
  /^version = "/ { version = substr($0, 12, length($0) - 12) }
  /^source = "/ { source = substr($0, 11, length($0) - 11) }
  END { exempt() }
' "${tmpdir}/base.Cargo.lock" >> cooldown.toml

cargo cooldown metadata --all-features --format-version 1 --no-deps > /dev/null

if ! cmp --silent Cargo.lock "${tmpdir}/pr.Cargo.lock"; then
  echo "Cargo.lock contains dependencies that do not pass cooldown." >&2
  exit 1
fi
