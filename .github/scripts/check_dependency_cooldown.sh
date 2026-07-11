#!/usr/bin/env bash
set -euo pipefail

base_ref="${COOLDOWN_BASE_REF:-main}"

git fetch --no-tags origin "+refs/heads/${base_ref}:refs/remotes/origin/${base_ref}" ||
  echo "Failed to fetch origin/${base_ref}; using the local ref." >&2
base_rev="refs/remotes/origin/${base_ref}"
merge_base="$(git merge-base "${base_rev}" HEAD)"

if git diff --quiet "${merge_base}" -- Cargo.lock; then
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
# The generated exemptions match crate and version only (cargo-cooldown ignores source).
awk '
  function exempt() {
    if (source ~ /^(registry|sparse)\+/) {
      print ""
      print "[[allow.exact]]"
      print "crate = \"" name "\""
      print "version = \"" version "\""
    }
  }

  /^\[\[/ {
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
  echo "cargo-cooldown rewrote these Cargo.lock entries:" >&2
  diff "${tmpdir}/pr.Cargo.lock" Cargo.lock >&2 || true
  echo "Wait for the dependencies above to satisfy cooldown, or regenerate Cargo.lock if it is out of sync with the manifests." >&2
  exit 1
fi
