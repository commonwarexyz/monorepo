#!/usr/bin/env bash
set -euo pipefail

check_cooldown() {
  cargo cooldown --workspace --all-features check
}

check_lockfile() {
  git diff --exit-code Cargo.lock
}

if [[ "${GITHUB_EVENT_NAME:-}" != "pull_request" ]]; then
  check_cooldown
  check_lockfile
  exit 0
fi

base_ref="${COOLDOWN_BASE_REF:-}"
head_sha="${COOLDOWN_HEAD_SHA:-}"
if [[ -z "${base_ref}" || -z "${head_sha}" ]]; then
  echo "COOLDOWN_BASE_REF and COOLDOWN_HEAD_SHA are required for pull_request cooldown checks" >&2
  exit 1
fi

git fetch --no-tags origin "refs/heads/${base_ref}:refs/remotes/origin/${base_ref}"
base_rev="refs/remotes/origin/${base_ref}"
merge_base="$(git merge-base "${base_rev}" "${head_sha}")"

if git diff --quiet "${merge_base}" "${head_sha}" -- Cargo.lock; then
  echo "Cargo.lock did not change; skipping cargo-cooldown."
  exit 0
fi

tmpdir="$(mktemp -d)"
cp Cargo.lock "${tmpdir}/pr.Cargo.lock"
cleanup() {
  status=$?
  cp "${tmpdir}/pr.Cargo.lock" Cargo.lock
  rm -rf "${tmpdir}"
  exit "${status}"
}
trap cleanup EXIT

git show "${base_rev}:Cargo.lock" > Cargo.lock

check_cooldown

if ! cmp --silent Cargo.lock "${tmpdir}/pr.Cargo.lock"; then
  echo "Cargo.lock differs after applying the cooldown baseline." >&2
  echo "Regenerate Cargo.lock after the upgraded dependencies satisfy cooldown." >&2
  exit 1
fi
