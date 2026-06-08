#!/usr/bin/env bash
set -euo pipefail

state_file="${RETIMER_STATE_FILE:-.retimer-state}"

# Cargo fingerprints workspace inputs by mtime. actions/checkout gives every
# file a fresh mtime, so cached workspace artifacts can look stale even when the
# source content is unchanged. Cache producers save the mtimes that correspond
# to the cached target directory, and cache consumers restore them before Cargo
# runs.

path_arg() {
  local file="$1"

  if [[ "$file" = /* ]]; then
    printf "%s\n" "$file"
  else
    printf "./%s\n" "$file"
  fi
}

hash_file() {
  local file

  file="$(path_arg "$1")"

  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | cut -d' ' -f1
  else
    echo "Neither sha256sum nor shasum is available" >&2
    exit 1
  fi
}

is_workspace_relative_path() {
  local file="$1"

  [[ "$file" != /* && "$file" != "." && "$file" != ".." && "$file" != ../* && "$file" != */../* ]]
}

get_mtime() {
  local file

  file="$(path_arg "$1")"

  if stat -c %Y "$file" >/dev/null 2>&1; then
    stat -c %Y "$file"
  else
    stat -f %m "$file"
  fi
}

set_mtime() {
  local file
  local mtime="$2"
  local timestamp

  file="$(path_arg "$1")"

  if touch -d "@${mtime}" "$file" >/dev/null 2>&1; then
    return 0
  fi

  timestamp="$(date -r "$mtime" +%Y%m%d%H%M.%S 2>/dev/null)" || return 1
  touch -t "$timestamp" "$file"
}

save_state() {
  local tmp
  local count

  tmp="$(mktemp "${state_file}.tmp.XXXXXX")"
  trap 'rm -f "$tmp"' EXIT

  # Only tracked regular files are retimed. Untracked build output and generated
  # files are intentionally ignored.
  while IFS= read -r -d '' file; do
    if [[ -f "$file" && ! -L "$file" && "$file" != "$state_file" ]]; then
      printf "%s\t%s\t%s\n" "$(hash_file "$file")" "$(get_mtime "$file")" "$file" >> "$tmp"
    fi
  done < <(git ls-files -z)

  mv "$tmp" "$state_file"
  trap - EXIT

  count="$(wc -l < "$state_file" | tr -d ' ')"
  echo "Saved retimer state for ${count} files"
}

restore_state() {
  local restored=0
  local changed=0
  local missing=0
  local malformed=0
  local total=0

  if [[ ! -f "$state_file" ]]; then
    echo "No retimer state found"
    return 0
  fi

  # State entries are hash<TAB>mtime<TAB>path. The final read variable gets the
  # rest of the line, so spaces and tabs in paths do not split the path field.
  while IFS=$'\t' read -r saved_hash saved_mtime file || [[ -n "${saved_hash:-}${saved_mtime:-}${file:-}" ]]; do
    total=$((total + 1))

    if [[ -z "${saved_hash:-}" || -z "${saved_mtime:-}" || -z "${file:-}" ]]; then
      malformed=$((malformed + 1))
      continue
    fi

    if [[ ! "$saved_hash" =~ ^[0-9a-fA-F]{64}$ || ! "$saved_mtime" =~ ^[0-9]+$ ]]; then
      malformed=$((malformed + 1))
      continue
    fi

    if ! is_workspace_relative_path "$file"; then
      malformed=$((malformed + 1))
      continue
    fi

    if [[ ! -f "$file" || -L "$file" ]]; then
      missing=$((missing + 1))
      continue
    fi

    # Do not retime changed files. This preserves Cargo's rebuild behavior for
    # Rust source edits while still allowing unchanged workspace crates to reuse
    # cached artifacts.
    if [[ "$(hash_file "$file")" != "$saved_hash" ]]; then
      changed=$((changed + 1))
      continue
    fi

    if set_mtime "$file" "$saved_mtime"; then
      restored=$((restored + 1))
    else
      malformed=$((malformed + 1))
    fi
  done < "$state_file"

  echo "Retimer restored ${restored}/${total} files (${changed} changed, ${missing} missing, ${malformed} malformed)"
}

case "${1:-}" in
  save)
    save_state
    ;;
  restore)
    restore_state
    ;;
  *)
    echo "Usage: $0 {save|restore}" >&2
    exit 1
    ;;
esac
