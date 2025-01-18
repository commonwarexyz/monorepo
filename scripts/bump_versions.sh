#!/usr/bin/env bash
#
# Increment patch versions for crates/packages whose name starts with "commonware-"
# in both package declarations and [workspace.dependencies].

set -euo pipefail

# Function: bump the patch number in e.g., 0.0.14 -> 0.0.15
bump_version() {
  local old="$1"
  local major minor patch
  IFS='.' read -r major minor patch <<< "$old"
  patch=$((patch + 1))
  echo "$major.$minor.$patch"
}

# Recursively find all Cargo.toml files
find . -name "Cargo.toml" | while read -r cargo_file; do
  # We'll store updated file content in an array
  content=()
  changed=false

  # Read the file line by line
  name=""
  while IFS= read -r line; do
    # 1) Match workspace deps like: commonware-foo = { version = "0.0.3", path = "foo" }
    if [[ "$line" =~ ^[[:space:]]*(commonware-[^[:space:]]+)[[:space:]]*=\ {[[:space:]]*version[[:space:]]*=[[:space:]]*\"([0-9]+\.[0-9]+\.[0-9]+)\" ]]; then
      old="${BASH_REMATCH[2]}"
      new="$(bump_version "$old")"
      line="${line/$old/$new}"
      changed=true
    fi

    # 2) Check for package name lines like: name = "commonware-foo"
    if [[ "$line" =~ ^[[:space:]]*name[[:space:]]*=[[:space:]]*\"(commonware-[^\"]+)\" ]]; then
      name="${BASH_REMATCH[1]}"
    else
      # 3) If name is set, we may be on a version line
      if [[ -n "$name" && "$line" =~ ^[[:space:]]*version[[:space:]]*=[[:space:]]*\"([0-9]+\.[0-9]+\.[0-9]+)\" ]]; then
        old="${BASH_REMATCH[1]}"
        new="$(bump_version "$old")"
        line="${line/$old/$new}"
        changed=true
        name=""
      fi
    fi

    content+=("$line")
  done < "$cargo_file"

  # If we changed anything, overwrite the file
  if $changed; then
    # Fix: Use a loop to write each line separately to avoid formatting issues.
    # This is important because if the lines in the `content` array contain formatting symbols (e.g., %s, %d),
    # they may be misinterpreted by `printf`, causing errors.
    for line in "${content[@]}"; do
      printf "%s\n" "$line"
    done > "$cargo_file"
    echo "Updated $cargo_file"
  fi
done
