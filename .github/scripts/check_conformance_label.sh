#!/usr/bin/env bash
set -eo pipefail

# Labels that allow conformance.toml changes (at least one required for changes to existing cases)
required_labels=(
  breaking-format
  breaking-api
)

repo="${GITHUB_REPOSITORY:-commonwarexyz/monorepo}"

if [ -z "${PR_NUMBER:-}" ]; then
  echo "ERROR: PR_NUMBER is not set"
  exit 1
fi

# Use the paginated PR files API instead of `gh pr diff`: GitHub rejects
# oversized PR diffs, but this endpoint still returns per-file metadata.
changed=()
has_deletions=false
files=$(gh api --paginate "repos/$repo/pulls/$PR_NUMBER/files" \
  --jq '.[] | [.filename, (.deletions | tostring)] | @tsv')

# Filter for conformance.toml files and flag any non-additive changes.
while IFS=$'\t' read -r filename deletions; do
  if [[ "$filename" != *conformance.toml ]]; then
    continue
  fi

  changed+=("$filename")

  # Any deleted line means an existing conformance case changed or was removed.
  if (( deletions > 0 )); then
    has_deletions=true
    echo "Deletion/modification found in: $filename"
  fi
done <<< "$files"

if [ "${#changed[@]}" -eq 0 ]; then
  echo "No conformance.toml files changed"
  exit 0
fi

echo "Conformance files changed:"
printf "%s\n" "${changed[@]}"
echo ""

if [ "$has_deletions" = "false" ]; then
  echo "All conformance.toml changes are additive, no label required"
  exit 0
fi

echo ""

# Get PR labels
labels=$(gh pr view "$PR_NUMBER" --repo "$repo" --json labels --jq '.labels[].name')

# Check if any required label is present
for req in "${required_labels[@]}"; do
  if echo "$labels" | grep -qx "$req"; then
    echo "Found required label: $req"
    exit 0
  fi
done

echo "ERROR: conformance.toml file(s) changed but no required label found."
echo ""
echo "Modifying or removing entries in conformance.toml files is a BREAKING CHANGE."
echo "Adding new entries is allowed without a label."
echo ""
echo "Required labels (at least one):"
printf "  - %s\n" "${required_labels[@]}"
exit 1
