#!/usr/bin/env bash
set -eo pipefail

# Labels that allow conformance.toml changes (at least one required for changes to existing cases)
required_labels=(
  breaking-format
  breaking-api
)

# Get changed files
diff=$(gh pr diff "$PR_NUMBER" --name-only)

# Filter for conformance.toml files
changed=$(echo "$diff" | grep 'conformance\.toml$' || true)

if [ -z "$changed" ]; then
  echo "No conformance.toml files changed"
  exit 0
fi

echo "Conformance files changed:"
echo "$changed"
echo ""

# Check if any conformance.toml changes include deletions
has_deletions=false
current_file=""
while IFS= read -r line; do
  # Track which file we're in
  if [[ "$line" =~ ^diff\ --git\ a/(.*)\ b/ ]]; then
    current_file="${BASH_REMATCH[1]}"
  fi
  # If we're in a conformance.toml file and see a deletion line (starts with - but not ---)
  if [[ "$current_file" == *conformance.toml ]] && [[ "$line" =~ ^-[^-] ]]; then
    has_deletions=true
    echo "Deletion/modification found in: $current_file"
    break
  fi
done < <(gh pr diff "$PR_NUMBER")

if [ "$has_deletions" = "false" ]; then
  echo "All conformance.toml changes are additive, no label required"
  exit 0
fi

echo ""

# Get PR labels
labels=$(gh pr view "$PR_NUMBER" --json labels --jq '.labels[].name')

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
