#!/usr/bin/env bash
set -eo pipefail

# Labels that allow conformance.toml changes (at least one required)
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
echo "Changing conformance.toml files is a BREAKING CHANGE."
echo ""
echo "Required labels (at least one):"
printf "  - %s\n" "${required_labels[@]}"
exit 1
