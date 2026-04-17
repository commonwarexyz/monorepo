#!/usr/bin/env bash
set -eo pipefail

# Labels that allow conformance.toml changes (at least one required for changes to existing cases)
required_labels=(
  breaking-format
  breaking-api
)

# GitHub may refuse to render full PR diffs once they exceed the API's line cap.
# Use the paginated files API instead so large PRs still work.
repo="${GITHUB_REPOSITORY:-$(gh repo view --json nameWithOwner --jq '.nameWithOwner')}"
files=$(gh api --paginate --slurp "/repos/${repo}/pulls/${PR_NUMBER}/files")

# Filter for conformance.toml files
changed=$(jq -r '.[] | .[] | select(.filename | endswith("conformance.toml")) | .filename' <<<"$files")

if [ -z "$changed" ]; then
  echo "No conformance.toml files changed"
  exit 0
fi

echo "Conformance files changed:"
echo "$changed"
echo ""

# Check if any conformance.toml changes include deletions or other non-additive edits.
# If GitHub omits the patch for an existing file, require a label conservatively since
# we can no longer prove the change is additive.
has_deletions=false
while IFS= read -r file; do
  filename=$(jq -r '.filename' <<<"$file")
  status=$(jq -r '.status' <<<"$file")
  patch_present=$(jq -r 'has("patch")' <<<"$file")

  if [[ "$status" == "removed" || "$status" == "renamed" ]]; then
    has_deletions=true
    echo "Deletion/modification found in: $filename ($status)"
    break
  fi

  if [[ "$status" != "added" && "$patch_present" != "true" ]]; then
    has_deletions=true
    echo "Unable to inspect patch for existing conformance file: $filename"
    break
  fi

  if jq -e '
    (.patch // "")
    | split("\n")
    | any(startswith("-") and (startswith("---") | not))
  ' <<<"$file" >/dev/null; then
    has_deletions=true
    echo "Deletion/modification found in: $filename"
    break
  fi
done < <(
  jq -c '.[] | .[] | select(.filename | endswith("conformance.toml"))' <<<"$files"
)

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
