#!/usr/bin/env bash
#
# Syncs a pull request with the commonwarexyz/projects/2 GitHub Project.
#
# Required environment variables:
#   GH_TOKEN       - PAT with "project" (read/write) and "read:org" scopes
#                    "project" is needed to add items and update fields on the
#                    org project board (addProjectV2ItemById,
#                    updateProjectV2ItemFieldValue). "read:org" is needed to
#                    check whether the PR author is an org member.
#   PR_NODE_ID     - GraphQL node ID of the pull request
#   PR_AUTHOR      - Login of the pull request creator
#   PR_ACTION      - The pull_request event action
#   PR_DRAFT       - Whether the PR is currently a draft ("true"/"false")
#
set -euo pipefail

ORG="commonwarexyz"
PROJECT_NUMBER=2

# --- Check org membership ---------------------------------------------------

if ! gh api --silent "/orgs/${ORG}/members/${PR_AUTHOR}" 2>/dev/null; then
  echo "${PR_AUTHOR} is not a member of ${ORG}, skipping."
  exit 0
fi

# --- Resolve project and field IDs ------------------------------------------

PROJECT_DATA=$(gh api graphql -f query='
  query($org: String!, $number: Int!) {
    organization(login: $org) {
      projectV2(number: $number) {
        id
        field(name: "Status") {
          ... on ProjectV2SingleSelectField {
            id
            options { id name }
          }
        }
      }
    }
  }' -f org="$ORG" -F number="$PROJECT_NUMBER")

PROJECT_ID=$(echo "$PROJECT_DATA" | jq -r '.data.organization.projectV2.id')
STATUS_FIELD_ID=$(echo "$PROJECT_DATA" | jq -r '.data.organization.projectV2.field.id')

get_option_id() {
  echo "$PROJECT_DATA" | jq -r --arg name "$1" \
    '.data.organization.projectV2.field.options[] | select(.name == $name) | .id'
}

# --- Determine desired status -----------------------------------------------

case "$PR_ACTION" in
  opened|reopened)
    if [ "$PR_DRAFT" = "true" ]; then
      STATUS_NAME="In Progress"
    else
      STATUS_NAME="Ready for Review"
    fi
    ;;
  ready_for_review)
    STATUS_NAME="Ready for Review"
    ;;
  converted_to_draft)
    STATUS_NAME="In Progress"
    ;;
  closed)
    STATUS_NAME="Done"
    ;;
  *)
    echo "Unhandled action: ${PR_ACTION}, skipping."
    exit 0
    ;;
esac

OPTION_ID=$(get_option_id "$STATUS_NAME")
if [ -z "$OPTION_ID" ]; then
  echo "Could not find status option '${STATUS_NAME}' in project."
  exit 1
fi

# --- Add PR to project (idempotent) -----------------------------------------

ITEM_ID=$(gh api graphql -f query='
  mutation($project: ID!, $pr: ID!) {
    addProjectV2ItemById(input: {projectId: $project, contentId: $pr}) {
      item { id }
    }
  }' -f project="$PROJECT_ID" -f pr="$PR_NODE_ID" \
  | jq -r '.data.addProjectV2ItemById.item.id')

echo "Added/found item ${ITEM_ID} in project."

# --- Set status --------------------------------------------------------------

gh api graphql -f query='
  mutation($project: ID!, $item: ID!, $field: ID!, $value: String!) {
    updateProjectV2ItemFieldValue(input: {
      projectId: $project,
      itemId: $item,
      fieldId: $field,
      value: {singleSelectOptionId: $value}
    }) {
      projectV2Item { id }
    }
  }' -f project="$PROJECT_ID" -f item="$ITEM_ID" \
     -f field="$STATUS_FIELD_ID" -f value="$OPTION_ID" > /dev/null

echo "Set status to '${STATUS_NAME}'."
