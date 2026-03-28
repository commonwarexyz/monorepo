#!/usr/bin/env bash
# Convert and validate newly created fuzz traces while cargo fuzz is running.
#
# Usage:
#   ./scripts/watch_new_traces.sh [test_dir [traces_root]]

set -euo pipefail

TEST_DIR="${1:-traces}"
TRACES_ROOT="${2:-../fuzz/artifacts/traces}"
STATE_DIR="${TEST_DIR}/.live_state"
SEEN_DIR="${STATE_DIR}/seen"
STAGING_DIR="${STATE_DIR}/staging"
POLL_INTERVAL_SECONDS="${POLL_INTERVAL_SECONDS:-2}"

mkdir -p "$TEST_DIR" "$SEEN_DIR" "$STAGING_DIR"

cleanup() {
    rm -rf "$STAGING_DIR"
}

trap cleanup EXIT INT TERM

while true; do
    if [ ! -d "$TRACES_ROOT" ]; then
        sleep "$POLL_INTERVAL_SECONDS"
        continue
    fi

    while IFS= read -r json_file; do
        [ -f "$json_file" ] || continue

        hash="$(basename "$json_file" .json)"
        seen_marker="${SEEN_DIR}/${hash}"
        [ -f "$seen_marker" ] && continue

        staging_dir="${STAGING_DIR}/${hash}"
        rm -rf "$staging_dir"
        mkdir -p "$staging_dir"
        cp "$json_file" "${staging_dir}/${hash}.json"

        if cargo run -p commonware-consensus-fuzz --bin trace_to_quint -- "$staging_dir" "$TEST_DIR"; then
            qnt_file="${TEST_DIR}/trace_${hash}.qnt"
            TRACE_SELECTION_STRATEGY="${TRACE_SELECTION_STRATEGY:-current}" \
                ./scripts/test_traces.sh "$qnt_file" "$TRACES_ROOT"
            : > "$seen_marker"
        fi

        rm -rf "$staging_dir"
    done < <(find "$TRACES_ROOT" -type f -name '*.json' | sort)

    sleep "$POLL_INTERVAL_SECONDS"
done
