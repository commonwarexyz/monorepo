#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
cd "${repo_root}"

run_mutation() {
    local mutation=$1
    local test_name=$2
    local log
    log=$(mktemp)
    if RUSTFLAGS="--cfg ${mutation}" cargo test -p commonware-runtime "${test_name}" --lib -- --nocapture \
        >"${log}" 2>&1; then
        cat "${log}"
        rm -f "${log}"
        echo "mutation survived: ${mutation} (${test_name})" >&2
        exit 1
    fi
    cat "${log}"
    if ! grep -q 'test result: FAILED' "${log}"; then
        rm -f "${log}"
        echo "mutation did not reach a failing test: ${mutation} (${test_name})" >&2
        exit 1
    fi
    rm -f "${log}"
    echo "mutation killed: ${mutation} (${test_name})"
}

run_mutation commonware_volume_mutation_skip_commit_sync test_recover_storage_crash_fan
run_mutation commonware_volume_mutation_accept_stale_ref \
    test_volume_checksum_page_rechecks_ref_after_commit_swap
run_mutation commonware_volume_mutation_skip_commit_poison \
    test_volume_coalesced_commit_failure_poisons_waiters
