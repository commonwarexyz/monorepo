#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: trace-barriers.sh <leaf-block-device> <new-output-directory> [--storage-path <path>] -- <command> [args...]" >&2
    exit 2
}

[[ ${EUID} -eq 0 ]] || { echo "trace-barriers: must run as root" >&2; exit 1; }
[[ $# -ge 4 ]] || usage
device=$1
output=$2
shift 2

storage_path=
if [[ ${1:-} == --storage-path ]]; then
    [[ $# -ge 3 ]] || usage
    storage_path=$2
    shift 2
fi
[[ ${1:-} == -- ]] || usage
shift
[[ $# -gt 0 ]] || usage

[[ -b ${device} ]] || { echo "trace-barriers: not a block device: ${device}" >&2; exit 1; }
[[ ! -e ${output} ]] || { echo "trace-barriers: output already exists: ${output}" >&2; exit 1; }
command -v lsblk >/dev/null || { echo "trace-barriers: missing lsblk" >&2; exit 1; }
command -v sha256sum >/dev/null || { echo "trace-barriers: missing sha256sum" >&2; exit 1; }
command -v trace-cmd >/dev/null || { echo "trace-barriers: missing trace-cmd" >&2; exit 1; }

mkdir -m 0700 "${output}"
if [[ -n ${storage_path} ]]; then
    "$(dirname "${BASH_SOURCE[0]}")/capture-storage-profile.sh" \
        "${storage_path}" "${output}/storage-profile"
fi
trace_file=${output}/barriers.dat
report_file=${output}/barriers.txt
workload_status_fifo=${output}/.workload-status
major_minor=$(lsblk -dnro MAJ:MIN "${device}")
[[ -n ${major_minor} ]] || { echo "trace-barriers: could not resolve device number" >&2; exit 1; }
trace_major_minor=${major_minor/:/,}

{
    echo "captured_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "device=${device}"
    echo "major_minor=${major_minor}"
    printf 'command='
    printf '%q ' "$@"
    echo
} >"${output}/trace-context.txt"

mkfifo -m 0600 "${workload_status_fifo}"
exec {workload_status_fd}<>"${workload_status_fifo}"
cleanup_status_fifo() {
    exec {workload_status_fd}>&-
    rm -f "${workload_status_fifo}"
}
trap cleanup_status_fifo EXIT

set +e
# The single-quoted script is expanded by the traced Bash process.
# shellcheck disable=SC2016
trace-cmd record \
    -o "${trace_file}" \
    -e block:block_rq_issue \
    -e block:block_rq_complete \
    -- bash -c '
        set +e
        "$@"
        status=$?
        echo "${status}" >&3
        exit "${status}"
    ' trace-barriers-workload "$@" 3>"${workload_status_fifo}"
trace_status=$?
set -e
if ! read -r -t 1 workload_status <&"${workload_status_fd}"; then
    echo "trace-barriers: traced workload did not record its exit status" >&2
    exit 1
fi
cleanup_status_fifo
trap - EXIT
[[ ${workload_status} =~ ^[0-9]+$ && ${workload_status} -le 255 ]] || {
    echo "trace-barriers: invalid traced workload status: ${workload_status}" >&2
    exit 1
}
if [[ ${trace_status} -ne 0 ]]; then
    echo "trace-barriers: trace-cmd failed with status ${trace_status}" >&2
    exit "${trace_status}"
fi
trace-cmd report -i "${trace_file}" >"${report_file}"

device_report=${output}/device-barriers.txt
grep -E "block_rq_(issue|complete):[[:space:]]+${trace_major_minor} " "${report_file}" >"${device_report}" || true
issue_count=$(grep -c 'block_rq_issue:' "${device_report}" || true)
barrier_count=$(grep 'block_rq_issue:' "${device_report}" | grep -Ec " ${trace_major_minor} [A-Z]*F[A-Z]* " || true)

{
    echo "device=${device}"
    echo "major_minor=${major_minor}"
    echo "workload_status=${workload_status}"
    echo "requests=${issue_count}"
    echo "barrier_requests=${barrier_count}"
} >"${output}/result.txt"
(
    cd "${output}"
    find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum
) >"${output}/SHA256SUMS"

echo "device=${device} major_minor=${major_minor} workload_status=${workload_status} requests=${issue_count} barrier_requests=${barrier_count}"
echo "trace=${trace_file}"
echo "report=${device_report}"
if [[ ${workload_status} -ne 0 ]]; then
    echo "trace-barriers: traced workload failed with status ${workload_status}" >&2
    exit "${workload_status}"
fi
if [[ ${issue_count} -eq 0 ]]; then
    echo "trace-barriers: no requests reached the selected leaf device" >&2
    exit 1
fi
if [[ ${barrier_count} -eq 0 ]]; then
    echo "trace-barriers: no REQ_PREFLUSH/FUA marker reached the selected leaf device" >&2
    exit 1
fi
