#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: trace-barriers.sh <leaf-block-device> <new-output-directory> -- <command> [args...]" >&2
    exit 2
}

[[ ${EUID} -eq 0 ]] || { echo "trace-barriers: must run as root" >&2; exit 1; }
[[ $# -ge 4 && $3 == -- ]] || usage
device=$1
output=$2
shift 3

[[ -b ${device} ]] || { echo "trace-barriers: not a block device: ${device}" >&2; exit 1; }
[[ ! -e ${output} ]] || { echo "trace-barriers: output already exists: ${output}" >&2; exit 1; }
command -v lsblk >/dev/null || { echo "trace-barriers: missing lsblk" >&2; exit 1; }
command -v trace-cmd >/dev/null || { echo "trace-barriers: missing trace-cmd" >&2; exit 1; }

mkdir -m 0700 "${output}"
trace_file=${output}/barriers.dat
report_file=${output}/barriers.txt
major_minor=$(lsblk -dnro MAJ:MIN "${device}")
[[ -n ${major_minor} ]] || { echo "trace-barriers: could not resolve device number" >&2; exit 1; }
trace_major_minor=${major_minor/:/,}

trace-cmd record \
    -o "${trace_file}" \
    -e block:block_rq_issue \
    -e block:block_rq_complete \
    -- "$@"
trace-cmd report -i "${trace_file}" >"${report_file}"

device_report=${output}/device-barriers.txt
grep -E "block_rq_(issue|complete): ${trace_major_minor} " "${report_file}" >"${device_report}" || true
issue_count=$(grep -c 'block_rq_issue:' "${device_report}" || true)
barrier_count=$(grep 'block_rq_issue:' "${device_report}" | grep -Ec " ${trace_major_minor} [A-Z]*F[A-Z]* " || true)

echo "device=${device} major_minor=${major_minor} requests=${issue_count} barrier_requests=${barrier_count}"
echo "trace=${trace_file}"
echo "report=${device_report}"
if [[ ${issue_count} -eq 0 ]]; then
    echo "trace-barriers: no requests reached the selected leaf device" >&2
    exit 1
fi
if [[ ${barrier_count} -eq 0 ]]; then
    echo "trace-barriers: no REQ_PREFLUSH/FUA marker reached the selected leaf device" >&2
    exit 1
fi
