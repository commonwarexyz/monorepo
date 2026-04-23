#!/usr/bin/env bash
# Validate a single recorded trace JSON against the Quint spec.
#
# Converts the trace to consensus/quint/traces/trace_<hash>.qnt via the
# trace_to_quint bin, then runs `quint test` on that file. No sweep, no
# crash-directory housekeeping; one-shot path for ad-hoc validation of a
# specific JSON (e.g. a rejected_traces/ file from tlc_watch).
#
# Usage:
#   ./scripts/validate_trace.sh <path/to/trace.json> [max-samples]
#
# Arguments:
#   <path/to/trace.json>  - accepted/rejected/errored trace JSON, any location
#   [max-samples]         - quint --max-samples, default 5
#
# Environment:
#   QUINT_HEAP_MB - Node.js heap for quint, default 24576
#   KEEP_QNT=1    - retain the generated traces/trace_<hash>.qnt after exit

set -euo pipefail

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
    echo "Usage: $0 <path/to/trace.json> [max-samples]" >&2
    exit 2
fi

trace_json="$1"
max_samples="${2:-5}"
heap_mb="${QUINT_HEAP_MB:-24576}"

if [ ! -f "$trace_json" ]; then
    echo "Error: $trace_json is not a file" >&2
    exit 1
fi

script_dir="$(cd "$(dirname "$0")" && pwd)"
quint_dir="$(cd "$script_dir/.." && pwd)"
cd "$quint_dir"

hash="$(basename "$trace_json" .json)"
out_dir="traces"
mkdir -p "$out_dir"

staging="$(mktemp -d)"
cleanup() {
    rm -rf "$staging"
    if [ "${KEEP_QNT:-0}" != "1" ]; then
        rm -f "$out_dir/trace_${hash}.qnt"
    fi
}
trap cleanup EXIT INT TERM

cp "$trace_json" "$staging/$(basename "$trace_json")"

echo "[validate-trace] converting $trace_json"
cargo run -q -p commonware-consensus-fuzz --bin trace_to_quint -- "$staging" "$out_dir"

qnt_file="$out_dir/trace_${hash}.qnt"
if [ ! -f "$qnt_file" ]; then
    echo "Error: expected $qnt_file after conversion" >&2
    exit 1
fi

echo "[validate-trace] running quint on $qnt_file (max-samples=$max_samples)"
quint_bin="$(command -v quint)"
if [ -z "$quint_bin" ]; then
    echo "Error: quint not found in PATH" >&2
    exit 1
fi

NODE_OPTIONS="--max-old-space-size=${heap_mb}" \
    "$quint_bin" test \
        --main=tests \
        --backend=rust \
        --max-samples="$max_samples" \
        --verbosity=4 \
        --match=traceTest \
        "$qnt_file"
