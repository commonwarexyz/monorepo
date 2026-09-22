#!/usr/bin/env bash
# Run on an otherwise idle AVX-512 IFMA host. Does not provision cloud resources.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../../.."
for required in cargo just taskset python3; do
    command -v "$required" >/dev/null
done
python3 - <<'PY'
import platform
from pathlib import Path
assert platform.machine() == "x86_64", "an x86-64 host is required"
flags = Path("/proc/cpuinfo").read_text().split("flags", 1)[1].splitlines()[0].split()
assert {"avx512f", "avx512ifma"} <= set(flags), "AVX-512F and IFMA are required"
PY
export COMMONWARE_REQUIRE_AVX512=1
export COMMONWARE_DECODE_COUNTS="${COMMONWARE_DECODE_COUNTS:-1000,6000,100000}"
mkdir -p target/decode-benchmark
log="target/decode-benchmark/$(date -u +%Y%m%dT%H%M%SZ).log"
{
    date -u
    git rev-parse HEAD
    git status --short
    rustc -Vv
    lscpu
    python3 cryptography/bls/scripts/subgroup.py
    just test -p commonware-cryptography-bls --release decompression:: --test-threads 1
    cargo bench -p commonware-cryptography-bls --bench decode --no-run
    taskset -c "${COMMONWARE_DECODE_CPU:-0}" \
        cargo bench -p commonware-cryptography-bls --bench decode
} 2>&1 | tee "$log"
