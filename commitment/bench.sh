#!/bin/bash
# Benchmark with SMT disabled, pinned to 8 physical cores, performance governor.
# Run as root: sudo ./commitment/bench.sh
set -e

CORES="0-7"
BINARY="target/release/examples/profile"

echo "=== CPU Setup ==="

# Disable SMT
echo off > /sys/devices/system/cpu/smt/control 2>/dev/null || true
echo "SMT: $(cat /sys/devices/system/cpu/smt/active 2>/dev/null && echo active || echo off)"

# Set performance governor on cores 0-7
for i in $(seq 0 7); do
    echo performance > /sys/devices/system/cpu/cpu${i}/cpufreq/scaling_governor 2>/dev/null || true
done
echo "Governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)"

# Show current frequency
sleep 0.5
echo "Frequency: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq)kHz (max: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq)kHz)"

echo ""
echo "=== Building ==="
RUSTFLAGS="-C target-cpu=native" cargo build --release -p commonware-commitment --example profile 2>&1 | grep -E "Compiling commonware-commitment|Finished"

echo ""
echo "=== Benchmark (pinned to cores ${CORES}, SMT off) ==="
taskset -c ${CORES} ${BINARY}

echo ""
echo "=== Criterion Benchmark ==="
RUSTFLAGS="-C target-cpu=native" taskset -c ${CORES} cargo bench -p commonware-commitment 2>&1 | grep -E "time:|commitment::"

echo ""
echo "=== Restoring SMT ==="
echo on > /sys/devices/system/cpu/smt/control 2>/dev/null || true
echo "SMT: $(cat /sys/devices/system/cpu/smt/active 2>/dev/null)"
