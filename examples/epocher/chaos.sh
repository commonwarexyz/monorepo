#!/usr/bin/env bash
set -euo pipefail

# Chaos runner for epocher: runs indexer and 10 validators locally,
# randomly restarting each validator every 0–10 minutes independently.
#
# Requirements: cargo, Rust toolchain installed.
# Usage: ./chaos.sh

RUST_LOG=${RUST_LOG:-info}
export RUST_LOG

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")"/../.. && pwd)
cd "$ROOT_DIR"

# Ensure we kill all children on exit
cleanup() {
  trap - EXIT INT TERM
  pkill -P $$ || true
}
trap cleanup EXIT INT TERM

BIN_VALIDATOR="-p commonware-epocher --release --bin commonware-epocher"
BIN_INDEXER="-p commonware-epocher --release --bin commonware-epocher-indexer"

INDEXER_PORT=4001
BOOTSTRAP_KEY=1
BOOTSTRAP_PORT=3001
BOOTSTRAP_ADDR="1@127.0.0.1:${BOOTSTRAP_PORT}"

log() { printf '[%(%Y-%m-%dT%H:%M:%S%z)T] %s\n' -1 "$*"; }

# Start indexer
log "starting indexer on :${INDEXER_PORT}"
cargo run ${BIN_INDEXER} -- --me 1@${INDEXER_PORT} &
INDEXER_PID=$!

sleep 1

# Start bootstrap validator (key 1)
log "starting bootstrap validator ${BOOTSTRAP_KEY}@${BOOTSTRAP_PORT}"
cargo run ${BIN_VALIDATOR} -- --me ${BOOTSTRAP_KEY}@${BOOTSTRAP_PORT} --indexer http://127.0.0.1:${INDEXER_PORT} &
BOOTSTRAP_PID=$!

sleep 2

# Function to run a validator until killed
run_validator() {
  local key=$1
  local port=$2
  cargo run ${BIN_VALIDATOR} -- --me ${key}@${port} \
    --bootstrappers ${BOOTSTRAP_ADDR} \
    --indexer http://127.0.0.1:${INDEXER_PORT}
}

# Chaos loop per validator (keys 2..10)
chaos_validator() {
  local key=$1
  local port=$2
  while true; do
    # Random up-time 0..10 minutes
    local up_sec=$((RANDOM % 600))
    log "validator ${key}: starting on port ${port} for ~${up_sec}s"
    run_validator ${key} ${port} &
    local pid=$!
    # Sleep for up period (if up_sec is 0, yield once)
    if [[ ${up_sec} -gt 0 ]]; then
      sleep ${up_sec} || true
    else
      sleep 1 || true
    fi
    # Kill process (if still running)
    if kill -0 ${pid} 2>/dev/null; then
      log "validator ${key}: stopping"
      kill ${pid} 2>/dev/null || true
      # Give some time to terminate; force kill if needed
      sleep 2 || true
      kill -9 ${pid} 2>/dev/null || true
    fi
    # Random downtime 0..60 seconds
    local down_sec=$((RANDOM % 60))
    log "validator ${key}: down for ~${down_sec}s"
    if [[ ${down_sec} -gt 0 ]]; then
      sleep ${down_sec} || true
    else
      sleep 1 || true
    fi
  done
}

# Start chaos controllers for validators 2..10
for key in $(seq 2 10); do
  port=$((3000 + key))
  chaos_validator ${key} ${port} &
done

# Wait forever (children are managed by traps)
wait


