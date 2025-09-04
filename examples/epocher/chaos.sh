#!/usr/bin/env bash
set -euo pipefail

# Chaos runner for epocher: runs indexer and 10 validators locally,
# randomly restarting each validator.
#
# Requirements: cargo, Rust toolchain installed.
# Usage: ./chaos.sh [prefix]
# If prefix is not provided, a random 8-character alphanumeric string is used.

RUST_LOG=${RUST_LOG:-info}
export RUST_LOG

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")"/../.. && pwd)
cd "$ROOT_DIR"

# Build once so we can run binaries directly (simplifies clean shutdowns)
cargo build -p commonware-epocher --release >/dev/null

# Ensure we kill all children on exit
cleanup() {
  trap - EXIT INT TERM
  # Terminate the entire process group (script + children + grandchildren)
  kill -TERM -$$ 2>/dev/null || true
  sleep 1 || true
  kill -KILL -$$ 2>/dev/null || true
}
trap cleanup EXIT INT TERM

PATH_VALIDATOR="$ROOT_DIR/target/release/commonware-epocher"
PATH_INDEXER="$ROOT_DIR/target/release/commonware-epocher-indexer"

INDEXER_PORT=4001
BOOTSTRAP_KEY=1
BOOTSTRAP_PORT=3001
BOOTSTRAP_ADDR="1@127.0.0.1:${BOOTSTRAP_PORT}"

log() { printf '[%(%Y-%m-%dT%H:%M:%S%z)T] %s\n' -1 "$*"; }

# Optional storage prefix handling
PREFIX="${1:-}"
if [[ -z "${PREFIX}" ]]; then
  generate_prefix() {
    local s=""
    while [[ ${#s} -lt 8 ]]; do
      s="${s}$(dd if=/dev/urandom bs=64 count=1 2>/dev/null | LC_ALL=C tr -dc 'A-Za-z0-9')"
    done
    printf '%s' "${s:0:8}"
  }
  PREFIX="$(generate_prefix)"
fi
STORAGE_BASE="/tmp/commonware-epocher/${PREFIX}"

# Announce chosen prefix
log "using storage at: ${STORAGE_BASE}"

# Start indexer
log "starting indexer on :${INDEXER_PORT}"
"${PATH_INDEXER}" --me 1@${INDEXER_PORT} --storage-dir "${STORAGE_BASE}/indexer" &

sleep 1

# Start bootstrap validator (key 1)
log "starting bootstrap validator ${BOOTSTRAP_KEY}@${BOOTSTRAP_PORT}"
mkdir -p "${STORAGE_BASE}/${BOOTSTRAP_KEY}"
"${PATH_VALIDATOR}" --me ${BOOTSTRAP_KEY}@${BOOTSTRAP_PORT} --indexer http://127.0.0.1:${INDEXER_PORT} --storage-dir "${STORAGE_BASE}/${BOOTSTRAP_KEY}" &

sleep 2

# Function to run a validator until killed
run_validator() {
  local key=$1
  local port=$2
  local storage_dir="${STORAGE_BASE}/${key}"
  mkdir -p "${storage_dir}"
  exec "${PATH_VALIDATOR}" --me ${key}@${port} \
    --bootstrappers ${BOOTSTRAP_ADDR} \
    --indexer http://127.0.0.1:${INDEXER_PORT} \
    --storage-dir "${storage_dir}"
}

# Chaos loop per validator (keys 2..10)
chaos_validator() {
  local key=$1
  local port=$2
  while true; do
    # Random up-time 0..120 seconds
    local up_sec=$((RANDOM % 120))
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
      kill -TERM ${pid} 2>/dev/null || true
      # Wait up to ~3s for clean shutdown
      for _ in 1 2 3 4 5 6; do
        if kill -0 ${pid} 2>/dev/null; then
          sleep 0.5 || true
        else
          break
        fi
      done
      # Force kill if still alive
      if kill -0 ${pid} 2>/dev/null; then
        kill -KILL ${pid} 2>/dev/null || true
      fi
      # Reap process to avoid zombies
      wait ${pid} 2>/dev/null || true
    fi
    # Random downtime 0..10 seconds
    local down_sec=$((RANDOM % 10))
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
