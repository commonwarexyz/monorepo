#!/bin/bash
# Builds the three measured binaries inside rust:1.95-bookworm (linux/arm64). Expects the monorepo at the
# working directory, CARGO_TARGET_DIR set, and /out mounted; see README step 2.
set -euo pipefail
apt-get update -qq >/dev/null && apt-get install -y -qq clang cmake libclang-dev >/dev/null 2>&1
export CARGO_PROFILE_RELEASE_WITH_DEBUG_DEBUG=line-tables-only
export RUSTFLAGS="-C force-frame-pointers=yes -C target-cpu=generic"
export CARGO_BUILD_JOBS=8
for spec in "base:unsafe-disable-sync" "payments:payments,unsafe-disable-sync" "base-fsync:"; do
  mode=${spec%%:*}; feats=${spec#*:}
  echo "[build] $mode features='$feats' $(date -u +%FT%TZ)"
  cargo build --locked --target aarch64-unknown-linux-gnu --profile release-with-debug --package commonware-log-multimmit --features "$feats"
  mkdir -p /out/$mode
  cp "$CARGO_TARGET_DIR/aarch64-unknown-linux-gnu/release-with-debug/commonware-log-multimmit" /out/$mode/commonware-log-multimmit-debug
  strip -o /out/$mode/commonware-log-multimmit /out/$mode/commonware-log-multimmit-debug
  echo "[built] $mode $(sha256sum /out/$mode/commonware-log-multimmit | cut -d' ' -f1)"
done
echo BUILD_DONE
