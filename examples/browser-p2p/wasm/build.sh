#!/bin/sh
set -eu

. "$(dirname "$0")/toolchain.sh"

cargo build --release --target wasm32-unknown-unknown
wasm-bindgen \
  --target web \
  --out-dir ../dist/wasm \
  --out-name browser_p2p \
  target/wasm32-unknown-unknown/release/commonware_browser_p2p.wasm
