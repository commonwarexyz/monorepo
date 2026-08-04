#!/usr/bin/env bash
# Ensure runtime APIs still under development do not enter the BETA public surface.

set -euo pipefail

target_dir="${CARGO_TARGET_DIR:-target}/stability-alpha-surface"
json_path="$target_dir/doc/commonware_runtime.json"

RUSTC_WRAPPER="" \
RUSTFLAGS="--cfg commonware_stability_BETA" \
RUSTDOCFLAGS="-Z unstable-options --output-format json --cfg commonware_stability_BETA -Arustdoc::broken_intra_doc_links" \
CARGO_TARGET_DIR="$target_dir" \
cargo +nightly doc -p commonware-runtime --no-deps >/dev/null

alpha_paths=(
    commonware_runtime::atomic_api::ATOMIC_BLOB_TAG_LEN
    commonware_runtime::atomic_api::AtomicBlob
    commonware_runtime::atomic_api::AtomicStorage
    commonware_runtime::atomic_api::BatchOperation
    commonware_runtime::atomic_api::BatchStorage
    commonware_runtime::utils::buffer::paged::atomic::ATOMIC_MARKER_LEN
    commonware_runtime::utils::buffer::paged::atomic::AtomicReplay
    commonware_runtime::utils::buffer::paged::atomic::AtomicSnapshot
    commonware_runtime::utils::buffer::paged::atomic::AtomicWriter
    commonware_runtime::utils::buffer::paged::atomic::atomic_page_size
)

leaked=0
for path in "${alpha_paths[@]}"; do
    if jq -e --arg path "$path" \
        '.paths[] | select((.path | join("::")) == $path)' \
        "$json_path" >/dev/null; then
        echo "ALPHA API is visible at BETA: $path" >&2
        leaked=1
    fi
done

exit "$leaked"
