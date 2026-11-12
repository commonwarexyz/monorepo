#!/usr/bin/env bash
set -eo pipefail

no_std_packages=(
  commonware-codec
  commonware-utils
  commonware-cryptography
  commonware-cryptography-curve25519
  commonware-math
  commonware-storage
  commonware-parallel
)

target="riscv32imac-unknown-none-elf"
image="ghcr.io/commonwarexyz/monorepo/rust-riscv32imac-cross@sha256:41e68788e362c24f5398e321cf701e709d14ddf2f7b419cfcb90216afa292ab8"
base_rustflags="${RUSTFLAGS:-}"

for package in "${no_std_packages[@]}"; do
  build_cmd=(docker run \
    --rm \
    -v `pwd`:/workdir \
    -w="/workdir" \
    "$image" cargo +nightly build -p "$package" -Zbuild-std=core,alloc --no-default-features --target "$target" --release)
  pretty_cmd="${build_cmd[*]}"
  if [ -n "$CI" ]; then
    echo "::group::${pretty_cmd}"
  else
    printf "\n%s:\n  %s\n" "$package" "$pretty_cmd"
  fi

  RUSTFLAGS="${base_rustflags} -D warnings" "${build_cmd[@]}"
  du -h "target/${target}/release/lib${package//-/_}.rlib"

  if [ -n "$CI" ]; then
    echo "::endgroup::"
  fi
done
