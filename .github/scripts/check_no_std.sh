#!/usr/bin/env bash
set -eo pipefail

no_std_packages=(
  commonware-codec
  commonware-utils
  commonware-cryptography
  commonware-storage
)

target="riscv32imac-unknown-none-elf"
image="ghcr.io/commonwarexyz/monorepo/rust-riscv32imac-cross@sha256:652f5ff21c943935bc1caf7cf0c65b38127381c66b423f70f86dc7785d93ce85"
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
