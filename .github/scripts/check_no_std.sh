#!/usr/bin/env bash
set -eo pipefail

no_std_packages=(
  commonware-codec
  commonware-utils
  commonware-cryptography
  commonware-storage
)

target="thumbv7em-none-eabihf"
base_rustflags="${RUSTFLAGS:-}"

for package in "${no_std_packages[@]}"; do
  build_cmd=(cargo build -p "$package" --no-default-features --target "$target" --release)
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
