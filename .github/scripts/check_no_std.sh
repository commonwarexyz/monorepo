#!/usr/bin/env bash
set -eo pipefail

no_std_packages=(
  commonware-codec
  commonware-utils
  commonware-cryptography
  commonware-storage
)

for package in "${no_std_packages[@]}"; do
  build_cmd="cargo build -p $package --no-default-features --target thumbv7em-none-eabihf --release"
  if [ -n "$CI" ]; then
    echo "::group::$build_cmd"
  else
    printf "\n%s:\n  %s\n" "$package" "$build_cmd"
  fi

  $build_cmd && du -h "target/thumbv7em-none-eabihf/release/lib${package//-/_}.rlib"

  if [ -n "$CI" ]; then
    echo "::endgroup::"
  fi
done
