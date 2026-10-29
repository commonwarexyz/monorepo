#!/usr/bin/env bash
# Installs and starts kache. Any failure leaves the job uncached instead of failing it.
set -euo pipefail

KACHE_VERSION=v2.0.0-rc.3

disable() {
  echo "::warning::$1, kache disabled for this job."
  exit 0
}

if [ -z "$R2_BUCKET" ] || [ -z "$R2_ENDPOINT" ] \
  || [ -z "$R2_ACCESS_KEY_ID" ] || [ -z "$R2_SECRET_ACCESS_KEY" ]; then
  disable "R2 environment is incomplete"
fi
command -v jq >/dev/null || disable "jq is unavailable"

# Digests of the release archives, pinned so that a replaced asset never runs.
case "$RUNNER_OS-$RUNNER_ARCH" in
  Linux-X64)
    target=x86_64-unknown-linux-musl
    sha256=e834d16c24df8daa550765b56809f34dd75f9a562fc8febe84bbb7167ae925c7
    ;;
  Linux-ARM64)
    target=aarch64-unknown-linux-musl
    sha256=92d9072ff80187d9ced2eb5e7b3faa79238b14660b9c6d93ab903ad6200fea67
    ;;
  macOS-ARM64)
    target=aarch64-apple-darwin
    sha256=fe3a044df484377052e2e6872a3a771e4d308c4b7309fc980b048fd28994f7d2
    ;;
  macOS-X64)
    target=x86_64-apple-darwin
    sha256=75da6c08c0f5cebb515fbf24939a37bf76151d01fd81c1245a6221d36c63d85a
    ;;
  *)
    disable "No kache build is pinned for $RUNNER_OS-$RUNNER_ARCH"
    ;;
esac

root="$RUNNER_TEMP/kache"
mkdir -p "$root/bin"
archive="$root/kache.tar.gz"
url="https://github.com/kunobi-ninja/kache/releases/download/$KACHE_VERSION/kache-$target.tar.gz"
curl -sSfL --retry 3 -o "$archive" "$url" || disable "Downloading kache failed"
echo "$sha256  $archive" | shasum -a 256 -c - >/dev/null \
  || disable "The kache archive does not match its pinned digest"
# v2 archives also contain kache-engine, which kache runs from the same directory.
tar -xzf "$archive" -C "$root/bin" || disable "Extracting kache failed"
[ -x "$root/bin/kache" ] || disable "The kache archive has no kache binary"
real="$root/bin/kache"
"$real" --version

# Hide GitHub Actions from every client and the daemon to seed the base.
# cc-rs requires the wrapper filename to be kache.
mkdir -p "$root/shim"
printf '#!/bin/sh\nexec env -u GITHUB_ACTIONS "%s" "$@"\n' "$real" >"$root/shim/kache"
chmod +x "$root/shim/kache"
kache="$root/shim/kache"

if [ "$RUNNER_OS" = "Linux" ]; then
  # Same filesystem as CARGO_TARGET_DIR, so restores can hardlink.
  store=/mnt/kache
  sudo mkdir -p "$store"
  sudo chown "$(id -u):$(id -g)" "$store"
  max_size=20GiB
else
  store="$root/store"
  max_size=10GiB
fi

endpoint="$R2_ENDPOINT"
case "$endpoint" in
  *://*) ;;
  *) endpoint="https://$endpoint" ;;
esac

# The daemon drops the KACHE_S3_* remote settings but keeps the credentials (kache#706), so
# the remote goes in a config file. Seed jobs write the base prefix through the shim.
config="$root/config.toml"
cat >"$config" <<EOF
[cache.remote]
type = "s3"
bucket = "$R2_BUCKET"
endpoint = "$endpoint"
region = "auto"
prefix = "kache-pilot-rc-base"
EOF

env_vars=(
  "KACHE_CONFIG=$config"
  "KACHE_CACHE_DIR=$store"
  "KACHE_RUNTIME_DIR=/tmp/kache"
  "KACHE_MAX_SIZE=$max_size"
  "KACHE_CACHE_EXECUTABLES=1"
  "KACHE_MANIFEST_KEY=$MANIFEST_KEY-$GITHUB_JOB-$RUNNER_OS-$RUNNER_ARCH"
)
for var in "${env_vars[@]}"; do
  export "${var?}"
done
# Only the daemon, doctor and save-manifest talk to R2, so the credentials stay out of
# GITHUB_ENV. post.js passes them to post.sh.
export KACHE_S3_ACCESS_KEY="$R2_ACCESS_KEY_ID" KACHE_S3_SECRET_KEY="$R2_SECRET_ACCESS_KEY"

# Starting early lets prefetching overlap the rest of the setup.
"$kache" daemon start >/dev/null || disable "The kache daemon did not start"
# Log the remote and whether this job writes to it, then check that it accepts the credentials.
doctor="$("$kache" doctor --json 2>/dev/null || true)"
jq -r '.checks[]? | select(.label | IN("Remote", "Remote access", "Remote writes"))
  | "\(.label): \(.detail)"' <<<"$doctor" || true
if ! jq -e '.checks[]? | select(.label == "Remote access") | .pass' <<<"$doctor" >/dev/null; then
  "$kache" daemon stop >/dev/null 2>&1 || true
  disable "kache cannot reach the R2 remote"
fi

# Seed verification requires permission to write the base prefix.
if ! jq -e 'any(.checks[]?; .label == "Remote writes" and .detail == "read-write")' <<<"$doctor" >/dev/null; then
  "$kache" daemon stop >/dev/null 2>&1 || true
  disable "kache seed cannot write the R2 remote"
fi
echo "kache-seed-remote-writes: verified"

{
  printf '%s\n' "${env_vars[@]}"
  echo "CARGO_INCREMENTAL=0"
  echo "RUSTC_WRAPPER=$kache"
} >>"$GITHUB_ENV"
echo "$root/shim" >>"$GITHUB_PATH"
echo "enabled=true" >>"$GITHUB_STATE"
