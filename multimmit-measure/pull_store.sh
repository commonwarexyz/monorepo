#!/bin/bash
# usage: pull_store.sh <testbed> <prometheus|loki> [suffix]
# Copies a monitor's whole Prometheus or Loki store. The container is paused (frozen in place) for the
# copy, so no file changes while it is read; a stop would not do, since the host recreates stopped
# monitoring containers at once. The copy is streamed here as tar.zst, then the container resumes.
set -euo pipefail
tb=$1; store=$2; suffix=${3:-}
AR=$(cd "$(dirname "$0")/.." && pwd)
ip=$(python3 -c "import json; print(json.load(open('$AR/testbeds/$tb/hosts.json'))['monitoring'][0])")
tag=$(grep '^tag:' "$AR/testbeds/$tb/deploy/config.yaml" | cut -d' ' -f2)
key=~/.commonware_deployer/$tag/id_rsa_$tag
case $store in
  prometheus) src="-C /opt/prometheus data" ;;
  loki) src="-C / loki" ;;
  *) echo "unknown store $store"; exit 2 ;;
esac
out="$AR/package/$store-$tb${suffix:+-$suffix}.tar.zst"
S="ssh -i $key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ServerAliveInterval=15 ubuntu@$ip"
$S "sudo docker pause $store >/dev/null"
trap '$S "sudo docker unpause $store >/dev/null 2>&1 || true"' EXIT
$S "sync; sudo tar -cf - $src" | zstd -q -f -T0 -3 -o "$out"
$S "sudo docker unpause $store >/dev/null; sudo docker inspect -f '{{.State.Status}}' $store"
trap - EXIT
zstd -t -q "$out"
echo "$store $tb $(stat -f %z "$out") $(shasum -a 256 "$out" | cut -c1-64)"
