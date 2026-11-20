#!/usr/bin/env bash
#
# Runs the workload bench (workload.rs) across QMDB variants, state sizes, access patterns, batch
# sizes, core counts, volumes, record sizes, and index configurations, and measures resident memory
# and load time. Each run appends its JSON lines to $RESULTS/<run name>.jsonl, seed loads append
# to $RESULTS/seeds.jsonl, and the load group appends to $RESULTS/loads.jsonl.
#
# Usage: workload.sh GROUP [VARIANT...]
#
#   GROUP    control, state, active, zipf, batch, creates, cores, disks, records, index, memory,
#            load, or all
#   VARIANT  au (any::unordered), ao (any::ordered), cu (current::unordered), or co
#            (current::ordered). The default is all four. control ignores VARIANT and runs
#            any::unordered. index supports only au and ao, and all runs it for those alone.
#
# Environment:
#
#   BIN      workload bench executable. Required. Build it with one codegen unit, so that inlining
#            does not depend on how the compiler partitions the crate:
#              CARGO_PROFILE_BENCH_CODEGEN_UNITS=1 \
#                cargo bench -p commonware-storage --bench workload --no-run
#   NVME     directory for seeds and clones, on a filesystem with reflink (default /mnt/nvme)
#   GP3_16K  directory on the second volume of the disks group (default /mnt/gp3-16k)
#   GP3_3K   directory on the third volume of the disks group (default /mnt/gp3-3k)
#   RESULTS  output directory (default ./results)
#   THREADS  runtime and pool threads of a load or of a run that is not pinned (default 32)
#
# The script works only inside a directory named qmdb-workload under each of $NVME, $GP3_16K, and
# $GP3_3K. It creates that directory and deletes what it finds there.
#
# A seed is a database that is loaded once, closed, and never run against. Every run starts a new
# process after the OS page cache is dropped. Most runs open a fresh reflink clone of a seed, so
# they inherit no state from earlier runs. The disks group instead opens copies of one prewarmed
# clone.
#
# Needs Linux with bash 4.4 or later, GNU cp, findmnt, taskset, and sudo, CPUs 0 through 31 for
# the cores group, about 150 GiB of memory, and about 1 TB under $NVME.

set -euo pipefail

BIN=${BIN:?set BIN to the workload bench executable}
NVME=${NVME:-/mnt/nvme}
GP3_16K=${GP3_16K:-/mnt/gp3-16k}
GP3_3K=${GP3_3K:-/mnt/gp3-3k}
RESULTS=${RESULTS:-$PWD/results}
THREADS=${THREADS:-32}
SEEDS=$NVME/qmdb-workload/seeds
WORK=$NVME/qmdb-workload/work

# Number of cores a run is pinned to. Only the cores group sets it, for one run at a time.
CORES=

declare -A DB=(
  [au]=any::unordered
  [ao]=any::ordered
  [cu]=current::unordered
  [co]=current::ordered
)

# Read phases that let resident memory settle. The allocator returns the memory an open freed a few
# seconds after the open, so the line of the second phase reports settled memory.
SETTLE="read:readers=4,secs=15,label=settle;read:readers=4,secs=5,label=settle2"

# disk_of PATH: the name of the block device that holds PATH, as /proc/diskstats lists it.
disk_of() {
  local source name
  source=$(findmnt -no SOURCE --target "$1")
  name=$(basename "$source")
  if ! grep -qw -- "$name" /proc/diskstats; then
    echo "$1 must be on a block device that /proc/diskstats lists, found $source" >&2
    return 1
  fi
  echo "$name"
}

# Writes back dirty pages, then drops the OS page cache, dentries, and inodes.
drop_caches() {
  sync
  echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null
}

# clone SEED DEST: replace DEST with a reflink copy of SEED.
clone() {
  rm -rf "${2:?}"
  mkdir -p "$(dirname "$2")"
  cp -a --reflink=always "$1" "$2"
}

# seed NAME DB KEYS [flags]: load seed NAME unless $SEEDS/NAME.ok shows that an earlier call
# finished loading it.
seed() {
  local name=$1 db=$2 keys=$3 disk
  shift 3
  if [ -f "$SEEDS/$name.ok" ]; then return; fi
  disk=$(disk_of "$NVME")
  rm -rf "${SEEDS:?}/$name"
  "$BIN" load --dir "$SEEDS/$name" --db "$db" --keys "$keys" --threads "$THREADS" \
    --disk "$disk" --tag "seed:$name" --out "$RESULTS/seeds.jsonl" "$@"
  touch "$SEEDS/$name.ok"
}

# unseed NAME: remove seed NAME, marker first so that an interrupted removal is loaded again.
unseed() {
  rm -f "$SEEDS/$1.ok"
  rm -rf "${SEEDS:?}/$1"
}

# run_on DIR NAME DB KEYS PHASES [flags]: drop the OS page cache, then open DIR in a new process,
# run the phases in order, and append the output to $RESULTS/NAME.jsonl. With CORES set, the
# process is pinned to cores 0 through CORES - 1 and runs CORES threads.
#
# An ordered database rewrites the predecessor of every key it creates, so even a freshly loaded
# one holds superseded operations above its inactivity floor. An open resolves each of them, with
# a random read whenever the init cache has evicted the operation it replaces. An ordered run
# therefore gets an init cache sized to hold two operations per key.
run_on() {
  local dir=$1 name=$2 db=$3 keys=$4 phases=$5 disk
  shift 5
  local pin=() init=()
  if [ -n "$CORES" ]; then pin=(taskset -c "0-$((CORES - 1))"); fi
  case $db in *::ordered) init=(--init-cache "$((keys * 2))") ;; esac
  disk=$(disk_of "$dir")
  drop_caches
  "${pin[@]}" "$BIN" run --dir "$dir" --db "$db" --keys "$keys" --threads "${CORES:-$THREADS}" \
    --disk "$disk" --tag "$name" --phases "$phases" --out "$RESULTS/$name.jsonl" \
    "${init[@]}" "$@"
}

# The same short workload on any::unordered at 10M keys for every host, to compare hosts before
# comparing results across them.
control() {
  local phases="update:active=0.01,batch=10000,secs=10,windows=3,label=hot"
  phases+=";update:active=1,batch=10000,secs=10,windows=3,label=uniform"
  phases+=";read:readers=32,secs=10,label=reads"
  seed au-10m any::unordered 10000000
  clone "$SEEDS/au-10m" "$WORK/db"
  run_on "$WORK/db" control any::unordered 10000000 "$phases"
}

# State size: a 1M-key active set and an active set of every key, at 10M, 100M, and 1B keys.
# Warm-up of the full active set is capped by warm-max-secs so that each run ends in bounded time.
state() {
  local p=$1 db=${DB[$1]} size tag keys cap
  for size in "1b 1000000000 120" "100m 100000000 180" "10m 10000000 180"; do
    read -r tag keys cap <<< "$size"
    seed "$p-$tag" "$db" "$keys"
    clone "$SEEDS/$p-$tag" "$WORK/db"
    run_on "$WORK/db" "state-$p-$tag-active1m" "$db" "$keys" \
      "update:active-keys=1000000,label=active1m"
    clone "$SEEDS/$p-$tag" "$WORK/db"
    run_on "$WORK/db" "state-$p-$tag-uniform" "$db" "$keys" \
      "update:active=1,warm-max-secs=$cap,label=uniform"
  done
}

# Active set: the share of 1B keys that batches draw from. Warm-up of the widest shares, 0.1 and
# 0.3, is capped.
active() {
  local p=$1 db=${DB[$1]} point share extra
  seed "$p-1b" "$db" 1000000000
  for point in "0.01" "0.1 ,warm-max-secs=300" "0.03" "0.3 ,warm-max-secs=120"; do
    read -r share extra <<< "$point"
    clone "$SEEDS/$p-1b" "$WORK/db"
    run_on "$WORK/db" "active-$p-$share" "$db" 1000000000 \
      "update:active=$share,label=active-$share$extra"
  done
}

# Zipf-distributed access over 1B keys, with exponents 0.5, 0.99, and 1.2.
zipf() {
  local p=$1 db=${DB[$1]} s
  seed "$p-1b" "$db" 1000000000
  for s in 0.99 0.5 1.2; do
    clone "$SEEDS/$p-1b" "$WORK/db"
    run_on "$WORK/db" "zipf-$p-$s" "$db" 1000000000 \
      "update:dist=zipf,zipf=$s,warm-max-secs=300,label=zipf-$s"
  done
}

# Batch size: one process runs every size on a 1% active set. The first phase warms up the freshly
# loaded database, so later phases skip the minimum warm-up and only wait for their windows to
# agree.
batch() {
  local p=$1 db=${DB[$1]} b
  local phases="update:active=0.01,batch=10000,label=batch-10000"
  for b in 100 1000 100000; do
    phases+=";update:active=0.01,batch=$b,warm-min-updates=0,label=batch-$b"
  done
  phases+=";update:active=0.01,batch=1000000,warm-min-updates=0,min-batches=10,label=batch-1000000"
  seed "$p-1b" "$db" 1000000000
  clone "$SEEDS/$p-1b" "$WORK/db"
  run_on "$WORK/db" "batch-$p" "$db" 1000000000 "$phases"
}

# New keys: the number of keys in each 10K-key batch that did not exist before. As in the batch
# group, only the first phase does the minimum warm-up.
creates() {
  local p=$1 db=${DB[$1]} c
  local phases="update:active=0.01,creates=0,label=creates-0"
  for c in 100 1000 5000 10000; do
    phases+=";update:active=0.01,creates=$c,warm-min-updates=0,label=creates-$c"
  done
  seed "$p-1b" "$db" 1000000000
  clone "$SEEDS/$p-1b" "$WORK/db"
  run_on "$WORK/db" "creates-$p" "$db" 1000000000 "$phases"
}

# Cores: the process is pinned to N cores and runs N threads. any::unordered repeats the sweep
# with 100K-key batches.
cores() {
  local p=$1 db=${DB[$1]} n
  seed "$p-1b" "$db" 1000000000
  for n in 32 16 8 4 2 1; do
    clone "$SEEDS/$p-1b" "$WORK/db"
    CORES=$n run_on "$WORK/db" "cores-$p-$n" "$db" 1000000000 \
      "update:active=0.01,label=cores-$n"
  done
  if [ "$p" != au ]; then return; fi
  for n in 32 16 8 4 2 1; do
    clone "$SEEDS/$p-1b" "$WORK/db"
    CORES=$n run_on "$WORK/db" "cores100k-$p-$n" "$db" 1000000000 \
      "update:active=0.01,batch=100000,label=cores-$n"
  done
}

# Disks: one database is warmed on $NVME, copied to the other two volumes, and run through the
# same phases on each. any::unordered also runs uniform point reads at five reader counts.
#
# A database that has been updated holds superseded operations across its whole journal, so every
# leg opens with an init cache sized to hold two operations per key. The uniform phase on the third
# volume measures one window, because its batches are the slowest.
disks() {
  local p=$1 db=${DB[$1]} n reads="" copy i phases first second third
  local legs=(nvme gp3-16k gp3-3k) windows=("" "" ",windows=1")
  local dirs=("$WORK/db" "$GP3_16K/qmdb-workload/db" "$GP3_3K/qmdb-workload/db")
  first=$(disk_of "$NVME")
  second=$(disk_of "$GP3_16K")
  third=$(disk_of "$GP3_3K")
  if [ "$first" = "$second" ] || [ "$first" = "$third" ] || [ "$second" = "$third" ]; then
    echo "disks: \$NVME, \$GP3_16K, and \$GP3_3K must be on three block devices" >&2
    return 1
  fi
  if [ "$p" = au ]; then
    for n in 1 4 16 64 256; do reads+=";read:readers=$n,secs=15,label=readers-$n"; done
  fi
  seed "$p-1b" "$db" 1000000000
  clone "$SEEDS/$p-1b" "$WORK/warm"
  run_on "$WORK/warm" "disks-$p-prewarm" "$db" 1000000000 \
    "update:active=0.01,windows=1,secs=5,label=prewarm"
  rm -rf "${dirs[1]:?}" "${dirs[2]:?}"
  mkdir -p "$GP3_16K/qmdb-workload" "$GP3_3K/qmdb-workload"
  cp -a "$WORK/warm" "${dirs[1]}" &
  copy=$!
  cp -a "$WORK/warm" "${dirs[2]}"
  wait "$copy"
  clone "$WORK/warm" "$WORK/db"
  for i in 0 1 2; do
    phases="update:active=0.01,warm-min-updates=0,label=hot;update:active=1,warm-min-updates=0"
    phases+=",warm-max-secs=60,max-secs=300${windows[i]},label=uniform$reads"
    run_on "${dirs[i]}" "disks-$p-${legs[i]}" "$db" 1000000000 "$phases" --init-cache 2000000000
  done
  rm -rf "$WORK/warm" "${dirs[1]:?}" "${dirs[2]:?}"
}

# Record size: value sizes at 32-byte keys, then key sizes at 32-byte values, on the
# variable-size journal at 100M keys. Each seed is removed after its run to bound disk use.
records() {
  local p=$1 db=${DB[$1]} shape k v name
  for shape in "32 32" "32 128" "32 512" "32 2048" "20 32" "64 32"; do
    read -r k v <<< "$shape"
    name=$p-var-k$k-v$v
    seed "$name" "$db" 100000000 --log variable --key-size "$k" --value-size "$v"
    clone "$SEEDS/$name" "$WORK/db"
    run_on "$WORK/db" "rec-$p-k$k-v$v" "$db" 100000000 "update:active=0.01,label=rec-k$k-v$v" \
      --log variable --key-size "$k" --value-size "$v"
    unseed "$name"
  done
}

# Index and translator: 100M keys under each index and translator configuration of the variant.
# Memory is measured with a page cache too small to matter, and the workloads with a 1 GiB cache so
# that uniform work reaches the disk. Each seed is removed after its runs to bound disk use.
index() {
  local p=$1 db=${DB[$1]} flavors flavor idx tr name
  local phases="update:active=0.01,label=hot;update:active=1,warm-max-secs=60,label=uniform"
  phases+=";read:readers=64,secs=15,label=reads"
  case $p in
    au) flavors=("p2 eight" "plain eight" "p2 four" "p2 two") ;;
    ao) flavors=("p3 eight" "plain eight" "p2 eight") ;;
  esac
  for flavor in "${flavors[@]}"; do
    read -r idx tr <<< "$flavor"
    name=$p-idx-$idx-$tr
    seed "$name" "$db" 100000000 --index "$idx" --translator "$tr"
    clone "$SEEDS/$name" "$WORK/db"
    run_on "$WORK/db" "idxmem-$p-$idx-$tr" "$db" 100000000 "$SETTLE" \
      --index "$idx" --translator "$tr" --cache-pages 64
    clone "$SEEDS/$name" "$WORK/db"
    run_on "$WORK/db" "idx-$p-$idx-$tr" "$db" 100000000 "$phases" \
      --index "$idx" --translator "$tr" --cache-pages 262144
    unseed "$name"
  done
}

# Memory and disk: prune a clone, then read resident memory with a page cache too small to
# matter. The prune line reports the size of a pruned database.
memory() {
  local p=$1 db=${DB[$1]} size tag keys
  for size in "1b 1000000000" "100m 100000000" "10m 10000000"; do
    read -r tag keys <<< "$size"
    seed "$p-$tag" "$db" "$keys"
    clone "$SEEDS/$p-$tag" "$WORK/db"
    run_on "$WORK/db" "rss-$p-$tag" "$db" "$keys" "prune:;$SETTLE" --cache-pages 64
  done
}

# Load: time a 1B-key load into a scratch directory.
load() {
  local p=$1 db=${DB[$1]} disk
  disk=$(disk_of "$NVME")
  rm -rf "$WORK/load"
  "$BIN" load --dir "$WORK/load" --db "$db" --keys 1000000000 --threads "$THREADS" \
    --disk "$disk" --tag "load:$p-1b" --out "$RESULTS/loads.jsonl"
  rm -rf "$WORK/load"
}

# Parse the group and check every variant before creating any directory.
group=${1:?usage: workload.sh GROUP [VARIANT...]}
shift
variants=("$@")
if [ ${#variants[@]} -eq 0 ]; then
  variants=(au ao cu co)
  if [ "$group" = index ]; then variants=(au ao); fi
fi
for p in "${variants[@]}"; do
  if [ -z "${DB[$p]:-}" ]; then
    echo "unknown variant $p" >&2
    exit 1
  fi
  if [ "$group" = index ] && [ "$p" != au ] && [ "$p" != ao ]; then
    echo "index supports only au and ao" >&2
    exit 1
  fi
done

mkdir -p "$RESULTS" "$SEEDS" "$WORK"
ulimit -n "$(ulimit -Hn)"

case $group in
  control) control ;;
  state | active | zipf | batch | creates | cores | disks | records | index | memory | load)
    for p in "${variants[@]}"; do "$group" "$p"; done
    ;;
  # all runs control once, then each per-variant group, then index for the variants it supports.
  all)
    control
    for g in state active zipf batch creates cores disks records memory load; do
      for p in "${variants[@]}"; do "$g" "$p"; done
    done
    for p in "${variants[@]}"; do
      case $p in au | ao) index "$p" ;; esac
    done
    ;;
  *)
    echo "unknown group $group" >&2
    exit 1
    ;;
esac
