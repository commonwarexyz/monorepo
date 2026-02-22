# commonware-p2p

[![Crates.io](https://img.shields.io/crates/v/commonware-p2p.svg)](https://crates.io/crates/commonware-p2p)
[![Docs.rs](https://docs.rs/commonware-p2p/badge.svg)](https://docs.rs/commonware-p2p)

Communicate with authenticated peers over encrypted connections.

## Status 

Stability varies by primitive. See [README](https://github.com/commonwarexyz/monorepo#stability) for details.

## Benchmarking

Run the long-lived authenticated lookup benchmark:

```bash
cargo bench -p commonware-p2p --bench authenticated_lookup
```

This benchmark establishes peer connections once and then measures sustained
message exchange over long-lived channels.

## Profiling with samply

1. Ensure Linux perf events are available for non-root profiling:

```bash
echo "1" | sudo tee /proc/sys/kernel/perf_event_paranoid
```

2. Record a profile for the long-lived benchmark:

```bash
samply record --save-only -o /tmp/p2p_authenticated_lookup_profile.json.gz -- cargo bench -p commonware-p2p --bench authenticated_lookup
```

3. Open the profile:

```bash
samply load /tmp/p2p_authenticated_lookup_profile.json.gz
```

For cleaner CPU profiles (less criterion analysis noise), profile the compiled
benchmark binary directly:

```bash
cargo bench -p commonware-p2p --bench authenticated_lookup --no-run
BENCH_BIN=$(ls -t target/release/deps/authenticated_lookup-* | rg -v "\\.d$" | sed -n "1p")
samply record --save-only --unstable-presymbolicate --duration 5 -o /tmp/p2p_authenticated_lookup_profile.json.gz -- "$BENCH_BIN" --bench msg_size=16384
```

## Profile-driven optimization status

- Implemented:
  - Cached peer-actor metric counters for hot sent/received/dropped paths in
    authenticated lookup and discovery actors.
  - Added a connection warm-up timeout guard in the long-lived lookup benchmark
    to avoid infinite warm-up loops on failure.
  - Stream recv-path copy removal (in `commonware-stream`) also benefits p2p
    because authenticated transport uses stream encryption internally.
- Latest benchmark snapshot (`authenticated_lookup::steady_state`):
  - 64 B: 1.88 MiB/s (improved vs prior baseline)
  - 1 KiB: 25.69 MiB/s (no statistically significant change)
  - 16 KiB: 259.49 MiB/s (improved vs prior baseline)

## Ranked next optimization opportunities

1. Reduce encrypted send-path copy/allocation pressure in `commonware-stream`.
2. Add a non-criterion long-running profile harness for p2p steady-state runs.
3. Evaluate lower-overhead timeout/deadline handling in runtime network paths.