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