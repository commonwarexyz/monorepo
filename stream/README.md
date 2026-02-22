# commonware-stream

[![Crates.io](https://img.shields.io/crates/v/commonware-stream.svg)](https://crates.io/crates/commonware-stream)
[![Docs.rs](https://docs.rs/commonware-stream/badge.svg)](https://docs.rs/commonware-stream)

Exchange messages over arbitrary transport.

## Benchmarking

Run the long-lived encrypted transport benchmark:

```bash
cargo bench -p commonware-stream --bench encrypted_transport
```

This benchmark keeps a connection open and measures steady-state encrypted
message throughput across several message sizes.

## Profiling with samply

1. Ensure Linux perf events are available for non-root profiling:

```bash
echo "1" | sudo tee /proc/sys/kernel/perf_event_paranoid
```

2. Record a profile for the long-lived benchmark:

```bash
samply record --save-only -o /tmp/stream_encrypted_transport_profile.json.gz -- cargo bench -p commonware-stream --bench encrypted_transport
```

3. Open the profile:

```bash
samply load /tmp/stream_encrypted_transport_profile.json.gz
```
