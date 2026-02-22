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

For cleaner CPU profiles (less criterion analysis noise), profile the compiled
benchmark binary directly:

```bash
cargo bench -p commonware-stream --bench encrypted_transport --no-run
BENCH_BIN=$(ls -t target/release/deps/encrypted_transport-* | rg -v "\\.d$" | sed -n "1p")
samply record --save-only --unstable-presymbolicate --duration 5 -o /tmp/stream_encrypted_transport_profile.json.gz -- "$BENCH_BIN" --bench msg_size=16384
```

## Profile-driven optimization status

- Implemented:
  - `Receiver::recv` now avoids an unconditional extra copy before decrypting.
    It coalesces with the buffer pool and uses `try_into_mut` to mutate in place
    when ownership allows.
- Latest measured impact (16 KiB messages, criterion baseline comparison):
  - time: `-11.57%` median (p = 0.02)
  - throughput: `+13.09%` median

## Ranked next optimization opportunities

1. Reduce send-path copy pressure in `Sender::send` (highest expected impact).
2. Add a non-criterion long-running profile harness for cleaner flamegraphs.
3. Investigate timeout wrapper overhead in runtime send/recv paths.
