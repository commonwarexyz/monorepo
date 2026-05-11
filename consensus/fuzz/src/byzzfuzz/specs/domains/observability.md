# Observability

## Purpose

Observability records a bounded ByzzFuzz decision trace and exposes it to the fuzz harness panic hook only when explicitly enabled.

## Key Files

- `consensus/fuzz/src/byzzfuzz/log.rs` - process-wide bounded FIFO log.
- `consensus/fuzz/src/byzzfuzz/forwarder.rs` - logs partition drops and process intercepts.
- `consensus/fuzz/src/byzzfuzz/injector.rs` - logs omit, skip, and replacement decisions.
- `consensus/fuzz/src/byzzfuzz/runner.rs` - logs sampled schedules and GST transition.
- `consensus/fuzz/src/lib.rs` - installs the ByzzFuzz panic hook and drains the log on success.

## Core Types

```rust
const LOG_CAP: usize = 8192;

static LOG: OnceLock<Mutex<VecDeque<String>>> = OnceLock::new();

pub fn push(line: String);
pub fn clear();
pub fn take() -> Vec<String>;
```

The log is process-wide, bounded, and drained explicitly.

## Flow

```
byzzfuzz::run
    |
    | log::clear()
    | setup and decisions call log::push(...)
    |
    +-- successful run:
    |       fuzz() drains log::take()
    |
    +-- panic:
            panic hook checks BYZZFUZZ_LOG
            if set, drains log::take() and prints entries
            previous panic hook runs afterward
```

## Related Invariants

- [Observability](../invariants/invariants.md#observability) - log retention and panic-hook invariants.

## Configuration

| Parameter | Value | Meaning |
| --------- | ----- | ------- |
| `LOG_CAP` | `8192` | Maximum retained decision lines. |
| `BYZZFUZZ_LOG` | Any present value | Enables panic-time log printing. |

## Extension Points

- Add new decision lines at the point where the decision is made.
- Keep log messages compact because the buffer is bounded by line count, not bytes.
- Add structured parsing only if the panic hook and existing text output remain usable.

## Related Specs

- [ByzzFuzz/Harness Contract](../contracts/byzzfuzz-harness.md) - panic hook integration.
- [Network Interception](network-interception/README.md) - forwarder log sites.
- [Process Injection](process-injection/README.md) - injector log sites.
