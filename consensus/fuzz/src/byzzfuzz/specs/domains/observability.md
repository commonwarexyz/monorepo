# Observability

## Purpose

Observability records a bounded ByzzFuzz decision trace so a panic can be explained without rerunning, and exposes that trace to the fuzz harness's panic hook only when explicitly enabled.

## Key Files

- `consensus/fuzz/src/byzzfuzz/log.rs` - bounded decision log.
- `consensus/fuzz/src/byzzfuzz/forwarder.rs` - logs partition drops and process intercepts.
- `consensus/fuzz/src/byzzfuzz/injector.rs` - logs omit, skip, and replacement decisions.
- `consensus/fuzz/src/byzzfuzz/runner.rs` - logs sampled schedules and GST transition.
- `consensus/fuzz/src/lib.rs` - installs the ByzzFuzz panic hook and drains the log on successful runs.

## Core Types

| Item | Role |
| ---- | ---- |
| Decision log | Process-wide, bounded, append-only buffer of human-readable decision lines. |
| `push`, `clear`, `take` | Append a line, reset the buffer, drain it in insertion order. |

## Flow

```
run begins
    |
    | log cleared
    v
fault decisions push lines as they occur
    |
    +-- successful run: harness drains the log so the next run starts clean
    +-- panic: panic hook drains and prints the log only when enabled by environment
            previously installed panic hook runs afterwards
```

The log is bounded by line count, so the trail kept on panic is the most recent decisions leading to the failure.

## Related Invariants

- [Observability](../invariants/invariants.md#observability) - retention bound, FIFO eviction, panic-hook ordering, opt-in printing.

## Configuration

| Parameter | Source | Meaning |
| --------- | ------ | ------- |
| Retention cap | `log.rs` | Maximum retained decision lines. |
| Print diagnostics | `CONSENSUS_FUZZ_LOG` env var | Enables sanitized configuration printing and ByzzFuzz panic-time log printing when any value is set. |

## Extension Points

- Add decision lines at the site where the decision is made.
- Keep log lines compact: the buffer is bounded by line count, not bytes.
- Structured emission is acceptable as long as the panic-hook output remains readable.

## Related Specs

- [ByzzFuzz/Harness Contract](../contracts/byzzfuzz-harness.md) - panic-hook integration.
- [Network Interception](network-interception/README.md) - forwarder log sites.
- [Process Injection](process-injection/README.md) - injector log sites.
