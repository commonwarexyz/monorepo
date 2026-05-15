# Contract: Forwarder (sync) <-> Injector (async)

## Boundary Rule

Forwarders run synchronously inside `SplitForwarder` closures and push `Intercept` work items into an unbounded mpsc channel; the async injector consumes them and emits replacement votes via a cloned byzantine vote sender that bypasses the forwarder.

## Interfaces

| Interface | Package | Consumed By | Purpose |
| --------- | ------- | ----------- | ------- |
| `intercept::channel::<P>()` | `consensus/fuzz/src/byzzfuzz/intercept.rs` | `runner::setup_engines` | Constructs the sync->async `(UnboundedSender, UnboundedReceiver)` pair. |
| `Intercept<P>` | `consensus/fuzz/src/byzzfuzz/intercept.rs` | forwarders push, injector consumes | One captured byzantine outgoing message paired with one matching `procFault`. |
| `InterceptChannel` | `consensus/fuzz/src/byzzfuzz/intercept.rs` | forwarder, injector | Discriminates `Vote` / `Cert` / `Resolver` for routing. |
| `ByzzFuzzInjector::start` | `consensus/fuzz/src/byzzfuzz/injector.rs` | `runner::setup_engines` | Spawns the async loop with the cloned byzantine vote sender and intercept receiver. |
| Cloned byzantine vote sender | `commonware_p2p::Sender` from `runner` | injector | Emits replacement votes bypassing the forwarder. |

## Initialization

`runner::setup_engines` creates `(intercept_tx, intercept_rx)` once, hands `Some(intercept_tx)` to the byzantine sender's forwarders (`None` to honest senders), clones the byzantine vote sender before `split_with` so the injector bypasses the forwarder, and calls `ByzzFuzzInjector::start(vote_sender, intercept_rx)`. The original `intercept_tx` is dropped at the end of `setup_engines` so the channel closes once all forwarder-held clones drop.

## Data Flow Across Boundary

```
forwarder (sync)                       injector (async)
    |                                       ^
    | per matching ProcessFault:            |
    |   build Intercept { channel,          |
    |     view, bytes, action, targets }    |
    |   targets already partition-filtered  |
    |   send intercept work item            |
    +--> intercept_tx.send(Intercept) ------+
    |   on success, remove targets          |
    |   on failure, preserve original       |
                                            |
                                            v
                                  match action / channel:
                                    MutateVote + Vote ->
                                      decode, mutate, re-sign,
                                      send to targets via cloned vote sender
                                    Omit -> emit nothing
```

Only `Vote` content is mutated. `Intercept.bytes` carries the wire bytes; `Intercept.targets` is final (no re-filtering by the injector). Certificate and resolver process faults are represented with `ProcessAction::Omit`.

## Error Propagation

`intercept_tx.send` is non-fatal: if the channel is closed, forwarders log the failure and preserve the original delivery instead of silently turning mutation into omission. The injector ignores `vote_sender.send` errors (`let _ = ...`). Undecodable vote bytes inside the injector are logged and skipped.

## Breaking Change Checklist

- If `Intercept` fields change, update both forwarder push sites (`forwarder::intercept_proc_fault_targets`) and the injector consumer (`ByzzFuzzInjector::handle_intercept`).
- If `InterceptChannel` variants change, update `ProcessAction::supports_channel`, `ByzzFuzzInjector::handle_intercept`, and the per-channel forwarders.
- If the injector starts mutating `Cert` or `Resolver` content, supersede [ADR-001](../decisions/001-process-fault-model.md) and update [Process Injection](../domains/process-injection/README.md).
- If the byzantine vote sender is no longer cloned before `split_with`, injector emissions will re-enter the forwarder; update `runner.rs` and this contract.
