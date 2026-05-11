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
    |     view, bytes, omit, targets }      |
    |   targets already partition-filtered  |
    |   remove targets from kept set        |
    +--> intercept_tx.send(Intercept) ------+
                                            |
                                            v
                                  match channel / omit:
                                    Vote + !omit -> decode, mutate, re-sign,
                                                     send to targets via
                                                     cloned vote sender
                                    Cert / Resolver -> emit nothing
                                                       (forwarder already dropped)
                                    omit=true -> emit nothing
```

Only `Vote` content is mutated. `Intercept.bytes` carries the wire bytes; `Intercept.targets` is final (no re-filtering by the injector).

## Error Propagation

`intercept_tx.send` is non-fatal: forwarders discard the `SendError` because a closed channel means the injector has exited. The injector ignores `vote_sender.send` errors (`let _ = ...`). Undecodable vote bytes inside the injector are logged and skipped.

## Breaking Change Checklist

- If `Intercept` fields change, update both forwarder push sites (`forwarder::intercept_proc_fault_targets`) and the injector consumer (`ByzzFuzzInjector::handle_intercept`).
- If `InterceptChannel` variants change, update the omit-only check in `ByzzFuzzInjector::handle_intercept` and the per-channel forwarders.
- If the injector starts mutating `Cert` or `Resolver` content, supersede [ADR-002](../decisions/002-semantically-mutate-votes-only.md) and update [Process Injection](../domains/process-injection/README.md).
- If the byzantine vote sender is no longer cloned before `split_with`, injector emissions will re-enter the forwarder; update `runner.rs` and this contract.
