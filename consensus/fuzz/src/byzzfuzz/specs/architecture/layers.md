# Layers

## Context

ByzzFuzz is a specialized fuzzing mode inside the consensus fuzz crate.
It must stay deterministic, reuse the simulated p2p network, and avoid becoming a second consensus implementation.

## Layer Model

```
fuzz target binaries
    |
    v
consensus/fuzz/src/lib.rs
    - Mode::Byzzfuzz dispatch
    - FuzzInput and panic hook integration
    - shared setup_network and spawn_honest_validator
    |
    v
consensus/fuzz/src/byzzfuzz/runner.rs
    - samples schedule bounds
    - wires forwarders, receivers, injector, reporters
    - drives phase 1, GST, phase 2, and invariants
    |
    +--> fault scheduling
    |       sampling.rs, fault.rs, scope.rs
    |
    +--> network interception
    |       forwarder.rs, intercept.rs
    |
    +--> process injection
    |       injector.rs, mutator.rs, observed.rs
    |
    +--> observability
            log.rs
```

Dependency direction is inward from the harness entry point to the ByzzFuzz module.
ByzzFuzz may depend on shared fuzz helpers in `consensus/fuzz/src/lib.rs`, `strategy.rs`, `utils.rs`, and `invariants.rs`.
Shared helpers must not depend on private ByzzFuzz internals except for the public mode dispatch and panic log
handling already present in `lib.rs`.

`runner.rs` owns cross-domain orchestration. Lower domains expose small data types, factories, or helpers and do not spawn whole Simplex runs.

## Related Invariants

- [Layers](../invariants/invariants.md#layers) - architectural dependency and ownership invariants.

## Anti-Patterns

- Adding a second public ByzzFuzz entry point bypasses `Mode::Byzzfuzz` and the panic-log hook.
- Encoding Simplex consensus rules inside ByzzFuzz duplicates protocol logic; ByzzFuzz should decode, observe, mutate, 
  and re-sign existing Simplex message types.
- Letting lower-level modules spawn validators makes phase behavior hard to reason about.
- Introducing direct runtime-specific dependencies violates the fuzz crate's deterministic testing model.
