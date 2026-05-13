# Contract: ByzzFuzz <-> Fuzz Harness

## Boundary Rule

The fuzz harness dispatches into ByzzFuzz through `Mode::Byzzfuzz` and `byzzfuzz::run`; ByzzFuzz may use shared harness setup helpers but private ByzzFuzz behavior stays inside `consensus/fuzz/src/byzzfuzz`.

## Interfaces

| Interface | Package | Consumed By | Purpose |
| --------- | ------- | ----------- | ------- |
| `pub mod byzzfuzz` | `consensus/fuzz/src/lib.rs` | Fuzz crate users | Exposes the ByzzFuzz module. |
| `pub use runner::run` | `consensus/fuzz/src/byzzfuzz/mod.rs` | `fuzz::<P, Byzzfuzz>` dispatch | Runs one ByzzFuzz iteration. |
| `pub struct Byzzfuzz` | `consensus/fuzz/src/lib.rs` | Fuzz targets | Marker type implementing `FuzzMode`. |
| `Mode::Byzzfuzz` | `consensus/fuzz/src/lib.rs` | `fuzz` dispatcher | Selects ByzzFuzz mode. |
| `setup_network` | `consensus/fuzz/src/lib.rs` | `runner.rs` | Builds simulated network, participants, schemes, and channel registrations. |
| `spawn_honest_validator` | `consensus/fuzz/src/lib.rs` | `runner.rs` | Starts Simplex engine, application, and reporter. |
| `byzzfuzz::log::take` | `consensus/fuzz/src/byzzfuzz/log.rs` | `lib.rs` panic hook | Drains decision trace. |

## Initialization

ByzzFuzz fuzz targets call:

```rust
fuzz::<SimplexId, Byzzfuzz>(input);
```

`fuzz` installs the ByzzFuzz panic hook when `M::MODE == Mode::Byzzfuzz`, then dispatches to `byzzfuzz::run::<P>(input)` inside `panic::catch_unwind`.

Inside `run`, ByzzFuzz coerces `FuzzInput` to a fixed four-node connected shape, creates a deterministic runner seeded by `input.raw_bytes`, and calls shared setup helpers.

## Data Flow Across Boundary

```
FuzzInput
    |
    | raw_bytes -> FuzzRng
    | required_containers -> schedule bounds and phase 1 target
    | forwarding -> spawn_honest_validator, then currently disabled in fuzz()
    | certify -> overwritten by ByzzFuzz, then passed to spawn_honest_validator
    v
byzzfuzz::run
    |
    | reporters -> invariants
    | panic decisions -> byzzfuzz::log
    v
fuzz() panic handling
```

ByzzFuzz overwrites `configuration`, `partition`, `degraded_network`, and `certify` before setup. The `certify` override samples a ByzzFuzz-specific policy from the deterministic context; single-target variants in that policy pin to the byzantine validator so the disabled certifier coincides with the existing adversary. Other fields remain available to shared helper calls.

## Error Propagation

ByzzFuzz liveness failures and invariant failures panic inside `run`. The top-level `fuzz` function catches the unwind, prints `raw_bytes`, and resumes the panic. The panic hook drains and prints the decision log only when `CONSENSUS_FUZZ_LOG` is set.

## Breaking Change Checklist

- If `byzzfuzz::run` signature changes, update `Mode::Byzzfuzz` dispatch in `consensus/fuzz/src/lib.rs` and all ByzzFuzz fuzz targets.
- If `FuzzInput` fields used by ByzzFuzz change, update `runner.rs` and [Runner Liveness](../domains/runner-liveness.md).
- If `setup_network` or `spawn_honest_validator` signatures change, update `runner.rs` wiring and this contract.
- If panic-log behavior changes, update [Observability](../domains/observability.md).
- If ByzzFuzz stops forcing `N4F0C4` or connected topology, update [Runner Liveness](../domains/runner-liveness.md) and create or supersede an ADR.
- If the ByzzFuzz certify-policy sampler stops pinning single-target variants to the byzantine validator, update [Invariants](../invariants/invariants.md) and create or supersede an ADR.
