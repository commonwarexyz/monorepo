# ByzzFuzz Specs Index

## Navigation by Task

| Task | Read First | Then Read |
| ---- | ---------- | --------- |
| Change `(c, d, r)` sampling, receiver sampling, or fault scopes | [Fault Scheduling](domains/fault-scheduling.md) | [Fault Flow](architecture/fault-flow.md), [Process Fault Model ADR](decisions/001-process-fault-model.md) |
| Change outbound drop or intercept behavior | [Network Interception](domains/network-interception/README.md) | [Round Tracking](domains/network-interception/round-tracking.md), [Forwarder/Injector Contract](contracts/forwarder-injector.md), [Process Fault Model ADR](decisions/001-process-fault-model.md) |
| Change vote mutation semantics | [Process Injection](domains/process-injection/README.md) | [Mutator](domains/process-injection/mutator.md), [Process Fault Model ADR](decisions/001-process-fault-model.md), [Small-Scope Strategy ADR](decisions/004-byzzfuzz-local-small-scope-strategy.md) |
| Change post-GST liveness behavior | [Runner Liveness](domains/runner-liveness.md) | [Fault Flow](architecture/fault-flow.md), [Post-GST Catch-Up ADR](decisions/005-post-gst-required-container-catch-up.md), [Superseded Post-GST Liveness ADR](decisions/003-post-gst-liveness-check.md) |
| Change panic logging or decision trace output | [Observability](domains/observability.md) | [ByzzFuzz/Harness Contract](contracts/byzzfuzz-harness.md) |
| Wire a new fuzz target into ByzzFuzz mode | [ByzzFuzz/Harness Contract](contracts/byzzfuzz-harness.md) | [Layers](architecture/layers.md) |
| Check or update invariants | [Invariants](invariants/invariants.md) | Relevant domain or architecture spec, then affected contracts |
| Review architecture before a broad refactor | [Layers](architecture/layers.md) | [Fault Flow](architecture/fault-flow.md), all contracts |

## Dependency Graph

```
fuzz_targets/*_byzzfuzz.rs
    |
    v
consensus/fuzz/src/lib.rs
    |   Mode::Byzzfuzz -> byzzfuzz::run
    v
byzzfuzz::runner
    |-- samples schedules via fault-scheduling
    |-- wires split forwarders and tracking receivers
    |-- spawns honest Simplex validators
    |-- spawns process-fault injector
    |
    +--> network-interception --Intercept--> process-injection
    |             |                              |
    |             +--> observed-state pool <-----+
    |
    +--> invariants catalog
    |
    +--> invariants and reporter monitors
```

## Directory Listing

### Foundation

- [META](META.md) - spec formats, naming, and update rules.
- [Workflow](WORKFLOW.md) - project-specific usage workflow.

### Architecture

- [Fault Flow](architecture/fault-flow.md) - end-to-end phase and fault routing model.
- [Layers](architecture/layers.md) - dependency direction and module responsibilities.

### Domains

- [Fault Scheduling](domains/fault-scheduling.md) - fault data, `(c, d, r)` schedule generation, and scope sampling.
- [Network Interception](domains/network-interception/README.md) - outbound filtering, process intercepts, and observed-value capture.
- [Round Tracking](domains/network-interception/round-tracking.md) - `rnd(m)` tracking through outbound and inbound messages.
- [Observability](domains/observability.md) - bounded decision log and panic-hook integration.
- [Process Injection](domains/process-injection/README.md) - async injector and vote replacement behavior.
- [Mutator](domains/process-injection/mutator.md) - observed-value-first proposal and nullify mutations.
- [Runner Liveness](domains/runner-liveness.md) - ByzzFuzz run setup and GST transition.

### Invariants

- [Invariants](invariants/invariants.md) - central catalog of all ByzzFuzz invariants.

### Contracts

- [ByzzFuzz/Harness](contracts/byzzfuzz-harness.md) - boundary with `consensus/fuzz/src/lib.rs` and fuzz targets.
- [Forwarder/Injector](contracts/forwarder-injector.md) - sync forwarder to async injector handoff.

### Decisions

- [ADR Template](decisions/_template.md) - template for new decision records.
- [ADR-001: Process Fault Model](decisions/001-process-fault-model.md) - fixed byzantine identity, process actions, message scopes, and forwarder/injector handoff.
- [ADR-003: Post-GST Liveness Check](decisions/003-post-gst-liveness-check.md) - superseded liveness check after fault phase.
- [ADR-004: ByzzFuzz-Local Small-Scope Strategy](decisions/004-byzzfuzz-local-small-scope-strategy.md) - observed-value replay with local nearby edits for vote mutation.
- [ADR-005: Post-GST Required-Container Catch-Up](decisions/005-post-gst-required-container-catch-up.md) - current liveness targets after GST.
