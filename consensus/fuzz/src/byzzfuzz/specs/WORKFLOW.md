# Specification Workflow

This guide defines how to use and maintain the ByzzFuzz specs.

## 1. General Philosophy

Specifications are the intended behavior for the ByzzFuzz harness. They are maintained manually and compared against code when the implementation changes.

- A discrepancy between a spec and code is a bug in one of them.
- Specs are optimized for agents: concise, structured, and cross-linked.
- Domains describe behavior, not file layout.
- Contracts describe boundaries where changes have higher coupling risk.

## 2. Getting Started: Navigation

### Step 1: INDEX.md

Open `consensus/fuzz/src/byzzfuzz/specs/INDEX.md` and use the task table to find the relevant document.

### Step 2: Domain README

For multi-file domains, read the `README.md` first. It contains purpose, key files, core types, flow, configuration, extension points, and links to related invariants.

### Step 3: Detail Files and Contracts

Read detail files when changing a specific component. Read contracts when touching wiring between the harness, forwarders, injectors, or upstream Simplex components.

## 3. Document Formats

Every spec follows one of the formats in `META.md`:

1. **Domain README** - `domains/*/README.md` or `domains/*.md`
2. **Domain Detail** - `domains/*/<component>.md`
3. **Contract** - `contracts/*.md`
4. **Architecture** - `architecture/*.md`
5. **ADR** - `decisions/NNN-slug.md`
6. **Invariant Catalog** - `invariants/invariants.md`

## 4. Cross-References

Rules for links:

```markdown
[Runner Liveness](domains/runner-liveness.md)
[Phase Model](architecture/fault-flow.md#phase-model)
`consensus/fuzz/src/byzzfuzz/runner.rs`
```

Links between specs are relative from `consensus/fuzz/src/byzzfuzz/specs/`. Source paths are repo-root paths in backticks.

## 5. Update Protocol

### When to Update

- Update specs after changing documented behavior.
- Update contracts after changing boundary interfaces or wiring.
- Check affected invariants after changing code or specs; every applicable invariant must still hold.
- Update `invariants/invariants.md` when an invariant is added, removed, or changed.
- Update `INDEX.md` after adding or removing a spec.
- Create a new ADR after a new architectural decision.

### How to Update

1. Read the current spec fully.
2. Preserve the section order defined in `META.md`.
3. Keep source paths as repo-root paths.
4. Read the affected invariant group in `invariants/invariants.md`.
5. Verify the invariants still hold after the change.
6. Keep invariants affirmative and centralized in `invariants/invariants.md`.
7. Keep accepted ADRs immutable. Supersede them with a new ADR.

### Validation Checklist

- [ ] All required sections are present.
- [ ] Cross-references resolve to existing spec files.
- [ ] Key Files paths exist in the repo.
- [ ] Affected invariants have been checked and still hold.
- [ ] Invariant statements live in `invariants/invariants.md` and are affirmative.
- [ ] `INDEX.md` lists every spec file.

## 6. Workflow for Typical Tasks

### Change fault schedule sampling

1. Read [Fault Scheduling](domains/fault-scheduling.md).
2. Read [Fault Flow](architecture/fault-flow.md) if the change affects phase behavior.
3. Read [Invariants](invariants/invariants.md#fault-scheduling).
4. Update sampling code and any tests.
5. Verify the fault-scheduling invariants still hold.
6. Update the fault-scheduling spec and `INDEX.md` if files move.

### Change forwarder filtering or interception

1. Read [Network Interception](domains/network-interception/README.md).
2. Read [Round Tracking](domains/network-interception/round-tracking.md).
3. Read [Forwarder/Injector Contract](contracts/forwarder-injector.md).
4. Read [Invariants](invariants/invariants.md#network-interception) and [Round Tracking Invariants](invariants/invariants.md#round-tracking).
5. Preserve the sync `SplitForwarder` boundary and the async injector handoff unless a new ADR supersedes it.
6. Verify the affected invariants still hold.

### Change vote mutation behavior

1. Read [Process Injection](domains/process-injection/README.md).
2. Read [Mutator](domains/process-injection/mutator.md).
3. Read [ADR-002](decisions/002-semantically-mutate-votes-only.md).
4. Read [Invariants](invariants/invariants.md#process-injection) and [Mutator Invariants](invariants/invariants.md#mutator).
5. Confirm certificate and resolver behavior remains omit-only or create a superseding ADR.
6. Verify the affected invariants still hold.

### Change liveness or GST behavior

1. Read [Runner Liveness](domains/runner-liveness.md).
2. Read [ADR-005](decisions/005-post-gst-required-container-catch-up.md).
3. Read [Invariants](invariants/invariants.md#runner-liveness).
4. Confirm the change still separates network partitions from Byzantine process faults at GST.
5. Verify the runner-liveness invariants still hold.

### Add a new ByzzFuzz fuzz target

1. Read [ByzzFuzz/Harness Contract](contracts/byzzfuzz-harness.md).
2. Read [Invariants](invariants/invariants.md#layers).
3. Add a target that calls `fuzz::<P, Byzzfuzz>(input)`.
4. Confirm `Byzzfuzz` mode is still installed through `Mode::Byzzfuzz`.

## 7. Working with ADRs

### Creating a New ADR

1. Determine the next number in `decisions/`.
2. Copy `decisions/_template.md`.
3. Fill every section.
4. Add it to `INDEX.md`.

### Superseding a Decision

1. Create a new ADR with the updated decision.
2. Change the old ADR status to `Superseded by [NNN](./NNN-slug.md)`.
3. Do not otherwise edit the old accepted ADR.

## 8. Content Formatting Principles

### Invariants

Invariant statements live in [Invariants](invariants/invariants.md). Use affirmative statements there, and verify that affected invariants hold after every code or spec change. Domain and architecture specs should link to the relevant invariant group instead of carrying invariant bullets locally.

### Key Files

Use repo-root paths:

```markdown
- `consensus/fuzz/src/byzzfuzz/runner.rs` - ByzzFuzz run orchestration.
```

### ASCII Diagrams

Use ASCII diagrams for phase and dependency flow. Do not use Mermaid.

## 9. Anti-Patterns

| Anti-pattern | Why it is bad | Use Instead |
| ------------ | ------------- | ----------- |
| Mirroring every Rust file as a spec | Hides conceptual boundaries | Domain specs by behavior |
| Updating code but not specs | Leaves agents with stale invariants | Update affected specs and check `invariants/invariants.md` in the same change |
| Leaving invariant statements in domain or architecture specs | Splits the source of truth | Put invariant statements in `invariants/invariants.md` and link to them |
| Editing accepted ADR content | Loses decision history | Supersede with a new ADR |
| Documenting guessed behavior | Creates false confidence | Read source and mark open questions only when necessary |

## 10. Quick Start

1. Need to learn behavior: `INDEX.md` -> task table -> domain spec.
2. Need to change code: domain spec -> invariants -> contract -> implementation -> spec update.
3. Need a new decision: create ADR -> update `INDEX.md`.
4. Need format rules: read `META.md`.
