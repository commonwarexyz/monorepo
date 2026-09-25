# StateLens for Simplex: Product Requirements Document

| | |
|---|---|
| Status | Draft |
| Date | 2026-09-25 |
| Scope | `consensus/src/simplex` (voter, batcher, resolver) |
| Subproject root | `consensus/fuzz/statelens/` |
| Reference | Wong et al., "State-Aware Fuzzing of JavaScript Engines with LLM-Guided Instrumentation" (StateLens), SOSP '26, [arXiv:2609.24550](https://arxiv.org/abs/2609.24550) |

---

## 1. Summary

Build an invariant-driven, state-aware fuzzing workflow for the Simplex consensus implementation, adapted from StateLens.

- **Humans own a registry of invariants written in English.** Invariants are long-term properties of the protocol and of a correct replica. They are not tied to a particular implementation. They come from humans or from LLMs that read GitHub issues, design documents, and code comments. Every invariant records where it came from (the source).
- **A campaign starts from a fresh clone and ends when the fuzzer (libfuzzer) stops.** An LLM coding agent reads the approved invariants and the current Simplex code. It instruments the code with:
  1. assertions that check the invariants;
  2. state probes derived from the invariants;
  3. StateLens-style state probes for "semantic beacons" in the code (enums, state transitions, developer asserts and comments).

  The instrumented tree then runs the Simplex tests, followed by a `TwinsMutator`-based fuzz target built on `consensus/fuzz/core`. An invariant violation is a panic. The only result of a campaign is whether it panicked. The instrumented tree is never reused, but can be used for investigation of a crash.

---

## 2. Background

### 2.1 StateLens in one paragraph

Once a fuzzer saturates edge coverage, executions that take the same paths but reach different internal states look identical to it. StateLens has three stages:

1. **Offline analysis.** An LLM agent mines "semantic beacons" (asserts, enums, comments, bug reports, design docs). These are developer-written evidence that some state or transition matters. The agent traces where each state is set, changed, and used, and selects read-only expressions to observe, preferring before/after pairs around side-effecting transitions.
2. **Instrumentation.** It synthesizes lightweight probes that hash `(site, value_a, value_b)` into a coverage bitmap. Instrumented code is validated by compiling it and running the target's test suite.
3. **Fuzzing.** It fuzzes with edge coverage plus state coverage.

### 2.2 Where we are today

- `consensus/fuzz/simplex/src/state_cov.rs` already provides a state-coverage signal: a `sancov::Counters<65536>` table fed by FNV-hashed tokens. The tokens are computed **once per run, after the run**, from the mock reporters, metrics, and trace events. Nothing inside the voter, batcher, or resolver is observed while it runs.
- Oracles are the protocol-level checks in `consensus/fuzz/simplex/src/invariants.rs` and related modules. They also run after the run, over reporter output.
- The replica's internal state (`voter::State`, `voter::Round`, `voter::Slot`, `batcher::Round`/`VoteTracker`, `resolver::State`) is neither a feedback signal nor checked by any oracle.

### 2.3 The gap this project fills

1. **Feedback from inside the replica, at the moment a transition happens.** Examples: `CertifyState` moving `Outstanding -> Aborted` because the view advanced; `Slot` status `Verified -> Equivocated`; a latched timeout racing a late certificate.
2. **Low-level oracles.** Assertions over replica-local, actor-local, cross-actor, and temporal properties that the reporter-level checks cannot observe.

---

## 3. Goals and Non-Goals

### 3.1 Goals

- G1. A persistent, maintained, and reused registry of English invariants in `consensus/fuzz/statelens/invariants`, each with its source recorded.
- G2. A simple, agent-agnostic way to turn the specified set of source (GitHub issues, design documents, code comments from specified files, crates, modules) into invariant entries in a fixed format (as simple as possible).
- G3. A campaign workflow in which an LLM agent (`claude code` or `codex`) instruments a fresh clone with assertions, invariant probes, beacon probes, and ghost variables in the state. The workflow runs the tests first, then fuzzing.
- G4. A `TwinsMutator` fuzz target on `consensus/fuzz/core`. It adds the StateLens counter table to libFuzzer's normal edge coverage.
- G5. Byzantine replicas are never checked and never feed coverage.
- G6. The committed subproject does not affect normal builds, lints, or CI of the workspace.

### 3.2 Non-Goals

- `marshal` or any crate other than `consensus/src/simplex`.
- Modes other than `TwinsMutator` (Standard, FaultyNet, TwinsCampaign, ByzzFuzz, Mallory, Chaos).
- Integration with the existing `state_cov.rs` or happens-before feedback.
- Changing, deduplicating against, or replacing `invariants.rs`. The existing checks run exactly as today. The new invariants may overlap with them on purpose. It may be adjusted later, if we see that throughput is very low and does not satisfy fuzzing requirements.
- Automated approval, review gates, or trust scoring for invariants. Approval is entirely a human responsibility.
- Mining new invariants during a campaign.
- Switching between edge-only and state-augmented feedback (StateLens' "dual feedback"). The state counters are always on.
- Seed corpora, corpus reuse between campaigns, campaign reports, or dashboards.
- Reusing an instrumented tree after a campaign.

---

## 4. Roles

| Role | Responsibility |
|---|---|
| Invariant author (developer or security engineer) | Writes invariants by hand; reviews LLM-generated ones; sets `status`. |
| Analyst agent (`claude` or `codex`) | Phase 1: reads sources and writes invariant entries in the reference format. |
| Instrumenter agent (`claude` or `codex`) | Phase 2: reads approved invariants and the Simplex code; writes assertions, probes, and ghost state into a fresh clone. |
| Fuzz operator | Starts a campaign. Investigates the instrumented clone when it panics. |

---

## 5. Terminology

| Term | Meaning |
|---|---|
| Invariant | A property, in English, that must always hold for an honest Simplex replica or for the protocol. It is implementation-agnostic and long-lived. |
| Source kind | Where an invariant came from: `human`, `issue`, `design`, `comment`, `spec`, `paper`. |
| Semantic beacon | Developer-written evidence in the code that a state or transition matters: an enum, a `debug_assert!`, a comment, a state flag. A beacon is not a state itself. |
| Assertion | Instrumentation that panics when an approved invariant is violated. |
| State probe | Instrumentation that increments the counter for `hash(site, a, b)` in the StateLens counter table. It never changes behavior. |
| Invariant probe | A state probe derived from an invariant, e.g. the pair (precondition, conclusion). |
| Beacon probe | A state probe derived from a semantic beacon and not tied to any invariant. |
| Ghost field / ghost state | Extra fields added only so that assertions and probes can use history or cross-actor data. |
| Byzantine guard | A check, before every assertion and probe, that skips it when the running replica is compromised. |
| Campaign | Fresh clone -> instrument -> test -> fuzz, then stop. |

---

## 6. Workflow Overview

```
PHASE 1: BUILD INVARIANTS  (repeatable, any time, committed to the repo)

  source (issue | design doc | code comments | spec | paper)
        |
        v
  analyst agent (claude|codex) + prompt + reference output format
        |
        v
  consensus/fuzz/statelens/invariants/INV-xxxx.md   status: draft
        |
        v
  human edits / sets status: approved | rejected     (plus human-written entries)


PHASE 2: RUN CAMPAIGN  (fresh clone, instrument, then discard)

  fresh clone
    -> materialize runtime support + fuzz target
    -> instrumenter agent (claude|codex):
         approved invariants -> assertions + invariant probes + ghost state
         current code        -> beacon probes
    -> build
    -> run Simplex tests on instrumented code   (panic => STOP, human investigates)
    -> run TwinsMutator StateLens fuzz target   (panic => STOP, human investigates)
```

---

## 7. Requirements

### 7.1 Subproject layout

R-LAYOUT-1. Everything that lasts between campaigns lives under `consensus/fuzz/statelens/`:

```
consensus/fuzz/statelens/
  PRD.md                      this document
  SPEC.md                     technical specification (next step)
  README.md                   how to run Phase 1 and Phase 2
  invariants/                 the registry: one file per invariant
    INV-0001.md
    ...
  templates/
    invariant.md              reference format for invariant entries
  prompts/
    analyst-issue.md          Phase 1: GitHub issue -> invariants
    analyst-design.md         Phase 1: design document -> invariants
    analyst-comments.md       Phase 1: code comments of a module -> invariants
    instrument-invariants.md  Phase 2: invariants -> assertions, invariant probes, ghost state
    instrument-beacons.md     Phase 2: code -> beacon probes
  runtime/                    source templates copied into the clone during Phase 2
    statelens.rs              guard, counter table, probe/assert macros, ghost store
    target.rs                 fuzz target
  scripts/                    or justfile recipes: extract, campaign
```

R-LAYOUT-2. Files under `runtime/` are templates. No committed crate compiles them, and committed code does not include them as a module. A cargo-fuzz package (a `Cargo.toml` with `cargo-fuzz = true`) must not exist under `consensus/fuzz/statelens/` on the main branch. The existing `just fuzz` / `just build` recipes discover packages by grepping `*/Cargo.toml` for `cargo-fuzz = true`, and would otherwise pick it up in CI (G6).

R-LAYOUT-3. The only committed changes outside `consensus/fuzz/statelens/` are optional `just` recipes that call into it.

### 7.2 Invariant registry

R-REG-1. Each invariant is one Markdown file `invariants/INV-NNNN.md` with YAML front matter. IDs are never reused.

R-REG-2. Front-matter fields:

| Field | Required | Values / notes |
|---|---|---|
| `id` | yes | `INV-NNNN` |
| `title` | yes | One line. |
| `source_kind` | yes | `human`, `issue`, `design`, `comment`, `spec`, `paper`. |
| `source_ref` | yes | Issue URL, document path, or `file:line` / module path. |
| `scope` | yes | One or more of `protocol`, `replica`, `voter`, `batcher`, `resolver`, `cross-actor`. |

R-REG-3. Required body sections:
- **Statement**: the invariant in English, implementation-agnostic, stated for an honest replica unless the scope is `protocol`.
- **Rationale**: why it must hold (protocol argument or reference).
- **Evidence**: what the source says. For `issue`, describe the violating scenario.

Optional body sections:
- **Preconditions / assumptions**: e.g. "after recovery from the journal".
- **Observation hints**: non-binding pointers to where the concepts live in today's code. Phase 2 may ignore them.

R-REG-4. The Statement must not reference identifiers that exist only in the implementation. Implementation hints go in "Observation hints".

R-REG-5: EARs format should be used if possible.

R-REG-6. The reference format is `templates/invariant.md`. Example:

```markdown
---
id: INV-0001
title: No finalize and nullify in the same view
source_kind: human
source_ref: consensus/src/simplex/actors/voter/round.rs
author: <name>
scope: [replica, voter]
---

## Statement
Within a single view, an honest replica never signs both a finalize vote and a
nullify vote, including across crashes and restarts.

## Rationale
A finalize vote asserts the replica will not help skip the view; a nullify vote
asserts it will. Signing both lets a Byzantine coalition assemble conflicting
certificates for the same view.

## Evidence
Human-authored from protocol design.

## Preconditions / assumptions
Holds across journal replay: a replica that signed one before a restart must not
sign the other after it.

## Observation hints
Per-view broadcast flags in the voter round state; journal replay path.
```

### 7.3 Phase 1: build invariants

R-P1-1. Phase 1 is a single agent invocation per source (set of similar sources, e.g. set of files).
It is parameterized by the agent (`claude|codex`), the source kind, and the source reference. Example interface (final form in SPEC):
`just statelens extract agent=claude kind=issue source=<url>`.

R-P1-2. Each source kind has one prompt file in `prompts/`. Every prompt:
- casts the agent as an analyst for that source kind;
- tells it to read the source (and any code it needs for context);
- tells it to write zero or more invariant files that strictly follow `templates/invariant.md`, with the right `source_kind` / `source_ref` / `author`, and the next free IDs.

R-P1-3. Supported sources:
- GitHub issues and PRs (read via `gh`).
- Design documents (local paths or URLs).
- Code comments (a file or module path under `consensus/src/simplex`).
- Paper (page, line)
- Formal spec in Quint, TLA+, Lean (`consensus/src/simplex/replica.qnt:34`)

R-P1-4. For `issue`, the agent writes the invariant(s) that the issue's bug violated or could have violated, generalized from the specific bug.

R-P1-5. Phase 1 does no deduplication, scoring, or approval. Humans review drafts, edit them, maintain them.

### 7.4 Phase 2: campaign

R-P2-1. A campaign runs in a fresh clone of the repository at the chosen commit. It takes one parameter: the agent (`claude|codex`) from a config file or CLI. There are no other campaign parameters and no seed corpus.

R-P2-2. Steps, in order:
1. **Materialize.** Copy `runtime/statelens.rs` into `consensus/src/simplex/` and register it as a module. Create the StateLens fuzz package and target from `runtime/target.rs`. Patch the twins runner in `consensus/fuzz/core` so that it publishes the compromised set to the StateLens runtime before starting nodes and clears it after the run (section 8.4).
2. **Instrument invariants.** Run the instrumenter agent with `prompts/instrument-invariants.md` over every `approved` invariant. For each invariant it adds assertions, invariant probes, and any ghost state needed.
3. **Instrument beacons.** Run the instrumenter agent with `prompts/instrument-beacons.md` over the voter, batcher, and resolver. It adds beacon probes.
4. **Write the instrumentation plan.** A file in the clone lists each invariant -> the sites and ghost fields used, and each beacon probe -> its site and what it observes. The operator uses it when investigating. If the agent could not bind an invariant, the plan says so and gives the reason.
5. **Build.** On compile errors, the agent repairs its own instrumentation (as in StateLens section 5), without weakening assertions.
6. **Test.** Run the Simplex tests of `commonware-consensus` on the instrumented code. A failing assertion stops the campaign for human investigation.
7. **Fuzz.** Run the StateLens target until it panics or the operator stops it.

R-P2-3. The only output of a campaign is whether it panicked, together with the standard artifacts described in 7.8.

### 7.5 Instrumentation rules

R-INS-1. **No code removal.** The agent may add code, fields, ghost state, helper functions, module-level statics, and hooks. It must not delete or change existing logic. The only intended behavior change is a panic when an invariant is violated.
When the agent adds the code it must add a comment or use a style that would signal that this code is instrumentation and was added.

R-INS-2. **Byzantine guard.** Every assertion and every probe is guarded by `!statelens::is_byzantine(me)`, where `me` is the replica's own participant index (`scheme.me()`, already available in the voter, batcher, and resolver). `is_byzantine` reads the compromised set published by the harness (section 8.4). A replica with no participant index (`me() == None`) is treated as honest.

R-INS-3. **Determinism.** Assertions, probes, and ghost updates must not:
- `await`;
- spawn tasks;
- touch the runtime context, RNG, clock, network, storage, or metrics;
- change the order or content of messages;
- consume values the original code later relies on.

This keeps a crash reproducible from the same input on the same instrumented tree.

R-INS-4. **Assertion form.** Assertions use a StateLens macro that panics with a message starting `[statelens][INV-NNNN]` plus the invariant title and a short dump of the values involved. One invariant may produce several assertion sites.

R-INS-5. **Ghost state.**
- Ghost fields may be added to existing structs (e.g. `voter::State`, `voter::Round`, `batcher::Round`, `resolver::State`).
- Cross-actor and cross-restart invariants may use a per-replica ghost store in `statelens.rs`, keyed by participant index and reset per fuzz run. This is safe because the deterministic runtime is single-threaded.
- Cross-actor assertions must allow for mailbox delivery lag. They must hold under any delivery order the implementation allows, not only when actors are in step.

R-INS-6. **Cost.** Probes and assertions are O(1) or bounded by the number of tracked views. No unbounded scans on hot paths.

### 7.6 Feedback (StateLens adaptation)

R-FB-1. **Counter table.** `statelens.rs` owns a `sancov::Counters<65536>` table. It is registered with libFuzzer once, under `cfg(fuzzing)`, and zeroed at the start of every fuzz run. The mechanism is the same as `consensus/fuzz/simplex/src/state_cov.rs`, but the table is separate. `state_cov` and happens-before feedback are not enabled for the StateLens target.

R-FB-2. **Probe primitive.** `probe(site, a, b)` increments the counter at `hash(site, a, b) mod N`, saturating. `site` is a constant string or ID unique within the instrumented tree. `a` and `b` are small discrete values (`u32`).

R-FB-3. **Invariant probes.** For each assertion of the form "if A then B", the agent also emits a probe over `(A, B)` at the same site, and, where meaningful, a bucketed margin to violation for numeric invariants. Both reward reaching an invariant's precondition, not only the code around it.

R-FB-4. **Beacon probes.** The agent mines semantic beacons in the voter, batcher, and resolver:
- state enums, e.g. `CertifyState`, `slot::Status`, `TimeoutReason`, `Activity` kinds;
- per-view flags and `Option` certificate slots;
- `debug_assert!`s and comments that describe fragile states.

It emits probes that record `(pre, post)` pairs around transitions. Priority goes to:
- transitions caused by side effects or asynchrony (StateLens O2): a view change while certification is outstanding, a timeout racing a certificate, equivocation detected after verification, journal replay;
- conditions set in one actor and used in another (StateLens O1): voter <-> batcher <-> resolver through mailboxes.

R-FB-5. **Discretization.**
- Probes never hash raw views, digests, keys, payloads, or timestamps.
- Views are recorded relative to something (e.g. `view - last_finalized`, `view - current_view`) and bucketed (e.g. 0, 1, 2, 3-4, 5-8, 9+).
- Counts are bucketed the same way.
- Probes do not include the replica index, so symmetric replicas share features.

R-FB-6. **No mode switching.** libFuzzer's edge coverage stays on. The StateLens counters only add features. There is no plateau-based switching.

### 7.7 Oracles

R-OR-1. **Oracles** are:
1. the assertions of approved invariants (7.5);
2. the existing post-run checks in `invariants.rs` and related modules, run exactly as the `TwinsMutator` harness runs them today;
3. any other panic in the process.

R-OR-2. Every oracle failure is a panic. The panic propagates to libFuzzer as a crash. This already happens: the deterministic runtime defaults to `catch_panics: false`, and `fuzz()` does `catch_unwind` then `resume_unwind`.

R-OR-3. An assertion panic in step 6 (tests) or step 7 (fuzz) stops the campaign. A human decides whether it is an implementation bug, a wrong invariant, or a wrong binding. Fixes to wrong invariants are made in the registry by hand.

### 7.8 Crash artifacts

R-ART-1. Reuse the existing consensus fuzz artifacts unchanged:
- libFuzzer writes the crashing input to the target's `artifacts/` directory;
- `just run <target> <crash_file>` replays it;
- `CONSENSUS_FUZZ_LOG=1` prints the decoded `FuzzInput` (`print_fuzz_input`) and the existing logs;
- the panic message carries the `INV-NNNN` ID.

R-ART-2. The operator investigates inside the instrumented clone (including the instrumentation plan from R-P2-2 step 4) before throwing it away. No extra bundle format is added.

### 7.9 Agent abstraction

R-AG-1. The agent is a parameter (`claude|codex`). Prompts are plain Markdown and do not depend on either agent. A small script maps the parameter to the non-interactive invocation of each CLI.

R-AG-2. Phase 2 agents may use any tools available in their CLI (search, LSP, build, test) to trace call graphs and data flow.

### 7.10 Non-functional

R-NF-1. Correctness first: no probe or ghost update may change protocol behavior (R-INS-1, R-INS-3).

R-NF-2. Determinism: an input that crashes on an instrumented tree crashes the same way when replayed on that tree.

R-NF-3. Overhead: measure exec/s against the same target with plain `CodeCoverage`. There is no hard limit, but a slowdown above 2x should be reported as a problem with the instrumentation.

R-NF-4. The committed subproject does not change workspace build, lint, stability checks, tests, or CI (G6, R-LAYOUT-2).

R-NF-5. Committed files use plain ASCII.

---

## 8. Fuzz Harness: High-Level Design

### 8.1 Shape

```
libFuzzer
  |  bytes -> FuzzInput (existing Arbitrary impl in consensus/fuzz/core)
  v
statelens fuzz target  (materialized from runtime/target.rs)
  |  statelens::reset()            zero counters, clear ghost store
  |  fuzz::<SimplexCertificateMock, TwinsMutator, CodeCoverage>(input)
  v
consensus/fuzz/simplex::fuzz -> run_with_twins_mutator
  v
consensus/fuzz/core::run_twins_with_backend
  |  sample twins scenario -> compromised set
  |  [hook] statelens::set_compromised(compromised)        (patched in Phase 2)
  |
  |-- compromised participant i:
  |     primary   = real Simplex engine  (instrumented, guard => skipped)
  |     secondary = Disrupter            (no Simplex actor code)
  |-- honest participants:
  |     real Simplex engines: voter / batcher / resolver
  |       assertions  -> panic on violation
  |       probes      -> StateLens counter table
  |       ghost state -> per-struct fields + per-replica ghost store
  v
existing post-run oracles (invariants.rs, vote/safety checks)  -> panic on violation
  v
[hook] statelens::clear_compromised()
libFuzzer reads edge coverage + StateLens counters -> keep input if new features
```

### 8.2 Why `TwinsMutator`

Twins is the best available way to put an honest replica into states that only Byzantine peers can cause: equivocating proposals and votes, split network views, conflicting certificates. In `TwinsMutator` a compromised participant runs a legitimate primary engine plus a `Disrupter` secondary that mutates content according to `input.strategy`. Honest replicas therefore face both network splits and content mutations, which is where replica-local and cross-actor invariants are most likely to break.

### 8.3 How StateLens maps onto Simplex

| StateLens (JS engines) | This project (Simplex) |
|---|---|
| Engine subsystems (IC, JIT, GC) | Actors: voter, batcher, resolver |
| O1: conditions cross implementation boundaries | Conditions set in one actor and used in another through mailboxes; conditions that must survive journal replay |
| O2: side effects invalidate assumptions | Asynchrony: view advances while certification is outstanding; timeouts race certificates; equivocation detected after verification |
| O3: developer artifacts reveal states | Enums (`CertifyState`, `slot::Status`, `TimeoutReason`), per-view flags, `debug_assert!`s, comments, GitHub issues, design docs |
| Knowledge base + retrieval | Replaced by (a) the invariant registry, (b) the agent reading the code directly |
| Probes: `(site, a, b)` into a shared-memory bitmap | Same, into an in-process `sancov` counter table (libFuzzer is in-process, so no IPC) |
| Oracle: crashes / ASan | Invariant assertions plus existing protocol checks, all as panics |
| Re-instrument each engine release | Instrument a fresh clone for each campaign |
| Dual feedback with plateau switch | Always-on state counters on top of edge coverage |
| Every thread and process is instrumented | Only honest replicas are observed (Byzantine guard) |

### 8.4 Byzantine guard plumbing

`commonware-consensus` cannot depend on the fuzz crates, so the guard state lives in `consensus/src/simplex/statelens.rs`, which is materialized in the clone. The twins runner (`consensus/fuzz/core/src/lib.rs`, where `compromised` is built from the sampled case) is patched in the clone to:
- call `statelens::set_compromised(&compromised)` before any engine starts;
- call `statelens::clear_compromised()` after the run.

Instrumented code calls `statelens::is_byzantine(me)` with `me` from `scheme.me()`. The guard is keyed on participant identity, so it covers the compromised primary engine. The `Disrupter` secondary runs no Simplex actor code.

### 8.5 Running continuously

Every campaign starts from scratch:
- The registry grows between campaigns through Phase 1 and human review.
- Beacon probes are mined again from the current code each time, so they follow code changes without maintenance.
- Invariants are bound to the code again each time, so a refactor does not invalidate the registry. Only invariants whose concepts disappear entirely stop binding, and the instrumentation plan reports them.
- No corpus or instrumentation carries over between campaigns.

---

## 9. Acceptance Criteria

AC-1. `templates/invariant.md` and the three Phase 1 prompts exist. Running Phase 1 on a real GitHub issue with each agent produces at least one file that follows R-REG-1 to R-REG-4 with `status: draft`.

AC-2. On `main`, `just lint`, `just test -p commonware-consensus`, and the CI fuzz matrix behave exactly as before this project (G6).

AC-3. A campaign on a fresh clone with at least one approved invariant:
- materializes the runtime and target;
- instruments the code;
- writes the instrumentation plan;
- builds;
- runs the Simplex tests;
- starts the fuzz target.

AC-4. On the same commit, the StateLens target shows more libFuzzer features than the same target with plain `CodeCoverage`, which shows the probes fire.

AC-5. **Positive control.** A deliberately false approved invariant (e.g. "an honest replica never observes a nullification") makes the campaign panic with its `INV-` ID. It panics during the tests or within a short fuzz run.

AC-6. **Guard control.** An assertion that only a compromised replica can violate never fires over a short `TwinsMutator` run. The same assertion fires if the guard is removed.

AC-7. **Determinism control.** Replaying a crashing input with `just run` on the same instrumented tree reproduces the same panic.

---

## 10. Risks and Open Points

| Risk | Mitigation |
|---|---|
| LLM-written invariants are wrong under Byzantine conditions and cause false alarms. | Approval by humans; tests run before fuzzing; triage by humans; wrong invariants are fixed in the registry. |
| Bindings change between campaigns, because agent output is not deterministic. | Accepted by design: every campaign is fresh. The instrumentation plan documents each binding. |
| Probes change scheduling or behavior. | R-INS-1 and R-INS-3; AC-7. |
| Too many probe features (corpus bloat) or hash collisions. | Discretization rules (R-FB-5); 64K table; exclude replica index. |
| Cross-actor assertions fire only because of mailbox lag. | R-INS-5: assertions must allow for any legal delivery order. |
| StateLens evidence comes from memory-safety bugs in C++ engines; payoff on Rust logic bugs is unproven. | AC-4/AC-5 establish basic function. Measuring bug-finding (e.g. on planted bugs) is left for later. |
| libFuzzer stops at the first crash. | Intended: "panic => human investigates". |

---

## 11. Handoff to SPEC

The SPEC should pin down:
1. `templates/invariant.md` verbatim, and the three analyst prompts.
2. The `statelens.rs` API:
   - `reset`, `set_compromised`, `clear_compromised`, `is_byzantine`;
   - the `probe` / assertion macros;
   - the ghost store;
   - the hash and discretization helpers.
3. The fuzz target and package manifest template, and how Phase 2 registers the package so `just run` finds it.
4. The exact patch point in `run_twins_with_backend`.
5. The two instrumenter prompts, including the rules in 7.5 and 7.6 and the format of the instrumentation plan.
6. The `extract` and `campaign` scripts or `just` recipes, including the non-interactive `claude` / `codex` invocations.
7. The list of Simplex test commands used in step 6.
