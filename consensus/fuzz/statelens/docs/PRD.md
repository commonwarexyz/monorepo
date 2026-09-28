# StateLens for Simplex: Product Requirements Document

| | |
|---|---|
| Scope | `consensus/src/simplex` (voter, batcher, resolver) and `consensus/src/marshal` (core, standard, coding) |
| Subproject root | `consensus/fuzz/statelens/` |
| Specification | [SPEC.md](../docs/SPEC.md) |
| Reference | Wong et al., "State-Aware Fuzzing of JavaScript Engines with LLM-Guided Instrumentation" (StateLens), SOSP '26, [arXiv:2609.24550](https://arxiv.org/abs/2609.24550) |

---

## 1. Summary

Build an invariant-driven, state-aware fuzzing workflow for the Simplex consensus implementation, adapted from StateLens. By design, the implementation has two subsystems, and StateLens covers both:
- **Simplex** (`consensus/src/simplex`): the consensus protocol, with its voter, batcher and resolver actors (chapter 8);
- **marshal** (`consensus/src/marshal`): the ordered delivery of finalized blocks to the application (chapter 9).

The workflow has three phases:

1. **Discover invariants.** Humans own a registry of invariants written in English, one per subsystem. Invariants are long-term properties of the protocol and of a correct replica. They are not tied to a particular implementation. They come from humans or from LLMs that read GitHub issues, design documents, code comments, formal specifications, and papers. Every invariant records where it came from (the source). Every file in a registry is active: the next campaign that covers its subsystem uses it.
2. **Instrument the code and generate fuzz targets.** A campaign runs in place in the operator's fresh clone of the repository, where StateLens lives; StateLens does not make another clone. The campaign's profile, `simplex` or `marshal`, selects the subsystems it covers. An LLM coding agent reads the invariants and the current code, and instruments the code with:
   1. assertions that check the invariants;
   2. state probes derived from the invariants;
   3. StateLens-style state probes for "semantic beacons" in the code (enums, state transitions, developer asserts and comments).

   The campaign then builds the StateLens fuzz targets and runs the engine-level tests on the instrumented tree:
   - for Simplex, a `TwinsMutator`-based target built on `consensus/fuzz/core`;
   - for marshal, a StateLens variant of every existing marshal fuzz target.

   The campaign ends when the targets are built and tested, and prints the commands that run them.
3. **Run fuzz targets.** The operator runs the targets in the instrumented checkout until one panics or the operator stops it. An invariant violation is a panic. The instrumented tree is never reused for another campaign, but is used for fuzzing and for the investigation of a crash.

---

## 2. Background

### 2.1 StateLens in one paragraph

Once a fuzzer saturates edge coverage, executions that take the same paths but reach different internal states look identical to it. StateLens has three stages:

1. **Offline analysis.** An LLM agent mines "semantic beacons" (asserts, enums, comments, bug reports, design docs). These are developer-written evidence that some state or transition matters. The agent traces where each state is set, changed, and used, and selects read-only expressions to observe, preferring before/after pairs around side-effecting transitions.
2. **Instrumentation.** It synthesizes lightweight probes that hash `(site, value_a, value_b)` into a coverage bitmap. Instrumented code is validated by compiling it and running the target's test suite.
3. **Fuzzing.** It fuzzes with edge coverage plus state coverage.

### 2.2 The gap this project fills

1. **Feedback from inside the replica, at the moment a transition happens.**
2. **Low-level oracles.** Assertions over replica-local, actor-local, cross-actor, and temporal properties that the existing checks of the fuzz harnesses cannot observe.

Sections 8.2 and 9.2 describe where each subsystem stands today, with examples.

---

## 3. Goals and Non-Goals

### 3.1 Goals

- G1. Persistent, maintained, and reused registries of English invariants in `consensus/fuzz/statelens/invariants/`, one per subsystem (`simplex`, `marshal`), each invariant with its source recorded and an ID unique across registries.
- G2. A simple, agent-agnostic way to turn the specified set of sources (GitHub issues, design documents, code comments from specified files, crates, modules, formal specifications, papers) into invariant entries in a fixed format (as simple as possible), in the registry of the subsystem the operator names.
- G3. A campaign workflow, with one profile per subsystem, in which an LLM agent (`claude code` or `codex`) instruments a fresh clone with assertions, invariant probes, beacon probes, and ghost variables in the state. The workflow builds the StateLens fuzz targets and runs the tests (Phase 2); the operator then runs the targets (Phase 3).
- G4. A `TwinsMutator` fuzz target, `simplex_statelens`, added during a campaign to the existing `consensus/fuzz/simplex` package and running on `consensus/fuzz/core`. It uses only the `cert_mock` certificate scheme (R-P2-4) and adds the StateLens counter table to libFuzzer's normal edge coverage (chapter 8).
- G5. Byzantine replicas are never checked and never feed coverage, in either subsystem.
- G6. The committed subproject does not affect normal builds, lints, or CI of the workspace.
- G7. Fuzz marshal. The `marshal` profile binds the Simplex and marshal registries, instruments both subsystems, and builds a StateLens variant of every existing marshal fuzz target, using only the `cert_mock` scheme (chapter 9).
- G8. One runtime module serves both subsystems: one compromised set, one counter table and one ghost store per run.

### 3.2 Non-Goals

General:
- Crates other than `consensus/src/simplex` and `consensus/src/marshal`.
- Cross-subsystem invariants: invariants that relate the state of Simplex and marshal in one check, and a registry for them. Every invariant is bound in the code of its own subsystem.
- Real signature schemes (ed25519, BLS12-381, secp256r1) in StateLens fuzz targets; they use only the `cert_mock` scheme (R-P2-4).
- Changing, deduplicating against, or replacing the existing checks of the fuzz harnesses (`invariants.rs` and related modules of the Simplex and marshal fuzz packages). The existing checks run exactly as today. The new invariants may overlap with them on purpose. It may be adjusted later, if we see that throughput is very low and does not satisfy fuzzing requirements.
- Automated approval, review gates, or trust scoring for invariants. Approval is entirely a human responsibility, and invariant files carry no approval status.
- Mining new invariants during a campaign.
- Switching between edge-only and state-augmented feedback (StateLens' "dual feedback"). The state counters are always on.
- Seed corpora, corpus reuse between campaigns, campaign reports beyond the result summary, or dashboards.
- Reusing an instrumented tree for another campaign.
- Automating Phase 3. A campaign builds the StateLens fuzz targets but does not run them; the operator runs them with the existing `just run` recipe and chooses which targets, for how long, and with which libFuzzer arguments.

Simplex:
- Fuzz modes other than `TwinsMutator` (Standard, FaultyNet, TwinsCampaign, ByzzFuzz, Mallory, Chaos).
- Integration with the existing `state_cov.rs` or happens-before feedback.

Marshal:
- Fuzz targets other than the existing ones, or changes to their harnesses beyond the edits a campaign makes.
- Coding schemes other than the one the marshal fuzz targets use (Reed-Solomon).
- Following the planned move of marshal under `consensus/src/simplex/` (draft PR #4994) before it lands.

---

## 4. Roles

| Role | Responsibility |
|---|---|
| Invariant author (developer or security engineer) | Writes invariants by hand. Reviews, edits, or deletes LLM-generated ones before the next campaign, because every file in a registry is used. |
| Analyst agent (`claude` or `codex`) | Phase 1: reads sources and writes invariant entries in the reference format. |
| Instrumenter agent (`claude` or `codex`) | Phase 2: reads the invariants of the profile's registries and the code of its subsystems; writes assertions, probes, and ghost state into the checkout. |
| Fuzz operator | Clones the repository on a dedicated machine or container and starts a campaign in that clone (Phase 2), then runs the StateLens fuzz targets the campaign built (Phase 3). Investigates the instrumented checkout when something panics, then discards it. |

---

## 5. Terminology

| Term | Meaning |
|---|---|
| Subsystem | One of the two parts of the implementation that StateLens covers: `simplex` (`consensus/src/simplex`) or `marshal` (`consensus/src/marshal`). |
| Component | A part of a subsystem that gets its own beacon probes: the voter, batcher and resolver actors in Simplex; the core, standard and coding components in marshal. |
| Invariant | A property, in English, that must always hold for an honest replica or for the protocol. It is implementation-agnostic and long-lived, and it constrains one subsystem. |
| Registry | A directory `consensus/fuzz/statelens/invariants/<subsystem>/`. Every file in it is active for every profile that binds the subsystem. |
| Source kind | Where an invariant came from: `human`, `issue`, `design`, `comment`, `spec`, `paper`. |
| EARS | Easy Approach to Requirements Syntax: the sentence patterns (ubiquitous, state-driven, event-driven, unwanted behavior, complex) used for invariant statements. |
| Semantic beacon | Developer-written evidence in the code that a state or transition matters: an enum, a `debug_assert!`, a comment, a state flag. A beacon is not a state itself. |
| Assertion | Instrumentation (`sl_assert!` or `sl_implies!`) that panics when an invariant is violated. |
| State probe | Instrumentation that marks the counter for `hash(site, a, b)` in the StateLens counter table as seen. It never changes behavior. |
| Invariant probe | A state probe derived from an invariant, e.g. the pair (precondition, conclusion) that `sl_implies!` records. |
| Beacon probe | A state probe (`sl_probe!`) derived from a semantic beacon and not tied to any invariant. |
| Ghost state | Extra fields added only so that assertions and probes can use history or data from other actors or replicas: in existing structs, per replica (`Ghost`), or shared by all honest replicas (`Global`). |
| Byzantine guard | The check, built into every StateLens macro and ghost-state accessor, that skips replicas the harness marked as compromised. |
| False invariant | A deliberately false invariant in `false-invariants/<subsystem>/`, with a `FALSE-` ID. A working campaign must panic on it; it is used only to test the workflow itself. |
| Byzantine mode | The `STATELENS_BYZANTINE` switch: what instrumentation does when a compromised replica reaches an instrumented site. `skip` (default) is the Byzantine guard; `check` checks the replica like an honest one; `panic` panics, to test the guard. |
| Profile | What a campaign binds, instruments, tests and builds: `simplex` (the Simplex subsystem, chapter 8) or `marshal` (both subsystems, chapter 9). |
| StateLens variant | A fuzz target that a `marshal` campaign creates. It runs the harness of an existing marshal fuzz target between `statelens::reset()` and `statelens::clear_compromised()`, and is named `<target>_statelens`. |
| Campaign | Phase 2 for one profile: materialize -> instrument -> build -> test, in place in a fresh clone of the repository, then stop. Phase 3 runs the targets it built. |
| Test gate | The engine-level tests of the profile's subsystems, which a campaign runs on the instrumented tree before it hands the targets over. |

---

## 6. Workflow Overview

### 6.1 Phases

```
PHASE 1: DISCOVER INVARIANTS  (repeatable, any time, committed to the repo)

  source (issue | design doc | code comments | spec | paper)
        |
        v
  analyst agent (claude|codex) + prompt + reference output format
        |
        v
  consensus/fuzz/statelens/invariants/<subsystem>/INV-xxxx.md    (active immediately)
        |
        v
  human reviews: edits, deletes, or adds entries by hand


PHASE 2: INSTRUMENT THE CODE AND GENERATE FUZZ TARGETS
         (a campaign, in place in a fresh clone of the repo)

  operator: git clone <repo>; cd consensus/fuzz/statelens; just fuzz [--profile simplex|marshal]
    -> materialize runtime support, fuzz targets, runner hooks
    -> instrumenter agent (claude|codex):
         registry invariants -> assertions + invariant probes + ghost state
         current code        -> beacon probes (Simplex actors; marshal components)
    -> build the StateLens fuzz targets (up to 3 agent repair attempts)
    -> run the engine-level tests         (panic => STOP, human investigates)
    -> print the commands that run the StateLens fuzz targets


PHASE 3: RUN FUZZ TARGETS  (operator, in the instrumented clone; discard it afterwards)

  operator: cd consensus/fuzz; just run <target> -- -fork=N
    -> libFuzzer runs until it panics or is stopped   (panic => human investigates)
```

### 6.2 Running continuously

Every campaign starts from scratch:
- The registry grows between campaigns through Phase 1 and human review. The registry in the checkout is used, including uncommitted edits.
- Each campaign needs a fresh clone, because it instruments the checkout in place.
- Beacon probes are mined again from the current code each time, so they follow code changes without maintenance.
- Invariants are bound to the code again each time, so a refactor does not invalidate the registry. Only invariants whose concepts disappear entirely stop binding, and the instrumentation plan reports them.
- No corpus or instrumentation carries over between campaigns.

---

## 7. Requirements

### 7.1 Subproject layout

R-LAYOUT-1. Everything that lasts between campaigns lives under `consensus/fuzz/statelens/`:

```
consensus/fuzz/statelens/
  docs/
    PRD.md                    this document
    SPEC.md                   technical specification
  README.md                   how to run the three phases
  config.env                  defaults: agent, models, toolchains
  justfile                    recipes: extract, fuzz, check-invariants
  .gitignore                  ignores the generated campaign/ and extract/ directories
  invariants/                 the registries: one file per invariant, all active
    simplex/
      INV-0001.md
      ...
    marshal/
      ...
  false-invariants/           deliberately false invariants; a working campaign must panic on them
    simplex/
      FALSE-0001.md
    marshal/
      FALSE-0002.md
  templates/
    invariant.md              reference format for invariant entries
  prompts/
    analyst.md                Phase 1: shared rules and output format
    analyst-issue.md          Phase 1: GitHub issue or PR -> invariants
    analyst-design.md         Phase 1: design document -> invariants
    analyst-comment.md        Phase 1: code comments of files or modules -> invariants
    analyst-spec.md           Phase 1: formal specification -> invariants
    analyst-paper.md          Phase 1: paper -> invariants
    instrument.md             Phase 2: shared rules and runtime API
    instrument-invariants.md  Phase 2: invariants -> assertions, invariant probes, ghost state
    instrument-beacons.md     Phase 2: code -> beacon probes
    repair.md                 Phase 2: fix instrumentation that does not build
    subsystems/
      simplex-analyst.md      Phase 1: what the analyst needs to know about Simplex
      marshal-analyst.md      Phase 1: the same for marshal
      simplex-instrument.md   Phase 2: rules for instrumenting Simplex code
      marshal-instrument.md   Phase 2: rules for instrumenting marshal code
  runtime/                    source templates copied into the source tree during Phase 2
    statelens.rs              guard, counter table, probe/assert macros, ghost state
    target.rs                 fuzz target (cert_mock scheme only)
  scripts/
    statelens.py              lint, extract, campaign
```

R-LAYOUT-2. Files under `runtime/` are templates. No committed crate compiles them, and committed code does not include them as a module. A cargo-fuzz package (a `Cargo.toml` with `cargo-fuzz = true`) must not exist under `consensus/fuzz/statelens/` on the main branch. The existing `just fuzz` / `just build` recipes discover packages by grepping `*/Cargo.toml` for `cargo-fuzz = true`, and would otherwise pick it up in CI (G6). The templates must stay `rustfmt`-clean, because CI's `just check-fmt` formats every `*.rs` file in the tree.

R-LAYOUT-3. Nothing outside `consensus/fuzz/statelens/` is committed. The recipes live in `consensus/fuzz/statelens/justfile`.

### 7.2 Invariant registry

R-REG-1. Each invariant is one Markdown file `invariants/<subsystem>/INV-NNNN.md` with YAML front matter, where `<subsystem>` is `simplex` or `marshal`. Every file in a registry is active: the next campaign whose profile binds the subsystem binds it. There is no approval status; humans review, edit, and delete files. IDs are global: a new ID is one more than the highest ID in any registry. An ID therefore names one invariant across registries, and it is reused only if the file with the highest ID is deleted.

R-REG-2. Front-matter fields:

| Field | Required | Values / notes |
|---|---|---|
| `id` | yes | `INV-NNNN`, equal to the file name |
| `title` | yes | One line, at most 80 characters. |
| `source_kind` | yes | `human`, `issue`, `design`, `comment`, `spec`, `paper`. |
| `source_ref` | yes | Issue URL, document path, or `file:line` / module path. |
| `scope` | yes | One or more of the registry's values. `simplex`: `protocol`, `replica`, `voter`, `batcher`, `resolver`, `cross-actor`. `marshal`: `protocol`, `replica`, `core`, `resolver`, `standard`, `coding`, `application`, `cross-component`, where `resolver` means marshal's backfill resolver. |
| `author` | no | A person, or `claude`, `codex`, `claude/<model>`, `codex/<model>`. |

R-REG-3. Required body sections:
- **Statement**: the invariant in English, implementation-agnostic, stated for an honest replica unless the scope is `protocol`.
- **Rationale**: why it must hold (protocol argument or reference).
- **Evidence**: what the source says. For `issue`, describe the violating scenario.

Optional body sections:
- **Preconditions / assumptions**: e.g. "after recovery from the journal".
- **Observation hints**: non-binding pointers to where the concepts live in today's code. Phase 2 may ignore them.

R-REG-4. The Statement must not reference identifiers that exist only in the implementation. Implementation hints go in "Observation hints".

R-REG-5. Statements use EARS patterns where possible: ubiquitous (`The replica shall ...`), state-driven (`While ..., the replica shall ...`), event-driven (`When ..., the replica shall ...`), unwanted behavior (`If ..., then the replica shall ...`), or complex. The pattern determines how the invariant is checked (SPEC section 4.4).

R-REG-6. The reference format is `templates/invariant.md`. Example:

```markdown
---
id: INV-0001
title: No finalize and nullify in the same view
source_kind: human
source_ref: consensus/src/simplex/actors/voter/round.rs
scope: [replica, voter]
author: <name>
---

## Statement
The replica shall not sign both a finalize vote and a nullify vote for the same view,
including across a crash and journal recovery.

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

R-REG-7. `just check-invariants` checks the format of the registry files and the false invariants (SPEC section 4.6).

R-REG-8. False invariants live in `false-invariants/<subsystem>/` with `FALSE-` IDs, which are global like invariant IDs. They are deliberately false, so a working campaign must panic on them. A campaign uses those of its profile's subsystems only when run with `STATELENS_FALSE_INVARIANTS=1`, to test the workflow itself.

### 7.3 Phase 1: discover invariants

R-P1-1. Phase 1 is a single agent invocation per source (set of similar sources, e.g. set of files).
It is parameterized by the agent (`claude|codex`), the registry (`simplex` or `marshal`), the source kind, and the source reference. Interface, run in `consensus/fuzz/statelens/`:
`just extract [--registry simplex|marshal] <kind> <source>...`, e.g. `just extract issue <url>`. The registry defaults to `simplex`. The agent comes from `config.env`, the `STATELENS_AGENT` environment variable, or `--agent`.

R-P1-2. Each source kind has one prompt file, `prompts/analyst-<kind>.md`, appended to the shared `prompts/analyst.md`, which includes the registry's part, `prompts/subsystems/<subsystem>-analyst.md`. Every prompt:
- casts the agent as an analyst for that source kind;
- tells it to read the source (and any code it needs for context);
- tells it to write zero or more invariant files that strictly follow `templates/invariant.md`, with EARS statements, the right `source_kind` / `source_ref` / `author`, and IDs starting at the next free ID, which the script computes.

R-P1-3. Supported sources:
- GitHub issues and PRs (read via `gh`, or the GitHub REST API or web fetch when `gh` is not installed).
- Design documents (local paths or URLs).
- Code comments (a file or module path under `consensus/src/simplex` or `consensus/src/marshal`, matching the registry).
- Paper (page, line); the script converts a PDF to text when `pdftotext` or `pypdf` is available.
- Formal spec in Quint, TLA+, Lean (`consensus/src/simplex/replica.qnt:34`)

R-P1-4. For `issue`, the agent writes the invariant(s) that the issue's bug violated or could have violated, generalized from the specific bug.

R-P1-5. Phase 1 does no deduplication, scoring, or approval. Its files are active as soon as they are written; humans review, edit, maintain, or delete them before the next campaign. The script lints the new files and reports any change the agent made to existing files.

### 7.4 Phase 2: instrument the code and generate fuzz targets

R-P2-1. A campaign runs in place in the operator's checkout: the operator clones the repository, where StateLens lives, and runs the campaign in that clone. StateLens does not make another clone. The checkout must have no tracked changes outside `consensus/fuzz/statelens/` and no instrumentation from an earlier campaign. The campaign instruments the checkout in place and never commits; the operator fuzzes in the checkout and discards it afterwards. Uncommitted edits to the registries are used. It takes two parameters: the agent (`claude|codex`), from a config file (`config.env`), the environment or the CLI; and the profile (`simplex`, the default, or `marshal`), from the CLI. There are no other campaign parameters and no seed corpus. The campaign passes no arguments to libFuzzer; the operator gives them in Phase 3.

R-P2-2. Steps, in order; R-S-P2-1 and R-M-P2-1 say what each step does for their profile:
1. **Materialize.** Copy `runtime/statelens.rs` into `consensus/src/simplex/` and register it as a module. Add `sancov` to the dependencies of `commonware-consensus`. Patch the twins runner in `consensus/fuzz/core` so that it publishes the compromised set to the StateLens runtime before starting nodes and checks the participant index mapping (section 8.4). Patch the deterministic runtime so that a fresh runtime clears StateLens ghost state (R-INS-5). Add the profile's fuzz targets. Every edit is anchored on an exact line of the current code, and the campaign stops if an anchor has moved.
2. **Instrument invariants.** Run the instrumenter agent with `prompts/instrument-invariants.md` over every invariant of the profile's registries, in batches of 8 within one registry. For each invariant it adds assertions, invariant probes, and any ghost state needed.
3. **Instrument beacons.** Run the instrumenter agent with `prompts/instrument-beacons.md` once for each component of the profile. It adds beacon probes.
4. **Write the instrumentation plan.** The agents record, in `consensus/fuzz/statelens/campaign/plan.md`, each invariant -> the sites and ghost fields used, and each beacon probe -> its site and what it observes. The operator uses it when investigating. If the agent could not bind an invariant, the plan says so and gives the reason. The script adds an `unbound` entry for any invariant the agent skipped, a summary, and a check that instrumentation changed no file outside the profile's subsystems.
5. **Build.** Run `cargo check` of `commonware-consensus` (library and tests, stable toolchain) and the sanitizer build of the profile's fuzz targets (pinned nightly). On errors, the agent repairs its own instrumentation (as in StateLens section 5), without weakening assertions, for at most 3 attempts.
6. **Test.** Run the test gate: the engine-level tests of the profile's subsystems on the instrumented code, together with the tests of the StateLens runtime module. Any failure stops the campaign for human investigation.
7. **Hand over.** Print the result and the command that runs each fuzz target in this checkout. The campaign does not run the fuzzer; the operator does, in Phase 3 (7.5).

R-P2-3. The only output of a campaign is its result: one of `READY` (the StateLens fuzz targets are built and the test gate passed), `PANIC (tests)`, `BUILD FAILED`, or `SETUP FAILED`. It is printed with the checkout location and, where there is one, the first panic message. A `READY` result also prints the command that runs each StateLens target and the command that replays a crash. The standard artifacts described in 7.9 hold the crashes that Phase 3 finds.

R-P2-4. **Cryptography (decision).** StateLens fuzz targets use only the `cert_mock` certificate scheme: the mock scheme in `consensus/src/simplex/mocks/scheme.rs`, which `consensus/fuzz/core` imports as `cert_mock`. Every target instantiates the harness with a `cert_mock`-based Simplex type from `consensus/fuzz/core/src/simplex.rs`, such as `SimplexCertificateMock`. No target uses ed25519, BLS12-381, or secp256r1 schemes. A campaign refuses to materialize a target that breaks this rule; for the marshal variants, R-M-P2-2 says how this is checked. The rule covers fuzz targets only; the test gate (R-P2-2 step 6) runs the engine-level tests with their own fixtures.

### 7.5 Phase 3: run fuzz targets

R-P3-1. The operator runs the StateLens fuzz targets in the instrumented checkout, with the commands that a `READY` campaign printed, through the existing `just run` recipe in `consensus/fuzz`. The operator chooses which targets to run, for how long, and with which libFuzzer arguments (for example `-fork=N` or `-max_total_time=<s>`). StateLens neither runs nor supervises the fuzzer.

R-P3-2. A run ends when the target panics or the operator stops it; libFuzzer, including its fork mode, stops at the first crash. A panic is an oracle failure (7.8), and the operator investigates it with the crash artifacts (7.9).

R-P3-3. After fuzzing and any investigation, the operator discards the checkout. It is never reused for another campaign (R-P2-1).

### 7.6 Instrumentation rules

R-INS-1. **No code removal.** The agent may add code, fields, ghost state, helper functions, module-level statics, and hooks. It must not delete or change existing logic. The only allowed change to an existing line is wrapping an expression in a block, keeping its tokens; each such edit is listed in the plan. The only intended behavior change is a panic when an invariant is violated.
When the agent adds code, it must mark it as instrumentation with a comment line `// [statelens] <tag>` directly above it. Tags: `INV-NNNN` for assertions and invariant probes, `ghost:INV-NNNN` for ghost state, `beacon:<label>` for beacon probes, and `me` for code added only to make the replica index available.

R-INS-2. **Byzantine guard.** Every assertion, every probe, and every ghost-state access is guarded. The StateLens macros and ghost-state accessors call `statelens::should_check(me)`, which skips replicas that `statelens::is_byzantine(me)` reports as compromised, so no call site can omit the guard. `me` is the replica's own participant index; R-S-INS-1 and R-M-INS-1 give its sources in each subsystem. `is_byzantine` reads the compromised set published by the harness (section 8.4). A replica with no participant index (`me() == None`) is treated as honest. For testing, `STATELENS_BYZANTINE=check` checks compromised replicas like honest ones, and `STATELENS_BYZANTINE=panic` panics when one reaches an instrumented site (AC-7).

R-INS-3. **Determinism.** Assertions, probes, and ghost updates must not:
- `await`;
- spawn tasks or take locks;
- touch the runtime context, RNG, clock, network, storage, metrics, or logging;
- change the order or content of messages;
- consume values the original code later relies on.

This keeps a crash reproducible from the same input on the same instrumented tree.

R-INS-4. **Assertion form.** Assertions use the StateLens macros `sl_assert!(me, "INV-NNNN", cond, ...)` and `sl_implies!(me, "INV-NNNN", pre, post, ...)`, invoked by module path (`crate::simplex::statelens::sl_implies!`), because `simplex` is declared inside `stability_scope!`. Marshal code invokes them by the same path. A violation panics with a message starting `[statelens][INV-NNNN] replica=<index>`, followed by the invariant title and a short dump of the values involved. One invariant may produce several assertion sites.

R-INS-5. **Ghost state.**
- Ghost fields may be added to existing structs (e.g. `voter::State`, `voter::Round`, `batcher::Round`, `resolver::State`).
- Cross-actor and cross-restart invariants may use per-replica ghost state (`Ghost`, `with_ghost`) in `statelens.rs`, keyed by participant index and shared by all actors and components of the replica, in both subsystems.
- `protocol`-scope invariants may use ghost state shared by all honest replicas (`Global`, `with_global`).
- Ghost state lives for one run: it is cleared before every fuzz input and whenever a fresh deterministic runtime starts (for example each seed of a multi-seed test), and it survives a crash-restart from a checkpoint. Keeping it per thread is safe because the deterministic runtime runs all tasks on the calling thread.
- Cross-actor assertions must allow for mailbox delivery lag. They must hold under any delivery order the implementation allows, not only when actors are in step.

R-INS-6. **Cost.** Probes and assertions are O(1) or bounded by the number of tracked views. No unbounded scans on hot paths.

R-INS-7. **Scope.** The agent edits only non-test code of the profile's subsystems: `consensus/src/simplex/`, excluding `mocks/` and `scheme/`, and, for the `marshal` profile, `consensus/src/marshal/`, excluding `mocks/`. Each invariant is bound only in the code of its own subsystem. The agent may also add initializers of new fields in struct literals anywhere. It does not edit `Cargo.toml` files or anything under `consensus/fuzz/`; the campaign script makes those edits. A campaign stops if instrumentation changed a file outside the profile's subsystems.

### 7.7 Feedback (StateLens adaptation)

R-FB-1. **Counter table.** `statelens.rs` owns a `sancov::Counters<65536>` table. It is registered with libFuzzer once, under `cfg(fuzzing)` and unless `STATELENS_FEEDBACK=0`, and zeroed before every fuzz input. The mechanism is the same as `consensus/fuzz/simplex/src/state_cov.rs`, but the table is separate. `state_cov` and happens-before feedback are not enabled for the StateLens targets. Once the table is registered, libFuzzer stops printing `cov:`; runs are compared by `ft:`.

R-FB-2. **Probe primitive.** `sl_probe!(me, "label", a, b)` sets the counter at `hash(site, a, b) mod N` to 1 (presence only), so a state observed many times in one input yields a single feature. `site` is the label plus the call location, so every call site is distinct. `a` and `b` are small discrete values that convert into `u32` (`bool`, `u8`, `u16`, `u32`); raw `u64` values do not compile.

R-FB-3. **Invariant probes.** `sl_implies!` records `(pre, post)` at every assertion site of the form "if A then B", which rewards reaching an invariant's precondition, not only the code around it. Where meaningful, the agent also adds a bucketed margin to violation for numeric invariants.

R-FB-4. **Beacon probes.** For each component of the profile, the agent mines semantic beacons: state enums, flags and optional fields of per-view or per-height state, and `debug_assert!`s and comments that describe fragile states. It emits probes that record `(pre, post)` pairs around transitions, 20 to 60 per component. Priority goes to:
- transitions caused by side effects or asynchrony (StateLens O2);
- conditions set in one component and used in another through mailboxes (StateLens O1).

R-S-FB-1 and R-M-FB-1 list the beacons of each subsystem.

R-FB-5. **Discretization.**
- Probes never hash raw views, heights, digests, commitments, keys, payloads, or timestamps.
- Views and heights are recorded relative to something (e.g. `delta(view, last_finalized)`, `delta(view, current_view)`, or a height relative to marshal's processed floor) and bucketed with `bucket` (0, 1, 2, 3-4, 5-8, 9+).
- Counts are bucketed the same way; enums go through `disc`, booleans through `flag`, and two small values can share one side through `pack`.
- Probes do not include the replica index, so symmetric replicas share features.

R-FB-6. **No mode switching.** libFuzzer's edge coverage stays on. The StateLens counters only add features. There is no plateau-based switching.

### 7.8 Oracles

R-OR-1. **Oracles** are:
1. the assertions of the invariants of the profile's registries (7.6);
2. the existing checks of the fuzz harnesses, run exactly as the original harnesses run them today: `invariants.rs` and related modules for the Simplex target, and the marshal harness checks for the marshal variants;
3. any other panic in the process.

R-OR-2. Every oracle failure is a panic. The panic propagates to libFuzzer as a crash. This already happens: the deterministic runtime defaults to `catch_panics: false`; the Simplex harness's `fuzz()` catches a panic with `catch_unwind` and re-raises it with `resume_unwind`, and the marshal harnesses let it propagate.

R-OR-3. Any test failure in step 6 stops the campaign, and any crash stops the fuzz run that found it (libFuzzer stops at the first crash). A human decides whether it is an implementation bug, a wrong invariant, or a wrong binding. Fixes to wrong invariants are made in the registry by hand.

### 7.9 Crash artifacts

R-ART-1. Reuse the existing consensus fuzz artifacts unchanged:
- libFuzzer writes the crashing input to the artifact directory of the target's package: `consensus/fuzz/simplex/artifacts/simplex_statelens/`, or `consensus/fuzz/marshal/artifacts/<variant>/` for a marshal variant;
- `just run <target> <crash_file>` replays it, with the `STATELENS_BYZANTINE` value of the run that found it: a guard-test crash (`STATELENS_BYZANTINE=panic`) exists only in that mode;
- for the Simplex target, `CONSENSUS_FUZZ_LOG=1` also prints the decoded `FuzzInput` (`print_fuzz_input`); the marshal harnesses print only their existing logs;
- the panic message carries the `INV-NNNN` ID.

R-ART-2. The operator investigates inside the instrumented checkout before discarding it. The checkout keeps the instrumentation plan, the campaign logs, the rendered prompts, and the instrumentation diff under `consensus/fuzz/statelens/campaign/`. The campaign never commits. No extra bundle format is added.

### 7.10 Agent abstraction

R-AG-1. The agent is a parameter (`claude|codex`). Prompts are plain Markdown and do not depend on either agent. `scripts/statelens.py` maps the parameter to the non-interactive invocation of each CLI (`claude -p`, `codex exec`).

R-AG-2. Phase 2 agents may use any tools available in their CLI (search, LSP, build, test) to trace call graphs and data flow.

R-AG-3. Phase 1 agents run restricted in the operator's working tree: file edits, read-only tools, `gh`, and `curl`. Phase 2 agents run with full permissions in the checkout, so campaigns must run on a dedicated machine or container.

### 7.11 Non-functional

R-NF-1. Correctness first: no probe or ghost update may change protocol behavior (R-INS-1, R-INS-3).

R-NF-2. Determinism: an input that crashes on an instrumented tree crashes the same way when replayed on that tree with the same `STATELENS_BYZANTINE` value.

R-NF-3. Overhead: measure the exec/s of each StateLens target against its original target (plain edge coverage) in an uninstrumented checkout at the same commit. There is no hard limit, but a slowdown above 2x should be reported as a problem with the instrumentation. R-S-NF-1 and section 9.4 name the original targets.

R-NF-4. The committed subproject does not change workspace build, lint, formatting, stability checks, tests, or CI (G6, R-LAYOUT-2).

R-NF-5. Committed files use plain ASCII.

### 7.12 Acceptance criteria

AC-1. `templates/invariant.md`, `prompts/analyst.md`, and the five per-kind analyst prompts exist. Running Phase 1 on a real GitHub issue with each agent produces at least one file that passes `just check-invariants`.

AC-2. On `main`, `just check-fmt`, `just lint`, `just test -p commonware-consensus`, and the CI fuzz matrix behave exactly as before this project (G6).

AC-3. **Registries.** `just check-invariants` reports no problem. `invariants/simplex/` holds INV-0001 to INV-0018, and `false-invariants/simplex/` holds FALSE-0001. `just extract --registry marshal comment consensus/src/marshal/mod.rs` writes files into `invariants/marshal/`, numbered from the next global ID.

Sections 8.5 and 9.5 give the acceptance criteria of each profile.

---

## 8. StateLens for Simplex

### 8.1 Overview

Simplex is the consensus subsystem (`consensus/src/simplex`): leaders propose blocks for
views, and replicas vote to notarize, nullify or finalize them. Each replica runs three
actors: the voter, the batcher and the resolver. The `simplex` profile covers this
subsystem. A `simplex` campaign:
- binds the simplex registry;
- adds beacon probes to the voter, batcher and resolver;
- runs the engine-level Simplex tests;
- builds one fuzz target, `simplex_statelens` (G4), which the operator runs in Phase 3.

The runtime module lives in this subsystem, at `consensus/src/simplex/statelens.rs`, and
serves marshal too (G8).

### 8.2 Background

- `consensus/fuzz/simplex/src/state_cov.rs` already provides a state-coverage signal: a `sancov::Counters<65536>` table fed by FNV-hashed tokens. The tokens are computed **once per run, after the run**, from the mock reporters, metrics, and trace events. Nothing inside the voter, batcher, or resolver is observed while it runs.
- Oracles are the protocol-level checks in `consensus/fuzz/simplex/src/invariants.rs` and related modules. They also run after the run, over reporter output.
- The replica's internal state (`voter::State`, `voter::Round`, `voter::Slot`, `batcher::Round`/`VoteTracker`, `resolver::State`) is neither a feedback signal nor checked by any oracle.
- The fuzzer cannot tell apart, for example, `CertifyState` moving `Outstanding -> Aborted` because the view advanced, `Slot` status moving `Verified -> Equivocated`, or a latched timeout racing a late certificate.

#### How StateLens maps onto Simplex

| StateLens (JS engines) | This project (Simplex) |
|---|---|
| Engine subsystems (IC, JIT, GC) | Actors: voter, batcher, resolver |
| O1: conditions cross implementation boundaries | Conditions set in one actor and used in another through mailboxes; conditions that must survive journal replay |
| O2: side effects invalidate assumptions | Asynchrony: view advances while certification is outstanding; timeouts race certificates; equivocation detected after verification |
| O3: developer artifacts reveal states | Enums (`CertifyState`, `slot::Status`, `TimeoutReason`), per-view flags, `debug_assert!`s, comments, GitHub issues, design docs, formal specs, papers |
| Knowledge base + retrieval | Replaced by (a) the invariant registry, (b) the agent reading the code directly |
| Probes: `(site, a, b)` into a shared-memory bitmap | Same, into an in-process `sancov` counter table (libFuzzer is in-process, so no IPC), presence only |
| Validation: compile, test suite, LLM repair | `cargo check` and the fuzz build with up to 3 agent repairs, then the engine-level test gate |
| Oracle: crashes / ASan | Invariant assertions plus existing protocol checks, all as panics |
| Re-instrument each engine release | Instrument a fresh clone for each campaign |
| Dual feedback with plateau switch | Always-on state counters on top of edge coverage |
| Every thread and process is instrumented | Only honest replicas are observed (Byzantine guard) |

### 8.3 Requirements

#### Phase 2

R-S-P2-1. For the `simplex` profile, the steps of R-P2-2 do the following:
1. **Materialize.** Add the fuzz target `simplex_statelens`, from `runtime/target.rs`, to
   the existing `consensus/fuzz/simplex` package.
2. **Instrument invariants.** Bind the simplex registry.
3. **Instrument beacons.** Once for each of the voter, batcher and resolver.
4. **Write the plan and check scope,** with `consensus/src/simplex/` allowed (R-INS-7).
5. **Build.** The sanitizer build of `simplex_statelens`.
6. **Test.** The test gate is the engine-level Simplex tests of `commonware-consensus`
   (`simplex::tests`, including the `slow` group), together with the tests of the
   StateLens runtime module. The Twins tests are excluded, because they run two live
   engines under one replica identity. The gate is about 240 tests and takes about 2
   minutes on 16 cores.
7. **Hand over.** The summary gives the command that runs `simplex_statelens`.

#### Instrumentation

R-S-INS-1. Identity in Simplex. `me` is `scheme.me()`: the voter, batcher and resolver
each hold the replica's signing scheme. Where no scheme is in scope, the agent adds a
`// [statelens] me` field, set where the struct is created.

#### Feedback

R-S-FB-1. The instrumenter mines Simplex beacons in the voter, batcher and resolver:
- state enums, e.g. `CertifyState`, `slot::Status`, `TimeoutReason`, `Activity` kinds;
- per-view flags and `Option` certificate slots;
- `debug_assert!`s and comments that describe fragile states.

Priority goes to:
- transitions caused by side effects or asynchrony: a view change while certification is
  outstanding, a timeout racing a certificate, equivocation detected after verification,
  journal replay;
- conditions set in one actor and used in another: voter <-> batcher <-> resolver through
  mailboxes.

#### Non-functional

R-S-NF-1. The original target of `simplex_statelens` is `simplex_cert_mock_twins_mutator`
(plain `CodeCoverage`), against which R-NF-3 measures overhead. With minimal
instrumentation both run at about 13 executions per second per process, so the operator
runs `simplex_statelens` with libFuzzer's `-fork=N`.

### 8.4 Fuzz harness

The marshal variants (9.4) share the runtime module and the Twins runner hook described
here.

#### Shape

```
libFuzzer   (started by the operator: just run simplex_statelens)
  |  bytes -> FuzzInput (existing Arbitrary impl in consensus/fuzz/core)
  v
simplex_statelens fuzz target  (consensus/fuzz/simplex, from runtime/target.rs)
  |  statelens::reset()            zero counters, clear compromised set and ghost state
  |  fuzz::<SimplexCertificateMock, TwinsMutator, CodeCoverage>(input)
  |                                cert_mock certificate scheme only (R-P2-4)
  v
consensus/fuzz/simplex::fuzz -> run_with_twins_mutator
  v
consensus/fuzz/core::run_twins_with_backend
  |  sample twins scenario -> compromised set
  |  [hook] statelens::set_compromised(compromised)        (patched in Phase 2)
  |  [hook] assert each scheme's own index == its participant index
  |
  |-- compromised participant i:
  |     primary   = real Simplex engine  (instrumented, guard => skipped)
  |     secondary = Disrupter            (no Simplex actor code)
  |-- honest participants:
  |     real Simplex engines: voter / batcher / resolver
  |       assertions  -> panic on violation
  |       probes      -> StateLens counter table
  |       ghost state -> struct fields, Ghost (per replica), Global (all honest)
  v
existing post-run oracles (invariants.rs, vote/safety checks)  -> panic on violation
  v
statelens::clear_compromised()     (in the target, after fuzz() returns)
libFuzzer reads edge coverage + StateLens counters -> keep input if new features
```

#### Why `TwinsMutator`

Twins is the best available way to put an honest replica into states that only Byzantine peers can cause: equivocating proposals and votes, split network views, conflicting certificates. In `TwinsMutator` a compromised participant runs a legitimate primary engine plus a `Disrupter` secondary that mutates content according to `input.strategy`. Honest replicas therefore face both network splits and content mutations, which is where replica-local and cross-actor invariants are most likely to break.

#### Byzantine guard plumbing

`commonware-consensus` cannot depend on the fuzz crates, so the guard state lives in `consensus/src/simplex/statelens.rs`, which the campaign materializes. Marshal code uses the same module. The campaign patches the twins runner (`consensus/fuzz/core/src/lib.rs`, where `compromised` is built from the sampled case) to:
- call `statelens::set_compromised(...)` before any engine starts;
- assert that every scheme's own index (`scheme.me()`) equals its position in the participant list.

The fuzz target calls `statelens::reset()` before every input and `statelens::clear_compromised()` after `fuzz()` returns, not inside the runner, so compromised replicas stay guarded while the runtime shuts down.

The campaign also patches the deterministic runtime: `Runner::new` calls a hook that StateLens registers, which clears ghost state. A fresh runtime therefore starts with no history (each fuzz input, each seed of a test), while a runtime resumed from a checkpoint keeps it.

The guard is built into the StateLens macros and ghost-state accessors, which call `statelens::should_check(me)` with `me` from `scheme.me()`. The guard is keyed on participant identity, so it covers the compromised primary engine. The `Disrupter` secondary runs no Simplex actor code. The compromised set is thread-local, which is sound because the deterministic runtime runs every task on the thread that starts it.

### 8.5 Acceptance Criteria

AC-4. A `simplex` campaign on a fresh clone with at least one invariant in the simplex registry:
- materializes the runtime and target;
- instruments the code;
- writes the instrumentation plan;
- builds;
- runs the test gate;
- reports `READY` with the command that runs the fuzz target, and that command starts it.

AC-5. On an instrumented checkout, the `ft:` value reported by libFuzzer after a fixed time is higher with StateLens feedback than with `STATELENS_FEEDBACK=0`, which shows the probes fire.

AC-6. **False-invariant test.** A campaign run with `STATELENS_FALSE_INVARIANTS=1` includes the deliberately false invariant `false-invariants/simplex/FALSE-0001.md` ("the replica shall not accept a nullification certificate") and stops with `[statelens][FALSE-0001]` in the test gate. If the tests do not reach it, a short run of the printed command panics with it.

AC-7. **Guard test.** With `STATELENS_BYZANTINE=panic`, a short run of the StateLens target panics with `[statelens][BYZANTINE]` as soon as a compromised replica reaches an instrumented site. With the default (`skip`), no such panic occurs, and the participant index check in the runner never fails.

AC-8. **Determinism test.** Replaying a crashing input with `just run simplex_statelens <crash_file>` on the same instrumented tree, with the `STATELENS_BYZANTINE` value of the run that found it, reproduces the same panic.

### 8.6 Risks and Open Points

| Risk | Mitigation |
|---|---|
| Low throughput (about 13 executions per second per process). | libFuzzer's `-fork=N`; the existing `invariants.rs` checks may be adjusted later (section 3.2). |
| The Twins tests are not part of the test gate. | The fuzz harness itself exercises Twins scenarios with the correct guard. |

---

## 9. StateLens for Marshal

### 9.1 Overview

Marshal is the second subsystem of the Simplex implementation, and the `marshal` profile
covers it. The profile takes the approach of the existing marshal fuzz targets, which run
real Simplex engines that drive marshal. A `marshal` campaign therefore:
- binds the simplex and marshal registries, each invariant in the code of its own
  subsystem;
- adds beacon probes to the Simplex actors and to marshal's components;
- runs the Simplex and marshal engine-level tests;
- builds a StateLens variant of every existing marshal fuzz target, which the operator
  runs in Phase 3.

Marshal code calls the runtime module of the Simplex subsystem,
`consensus/src/simplex/statelens.rs` (G8), because marshal already depends on
`crate::simplex`.

### 9.2 Background

- Marshal (`consensus/src/marshal`) turns Simplex certificates, and the blocks
  disseminated for proposals, into an ordered, at-least-once stream of finalized blocks
  for the application. It consists of:
  - the core actor: ordering, the processed floor and its anchor, caches, durable
    archives, application acknowledgements, subscriptions, and repair and backfill of
    missing blocks and certificates;
  - the backfill resolver;
  - the standard-mode consensus adapters, `Inline` and `Deferred`;
  - the coding mode: the `Marshaled` adapter, and the shards engine, which disseminates,
    checks and reconstructs erasure-coded blocks.
- `consensus/fuzz/marshal` has 12 fuzz targets, all on the `cert_mock` scheme. Eleven run
  real Simplex engines; the store target drives the core actor directly. The four Twins
  targets reach the Twins runner that every campaign patches (R-P2-2 step 1).
- The oracles of these targets (`end_to_end/invariants.rs` and the scenario checks) run
  during and after a run, at the marshal/application boundary: certification agreement,
  header-context mismatch, parent linkage, agreement per height, in-order delivery, and
  progress after GST.
- Marshal's internal state is neither a feedback signal nor checked by any oracle: floor
  anchors, acknowledgements in flight, repair and backfill in flight, and commitment
  phases and reconstruction in the shards engine.

### 9.3 Requirements

#### Registry

R-M-REG-1. Marshal Statements use marshal's protocol terms: finalized blocks and heights,
certificates for blocks, the processed floor, delivery to the application and its
acknowledgement, backfill requests and responses, durable storage, pruning and, for
coding, commitments, shards and reconstruction. As in R-REG-4, they never name Rust
identifiers.

R-M-REG-2. `false-invariants/marshal/FALSE-0002.md` is the deliberately false marshal
invariant: "the replica shall not deliver a finalized block above height 1 to the
application".

#### Phase 2

R-M-P2-1. For the `marshal` profile, the steps of R-P2-2 do the following:
1. **Materialize.** Add one StateLens variant per existing marshal fuzz target to
   `consensus/fuzz/marshal`, and a hook to the marshal wedge scenario that publishes its
   Byzantine role (9.4). The `simplex_statelens` target is not added.
2. **Instrument invariants.** Bind the simplex registry, then the marshal registry.
3. **Instrument beacons.** Once for each of the Simplex voter, batcher and resolver, then
   for marshal's core, standard and coding components.
4. **Write the plan and check scope,** with the code of both subsystems allowed
   (R-INS-7).
5. **Build.** The sanitizer build of every StateLens variant.
6. **Test.** The test gate of R-S-P2-1 step 6, plus every marshal test of
   `commonware-consensus`, including the `slow` group.
7. **Hand over.** The summary gives one run command per StateLens variant.

R-M-P2-2. R-P2-4 applies to every StateLens variant. A campaign refuses to materialize a
variant whose target names a Simplex type without the `cert_mock` scheme, directly or
through the marshal fuzz package.

#### Phase 3

R-M-P3-1. The operator chooses which variants to run (R-P3-1). Only the variants that
section 9.4 marks as having an adversary with a real Simplex engine or marshal exercise
the Byzantine guard.

#### Instrumentation

R-M-INS-1. Identity in marshal. `me` is the participant index of the replica's own
signing scheme, which marshal gets from its scheme provider:
- The core actor derives `me` when it is created and passes it to the mailbox it returns,
  so the standard adapters can read it from the mailbox they hold.
- The coding adapter and the shards engine derive it from their scheme provider at the
  epoch in hand.

A site that cannot obtain `me` gets no instrumentation. `None` means "not a participant"
and turns the guard off, so it never stands in for an unknown identity.

#### Feedback

R-M-FB-1. The instrumenter mines marshal beacons:
- state enums: sync kinds, request kinds, gate outcomes, validation stages, commitment
  phases and statuses, retirement reasons, reconstruction states;
- the floor and its pending anchor;
- acknowledgements in flight, and repair and backfill in flight;
- durability flags.

Priority goes to transitions under asynchrony:
- a finalization arrives before its block;
- the floor moves while backfill is in flight;
- a block arrives after its height was passed or pruned;
- dispatch runs ahead of acknowledgements;
- certification is requested before the block is available;
- shards arrive out of order or after reconstruction;
- state is rebuilt from the archives after a restart.

### 9.4 Fuzz harness

| Existing target (the variant appends `_statelens`) | Family | Adversary runs a real Simplex engine or marshal | Guard |
|---|---|---|---|
| `marshal_e2e_standard_app_cert_mock_twins` | Twins | yes: the compromised primary runs Simplex, marshal and the application | Twins runner hook (existing) |
| `marshal_e2e_coding_app_cert_mock_twins` | Twins | yes | Twins runner hook |
| `marshal_e2e_standard_deferred_cert_mock_twins_split_header` | Twins | yes | Twins runner hook |
| `marshal_e2e_standard_inline_cert_mock_twins_split_header` | Twins | yes | Twins runner hook |
| `marshal_e2e_standard_deferred_cert_mock_scenarios` | wedge scenario | yes: the Byzantine role runs a full stack behind the wedge | wedge hook (new) |
| `marshal_e2e_standard_deferred_cert_mock_disrupter` | Disrupter | no: the Byzantine node is a `Disrupter` | none needed |
| `marshal_e2e_coding_cert_mock_disrupter` | Disrupter | no | none needed |
| `marshal_e2e_standard_deferred_cert_mock_poison` | Disrupter, poisoned backfill answer | no | none needed |
| `marshal_e2e_standard_deferred_cert_mock_block_dissemination` | Byzantine first leader | no: the Byzantine node runs only a block-gossip disrupter | none needed |
| `marshal_scenario_standard_deferred_cert_mock` | scenario prefix | no: node A runs a `Disrupter` and a block-gossip adversary, but no Simplex engine or marshal | none needed |
| `marshal_scenario_standard_inline_cert_mock` | scenario prefix | no | none needed |
| `marshal_actor_standard_store_cert_mock` | store | no peers | none needed |

A variant calls `statelens::reset()` before the harness runs, and `reset()` empties the
compromised set. So in the targets without a guard, every engine and marshal is checked.
In the Twins targets, the Twins runner hook of R-P2-2 step 1 (section 8.4) publishes the compromised identity,
whose primary runs a real Simplex engine and marshal. In the wedge scenario, a new hook in
the scenario runner publishes the Byzantine role before any engine starts. It also checks
the participant index mapping, as the Twins hook does.

```
libFuzzer   (started by the operator: just run <target>_statelens)
  |  bytes -> the input type of the existing target
  v
<target>_statelens   (consensus/fuzz/marshal, generated from <target>.rs)
  |  statelens::reset()
  |  the existing target's harness call, unchanged
  |  statelens::clear_compromised()
  v
marshal harness: Twins | wedge scenario | Disrupter | scenario prefix | store
  |  [hook] set_compromised(...)    Twins runner (existing), wedge scenario (new)
  |-- honest validators: Simplex engine -> Inline|Deferred|Marshaled -> marshal -> application
  |     simplex assertions and probes: voter, batcher, resolver
  |     marshal assertions and probes: core, standard, coding
  |-- adversary: compromised primary (guarded) plus secondary, wedge role (guarded),
  |     or disrupters that run no Simplex actor or marshal code
  v
existing marshal oracles  -> panic on violation
```

### 9.5 Acceptance Criteria

AC-9. **Marshal campaign.** A `marshal` campaign on a fresh clone, with at least one
marshal invariant:
- materializes one variant per marshal fuzz target;
- instruments the code;
- writes the plan;
- builds;
- passes the test gate;
- reports `READY` with one run command per variant, and each command starts its variant.

AC-10. **False invariants.** `STATELENS_FALSE_INVARIANTS=1 just fuzz --profile marshal`
stops with `PANIC (tests)`, and the test log contains both `[statelens][FALSE-0001]` and
`[statelens][FALSE-0002]`.

AC-11. **Guard.** With `STATELENS_BYZANTINE=panic`, each Twins variant and the
wedge-scenario variant panic with `[statelens][BYZANTINE]`. The other variants, and every
variant in the default mode, never do, and the participant index checks never fail.

AC-12. **Determinism.** Replaying the input of a crashing marshal variant on the same tree,
with the `STATELENS_BYZANTINE` value of the run that found it, reproduces the same panic.

AC-13. **Feedback.** On one Twins variant, the `ft:` value after a fixed time is higher
with StateLens feedback than with `STATELENS_FEEDBACK=0`.

### 9.6 Risks and Open Points

| Risk | Mitigation |
|---|---|
| Simplex invariants were bound and tested against the mock application. With marshal's real certifiers and harness-seeded journals, they may fail for reasons that are not bugs. | Triage as in R-OR-3. A 2-minute smoke run of a marshal Twins target on a simplex-instrumented tree found no violation (SPEC section 8.1). |
| The standard adapters get `me` only through an instrumentation field in marshal's mailbox. An agent that misses it leaves adapter sites uninstrumented. | R-M-INS-1 is in the prompt. The plan names the identity source of every marshal site. AC-11. |
| The operator chooses which of the twelve variants to run. Skipping the Twins and wedge variants skips every variant in which the adversary runs Simplex or marshal code. | The summary lists every variant (SPEC section 8.3), and 9.4 says which have an adversary with a real stack. One Twins process measured 15 exec/s and 628 MB peak RSS. |
| Six beacon runs (three per subsystem) raise the probe count and the agent time. | The per-actor budget of R-FB-4 applies to each component. |
| Marshal moves under `consensus/src/simplex/` (draft PR #4994). | Paths are profile data in `statelens.py`. When the move lands, the marshal root and test filter change, and the `simplex` profile's editable code must exclude `consensus/src/simplex/marshal/`. |
| Issue #4701 removes marshal's backward ancestry API. | Statements are implementation-agnostic (R-REG-4), and bindings are made again in every campaign. Observation hints may go stale. |
| The Twins observation wrappers forward completions through spawned tasks, so scheduling is sensitive. | R-INS-3; AC-12. |
| The wedge scenario's Byzantine role runs honest code. Guarding it hides its state from feedback. | Accepted, as required by G5. |
| The store variant has no peers and reaches only the core actor's store paths. | Accepted: the variants follow the existing target set. |

---

## 10. Risks and Open Points

| Risk | Mitigation |
|---|---|
| LLM-written invariants are wrong under Byzantine conditions and cause false alarms. | Human review of the registry; the test gate runs before fuzzing; triage by humans; wrong invariants are fixed in the registry. |
| A draft invariant takes effect before anyone reviewed it, because every file in the registry is active. | Phase 1 prints a review reminder; the operator reviews `invariants/` before starting a campaign. |
| Bindings change between campaigns, because agent output is not deterministic. | Accepted by design: every campaign is fresh. The instrumentation plan and diff document each binding. |
| An instrumented checkout is reused for another campaign or committed by mistake. | The campaign refuses a checkout with tracked changes outside `consensus/fuzz/statelens/` or earlier instrumentation, and never commits; operators discard the checkout after a campaign. |
| Probes change scheduling or behavior. | R-INS-1 and R-INS-3; AC-8. |
| Too many probe features (corpus bloat) or hash collisions. | Presence-only probes (R-FB-2); discretization rules (R-FB-5); 64K table; exclude replica index. |
| Cross-actor assertions fire only because of mailbox lag. | R-INS-5: assertions must allow for any legal delivery order. |
| History kept in ghost state leaks from one run into the next, for example between the seeds of one test (found by the first end-to-end campaign). | The deterministic runtime's fresh-run hook clears ghost state (R-INS-5, section 8.4). |
| The patch anchors of the materialize step move with the code. | The campaign stops with a message that names the anchor, which is then updated in `scripts/statelens.py`. |
| Phase 2 agents have full access to the host. | Campaigns run on a dedicated machine or container (R-AG-3). |
| StateLens evidence comes from memory-safety bugs in C++ engines; payoff on Rust logic bugs is unproven. | AC-5/AC-6 establish basic function. Measuring bug-finding (e.g. on planted bugs) is left for later. |
| libFuzzer stops at the first crash. | Intended: "panic => human investigates". |
| A campaign's result says nothing about fuzzing: how long and how widely the targets run in Phase 3 is up to the operator. | The summary prints the command for every StateLens target (SPEC section 7.9), and crashes land in the standard artifact directories (R-ART-1). |

---

## 11. Specification

[SPEC.md](../docs/SPEC.md) specifies:
1. the committed files and the registry format, including `templates/invariant.md` and the lint rules;
2. the `statelens.py` commands (`lint`, `extract`, `campaign`), their configuration, the profiles, and exit codes;
3. the exact edits a campaign makes to the source tree, with their anchors;
4. the runtime module `statelens.rs` and the fuzz target, verbatim and tested;
5. all prompts, verbatim, with the per-subsystem parts;
6. the agent invocations for `claude` and `codex`;
7. in chapter 7, StateLens for Simplex: the campaign of the `simplex` profile, and how the operator runs its target in Phase 3;
8. in chapter 8, StateLens for Marshal: what is specific to the `marshal` profile;
9. the acceptance procedures for AC-1 to AC-13.
