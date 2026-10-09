# StateLens: Product Requirements Document

| | |
|---|---|
| Scope | `consensus/src/simplex`, `consensus/src/marshal` and `storage/src/qmdb`, each directory in full; chapter 5 names the parts that get their own beacon probes |
| Subproject root | `statelens/` |
| Specification | [SPEC.md](../docs/SPEC.md) |
| Reference | Wong et al., "State-Aware Fuzzing of JavaScript Engines with LLM-Guided Instrumentation" (StateLens), SOSP '26, [arXiv:2609.24550](https://arxiv.org/abs/2609.24550) |
| Reference | Li et al., "SyzHarness: Patch-Based Kernel Bug Reproduction with LLM-Synthesized Fuzzing Harnesses", arXiv preprint, [arXiv:2609.23889v2](https://arxiv.org/abs/2609.23889v2); chapter 11 adapts it |

---

## 1. Summary

Build an invariant-driven, state-aware fuzzing workflow for the Simplex consensus implementation and the qmdb databases of the storage crate, adapted from StateLens. StateLens covers three subsystems:
- **Simplex** (`consensus/src/simplex`): the consensus protocol, with its voter, batcher and resolver actors (chapter 8);
- **marshal** (`consensus/src/marshal`): the ordered delivery of finalized blocks to the application (chapter 9);
- **qmdb** (`storage/src/qmdb`): the databases built on an append-only log of operations, all of them authenticated but the `store` (chapter 10).

The workflow has three phases:

1. **Discover invariants.** Humans own a registry of invariants written in English, one per subsystem. Invariants are long-term properties of the protocol, of a correct replica, or of a database. They are not tied to a particular implementation. They come from humans or from LLMs that read GitHub issues, design documents, code comments, formal specifications, papers, and knowledge-base findings. Every invariant records where it came from (the source). Every file in a registry is active: the next campaign that covers its subsystem uses it.

2. **Instrument the code and generate fuzz targets.** A campaign runs in place in the operator's fresh clone of the repository, where StateLens lives; StateLens does not make another clone. The campaign's profile, `simplex`, `marshal` or `qmdb`, selects the subsystems it covers. An LLM coding agent reads the invariants and the current code, and instruments the code with:
   1. assertions that check the invariants;
   2. state probes derived from the invariants;
   3. StateLens-style state probes for semantic beacons, which the agent discovers as it works: from the code (enums, state transitions, developer asserts and comments), and from a knowledge base of developer artifacts it queries while instrumenting (section 7.3).

   The campaign then builds the StateLens fuzz targets and runs the engine-level tests on the instrumented tree:
   - for Simplex, a StateLens variant of every existing simplex fuzz target;
   - for marshal, a StateLens variant of every existing marshal fuzz target;
   - for qmdb, a StateLens variant of every existing qmdb fuzz target of `storage/fuzz`.

   The campaign ends when the targets are built and tested, and prints the commands that run them.
3. **Run fuzz targets.** The operator runs the targets in the instrumented checkout until one panics or the operator stops it. An invariant violation is a panic. The instrumented tree is never reused for another campaign, but is used for fuzzing and for the investigation of a crash.

Target-State Synthesis (chapter 11) extends the three phases for the `simplex` and `marshal` profiles. Phase 1 also turns sources into target states: cards that describe a protocol state and the history of events that reaches it. After a campaign, a synthesis step writes one dedicated fuzz target per card and base target, a scaffold, which drives that base into that state and reports, through the probes the campaign installed, which stages of the history it reached. Phase 3 runs the scaffolds like any other target, or all of them with `just fuzz <profile> --state-reaching`.

---

## 2. Background

### 2.1 StateLens in one paragraph

Once a fuzzer saturates edge coverage, executions that take the same paths but reach different internal states look identical to it. StateLens has three stages:

1. **Offline analysis.** An LLM agent mines "semantic beacons" (asserts, enums, comments, bug reports, design docs). These are developer-written evidence that some state or transition matters. The paper's agent retrieves them on demand from a knowledge base rather than reading whole artifacts. The agent traces where each state is set, changed, and used, and selects read-only expressions to observe, preferring before/after pairs around side-effecting transitions.
2. **Instrumentation.** It synthesizes lightweight probes that hash `(site, value_a, value_b)` into a coverage bitmap. Instrumented code is validated by compiling it and running the target's test suite.
3. **Fuzzing.** It fuzzes with edge coverage plus state coverage.

### 2.2 The gap this project fills

1. **Feedback from inside the replica or the database, at the moment a transition happens.**
2. **Low-level oracles.** Assertions over replica-local, actor-local, cross-actor, database-internal and temporal properties that the existing checks of the fuzz harnesses cannot observe.
3. **Developer artifacts that are not in this repository.** Hundreds of triaged findings record which internal states mattered enough to report, with their root cause and their lifecycle. Nothing in the fuzzers reads them, and they are the closest thing the workspace has to the paper's knowledge base.
4. **Reaching known interesting states.** Tests, pull requests, bug reports and comments describe states that only a specific multi-step history reaches. The drivers of the fuzz targets sample schedules and faults at random and rarely produce such a history (section 11.2).

Sections 8.2, 9.2, 10.2 and 11.2 describe where each subsystem and the target states stand today, with examples.

---

## 3. Goals and Non-Goals

### 3.1 Goals

- G1. Persistent, maintained, and reused registries of English invariants in `statelens/invariants/`, one per subsystem (`simplex`, `marshal`, `qmdb`), each invariant with its source recorded and an ID unique across registries.
- G2. A simple, agent-agnostic way to turn the specified set of sources (GitHub issues, design documents, code comments from specified files, crates, modules, formal specifications, papers) into invariant entries in a fixed format (as simple as possible), in the registry of the subsystem the operator names.
- G3. A campaign workflow, with one profile per subsystem, in which an LLM agent (`claude code` or `codex`) instruments a fresh clone with assertions, invariant probes, beacon probes, and ghost variables in the state. The workflow builds the StateLens fuzz targets and runs the tests (Phase 2); the operator then runs the targets (Phase 3).
- G4. Fuzz Simplex. The `simplex` profile binds the Simplex registry, instruments `consensus/src/simplex`, and builds a StateLens variant of every existing simplex fuzz target of `consensus/fuzz/simplex`, using only the `cert_mock` scheme (R-P2-4). Each variant is derived from its target rather than written by hand, so it inherits that target's driver, features and feedback, and adds the StateLens counter table to them (chapter 8).
- G5. Byzantine replicas are never checked and never feed coverage, in either consensus subsystem.
- G6. The committed subproject does not affect normal builds, fuzzing, testing, deterministic runtime, lints, or CI of the workspace.
- G7. Fuzz marshal. The `marshal` profile binds the Simplex and marshal registries, instruments both subsystems, and builds a StateLens variant of every existing marshal fuzz target, using only the `cert_mock` scheme (chapter 9).
- G8. One runtime module serves both consensus subsystems: one compromised set, one counter table and one ghost store per run. The qmdb profile puts a copy of the same module in the storage crate.
- G9. A knowledge base of developer artifacts, above all the findings reported against this workspace, that the campaign's beacon step queries while it instruments, so a probe can be aimed at a state that has gone wrong before and not only at one the code makes visible.
- G10. Fuzz qmdb. The `qmdb` profile binds the qmdb registry, instruments `storage/src/qmdb`, and builds a StateLens variant of every existing qmdb fuzz target (chapter 10). It shares the method, the runtime template, the prompts and the scripts with the consensus profiles, and nothing else.
- G11. A registry of target states in `statelens/target-states/`, one per consensus subsystem (`simplex`, `marshal`), and an agent-agnostic way to turn tests, GitHub issues and PRs, code comments, documents, knowledge-base findings and plain text into target-state cards in a fixed format (R-TS-REG-1, R-TS-P1-1).
- G12. Witnessed state-reaching fuzz targets. After a campaign, an agent writes one scaffold per card and base, an existing target of the profile the operator selects: it fixes the card's essential history, leaves its uncertain parameters, timings and orderings to libFuzzer, and reports which stages of the history it reached, witnessed by the probes the campaign installed and by harness observables (chapter 11).

### 3.2 Non-Goals

General:
- Code other than `consensus/src/simplex`, `consensus/src/marshal` and `storage/src/qmdb`.
- Cross-subsystem invariants: invariants that relate the state of two subsystems in one check, and a registry for them. Every invariant is bound in the code of its own subsystem, and no campaign instruments both crates.
- Real signature schemes (ed25519, BLS12-381, secp256r1) in StateLens fuzz targets; they use only the `cert_mock` scheme (R-P2-4).
- Changing, deduplicating against, or replacing the existing checks of the fuzz harnesses (`invariants.rs` and related modules of the Simplex and marshal fuzz packages). The existing checks run exactly as today. The new invariants may overlap with them on purpose. It may be adjusted later, if we see that throughput is very low and does not satisfy fuzzing requirements.
- Automated approval, review gates, or trust scoring for invariants. Approval is entirely a human responsibility, and invariant files carry no approval status.
- Mining new invariants during a campaign. The campaign discovers beacons, which are probes, never invariants. Target states, likewise, come from Phase 1 only, never from a campaign or a synthesis (R-TS-P1-1).
- A GPU, a hosted embedding service, a vector database, or training a model. `kb search` embeds with a small pretrained model on the CPU, keeps its vectors in a flat local file, and never sends text off the machine (R-KB-9).
- A data-flow tool, and the paper's iterative state discovery as a stage of its own, with a frontier and a step budget. The instrumenter traces state with the code index and the syntax-tree queries (R-AG-4, R-AG-5), search and reading, and follows a value through a computation by its own reasoning, which those tools confirm or reject (R-AG-2). A finding's own citations name the files and symbols it would otherwise have to rediscover. Refining a scaffold (R-TS-SYN-7) is not that stage: it has no frontier, explores no new states, and makes at most 3 further attempts at one card.
- Committing any knowledge-base content to this repository (R-KB-6).
- Assertions derived from the knowledge base during a campaign. There a finding is evidence, not a property: it drives probes only, and invariants stay the only source of oracles. Phase 1 may turn findings into invariants (R-P1-7), which a human reviews like any other. Target states, their stage checks and their reach verdicts are never oracles either (R-OR-1).
- Switching between edge-only and state-augmented feedback (StateLens' "dual feedback"). The state counters are always on.
- Seed corpora, fuzz-corpus reuse between campaigns, campaign reports beyond the result summary and the per-card reach reports of a synthesis (R-TS-SYN-7), or dashboards. A scaffold's canonical input is the empty input, not a seed (R-TS-SC-2).
- Reusing an instrumented tree for another campaign.
- Automating Phase 3. A campaign builds the StateLens fuzz targets but does not run them; the operator runs them with `just run` or `just fuzz` and chooses which targets, for how long, and with which libFuzzer arguments. The reach check of a synthesis replays fixed inputs to verify a scaffold (R-TS-SYN-5); it is not a fuzz run.
- A synthesis that adds probes, assertions or ghost state, or that changes what the protocol does (R-TS-SYN-3). Scaffolds read the probes a campaign installed.
- Archiving the raw inputs of target states. The card is the record of its source (R-TS-P1-3).
- Gating fuzzing on a reach verdict. Every scaffold that passes the vetoes and builds is fuzzed, unless the rerun test gate removes it (R-TS-SYN-6).
- An LLM in the fuzz loop. Agents write cards and scaffolds before fuzzing starts; libFuzzer alone runs the targets.

Simplex:
- Integrating the StateLens table with the `state_cov.rs` or happens-before feedback of some simplex targets. Their variants keep that feedback as it is, beside the StateLens table.

Marshal:
- Fuzz targets other than the existing ones and the scaffolds of chapter 11, or changes to their harnesses beyond the edits a campaign or a synthesis (R-TS-SYN-3) makes.
- Coding schemes other than the one the marshal fuzz targets use (Reed-Solomon).
- Following the planned move of marshal under `consensus/src/simplex/` (draft PR #4994) before it lands.

qmdb:
- Storage code outside `storage/src/qmdb` (journals, archives, Merkle structures), though qmdb builds on it, and the storage fuzz targets other than the `qmdb_*` ones.
- Fuzz targets other than the existing ones, or changes to their harnesses beyond the edits a campaign makes.
- Target states and scaffolds. Target-State Synthesis covers the consensus profiles only (chapter 11).

---

## 4. Roles

| Role | Responsibility |
|---|---|
| Invariant author (developer or security engineer) | Writes invariants and target-state cards by hand. Reviews, edits or deletes LLM-written ones before the next campaign or synthesis, because every file in a registry is used (R-P1-5, R-TS-REG-1). |
| Analyst agent (`claude` or `codex`) | Phase 1: reads sources and writes invariant entries, or target-state cards (R-TS-P1-1), in the reference format. |
| Instrumenter agent (`claude` or `codex`) | Phase 2: reads the invariants of the profile's registries and the code of its subsystems, and queries the knowledge base while it works; writes assertions, probes and ghost state into the checkout. |
| Synthesizer agent (`claude` or `codex`) | Phase 2, after a campaign of the `simplex` or `marshal` profile: reads one target-state card, the instrumentation plan and the code, writes the card's scaffold on one base target under the edit contract (R-TS-SYN-3), and revises it from the reach-check feedback (R-TS-SYN-7). |
| Fuzz operator | Runs Phase 1: `just extract-invariants` or `just extract-states`, naming the registry, then `just check-invariants`. Sets `STATELENS_KB` for the campaign. Clones the repository on a dedicated machine or container and starts a campaign in that clone (Phase 2), optionally followed by a synthesis, then runs the StateLens fuzz targets and scaffolds they built (Phase 3). Investigates the instrumented checkout when something panics or a synthesis reports a finding candidate, then discards it. |

---

## 5. Terminology

| Term | Meaning |
|---|---|
| Subsystem | One of the three parts of the code that StateLens covers: `simplex` (`consensus/src/simplex`), `marshal` (`consensus/src/marshal`) or `qmdb` (`storage/src/qmdb`). |
| Component | A part of a subsystem that gets its own beacon probes in Phase 2: the voter, batcher and resolver actors in Simplex; the core, standard and coding components in marshal; the variants `any`, `current`, `immutable`, `keyless` and `store` and the sync engine in qmdb. |
| Invariant | A property, in English, that must always hold for an honest replica, for the protocol, or for a database. It is implementation-agnostic and long-lived, and it constrains one subsystem. |
| Invariant registry | A directory `statelens/invariants/<subsystem>/`, and its local part `statelens/invariants.local/<subsystem>/`, which git ignores and which holds the invariants derived from the knowledge base. Every file in either is active for every profile that binds the subsystem, unless the operator names the invariants a campaign binds (R-P2-1). |
| Source kind | Where an invariant or a target state came from: `human`, `issue`, `design`, `comment`, `spec`, `paper`, `kb`, and, for a target state only, `test` and `text` (R-TS-REG-2). |
| EARS | Easy Approach to Requirements Syntax: the sentence patterns (ubiquitous, state-driven, event-driven, unwanted behavior, complex) used for invariant statements. |
| State | A side-effect-free expression over runtime values: a field, a flag, an enum variant, a length, or a side-effect-free accessor. |
| State transition | The ordered pair of states observed at the program points before and after an operation. |
| State coverage | The set of states and transitions the counter table has seen. A probe's pair is either a transition's before and after, or two states observed together where a decision is made. |
| Semantic beacon | Developer-written evidence that a state or transition matters: in the code an enum, a `debug_assert!`, a comment or a state flag; in the knowledge base a finding. A beacon is not a state itself. |
| Knowledge base (KB) | A read-only corpus of developer artifacts outside this repository, which beacon extraction retrieves from. The first corpus is the findings repository; an operator may add others. |
| Search index | The local index `kb search` answers from: the findings' state-bearing sections, the corpus's design documents, and this repository's comments, doc comments and Markdown, each chunk with an embedding (R-KB-9). |
| Finding | One report in the knowledge base: structured claim fields (`module`, `severity`, `remediation_status`, and others) plus prose sections, of which the root cause, the lifecycle events and the trigger conditions carry the state evidence. |
| Assertion | Instrumentation (`sl_assert!` or `sl_implies!`) that panics when an invariant is violated. |
| State probe | Instrumentation that marks the counter for `hash(site, a, b)` in the StateLens counter table as seen. It never changes behavior. |
| Invariant probe | A state probe derived from an invariant, e.g. the pair (precondition, conclusion) that `sl_implies!` records. |
| Beacon probe | A state probe (`sl_probe!`) derived from a semantic beacon and not tied to any invariant. |
| Ghost state | Extra fields added only so that assertions and probes can use history or data from other actors or replicas: in existing structs, per replica (`Ghost`), or shared by all honest replicas (`Global`). |
| Byzantine guard | The check, built into every StateLens macro and ghost-state accessor, that skips replicas the harness marked as compromised. |
| False invariant | A deliberately false invariant in `false-invariants/<subsystem>/`, with a `FALSE-` ID. A working campaign must panic on it; it is used only to test the workflow itself. |
| Byzantine mode | The `STATELENS_BYZANTINE` switch: what instrumentation does when a compromised replica reaches an instrumented site. `skip` (default) is the Byzantine guard; `check` checks the replica like an honest one; `panic` panics, to test the guard. |
| Profile | What a campaign binds, instruments, tests and builds: `simplex` (the Simplex subsystem, chapter 8), `marshal` (both consensus subsystems, chapter 9) or `qmdb` (chapter 10). |
| StateLens variant | A fuzz target that a campaign creates from an existing target of its profile's package. It runs the body of that target between `statelens::reset()` and `statelens::clear_compromised()`, and is named `<target>_statelens`. Variants are derived; scaffolds (chapter 11) are written by an agent. |
| Campaign | Phase 2 for one profile: materialize -> instrument -> build -> test, in place in a fresh clone of the repository, then stop. Phase 3 runs the targets it built. |
| Test gate | The tests of the profile's subsystems that a campaign runs on the instrumented tree before it hands the targets over: the engine-level tests for the consensus profiles, every qmdb test for qmdb. |
| Corpus root | One directory `STATELENS_KB` names, holding findings and documents. It lies outside this repository and is read-only. |
| Target state | A concrete state of honest replicas that only a specific multi-step history reaches, such as the precondition of a reported bug. It is a goal for fuzzing, never a property or an oracle. |
| Card | One file `target-states/<subsystem>/TS-NNNN.md`, or in the local part `target-states.local/<subsystem>/`, that describes one target state: Statement, Rationale, Evidence, History and Knobs (R-TS-REG-3). |
| History | The numbered events `E1` to `En` of a card that reach its target state; `En` is the target state itself. Each event before `En` has one `Check` line, and `En` has one `Holds` line. |
| Entity | A replica, view, payload, parent, certificate or incarnation that a History line names with a short name. `v as E1` is the entity an earlier event bound; a name without `as` means "for some". |
| Knob | An uncertain parameter, timing or ordering of a card that the scaffold leaves to libFuzzer: one input byte that picks a value from a domain whose first value is the source's. |
| Scaffold | A state-reaching fuzz target that a synthesis writes for one card on one base target, named `<base>_tsNNNN_statelens`. It fixes the card's history, exposes its knobs, and reports which stages it reached. |
| Base target | The existing fuzz target of the profile's package whose driver, input type and oracles a scaffold reuses. |
| Shape A | A scaffold that pins its base target's input so that the base's own driver produces the History, and reads the stages after the run. |
| Shape B | A scaffold that drives the History online, stage by stage, and then hands off to its base target's free-running phase. |
| Stage | A scaffold's check of one History event, named by its event number: `held`, `missed` or `unverifiable` (`withheld` in a control run). |
| Witness | What establishes a held stage: `exact` harness observables keyed by the bound entities, an `intrinsic` probe observation whose two values come from one object, or a `construction` the harness performed itself (R-TS-SC-3). |
| Position | A value of the event sequence of one input, which every probe observation and every event of the scaffold's helper (a witness read, a stamped entry, a construction action, a restart, the handoff) advances. Positions are unique and strictly ordered within the input; a restart's position names the incarnation it begins (R-TS-FB-1). |
| Canonical input | The empty input. Every knob then takes its source value, so a scaffold run on it replays the source's history. |
| Handoff | The instant a scaffold's scripted history ends and the base's free-running phase, the continuation, begins: `En`'s witness, read freshly at that instant, must hold, and every fault the prefix opened is still in place. |
| Recovery | The release of the faults the prefix opened (a crashed replica, a partition, a held message). It is part of the continuation and never precedes the handoff. |
| Control run | A replay of the canonical input with one harness event of the History withheld, which must lose the target state; it shows that the History, not chance, produced it. |
| Reach verdict | The result of a scaffold's reach check, such as REACHED or PARTIAL (R-TS-SYN-6). It is reported and never an oracle; whether a scaffold is fuzzed depends only on the vetoes, the build and the test gate. |
| Finding candidate | A failure in a replay of a scaffold, other than a scaffold error, wherever in the code it happens. It is preserved, and a human triages it like a crash in Phase 3 (R-P3-2). |
| Scaffold error | A failure the scaffold's helper raises itself, with `[statelens-scaffold]` and a panic location in `target_states/mod.rs`, before any engine starts, for a condition of the scaffold's own code or knob bytes; the only failure attributed to the scaffold. |
| Edit contract | The one set of rules, with its mechanical guards, for every edit a synthesis makes to the checkout (R-TS-SYN-3). |

---

## 6. Workflow Overview

### 6.1 Phases

```
PHASE 1: DISCOVER INVARIANTS  (and target states; repeatable, any time, committed to the repo)

  operator: just extract-invariants [--registry simplex|marshal|qmdb] [--number N] <kind> <source>...
            just extract-states [--registry simplex|marshal] [--number N] [--local] <kind> <source>...

  source (issue | design doc | code comments | spec | paper | knowledge-base findings;
          for target states also test | text)
        |
        v
  analyst agent (claude|codex) + prompt + reference output format
        |
        v
  statelens/invariants/<subsystem>/INV-xxxx.md      (active immediately)
  statelens/target-states/<subsystem>/TS-xxxx.md    (active immediately; chapter 11)
        |
        v
  human reviews: edits, deletes, or adds entries by hand


PHASE 2: INSTRUMENT THE CODE AND GENERATE FUZZ TARGETS
         (a campaign, in place in a fresh clone of the repo)

  operator: git clone <repo>; export STATELENS_KB=<the findings repository>
            cd statelens; just campaign [--profile simplex|marshal|qmdb] [--invariants LIST]
    -> materialize runtime support, fuzz targets, runner hooks
    -> instrumenter agent (claude|codex):
         registry invariants -> assertions + invariant probes + ghost state
         current code, and the knowledge base it queries while reading it
                             -> beacon probes (Simplex actors; marshal components;
                                qmdb variants and sync)
                             -> audit: the sites that commit each action, the
                                checks that were missing, an honest status
    -> build the StateLens fuzz targets (up to 3 agent repair attempts)
    -> run the test gate                  (panic => STOP, human investigates)
    -> print the commands that run the StateLens fuzz targets

  then, for simplex or marshal, a synthesis in the same checkout (chapter 11):
  operator: just synthesize [--profile simplex|marshal] [--match GLOB]...
    -> per target-state card, one at a time:
         synthesizer agent (claude|codex): a scaffold on a base target, under the edit contract
         -> vetoes, build, reach check: replays of the empty input and a control
         -> up to 3 refinements           (replay failure => finding candidate, kept as is)
    -> print each verdict and the command that runs each scaffold


PHASE 3: RUN FUZZ TARGETS  (operator, in the instrumented clone; discard it afterwards)

  operator: cd statelens; just run <target> -- -fork=N    (or just fuzz <profile>)
            just fuzz <simplex|marshal> --state-reaching  (campaign, synthesis, scaffolds)
    -> libFuzzer runs until it panics or is stopped   (panic => human investigates)
```

### 6.2 Running continuously

Every campaign starts from scratch:
- The invariant registry grows between campaigns through Phase 1 and human review. The invariant registry in the checkout is used, including uncommitted edits.
- Each campaign needs a fresh clone, because it instruments the checkout in place.
- Beacon probes are discovered again each time, from the current code and the knowledge base, so they follow code changes without maintenance.
- The knowledge base is queried afresh each campaign, so a finding added since the last one is available without any maintenance here. A campaign without `STATELENS_KB` still runs, with code-mined beacons only.
- Invariants are bound to the code again each time, so a refactor does not invalidate the registry. Only invariants whose concepts disappear entirely stop binding, and the instrumentation plan reports them.
- The target-state registry grows the same way, through Phase 1 and human review. Cards never name probe labels, which change with every campaign; scaffolds are written again after every campaign, against that campaign's probes, and exist only in its checkout.
- No corpus, instrumentation or scaffold carries over between campaigns.

---

## 7. Requirements

### 7.1 Subproject layout

R-LAYOUT-1. Everything that lasts between campaigns lives under `statelens/`:

```
statelens/
  docs/
    PRD.md                    this document
    SPEC.md                   technical specification
  README.md                   how to run the three phases
  config.env                  defaults: agent, models, toolchains
  justfile                    recipes: extract, campaign, synthesize, run, fuzz, clean, check-*
  .gitignore                  ignores the generated campaign/ and extract/ directories,
                              config.local.env, invariants.local/ and target-states.local/
  invariants.local/           invariants derived from the knowledge base; never committed
  target-states.local/        target states from private sources (R-TS-P1-3); never committed
  target-states/              target-state cards, one file per state, all active (chapter 11)
    simplex/
      TS-0003.md
      ...
    marshal/
      TS-0001.md
      ...
  invariants/                 the registries: one file per invariant, all active
    simplex/
      INV-0001.md
      ...
    marshal/
      ...
    qmdb/
      ...
  false-invariants/           deliberately false invariants; a working campaign must panic on them
    simplex/
      FALSE-0001.md
    marshal/
      FALSE-0002.md
    qmdb/
      FALSE-0003.md
  examples/                   worked analyses, reference material for Phase 2 agents
    statelens_commonware_voter_example.md
    statelens_commonware_marshal_example.md
  templates/
    invariant.md              reference format for invariant entries
    target-state.md           reference format for target-state cards
  prompts/
    analyst.md                Phase 1: shared rules and output format
    analyst-issue.md          Phase 1: GitHub issue or PR -> invariants
    analyst-design.md         Phase 1: design document -> invariants
    analyst-comment.md        Phase 1: code comments of files or modules -> invariants
    analyst-spec.md           Phase 1: formal specification -> invariants
    analyst-paper.md          Phase 1: paper -> invariants
    analyst-kb.md             Phase 1: knowledge-base findings -> invariants
    state-analyst.md          Phase 1: any source -> target-state cards
    instrument.md             Phase 2: shared rules and runtime API
    instrument-invariants.md  Phase 2: invariants -> assertions, invariant probes, ghost state
    instrument-beacons.md     Phase 2: code and knowledge base -> beacon probes
    instrument-audit.md       Phase 2: audit the bindings against the commit sites
    discover-flow.md          method: follow state across functions without a data-flow tool
    repair.md                 Phase 2: fix instrumentation that does not build
    synthesize.md             synthesis: one card on one base -> one scaffold, under the edit contract
    subsystems/
      simplex-analyst.md      Phase 1: what the analyst needs to know about Simplex
      marshal-analyst.md      Phase 1: the same for marshal
      simplex-instrument.md   Phase 2: rules for instrumenting Simplex code
      marshal-instrument.md   Phase 2: rules for instrumenting marshal code
      qmdb-analyst.md         Phase 1: what the analyst needs to know about qmdb
      qmdb-instrument.md      Phase 2: rules for instrumenting qmdb code
      simplex-synthesize.md   synthesis: what the synthesizer needs to know about Simplex
      marshal-synthesize.md   synthesis: the same for marshal
  runtime/                    source templates copied into the source tree during Phase 2
    statelens.rs              guard, counter table, probe/assert macros, ghost state,
                              probe-trace read side; one template for every profile
    target_states.rs          scaffold helper: knobs, stages, witness records, reach lines
  scripts/
    statelens.py              lint, lint-examples, lint-plan, lint-prompts, extract, kb,
                              search-index, code, ast, targets, campaign, synthesize,
                              coverage, clean
    test_statelens.py         tests for the paths that fail quietly
```

R-LAYOUT-2. Files under `runtime/` are templates. No crate the workspace builds compiles them, and committed code does not include them as a module. No `Cargo.toml` the workspace builds exists under `statelens/` on the main branch: the workspace and CI name their crates and fuzz directories one by one, so a crate here would be built by nothing and checked by nothing (G6). One explicit exception: `statelens/differential/`, the test-only crate of the differential test (AC-25), has its own `Cargo.toml` with an empty `[workspace]` table, so cargo's upward search stops at it and the root workspace never lists or builds it, no CI job names it, and `statelens/scripts/differential.sh` builds it only in a scratch worktree. It includes the templates by `#[path]`, byte-identical, without a copy or an edit, and nothing in it is reachable from a workspace build, test, lint or fuzz job, so G6 and R-NF-4 hold; its lockfile is not committed. The templates, and every other `*.rs` file under `statelens/`, must stay `rustfmt`-clean, because CI's `just check-fmt` formats every `*.rs` file in the tree, and the crate's two manifests pass `just check-toml-fmt` likewise.

R-LAYOUT-3. Nothing outside `statelens/` is committed, except the visibility change of AC-25 in `consensus/fuzz/marshal/src`: `pub(crate)` widened to `pub` on the scenario primitives the differential test imports (the modules `environment`, `harness`, `input`, `recording_resolver` and `scenarios` of `scenarios/`, `app`, `twins` and `twins::stack` of `marshal/end_to_end/`, and their items), with the two lint `#[allow]`s this requires and no logic, signature or doc change; nothing under `consensus/src` changes. The recipes live in `statelens/justfile`.

### 7.2 Invariant registry

R-REG-1. Each invariant is one Markdown file `invariants/<subsystem>/INV-NNNN.md` with YAML front matter, where `<subsystem>` is `simplex`, `marshal` or `qmdb`. Every file in a registry is active: the next campaign whose profile binds the subsystem binds it, unless the operator names the invariants that campaign binds (R-P2-1). There is no approval status; humans review, edit, and delete files. IDs are global: a new ID is one more than the highest ID in any registry. An ID therefore names one invariant across registries, and it is reused only if the file with the highest ID is deleted. A registry has a local part, `invariants.local/<subsystem>/`, which git ignores: it holds the invariants derived from the knowledge base (R-KB-6, R-P1-7), campaigns bind it like the tracked part, and its IDs come from the same counter.

R-REG-2. Front-matter fields:

| Field | Required | Values / notes |
|---|---|---|
| `id` | yes | `INV-NNNN`, equal to the file name |
| `title` | yes | One line, at most 80 characters. |
| `source_kind` | yes | `human`, `issue`, `design`, `comment`, `spec`, `paper`, `kb`. A target-state card may also use `test` and `text` (R-TS-REG-2). |
| `source_ref` | yes | Issue URL, document path, or `file:line` / module path. |
| `scope` | yes | One or more of the registry's values. `simplex`: `protocol`, `replica`, `voter`, `batcher`, `resolver`, `cross-actor`. `marshal`: `protocol`, `replica`, `core`, `resolver`, `standard`, `coding`, `application`, `cross-component`, where `resolver` means marshal's backfill resolver. `qmdb`: `database`, `proof`, `sync`, `any`, `current`, `immutable`, `keyless`, `store`. |

R-REG-3. Required body sections:
- **Statement**: the invariant in English, implementation-agnostic, stated for the registry's system: an honest replica, or the protocol for scope `protocol`, in simplex and marshal; the database in qmdb.
- **Rationale**: why it must hold (protocol or design argument, or reference).
- **Evidence**: what the source says. For `issue`, describe the violating scenario.

Optional body sections:
- **Preconditions / assumptions**: e.g. "after recovery from the journal".
- **Observation hints**: non-binding pointers to where the concepts live in today's code. Phase 2 may ignore them.

R-REG-4. The Statement must not reference identifiers that exist only in the implementation. Implementation hints go in "Observation hints".

R-REG-5. Statements use EARS patterns where possible: ubiquitous (`The replica shall ...`), state-driven (`While ..., the replica shall ...`), event-driven (`When ..., the replica shall ...`), unwanted behavior (`If ..., then the replica shall ...`), or complex. In the qmdb registry the system is the database (`The database shall ...`). The pattern determines how the invariant is checked (SPEC section 4.4).

R-REG-6. The reference format is `templates/invariant.md`. Example:

```markdown
---
id: INV-0001
title: No finalize and nullify in the same view
source_kind: human
source_ref: consensus/src/simplex/actors/voter/round.rs
scope: [replica, voter]
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

### 7.3 Knowledge base

R-KB-1. **What it is.** A read-only corpus of developer artifacts outside this repository, which the campaign's beacon step queries while it instruments (R-FB-4). The first corpus is the findings repository: several hundred reports, each with structured claim fields and fixed prose sections, of which the root cause, the lifecycle events and the trigger conditions carry the state evidence. Its curated `kb/` and `config/` documents are the paper's design-document tier. An operator may add further corpora of the same kinds.

R-KB-2. **Location.** `STATELENS_KB` names one or more corpus roots, each outside this repository. A root that is missing or unreadable is reported and skipped. With none left, or the variable unset, the `kb` commands other than `search` fail and a campaign runs without a knowledge base, saying so, with its beacon step working from the code alone. Nothing else in StateLens depends on the knowledge base: campaigns and Phase 1 invariant extraction work without it.

R-KB-3. **Read-only.** StateLens never writes to a corpus root.

R-KB-4. **Index and retrieval.** Nothing loads a corpus into a prompt. It builds or refreshes an index of the claim fields of every finding (identifier, `module`, `summary`, `tags`, severity, confidence, remediation status, and the state the finding's directory records), and the agent then retrieves on demand through six commands: `modules` (what the registry covers), `find` (ranked findings, each with the files and symbols it cites), `grep` (prose snippets of the state-bearing sections), `cites` (a path in this repository to the findings about that code), `show` (one finding's claim block, or one state-bearing section) and `search` (snippets ranked by meaning for a question in plain words, R-KB-9). A whole document is read only once a snippet justifies it.

R-KB-5. **Scope filter.** Every query over findings is restricted to the `module` values of the subsystem whose component is being instrumented (R-S-KB-1, R-M-KB-1, R-Q-KB-1). Findings about other crates are out of scope for a beacon. Knowledge-base documents carry no `module`; the component being instrumented and the agent's judgment scope those instead.

R-KB-6. **Disclosure.** The knowledge base is private and an instrumented checkout is never pushed, so knowledge-base material may reach the instrumented tree. What must not happen is knowledge-base content reaching a commit of this repository: the index and the campaign logs stay in the git-ignored output directory, invariants derived from findings stay in the git-ignored local registry, and nothing derived from a finding is committed here.

R-KB-7. **Self-reflection filtering.** A query returns snippets that can use the right words for the wrong entity. The agent judges each against the state it is probing and discards the rest; the plan records what a probe watches and where the agent found it.

R-KB-8. **Every finding state is usable.** A finding's state and remediation status are shown with every hit, not used to filter it. A finding judged invalid may still describe a real transition, and a fixed finding is exactly the historical evidence the paper generalizes from. A beacon is a feedback signal, not an oracle, so weak evidence costs coverage, never correctness.

R-KB-9. **Semantic search.** `kb search` answers a question in plain words with snippets ranked by meaning and by words together: the paper's on-demand retrieval of ranked snippets that connect a semantic feature to files and functions. Its index covers the findings' state-bearing sections, the `kb/` and `context/` documents of each corpus root, and the comments, doc comments and Markdown documentation of this repository at HEAD, outside `statelens/`. Findings keep the module filter of R-KB-5, a code hit names its `path:line@commit` and the item it documents or sits in, and test code is hidden unless asked for. The index lives in the git-ignored output directory, like everything derived from the knowledge base (R-KB-6). `just search-index` builds or updates it, embedding on the CPU with the pretrained model `config.env` names, which it downloads only when the model is not on disk yet. An update embeds only the text that changed, and a query never uses the network. Without the model, the search ranks by words alone. A campaign refreshes the index before it instruments anything, and a failure there is a warning.

### 7.4 Phase 1: discover invariants

R-P1-1. Invariant extraction is a single agent invocation per source (set of similar sources, e.g. set of files).
It is parameterized by the agent (`claude|codex`), the registry (`simplex`, `marshal` or `qmdb`), the source kind, the source reference, and optionally the number of invariants to write. Interface, run in `statelens/`:
`just extract-invariants [--registry simplex|marshal|qmdb] [--number N] <kind> <source>...`, e.g. `just extract-invariants issue <url>`. The registry defaults to `simplex`. The agent comes from `config.env`, the `STATELENS_AGENT` environment variable, or `--agent`.

R-P1-2. Each source kind has one prompt file, `prompts/analyst-<kind>.md`, appended to the shared `prompts/analyst.md`, which includes the registry's part, `prompts/subsystems/<subsystem>-analyst.md`. Every prompt:
- casts the agent as an analyst for that source kind;
- tells it to read the source (and any code it needs for context);
- tells it to write zero or more invariant files that strictly follow `templates/invariant.md`, with EARS statements, the right `source_kind` and `source_ref`, and IDs starting at the next free ID, which the script computes.

R-P1-3. Supported sources:
- GitHub issues and PRs (read via `gh`, or the GitHub REST API or web fetch when `gh` is not installed).
- Design documents (local paths or URLs).
- Code comments (a file or module path under `consensus/src/simplex`, `consensus/src/marshal` or `storage/src/qmdb`, matching the registry).
- Paper (page, line); the script converts a PDF to text when `pdftotext` or `pypdf` is available.
- Formal spec in Quint, TLA+, Lean (`consensus/src/simplex/replica.qnt:34`)
- Knowledge-base findings (`kb`): the findings of the corpus roots given, or of `STATELENS_KB`, whose `module` belongs to the registry (R-P1-7).

Target states take the same sources, and tests and plain text besides (R-TS-P1-2).

R-P1-4. For `issue`, the agent writes the invariant(s) that the issue's bug violated or could have violated, generalized from the specific bug.

R-P1-5. Phase 1 does no deduplication, scoring, or approval. Its files are active as soon as they are written; humans review, edit, maintain, or delete them before the next campaign. The script lints the new files and reports any change the agent made to existing files of every registry, invariants and target-state cards (R-TS-REG-1), tracked and local alike, whichever kind the run writes. Because a Phase 1 agent can write anywhere in the tree it runs in, and that tree is the operator's own rather than a discarded checkout, the script also compares the whole worktree before and after the run and reports any path the agent changed outside the registry trees, its own logs excepted. Such a change is a problem, not a warning: the run reports it and exits nonzero.

R-P1-7. **Count and findings.** `--number N` bounds an extraction: the agent writes the N invariants the sources justify best, fewer when they justify fewer, and never invents one to reach N; more than N new files is reported as a problem. For `kb`, the agent reads the findings in the registry's scope only through the `kb` commands (R-KB-4) and writes the invariants the reported bugs violated, generalized as for issues, weighing a finding's state as evidence: one judged invalid is no evidence of a rule. Those invariants go to the local registry, never the tracked one (R-KB-6), and a `comment` source outside the registry's code is refused, so a corpus root cannot be read as a code comment into the tracked registry.

### 7.5 Phase 2: instrument the code and generate fuzz targets

R-P2-1. A campaign runs in place in the operator's checkout: the operator clones the repository, where StateLens lives, and runs the campaign in that clone. StateLens does not make another clone. The checkout must have no tracked changes outside `statelens/` and no instrumentation from an earlier campaign. The campaign instruments the checkout in place and never commits; the operator fuzzes in the checkout and discards it afterwards. Uncommitted edits to the registries are used. It takes the agent (`claude|codex`), from a config file (`config.env`), the environment or the CLI; the profile (`simplex`, the default, `marshal` or `qmdb`), from the CLI; and an optional selection of invariants, `--invariants LIST`, from the CLI, where `LIST` is a comma-separated list of `<registry>/INV-NNNN` ids, or of bare `INV-NNNN` ids when the profile binds one registry, and the flag may be repeated. Without a selection the campaign binds every invariant of its profile's registries; with one it binds the invariants the lists name and no other. The selection is applied after the registries are collected, so a local invariant, and under `STATELENS_FALSE_INVARIANTS=1` a false one (`simplex/FALSE-0001`), can be named too, and the bound set keeps the registries' order. A bare id under a profile that binds two registries is a setup failure that names the `<registry>/INV-NNNN` form; an id of a registry the profile does not bind, an id no file provides, or a list that names nothing is a setup failure that lists the ids available. The selection changes which invariants are bound and nothing else: the beacon probes, which are feedback and not oracles, are discovered as always. The campaign records the ids it bound and the number available. It also reads `STATELENS_KB` to find the knowledge base, and runs without one. There are no other campaign parameters and no seed corpus. Synthesis is not a campaign parameter: it is a separate step on a checkout that a campaign instrumented (R-TS-SYN-1). The campaign passes no arguments to libFuzzer; the operator gives them in Phase 3.

R-P2-2. Steps, in order; R-S-P2-1, R-M-P2-1 and R-Q-P2-1 say what each step does for their profile:
1. **Materialize.** Copy `runtime/statelens.rs` into the profile's subsystem (`consensus/src/simplex/`, or `storage/src/qmdb/` for qmdb) and register it as a module. Add `sancov` to the dependencies of that crate. For the consensus profiles, patch the twins runner in `consensus/fuzz/core` so that it publishes the compromised set to the StateLens runtime before starting nodes and checks the participant index mapping; the `simplex` profile patches the other simplex runners that run a real engine under a Byzantine identity the same way (section 8.4). Patch the deterministic runtime so that a fresh runtime clears StateLens ghost state (R-INS-5). Add the profile's fuzz targets. Every edit is anchored on an exact line of the current code, and the campaign stops if an anchor has moved.
2. **Instrument invariants.** Run the instrumenter agent with `prompts/instrument-invariants.md` over every invariant the campaign binds (R-P2-1), in batches of 8 within one registry. For each invariant it adds assertions, invariant probes, and any ghost state needed.
3. **Instrument beacons.** Run the instrumenter agent with `prompts/instrument-beacons.md` once for each component of the profile. It adds beacon probes, discovered from the component's current code and from the knowledge base it queries while reading it. Without a knowledge base the step proceeds from the code alone. Then run the instrumenter once more over the batches of step 2 with `prompts/instrument-audit.md`, which re-reads each Statement against the sites that commit the actions it names, adds the checks that are missing and can be added, and corrects a plan section whose status claims more coverage than it has (R-INS-8). The audit is the last agent pass, so no agent edits the tree it reviewed before the plan is checked and the targets are built. `STATELENS_AUDIT=0` skips the audit.
4. **Write the instrumentation plan.** The agents record, in `statelens/campaign/plan.md`, each invariant -> the sites and ghost fields used, and each beacon probe -> its site, what it observes, and where the agent found it. The operator uses it when investigating. If the agent could not bind an invariant, the plan says so and gives the reason. The script adds an `unbound` entry for any invariant the agent skipped, a summary, and a check that instrumentation changed no file outside the profile's subsystems. It also lints the plan against its own claims (R-INS-8) and reports the problems as warnings, because the plan is the agent's own account of what it bound.
5. **Build.** Run `cargo check` of the profile's crate, `commonware-consensus` or `commonware-storage` (library and tests, stable toolchain), and the sanitizer build of the profile's fuzz targets (pinned nightly). On errors, the agent repairs its own instrumentation (as in StateLens section 5), without weakening assertions, for at most 3 attempts.
6. **Test.** Run the test gate: the gated tests of the profile's subsystems on the instrumented code (the engine-level tests for the consensus profiles, every qmdb test for qmdb), together with the tests of the StateLens runtime module. Any failure stops the campaign for human investigation.
7. **Hand over.** Print the result and the command that runs each fuzz target in this checkout. The campaign does not run the fuzzer; the operator does, in Phase 3 (7.6).

R-P2-3. The only output of a campaign is its result: one of `READY` (the StateLens fuzz targets are built and the test gate passed), `PANIC (tests)`, `BUILD FAILED`, or `SETUP FAILED`. It is printed with the checkout location and, where there is one, the first panic message. A `READY` result also prints the command that runs each StateLens target and the command that replays a crash. The standard artifacts described in 7.10 hold the crashes that Phase 3 finds.

R-P2-4. **Cryptography (decision).** StateLens fuzz targets use only the `cert_mock` certificate scheme: the mock scheme in `consensus/src/simplex/mocks/scheme.rs`, which `consensus/fuzz/core` imports as `cert_mock`. Every target instantiates the harness with a `cert_mock`-based Simplex type from `consensus/fuzz/core/src/simplex.rs`, such as `SimplexCertificateMock`. No target uses ed25519, BLS12-381, or secp256r1 schemes. A campaign refuses to materialize a target that breaks this rule; for the marshal variants, R-M-P2-2 says how this is checked. The rule concerns the consensus targets: no qmdb target signs anything (R-Q-P2-2). The rule covers fuzz targets only; the test gate (R-P2-2 step 6) runs the engine-level tests with their own fixtures. It applies to scaffolds too: a synthesis refuses to build one that breaks it (R-TS-SYN-4), so this rule takes precedence over R-TS-SYN-6, which fuzzes every scaffold that builds, and a source test's real cryptography is re-expressed on `cert_mock`.

R-P2-6. **Worked analyses.** `examples/` holds one worked analysis per consensus subsystem, written against real code; qmdb has none yet. The Phase 2 prompts carry the transferable craft themselves -- what makes a state worth probing, how a wide dimension becomes one probe pair, and the readings of a Statement that are too strong and the ones that are too weak -- and name the examples only as reference material an agent may open. A prompt does not inline them: each is tens of thousands of tokens, several times the prompt, and a worked analysis of one component should not decide what another component's states are. Because they name real functions and fields, `just check-examples` fails when a name they cite no longer exists.

R-P2-5. **Recipes.** `just campaign` runs a campaign and no fuzzer, as R-P2-2 step 7 says. `just run <target>` fuzzes a target a campaign built, and `just fuzz <target>` is a convenience that does both in order, inferring the profile from the target's prefix and refusing a name that is no profile's. Given a profile name instead of a target, `just fuzz` runs every target that profile builds: one after another by default, or together with `--parallel`; `--tmux` implies `--parallel` and gives each target its own tmux window; `--fuzz-targets GLOB`, which may be repeated, narrows them to the ones a shell pattern names. `--invariants LIST`, which may be repeated, goes to the campaign, which then binds only the invariants it names (R-P2-1); it is refused with `--skip-campaign`, which runs no campaign, and with a single target. With `--state-reaching`, `just fuzz` runs the profile's scaffolds instead of its variants, after a campaign and a synthesis, and `--state-targets GLOB` selects the cards (R-TS-P3-1). A double-dash flag `just fuzz` does not know is refused rather than passed to libFuzzer, whose arguments take one dash or follow `--`. With `--skip-campaign`, `just fuzz` skips the campaign and runs the targets a campaign already built in the checkout, whatever that campaign's result, which is how an operator continues after a campaign that built its targets and stopped at the test gate. `--skip-synthesis`, its analogue for scaffolds, needs `--state-reaching` and fuzzes the scaffolds synthesis already built in this checkout, whatever their verdicts, without the synthesis preflight: the way to keep fuzzing after the checkout drifted from the synthesis baseline, for example when an upstream fix was merged into it; synthesis itself still refuses such a checkout (R-TS-P3-1). No time limit is imposed, so a target runs until it stops unless `-max_total_time` or `-runs` is passed; the sequential form says so, because there the first target would be the only one to run. `just test` runs only the test gate on the checkout as it stands, so a fix made by hand to an instrumented checkout is checked before it is fuzzed. `just check-plan` checks an instrumentation plan against its own claims and the instrumented code, expecting a section for each invariant the checkout's campaign bound, and `just check-prompts` checks that the specification still quotes the prompts verbatim, with `--write` to refresh the copies. `just coverage <profile|target...>` reports what the corpora a run built reach (R-P3-4), `just search-index` builds or updates the index `kb search` answers from, and `just search` asks it a question (R-KB-9). `just extract-states` and `just synthesize` are the recipes of Target-State Synthesis (R-TS-P1-1, R-TS-SYN-1). `just clean` undoes what a campaign or a synthesis wrote to a checkout: it deletes the files a campaign, an instrumenter or a synthesizer added and restores the paths they edit to `HEAD`, printing what it would do and acting only with `--yes`, and afterwards it checks that nothing in scope still differs from `HEAD` rather than reporting success on trust. It leaves `campaign/` and `extract/` alone, and it restores whole paths, so an edit of the operator's own inside them is lost.

### 7.6 Phase 3: run fuzz targets

R-P3-1. The operator runs the StateLens fuzz targets in the instrumented checkout, with the commands that a `READY` campaign or a synthesis printed, through `just run` in `statelens/`, which runs a target from the fuzz package that defines it. The operator chooses which targets to run, for how long, and with which libFuzzer arguments (for example `-fork=N` or `-max_total_time=<s>`). StateLens neither runs nor supervises the fuzzer. The one exception is the reach check of a synthesis, which replays fixed inputs through a scaffold to verify it and is not fuzzing (R-TS-SYN-5).

R-P3-2. A run ends when the target panics or the operator stops it; libFuzzer, including its fork mode, stops at the first crash. A panic is an oracle failure (7.9), and the operator investigates it with the crash artifacts (7.10). A failure in a reach replay of a scaffold, other than the helper's own scaffold error, is a finding candidate and is investigated the same way (R-TS-SYN-6).

R-P3-3. After fuzzing and any investigation, the operator discards the checkout. It is never reused for another campaign (R-P2-1).

R-P3-4. **Coverage.** `just coverage <profile|target...>` reports what the corpora a run built reach: it replays each StateLens target's corpus under coverage instrumentation and writes an HTML report per target, plus one merged over the profile's targets, under the fuzz package's `coverage/`. Each report is scoped to the code the profile instruments, and carries two summaries, one for that code and one for the whole workspace. A target with no corpus is skipped, so the command follows whatever the operator chose to run in Phase 3. A scaffold counts as a target of its profile (R-TS-P3-2). The reports are read by a person; nothing in a campaign or a synthesis depends on them.

### 7.7 Instrumentation rules

R-INS-1. **No code removal.** The agent may add code, fields, ghost state, helper functions, module-level statics, and hooks. It must not delete or change existing logic. The only allowed change to an existing line is wrapping an expression in a block, keeping its tokens; each such edit is listed in the plan. The only intended behavior change is a panic when an invariant is violated.
When the agent adds code, it must mark it as instrumentation with a comment line `// [statelens] <tag>` directly above it. Tags: `INV-NNNN` for assertions and invariant probes, `ghost:INV-NNNN` for ghost state, `beacon:<label>` for beacon probes, and `me` for code added only to make the replica index available.

R-INS-2. **Byzantine guard.** Every assertion, every probe, and every access to `Ghost` or `Global` is guarded. The StateLens macros and ghost-state accessors call `statelens::should_check(me)`, which skips replicas that `statelens::is_byzantine(me)` reports as compromised, so no call site can omit the guard. Ghost fields added to existing structs (R-INS-5) may be updated without the guard: each belongs to one replica, its updates change no behavior (R-INS-3), and only guarded assertions and probes act on it, so a compromised replica's fields are updated but never checked. `STATELENS_BYZANTINE` does not apply to these updates. `me` is the replica's own participant index; R-S-INS-1 and R-M-INS-1 give its sources in each consensus subsystem, and qmdb, which has no replicas, passes `None` (R-Q-INS-1). `is_byzantine` reads the compromised set published by the harness (section 8.4). A replica with no participant index (`me() == None`) is treated as honest. For testing, `STATELENS_BYZANTINE=check` checks compromised replicas like honest ones, and `STATELENS_BYZANTINE=panic` panics when one reaches an instrumented site (AC-7).

R-INS-3. **Non-interference.** Assertions, probes, and ghost updates observe program state without changing the semantics or control logic of the protocol or its implementation. Until an invariant is violated, an instrumented replica or database takes the same branches, keeps the same state, and sends, writes and returns the same things as the original code. Instrumentation may compute from any state it can reach, but it writes only its own state: ghost state, probe counters, the replica-index fields it adds (R-INS-2), and, while a scaffold watches, the probe trace of the read side (R-TS-FB-1). It must not:
- assign to or mutate existing variables, fields, or collections, whether directly, through `&mut` methods, or through interior mutability;
- call methods whose reads change state that any code, tests included, can observe, such as an LRU lookup that changes the eviction order;
- add a `return`, `break`, `continue`, or `?` that can leave or skip original code, or change which branch the original code takes;
- keep in ghost state a handle whose count or lifetime any code, tests included, can observe: channel endpoints, `Arc`s such as marshal's blocks, or values whose `Drop` has an effect;
- clone a block; keep its digest and height instead;
- `await`;
- spawn tasks or take locks;
- touch the runtime context, RNG, clock, network, storage I/O, metrics, or logging;
- change the order or content of messages;
- consume values the original code later relies on.

Tests count because the test gate runs them on the instrumented tree. Exception: instrumentation may force a memoized decode, such as `Lazy::get` or `==` on a `Lazy`, even on original values; filling that cache is not a write. Ghost state may keep clones of decoded messages that hold `Bytes`, such as votes. No other cache is exempt: filling `CodedBlock::shards`, for example, runs an erasure encode, can panic, and changes what `shard()` returns.

This also keeps a crash reproducible from the same input on the same instrumented tree.

R-INS-4. **Assertion form.** Assertions use the StateLens macros `sl_assert!(me, "INV-NNNN", cond, ...)` and `sl_implies!(me, "INV-NNNN", pre, post, ...)`, invoked by module path (`crate::simplex::statelens::sl_implies!`), because `simplex` is declared inside `stability_scope!`. Marshal code invokes them by the same path, and qmdb code as `crate::qmdb::statelens::sl_implies!`, for the same reason. A violation panics with a message starting `[statelens][INV-NNNN] replica=<index>`, followed by the invariant title and a short dump of the values involved. One invariant may produce several assertion sites.

R-INS-5. **Ghost state.**
- Ghost fields may be added to existing structs (e.g. `voter::State`, `voter::Round`, `batcher::Round`, `resolver::State`). Their updates need no Byzantine guard (R-INS-2).
- Cross-actor and cross-restart invariants may use per-replica ghost state (`Ghost`, `with_ghost`) in `statelens.rs`, keyed by participant index and shared by all actors and components of the replica, in both consensus subsystems. qmdb keeps its history in `Global` (R-Q-INS-2).
- `protocol`-scope invariants may use ghost state shared by all honest replicas (`Global`, `with_global`).
- Ghost state lives for one run: it is cleared before every fuzz input and whenever a fresh deterministic runtime starts (for example each seed of a multi-seed test), and it survives a crash-restart from a checkpoint. Keeping it per thread is safe because the deterministic runtime runs all tasks on the calling thread.
- The probe trace of the read side (R-TS-FB-1) lives for one input: `statelens::reset()` clears it, and a fresh runtime does not; a fresh runtime only starts the next run number within the input.
- Cross-actor assertions must allow for mailbox delivery lag. They must hold under any delivery order the implementation allows, not only when actors are in step.

R-INS-6. **Cost.** Probes and assertions are O(1) or bounded by what the code tracks (the views of a replica, the operations of a batch). No unbounded scans on hot paths. Ghost history is kept precisely because it outlives the implementation's own pruning, so it is not bounded by the tracked views: it is indexed for the question the assertion asks -- a second collection holding only the queried entries, or a field holding the last one, maintained where the history is written -- and never filtered or walked at the assertion.

R-INS-7. **Scope.** The agent edits only non-test code of the profile's subsystems: `consensus/src/simplex/`, excluding `mocks/` and `scheme/`, and, for the `marshal` profile, `consensus/src/marshal/`, excluding `mocks/`; for the `qmdb` profile, `storage/src/qmdb/`, excluding `benches/`. Each invariant is bound only in the code of its own subsystem. The agent may also add initializers of new fields in struct literals anywhere. It does not edit `Cargo.toml` files or any fuzz package; the campaign script makes those edits. A campaign stops if instrumentation changed a file outside the profile's subsystems. This scope is the instrumenter's; the synthesizer is a second agent role, whose edits follow the edit contract instead (R-TS-SYN-3).

R-INS-8. **Assertion sites and what a status claims.** An invariant about an action is checked where the action is committed: the point past which it is visible outside the replica or the database (a signature exists, a message reaches a mailbox or the broadcaster, a record is appended, a certificate is accepted, the view moves; a batch is applied, a commit becomes durable, a value or a proof is returned). Where the implementation splits the decision from the commit across an await, a mailbox, a reply handler or a later call, the check goes at the commit and reads the state there; a check at the decision site may be kept beside it, and never replaces it, because everything the replica learns while the work is outstanding is invisible at the decision. Every path that reaches a commit site is covered, including journal replay, retries and rebroadcasts. The plan records every commit site and whether it is checked, and the status says what that adds up to: `bound` when every commit site of every action the Statement names carries the check and the condition checked is the Statement itself, `partial` for anything less, `unbound` when nothing was added. The audit pass of R-P2-2 step 3 re-checks these claims with the agent, and `just check-plan` re-checks mechanically what it can: the ledger against the status, the status against the assertions present in the instrumented code, and every ledger entry marked as checked against the file and function it names, so that the pass which writes the ledger cannot also certify it and one assertion cannot cover every site of its file. A commit site the ledger never names is beyond any lint, so the campaign also reports how many commit sites are listed, how many are not checked, and how the assertion sites are distributed over the instrumented sources, where a layer nobody checked appears as a source with none.

### 7.8 Feedback (StateLens adaptation)

R-FB-1. **Counter table.** `statelens.rs` owns a `sancov::Counters<65536>` table. It is registered with libFuzzer once, under `cfg(fuzzing)` and unless `STATELENS_FEEDBACK=0`, and zeroed before every fuzz input. The mechanism is the same as `consensus/fuzz/simplex/src/state_cov.rs`, but the table is separate. A variant keeps the feedback of the target it was derived from, so the variants of the simplex targets with `state_cov` or happens-before feedback run it beside this table. Once the table is registered, libFuzzer stops printing `cov:`; runs are compared by `ft:`. A scaffold reads the probe trace of the runtime's read side (R-TS-FB-1) and adds one feature to this table per stage it holds (R-TS-FB-2); neither changes what a variant records.

R-FB-2. **Probe primitive.** `sl_probe!(me, "label", a, b)` sets the counter at `hash(site, a, b) mod N` to 1 (presence only), so a state observed many times in one input yields a single feature. `site` is the label plus the call location, so every call site is distinct. `a` and `b` are small discrete values that convert into `u32` (`bool`, `u8`, `u16`, `u32`); raw `u64` values do not compile.

R-FB-3. **Invariant probes.** `sl_implies!` records `(pre, post)` at every assertion site of the form "if A then B", which rewards reaching an invariant's precondition, not only the code around it. Where meaningful, the agent also adds a bucketed margin to violation for numeric invariants. The macro records `(pre, pre && post)`, so an assertion whose `post` is `false`, or which sits on the branch the replica takes only once it is about to violate the invariant, records the same pair on every passing execution and gives the fuzzer nothing; there the agent adds a probe where the state is classified, so that reaching the protected state is rewarded when the replica handles it correctly. A constant `true` `post` is not that case, because the pair follows the precondition.

R-FB-4. **Beacon probes.** For each component of the profile, the agent discovers semantic beacons as it reads the component's code: state enums, flags and optional fields of per-view or per-height state, and `debug_assert!`s and comments that describe fragile states. It queries the knowledge base (section 7.3) when a candidate needs developer context the source does not carry, so a state that has gone wrong before can be probed even when the code looks unremarkable. It emits probes that record `(pre, post)` pairs around transitions, 20 to 60 per component. Priority goes to:
- transitions caused by side effects or asynchrony (StateLens O2);
- conditions set in one component and used in another through mailboxes (StateLens O1).

R-S-FB-1, R-M-FB-1 and R-Q-FB-1 list the beacons of each subsystem.

R-FB-5. **Discretization.**
- Probes never hash raw views, heights, locations, digests, commitments, keys, values, payloads, or timestamps.
- Views, heights and locations are recorded relative to something (e.g. `delta(view, last_finalized)`, `delta(view, current_view)`, a height relative to marshal's processed floor, or a location relative to qmdb's inactivity floor) and bucketed with `bucket` (0, 1, 2, 3-4, 5-8, 9+).
- Counts are bucketed the same way; enums go through `disc`, booleans through `flag`, and two small values can share one side through `pack`.
- The agent counts a probe's pair space before adding it (`bucket` 6 values, `delta` 11, `flag` 2, an n-bit mask 2^n, `disc` the variant count, `pack` the product of what it packs) and keeps it within the budget by dropping or coarsening a dimension, rather than relying on the combinations a run is expected to reach. A smaller count is claimed only where the site bounds the input, and the plan says what bounds it.
- Probes do not include the replica index, so symmetric replicas share features.

R-FB-6. **No mode switching.** libFuzzer's edge coverage stays on. The StateLens counters only add features. There is no plateau-based switching.

### 7.9 Oracles

R-OR-1. **Oracles** are:
1. the assertions of the invariants of the profile's registries (7.7);
2. the existing checks of the fuzz harnesses, run exactly as the original harnesses run them today: `invariants.rs` and related modules for the Simplex variants, the marshal harness checks for the marshal variants, and the model checks of the qmdb targets for the qmdb variants;
3. any other panic in the process.

Stage checks and reach verdicts are not oracles: a scaffold runs its base target's oracles unchanged (R-TS-SC-5), and a missed stage never panics.

R-OR-2. Every oracle failure is a panic. The panic propagates to libFuzzer as a crash. This already happens: the deterministic runtime defaults to `catch_panics: false`; the Simplex harness's `fuzz()` and its audit entry points catch a panic with `catch_unwind` and re-raise it with `resume_unwind`, and the marshal and qmdb harnesses let it propagate.

R-OR-3. Any test failure in step 6 stops the campaign, and any crash stops the fuzz run that found it (libFuzzer stops at the first crash). A human decides whether it is an implementation bug, a wrong invariant, or a wrong binding. Fixes to wrong invariants are made in the registry by hand.

### 7.10 Crash artifacts

R-ART-1. Reuse the existing fuzz artifacts unchanged:
- libFuzzer writes the crashing input to the artifact directory of the target's package: `consensus/fuzz/simplex/artifacts/<variant>/` for a simplex variant, `consensus/fuzz/marshal/artifacts/<variant>/` for a marshal variant, or `storage/fuzz/artifacts/<variant>/` for a qmdb one;
- `just run <target> <crash_file>` replays it, with the `STATELENS_BYZANTINE` value of the run that found it: a guard-test crash (`STATELENS_BYZANTINE=panic`) exists only in that mode;
- for a Simplex variant, `CONSENSUS_FUZZ_LOG=1` also prints the decoded `FuzzInput` (`print_fuzz_input`); the marshal harnesses print only their existing logs;
- the panic message carries the `INV-NNNN` ID.

R-ART-2. The operator investigates inside the instrumented checkout before discarding it. The checkout keeps the instrumentation plan, the campaign logs, the rendered prompts, and the instrumentation diff under `statelens/campaign/`, and after a synthesis the reach reports, each pair's diff and the preserved replay failures under `statelens/campaign/reach/` (R-TS-SYN-7). The campaign never commits. No extra bundle format is added.

### 7.11 Agent abstraction

R-AG-1. The agent is a parameter (`claude|codex`). Prompts are plain Markdown and do not depend on either agent. `scripts/statelens.py` maps the parameter to the non-interactive invocation of each CLI (`claude -p`, `codex exec`).

R-AG-2. Phase 2 agents use the tools their CLI provides: file reading, text search, build and test. StateLens adds the code index of R-AG-4 and the syntax-tree queries of R-AG-5, but supplies no data-flow tool, so following a value through a computation is search and reading. The knowledge base matters for the same reason: a finding names the files and symbols it concerns, so the instrumenter starts from a citation rather than from a blank search.

R-AG-3. Phase 1 agents, the state analyst included, run restricted in the operator's working tree: file edits, read-only tools, `gh`, and `curl`; a `kb` extraction gets the `kb` commands instead of `gh` and `curl`. Phase 2 agents, the synthesizer included, run with full permissions in the checkout, so campaigns and syntheses must run on a dedicated machine or container.

R-AG-4. StateLens identifies entities in the code it instruments: where a name is defined, every reference to it, the call sites outside its definition with the enclosing function, and what a definition calls. Text search cannot do this here, because the names collide: `proposal` is five different methods of this crate and `broadcast_notarize` is both a field and a method of the same type. A campaign builds the index before it instruments, and instrumentation then edits the files the index describes. Which function calls which survives that, but line numbers do not: a probe inserted above a reference moves it. Since a line number is the whole answer, a stale one is not a degraded answer but a wrong one, so the build records the sources it indexed and every query rebases its hits onto the files as they now stand. A hit that cannot be placed is reported as lost rather than guessed, and an entity added after the build is absent from the index however well hits are rebased, so a query states what it cannot answer: which indexed files have changed, which are gone, and which source files have appeared since. It states this before choosing any result, so that an answer of `nothing matches` carries the warning too. Sites in test code are hidden unless asked for, because nearly three quarters of the crate is test code and it shares files with the code it exercises, and the boundary is read from the file as it now stands. A missing index degrades a sweep to search and reading; it does not fail it.

R-AG-5. StateLens reads the syntax tree of a file to answer what the index cannot: whether a site writes an entity or only reads it, and which item a comment documents. The first matters because a probe belongs where state changes, and the index records that a line mentions an entity without recording which it does. The second matters because a comment about an ordering, a race or a case that cannot happen names the state it concerns, and a comment is a token in the tree, so it can be told from the same words in code or in a string. A tree carries no types, so it gives shape where the index gives identity, and the two are used together. Where shape cannot decide, the answer says so: parsing does not expand macros, so a site inside a macro body is reported as unknown rather than dropped or guessed, and in this crate that is common because much of the concurrency sits inside `select!`.

### 7.12 Non-functional

R-NF-1. Correctness first: no probe or ghost update may change protocol behavior (R-INS-1, R-INS-3), and neither may any synthesis edit (R-TS-SYN-3).

R-NF-2. Determinism: an input that crashes on an instrumented tree crashes the same way when replayed on that tree with the same `STATELENS_BYZANTINE` value.

R-NF-3. Overhead: measure the exec/s of each StateLens target against its original target (plain edge coverage) in an uninstrumented checkout at the same commit. There is no hard limit, but a slowdown above 2x should be reported as a problem with the instrumentation. R-S-NF-1, section 9.4 and section 10.4 name the original targets. A scaffold has no original target: it is measured against the StateLens variant of its base target (R-TS-NF-3).

R-NF-4. The committed subproject does not change workspace build, lint, formatting, stability checks, tests, or CI (G6, R-LAYOUT-2).

R-NF-5. Committed files use plain ASCII.

### 7.13 Acceptance criteria

AC-1. `templates/invariant.md`, `prompts/analyst.md`, and the five per-kind analyst prompts exist. Running Phase 1 on a real GitHub issue with each agent produces at least one file that passes `just check-invariants`.

AC-2. On `main`, `just check-fmt`, `just lint`, `just test -p commonware-consensus`, `just test -p commonware-storage`, and the CI fuzz matrix behave exactly as before this project (G6).

AC-3. **Invariant registries.** `just check-invariants` reports no problem. `invariants/simplex/` holds INV-0001 to INV-0018, and `false-invariants/simplex/` holds FALSE-0001. `just extract-invariants --registry marshal comment consensus/src/marshal/mod.rs` writes files into `invariants/marshal/`, numbered from the next global ID.

AC-14. **Knowledge base.** With `STATELENS_KB` pointing at the findings repository, the `kb` commands answer from the index: `modules` lists the module values in scope, `find` and `cites` return only findings whose `module` is in the subsystem's filter, `cites` maps a component directory to the findings that name files under it, `show` refuses a section that is not state-bearing, and `search`, after `just search-index`, ranks snippets from the findings in scope, the `kb/` and `context/` documents, and this repository's comments and Markdown, naming `path:line@commit` and the item for a code hit.

AC-15. **No knowledge base.** With `STATELENS_KB` unset, a campaign warns that there is no knowledge base, renders the beacon step without query commands, and still reaches `READY`.

AC-16. **Audit pass.** A campaign whose first pass leaves a commit site unchecked ends with that invariant's plan section carrying the site in its `Sites` ledger and a `Status` the ledger supports, and the `audit` and `plan` lines of the summary report the change. With `STATELENS_AUDIT=0` the pass does not run, no `audit` line is printed, and the campaign still reaches `READY`.

AC-17. **Subproject checks.** `just check-plan` exits 0 on a plan whose claims match its ledger and the instrumented code, and 3 naming the section when a `bound` leaves a commit site unchecked or a site it calls checked asserts nothing there. `just check-prompts` exits 0 when section 13 of the specification quotes every prompt verbatim, and 3 naming the file otherwise.

AC-21. **Findings extraction.** With `STATELENS_KB` set, `just extract-invariants --registry qmdb --number 3 kb` writes at most three new invariants, all in `invariants.local/qmdb/`, none of which git lists, and all lint-clean; a `comment` extraction given the corpus root refuses it and names the `kb` command.

AC-29. **Invariant selection.** `just campaign --invariants INV-0002` on a fresh clone binds INV-0002 and no other invariant: `campaign/meta.json` lists it alone under `invariants` and the number of simplex invariants under `invariants_available`, the plan lists it alone, the campaign says `1 of <n> invariant(s) bound`, the beacon probes are added as without the flag, and `just check-plan` expects that one section. A bare id with the `marshal` profile, an id of a registry the profile does not bind, an id no file provides, and an empty list each stop the campaign with `SETUP FAILED` (exit 2) before any agent runs, the first naming the `<registry>/INV-NNNN` form and the others listing the ids available. `just fuzz simplex --invariants INV-0002` runs that campaign and then the variants; with `--skip-campaign` or with a single target it is refused (exit 1).

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
- builds a StateLens variant of every existing simplex fuzz target (G4), which the operator runs in Phase 3.

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
| Knowledge base + retrieval | A knowledge base of findings and curated documents outside this repository, which the agent queries on demand while it adds beacon probes. Commands over a structured index and full-text search answer structural questions, and `kb search` ranks snippets for a question in plain words by meaning over the findings, the design documents and this repository's comments and documentation, as the paper's vector-indexed knowledge base does (R-KB-9). The agent judges each snippet before using it (section 7.3). The invariant registry has no counterpart in the paper: it holds the properties the assertions check. |
| Probes: `(site, a, b)` into a shared-memory bitmap | Same, into an in-process `sancov` counter table (libFuzzer is in-process, so no IPC), presence only |
| Validation: compile, test suite, LLM repair | `cargo check` and the fuzz build with up to 3 agent repairs, then the engine-level test gate |
| Oracle: crashes / ASan | Invariant assertions plus existing protocol checks, all as panics |
| Re-instrument each engine release | Instrument a fresh clone for each campaign |
| Dual feedback with plateau switch | Always-on state counters on top of edge coverage |
| Every thread and process is instrumented | Only honest replicas are observed (Byzantine guard) |

### 8.3 Requirements

#### Phase 2

R-S-P2-1. For the `simplex` profile, the steps of R-P2-2 do the following:
1. **Materialize.** Add one StateLens variant per existing simplex fuzz target to
   `consensus/fuzz/simplex`, and the guard hooks of section 8.4 to its runners.
2. **Instrument invariants.** Bind the simplex registry.
3. **Instrument beacons.** Once for each of the voter, batcher and resolver; then audit
   the bindings.
4. **Write the plan and check scope,** with `consensus/src/simplex/` allowed (R-INS-7).
5. **Build.** The sanitizer build of every variant.
6. **Test.** The test gate is the engine-level Simplex tests of `commonware-consensus`
   (`simplex::tests`, including the `slow` group), together with the tests of the
   StateLens runtime module. The Twins tests are excluded, because they run two live
   engines under one replica identity. The gate is about 240 tests and takes about 2
   minutes on 16 cores.
7. **Hand over.** The summary gives one run command per variant.

#### Instrumentation

R-S-INS-1. Identity in Simplex. `me` is `scheme.me()`: the voter, batcher and resolver
each hold the replica's signing scheme. Where no scheme is in scope, the agent adds a
`// [statelens] me` field, set where the struct is created.

#### Feedback

R-S-KB-1. While instrumenting a Simplex component, a knowledge-base query covers the findings whose `module` names Simplex (`consensus/simplex` and its submodules). The findings repository holds 68 of them, 25 of which were judged invalid and are still usable (R-KB-8).

R-S-FB-1. The instrumenter discovers Simplex beacons in the voter, batcher and resolver, and queries the knowledge base about them (R-KB-4):
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

R-S-NF-1. The original target of a variant is the target it was derived from, against which
R-NF-3 measures overhead. With minimal instrumentation
`simplex_cert_mock_twins_mutator_statelens` and its original both run at about 13 executions
per second per process, so the operator runs a variant with libFuzzer's `-fork=N`.

R-S-NF-2. The simplex profile derives a StateLens variant from every `simplex_*` target of
`consensus/fuzz/simplex`, as the marshal and qmdb profiles do for their packages, so a target
added to the package is covered by the next campaign. A campaign builds all of them, 21 at
the reference commit, and the operator chooses which to run (R-P3-1).

### 8.4 Fuzz harness

The marshal variants (9.4) share the runtime module and the Twins runner hook described
here.

#### Variants

Every simplex target gets a variant `<target>_statelens` (R-S-NF-2), and its driver decides
which states it can reach. Twins is the best available way to put an honest replica into
states that only Byzantine peers can cause: equivocating proposals and votes, split network
views, conflicting certificates. In the Twins drivers a compromised participant runs two
halves under one identity: in TwinsCampaign both are real engines, and in TwinsMutator the
secondary is a `Disrupter` that mutates content according to `input.strategy`. Honest
replicas therefore face split network views and, under TwinsMutator, content mutations as
well, which is where replica-local and cross-actor invariants are most likely to break. The
other drivers reach other states: ByzzFuzz rewrites what a Byzantine engine sends, Mallory
runs an adaptive Byzantine actor, Chaos crashes and restarts honest nodes, and FaultyNet
partitions the network.

Only the variants whose adversary runs a real Simplex engine exercise the Byzantine guard:

| Existing targets (the variant appends `_statelens`) | Driver | Adversary runs a real Simplex engine | Guard |
|---|---|---|---|
| `simplex_cert_mock_twins_campaign`, `simplex_cert_mock_twins_campaign_audit`, `simplex_cert_mock_twins_campaign_hb`, `simplex_cert_mock_twins_campaign_state_cov`, `simplex_cert_mock_twins_mutator`, `simplex_cert_mock_twins_mutator_audit`, `simplex_cert_mock_twins_mutator_hb`, `simplex_cert_mock_twins_mutator_state_cov`, `simplex_cert_mock_shuffled_twins_mutator` | Twins | yes: the compromised primary, and under TwinsCampaign its secondary too | Twins runner hook |
| `simplex_cert_mock_chaos_twins` | Chaos-Twins | yes: both engines of the twin | Chaos-Twins hook |
| `simplex_cert_mock_byzzfuzz` | ByzzFuzz | yes: an engine whose messages are rewritten on the wire | ByzzFuzz hook |
| `simplex_cert_mock_audit` | audited Standard | only for inputs that draw the RejectView choice: the Byzantine participants then run an engine whose application certifies what honest ones reject | audit hook |
| `simplex_cert_mock`, `simplex_cert_mock_byzantine_first_leader`, `simplex_cert_mock_faulty_net`, `simplex_cert_mock_hb`, `simplex_cert_mock_hb_state_cov`, `simplex_cert_mock_state_cov`, `simplex_cert_mock_audit_notarize_omission` | Standard, FaultyNet, audited Standard | no: the Byzantine nodes are `Disrupter`s | none needed |
| `simplex_cert_mock_mallory` | Mallory | only after an amnesia restart, which brings its Honest-role node back on empty storage and makes it Byzantine; its Byzantine roles run an adversary actor, not an engine | Mallory hook |
| `simplex_cert_mock_chaos` | Chaos | no: every node is honest | none needed |

#### Shape of a TwinsMutator variant

```
libFuzzer   (started by the operator: just run simplex_cert_mock_twins_mutator_statelens)
  |  bytes -> FuzzInput (existing Arbitrary impl in consensus/fuzz/core)
  v
a StateLens variant  (consensus/fuzz/simplex, derived from the target it is named after)
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

#### Byzantine guard plumbing

`commonware-consensus` cannot depend on the fuzz crates, so the guard state lives in `consensus/src/simplex/statelens.rs`, which the campaign materializes. Marshal code uses the same module. The campaign patches the twins runner (`consensus/fuzz/core/src/lib.rs`, where `compromised` is built from the sampled case) to:
- call `statelens::set_compromised(...)` before any engine starts;
- assert that every scheme's own index (`scheme.me()`) equals its position in the participant list.

The `simplex` profile patches the four other runners of the table the same way: ByzzFuzz publishes its Byzantine index, Chaos-Twins the index of its twin, the audited Standard runner its Byzantine participants when they run an engine, and Mallory its node when an amnesia restart brings it back on empty storage. Without its hook, Chaos-Twins would also merge the histories of the twin's two engines, which share one participant index and so one `Ghost`, and Mallory's restarted node, which may sign what it signed before the restart, would be checked against its own earlier history. The marshal profile builds none of these variants and makes none of these edits.

The fuzz target calls `statelens::reset()` before every input and `statelens::clear_compromised()` after `fuzz()` returns, not inside the runner, so compromised replicas stay guarded while the runtime shuts down.

The campaign also patches the deterministic runtime: `Runner::new` calls a hook that StateLens registers, which clears ghost state. A fresh runtime therefore starts with no history (each fuzz input, each seed of a test), while a runtime resumed from a checkpoint keeps it.

The guard is built into the StateLens macros and ghost-state accessors, which call `statelens::should_check(me)` with `me` from `scheme.me()`. The guard is keyed on participant identity, so it covers every engine that runs under a compromised identity: the Twins primary, the TwinsCampaign secondary and both engines of the Chaos-Twins twin. A `Disrupter` secondary runs no Simplex actor code. The compromised set is thread-local, which is sound because the deterministic runtime runs every task on the thread that starts it.

### 8.5 Acceptance Criteria

AC-4. A `simplex` campaign on a fresh clone with at least one invariant in the simplex registry:
- materializes the runtime and one variant per simplex target;
- instruments the code;
- writes the instrumentation plan;
- builds;
- runs the test gate;
- reports `READY` with one run command per variant, and each command starts its variant.

AC-5. On an instrumented checkout, the `ft:` value reported by libFuzzer after a fixed time is higher with StateLens feedback than with `STATELENS_FEEDBACK=0`, which shows the probes fire.

AC-6. **False-invariant test.** A campaign run with `STATELENS_FALSE_INVARIANTS=1` includes the deliberately false invariant `false-invariants/simplex/FALSE-0001.md` ("the replica shall not accept a nullification certificate") and stops with `[statelens][FALSE-0001]` in the test gate. If the tests do not reach it, a short run of one of the printed `run` commands panics with it.

AC-7. **Guard test.** With `STATELENS_BYZANTINE=panic`, a short run of a variant whose adversary runs a real Simplex engine (8.4) panics with `[statelens][BYZANTINE]` as soon as that engine reaches an instrumented site; `simplex_cert_mock_audit_statelens` does so only for an input that draws the RejectView choice, and `simplex_cert_mock_mallory_statelens` only after an amnesia restart. The other variants never do. With the default (`skip`), no such panic occurs, and the participant index check of a runner hook never fails.

AC-8. **Determinism test.** Replaying a crashing input with `just run <variant> <crash_file>` on the same instrumented tree, with the `STATELENS_BYZANTINE` value of the run that found it, reproduces the same panic.

### 8.6 Risks and Open Points

| Risk | Mitigation |
|---|---|
| Low throughput (about 13 executions per second per process). | libFuzzer's `-fork=N`; the existing `invariants.rs` checks may be adjusted later (section 3.2). |
| The Twins tests are not part of the test gate. | The fuzz harness itself exercises Twins scenarios with the correct guard. |
| A campaign builds every simplex variant, 21 at the reference commit, which lengthens its build step. | The operator chooses which variants to run (R-P3-1). |
| A driver added to `consensus/fuzz/simplex` gets a variant at once, and may run a real engine under a Byzantine identity without publishing it, so the guard would check that replica. | Review a new driver against the table of 8.4, and give it a hook like the others when it runs such an engine. |

---

## 9. StateLens for Marshal

### 9.1 Overview

Marshal is the second subsystem of the Simplex implementation, and the `marshal` profile
covers it. The profile takes the approach of the existing marshal fuzz targets, which run
real Simplex engines that drive marshal. A `marshal` campaign therefore:
- binds the simplex and marshal registries, each invariant in the code of its own
  subsystem;
- adds beacon probes to the Simplex actors and to marshal's core, standard and coding
  components; marshal's backfill resolver, ancestry and application code get none in Phase 2,
  though a Phase 1 sweep does cover them;
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
   Byzantine role (9.4). No simplex variant is added; the marshal profile derives only from
   the targets of `consensus/fuzz/marshal`.
2. **Instrument invariants.** Bind the simplex registry, then the marshal registry.
3. **Instrument beacons.** Once for each of the Simplex voter, batcher and resolver, then
   for marshal's core, standard and coding components; then audit the bindings of both
   registries.
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
signing scheme. Marshal holds a scheme provider rather than a scheme, and looking a
provider up is not a read: an application may count lookups against the scope it serves
and retire it, so a lookup made by instrumentation can change what a later lookup of the
implementation returns. Instrumentation therefore learns `me` through a runtime helper
that reads a `ConstantProvider`, whose lookup only clones its scheme and which every
harness uses, and that reports any other provider as an unknown index without looking it
up:
- The core actor obtains `me` when it is created and passes it to the mailbox it returns,
  so the standard adapters can read it from the mailbox they hold.
- The coding adapter and the shards engine obtain it in the method that owns their
  provider.

The helper is the only source of `me` in marshal: reading `me()` from a scheme the
implementation holds would arm some sites of a component and not others under another
provider, and history one writes and another requires would be incomplete. A site whose
`me` is unknown gets no instrumentation. `None` means "not a participant"
and turns the guard off, so it never stands in for an unknown identity.

#### Feedback

R-M-KB-1. While instrumenting a marshal component, a knowledge-base query covers the findings whose `module` names marshal (`consensus/marshal` and its submodules `core`, `standard`, `coding`, `resolver`, `application` and `ancestry`). A `marshal` campaign also instruments the Simplex components, whose queries use the Simplex filter instead; a query never merges the two (R-KB-5). The findings repository holds 67 marshal reports, 17 of them judged invalid, and the largest group is about coding. Each beacon file goes to the registry of the subsystem whose code it names.

R-M-FB-1. The instrumenter discovers marshal beacons:
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

AC-10. **False invariants.** `STATELENS_FALSE_INVARIANTS=1 just campaign --profile marshal`
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
| Marshal sites are inert in tests whose provider is not a `ConstantProvider`, which includes every unit test of the shards engine, so the test gate screens less marshal instrumentation than it runs. | Every fuzz harness uses a `ConstantProvider`, so fuzzing runs every site. The coding tests screen the shards engine through the marshal test harness. SPEC section 8.5 lists what is inert. |
| The operator chooses which of the twelve variants to run. Skipping the Twins and wedge variants skips every variant in which the adversary runs Simplex or marshal code. | The summary lists every variant (SPEC section 8.3), and 9.4 says which have an adversary with a real stack. One Twins process measured 15 exec/s and 628 MB peak RSS. |
| Six beacon runs (three per subsystem) raise the probe count and the agent time. | The per-component budget of R-FB-4 applies to each of the six. |
| Marshal moves under `consensus/src/simplex/` (draft PR #4994). | Paths are profile data in `statelens.py`. When the move lands, the marshal root and test filter change, and the `simplex` profile's editable code must exclude `consensus/src/simplex/marshal/`. |
| Issue #4701 removes marshal's backward ancestry API. | Statements are implementation-agnostic (R-REG-4), and bindings are made again in every campaign. Observation hints may go stale. |
| The Twins observation wrappers forward completions through spawned tasks, so scheduling is sensitive. | R-INS-3; AC-12. |
| The wedge scenario's Byzantine role runs honest code. Guarding it hides its state from feedback. | Accepted, as required by G5. |
| The store variant has no peers and reaches only the core actor's store paths. | Accepted: the variants follow the existing target set. |

---

## 10. StateLens for qmdb

### 10.1 Overview

qmdb (`storage/src/qmdb`) is the family of log-based databases of the storage crate, and
the `qmdb` profile covers it. It shares the method, the runtime template, the prompts and the
scripts with the consensus profiles, and nothing else: no campaign instruments two crates. A
`qmdb` campaign:
- binds the qmdb registry, in the code of `storage/src/qmdb`;
- adds beacon probes to the five database variants and the sync engine;
- runs every qmdb test of `commonware-storage`;
- builds a StateLens variant of every existing qmdb fuzz target of `storage/fuzz`, which the
  operator runs in Phase 3.

qmdb code calls its own copy of the runtime module, `storage/src/qmdb/statelens.rs`, which a
campaign creates from the same template as the consensus copy (G8).

### 10.2 Background

- qmdb derives a database's state from an append-only log of operations, and a Merkle
  structure over the log authenticates it. The variants are `any`, `current`, `immutable`,
  `keyless` and the unauthenticated `store`. All change through batches that are applied
  and then committed, and each commit carries an inactivity floor below which operations may
  be pruned. The authenticated variants merkleize a batch before applying it, which gives the
  root it would produce; `store` finalizes a batch into a changeset and has no root. `sync` builds a database from an untrusted source up to a trusted
  target, and `verify` checks proofs.
- `storage/fuzz` has 17 qmdb fuzz targets. Each drives one variant through generated
  operation sequences, most on the deterministic runtime and against a model of the expected
  state. Some reopen the database within a run, `qmdb_current_recovery` injects storage
  faults and restarts from checkpoints, the sync targets build a database from a source, and
  `qmdb_verify_proof` checks proofs decoded from fuzzer bytes.
- The oracles of these targets compare what a database returns -- values, roots, proofs,
  recovered state -- with their model. Its internal state is neither a feedback signal nor
  checked by any oracle: batch chains and their staleness, the floor against the pruning
  boundary, a background sync in flight, the activity bitmap of a `current` database, and
  the state recovery rebuilds.

### 10.3 Requirements

#### Registry

R-Q-REG-1. qmdb Statements are about "the database": one database over its whole life,
restarts included. They use qmdb's terms: operations and their locations, keys and values,
active operations, the root, batches (merkleized, applied, stale; in `store`, finalized
changesets), commits, the inactivity floor, pruning, durability, recovery, proofs and sync
targets. As in R-REG-4, they never
name Rust identifiers. The scope values are `database`, `proof`, `sync`, and the variant a
property is about: `any`, `current`, `immutable`, `keyless` or `store`.

R-Q-REG-2. `false-invariants/qmdb/FALSE-0003.md` is the deliberately false qmdb invariant:
"the database shall not hold more than 64 operations in its log, counting the operations it
has pruned".

#### Phase 2

R-Q-P2-1. For the `qmdb` profile, the steps of R-P2-2 do the following:
1. **Materialize.** Copy the runtime module to `storage/src/qmdb/statelens.rs`, where its
   paths name `qmdb` and its consensus-only tests are left out, register it in
   `storage/src/qmdb/mod.rs`, add `sancov` to `commonware-storage`, and patch the
   deterministic runtime as every profile does. Add one StateLens variant per existing
   `qmdb_*` fuzz target to `storage/fuzz`. There is no runner hook: nothing in qmdb is
   compromised.
2. **Instrument invariants.** Bind the qmdb registry.
3. **Instrument beacons.** Once for each of `any`, `current`, `immutable`, `keyless`, `store`
   and the sync engine; then audit the bindings.
4. **Write the plan and check scope,** with `storage/src/qmdb/` allowed (R-INS-7).
5. **Build.** `cargo check` of `commonware-storage`, and the sanitizer build of every
   StateLens variant.
6. **Test.** Every qmdb test of `commonware-storage`, including the `slow` group, and the
   tests of the runtime module. There are no component tests: the qmdb tests drive whole
   databases.
7. **Hand over.** The summary gives one run command per StateLens variant.

R-Q-P2-2. R-P2-4 does not apply: no qmdb target signs anything.

#### Phase 3

R-Q-P3-1. The operator runs the variants with `just run` or `just fuzz` in `statelens/`
(R-P2-5), which runs a `qmdb_*` target from `storage/fuzz` on the same pinned toolchain as
the consensus targets. `STATELENS_BYZANTINE` has no effect.

#### Instrumentation

R-Q-INS-1. **Identity.** qmdb has no replicas and no participant index. Every site passes
`None` as `me`, which the Byzantine guard always checks.

R-Q-INS-2. **Ghost state.** History lives in `Global`, or in a ghost field of the database
when it need not survive a reopen. One run can hold several databases, such as a sync source
and its target, and a database can be reopened within a run, so `Global` keys history by an
identity a database keeps across a reopen, such as the partition its log uses: distinct
databases never merge, and a reopened database keeps its history.

R-Q-INS-3. **Commit sites.** In the authenticated variants a batch is merkleized in one call
and applied in another; in `store` it is finalized into a changeset and then applied.
`commit` or `sync` makes it durable later still, and another batch may be applied in between.
An invariant about the database's state is checked where the state changes or becomes
durable, not where it was computed (R-INS-8). A mutating method that fails consumes the
database, so checks sit on its success path.

#### Feedback

R-Q-KB-1. While instrumenting a qmdb component, a knowledge-base query covers the findings
whose `module` names qmdb (`storage/qmdb` and its submodules).

R-Q-FB-1. The instrumenter discovers qmdb beacons: batch chains and their staleness, the
inactivity floor against the pruning boundary and the log size, the activity bitmap of
`current`, a background sync in flight, recovery from a log that runs past its last commit,
sync targets and requests in flight, and the shape of proofs. Locations, floors and sizes
are recorded relative to one another, never raw (R-FB-5).

### 10.4 Fuzz harness

Every `qmdb_*` target of `storage/fuzz` gets a variant `<target>_statelens`, which calls
`statelens::reset()` before the target's body and `statelens::clear_compromised()` after
it. The targets do not share one shape: most open `fuzz_target!` over a structured input at
the top level, `qmdb_verify_proof` takes raw bytes, and `qmdb_current_mmb_prune_grow` is a
one-line target, which the derivation writes as a block first.

```
libFuzzer   (started by the operator: just run <target>_statelens)
  |  bytes -> the input type of the existing target
  v
<target>_statelens   (storage/fuzz, generated from <target>.rs)
  |  statelens::reset()
  |  the existing target's body, unchanged
  |  statelens::clear_compromised()      (a no-op: nothing is compromised)
  v
qmdb harness: a database, or a sync source and its target, on the deterministic runtime
  |  qmdb assertions and probes: any, current, immutable, keyless, store, sync
  v
existing model checks of the target  -> panic on violation
```

### 10.5 Acceptance Criteria

AC-18. **qmdb campaign.** A `qmdb` campaign on a fresh clone, with at least one qmdb
invariant:
- materializes one variant per qmdb fuzz target;
- instruments the code;
- writes the plan;
- builds;
- passes the test gate;
- reports `READY` with one run command per variant, and each command starts its variant.

AC-19. **False invariant.** `STATELENS_FALSE_INVARIANTS=1 just campaign --profile qmdb`
stops with `PANIC (tests)`, and the test log contains `[statelens][FALSE-0003]`.

AC-20. **Determinism.** Replaying the input of a crashing qmdb variant on the same tree
reproduces the same panic.

### 10.6 Risks and Open Points

| Risk | Mitigation |
|---|---|
| The qmdb registry starts empty, so a first campaign adds beacon probes only. | Phase 1 fills it: `just extract-invariants --registry qmdb comment storage/src/qmdb/...` and the other source kinds. |
| Several databases share one run, and history keyed carelessly merges them or loses a reopened database's past. | R-Q-INS-2 is in the prompt, and the plan names the key of every ghost field. |
| There is no worked analysis of qmdb for the agents to consult. | The prompts carry the method, and the Simplex and marshal analyses show it applied. Writing one is future work. |
| The storage targets other than `qmdb_*` (journals, archives, Merkle structures) get no variant, although qmdb builds on that code. | Accepted: the profile instruments qmdb code only (Non-Goals). |
| One code index serves one crate, so after a qmdb campaign the code queries answer about storage. | `just code-index --subsystem <name>` rebuilds it for another profile's crate. |

---

## 11. Target-State Synthesis

### 11.1 Overview

Target-State Synthesis reaches states that only a specific history of protocol events
produces: the states that tests, pull requests, bug reports and comments describe, and that
the drivers of the fuzz targets rarely reach. It covers the `simplex` and `marshal` profiles
and has three parts:
- **Phase 1** turns a source (a test, a GitHub issue or PR, a code comment, a document, a
  knowledge-base finding, or plain text) into a target-state card: a Statement of the state,
  the History of events that reaches it, and the Knobs the source leaves uncertain.
- **Synthesis**, a step after a campaign, writes one scaffold per card and base target: a
  dedicated fuzz target on an existing target of the profile, its base, that fixes the card's
  essential setup and History and leaves its knobs, timings and orderings to libFuzzer. The
  unit of synthesis is the pair (card, base): a card is synthesized on every selected base. The
  probes the campaign installed, together with harness observables, witness which stages of
  the History a run reached. A reach check replays fixed inputs through the scaffold, and its
  verdict drives up to 3 refinements.
- **Phase 3** fuzzes the scaffolds like any other target. An input that misses a stage
  continues into the base target's free-running phase and its oracles.

Synthesis never instruments: the probes stay part of the instrumented system under test and
serve every scaffold. Every edit a synthesis makes follows one edit contract (R-TS-SYN-3).
Every scaffold that passes the vetoes and builds is fuzzed, unless the rerun test gate removes it; its verdict is only reported.

`just fuzz simplex --parallel --tmux --state-reaching --state-targets TS-0004 --fuzz-targets "simplex_cert_*"`
runs a `simplex` campaign, synthesizes a scaffold for TS-0004 on each `simplex_cert_*` base
target, and runs each in a tmux window of its own; without `--state-targets`, every simplex
card gets a scaffold per base and a window each (R-TS-P3-1).

### 11.2 Background

- Every StateLens variant inherits its target's driver, which samples schedules, network
  faults, crashes and Byzantine behavior at random. A state that needs several events in a
  given order, at given replicas, is reached rarely or never. Two examples: the state behind
  the wedge that PR #4317 fixed, in which an honest replica certifies a notarized proposal
  after rejecting another header of the same payload, and the state of
  `test_standard_finalized_delivery_rejects_epoch_mismatch`
  (`consensus/src/marshal/standard/mod.rs`), in which a peer answers an outstanding request
  for a finalized block with a finalization that claims the wrong epoch. No variant arranges
  either history.
- The marshal scenario targets (`consensus/fuzz/marshal/src/scenarios/`, specified in its
  `specs/SPEC.md`, the scenario SPEC below) are the precedent. Each reproduces the
  state-producing prefix of a marshal standard test while the engines are stopped, checks the
  defining state at the handoff, and then starts the engines and fuzzes from there. They reach
  6 such states, and the method is static:
  - each scenario is hand-written Rust behind a closed enum, so a new state needs a human
    translation, a new variant and a recompile;
  - the prefix is fully fixed: libFuzzer chooses only what happens after the handoff;
  - a missed state panics, which libFuzzer records like a finding, and nothing reports how far
    the prefix got or refines it;
  - the handoff is checked through mailbox, resolver and buffer observables, never inside the
    replica;
  - the only sources are marshal standard tests.

  Target-State Synthesis keeps the scenario SPEC's rules where they apply -- name the source
  (S1), copy the history faithfully (S2), verify the state at the handoff (S3), tell
  incidental choices from essential ones (S7), fabricate nothing (I5) -- and makes the method
  dynamic: an agent extracts the card and writes the scaffold, the uncertain choices become
  knobs, a miss continues into free-running fuzzing instead of panicking, and stages are
  witnessed and refined. The scenario method is also the precedent the primitives are
  measured against: its prefixes are the one human-written definition of such states the
  repository has, so the differential test of AC-25 runs a TSS prefix of every scenario's
  source test beside the scenario's own prefix, on the same setup and input, and requires the
  same state and a REACHED verdict (SPEC section 18.10.1).

#### How SyzHarness maps onto Target-State Synthesis

SyzHarness synthesizes, from one Linux kernel patch, a Syzkaller pseudo-syscall that fixes the
setup and the call sequence that reach the bug, exposes the uncertain, bug-critical values to
the fuzzer, and is refined from reachability feedback. The paper never uses the term
Target-State Synthesis; the mapping is this project's:

| SyzHarness (Linux kernel) | This project (Simplex and marshal) |
|---|---|
| Input: one patch (commit message and diff) | A card extracted from a test, issue or PR, comment, document, finding or text (R-TS-P1-2) |
| Trigger scaffold: environment setup, object construction, syscall sequence | The base target's setup and the card's History, fixed by the scaffold |
| Uncertain, bug-critical knobs as parameters of the entry function | Knobs: input bytes that pick values, timings and orderings from domains (R-TS-SC-2) |
| Isolated configuration: only the new pseudo-syscall is enabled | A dedicated fuzz target per card and base |
| Hierarchical reachability: patched file, function and line (T_file, T_func, T_line) | Witnessed stages, one per History event (R-TS-SC-3) |
| At most 5 feedback iterations of hours of fuzzing each, and a separate compile-repair agent | At most 3 refinements, each judged by replays of fixed inputs; build failures are feedback to the same loop (R-TS-SYN-7) |
| A `main()` that runs the harness once with random values | The canonical input: the empty input, which replays the source's history (R-TS-SC-2) |
| Patch-differential validation: the crash occurs before the patch and not after it | The control run: withholding one harness event loses the target state (R-TS-SYN-5) |
| Oracle: KASAN | Invariant assertions and the base target's oracles, unchanged (R-TS-SC-5) |

The paper's failure analysis is why stages are witnessed by probes: in 14 of its 20 failures
the harness reached the patched file or function but not the condition the bug needs, which
the coverage of a location cannot tell apart. Here a stage is witnessed by a probe inside the
replica or by a harness observable keyed by the entities of the event (R-TS-SC-3).

### 11.3 Requirements

#### Registry

R-TS-REG-1. Each target state is one Markdown file, a card, `target-states/<subsystem>/TS-NNNN.md`, where `<subsystem>` is `simplex` or `marshal`. The registry has a local part, `target-states.local/<subsystem>/`, which git ignores (R-TS-P1-3). IDs come from one global `TS` counter over both parts and both subsystems, as invariant IDs do (R-REG-1). Every card is active: the next synthesis of the profile of the same name uses it. A card has no status field; humans review, edit and delete cards.

R-TS-REG-2. A card's front matter has the five keys of an invariant (R-REG-2), with `id` `TS-NNNN` and the scope values of its subsystem's registry. `source_kind` takes the kinds of invariants and two more, `test` and `text`. `source_ref` is an issue or PR URL with its merge commit (its head commit while unmerged), a pinned `path:line@commit` with the test's name, a document path or URL, or `text: <title>` (R-TS-P1-2).

R-TS-REG-3. The sections of a card, in order:
- **Statement**: one sentence, "While ..., the replica ...", about honest replicas.
- **Rationale**: what can go wrong in that state.
- **Evidence**: what the source shows, with pinned `path:line@commit` citations of at most about 40 lines each.
- **History**: the events `E1.` to `En.` that reach the state; `En` is the target state. Each event starts with its actor, `harness` or a replica's name, and names the entities it involves -- replicas, views, payloads, parents, certificates, incarnations -- with short names (R, v, d, p1). E1 to E(n-1) each have one indented `Check` line, which says the event happened; En has one `Holds` line, which says the target state holds at the handoff. Each line starts with the entities it binds, in parentheses: an entity shared with an earlier event is written `v as E1`, and a name without `as` is existential ("for some v"), as in `Check (R, v as E1, d as E4): R holds a notarization of d for v.` A replica's name starts with a capital letter and every other entity's with a small one, which is how the reach check tells replicas apart. An optional `Order:` line names the pairs of events that may happen in either order, each written `Ei and Ej in either order`.
- **Knobs**: "None.", or a table `| Knob | Event | Domain | Source value |` in which every domain has at least 2 values.
- **Observation hints**, optional: functions, types, tests and INV ids.
- **Source excerpts**: generated from the pinned citations, as for invariants.

R-REG-4 applies to the Statement and the History. A card never names a probe label, because labels change with every campaign. The reference format is `templates/target-state.md`.

R-TS-REG-4. `just check-invariants` lints cards too, with the rules of the registries (SPEC section 4.6) and two of their own. Rule 12 checks the History: numbering from `E1` without gaps, an actor for each event, `harness` or a replica's name, which starts with a capital letter, one `Check` line for each event before En and one `Holds` line for En, an entity list on each line, every `as Ek` naming an earlier event that binds that entity, and an `Order:` line, the last and not indented, whose pairs have the form above and name only defined events. Rule 13 checks the Knobs: "None.", or the table with its header and separator row, 1 to 16 rows, no empty cell, and in each row at least one event, all of which exist.

#### Phase 1

R-TS-P1-1. Target-state extraction works as invariant extraction does (R-P1-1): one agent invocation per source, or set of similar sources, run in `statelens/` as `just extract-states [--registry simplex|marshal] [--number N] [--local] <kind> <source>...`. The registry defaults to `simplex`; `qmdb` is refused. It renders one prompt, `prompts/state-analyst.md`, with the registry's part `prompts/subsystems/<registry>-analyst.md`, and applies the checks of R-P1-5 and the bound of R-P1-7 to cards: the new cards are linted, and a change to an existing card or invariant, a change outside the registry trees and StateLens' own outputs, or more than N new cards is a problem.

R-TS-P1-2. **Sources.** Every kind of R-P1-3, plus `test` and `text`. The agent writes the History from what the source says and confirms each event against the current code. It never invents an event the protocol cannot produce, never needs real cryptography, and may write zero cards. An event belongs to the History only if the state would differ without it; every other choice the source makes becomes a knob, with the source's value first, or is dropped (scenario SPEC S7). Per kind:
- `test`: `path:line[-end]` inside a test under the registry's source root or in its profile's fuzz package. The file exists at HEAD, where the card pins its citations; an untracked or merely staged test is committed first or given as `text`. The agent reads the test, its helpers and the code it drives. The test's checks on the state become `Check` and `Holds` lines, and its assertions on the outcome are dropped; a message the test puts straight into a mailbox becomes the protocol event that produces the same input.
- `text`: a file, or a literal that the script writes to `extract/` for the agent to read. Evidence quotes verbatim the passages that define the History, at most about 40 lines, and summarizes the rest. `source_ref` is `text: <title>` or the file's own path, never the copy in `extract/`.
- `issue`: `source_ref` names the URL and the merge commit, or the head commit of an unmerged PR, which is extracted again after the merge to pin its tests. Evidence pins the code the History runs against, normally `HEAD`. For a fix, the target state is the precondition the bug needed, not the bad outcome.
- `kb`: the findings of R-P1-7, or one finding id, resolved as `kb show` resolves it.
- `comment`, `design`, `spec`, `paper`: the protocol situation the source describes.

R-TS-P1-3. **Disclosure and the record.** A card goes where its source's disclosure allows, wherever the source lives: a `kb` or `text` source, any source path outside the repository, and any extraction run with `--local` (for a private advisory or a private repository) write to `target-states.local/<subsystem>/`; a public URL or an in-repo path writes to `target-states/<subsystem>/`. Sharing a local card is a manual rewrite without private detail, then a move. The card is the record of its source: synthesis reads only the card and the current code, so the card carries everything essential, and no raw input is archived; the prompt and log of an extraction stay in the git-ignored `extract/`. A campaign runs in a fresh clone, which has no git-ignored files, so the operator copies `target-states.local/` into it, as `invariants.local/`, and a synthesis prints how many tracked and local cards it uses.

#### Synthesis

R-TS-SYN-1. **The step.** `just synthesize [--profile simplex|marshal] [--match GLOB]... [--redo]` writes the scaffolds of a profile's cards in a checkout that a campaign of the same profile instrumented. It refuses to start unless that campaign's record names the profile and the checkout's current commit and lists no false invariant, its result is `READY` or `PANIC (tests)`, its instrumentation plan exists, and the runtime it materialized has the read side (R-TS-FB-1). A synthesis never instruments: it adds no probes, assertions or ghost state, and reads only what the campaign installed. `qmdb` is refused. The synthesizer runs with Phase 2 permissions (R-AG-3), one pair of a card and a base target at a time (R-TS-SYN-2), because the pairs share one crate. Because the pairs share one tree, and the scaffolds' modules are public siblings of one crate, so one can use another's items, a pair whose version is kept has every other standing scaffold, the card's other pairs included, rebuilt and replayed: if one no longer builds, stands worse than its report or gains or loses a crash, the pair's edits are restored and it is NOT BUILT, naming the scaffold it broke; otherwise those reports take their new verdicts. `--redo`, and the final check when it undoes a pair, also undo that pair's shared edits, so they revalidate every other scaffold the same way, before any pair, and roll back no pair: each report takes its new verdict, and a scaffold that no longer builds is recorded NOT BUILT. That revalidation is recorded once the diff is known to reverse-apply and before the undo, so one that an interrupt or another error stops is completed by the next synthesis before any pair; a `--redo` interrupted after its undo and before the pair's reports move finishes when run again. A pair whose revalidation already rewrote reports and whose edits are then restored, by an interrupt, another error or the recovery after a kill, leaves that revalidation recorded the same way, so the next synthesis revalidates every scaffold before any pair. The final check rebuilds every scaffold, and one that does not build stops the synthesis with exit 2.

R-TS-SYN-2. **Selection.** Each card gets one scaffold per selected base target, so the unit of synthesis is the pair (card, base) and the agent chooses no base. The candidate bases are the existing fuzz targets of the profile's package, except the Mallory target, whose custom mutator (`fuzz_mutator!`) a scaffold cannot reuse: 20 for simplex and 13 for marshal at the reference commit. The `--match` patterns narrow the selection: a card id pattern (`TS-0003`) selects cards, any other pattern selects bases, by base name or scaffold name, so `<base>_tsNNNN` pins one card to one base; with no base pattern every candidate base is selected. The pairs run in card order, then base order, and each pair has its own module, thin target, attempts, build, replays, verdict, report and diff, named `TS-NNNN_<base>` (R-TS-SYN-7). A pair that already has a reach report is skipped, saying so, and the card's other pairs are synthesized; `--redo` synthesizes the selected pairs again after moving each one's old outputs aside, the crash files of its scaffold included, so a preserved failure is never deleted, and leaves the card's other pairs standing.

R-TS-SYN-3. **Edit contract.** This requirement is the one contract for every edit a synthesis makes. Every other requirement, the prompts and the scripts refer to it instead of restating it.

Scaffold synthesis operates on a disposable copy of the repository, following the same assumption as StateLens. The generator may modify source code when necessary to expose state, make existing functionality callable, add fuzz-only accessors or wrappers, or support scaffold execution and verification. Such modifications must not change the production behavior or protocol semantics of the system under test.

Allowed examples include:
- widening visibility of existing functions, fields, or types;
- adding fuzz-only getters or read-side accessors;
- adding re-exports;
- adding wrappers around existing operations;
- adding campaign/runtime observation code;
- adding compile-time fuzz-only hooks that expose existing behavior;
- restructuring code only where the transformation is demonstrably semantics-preserving.

The generator must not modify production consensus logic, including:
- state-transition rules;
- branch conditions or protocol predicates;
- ordering of protocol operations;
- certificate or vote validation rules;
- message handling semantics;
- timeout behavior;
- persistence/recovery semantics;
- error handling that affects execution;
- state mutations used by the production implementation.

The principle is:
- Allowed: change how existing behavior is exposed or observed
- Forbidden: change what the protocol does

Because synthesis runs on a disposable copy, generated modifications do not need to be suitable for upstream production code. They only need to preserve the behavior of the production logic being fuzzed.

How the contract applies here:
- **Where.** The profile roots, which are the system under test (`consensus/src/simplex/`, plus `consensus/src/marshal/` for the `marshal` profile), and the profile's fuzz package (`consensus/fuzz/simplex/` or `consensus/fuzz/marshal/`), which reaches `consensus/fuzz/core/` only through its own `src/`. Any other path is out of scope.
- **Observation code** is read-only code the scaffold calls: getters, accessors, witness helpers. It never adds counter features, assertions or ghost state; those come only from the campaign (R-TS-SYN-1).
- **Enforcement.** The script enforces only the mechanical guards below. Semantics are enforced by the synthesis prompt, the test gate and human review of each pair's diff, which the synthesis saves.

Mechanical guards. Guards 1 to 3 compare the tree with a baseline that the first synthesis after a campaign takes before any pair and stores in `campaign/reach/`, and that every later synthesis of that campaign, `--redo` included, reuses, so it never changes: the content of every file git does not ignore under the paths above, `Cargo.lock`, and the state of the rest of the worktree. StateLens' own directory is the exception: it is compared with its state when the synthesis started, because operators edit cards and prompts between syntheses. The baseline, its test inventory (guard 5) and the campaign's files the guards compare with lie in the git-ignored `campaign/`, which an agent can write, so a synthesis reads them once, before any agent runs, holds them in memory, and after each run of the agent, and when the synthesis ends, since the agent's scaffolds run in the replays and the test gate after its last run, writes back any that changed, so a later synthesis reads them unchanged. They are evaluated on the cumulative difference from that baseline before any pair, where a failure stops the synthesis with exit 2, so a breach an earlier synthesis left behind, such as an edit outside the paths above, never passes; after every attempt; again on the kept version right before it is built for fuzzing; and once more over the whole tree, every kept version together, when the synthesis finishes; never against the state an attempt started from.
1. **Scope.** A change outside the paths above, other than to `Cargo.lock` (guard 2), stops the synthesis with exit 2 after the pair's edits inside them are restored; the operator then needs a fresh clone.
2. **Manifests.** No `Cargo.toml` under the paths above changes, so no dependency is added. The package manifest, `Cargo.lock`, `target_states/mod.rs` and the line of the package's `lib.rs` that declares `target_states` belong to the script and are compared with what the script itself last wrote there, which it stores with the baseline, or with the baseline where it wrote nothing: an agent's edit to them is restored, with feedback, and vetoes the version, which is not built.
3. **Instrumentation integrity.** No `sl_probe!`, `sl_assert!` or `sl_implies!` call is added, removed or changed, compared file by file as the multiset of call texts, so a call that only moves within its file is unchanged. Every non-blank line the campaign's instrumentation diff adds is still in its file, compared the same way, so no ghost update, field marked `// [statelens]` or runner hook of the fuzz package is removed or changed. `statelens.rs` stays byte-identical to the baseline, because the witness checks rely on its trace, so observation code lives elsewhere, and its module declaration, with the attributes directly above it, stays as in the baseline, with no `#[path]` attribute added under the profile roots. No call that writes ghost state or features, raises a violation or resets the runtime (`with_ghost`, `with_global`, `record`, `note`, `violation`, `reset`, `clear_compromised`) is added outside `target_states/mod.rs` and the scaffolds' thin targets, each checked to have the required shape (R-TS-SC-1); no call of `set_compromised` is added outside `target_states/`; no call of `tick()`, which advances the event sequence, or of `watch()` or `unwatch()`, which start a new trace and so forget a truncation the helper has not yet seen, is added outside `target_states/mod.rs`; no call of the read side (`watch` and the rest of R-TS-FB-1) is added under the profile roots; and no `[statelens-reach]` or `[statelens-scaffold]` literal appears outside `target_states/mod.rs`. Outside that file no edit adds a print, a panic hook, an included file or a `#[path]` module, because a print can forge a helper line however its literal is spelled, a panic hook can swallow an assertion's panic, and an included file can hold code the guards never read; and no Rust file that git ignores is compiled under those paths, because the guards, the diff and the restores would not see it. A call counts when the code reaches the runtime function through the runtime module, by path, alias or named import; the read side's names are common words, so a bare call does not count, and a glob import of the module escapes the check, a known limitation that review of the diff covers. A violation vetoes the version, with feedback. The script does not restore it, and because it is measured against the baseline, every later attempt that still contains it is vetoed again, with the same feedback, until the agent reverts it. Only a version that passes guards 1 to 3 is built and can be kept; when no attempt passes, the pair's edits are restored and its verdict is NOT BUILT. A failure of the check on the kept version or of the final check, which the per-attempt checks make impossible, restores the pair's edits and records NOT BUILT, and writes a failing file that no pair's edits touch back from the baseline, so nothing is fuzzed with an assertion, a probe or `statelens.rs` whose text changed. These are text checks: an edit that disables an unchanged assertion, such as an `if false` around it, is left to the test gate and review, which an annotation on hunks beside the instrumentation points at (guard 4).
4. **Marker.** Every changed hunk of the pair's own diff outside the pair's module and thin target carries `// [statelens] tss:TS-NNNN`; one without it is annotated `unmarked edit` for review, and one that changes or neighbors an assertion, a probe or a line the campaign added is annotated `edit beside instrumentation`.
5. **Test gate.** When the version kept for a pair changed a file under the profile roots, the script reruns the test gate. The rerun passes only when its output is usable, checked against nextest's own summary line, and every test that fails or no longer runs is one the test inventory records as failing. The inventory is taken with the synthesis baseline, from the campaign's validated gate log or else from one gate run on the tree as the campaign left it. A campaign that ended READY records no failing test: a test that fails in that one run flaked or was killed, and it stops the synthesis. Otherwise, unusable output included, the pair's edits are restored and GATE FAILED is recorded.
6. **Restore.** On NOT BUILT or GATE FAILED, the pair's edits are restored on every path. An interrupt or another error also restores them, once the command it stopped is killed with everything it started, and after the attempt's version, its replay outputs and a note naming the step that stopped are kept. When a synthesis is killed before it can restore them, the next synthesis restores the tree as it was before that pair, which each synthesis keeps until the pair ends. `just clean` returns the profile roots and the simplex and marshal fuzz packages, except their git-ignored `corpus/`, `artifacts/` and `coverage/`, to `HEAD`, which deletes `target_states/` and the thin targets.

R-TS-SYN-4. **Build.** For each pair the agent writes a module, `<pkg>/src/target_states/tsNNNN_<base>.rs`, and a thin target (R-TS-SC-1). The script declares the module, adds to the package manifest, after the agent's attempt, a `[[bin]]` copied from the base target's block under the scaffold's name, and builds the scaffold as R-P2-2 step 5 builds a variant. The agent adds the same block only for its own build and removes it again, since guard 2 restores an agent's edit to the manifest. Besides guards 2 and 3 of R-TS-SYN-3, a version is vetoed, and not built, when its thin target lacks the required shape, when the card gets a thin target on another base than the pair's, when it breaks R-P2-4, or when it does not publish its compromised set as R-TS-SC-6 requires. A veto or a build failure is feedback for the next attempt (R-TS-SYN-7).

R-TS-SYN-5. **Reach check.** A built version is checked by replays, never by fuzzing. Its binary runs one empty input file in libFuzzer's individual-file mode, in the pair's directory `campaign/reach/TS-NNNN_<base>/`, with `STATELENS_REACH=1`, no corpus and no libFuzzer flags, and prints a line per stage, the handoff, the reach count and `done`. A control run then replays the same input with one event withheld: an event before En whose actor is `harness`, which the scaffold's header names. In the control run a miss does not end the scripted history: the scaffold goes on with the remaining events, the handoff check and the base's oracles, so En gets a line. The control is vacuous when the withheld event is not a `harness` event before En, when the run prints no `withheld` line for it, when a stage before it misses or binds other values than in the canonical run, when a stage after it and before En has no line or is withheld too, since that omission could explain the miss by itself, when En is neither held nor missed, or when the run is incomplete: it prints no reach count or no `done`, or lines that name another card or another number of stages. A header without a `Control:` line has no control (`control missing`), which gives UNVERIFIED. After the last attempt, the kept version's canonical input is replayed once more to check determinism (R-TS-NF-2). A replay writes no corpus.

R-TS-SYN-6. **Verdicts and crash attribution.** Each pair gets one verdict:
- REACHED n/n: every stage held and no witness was rejected, En holds at the handoff, and the control run is not vacuous and does not reach En for the bound entities (`weak`, below), or the header declares the control not applicable, which only a card with no `harness` event before En allows, and only when every witness is `exact` or `construction`;
- UNVERIFIED k/n: no stage missed, but a stage is `unverifiable` or its witness was rejected; or the control is vacuous, reaches En for the bound entities (`weak`: En holds in the control run and no entity that both witnesses bind to a value has another value there; an entity the control's witness leaves out or binds to `?`, or whose value its own key or `as` source contradicts, does not tell the states apart), is missing, or is declared not applicable where REACHED does not allow it;
- PARTIAL k/n (a stage after E1 missed; k counts the stages held before it), UNREACHED 0/n, or NO REPORT (no reach count, or no `done`);
- CRASH (finding candidate), with the phase it happened in (prefix or continuation, which may be unknown for a Shape A failure that is not a panic) and its location as context; in Shape A, a stage the panic hook cannot evaluate is `unverifiable (crashed)`;
- SCAFFOLD ERROR;
- NOT BUILT (no version passed the vetoes and built, or the kept version broke another standing scaffold, a pair of the same card included, R-TS-SYN-1), or GATE FAILED (guard 5 of R-TS-SYN-3). GATE FAILED over a version that crashed still reports that finding candidate.

Verdicts are only reported: every scaffold that passes the vetoes and builds is fuzzed, whatever its verdict, unless the rerun test gate removes it. Every failure in a replay, in any phase, is preserved and is a finding candidate: a panic, a `[statelens][INV-NNNN]` or `[statelens][BYZANTINE]` message, a harness oracle failure, a sanitizer report, an out-of-memory error, a leak, a runtime timeout or stall, or a wall-clock timeout. Its crash file, log, replay command and the scaffold version are kept under `campaign/reach/TS-NNNN_<base>/`. The version is kept before the replays start, as a diff and a copy of every file it created or changed, so an interrupt or another error that restores the pair's edits never discards it. Where the failure happened is diagnostic context only: the report names the panic location, or the first frame outside the standard library of a sanitizer stack, and whether that line belongs to the pair's diff (`location in TS-NNNN diff`). A line the diff added or moved does not make the failure the scaffold's, because a restructured production assertion, or an accessor that exposes earlier corruption, fails for the system's own reasons. The only failure attributed to the scaffold is one its helper raises itself, with `[statelens-scaffold] <reason>` and a panic location inside the helper, `target_states/mod.rs`. The helper raises it only before any engine starts, so only for conditions of the scaffold's own code and knob bytes, never of the system's output: more than 16 knobs or more knobs picked than split, an empty knob domain or one with a single value, and a stage-deadline budget over the runtime's deadline. Such a failure is SCAFFOLD ERROR. A later misuse of the helper, such as a stage held twice, raises nothing: the call has no effect and returns false.

R-TS-SYN-7. **Refinement.** After the first attempt, the agent gets at most 3 further attempts per pair, each with feedback that names what to change: for a `cannot:` miss, nothing, unless an allowed edit or another shape gives the capability, another base being a pair of its own; otherwise the setup or shape for a miss at E1; an event's content, recipient or order for a later miss; the knob domains, the timing, or what keeps the state pending for a miss at En or a lost handoff; a witness that binds the relation for an `unverifiable` stage or a rejected witness; the event to withhold for a weak, vacuous or missing control; and the named reason of a SCAFFOLD ERROR. Automatic repair covers only SCAFFOLD ERROR, the one explicitly identified scaffold error, and the outcomes that are not crashes: vetoes, build failures, NO REPORT, misses, `unverifiable` stages, rejected witnesses and weak, vacuous or missing controls. The agent builds its scaffold but never runs it or the fuzzer: only the script's replays judge a version. A crash file that a run leaves in the checkout during an attempt all the same is moved into the attempt's outputs, never deleted, and counts as a CRASH (finding candidate) of that attempt when that attempt's version passed the vetoes and built; otherwise the file stays a finding candidate in the attempt's outputs, and refinement stops all the same. A CRASH (finding candidate) stops refinement for its pair: the crashing version is kept and built for fuzzing, never replaced by one that avoids the failure, and a human triages it (R-P3-2); if the rerun test gate then removes it (GATE FAILED), the crash stays preserved and reported. If triage shows a fault of the scaffold, the operator synthesizes the pair again with `--redo`. Otherwise the best built version is kept: REACHED before UNVERIFIED, PARTIAL, UNREACHED, NO REPORT and SCAFFOLD ERROR, then the most stages held, then the later attempt. With no version built, the pair's edits are restored and its verdict is NOT BUILT. The outputs stay in the git-ignored `campaign/reach/`, named after the pair, `TS-NNNN_<base>`: a report per pair (the verdict, each stage's witness, the handoff, the attempts, the crash attribution, the probe labels and sites read, the run and replay commands of its latest check, and the revalidations of R-TS-SYN-1), the pair's diff, each built attempt's version and the version an attempt left with a stray failure, kept before any restore, a note for an attempt during which the synthesis stopped, the test inventory of guard 5, and the prompts and logs.

#### Scaffold

R-TS-SC-1. **Shapes and files.** A scaffold reuses a base target's driver, input type and oracles, in one of two shapes. **Shape A**, preferred where it fits, pins the fields of the base input that make the base's own driver produce the History, calls the base's entry unchanged, and reads the stages from the probe trace and the harness after the run. **Shape B** drives the History online, stage by stage, and then hands off to the base's free-running phase (R-TS-SC-4). A scaffold, one per pair of a card and a base target (R-TS-SYN-2), is a module `<pkg>/src/target_states/tsNNNN_<base>.rs` and a thin target `fuzz_targets/<base>_tsNNNN_statelens.rs`, which runs the module between `statelens::reset()` and `statelens::clear_compromised()` as a variant runs its target. The name keeps the profile's prefix and the `_statelens` suffix, so the recipes treat a scaffold like a variant. Scaffolds are written, not derived: they are the exception to G4 and G7.

R-TS-SC-2. **Knobs and the canonical input.** A scaffold takes its base target's input type unchanged. Its knobs are the first K bytes, K at most 16, of the base input's own `raw_bytes`, zero-padded; the rest stays for the base. A knob is `domain[byte % len]`, with the source's value at `domain[0]`, so the empty input is the canonical input: every knob takes its source value, and the run replays the source's history. The fields the History fixes are pinned, and the fields that depend on them are reset as the base's decoder would set them. The scaffold picks every knob, and opens its stages, before any engine starts and before it pins a field or performs an action a stage witnesses: until the stages open nothing is observed and no position is taken.

R-TS-SC-3. **Stages and witnesses.** A scaffold checks one stage per History event, named by its event number. It binds the card's entities to the concrete values it chose or observed, and records for each held stage one witness that establishes the whole `Check` or `Holds` line, including its relations to earlier events. A witness is one of:
- `exact`: a harness observable keyed by the bound entities, such as a reporter's map keyed by view or digest, a resolver or buffer recorder, a recording wrapper in `target_states/`, a network intercept record, or a side-effect-free local query. A query that subscribes, hints, fetches or verifies is no witness, because it could create or satisfy the state it checks. An exact observable establishes an order only if each entry carries its own position, which a recording wrapper takes through the helper's `stamp` as it records the entry: `stamp` takes the position and prints the entry, and the script accepts an entry's position only if such a line names that entry; read after the run, an observable establishes presence only. A line that states several facts may have one observable for each, all keyed by the bound entities. A recording wrapper records synchronously and forwards every call and reply unchanged and at once, so it never creates the state it records.
- `intrinsic`: one probe observation at a site whose two values come from one object. It binds the observing replica and the relation among that object's fields at that instant, and no view, digest or other identity, so it witnesses only a line whose other entities are all existential, and it leaves them unbound. Two observations at different sites witness nothing together.
- `construction`: an action the harness performed itself and that cannot fail silently, such as a pinned elector or a certificate it built. It is allowed only for an event whose actor in the History is `harness`, never for En, and it proves only that the harness action happened: a line that also states what a replica holds or does needs an `exact` or `intrinsic` witness. The helper performs the action itself and takes its position right before it, so the position is the action's, not that of the moment a witness was made: it can take part in an order, and two harness actions with no probe observation between them are still ordered. In Shape A only an action the scaffold performs before it calls the base's entry qualifies.

A probe observation whose subject its own site does not fix is no witness. A stage whose entities or relations no available witness binds is `unverifiable`, not missed, and so is a stage whose witness is read at or after the first observation the trace dropped at its cap, and En when that observation comes at or before the handoff mark (`unverifiable (trace truncated)`, R-TS-FB-1). A stage is held only through the helper, which prints the witness record: every entity of the line with its value, or `?` when the witness leaves it unbound, and the stage that bound it; and the evidence, which carries every value the record binds: the probe observation (run, position, replica, label, site, values), each observable with its key written as entity values, the value read and the positions of the entry and of the read, or the action with the values it used and its position. Positions are unique, so the script compares them strictly. The script recomputes each record and downgrades a held stage to `unverifiable`, with `witness rejected: <rule>`, when:
- an `as Ek` entity's value differs from the one Ek bound, or Ek left it unbound;
- the record omits an entity of the line, or its evidence lacks a value the record binds;
- a stage's position is not greater than that of an earlier stage it must follow under the History, less the pairs its `Order:` line frees;
- the run differs from that of an earlier stage the line relates to, without a marked boundary between them;
- the observing replica is not the bound one;
- an intrinsic witness cites more than one observation, or binds a value to an entity other than its replica;
- a construction witness is used for En, or for an event whose actor in the History is not `harness`;
- a relation on a replica crosses a marked restart of it, and the line does not name the incarnation that the last such restart began, or the line names an incarnation that no marked restart began or that begins after the line's evidence.

Both stages of an ordered pair must carry a position, in either shape: a stage that the History or its `Order:` line requires to follow an earlier stage, and every earlier stage it must follow; and so must a stage and the earlier stages its `as` entities link it to, when a marked restart of a replica it binds happened. A position comes from a probe observation, an exact entry the helper stamped, or a construction action. Presence-only evidence, such as a map read after the run, cannot establish an order, so such a stage, earlier or later, is `unverifiable (no position)`. Stages that `Order:` leaves free need no position relative to each other.

Every fresh runtime of an input has its own run number; a runtime resumed from a checkpoint keeps it. A replica restart inside one run, and a resume from a checkpoint, are incarnation boundaries: the scaffold marks every restart it drives through the helper, which gives the restart a position of its own and names the incarnation it begins by that position, so two restarts with no probe observation between them begin distinct incarnations; and in Shape A it adds a marked hook, an edit under R-TS-SYN-3, to a base driver that restarts replicas; the subsystem's synthesis rules name the known restart sites as guidance. Pairs of related stages across a marked restart are annotated `relation across restart` for review. A restart that nothing marks is invisible to the checks. The first miss ends the scripted history, except in the control run (R-TS-SYN-5); the input continues into the base's free-running phase and every oracle.

R-TS-SC-4. **Handoff and recovery.** They are separate. In Shape B the scaffold publishes its compromised set first (R-TS-SC-6), then drives E1 to E(n-1) online, each stage with a deadline in simulated time: passing it is a miss, never a wait, every wait on a reply of the system under test is raced against it, and a dropped reply is a miss. Then comes the handoff check, which the helper decides, not the scaffold. It requires a fresh, uninterrupted read of En's witness at the handoff: the scaffold passes the read to the helper's handoff call, which takes the read and the handoff mark in that one call, so no await or yield comes between them, and a witness read before the call does not count. The positions date the read, not what it read, so En takes an `exact` witness where one exists: a probe observation read inside the call may be older than a later one that contradicts it. In addition, no probe observation may carry a position between the read (`read=`) and the mark (`mark=`). Because every observation and helper event takes its own position, the handoff holds only if En is held this way and `mark=` is `read=` + 1, and the script rechecks both from the positions the lines carry. For a state defined by pending work or a withheld delivery, an `exact` observable shows the work still pending at that instant: requested, and neither answered nor cancelled (scenario SPEC S3). Nothing the prefix does may complete or cancel that work before the handoff. Then the handoff: the continuation starts with every fault the prefix opened still in place -- a crashed replica down, a partition, a held message. Recovery is part of the continuation and never precedes the handoff. Every such fault is released no later than the base's first heal (GST), and the base's liveness measurement starts after the handoff and the release. Network cuts go through the base's own fault input, or are composed with the base's current cut, so the base installs and heals them; the scaffold never heals the network on its own. Crashed replicas and held messages are released at the handoff plus a delay that a knob picks within the base's fault phase, and a base with no GST releases them before its liveness wait starts. Where the base sets a runtime deadline, the scaffold's is the base's plus the stage deadlines plus the largest release delay. If En does not hold at the handoff, En is missed, even if it held earlier, and the continuation still runs. A marshal prefix leaves enough heights before the epoch ends for the liveness measurement; the script cannot measure that, so review of the module checks it. In Shape A the base's own schedule runs and the scaffold imposes no cleanup; the handoff is implicit in En's witness, read in the handoff call after the run, which counts only if it has a position and the trace has a later observation of an honest replica in the same run, and En is `unverifiable` otherwise.

R-TS-SC-5. **Oracles.** A scaffold never removes, weakens or narrows an oracle of its base target. In Shape B, progress targets are re-based on the handoff, in the base's own measure, so that the liveness the base requires is measured from the reached state; in Shape A the base's oracles run inside its entry unchanged, so a History whose continuation they would not measure takes Shape B. The scaffold prints `done` after the last oracle, so a report without it shows that the oracles may not have run.

R-TS-SC-6. **No fabrication, and the guard.** A scaffold delivers events through the network or the harness's own operations and fabricates nothing a correct replica would not produce (scenario SPEC I5): a scripted vote goes only on its signer's own channel. Every injection, such as a seeded journal or a direct resolver delivery, is listed in the module's header with the INV ids whose ghost history it bypasses. A Shape B scaffold publishes, before any engine starts, the replicas it runs as real engines under a Byzantine identity (`statelens::set_compromised`, with an empty set if there are none), as the runner hooks of section 8.4 do; a Shape A scaffold relies on its base target's hook. Reach replays run in the default Byzantine mode, so a compromised replica is never observed (R-INS-2).

R-TS-SC-7. **Missing capabilities.** A stage that needs a capability that neither the harness nor an edit under R-TS-SYN-3 provides is reported as `cannot: <capability>`, in its stage line and in the module header's `Missing:` line, and is never approximated; the history up to that stage still runs and hands off. The prefix and witness code a scaffold adds never panics on data of the system under test: no `unwrap`, `expect` or indexing on it, but a miss instead; the base's oracles and the code copied from its driver keep their panics (R-TS-SC-5).

#### Feedback

R-TS-FB-1. **Read side.** The runtime template gets a read side, off by default. While a scaffold watches, every probe hit that passes the Byzantine guard is appended to an ordered trace of the input, with its label, call site, observing replica, values, position and run number. Positions come from one event sequence per input, which every probe observation and every event of the scaffold's helper advances: a witness read, an entry a recording wrapper stamps, a construction action, a restart boundary, and the start and the mark of the handoff each take their own position through `tick()`, which returns a value greater than every earlier position of the input. Two harness actions with no probe observation between them therefore still get distinct, ordered positions, and order checks are strict. `mark()` returns the last position issued, without advancing the sequence, and `reset()` starts it again at 0, through a private `clear_trace()` that the self-tests call instead, so positions are unique within one input. Only the helper, `target_states/mod.rs`, calls `tick()` (guard 3 of R-TS-SYN-3); a recording wrapper stamps an entry through the helper (R-TS-SC-3). A scaffold asks for the earliest matching hit at or after a position, for the current run number, and for the call sites of a label, which it looks up at run time and never hard-codes, because synthesis edits move lines. Instrumentation never calls the read side (guard 3 of R-TS-SYN-3). When nothing watches, a probe hit costs one thread-local check; the read side does no I/O, takes no locks and never awaits (R-INS-3). The trace and its sequence live for one input (R-INS-5), deterministic and single-threaded. The trace has a cap, past which it keeps no more observations while the sequence still advances, and the runtime reports the position of the first observation it dropped. What the trace holds from that position on is incomplete: its latest observation may describe a state that has since changed. So a stage whose witness is read at or after that position, and En when that position comes at or before the handoff mark, is `unverifiable (trace truncated)`, adds no stage feature, and the handoff does not hold. The helper prints the position once, and the script rechecks every stage line against it, so such a replay is never REACHED. The counter table and the features of every variant are unchanged.

R-TS-FB-2. **Stage features.** A held stage k of card TS-NNNN adds the feature `(site_hash("TS-NNNN"), k, 0)` to the StateLens counter table, through the runtime's existing `record`, so libFuzzer keeps an input that reaches a stage none reached before. R-FB-6 holds: features are only added.

#### Phase 3

R-TS-P3-1. **`--state-reaching`.** `just fuzz <simplex|marshal> --state-reaching` runs a campaign, unless `--skip-campaign` is given, then a synthesis, which stops the command when it fails, unless `--skip-synthesis` is given, then the scaffolds only, never the variants, through the sequential, `--parallel` and `--tmux` forms of R-P2-5; the tmux session is `statelens-<profile>-reach`. `--state-targets GLOB` selects cards by id (`TS-0003`) and `--fuzz-targets GLOB` the candidate base targets, by any name a variant or scaffold of theirs has; both may be repeated, a pattern of the other flag's form is refused, `--state-targets` and `--skip-synthesis` are refused without `--state-reaching`, and each selected card yields one scaffold per selected base target, every candidate base without `--fuzz-targets` (R-TS-SYN-2). A pattern that selects nothing fails before the campaign starts. `--state-reaching` with a single target or with `qmdb` is refused. `--skip-synthesis` fuzzes the scaffolds synthesis already built in this checkout for the selection, whatever their verdicts, without the synthesis preflight: the way to keep fuzzing after the checkout drifted from the synthesis baseline (R-TS-SYN-3), for example when an upstream fix was merged into it; synthesis itself still refuses such a checkout, and a selection none was built for fails as after a synthesis that built none. It composes with `--skip-campaign`, `--parallel`, `--tmux` and the arguments after `--`. For example, `just fuzz simplex --parallel --tmux --state-reaching --state-targets TS-0004 --fuzz-targets "simplex_cert_*"` runs a `simplex` campaign, synthesizes TS-0004 on each `simplex_cert_*` base target, and opens a tmux window per scaffold, each running `just run <scaffold>` with no added arguments; `--fuzz-targets simplex_cert_mock` opens one window; without `--state-targets`, every simplex card gets a scaffold per base and a window each. `--invariants LIST` goes to that campaign as in R-P2-5: `just fuzz simplex --state-reaching --state-targets TS-0004 --fuzz-targets "simplex_cert_mock_twins_*" --invariants "simplex/INV-0001,simplex/INV-0002" -- -max_total_time=3600` runs a `simplex` campaign that binds those two invariants, synthesizes TS-0004 on each of the eight `simplex_cert_mock_twins_*` bases, and fuzzes the eight scaffolds, `<base>_ts0004_statelens`, in turn for an hour each.

R-TS-P3-2. **Run, replay, coverage, clean.** `just run <scaffold>` fuzzes a scaffold, and `just run <scaffold> <crash_file>` replays a crash, as for a variant (R-ART-1); with `STATELENS_REACH=1` the replay also prints the stage lines, which show how far a fuzzed input got. `just coverage` and `just clean` include scaffolds (R-P3-4, R-P2-5). A crash of a scaffold in Phase 3 is investigated like any other (R-P3-2).

#### Non-functional

R-TS-NF-1. A scaffold uses the same input type, `run` recipe and libFuzzer flags as ordinary fuzzing, and no seed corpus: its canonical input is the empty input (R-TS-SC-2), and the `run` command a synthesis prints for it carries no libFuzzer arguments.

R-TS-NF-2. **Determinism.** R-NF-2 applies to scaffolds. The rerun of the canonical input after the last attempt (R-TS-SYN-5) annotates the card `nondeterministic` when its stage lines differ.

R-TS-NF-3. **Overhead.** A scaffold's exec/s is measured against the StateLens variant of its base target, not against an uninstrumented target (R-NF-3).

### 11.4 Fuzz harness

#### Shape A

```
libFuzzer   (started by the operator: just run <base>_tsNNNN_statelens)
  |  bytes -> the base target's input type
  v
<base>_tsNNNN_statelens   (the base's package; written by the synthesizer, checked by the script)
  |  statelens::reset()
  |  tsNNNN_<base>::fuzz(input)
  |    knobs <- first bytes of raw_bytes; watch the probe trace
  |    pin the input fields the History fixes
  |    the base target's entry, unchanged:
  |      its setup and runner hook, its own schedule and faults, its oracles
  |    stages E1..En, read from the trace and the harness after the run
  |      held | missed | unverifiable; a held stage adds a stage feature
  |    implicit handoff: En's witness, then a later honest observation in the same run
  |    done
  |  statelens::clear_compromised()
  v
libFuzzer reads edge coverage + StateLens counters, stage features included
```

#### Shape B

```
libFuzzer   (started by the operator: just run <base>_tsNNNN_statelens)
  v
<base>_tsNNNN_statelens
  |  statelens::reset()
  |  tsNNNN_<base>::fuzz(input)
  |    knobs, watch the probe trace
  |    statelens::set_compromised(...)             before any engine starts
  |    pinned fields, the base target's setup
  |    E1 .. E(n-1), driven online, each stage with a deadline in simulated time
  |      held -> the next event               missed -> the scripted history ends
  |    handoff check: En's witness read in the handoff call, nothing between
  |      the read and the mark; En holds now, and pending work is still pending
  |  ===== handoff: every fault the prefix opened is still in place =====
  |    continuation: the base target's free-running phase
  |      recovery: crashed replicas restart and held messages are released at
  |                handoff + d (a knob); network cuts heal at the base's own GST
  |      liveness is measured after the handoff and the recovery
  |      the base target's oracles, unchanged
  |    done
  |  statelens::clear_compromised()
  v
libFuzzer reads edge coverage + StateLens counters, stage features included
```

#### Initial cards

| Card | Profile | Source | Expected shape | Expected base family |
|---|---|---|---|---|
| TS-0001 | marshal | PR #4317, merged as `85f85284d7`, written by hand: the replica certifies a notarized proposal after rejecting another header of the same payload and voting to nullify the view | A or B | e2e standard with a real Byzantine engine (wedge scenario, Twins split-header) |
| TS-0002 | marshal | `test consensus/src/marshal/standard/mod.rs:7027` (`test_standard_finalized_delivery_rejects_epoch_mismatch`): a peer answers an outstanding request for a finalized block with a finalization that claims another epoch | B | e2e standard with a Byzantine backfill answer (poison) |
| TS-0003 | simplex | `test consensus/src/simplex/mod.rs:3260` (`all_crash_after_nullify`): replicas that voted to nullify a view crash before the nullification spreads, then recover from their journals | B | Chaos |
| TS-0004 | simplex | `text`, a smoke card: R votes to nullify v; a notarization for v reaches R; R dispatches certification for the same v | A or B | Standard, FaultyNet |

The synthesizer chooses each shape; the operator selects the bases, one scaffold per card and base (R-TS-SYN-2); the table gives the expected shape and base family. TS-0001 is the worked example of SPEC section 18.3. TS-0004, extracted from `text`, is moved by hand from the local part (R-TS-P1-3). It is expected to be REACHED with an `exact` witness for En: a recording wrapper in `target_states/` around R's automaton keys certification requests by round and stamps each with its own position. R's nullify vote for v needs a position too, so a transparent recording wrapper in `target_states/` around R's reporter or vote sender stamps it; R's reporter map of nullify votes, read after the run, gives presence only and cannot order the vote (R-TS-SC-3). An intrinsic observation at the voter's certification-handle site, if the campaign has that beacon, only corroborates it.

### 11.5 Acceptance Criteria

AC-22. **Registry and extraction.** `just check-invariants` reports no problem with TS-0001 to TS-0004 in the registry. With each agent, `just extract-states --registry marshal test consensus/src/marshal/standard/mod.rs:7027`, `just extract-states --registry simplex test consensus/src/simplex/mod.rs:3260` and `just extract-states --registry simplex text "<paragraph>"` each write lint-clean cards, the last only into `target-states.local/simplex/`. A `kb` extraction and an extraction with `--local` write only into `target-states.local/`. A `test` path outside the registry's roots and `--registry qmdb` are refused.

AC-23. **Read side.** The read side's self-tests pass in the test gate of a campaign: nothing is kept while nothing watches; probe observations and `tick()` share one strictly increasing sequence of positions, so two ticks with no observation between them get distinct, ordered positions, and positions are unique only within an input, because `clear_trace()`, which `reset()` calls, starts the sequence again; `mark()` returns the last position without advancing; the earliest match at or after a position is found; call sites and run numbers are kept; a guarded replica is never observed; and the cap holds while the sequence still advances, the runtime keeping the position of the first observation it dropped, which a later drop does not move, until `watch` or `unwatch` resets it. The helper's self-tests pass: a stage read after a state change past the cap, and En, are `unverifiable (trace truncated)` with no feature, and the handoff is lost; an En recorded `unverifiable` before the handoff keeps its reason and loses the handoff; and with `STATELENS_REACH` unset the helper reads no trace for a line it does not print. A campaign whose instrumentation calls the read side stops at its scope check.

AC-24. **Simplex synthesis.** On a `simplex` checkout whose campaign ended `READY` or `PANIC (tests)`, `just synthesize --profile simplex --match simplex_cert_mock_chaos_ts0003 --match simplex_cert_mock_ts0004` builds one scaffold per pair, TS-0003 on `simplex_cert_mock_chaos` and TS-0004 on `simplex_cert_mock`, prints each verdict and a `run` command with no libFuzzer arguments, writes a report and a diff per pair, `TS-NNNN_<base>.md` and `.diff`, under `campaign/reach/`, and leaves no corpus or crash artifact for the scaffolds in the fuzz package; TS-0004 is REACHED with an `exact` witness for En. With stub agents, every guard of R-TS-SYN-3 holds: an edit outside scope stops the synthesis with exit 2 and restores the pair's edits, and a second synthesis on that checkout stops with exit 2 before any pair; a dependency added to a manifest is restored; an added `sl_probe!` is vetoed; a stub, each of whose attempts writes a valid module and thin target, whose first attempt removes or alters an `sl_assert!` call and whose second attempt makes an unrelated edit, leaving that change in place, is vetoed in every attempt with the same feedback, changes nothing after its second attempt, which ends the pair, and ends NOT BUILT, with the assertion as it was in the baseline, while a variant whose second attempt reverts the change builds; a deleted ghost update, a changed runner hook, a `#[path]` attribute on the runtime module's declaration, a `watch()` call, a print or a panic hook in the module, and a module under a path git ignores are vetoed; a marked accessor under the profile roots makes the script rerun the test gate, and a test that fails there and that the test inventory does not record as failing records GATE FAILED and restores the accessor; an unmarked hunk is annotated `unmarked edit`; an agent that never builds gives NOT BUILT, with the pair's edits restored and every variant still building. The rerun test gate fails closed: with `NEXTEST_STATUS_LEVEL=fail` and `CARGO_TERM_COLOR=always` set, a failing accessor still gives GATE FAILED, and an accessor that keeps a test of the gate from compiling gives GATE FAILED for unusable output. With two pairs, a second pair that breaks the first pair's scaffold is NOT BUILT, naming the first, `TS-0003_simplex_cert_mock_chaos`, with its edits restored and the first pair's report unchanged; a second pair that changes shared code and breaks nothing has the first pair's report revalidated, and so does a `--redo` of that second pair that undoes the shared change, by the next synthesis when that `--redo` is interrupted during the revalidation; and a second pair that writes only its own module and thin target has the first pair's report revalidated too, since one module can use another's items. One card on two bases, `just synthesize --profile simplex --match TS-0004 --match simplex_cert_mock --match simplex_cert_mock_faulty_net`, gives two scaffolds, `simplex_cert_mock_ts0004_statelens` and `simplex_cert_mock_faulty_net_ts0004_statelens`, two reports and two diffs, and the second pair revalidates the first; the same command again skips both pairs, saying so per pair; and a `--redo` of one pair, `--redo --match simplex_cert_mock_ts0004`, moves that pair's outputs aside and leaves the other pair's scaffold standing, revalidated.

AC-25. **Marshal synthesis.** The same on a `marshal` checkout for TS-0001 on `marshal_e2e_standard_deferred_cert_mock_twins_split_header` and TS-0002 on `marshal_e2e_standard_deferred_cert_mock_poison`, including a scaffold whose target state is pending work, whose handoff check shows that work still pending at the handoff; a stub that reads En's witness, lets that work complete, and only then passes the witness to the handoff call gets `handoff lost`. **Differential test.** `statelens/scripts/differential.sh` runs, in a scratch worktree and never in the checkout, the test-only crate `statelens/differential/`, which for the six source tests of the marshal scenario prefixes drives two prefixes on an identical setup and input: the scenario's `drive`, unmodified, and a hand-written TSS prefix built from the helper primitives and the same harness verbs as `prompts/synthesize.md` prescribes for a scaffold, one stage per History event, a witness per stage from exact observables or constructions, En read freshly inside the handoff, no fabrication. Both take a side-effect-free, canonicalized state digest after `finish`, and the TSS side's captured `[statelens-reach]` lines go through `statelens.py reach-verdict`. The script runs the 30 tests the crate is expected to list and refuses a listing that differs (exit 2, before any replay). The 24 positive tests, seven cards on two marshal variants and two configurations, give equal digests and `REACHED n/n` with no rejected witness; the six negative controls, a dropped event, En read before the handoff, two order-relevant events swapped, a certificate reported to another node, a finalization delivered to another node and a delivery left armed, each give, from a replay that ran to its digest line and a verdict the validator computed, an unequal digest or a verdict other than REACHED (a crash, a missing digest line or an unparsed verdict is an error of the run, `(ERROR)`, not a caught control); the fuzz package passes clippy, rustfmt and its own tests with the widened visibility; `cargo metadata` at the root lists neither the crate nor its shim; and the worktree is gone afterwards, each run in a scratch directory of its own. The test establishes that a hand-written TSS prefix leaves the cluster in the same settled state after `finish` as the scenario prefix; it does not establish that the two states are equal at the handoff mark, and it judges the primitives and a human reconstruction against the scenario method, never an agent's output (SPEC section 18.10.1).

AC-26. **Stage semantics.** With stub scaffolds, each witness rejection rule of R-TS-SC-3 (an `as Ek` value that differs or that Ek left unbound, an entity missing from the record, a bound value its evidence lacks, an order the positions contradict, a foreign run, a wrong replica, an intrinsic witness with two observations, a construction witness for En or for an event whose actor is not `harness`, a relation across a restart whose incarnation the line does not name) gives UNVERIFIED with `witness rejected`; an ordered pair in which one stage has presence-only evidence, the later one, or the earlier one while the later is stamped, gives UNVERIFIED with `unverifiable (no position)`; two harness actions with no probe observation between them get distinct positions in the order performed, so a stub that performs them in the History's order holds both stages and one that performs them in reverse gives `witness rejected: order`; two restarts of one replica with no probe observation between them begin two distinct incarnations, and a stub whose line, related to a stage before both restarts, names the first while its evidence comes after the second gives `witness rejected: incarnation`; and a vacuous control, a `weak` control, a header without a `Control:` line, and a control declared not applicable while a probe witness is used or on a card with a `harness` event before En each give UNVERIFIED. Two canonical replays print identical stage lines. A scaffold that prints `[statelens-reach]` or `[statelens-scaffold]` itself is vetoed. A panic with an `[statelens][INV-NNNN]` message in the prefix, a panic on a line the pair's diff added or moved, and a sanitizer report in an added accessor each give CRASH (finding candidate), the last two with `location in TS-NNNN diff`, stop refinement for the pair, and preserve the crash file. A helper error `[statelens-scaffold]` for an empty knob domain gives SCAFFOLD ERROR, and the pair is refined; a stage held twice raises no error. A stub that fills the trace to its cap, changes the state past it and reads in the handoff the latest observation the trace kept gives UNVERIFIED with `unverifiable (trace truncated)`, and so do its lines with En held and the handoff holding. A synthesis interrupted during the control replay of a version whose canonical replay failed restores the pair's edits and keeps the crash file, the logs, the version and a note naming the step that stopped.

AC-27. **Recipe.** On a checkout with a `simplex` campaign, `just fuzz simplex --parallel --tmux --state-reaching --state-targets TS-0004 --fuzz-targets "simplex_cert_*" --skip-campaign` synthesizes and opens the tmux session `statelens-simplex-reach` with one window per `simplex_cert_*` base of TS-0004 whose scaffold built, 20 pairs at the reference commit, and none for a variant, each running `just run <scaffold>` with no added arguments; without `--skip-campaign` the same command runs the campaign first. `--fuzz-targets simplex_cert_mock` gives one window, `--fuzz-targets "simplex_cert_mock_twins_*"` eight, `--state-targets "TS-000*"` one window per scaffold of every pair of TS-0003 and TS-0004, and a pattern that selects nothing fails before the synthesis. On the same checkout after an upstream fix was merged into it, so that it differs from the synthesis baseline, the first command with `--skip-synthesis` runs no synthesis and opens one window per scaffold of TS-0004 already built on a `simplex_cert_*` base, whatever its verdict; without `--skip-synthesis` the synthesis refuses the checkout and the command stops. `--bogus`, `--state-targets` without `--state-reaching`, `--skip-synthesis` without `--state-reaching`, a `TS-` pattern given to `--fuzz-targets`, any other pattern given to `--state-targets`, `qmdb` and a single target with `--state-reaching` are refused.

AC-28. **Clean and guard.** After a synthesis, `just clean --yes` returns the profile roots and the simplex and marshal fuzz packages, except their git-ignored `corpus/`, `artifacts/` and `coverage/`, to `HEAD` and deletes every scaffold, and a campaign refuses a checkout that still has a `target_states/` directory. For a scaffold that runs a replica under a Byzantine identity (a non-empty compromised set, R-TS-SC-6), a canonical replay with `STATELENS_BYZANTINE=panic` panics with `[statelens][BYZANTINE]`; when no scaffold has one, the check is recorded as not applicable.

### 11.6 Risks and Open Points

| Risk | Mitigation |
|---|---|
| An over-constrained scaffold fixes what a bug needs to vary, and hides the bug. | Only the essential History is fixed; every incidental choice becomes a knob with at least 2 values (R-TS-P1-2, R-TS-REG-3), and an input that misses a stage continues into the base's free-running phase (R-TS-SC-3). |
| The agent reconstructs a History the source does not describe, or a scaffold reaches a different state than the card. | Every event is confirmed against the code and pinned in Evidence (R-TS-P1-2), and humans review cards. Witness records are recomputed by the script (R-TS-SC-3), and the control run shows that the History, not chance, produced En (R-TS-SYN-5). |
| Probes are coarse: a probe value seldom carries a view or a digest, so many stages bind no entity and end `unverifiable`. | Exact harness observables keyed by the bound entities (R-TS-SC-3). UNVERIFIED is reported as such and never counted as reached, and the scaffold is fuzzed anyway (R-TS-SYN-6). A new probe comes from an invariant or a beacon of the next campaign, never from a synthesis. |
| An injection, such as a seeded journal or a direct delivery, bypasses ghost history, so an invariant fails for a state no execution produced. | Injections are listed in the module header with the INV ids whose history they bypass (R-TS-SC-6), and a human triages every finding candidate. |
| Agent output is not deterministic: two syntheses of one pair differ. | Accepted, as for bindings. The reach report and the pair's diff document each scaffold, and the rerun of the canonical input checks the kept version (R-TS-NF-2). |
| A scaffold crashes on its canonical input, so its fuzz run stops at once. | Intended: the crash is a finding candidate, kept and preserved, and `just run` reproduces it immediately (R-TS-SYN-7). If triage shows a fault of the scaffold, `--redo` writes the pair again. |
| Private detail from a finding, an advisory or a private text reaches a commit through a card. | Routing by disclosure: such cards go to the git-ignored local part, and sharing one is a manual rewrite (R-TS-P1-3, R-KB-6). |
| A base target restarts replicas without marking the incarnations, so a relation across a restart cannot be checked. | The scaffold marks every restart it drives, and in Shape A adds a marked hook, an edit under R-TS-SYN-3, to a base driver that restarts replicas, at the known restart sites its subsystem's synthesis rules name. A relation across a marked restart must name the incarnation, and such pairs are annotated `relation across restart` for review (R-TS-SC-3). A restart that nothing marks stays invisible to the checks, a known limitation; review of the pair's diff is what catches a missing hook. |
| The helper primitives, or a prefix written by the scaffold rules, reach a state other than the one the source test describes, and the reach check accepts it. | The differential test of AC-25: a TSS prefix per marshal scenario source test beside the scenario's own prefix, equal state digests and REACHED required, with negative controls that must be caught (SPEC section 18.10.1). It judges the primitives and a human reconstruction, not agent output; what an agent writes is judged by AC-24 and AC-25 with a real agent and by review. |

---

## 12. Risks and Open Points

| Risk | Mitigation |
|---|---|
| LLM-written invariants are wrong under Byzantine conditions and cause false alarms. | Human review of the registry; the test gate runs before fuzzing; triage by humans; wrong invariants are fixed in the registry. |
| A draft invariant, beacon or target state takes effect before anyone reviewed it, because every file in a registry is active. | Phase 1 prints a review reminder for each; the operator reviews `invariants/` before starting a campaign and `target-states/` before a synthesis. |
| Bindings change between campaigns, because agent output is not deterministic. | Accepted by design: every campaign is fresh. The instrumentation plan and diff document each binding. |
| An instrumented checkout is reused for another campaign or committed by mistake. | The campaign refuses a checkout with tracked changes outside `statelens/` or earlier instrumentation, and never commits; operators discard the checkout after a campaign. |
| Probes change scheduling or behavior. | R-INS-1 and R-INS-3; AC-8. |
| A synthesis edit changes what the protocol does, so a scaffold fuzzes a different system. | The edit contract (R-TS-SYN-3): mechanical guards on scope, manifests and instrumentation, checked against a baseline taken when the synthesis starts, so a vetoed edit an agent leaves in place stays vetoed, a test-gate rerun after any edit under the profile roots, a diff per pair for review, and `just clean` (AC-24, AC-28). |
| A campaign's beacon probes depend on the knowledge base the operator configured, so two operators get different probes and a campaign is not reproducible from this repository alone. | Accepted. Beacons add feedback only, never oracles, so a missing one costs coverage, not correctness. The plan records what each probe watches and where it was found. |
| A query misses a finding that uses other words than the question. | `kb search` ranks by meaning as well as by words (R-KB-9). Neither use of the knowledge base depends on an operator's wording: a `kb` extraction reads every finding in the registry's scope (R-P1-3), and the beacon step starts from `kb cites` on the directory it instruments (R-KB-4). Only the word queries an agent adds can miss such a finding; it can query again with other terms, and the index exposes `module`, `tags` and `summary`, so a query can be narrowed or widened. |
| The knowledge base and the code drift apart: a finding cites a revision whose symbols have since moved or gone. | The instrumenter is reading the current code when it queries, so a citation that no longer resolves is visible to it immediately; nothing durable records the stale link. |
| Too many probe features (corpus bloat) or hash collisions. | Presence-only probes (R-FB-2); discretization rules (R-FB-5); 64K table; exclude replica index. |
| Cross-actor assertions fire only because of mailbox lag. | R-INS-5: assertions must allow for any legal delivery order. |
| History kept in ghost state leaks from one run into the next, for example between the seeds of one test (found by the first end-to-end campaign). | The deterministic runtime's fresh-run hook clears ghost state (R-INS-5, section 8.4). |
| The patch anchors of the materialize step move with the code. | The campaign stops with a message that names the anchor, which is then updated in `scripts/statelens.py`. |
| Phase 2 agents, the synthesizer included, have full access to the host. | Campaigns and syntheses run on a dedicated machine or container (R-AG-3). |
| StateLens evidence comes from memory-safety bugs in C++ engines; payoff on Rust logic bugs is unproven. | AC-5/AC-6 establish basic function. Measuring bug-finding (e.g. on planted bugs) is left for later. |
| libFuzzer stops at the first crash. | Intended: "panic => human investigates". |
| A campaign's result says nothing about fuzzing: how long and how widely the targets run in Phase 3 is up to the operator. | The summary prints the command for every StateLens target (SPEC section 7.9), and crashes land in the standard artifact directories (R-ART-1). |

---

## 13. Specification

[SPEC.md](../docs/SPEC.md) specifies:
1. the committed files and the registry format, including `templates/invariant.md` and the lint rules;
2. the `statelens.py` commands (`lint`, `extract`, `kb`, `campaign`, `synthesize`), their configuration, the profiles, and exit codes;
3. the knowledge base: corpus layout, the index, the `kb` retrieval commands and the per-subsystem module filter;
4. the exact edits a campaign makes to the source tree, with their anchors;
5. the runtime module `statelens.rs` and the fuzz target, verbatim and tested;
6. all prompts, verbatim, with the per-subsystem parts;
7. the agent invocations for `claude` and `codex`;
8. in chapter 7, StateLens for Simplex: the campaign of the `simplex` profile, and how the operator runs its targets in Phase 3;
9. in chapter 8, StateLens for Marshal: what is specific to the `marshal` profile;
10. in chapter 17, StateLens for qmdb: what is specific to the `qmdb` profile;
11. in chapter 18, Target-State Synthesis: the target-state registry and its extraction, the read side of the runtime, the synthesis step and its edit contract, the scaffold contract, the reach check, and the `--state-reaching` recipe;
12. the acceptance procedures for AC-1 to AC-29.
