# StateLens for Simplex: Technical Specification

| | |
|---|---|
| Implements | [PRD.md](PRD.md) |
| Audience | The coding agent that implements `consensus/fuzz/statelens/`, and fuzz operators |
| Verified against | commits `7cb6a3d583` and `2e56fa856e` (see section 1.2); marshal at commit `2649e4a668` (see section 8.1) |

---

## 1. Purpose

This document turns the PRD into buildable artifacts: every committed file, the exact
edits a campaign makes to the source tree, the runtime support module, the prompts, the
orchestration script, and the acceptance procedures.

### 1.1 Conventions

- MUST, MUST NOT, SHOULD and MAY are normative.
- Paths are relative to the repository root unless stated otherwise.
- "The checkout" is the operator's fresh clone of the repository. StateLens lives in
  it; a campaign runs in it and instruments it in place. StateLens never makes another
  clone.
- `SL` is `consensus/fuzz/statelens/`.
- Text marked "verbatim" MUST be copied exactly. Everything else describes behavior
  and leaves the implementation free.

### 1.2 What was verified

The following were built and exercised in a scratch checkout of the commit above:

- `runtime/statelens.rs` (Appendix A): 10 unit tests pass inside `commonware-consensus`
  with the workspace's `warnings = "deny"` on stable, and the `cfg(fuzzing)` path
  compiles on the CI-pinned nightly. The file is `rustfmt`-clean with the repository
  configuration.
- The materialization edits (section 7.2), the fuzz target and the Twins runner hook
  (Appendix B): `cargo fuzz build` succeeds and the target runs.
- The Byzantine guard end to end: with `STATELENS_BYZANTINE=panic` the first input
  panics with `[statelens][BYZANTINE] replica=2`; replaying the saved artifact in the
  same mode reproduces the panic; in the default mode the same input runs cleanly, and a
  30-second run produces no such panic. The index-mapping assertion in the hook never
  fired.
- The test gate (section 7.7) with sample instrumentation: 240 tests passed in 125 s
  on 16 cores.
- Throughput of the target with minimal instrumentation: about 13 executions per
  second per process.

End-to-end campaigns at commit `2e56fa856e`, with Claude as the agent, in scratch clones:

- AC-1: Claude and Codex each wrote lint-clean invariants from issue #2070.
- AC-6: with INV-0001 and FALSE-0001, the test gate stopped the campaign with
  `[statelens][FALSE-0001]`; every one of the 175 failing tests failed on that invariant
  only. The agent added 143 probe sites, and none of them panicked.
- AC-4: with the nine registry invariants (5 bound, 4 partial, 21 assertion sites, 147
  probe sites), the first run exposed ghost state leaking between the seeds of one test:
  26 tests raised a false INV-0001 alarm, and the `nuller` tests pass with one seed and
  fail with two. With the fresh-run hook (D16), all 242 tests pass and a 3-minute fuzz
  run finds no violation.
- AC-5: after 3 minutes on empty corpora, `ft:` is 48,371 with StateLens feedback and
  47,131 without.
- AC-7: with real instrumentation, `STATELENS_BYZANTINE=panic` panics on the first input.
- R-NF-3: 13 executions per second both for the instrumented target and for the stock
  `simplex_cert_mock_twins_mutator` target (2,502 and 2,529 inputs in 3 minutes).

Section 8.1 lists what was checked for marshal, at commit `2649e4a668`.

The knowledge base has not been exercised with a real agent: section 5.6, the `kb` row of
5.4, and the knowledge-base part of the beacon step (7.4, prompt 13.9). AC-14 and AC-15
cover it.

---

## 2. Decisions

These decisions were made while writing this specification. The PRD states each of
them; the last column names the PRD requirement.

| ID | Decision | PRD requirement |
|---|---|---|
| D1 | Every file in a registry (`SL/invariants/<subsystem>/`) is active. Phase 1 writes there; humans review, edit and delete. There is no `status` field. | R-REG-1, R-P1-5 |
| D2 | The test gate runs the engine-level tests `simplex::tests::*` including the `slow` group, minus the Twins tests, plus the `simplex::statelens` self-tests. Only 7 of the 247 engine-level tests are outside the `slow` group, so a non-slow gate would check almost nothing. Twins tests run two live engines with one identity, which breaks per-replica ghost state. | R-S-P2-1 step 6 |
| D3 | Probes record presence: a counter is set to 1, never incremented. | R-FB-2 |
| D4 | Phase 2 agents run with full permissions in the checkout. Phase 1 agents run restricted. Campaigns MUST run on a dedicated machine or container. | R-AG-3 |
| D5 | The fuzz target `simplex_statelens` is added during a campaign to the existing `consensus/fuzz/simplex` package; no new package is created. `just run simplex_statelens` works unchanged. | G4, R-S-P2-1 step 1 |
| D6 | The macros are `macro_rules!` items re-exported with `pub(crate) use` and invoked by path: `crate::simplex::statelens::sl_implies!(...)`. `#[macro_export]` cannot work: `simplex` is declared inside `stability_scope!`, and macro-expanded `macro_export` macros cannot be called by absolute path from their own crate. | R-INS-4 |
| D7 | The Byzantine guard is built into the macros and into the ghost accessors, so no call site can forget it. The fuzz target calls `clear_compromised()` after `fuzz()` returns, not inside the runner, so compromised replicas stay guarded while the runtime shuts down. | R-INS-2, PRD section 8.4 |
| D8 | The runner hook also asserts that every scheme's own index equals its position in the participant list. | PRD section 8.4, AC-7 |
| D9 | `protocol`-scope invariants use a guarded ghost store shared by all honest replicas (`Global`, `with_global`). | R-INS-5 |
| D10 | A campaign runs in place in the operator's checkout, a fresh clone of the repository; StateLens never makes another clone. The campaign refuses a checkout with tracked changes outside `SL/` or with instrumentation from an earlier campaign, never commits, and records its changes in `SL/campaign/instrumentation.diff`. Uncommitted registry edits are used. | R-P2-1 |
| D11 | Tests use the `stable` toolchain; fuzz builds use the nightly pinned in `.github/workflows/slow.yml`. | R-P2-2 step 5 |
| D12 | Orchestration is one Python 3 script, `SL/scripts/statelens.py` (standard library only), wrapped by `SL/justfile`. | R-LAYOUT-1, R-AG-1 |
| D13 | No `Cargo.toml` is committed under `SL/`. `SL/runtime/*.rs` MUST stay `rustfmt`-clean, because CI's `just check-fmt` formats every `*.rs` file in the tree. | R-LAYOUT-2, R-NF-4 |
| D14 | Prompt files are named `analyst-<kind>.md`, one per source kind (`issue`, `design`, `comment`, `spec`, `paper`), plus a shared `analyst.md`. | R-LAYOUT-1, R-P1-2 |
| D15 | StateLens fuzz targets use only the `cert_mock` certificate scheme (`consensus/src/simplex/mocks/scheme.rs`, imported as `cert_mock` in `consensus/fuzz/core`). Every `fuzz::<P, ...>` call in a target template names a `P` whose `impl Simplex` in `consensus/fuzz/core/src/simplex.rs` sets `type Scheme = cert_mock::Scheme<...>`. At the reference commit these are `SimplexCertificateMock`, `SimplexCertificateMockAttributable`, `SimplexCertificateMockCustomRoundRobin` and `SimplexCertificateMockByzantineFirstLeader`; the committed target uses `SimplexCertificateMock`. No ed25519, BLS12-381 or secp256r1 scheme is used. The materialize step enforces this (section 7.2). The test gate is not affected. | R-P2-4 |
| D16 | Ghost state lives for one run. The campaign patches the deterministic runtime so that `Runner::new` calls a hook that clears it; independent runs in one test thread (for example the seeds of one test) no longer share history, while a crash-restart from a checkpoint keeps it (Appendix B.4). | R-INS-5, PRD section 8.4 |
| D17 | Registries are directories per subsystem: `invariants/simplex/` and `invariants/marshal/`, and likewise for false invariants. No invariant file lies directly under `invariants/` or `false-invariants/`. | R-REG-1, R-REG-8 |
| D18 | Each ID prefix has one global counter across all registries, so the marshal false invariant is FALSE-0002. The lint rejects an ID that two files use. | R-REG-1, R-REG-8, R-M-REG-2 |
| D19 | Scope vocabularies are per registry (section 4.2). | R-REG-2 |
| D20 | Profiles are data in `statelens.py` (section 5.5). `--profile` defaults to `simplex`. | R-P2-1 |
| D21 | Both subsystems use the runtime module at `consensus/src/simplex/statelens.rs` (Appendix A), and marshal code calls it as `crate::simplex::statelens::...`. | G8 |
| D22 | The per-subsystem parts of the prompts live in `prompts/subsystems/` (sections 13.11 to 13.14), and the shared prompts take them through placeholders. | R-P1-2 |
| D23 | A campaign does not run the fuzzer, in either profile. It ends after the test gate with the result `READY`, and prints, for each StateLens target, the command that runs it and the command that replays a crash. The operator runs the targets with the existing `just run` recipe, and chooses which ones, for how long, and with which libFuzzer arguments. The campaign passes no arguments to libFuzzer. Exit codes 5 and 6 are retired. | R-P2-2 step 7, R-P2-3, R-P3-1 |
| D31 | Beacon discovery happens inside the campaign's beacon step, not as a separate phase with its own artifact. The knowledge base is private and an instrumented checkout is never pushed, so nothing has to cross a reviewed boundary between them. | R-FB-4 |
| D32 | The knowledge base stays outside this repository and is read-only. `STATELENS_KB` names its roots, and an empty value disables beacon extraction without affecting anything else. | R-KB-1 to R-KB-3 |
| D33 | Retrieval is a structured index over the findings' claim fields plus full-text search of their prose sections. No vector store and no embedding service. | R-KB-4 |
| D37 | A finding's state and remediation status are shown to the instrumenter, not used to filter findings out. Weak evidence costs coverage, not correctness. | R-KB-8 |
| D42 | The beacon step is an agent loop over actions (read code, the five `kb` queries, add a probe), not a fixed procedure. Reading code leads, and a query is what the agent does when its hypothesis needs developer context. How long to spend on a candidate is the agent's judgment; there is no step budget. | R-FB-4 |

D24 to D30 concern marshal only; they are in section 8.2.

---

## 3. Committed layout

```
consensus/fuzz/statelens/
  docs/
    PRD.md
    SPEC.md
  README.md                      operator guide (Appendix D)
  config.env                     defaults (section 5.1)
  justfile                       recipes (section 5.3)
  .gitignore                     two lines: `campaign/` and `extract/`
  invariants/                    the registries; every INV-*.md is active (section 4.1)
    simplex/
    marshal/                     the marshal invariants
  false-invariants/
    simplex/FALSE-0001.md        deliberately false invariant for AC-6 (Appendix C)
    marshal/FALSE-0002.md        deliberately false invariant for AC-10 (Appendix E)
  examples/                      worked analyses the Phase 2 prompts point agents at
    statelens_commonware_voter_example.md     the Simplex voter (sections 13.8, 13.9)
    statelens_commonware_marshal_example.md   marshal's deferred verification path
  templates/
    invariant.md                 reference format (section 4.5)
  prompts/
    analyst.md                   Phase 1, shared part (section 13.1)
    analyst-issue.md             Phase 1, per kind (sections 13.2 to 13.6)
    analyst-design.md
    analyst-comment.md
    analyst-spec.md
    analyst-paper.md
    instrument.md                Phase 2, shared rules and API (section 13.7)
    instrument-invariants.md     Phase 2, bind invariants (section 13.8)
    instrument-beacons.md        Phase 2, beacon probes (section 13.9)
    repair.md                    Phase 2, compile repair (section 13.10)
    subsystems/
      simplex-analyst.md         Phase 1, Simplex part (section 13.11)
      marshal-analyst.md         Phase 1, marshal part (section 13.12)
      simplex-instrument.md      Phase 2, Simplex rules (section 13.13)
      marshal-instrument.md      Phase 2, marshal rules (section 13.14)
  runtime/
    statelens.rs                 runtime support module (Appendix A)
    target.rs                    fuzz target, cert_mock scheme only (Appendix B.1, D15)
  scripts/
    statelens.py                 lint, extract, kb, campaign (sections 5 to 7)
```

Constraints on committed files:

- Plain ASCII only (R-NF-5).
- No `Cargo.toml` anywhere under `SL/` (R-LAYOUT-2).
- `runtime/*.rs` pass `rustfmt +<pinned nightly> --edition 2024 --check` with the
  repository `rustfmt.toml`.
- Nothing outside `SL/` is changed (R-LAYOUT-3).

---

## 4. Invariant registry

### 4.1 Files and IDs

- One invariant per file: `SL/invariants/<subsystem>/INV-NNNN.md`, where `<subsystem>` is
  `simplex` or `marshal`, and `NNNN` is a zero-padded decimal of at least 4 digits.
- False invariants live in `SL/false-invariants/<subsystem>/FALSE-NNNN.md` and are used
  only when `STATELENS_FALSE_INVARIANTS=1` (section 7.1).
- IDs are global. The next ID is `1 + max(N)` over the `INV-N` files of all registries,
  and likewise over the `FALSE-N` files. Deleting the file with the highest ID lets its ID
  be reused; this is accepted.

### 4.2 Front matter

YAML front matter between two `---` lines. Keys, in this order:

| Key | Required | Value |
|---|---|---|
| `id` | yes | Equal to the file name without `.md`. |
| `title` | yes | One line, at most 80 characters. |
| `source_kind` | yes | `human`, `issue`, `design`, `comment`, `spec` or `paper`. |
| `source_ref` | yes | URL, path, `path:line`, document section, or paper page. |
| `scope` | yes | Inline list, one or more of the registry's scope values (below). |

| Registry | Allowed `scope` values |
|---|---|
| `simplex` | `protocol`, `replica`, `voter`, `batcher`, `resolver`, `cross-actor` |
| `marshal` | `protocol`, `replica`, `core`, `resolver`, `standard`, `coding`, `application`, `cross-component`; here `resolver` is marshal's backfill resolver |

### 4.3 Body

Level-2 sections, in this order:

1. `## Statement` (required): one sentence in EARS form (section 4.4). It MUST NOT name
   implementation identifiers.
2. `## Rationale` (required): why it must hold.
3. `## Evidence` (required): what the source says. For `issue`, the violating
   scenario.
4. `## Preconditions / assumptions` (optional).
5. `## Observation hints` (optional, non-binding): where the concepts live in the code.

### 4.4 EARS statements and how they are checked

The system is "the replica" (one honest replica) or, for scope `protocol`, "the
protocol".

| EARS pattern | Form | Checked with |
|---|---|---|
| Ubiquitous | `The replica shall <response>.` | `sl_assert!(cond)` |
| State-driven | `While <state>, the replica shall <response>.` | `sl_implies!(state, response)` |
| Event-driven | `When <trigger>, the replica shall <response>.` | `sl_implies!(trigger, response)` at the trigger site |
| Unwanted behavior | `If <condition>, then the replica shall <response>.` | `sl_implies!(condition, response)` |
| Complex | `While <state>, when <trigger>, the replica shall <response>.` | `sl_implies!(state && trigger, response)` |

Prohibitions use `shall not`. History ("after", "once", "never again") is kept in
ghost state (section 9.4) and checked at the later action.

### 4.5 `templates/invariant.md` (verbatim)

~~~markdown
---
id: INV-NNNN
title: <one line, at most 80 characters>
source_kind: <human | issue | design | comment | spec | paper>
source_ref: <URL, path, path:line, document section, or paper page>
scope: [<one or more of the registry's scope values, listed in the prompt context>]
---

## Statement
<One EARS sentence about "the replica", or "the protocol" for scope protocol.>

## Rationale
<Why it must hold: the protocol argument, or the reference that states it.>

## Evidence
<What the source says. For an issue: the violating scenario in two to five sentences.>

## Preconditions / assumptions
<Optional. Conditions or modeling assumptions under which the Statement is claimed.
Delete this section if unused.>

## Observation hints
<Optional and non-binding. Where the concepts live in today's code. Delete this section
if unused.>
~~~

### 4.6 Lint rules

`statelens.py lint [PATH...]` checks each file (default: every `*.md` in
`SL/invariants/*/` and `SL/false-invariants/*/`; `.gitkeep` files are ignored) and prints
`path: problem` for every violation:

1. The file is in `invariants/<subsystem>/` and named `INV-\d{4,}\.md`, or in
   `false-invariants/<subsystem>/` and named `FALSE-\d{4,}\.md`, where `<subsystem>` is a
   known registry. A Markdown file directly in `invariants/` or `false-invariants/` is a
   problem.
2. The file starts with `---`, and a second `---` line closes the front matter.
3. Every front-matter line is `key: value`. Required keys are present and non-empty;
   unknown keys are reported.
4. `id` equals the file stem.
5. `source_kind` is one of the allowed values.
6. `scope` is `[a, b, ...]` with the allowed values of the file's registry only
   (section 4.2).
7. `## Statement`, `## Rationale` and `## Evidence` are present, in this order, and
   non-empty.
8. Only ASCII characters.
9. No two files, in any registries, have the same `id`; a repeated ID is a problem for
   each file that has it.

Exit code 0 when clean, 3 otherwise. EARS conformance is not linted; humans review it.

### 4.7 False invariants

Each registry has a deliberately false invariant, on which a working campaign must panic:
`SL/false-invariants/simplex/FALSE-0001.md` (Appendix C, AC-6) and
`SL/false-invariants/marshal/FALSE-0002.md` (Appendix E, AC-10). They follow the registry
format with an ID prefix of `FALSE`. A campaign binds those of its profile's subsystems,
and only when `STATELENS_FALSE_INVARIANTS=1`.

---

## 5. Configuration and command line

### 5.1 `config.env` (verbatim)

~~~
# StateLens defaults. An environment variable with the same name overrides a value
# here, and `--agent` overrides STATELENS_AGENT.

# Agent CLI used by extract and campaign: claude or codex.
STATELENS_AGENT=claude

# Model passed to the agent CLI; empty means the CLI default.
STATELENS_CLAUDE_MODEL=
STATELENS_CODEX_MODEL=

# Toolchain for the test gate and the check command.
STATELENS_TEST_TOOLCHAIN=stable

# Toolchain for fuzz builds; empty means NIGHTLY_VERSION from
# .github/workflows/slow.yml.
STATELENS_FUZZ_TOOLCHAIN=

# Knowledge base roots for beacon extraction, separated by `:`. Empty disables
# beacon extraction; nothing else depends on it.
STATELENS_KB=
~~~

Parsing: `KEY=VALUE` lines; `#` starts a comment line; values are not shell-expanded.
Precedence: command-line flag, then non-empty environment variable, then `config.env`.

Generated outputs stay inside the subproject and are ignored by git: `SL/campaign/` for
campaigns, `SL/extract/` for Phase 1 logs, paper text, the knowledge-base index
(`SL/extract/kb-index.json`).

The index holds every indexed finding's summary, tags and citations. It is ignored by git,
like the campaign logs that quote what the instrumenter retrieved.

Environment-only switches:

| Variable | Effect |
|---|---|
| `STATELENS_FALSE_INVARIANTS=1` | Campaign also binds the false invariants of its profile's subsystems, `SL/false-invariants/<subsystem>/*.md`, next to their registries (AC-6, AC-10). |
| `CARGO_TARGET_DIR` | Passed through. By default builds use the checkout's `target/`. |
| `STATELENS_BYZANTINE`, `STATELENS_FEEDBACK` | Read by the runtime module (section 9.5). |

### 5.2 Prerequisites

A fresh clone of the repository on a dedicated machine or container (D4, D10), with
`git`, `python3` (3.9 or later), `just`, `cargo` with the `stable` and pinned nightly
toolchains, `cargo-nextest`, `cargo-fuzz`, and the chosen agent CLI (`claude` or
`codex`), logged in. Phase 1 with `issue` sources also needs `gh` (logged in) or
network access for `curl`. Phase 1 with PDF papers uses `pdftotext` or the Python
`pypdf` module when available. Beacon extraction needs `STATELENS_KB` to name at least
one readable corpus root.

### 5.3 `justfile` (verbatim)

~~~
# StateLens recipes. See README.md.

set positional-arguments := true

# Turn sources into invariants: just extract <kind> <source>...
extract *args:
    python3 scripts/statelens.py extract "$@"

# Instrument this checkout and build the StateLens targets: just campaign [--agent A] [--profile P]
campaign *args:
    python3 scripts/statelens.py campaign "$@"

# Fuzz a target a campaign built: just run <target> [-- -fork=8 -max_total_time=600]
run target *args:
    cd .. && just run "$@"

# Campaign, then fuzz one of its targets: just fuzz <target> [-- -fork=8]
fuzz target *args:
    #!/usr/bin/env bash
    set -euo pipefail
    # The target names its profile: only the `simplex` profile builds `simplex_statelens`.
    target="$1"
    shift
    if [ "$target" = "simplex_statelens" ]; then profile=simplex; else profile=marshal; fi
    just campaign --profile "$profile"
    just run "$target" "$@"

# Undo what a campaign wrote to this checkout: just clean [--yes]
clean *args:
    python3 scripts/statelens.py clean "$@"

# Check invariant files: just check-invariants [path...]
check-invariants *args:
    python3 scripts/statelens.py lint "$@"
~~~

### 5.4 `scripts/statelens.py`

Standard library only; Python 3.9 compatible. The script finds the repository root with
`git rev-parse --show-toplevel` from its own directory, and prints progress lines
prefixed with `statelens:`.

| Subcommand | Usage | Exit codes |
|---|---|---|
| `lint` | `lint [PATH...]` | 0 clean, 3 problems |
| `extract` | `extract [--agent A] [--registry R] KIND SOURCE...`, where `R` is `simplex` (default) or `marshal` | 0 done (including zero files), 1 usage, 2 agent failed, 3 lint problems |
| `kb` | `kb modules [--registry R]`, `kb find [--registry R] TERM...`, `kb grep [--registry R] TEXT`, `kb cites [--registry R] PATH`, `kb show [--registry R] IDENTIFIER [SECTION]` (section 5.6) | 0 done, including no hits, 1 usage, an identifier out of the registry's scope, or a section that is not state-bearing, 2 no readable corpus root |
| `clean` | `clean [--yes]`; without `--yes` it prints what it would undo and changes nothing | 0 in every case; a preview is not a failure |
| `campaign` | `campaign [--agent A] [--profile P] [--stop-after STEP]`, where `P` is `simplex` (default) or `marshal` | 0 ready (the StateLens targets are built and the test gate passed) or stopped after a step, 1 usage, 2 setup or agent failure (including a missing tool or a checkout that is not fresh), 3 build failed, 4 test gate failed; codes 5 and 6 are no longer used (D23) |

`--stop-after` accepts `materialize`, `instrument` or `build`. It exists for
development and acceptance testing and is not a campaign parameter in the PRD sense. A
campaign that stops this way exits with code 0 and reports the result
`STOPPED after <step>`.

Placeholders in prompt files have the form `{{NAME}}` (upper case). Rendering MUST fail
on a placeholder without a value. Every rendered prompt is saved next to its log.

### 5.5 Profiles

A campaign's profile selects what it binds, instruments, tests and builds (D20). Profiles
are data in `statelens.py`:

| Item | `simplex` | `marshal` |
|---|---|---|
| Registries, in binding order | `simplex` | `simplex`, `marshal` |
| Knowledge-base `module` filter, per component's subsystem | `consensus/simplex` and its submodules | the same, and `consensus/marshal` and its submodules |
| Editable roots (scope check) | `consensus/src/simplex/` | `consensus/src/simplex/`, `consensus/src/marshal/` |
| Warn-only paths | `consensus/src/simplex/mocks/`, `consensus/src/simplex/scheme/` | the same, and `consensus/src/marshal/mocks/` |
| Beacon components, as `ACTOR`: `ACTOR_DIR` | `voter`, `batcher`, `resolver`: `consensus/src/simplex/actors/<actor>` | the three of `simplex`; `marshal.core`: `consensus/src/marshal/core`; `marshal.standard`: `consensus/src/marshal/standard`; `marshal.coding`: `consensus/src/marshal/coding` |
| Materialize edits | Section 7.2, edits 1 to 8 | Section 7.2, edits 1 to 3 and 6 to 8, and edits M1 to M3 (section 8.3) |
| Cryptography check | D15 (section 7.2) | Section 8.4 |
| Fuzz package | `consensus/fuzz/simplex` | `consensus/fuzz/marshal` |
| Fuzz targets it builds | `simplex_statelens` | One StateLens variant per target in `consensus/fuzz/marshal/fuzz_targets/` |
| Test filter | Section 7.7 | Section 8.3, step 6 |

### 5.6 Knowledge base

**What it is.** One or more read-only corpus roots named by `STATELENS_KB` (D32). A corpus
is a directory tree of Markdown documents of two kinds:

- **Findings**: reports under `findings/<state>/<name>.md`, where `<state>` is one of
  `valid`, `tested`, `triaged`, `intake` or `invalid`. Each opens with a fenced ` ```claim `
  block of `key: value` lines, of which `module`, `summary`, `tags`, `severity_current`,
  `confidence`, `remediation_status` and `related_findings` are read, followed by level-2
  prose sections. The state-bearing sections are `## Root Cause`, `## Lifecycle Events`,
  `## Exploitation Or Trigger Conditions` and `## Context`.
- **Documents**: Markdown under the root's `kb/`, `config/` or `context/` directory. These
  are the design-document tier, the paper's second artifact kind. They are retrieved by
  `kb grep` only and cited by path. A document carries no `module`, so it is returned for
  every registry; R-KB-5 scopes findings, and a document is scoped by the component the
  instrumenter is working on and by its own judgment instead. Markdown anywhere else under a root
  is not indexed.

A corpus root that is missing, unreadable, or has no `findings/` directory and no Markdown
document is reported and skipped. When no root survives, the command exits with code 2
(R-KB-2).

**Read-only.** StateLens opens corpus files for reading only, and writes nothing under a
corpus root (R-KB-3). The index lives in `SL/extract/kb-index.json`.

**Index.** Building or refreshing the index walks every root in full and records, per
finding: its identifier (the file stem), the corpus root, the path, the state from the
directory, every field of the claim block that is read, and the byte offsets of the
state-bearing sections, and the files and symbols the finding cites. The index is keyed by
identifier, not by path, because the corpus moves a finding between state directories as it
is triaged. Every refresh re-walks the
roots and drops an entry whose file is gone; an entry whose path or state changed is
rewritten. Re-parsing is skipped only for a file whose path, modification time and size are
all unchanged, and the index file is rewritten only when some entry was added, removed or
re-parsed, so a read-only query leaves it untouched. A corpus file is read at most once per
invocation. A finding whose claim block is absent or unparsable is indexed by path and
its path, state and citations alone, with every claim field empty, and every command that
refreshes the index reports how many such findings
there are, from the index rather than from the parse, so the count survives the cache. Two
findings with the same identifier in different roots
are both indexed, and the root is part of the identity the commands print.

**Retrieval.** The agent must reach the corpus only through these commands; section 12 says
how far each agent CLI enforces that. It runs these commands, from the
repository root, and gets back only what they print (D33):

| Command | Returns |
|---|---|
| `kb modules` | Every `module` value in the index that passes the registry's filter, with a count |
| `kb find TERM...` | Up to 20 findings whose `summary` or `tags` match, ranked; per hit the identifier, state, `module`, severity, remediation status, `summary`, and the files and symbols it cites |
| `kb grep TEXT` | Up to 40 snippets from the state-bearing sections and the documents, each with its identifier or path, the section name, and three lines of context |
| `kb cites PATH` | Up to 20 findings that cite a file under `PATH`, most citations first; per hit the identifier, state, how many citations, remediation status, `summary`, which of its files fall under `PATH`, and its symbols |
| `kb show IDENTIFIER [SECTION]` | One finding's claim block, the files and symbols it cites and the names of its state-bearing sections, or one of those sections |

Each is `python3 consensus/fuzz/statelens/scripts/statelens.py kb <subcommand>`. The
`--registry` flag defaults to `simplex`, so the command lines rendered into the prompt pass
the run's registry explicitly on every query, `show` included. Section 12 gives the allowlist entry
that permits exactly this command.

`kb cites` is the entry point for a component: it turns a path in this repository into the
findings about that code, so the instrumenter can ask what is known about the file in front
of it.

`kb find`, `kb grep` and `kb cites` are restricted to the `module` filter of the subsystem
whose component is being instrumented (section 5.5), not of the profile, so a marshal
component's queries never return Simplex findings and the reverse.
The `module` filter applies to findings, so `kb show` refuses a finding out of scope exactly
as it refuses an unknown identifier; a document has no `module` and is addressable by its
path through `show` as well as `grep`, returning neither a claim block nor a state-bearing
section; this matters because a finding's claim block names related findings, and
those names must not become a way around the filter. `kb show` also refuses a section
outside the state-bearing set, so `## Impact` and the other exploit-bearing sections are not
reachable through the interface at all. Every command prints the corpus root of each hit,
because one identifier can occur in two roots.

**Retrieval is an action, not a prologue.** The prompt gives the agent a loop rather than a
procedure: at each step it chooses between reading code, one of the five `kb` queries, and
writing a beacon. Reading code leads, because a candidate announces itself there as an enum, a
`debug_assert!`, a per-view flag or a comment about a race. A query is what the agent does
when its hypothesis needs context the source does not carry: what an assumption means, why it
matters, whether it has failed before, or which code manages the transition (D42). This is the paper's on-demand retrieval and its query refinement, within
one agent run. The campaign's instrumenter is the agent doing this, so retrieval and
instrumentation happen in one loop. What this project does not have is the paper's Phase 2
frontier: no call-graph or data-flow tool, so tracing a state across functions is search and
reading, and the findings' own citations stand in for it.

**Citations.** A hit names the files and symbols its finding cites: paths matching
`<crate>/src/**/*.rs`, with an optional `:line`, and backticked `Type::method` symbols, each
list ordered by how often the finding cites it. This is what connects a retrieved feature to
the relevant files and functions, and it is the material a beacon's `Seed symbols` and
`Candidate sites` are built from, so the agent does not have to rediscover by reading what
the corpus already states.

Citations are harvested from every section of a finding, including those whose prose is not
retrievable. In this corpus they sit overwhelmingly in `## Evidence`, which is not
state-bearing, so harvesting only from the state-bearing sections would find almost none. A
path or a symbol is a pointer into this repository's own code, not exploit detail, so
exposing the citation while withholding the prose around it keeps R-KB-6 intact.

**Module normalization.** Before filtering, a `module` value is normalized: a value naming
a source path (`consensus/src/simplex/actors/voter/actor.rs`) is mapped to its crate module
(`consensus/simplex`), and a trailing file name is dropped. A value that normalizes to
`consensus` alone is too coarse to attribute and matches no registry; the finding is
indexed and reported in the `kb modules` output under `consensus`, so an operator can see
what was excluded.

**Determinism.** `kb find` ranks by: an exact `module` match above a submodule match; then
the number of distinct terms matched in `summary` and `tags`; then `valid` above `tested`
above `triaged` above `intake` above `invalid`. `kb grep` matches a case-insensitive
literal substring, never a regular expression, so the two backends of section 5.2 agree; it
orders hits by corpus root in the order `STATELENS_KB` lists them, then by path, then by
byte offset. All three of `kb find`, `kb cites` and `kb grep` truncate after their limit and say how many
hits were dropped. `kb cites` orders by citation count, then by the state rank above, then by
index order. Ties keep
index order, so one index gives one answer.

---

## 6. Phase 1: discover invariants

### 6.1 Sources

| Kind | Source syntax |
|---|---|
| `issue` | GitHub URL of an issue or pull request, or `owner/repo#N` |
| `design` | Local path or URL, with an optional `#section` suffix |
| `comment` | File or directory under `consensus/src/<registry>`, optionally `path:line` or `path:start-end` |
| `spec` | Quint, TLA+ or Lean file, optionally `path:line` |
| `paper` | Local PDF or text file, or URL, with an optional `#page=N` suffix |

Several sources of one kind MAY be passed at once (R-P1-1). Local paths are relative to
the repository root, which is the agent's working directory.

### 6.2 Procedure

1. Validate `KIND`, the registry, and that at least one source is given.
2. Record the content hash of every file under `SL/invariants/`, in all registries.
3. Compute `NEXT_ID`, which is global (section 4.1).
4. For `paper`, convert each local `.pdf` source (ignoring a `#...` suffix) to text in
   `SL/extract/papers/<stem>-<digest>.txt`, where `<digest>` is the first 10 hex digits of
   the SHA-256 of the resolved path, so papers with the same file name do not overwrite
   each other. Convert with `pdftotext -layout`, falling back to `pypdf`. When
   neither is available, pass the PDF as is. List the text next to the source.
5. Render the prompt: `prompts/analyst.md`, a blank line, then `prompts/analyst-<KIND>.md`.
   Placeholders: `KIND`, `NEXT_ID`, `TEMPLATE` (the content of `templates/invariant.md`),
   `SOURCES` (one `- <source>` line per source, with `(text: <path>)` appended for
   converted papers), `REGISTRY` (the registry name), `CONTEXT` (the content of
   `prompts/subsystems/<registry>-analyst.md`) and `SOURCE_ROOT`
   (`consensus/src/<registry>`).
6. Run the agent with the Phase 1 invocation (section 12), working directory = the
   repository root, prompt on standard input. Log to
   `SL/extract/<UTC timestamp>-<kind>.log`.
7. New files = files that did not exist in step 2. Report any pre-existing file whose
   hash changed as a problem ("agent modified or deleted an existing invariant"), and any new file
   outside `SL/invariants/<registry>/` ("agent wrote outside the registry").
8. Lint the new files (section 4.6).
9. Print each new file with its title and the reminder: "Every file in a registry is
   used by the next campaign that binds it. Review, edit or delete these files first."

---

---

## 7. StateLens for Simplex

This chapter specifies StateLens for the Simplex subsystem: the campaign of the `simplex`
profile, which instruments the code and generates the fuzz target (Phase 2, sections 7.1
to 7.9), and how the operator runs the target (Phase 3, sections 7.10 to 7.12). Where a
rule depends on the profile, it says so; chapter 8 gives what differs for marshal.

### 7.1 Preconditions and setup

A campaign runs in place in the checkout (D10); `repo` is its root
(`git rev-parse --show-toplevel`). StateLens never makes another clone.

1. Check the preconditions, in this order. Each failure exits with code 2; the last two
   ask for a fresh clone:
   - `cargo`, `cargo-nextest`, `cargo-fuzz` and `just` are on `PATH` (the agent CLI is
     checked before), so a missing tool fails before any agent time is spent;
   - none of `consensus/src/simplex/statelens.rs`,
     `consensus/fuzz/simplex/fuzz_targets/simplex_statelens.rs` and
     `consensus/fuzz/marshal/fuzz_targets/*_statelens.rs` exists (an earlier campaign
     already instrumented this checkout);
   - `git status --porcelain --untracked-files=no` lists no path outside `SL/`.
2. `base = git rev-parse HEAD`.
3. Recreate `SL/campaign/` with `logs/`, `prompts/` and `meta.json`: `base`, `agent`,
   `model`, `profile`, test and fuzz toolchains, start time, invariant IDs, and `targets`
   (the StateLens targets the campaign builds).
4. The invariants to bind are those of the profile's registries, in the order of section
   5.5. For each registry they are `SL/invariants/<subsystem>/*.md`, plus
   `SL/false-invariants/<subsystem>/*.md` when `STATELENS_FALSE_INVARIANTS=1`, sorted by
   ID. Uncommitted files are included. Lint them (section 4.6) and print any problem as a
   warning.
5. Create `SL/campaign/plan.md` with this content, then fill in the values:

~~~markdown
# StateLens instrumentation plan

- Base commit: <base>
- Agent: <agent>
- Profile: <profile>
- Invariants: <count> (<registry>: <ID, ID, ...>; <registry>: <ID, ID, ...>)

## Invariants

## Beacon probes

| Label | File and function | a | b | Beacon |
|---|---|---|---|---|
~~~

All steps run with working directory `repo` unless stated otherwise. The campaign never
commits, stages, stashes or resets anything, apart from `git add --intent-to-add` on the
files the campaign creates (section 7.2) and on the files its agents create under the
profile's editable roots (section 7.5).

### 7.2 Step 1: materialize

This section gives the edits of the `simplex` profile. The `marshal` profile makes edits 1
to 3 and 6 to 8, and edits M1 to M3 with its own cryptography check (sections 8.3 and
8.4).

Before any edit, the script checks the cryptography rule (D15). For every target template
in `SL/runtime/` (every `*.rs` file except `statelens.rs`) and every `fuzz::<P` or
`fuzz_audit::<P` call in it, `consensus/fuzz/core/src/simplex.rs` MUST contain
`impl Simplex for P {` with `type Scheme = cert_mock::Scheme<` inside that impl block. A
template that fails the check, or that contains no such call, aborts the campaign with
exit code 2 and a message that names the template and `P`.

Each edit that uses an anchor MUST find exactly one line equal to the anchor. A missing
or repeated anchor aborts the campaign with exit code 2 and a message that names the
file and the anchor.

| # | File | Edit |
|---|---|---|
| 1 | `consensus/src/simplex/statelens.rs` | Create as a copy of `SL/runtime/statelens.rs`. |
| 2 | `consensus/src/simplex/mod.rs` | After the line `pub mod types;` insert `pub mod statelens;`. |
| 3 | `consensus/Cargo.toml` | After the line `thiserror.workspace = true` insert `sancov.workspace = true`. |
| 4 | `consensus/fuzz/simplex/fuzz_targets/simplex_statelens.rs` | Create as a copy of `SL/runtime/target.rs`. |
| 5 | `consensus/fuzz/simplex/Cargo.toml` | Append the `[[bin]]` block of Appendix B.2. |
| 6 | `consensus/fuzz/core/src/lib.rs` | After the line `let compromised = case.compromised.iter().copied().collect::<HashSet<_>>();` (with four leading spaces) insert the hook of Appendix B.3. |
| 7 | `runtime/src/deterministic.rs` | Before the line `impl From<Config> for Runner {` insert the static of Appendix B.4. |
| 8 | `runtime/src/deterministic.rs` | After the line `pub fn new(cfg: Config) -> Self {` (with four leading spaces) insert the call of Appendix B.4. |

Anchors in the same file are applied from the bottom up, so earlier insertions do not
move later anchors.

Then run `git add --intent-to-add` on the two created files, so that `git diff` shows
them, and record the baseline snapshot for the scope check (section 7.5): every path that
`git status --porcelain --untracked-files=all` lists, with a hash of its content.

`sancov` is already a workspace dependency and is in `Cargo.lock`, so no network access
is needed. No workspace `Cargo.toml` edit is needed for `cfg(fuzzing)`: the module
allows `unexpected_cfgs` itself.

### 7.3 Step 2: bind invariants

1. Take the invariants of section 7.1 step 4. When there are none, skip to step 3 with a
   warning.
2. Split them into batches of 8 within one registry, in the order of section 5.5.
3. For each batch, render `prompts/instrument.md`, a blank line, then
   `prompts/instrument-invariants.md`. Placeholders: `BASE`, `PLAN`
   (`consensus/fuzz/statelens/campaign/plan.md`), `CHECK` (section 7.6),
   `INVARIANT_IDS` (comma separated), `INVARIANTS` (for each file, a line
   `===== <path from repo root> =====` followed by its content), `REGISTRY` (the batch's
   registry) and `SUBSYSTEM_RULES` (the content of
   `prompts/subsystems/<registry>-instrument.md`).
4. Run the agent with the Phase 2 invocation (section 12). Save the prompt to
   `SL/campaign/prompts/invariants-<registry>-<n>.md` and the output to
   `SL/campaign/logs/invariants-<registry>-<n>.log`.
5. A non-zero agent exit aborts the campaign with exit code 2.

### 7.4 Step 3: beacon probes

For each beacon component of the profile (section 5.5), render `prompts/instrument.md`, a
blank line, then `prompts/instrument-beacons.md`. Placeholders: `BASE`, `PLAN`, `CHECK`,
`ACTOR` and `ACTOR_DIR` from the profile table, `SUBSYSTEM_RULES` of the component's
subsystem, and `QUERY`, the knowledge-base commands of section 5.6 with the concrete command
line for each, carrying the `module` filter of the component's subsystem. Run and log as in
section 7.3, with `beacons-<ACTOR>` as the file stem.

The agent discovers the beacons in this step. It reads the component's code, where a
candidate announces itself as a state enum, a `debug_assert!`, a per-view flag or a comment
about a race, and it queries the knowledge base when a candidate needs developer context the
source does not carry: what an assumption means, why it matters, whether it has failed
before, or which code manages the transition. The campaign resolves the corpus roots during
setup (section 7.1) and refreshes the index before the first agent step, so a query costs no
corpus walk. When `STATELENS_KB` names no readable root, the campaign says so, `QUERY` is
empty and the step proceeds from the code alone.

### 7.5 Step 4: finalize the plan and check scope

1. Parse `plan.md`: headings `### <ID>: <title>` and lines `- Status: bound|partial|unbound`.
2. For every registry ID without a heading, append a section with `Status: unbound` and
   `Notes: not processed by the agent`.
3. Take a new snapshot (section 7.2) and compare it with the baseline. Every path that is
   new, changed or gone since the baseline:
   - outside the profile's editable roots (section 5.5) aborts the campaign with exit
     code 2 ("instrumentation edited <path>"), except `Cargo.lock`, which the first build
     updates for the new `sancov` dependency;
   - under a warn-only path of the profile produces a warning.
4. Run `git add --intent-to-add` on every untracked file under the editable roots (files
   the agents created; no content is staged), so that `git diff` and the counts include
   them. Then count the deleted lines under the editable roots (`git diff --numstat`),
   the added `sl_assert!`, `sl_implies!` and `sl_probe!` call sites, and the beacon table
   rows.
5. Append a `## Summary` section to the plan with the status counts, call-site counts,
   beacon-table row count and deleted-line count. Deleted lines are expected to be 0; any other
   value must match the "Edited lines" entries of the plan.
6. Write `SL/campaign/instrumentation.diff` with the output of `git diff`.

### 7.6 Step 5: build and repair

Commands, run in order:

1. `CHECK`: `cargo +<test toolchain> check -p commonware-consensus --lib --tests`
2. `FUZZBUILD`: `cargo +<fuzz toolchain> fuzz build --fuzz-dir consensus/fuzz/simplex simplex_statelens`;
   for the `marshal` profile, the build of each StateLens variant (section 8.3).

The fuzz toolchain is `STATELENS_FUZZ_TOOLCHAIN`, or the value of `NIGHTLY_VERSION:` in
`.github/workflows/slow.yml`, or `nightly`.

On a failure, run a repair attempt: render `prompts/instrument.md`, a blank line, then
`prompts/repair.md`. Placeholders: `BASE`, `PLAN`, `CHECK`, `ATTEMPT`, `COMMAND` (the
failing command), `ERRORS` (its last 150 output lines), `SUBSYSTEM_RULES` (the parts of
all the profile's subsystems, in the order of section 5.5). Run the agent, repeat the
section 7.5 scope check, then run both commands again. After 3 failed attempts, exit with
code 3. After a successful repair, write `SL/campaign/instrumentation.diff` again.

### 7.7 Step 6: test gate

~~~
cargo +<test toolchain> nextest run -p commonware-consensus --lib --no-fail-fast \
  --ignore-default-filter \
  -E '(test(/^simplex::tests::/) & not test(/::test_twins/)) | test(/^simplex::statelens::/)'
~~~

Log to `SL/campaign/logs/test.log`. On failure, print the `FAIL` lines and every
`[statelens][` line, write the summary (section 7.9), and exit with code 4. The whole
gate is 240 tests and took 125 s on 16 cores at the verified commit. The `marshal`
profile adds the marshal tests (section 8.3, step 6).

### 7.8 Step 7: hand-over

The campaign does not run the fuzzer (D23). After the test gate passes, it writes the
summary of section 7.9 with the result `READY`, and exits with code 0. The `run` and
`replay` lines of the summary are where Phase 3 starts (section 7.10).

### 7.9 Result reporting

The console, and `SL/campaign/summary.txt` for a campaign that passed its preconditions,
end with these lines (omit those that do not apply). A run refused by the preconditions
prints its summary to the console only, so it cannot overwrite the summary of the
campaign that instrumented the checkout:

~~~
statelens: checkout   <repo>
statelens: base       <base>
statelens: agent      <agent>
statelens: profile    <profile>
statelens: invariants <n> (bound <b>, partial <p>, unbound <u>)
statelens: sites      <k> assertion sites, <m> probe sites, <d> deleted lines
statelens: result     READY | STOPPED after <step> | PANIC (tests) | BUILD FAILED | SETUP FAILED
statelens: reason     <why the campaign stopped, for any result other than READY>
statelens: panic      <first [statelens][...] line, or the first panic message>
statelens: run        cd <repo>/consensus/fuzz && NIGHTLY_VERSION=<fuzz toolchain> just run simplex_statelens -- -rss_limit_mb=4000 -print_final_stats=1
statelens: replay     cd <repo>/consensus/fuzz && CONSENSUS_FUZZ_LOG=1 NIGHTLY_VERSION=<fuzz toolchain> just run simplex_statelens simplex/artifacts/simplex_statelens/<crash file>
~~~

The `run` and `replay` lines appear only with `READY`, one pair per target: the `marshal`
profile prints one pair per StateLens variant (section 8.3). The `replay` line is a
template: the operator puts in the crash file that libFuzzer wrote, and adds the
`STATELENS_BYZANTINE` value of the run that found it (section 7.11).

### 7.10 Phase 3: running a target

Phase 3 is manual (D23). The operator runs the StateLens fuzz targets that a `READY`
campaign built, in the instrumented checkout. StateLens has no command for this phase.

The `run` lines of the summary (section 7.9) give one command per target. For the
`simplex` profile, in `consensus/fuzz`:

~~~
NIGHTLY_VERSION=<fuzz toolchain> just run simplex_statelens -- \
  -rss_limit_mb=4000 -print_final_stats=1
~~~

- The operator chooses which targets to run and adds libFuzzer arguments as needed, for
  example `-fork=<N>` to use N cores, or `-max_total_time=<s>` to bound the run.
- A run ends when the target panics or the operator stops it. libFuzzer, including its
  fork mode, stops at the first crash.
- The operator should not pass `-artifact_prefix` or `-exact_artifact_path`, which move the
  crash file elsewhere, or any `-handle_*` switch, which can stop libFuzzer from reporting
  a crash and saving its input.
- PRD section 9.4 lists the marshal variants whose adversary runs Simplex or marshal
  code; only they exercise the Byzantine guard.

### 7.11 Phase 3: crashes and replay

- libFuzzer writes a crashing input to the artifact directory of the target's package:
  `consensus/fuzz/simplex/artifacts/simplex_statelens/`, or
  `consensus/fuzz/marshal/artifacts/<variant>/` for a marshal variant (R-ART-1).
- The `replay` line of the summary, with the crash file put in, replays the input in the
  same checkout, and replay reproduces the panic (R-NF-2).
- Replay with the `STATELENS_BYZANTINE` value of the run that found the crash. A
  guard-test crash exists only with `STATELENS_BYZANTINE=panic`, and `check` changes which
  replicas are checked; without the same value, the input may run cleanly. For example:
  `STATELENS_BYZANTINE=panic` followed by the `replay` line.
- For the Simplex target, `CONSENSUS_FUZZ_LOG=1` also prints the decoded input; the
  marshal harnesses do not read it.

### 7.12 Phase 3: investigation

The instrumented checkout stays as it is until the operator discards it. The operator
uses:

- `SL/campaign/plan.md`: how each invariant was bound;
- `SL/campaign/instrumentation.diff` (or `git diff`): every change the campaign made;
- `SL/campaign/logs/` and `SL/campaign/prompts/`;
- the crash file, replayed as in section 7.11.

To locate the code for an invariant: `rg '\[statelens\] INV-0007' consensus/src`.

An instrumented checkout must not be committed or reused for another campaign; the next
campaign starts from a fresh clone.

---

## 8. StateLens for Marshal

This chapter specifies StateLens for the marshal subsystem: the `marshal` profile of PRD
chapter 9. A `marshal` campaign binds the simplex and marshal registries, instruments both
subsystems, and builds a StateLens variant of every marshal fuzz target. It follows chapter
7 with the differences of section 8.3, and the other chapters apply to it unchanged.

### 8.1 What was verified

At commit `2649e4a668`, in a checkout instrumented by a `simplex` campaign (18
invariants, 49 assertion sites, 146 probe sites), on 16 cores:

- Each of the 12 files in `consensus/fuzz/marshal/fuzz_targets/` has exactly one line
  for each anchor of edit M1 (section 8.3). The anchor of edit M3 occurs exactly once in
  `consensus/fuzz/marshal/src/marshal/end_to_end/scenario.rs`, with `schemes` and `Role`
  in scope.
- All four `impl Simplex` blocks in `consensus/fuzz/core/src/simplex.rs` use the
  `cert_mock` scheme. No other Simplex type is named under `consensus/fuzz/marshal/`.
- The marshal part of the test gate passed in 70.6 s: the 421 tests matching
  `test(/^marshal::/)`, including the `slow` group. Eight `slow` finalize tests of 24 to
  66 s make up its tail. No StateLens assertion fired.
- The stock target `marshal_e2e_standard_app_cert_mock_twins`, whose harness reaches the
  patched Twins runner, ran for 120 s. It executed 1,862 inputs (15 per second) with a
  peak RSS of 628 MB. There was no crash, no StateLens violation and no participant index
  mismatch, and the case report after 1,024 cases showed none skipped. This is a smoke
  test, not evidence that the simplex invariants hold in marshal targets:
  - the stock target does not call `statelens::reset()`, so state feedback was off;
  - inputs stayed at 4 bytes or less.
- With `STATELENS_BYZANTINE=panic`, the same target panicked on its first input with
  `[statelens][BYZANTINE] replica=2`. So the existing Twins runner hook (section 7.2,
  edit 6) already guards the compromised identity of marshal Twins targets at the
  Simplex sites.

Not verified: the script changes, the generated variants, the wedge hook, marshal
instrumentation, and AC-9 to AC-13. The knowledge base and beacons (section 5.6
and 6.4) have not been exercised with a real agent, so AC-14 to AC-17 are unverified too.

### 8.2 Decisions

| ID | Decision | PRD requirement |
|---|---|---|
| D24 | StateLens variants are generated from the existing marshal targets, with two anchored insertions each, rather than kept as templates. The variant set therefore always equals the target set. | R-M-P2-1 step 1 |
| D25 | The `marshal` profile does not create `simplex_statelens` (section 7.2, edits 4 and 5), and does not check `SL/runtime/target.rs`. | R-M-P2-1 step 1 |
| D26 | The wedge scenario gets its own guard hook (Appendix F). The Twins targets use edit 6, and the other targets need no hook. | G5 |
| D27 | The core actor derives `me` when it is created and copies it into its mailbox. The standard adapters read it there, and coding reads its scheme provider. `None` never stands for an unknown identity. | R-M-INS-1 |
| D28 | The marshal beacon components are `marshal.core`, `marshal.standard` and `marshal.coding`. The backfill resolver, application gates, ancestry and store modules have no identity of their own, so they are instrumented at their call sites in these components. | R-FB-4, R-M-FB-1 |
| D29 | The test gate of the `marshal` profile adds `test(/^marshal::/)` to the filter of section 7.7. | R-M-P2-1 step 6 |
| D30 | The campaign builds every StateLens variant and runs none of them (D23). The operator chooses which variants to fuzz. | R-M-P2-1 step 7, R-M-P3-1 |

### 8.3 The `marshal` campaign

A `marshal` campaign follows section 7, with these differences.

Step 1, materialize. First the cryptography check of section 8.4. Then edits 1 to 3 and
6 to 8 of section 7.2, and:

| # | File | Edit |
|---|---|---|
| M1 | `consensus/fuzz/marshal/fuzz_targets/<target>_statelens.rs`, for every `<target>.rs` in that directory | Create it as a copy of `<target>.rs` with two insertions. After the only line that matches `^    fuzz_target!\(\|input: [A-Za-z0-9_]+\| \{$`, insert `        commonware_consensus::simplex::statelens::reset();`. Before the only line equal to `    });`, insert `        commonware_consensus::simplex::statelens::clear_compromised();`. |
| M2 | `consensus/fuzz/marshal/Cargo.toml` | For every variant, append a `[[bin]]` block with `name = "<target>_statelens"` and `path = "fuzz_targets/<target>_statelens.rs"`, followed by whichever of the `test`, `doc`, `bench` and `required-features` keys the original target's block has. |
| M3 | `consensus/fuzz/marshal/src/marshal/end_to_end/scenario.rs` | After the line `        let router = Router::new([participants[Role::Byzantine.index()].clone()]);` (eight leading spaces), insert the hook of Appendix F. |

As in section 7.2, a missing or repeated anchor aborts the campaign with exit code 2
before any edit is made. `git add --intent-to-add` also covers the variants.

Step 2, bind invariants (section 7.3): the batches of the simplex registry come first,
with the Simplex subsystem rules, then those of the marshal registry, with the marshal
subsystem rules.

Step 3, beacon probes (section 7.4): one run for each of the six components of the profile
(section 5.5).

Step 4, plan and scope check (section 7.5): both editable roots of the profile are
allowed.

Step 5, build (section 7.6): `FUZZBUILD` is
`cargo +<fuzz toolchain> fuzz build --fuzz-dir consensus/fuzz/marshal <variant>`, run for
each variant in turn. The first failure is the one the repair step sees.

Step 6, test gate (section 7.7):

~~~
cargo +<test toolchain> nextest run -p commonware-consensus --lib --no-fail-fast \
  --ignore-default-filter \
  -E '(test(/^simplex::tests::/) & not test(/::test_twins/)) | test(/^simplex::statelens::/) | test(/^marshal::/)'
~~~

At the reference commit, the marshal part is 421 tests and took 70.6 s on 16 cores. A
marshal test that runs two live marshal actors under one identity would share ghost state
and must be excluded, as the Twins tests are. None is known at the reference commit.

Step 7, hand-over (section 7.8): the summary gives a `run` and a `replay` line for every
variant, in the order of `consensus/fuzz/marshal/fuzz_targets/`:

~~~
statelens: profile    marshal
statelens: run        cd <repo>/consensus/fuzz && NIGHTLY_VERSION=<fuzz toolchain> just run <variant> -- -rss_limit_mb=4000 -print_final_stats=1
statelens: replay     cd <repo>/consensus/fuzz && NIGHTLY_VERSION=<fuzz toolchain> just run <variant> marshal/artifacts/<variant>/<crash file>
~~~

Phase 3 (sections 7.10 to 7.12) applies to the variants. PRD section 9.4 says which variants have an
adversary that runs Simplex or marshal code.

### 8.4 Cryptography check

The `marshal` profile checks D15 as follows. Before edit M1, the script checks every `<target>.rs` in
`consensus/fuzz/marshal/fuzz_targets/`:
1. Every `::<P>` type argument in the file names a `P` that passes the D15 check: the
   `impl Simplex for P {` block in `consensus/fuzz/core/src/simplex.rs` contains
   `type Scheme = cert_mock::Scheme<`.
2. No type whose `impl Simplex` in `consensus/fuzz/core/src/simplex.rs` lacks the
   `cert_mock` scheme is named in the file, or in any `*.rs` file under
   `consensus/fuzz/marshal/src/`.

A failure aborts the campaign with exit code 2 and names the target and the type. At the
reference commit, all four `impl Simplex` blocks use `cert_mock`. Eight targets name
`SimplexCertificateMock` or `SimplexCertificateMockByzantineFirstLeader` explicitly. The
other four call entry points that fix the type themselves, through
`fuzz_marshal_twins_with::<SimplexCertificateMock, ...>` or
`SimplexCertificateMock::setup`.

### 8.5 Instrumentation conventions

These rules add to section 10 for marshal code, and the marshal subsystem rules (section
13.14) give them to the agent.

| Topic | Rule |
|---|---|
| Editable code | An invariant: the root of its subsystem (section 5.5). A beacon run: the component directory, and the marshal code it calls outside `mocks/`. |
| Runtime | Marshal code calls `crate::simplex::statelens::...`, as simplex code does. |
| Replica index | Core actor: derived once when the actor is created, from the scheme its provider returns for the epoch it starts in. It is kept in a `// [statelens] me` field and copied into a `// [statelens] me` field of `core::Mailbox` when the actor creates the mailbox. Standard adapters: read from the mailbox they hold. Coding adapter and shards engine: from their scheme provider at the epoch of the round in hand. |
| Modules without identity | The backfill resolver, the application gates and validation, ancestry and store are instrumented at their call sites in the components, never inside. |
| Unknown identity | Never pass `None` for an index that could not be obtained. Leave the site without instrumentation, and say why in the plan. |
| Discretization | Heights relative to the processed floor, the last delivered height or the finalized tip. Never raw heights, digests, commitments or shard indices. |

The rule for the core actor assumes that a replica's provider returns its own signing
scheme at every epoch. This holds for every harness at the reference commit. The Twins
stacks, the scenarios, the store target and the marshal test harness give each validator
a `ConstantProvider` over its own scheme. Some marshal tests use other providers:
`VerifierProvider`, `RetiringProvider`, `MultiEpochProvider` and `ChurningProvider`.
When the scheme a provider returns has no signer, `me` is `None`: that replica is not a
participant, and it is checked without ghost state.

### 8.6 Acceptance procedures

| AC | Procedure | Pass condition |
|---|---|---|
| AC-9 | With at least one marshal invariant: `just campaign --profile marshal`, then each printed `run` command. | Materialize (12 variants), instrument, plan, build and the test gate complete, the result is `READY` with one `run` line per variant, and each `run` command starts its variant. |
| AC-10 | `STATELENS_FALSE_INVARIANTS=1 just campaign --profile marshal`. | Result `PANIC (tests)`. `SL/campaign/logs/test.log` contains both `[statelens][FALSE-0001]` and `[statelens][FALSE-0002]`. |
| AC-11 | In an instrumented checkout, for each variant: `STATELENS_BYZANTINE=panic just run <variant> -- -max_total_time=120`, then the same without the variable. | With the variable, the four Twins variants and the wedge-scenario variant panic with `[statelens][BYZANTINE]`, and no other variant does. Without it, none does. `[statelens] participant index mismatch` never appears. Verified for the Simplex sites of the stock standard Twins target (section 8.1). |
| AC-12 | `just run <variant> <artifact>` in the checkout of a crashing Phase 3 run, with that run's `STATELENS_BYZANTINE` value. | The same `[statelens][...]` line as in that run. |
| AC-13 | Two 10-minute runs of `marshal_e2e_standard_app_cert_mock_twins_statelens` on empty corpora, one with `STATELENS_FEEDBACK=0` and one without. | `ft:` on the `DONE` line is higher with feedback. |
| R-NF-3 | With the same duration and flags: each variant in an instrumented checkout, and its original target in an uninstrumented checkout at the same commit. | The exec/s values are reported side by side. A slowdown above 2x is recorded as an instrumentation problem. |

### 8.7 Known limitations

- Throughput was measured for one stock target only: 15 exec/s for the standard Twins
  target. The other target families are unmeasured.
- A fuzz process of a Twins variant needs about 0.6 GB (measured for one target). The
  other variants are unmeasured, so the operator sizes the runs.
- The Byzantine role of the wedge scenario is guarded, so its state feeds neither the
  assertions nor the counters.
- The store variant has no peers and reaches only the core actor's store paths.
- The scenario-prefix targets seed notarizations into voter journals, and inject backfill
  deliveries. No Simplex test creates these states, and history kept in ghost state may
  not account for them.
- When marshal moves under `consensus/src/simplex/` (draft PR #4994), several paths
  change: the marshal root, the component directories, and the test filter (which
  becomes `simplex::marshal::`). The `simplex` profile's editable root must then exclude
  `consensus/src/simplex/marshal/`.
- Issue #4701 removes marshal's backward ancestry API. Bindings are made again in every
  campaign, but Observation hints that name that API will go stale.

---

## 9. Runtime support: `statelens.rs`

The full source is in Appendix A. This section specifies its behavior.

### 9.1 Byzantine guard

| Item | Behavior |
|---|---|
| `set_compromised(indices)` | Replaces the compromised set with `indices` (participant indices). Called by the runner hook. |
| `clear_compromised()` | Empties the set. |
| `is_byzantine(me)` | `true` if `me` is `Some(p)` and `p` is in the set. `None` is never compromised. |
| `should_check(me)` | `true` for honest replicas. For compromised replicas it follows `STATELENS_BYZANTINE`: `false` for `skip` (default), `true` for `check`, and a panic with `[statelens][BYZANTINE]` for `panic`. Any other value panics with the list of allowed values. |

The set is thread-local. This is sound because the deterministic runtime runs every task
on the thread that calls `Runner::start`, and because nextest runs each test in its own
process.

### 9.2 Macros

All three evaluate `me` first and do nothing else when `should_check(me)` is `false`.

| Macro | Behavior |
|---|---|
| `sl_probe!(me, "label", a, b)` | Records `(site, a, b)`. `a` and `b` convert with `Into<u32>`, so `bool`, `u8`, `u16` and `u32` are accepted and `u64` values fail to compile. The site hash covers the label, file, line and column of the call. |
| `sl_assert!(me, "ID", cond, fmt...)` | Panics through `violation` when `cond` is false. |
| `sl_implies!(me, "ID", pre, post, fmt...)` | Records `(site, pre, post)`. Evaluates `post` only when `pre` holds. Panics when `pre && !post`. |

The panic message is `[statelens][<ID>] replica=<index|none> <message>`. The reported
location is the macro call site (`#[track_caller]`).

### 9.3 Counter table

- `sancov::Counters<65536>` in a static.
- `record` sets `cell(site, a, b)` to 1 with an atomic store (presence, D3).
- `reset()` zeroes the table, clears the compromised set and all ghost state. In a
  `cfg(fuzzing)` build it registers the table with libFuzzer once, unless
  `STATELENS_FEEDBACK=0`.
- Once the table is registered, libFuzzer stops printing `cov:` because the table has no
  PC table. Compare runs by `ft:`.

### 9.4 Ghost state

- `Ghost`: one per replica, keyed by participant index. All actors and components of a
  replica share it, in both subsystems.
- `Global`: one per run, shared by all honest replicas.
- Lifetime: one run. `reset()` clears ghost state before every fuzz input, and the
  fresh-run hook (Appendix B.4) clears it whenever a fresh deterministic runtime is
  created, for example for each seed of a multi-seed test. A runtime resumed from a
  checkpoint (a crash-restart) keeps it. The hook is registered on the first ghost-state
  access.
- `with_ghost(me, f)` and `with_global(me, f)` return `None` without calling `f` for a
  guarded replica; `with_ghost` also does so when `me` is `None`. The closures MUST NOT
  nest.
- Instrumentation adds `pub` fields with `Default` types to `Ghost` and `Global`, each
  marked `// [statelens] ghost:INV-NNNN`, or `// [statelens] ghost:beacon:<label>` when a
  beacon probe is what needs the history.
- Ghost fields added to existing structs (PRD R-INS-5) belong to one replica and are
  updated without the guard. Only the guarded macros act on them, and
  `STATELENS_BYZANTINE` does not apply to their updates.

### 9.5 Discretization helpers and switches

| Helper | Result |
|---|---|
| `bucket(n)` | 0, 1, 2, 3-4, 5-8, 9+ map to 0..=5 |
| `delta(a, b)` | `bucket(a - b)` when `a >= b`, else `5 + bucket(b - a)` (6..=10) |
| `flag(b)` | 0 or 1 |
| `pack(high, low)` | `(high << 16) \| (low & 0xffff)` |
| `disc(&value)` | Stable code of an enum variant, payload ignored |

| Switch | Default | Effect |
|---|---|---|
| `STATELENS_BYZANTINE` | `skip` | What instrumentation does for a compromised replica: `skip` ignores it (the guard), `check` checks it like an honest replica, `panic` panics at the first instrumented site it reaches (AC-7). |
| `STATELENS_FEEDBACK` | on | `0` leaves the table unregistered. |

---

## 10. Instrumentation conventions

The prompts in section 13.7 are normative for the agent. In summary:

| Topic | Rule |
|---|---|
| Editable code | A beacon run: its component directory and the code it calls (section 8.5). Otherwise the non-test code of the profile's subsystems (section 5.5): `consensus/src/simplex/`, except `mocks/` and `scheme/`, and for the `marshal` profile `consensus/src/marshal/`, except `mocks/`. Each invariant only in the code of its own subsystem. New-field initializers may be added to struct literals anywhere, including tests. In `statelens.rs`, only `Ghost` and `Global` fields and private helpers. |
| Additions only | No deleted or changed logic. The only allowed edit of an existing line is wrapping an expression in a block, keeping its tokens; each such edit is listed in the plan. |
| Markers | `// [statelens] <tag>` above every added statement, block, field or item. Tags: `INV-NNNN`, `ghost:INV-NNNN`, `beacon:<label>`, `ghost:beacon:<label>`, `me`. |
| Replica index | Simplex: `self.scheme.me()`; otherwise a `// [statelens] me` field of type `Option<Participant>`. Marshal: section 8.5. Never `None` for an index that could not be obtained. |
| Non-interference | Observe program state without changing the semantics or control logic of the protocol or its implementation. Write only StateLens state: ghost state, probe counters, added `me` fields. No writes to existing variables, fields or collections (directly, through `&mut` methods or interior mutability); no methods whose reads change state that any code, tests included, can observe; no added `return`, `break`, `continue` or `?` that leaves or skips original code; no channel endpoints, `Arc`s (such as blocks) or values with a `Drop` effect kept in ghost state; no block clones; no `await`, spawn, lock, runtime context, RNG, clock, network, storage, metrics or logging; no reordering or consuming of values. Exception: forcing a memoized decode (`Lazy::get`, `==` on a `Lazy`), even on original values, and keeping clones of decoded messages that hold `Bytes`, such as votes. |
| Panics | Only through violations: saturating or checked arithmetic, no `unwrap` or `expect`, no out-of-bounds indexing. |
| Cost | O(1) per site, or bounded by the number of tracked views. |
| Warnings | Denied workspace-wide. Use full paths rather than new imports. |
| Discretization | No raw views, heights, digests, commitments, keys, payloads or timestamps. Views and heights relative to another known view or height. At most about 64 `(a, b)` pairs per probe. No replica index in probe values. |
| Adversarial input | Assert what the honest replica does or keeps, not what peers send. |
| Asynchrony | Checks across actors or components hold for every delivery delay the implementation allows. |

---

## 11. Instrumentation plan format

Agents add sections under `## Invariants`:

~~~markdown
### INV-0007: <title>
- Status: bound | partial | unbound
- Reading: <pre and post, or the checked condition, in code terms>
- Assertions: <file, function, macro and condition; one line each>
- Probes: <extra probes such as margins, or "none">
- Ghost state: <fields and where they are updated, or "none">
- Edited lines: <existing lines wrapped in blocks, or "none">
- Notes: <why partial or unbound; limitations>
~~~

and rows to the beacon table:

~~~markdown
| voter.certify.transition | actors/voter/round.rs Round::<fn> | disc(old) | disc(new) | CertifyState enum; comment at <line> |
~~~

The `Beacon` column says what the probe watches and where the agent found it: the code
construct, or the finding identifier when the knowledge base is what pointed at it.

The script adds the `## Summary` section (section 7.5).

---

## 12. Agent invocation

The prompt always goes to standard input.

Both phases run with the repository root as the working directory.

| Agent | Phase 1 | Phase 2 |
|---|---|---|
| `claude` | `claude -p --output-format text [--model M] --permission-mode acceptEdits --allowedTools Read Grep Glob Write Edit WebFetch "Bash(gh:*)" "Bash(curl:*)"` | `claude -p --output-format text [--model M] --dangerously-skip-permissions` |
| `codex` | `codex exec -C <repo root> [-m M] -s workspace-write -c sandbox_workspace_write.network_access=true -` | `codex exec -C <repo root> [-m M] --dangerously-bypass-approvals-and-sandbox -` |

Notes:

- Both CLIs read `AGENTS.md` or `CLAUDE.md` from the working directory. The Phase 2
  prompt states that its rules take precedence during a campaign.
- Phase 2 agents have unrestricted access to the host (D4). The README MUST say that
  campaigns run on a dedicated machine or container. Being unrestricted is also what lets
  the instrumenter run the `kb` commands of section 5.6; its prompt says when to.
- The script checks that the chosen CLI is on `PATH` before any other work.

---

## 13. Prompts (verbatim)

### 13.1 `prompts/analyst.md`

~~~markdown
# StateLens invariant analyst: extract invariants

You are a senior security engineer who specializes in Byzantine fault tolerant
consensus. Read the sources listed at the end and write invariants for the
`{{REGISTRY}}` registry of StateLens in this repository.

## Context

{{CONTEXT}}
- Every file in `consensus/fuzz/statelens/invariants/{{REGISTRY}}/` is used by the next
  fuzzing campaign that binds this registry. An agent turns each invariant into assertions inside honest replicas, and a
  fuzzer runs honest replicas next to Byzantine ones (equivocating, mutating messages,
  splitting the network) until an assertion fails. A wrong invariant costs a human
  investigation. A vague one cannot be checked.

## What makes a good invariant

- It holds in every execution for an honest replica, or, with scope `protocol`, for all
  honest replicas together. That includes executions with Byzantine replicas up to the
  fault threshold, arbitrary message delay, reordering and loss, timeouts, and crashes
  followed by recovery from persistent state.
- It constrains what an honest replica does or keeps: the honest actions in Context. It
  never requires a Byzantine replica to behave.
- It uses the protocol terms in Context. It never names Rust types, functions, fields or
  files; those go in "Observation hints".
- It is precise enough to decide, at a specific moment of an execution, whether it has
  been violated. Progress properties are welcome when they name that moment, like the example
  in Context. Do not write open-ended "eventually" properties.
- When a property holds only under extra conditions (for example, the replica must first
  have data it may still be waiting for), put those conditions into the Statement's
  trigger or state, or into "Preconditions / assumptions", instead of dropping the
  property. Whether and how to check it is decided later, when it is bound to the code.
- It is narrow: one property per invariant.
- It is justified by the source. Do not invent properties the source does not support.
  Writing zero invariants is a valid result.

## Statement format (EARS)

Write the Statement as one sentence in one of these patterns. The system is "the
replica" (an honest replica); for scope `protocol` it is "the protocol".

- Ubiquitous: `The replica shall <response>.`
- State-driven: `While <state>, the replica shall <response>.`
- Event-driven: `When <trigger>, the replica shall <response>.`
- Unwanted behavior: `If <condition>, then the replica shall <response>.`
- Complex: `While <state>, when <trigger>, the replica shall <response>.`

Use `shall not` for prohibitions. If no pattern fits, write one precise sentence and
explain why in the Rationale.

## Output

- Write one file per invariant: `consensus/fuzz/statelens/invariants/{{REGISTRY}}/<ID>.md`.
- Use IDs starting at `{{NEXT_ID}}` and increasing by one with no gaps.
- Follow the template below exactly: the same front matter keys and section headings,
  in the same order. Delete optional sections you do not use.
- Set `source_kind: {{KIND}}`. Make `source_ref` as precise as you can: URL,
  `path:line`, document section, or paper page.
- Plain ASCII only. Wrap lines at 100 characters.
- Do not modify or delete existing files, create other files, or write code.

When you finish, reply with a list of the files you wrote (ID, title, one line of
evidence), or with the reason you wrote none.

## Template

```markdown
{{TEMPLATE}}
```

## Example

The example shows the format; it comes from the simplex registry.

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

## Sources

Kind: `{{KIND}}`

{{SOURCES}}
~~~

### 13.2 `prompts/analyst-issue.md`

~~~markdown
## How to read an issue or pull request

- Read every listed issue or pull request completely: description, comments, linked
  issues, and the diff of the fixing pull request or commit. Use `gh issue view <ref>
  --comments`, `gh pr view <ref> --comments` and `gh pr diff <ref>` when `gh` is
  available; otherwise use the GitHub REST API with `curl` (for example
  `https://api.github.com/repos/<owner>/<repo>/issues/<n>` and `.../comments`) or your
  web fetch tool.
- Reconstruct the bug: the situation that triggered it, what the implementation did,
  and why that was wrong for the protocol.
- Write the invariants the bug violated. Generalize beyond the specific fix so that the
  invariant also catches variants of the bug on other code paths, while staying true
  for every correct execution.
- Cover both sides of the bug where they apply: what the replica must never do (the
  wrong action, or the state that made it crash), and what it must do instead at that
  moment. For example, a crash on a malformed message has two sides: the replica shall
  not panic on it, and the replica shall reject it and keep processing other messages.
- Also write the expected outcome: what the replica should have produced in the reported
  situation, given the inputs it had (a vote, a certificate, a state change), as an
  event-driven statement.
- For a liveness bug, also write the safety condition whose violation caused it, when
  one exists (for example "the replica shall not discard a certificate for a view above
  its finalized tip"). Do not write open-ended "eventually" properties.
- In Evidence, describe the violating scenario in two to five sentences and cite the
  issue, the pull request and the fixing commit.
- Write nothing for issues that are not about the behavior in scope for this registry
  (see Context), or that are about documentation, CI, builds, performance tuning or
  other crates.
~~~

### 13.3 `prompts/analyst-design.md`

~~~markdown
## How to read a design document

- Read the listed documents: local paths, or URLs through your web fetch tool or
  `curl`. A `#section` suffix names the part to focus on; read the rest for context.
- Extract every rule the document states or implies an honest replica follows, of the
  kinds listed in Context.
- Also extract the properties the design relies on in its safety argument.
- In source_ref give the document and the section heading. In Evidence quote or
  closely paraphrase the relevant sentence.
~~~

### 13.4 `prompts/analyst-comment.md`

~~~markdown
## How to read code comments

- The sources are files or directories under `{{SOURCE_ROOT}}`, optionally with
  `:line` or `:start-end`. Read the doc comments, the inline comments, and the
  conditions of `assert!`, `debug_assert!`, `unreachable!`, `expect("...")` and
  `panic!` in non-test code. Ignore test modules and `mocks/`.
- Look for conditions the author relies on: "must", "never", "always", "only", "cannot
  happen because", "invariant", "at most", "before", "after". Each one is a candidate.
- Restate each candidate in protocol terms. Keep Rust identifiers out of the Statement
  and put the code location and identifiers in "Observation hints".
- source_ref is `path:line` of the comment or assertion.
- Skip comments that describe mechanics without stating a condition.
~~~

### 13.5 `prompts/analyst-spec.md`

~~~markdown
## How to read a formal specification

- The sources are Quint, TLA+ or Lean files, optionally with `:line`. Read the named
  invariants and temporal properties, the assertions, and the guards and effects of
  the actions that model an honest replica.
- Translate each invariant, and each action guard that encodes a safety rule (for
  example "vote to finalize only if the view was not nullified"), into an EARS
  statement about an honest replica or the protocol. Keep the exact meaning.
- Record modeling assumptions the implementation may not share (a fixed number of
  replicas, bounded views, a static leader, no crashes) under "Preconditions /
  assumptions".
- source_ref is `path:line` of the property or action.
~~~

### 13.6 `prompts/analyst-paper.md`

~~~markdown
## How to read a paper

- The sources are papers or articles: a PDF or text file, or a URL, optionally with a
  page. When a text extraction is listed next to a PDF, read the extraction and use the
  PDF only for figures.
- Read the protocol description, the lemmas and theorems, and their proofs. Properties
  that the proofs rely on are the best candidates.
- This implementation is a modification of Simplex. When you are not sure that a
  property from the paper applies to the implementation, still write it and describe
  the doubt in the Rationale; a human will decide.
- source_ref is the paper title with page and section.
~~~

### 13.7 `prompts/instrument.md`

~~~markdown
# StateLens instrumenter

You are instrumenting consensus code in this repository for a StateLens fuzzing
campaign. Your changes turn English invariants into runtime assertions, and add state
probes that tell the fuzzer when an execution reached a new internal state.

## Where you are

- This checkout is a throwaway clone at commit `{{BASE}}`, instrumented in place for one
  fuzzing campaign. Nobody will review, merge or reuse your changes. The repository conventions in AGENTS.md and CLAUDE.md about public API
  stability, documentation, benchmarks, dependencies, commits and pull requests do not
  apply here. The rules in this prompt take precedence.
- Do not commit. Do not run the tests or the fuzzer; the campaign runs the tests after you.
  Do run the check command at the end of this prompt until it passes.
- Read `consensus/src/simplex/statelens.rs` first. It is the runtime support module.
- A fuzzer will run honest replicas next to Byzantine ones. Any panic you cause is
  reported to a human as a possible bug, so a false alarm wastes their time and a
  missed check hides a bug.

## Scope

- You may edit the non-test code that the subsystem rules below allow. Non-test code is
  code outside `#[cfg(test)]` items and `tests` modules.
  You may add initializers for new fields to struct literals anywhere, including tests,
  when the compiler requires them.
- In `statelens.rs` you may only add fields to `Ghost` and `Global`, and private helper
  functions.
- Do not edit anything else: no `Cargo.toml`, nothing under `consensus/fuzz/`, no
  other crate.

## Subsystem rules

{{SUBSYSTEM_RULES}}

## Rules

1. Add, never remove. Do not delete or change existing logic. The only allowed change
   to an existing line is wrapping an existing expression in a block so that
   instrumentation can run next to it, keeping the original tokens (for example
   `A => f(),` becomes `A => { <instrumentation>; f() }`). List every such edit in the
   plan under "Edited lines".
2. Mark everything you add with a comment line `// [statelens] <tag>` directly above
   it. Tags: `INV-NNNN` for assertions and invariant probes, `ghost:INV-NNNN` for ghost
   fields and their updates, `beacon:<label>` for beacon probes, `ghost:beacon:<label>` for
   ghost state a beacon probe needs, and `me` for code added only to make the replica index
   available.
3. Observe only honest replicas. The macros, `with_ghost` and `with_global` apply the
   Byzantine guard themselves. Ghost fields you add to existing structs may be updated
   without the guard, but act on them only through the macros. Always pass the
   replica's own index as `me`, obtained as the subsystem rules say. Never hard-code or
   guess an index, and never pass `None` for an index you could not obtain: `None`
   means the replica is not a participant and turns the guard off. Leave such a site
   without instrumentation and say so in the plan.
4. Observe, do not interfere. Instrumentation observes program state without changing
   the semantics or control logic of the protocol or its implementation: until an
   invariant is violated, the replica takes the same branches, keeps the same state and
   sends the same messages as the original code. Write only StateLens state: ghost
   fields, `Ghost` and `Global`, and the `me` fields you add. Do not assign to or mutate
   existing variables, fields or collections, whether directly, through `&mut` methods,
   or through interior mutability (`Cell`, `RefCell`, atomics), and do not call methods
   whose reads change state that any code, tests included, can observe (for example an
   LRU `get` that changes the eviction order). Exception: you may force a memoized
   decode, such as `Lazy::get` or `==` on a `Lazy`, even on original values. No other
   cache is exempt: filling `CodedBlock::shards`, for example, runs an erasure encode,
   can panic, and changes what `shard()` returns. Do not add a `return`, `break`,
   `continue` or `?` that can leave or skip original code. Do not keep in ghost state a
   handle whose count or lifetime any code, tests included, can observe: channel
   endpoints, `Arc`s such as blocks, or values whose `Drop` has an effect. Do not clone
   blocks; keep a block's digest and height instead. Clones of decoded messages that
   hold `Bytes`, such as votes, are fine. Do not `await`, spawn tasks, take locks, or
   use the runtime context, RNG, clock, network, storage, metrics or logging. Do not
   send or reorder messages, and do not move or consume values the original code uses
   later; clone small values if you need them after a move.
5. No accidental panics. Only an invariant violation may panic. Use saturating or
   checked arithmetic (tests run with overflow checks). Do not use `unwrap`, `expect`,
   or indexing that can go out of bounds.
6. Bounded cost: O(1) per site, or bounded by the number of views the replica tracks.
   Do not scan unbounded collections or allocate per message on hot paths unless an
   invariant requires it.
7. The workspace denies all warnings: no unused variables, imports or functions. Prefer
   full paths (`crate::simplex::statelens::bucket(...)`) to new `use` lines.
8. Byzantine peers are adversarial: a message an honest replica receives can contain
   anything. Assert what the honest replica itself does, keeps or accepts, not what
   peers send, unless the invariant is about how the replica handles bad input.
9. Actors and components run concurrently and exchange messages through mailboxes. A
   check that compares components of one replica must hold for every delivery delay the
   implementation allows, not only when they are in step.

## Runtime API (`crate::simplex::statelens`)

- `sl_assert!(me, "INV-NNNN", cond, "fmt", args...)` panics with
  `[statelens][INV-NNNN] replica=<i> <message>` when `cond` is false.
- `sl_implies!(me, "INV-NNNN", pre, post, "fmt", args...)` records the probe
  `(pre, post)` and panics when `pre` holds and `post` does not. `post` is evaluated
  only when `pre` holds.
- `sl_probe!(me, "label", a, b)` records the state `(a, b)` at this call site. `a` and
  `b` must be `bool`, `u8`, `u16` or `u32`.
- Invoke the macros by path, for example
  `crate::simplex::statelens::sl_implies!(self.scheme.me(), "INV-0007", pre, post, "...")`.
- Discretization: `bucket(n: u64) -> u32` (0, 1, 2, 3-4, 5-8, 9+),
  `delta(a: u64, b: u64) -> u32` (signed distance, bucketed), `flag(bool) -> u32`,
  `pack(high: u32, low: u32) -> u32` (two values below 2^16), `disc(&value) -> u32`
  (enum variant code, payload ignored). Views convert with `view.get()`.
- Ghost state: `with_ghost(me, |g: &mut Ghost| ...)` gives one `Ghost` per replica,
  shared by all its actors and components. `with_global(me, |g: &mut Global| ...)`
  gives one `Global` shared by all honest replicas, for `protocol` invariants. Both
  return `None` without running the closure for a skipped replica. Never nest them. Add
  the fields you need to `Ghost` or `Global`, with `Default` types. Ghost state lives
  for one run: it is cleared when a new run starts (every fuzz input, every seed of a
  test) and kept across a crash-restart within the run.
- Assertion messages start with the invariant title and include the values involved,
  for example `"no finalize after nullify: view={} nullified={}"`.

## Discretization rules

- Never feed raw views, heights, digests, keys, signatures, payloads or timestamps to a
  probe. Record views relative to another view the replica knows
  (`delta(view.get(), last_finalized.get())`), and counts through `bucket`.
- Keep each probe's value space small: at most about 64 distinct `(a, b)` pairs.
- Do not include the replica index in probe values.

## The plan

Keep `{{PLAN}}` up to date. Add your sections and rows; do not rewrite other parts.

For each invariant, add under `## Invariants`:

    ### INV-NNNN: <title>
    - Status: bound | partial | unbound
    - Reading: <pre and post, or the checked condition, in code terms>
    - Assertions: <file, function, macro and condition; one line each>
    - Probes: <extra probes such as margins, or "none">
    - Ghost state: <fields and where they are updated, or "none">
    - Edited lines: <existing lines wrapped in blocks, or "none">
    - Notes: <why partial or unbound; limitations>

For each beacon probe, add a row to the table under `## Beacon probes`:

    | <label> | <file> <function> | <a> | <b> | <beacon and where it was found> |

## Check command

Run this until it succeeds with no errors and no warnings:

    {{CHECK}}

Then reply with a short summary of what you added.
~~~

### 13.8 `prompts/instrument-invariants.md`

~~~markdown
## Task: bind invariants {{INVARIANT_IDS}} of the {{REGISTRY}} registry

Bind each invariant only in the code that the subsystem rules allow. For each invariant
below:

1. Read the Statement (EARS). Identify the trigger or state (`pre`) and the required
   response (`post`), or the single condition of a ubiquitous statement. Treat
   "Preconditions / assumptions" as part of `pre`. Treat "Observation hints" as leads,
   not as facts.
2. Find where the implementation establishes and uses the concepts. Trace with search,
   references and call hierarchy across the components the subsystem rules name,
   including the mailbox messages between them and the recovery path on restart.
3. Choose assertion sites where a violation first becomes observable: just before the
   replica acts (signs, broadcasts, persists, accepts a certificate, enters a view) or
   just after it changes the relevant state. Cover every code path that performs the
   action.
4. Map the EARS pattern to a macro. Ubiquitous: `sl_assert!`. State-driven,
   event-driven, unwanted behavior and complex: `sl_implies!(pre, post)`. For
   properties about history ("after", "once", "never again"), record the history in
   ghost state (`with_ghost` for one replica, `with_global` for scope `protocol`, or a
   `// [statelens] ghost:` field when the history belongs to one object) and assert at
   the later action.
5. For a numeric invariant, also add a margin probe:
   `sl_probe!(me, "INV-NNNN/margin", crate::simplex::statelens::bucket(distance), 0u8)`,
   where `distance` is how far the state is from a violation.
6. Be faithful: the code must check exactly the Statement. Never check something
   stronger, because that creates false alarms. If you can check only part of it, bind
   that part and set Status to `partial` with the reason. If you cannot bind it, add
   nothing for it and set Status to `unbound` with the reason.
7. Add the invariant's section to the plan.

Two worked examples of this reasoning live in `consensus/fuzz/statelens/examples/`:
`statelens_commonware_voter_example.md` on the Simplex voter, and
`statelens_commonware_marshal_example.md` on marshal's deferred verification path. Read the one
whose subsystem you are binding in.

Sections 9 to 25 of the voter example take a comment such as "nullification does not cancel
pending certification work" and turn it into a relation over named state, which is what steps 1
and 2 above ask of you; section 24 ranks the results by how much they actually say, and section
25 lists readings that look right and are too strong. That last one is rule 6: a Statement
bound more strictly than it is written produces false alarms that cost someone a day. The
marshal example does the same across a state machine that spans several functions, a restart and
a crash-recovery path, which is the harder case for step 2.

Read them for how the reasoning goes, not for what to add. They *derive* invariants, which is
Phase 1 work; your job is to bind the ones below, and their local labels (`INV-A1`, `M1` and so
on) are not registry ids. Section 0 of each gives the rest of the mapping.

Invariants:

{{INVARIANTS}}
~~~

### 13.9 `prompts/instrument-beacons.md`

~~~markdown
## Task: beacon probes for the {{ACTOR}} component (`{{ACTOR_DIR}}`)

Add state probes that let the fuzzer tell apart executions that run the same code in
different internal states. Do not add assertions in this task.

This is a loop, not a checklist. At each step you choose one action, look at what it
returned, and choose again. Your actions are: read and search the code of this component;
query the knowledge base with one of the commands below; add a probe.

Reading the code leads, because that is where a candidate announces itself. Query the
knowledge base when your hypothesis needs developer context the source does not carry.
Source shows you that an assumption exists. It rarely tells you what the assumption means,
why it matters, whether it has failed before, or which code manages the transition. The
moment you find yourself asking one of those, query. For example, reading

    let task = self.gates.take(round, digest);

tells you that certification consumes a gate, but not why a gate might be absent, nor what
happens to certification when it is: that is a query, not a guess.

### The knowledge base

{{QUERY}}

The knowledge base holds findings reported against this workspace, each with a summary, the
state it concerns, and the files and symbols it cites. `kb cites {{ACTOR_DIR}}` is the
fastest way to see which of them are about the code in front of you, and what they name.
When nothing is listed above, there is no knowledge base configured: work from the code
alone.

A finding tells you which states have gone wrong before, so a state it describes is worth
probing even when the code looks unremarkable. It never tells you to add an assertion: a
finding is evidence, not a property, and this task adds probes only.

### Beacons in the code

1. Inventory the semantic beacons in the non-test code of `{{ACTOR_DIR}}` and the types
   it owns: enums that describe states, modes, reasons or outcomes; boolean and
   `Option` fields of per-view or per-round state; the conditions of `debug_assert!`,
   `assert!`, `expect("...")` and `unreachable!`; comments about orderings, races,
   recovery, or cases that "cannot happen".
2. For each beacon, find the transition sites (where the state is set or changed) and
   the decision sites (where it is read to choose what to do).
3. Choose probes in this order of priority:
   - transitions caused by side effects or asynchrony, such as those the subsystem rules
     list;
   - conditions set in one actor or component and used in another through mailbox
     messages;
   - state combinations that comments or assertions call out as fragile.
4. Probe shape: `sl_probe!(me, "{{ACTOR}}.<beacon>.<event>", a, b)`, with `(a, b)` the
   state before and after a transition, or the state and its context at a decision
   point. Use `disc` for enums, `flag` for booleans and options, `delta` and `bucket`
   for views and counts, and `pack` to put two small values on one side.
5. Budget: 20 to 60 probes for this component. Avoid per-message hot loops unless the state
   there is interesting.
6. Add one row per probe to the "Beacon probes" table of the plan.

### A worked example

Two documents in `consensus/fuzz/statelens/examples/` work this task through end to end:
`statelens_commonware_voter_example.md` on the Simplex voter, and
`statelens_commonware_marshal_example.md` on marshal's deferred verification path. Read the one
whose subsystem matches this component. The parts that match what you are doing:

- section 0, how the example's vocabulary maps onto this workflow;
- sections 3 to 8, reading a comment, noticing what the source cannot answer, and querying the
  knowledge base at exactly that point rather than up front;
- section 26 of the voter example, or 32 of the marshal one, turning a finding into a coverage
  dimension and choosing which cells of it are worth telling apart;
- section 27, or 33 of the marshal one, the probe shapes: how several booleans become one packed
  side of the pair, how to observe two rules that live at different call sites, and when to
  split a wide dimension into several probes that a round relates;
- section 28 of the voter example, why reading a short-circuited condition eagerly changes what
  the program does;
- section 35 of the marshal example, a trace of observe, hypothesise, act, which is the shape
  your own reasoning should take.

Two things in them are not your job. They derive invariants, which belongs to Phase 1: you add
probes only. And they name artifacts from the StateLens paper, a Beacon Summary and a State
Report, which do not exist here -- your output is the probes and the plan rows. Section 0 of
each gives the rest of the mapping.
~~~

### 13.10 `prompts/repair.md`

~~~markdown
## Task: repair the instrumentation (attempt {{ATTEMPT}} of 3)

The instrumented tree does not build. Fix the instrumentation only: code marked
`// [statelens]`, and `consensus/src/simplex/statelens.rs`. Do not change existing code.
Do not weaken an assertion to make it compile: if an assertion cannot be written
faithfully, remove it and set its invariant to `unbound` in the plan with the reason.
Run the failing command and the check command until both pass.

Failing command:

    {{COMMAND}}

Last lines of its output:

{{ERRORS}}
~~~

### 13.11 `prompts/subsystems/simplex-analyst.md`

~~~markdown
- `consensus/src/simplex` implements a modified Simplex consensus protocol. Leaders
  propose blocks for views. Replicas vote to notarize a proposal, to nullify a view
  (skip it), or to finalize a notarized proposal, and a quorum of votes of one kind
  forms a certificate (notarization, nullification, finalization). Each replica runs
  three actors: the voter (the view state machine), the batcher (vote collection and
  verification) and the resolver (fetching missing certificates). Replicas persist
  their votes in a journal and recover from it after a crash. The module docs in
  `consensus/src/simplex/mod.rs` describe the protocol; read them when a source leaves
  a concept unclear.
- Honest actions: votes it signs, messages it sends, certificates it accepts, state it
  persists, views it enters.
- Protocol terms: views, leaders, proposals, parents, votes, certificates, timeouts, the
  finalized tip, the journal.
- Example of a progress property that names its moment: "When the replica times out in a
  view without having signed a finalize vote for it, the replica shall sign a nullify
  vote for that view".
- Kinds of rules in design documents: voting rules, conditions for entering a view,
  timeout and nullification rules, certificate validity and use, parent and ancestry
  rules, persistence and recovery guarantees, and bounds on tracked state.
- Scope values: `protocol`, `replica`, `voter`, `batcher`, `resolver`, `cross-actor`.
- In scope: Simplex behavior.
~~~

### 13.12 `prompts/subsystems/marshal-analyst.md`

~~~markdown
- `consensus/src/marshal` turns the certificates of the Simplex consensus protocol
  (`consensus/src/simplex`), and the blocks disseminated for its proposals, into an
  ordered stream of finalized blocks for the application. Each replica runs a marshal
  actor. It caches blocks and certificates, persists finalized blocks and their
  finalizations, and keeps a processed floor; it may start from a finalized floor instead
  of genesis. It delivers finalized blocks to the application in height order and at
  least once, waits for the application to acknowledge them, prunes what it no longer
  needs, and fetches missing blocks and certificates from peers (backfill). Between
  Simplex and marshal, a consensus adapter proposes, verifies and certifies blocks:
  `Inline` or `Deferred` in standard mode, or `Marshaled` in coding mode. In coding
  mode, blocks are erasure coded into shards, which the shards engine disseminates,
  checks and reconstructs. The module docs in `consensus/src/marshal/mod.rs` describe
  the design; read them when a source leaves a concept unclear.
- Honest actions: the blocks it delivers to the application and their order, the blocks
  and certificates it persists, prunes or serves to peers, the processed floor it keeps,
  the backfill requests it makes and the responses it accepts, the verification and
  certification results it reports to consensus, and the shards it accepts, forwards or
  uses for reconstruction.
- Protocol terms: finalized blocks, heights, parents, notarizations, finalizations, the
  processed floor, delivery and acknowledgement, backfill, durable storage, pruning,
  epochs, and, in coding mode, commitments, shards and reconstruction.
- Example of a progress property that names its moment: "When the replica learns a
  finalization for a height above every finalized tip it has reported, the replica shall
  report that height to the application as its new finalized tip".
- Kinds of rules in design documents: delivery order and duplication, floor and anchor
  rules, conditions for persisting, pruning and serving blocks and certificates, backfill
  and repair rules, verification and certification rules of the consensus adapters,
  shard validity and reconstruction rules, recovery after a restart, and bounds on
  tracked state.
- Scope values: `protocol`, `replica`, `core`, `resolver` (marshal's backfill resolver),
  `standard`, `coding`, `application`, `cross-component`.
- In scope: marshal behavior, including the consensus adapters and the coding mode.
  Simplex voting, views and the forming of certificates belong to the simplex registry.
~~~

### 13.13 `prompts/subsystems/simplex-instrument.md`

~~~markdown
### Simplex (`consensus/src/simplex/`)

- Editable code: non-test code in `consensus/src/simplex/`, except `mocks/` and
  `scheme/`.
- Components: the voter, batcher and resolver actors in `consensus/src/simplex/actors/`,
  which exchange messages through mailboxes, and the journal replay path on restart.
- Replica index: `self.scheme.me()` wherever a scheme is in scope (the voter, batcher and
  resolver all hold one). Where it is not, add a `// [statelens] me` field of type
  `Option<crate::simplex::statelens::Participant>`, set where the struct is created.
- Asynchrony worth probing: the view advances while work is outstanding, a timeout races
  a certificate, a verification or certification result arrives after the state moved
  on, equivocation is detected after acceptance, state is rebuilt from the journal.
~~~

### 13.14 `prompts/subsystems/marshal-instrument.md`

~~~markdown
### Marshal (`consensus/src/marshal/`)

- Editable code: non-test code in `consensus/src/marshal/`, except `mocks/`. Call the
  runtime from here as `crate::simplex::statelens::...`, as simplex code does.
- Components:
  - the core actor (`core/`): ordering, the processed floor, caches, archives,
    acknowledgements, subscriptions, and repair and backfill handling;
  - the standard consensus adapters (`standard/`): `Inline` and `Deferred`;
  - the coding mode (`coding/`): the `Marshaled` adapter and the shards engine.

  They exchange messages through mailboxes. They use the backfill resolver (`resolver/`),
  the application gates and validation (`application/`), `ancestry.rs` and `store.rs`.
- Replica index: the participant index of the replica's own signing scheme, which marshal
  gets from its scheme provider.
  - Core actor: derive it once when the actor is created, from the scheme its provider
    returns for the epoch it starts in. Keep it in a `// [statelens] me` field of type
    `Option<crate::simplex::statelens::Participant>`. When the actor creates its mailbox,
    copy it into a `// [statelens] me` field of the mailbox, so that every holder of a
    mailbox clone can read it.
  - Standard adapters: read it from the core mailbox they hold.
  - Coding adapter and shards engine: take it from the scheme their scheme provider
    returns for the epoch of the round in hand.
  - The backfill resolver, the application gates and validation, `ancestry.rs` and
    `store.rs` have no identity of their own. Instrument them at their call sites in the
    components above, never inside them.
  - When the scheme has no signer (it is a verifier), `me` is `None`: the replica is not a
    participant.
- Asynchrony worth probing:
  - a finalization arrives before its block;
  - the floor moves while backfill is in flight;
  - a block arrives after its height was passed or pruned;
  - dispatch runs ahead of acknowledgements;
  - certification is requested before the block is available;
  - shards arrive out of order or after reconstruction;
  - state is rebuilt from the archives after a restart.
- Heights: record them relative to the processed floor, the last delivered height or the
  finalized tip, never raw. Never feed commitments or shard indices to a probe.
~~~

---

## 14. Acceptance procedures

| AC | Procedure | Pass condition |
|---|---|---|
| AC-1 | For each agent: `just extract issue <URL of a real Simplex bug>`. | At least one new `invariants/simplex/INV-*.md`; `just check-invariants` reports no problem for it. |
| AC-2 | On `main` with the subproject committed: `git ls-files consensus/fuzz/statelens` contains no `Cargo.toml`; `just check-fmt`; `just lint`; `just test -p commonware-consensus`; the CI fuzz target listings for `consensus/fuzz/simplex` and `consensus/fuzz/marshal`. | All behave exactly as without the subproject. |
| AC-3 | `just check-invariants`; `git ls-files consensus/fuzz/statelens/invariants consensus/fuzz/statelens/false-invariants`; then `just extract --registry marshal comment consensus/src/marshal/mod.rs`. | No lint problem. Every invariant file is in a subsystem directory. The new files are in `invariants/marshal/`, numbered from the next global ID. |
| AC-4 | With at least one simplex invariant: `just campaign`, then the printed `run` command. | Materialize, instrument, plan, build and test gate complete, the result is `READY`, and the `run` command starts the fuzzer. |
| AC-5 | In an instrumented checkout, two 10-minute runs on empty corpora: `STATELENS_FEEDBACK=0 just run simplex_statelens <empty dir A> -- -max_total_time=600` and the same without the variable on `<empty dir B>`. | The `ft:` value on the `DONE` line is higher with feedback. Compare `ft:`, not `cov:` (section 9.3). |
| AC-6 | `STATELENS_FALSE_INVARIANTS=1 just campaign`; if the result is `READY`, a short run of the printed `run` command. | Result `PANIC (tests)` with `[statelens][FALSE-0001]`, or a panic with it in the short run. |
| AC-7 | In an instrumented checkout: `STATELENS_BYZANTINE=panic just run simplex_statelens -- -max_total_time=120`, then the same without the variable. | The first run panics with `[statelens][BYZANTINE]`; the second does not; `[statelens] participant index mismatch` never appears. Verified at the reference commit (section 1.2). |
| AC-8 | `just run simplex_statelens <artifact>` in the checkout of a crashing Phase 3 run, with that run's `STATELENS_BYZANTINE` value. | The same `[statelens][...]` line as in that run. Verified for `BYZANTINE` (section 1.2). |
| AC-14 | With `STATELENS_KB` set to a findings corpus, run the queries of section 5.6 by hand for each registry: `kb modules`, `kb find`, `kb cites <a component directory>`, `kb grep`, `kb show`. | Every command answers from the index; `find` and `cites` return only findings whose `module` is in that subsystem's filter; `cites` returns the findings that name files under the directory, with those files listed; `show` refuses a section that is not state-bearing and an identifier out of scope. |
| AC-15 | `STATELENS_KB=` with a campaign. | The campaign warns that there is no knowledge base, renders the beacon step with no query commands, and still reaches `READY`. |
| R-NF-3 | Same duration and flags: `simplex_statelens` in an instrumented checkout, and `simplex_cert_mock_twins_mutator` in an uninstrumented checkout at the same commit. | exec/s from `-print_final_stats=1` are reported side by side; a slowdown above 2x is recorded as an instrumentation problem. |

Section 8.6 gives the procedures for AC-9 to AC-13, and for R-NF-3 on the marshal
variants.

---

## 15. Implementation order

1. Create the layout of section 3 with the verbatim files: `config.env`, `justfile`,
   `templates/invariant.md`, all prompts with the subsystem parts (section 13),
   `false-invariants/simplex/FALSE-0001.md` (Appendix C),
   `false-invariants/marshal/FALSE-0002.md` (Appendix E), `runtime/statelens.rs`
   (Appendix A) and `runtime/target.rs` (Appendix B.1). Create `invariants/simplex/` and
   `invariants/marshal/`, each with a `.gitkeep` file while it is empty. Invariant files
   that already exist go to their subsystem directory with `git mv`.
2. Check the runtime templates:
   `rustfmt +<pinned nightly> --edition 2024 --config-path rustfmt.toml --check consensus/fuzz/statelens/runtime/*.rs`.
3. Implement `scripts/statelens.py` in this order: config and argument parsing, `lint`,
   prompt rendering, agent invocation, `extract`, the knowledge-base index and the `kb`
   commands, then `campaign`. Implement `campaign`
   for the `simplex` profile first, starting with the materialize step and
   `--stop-after materialize`, and then for the `marshal` profile (chapter 8).
4. Write `README.md` (Appendix D).
5. Validate:
   - `just check-invariants`;
   - `STATELENS_FALSE_INVARIANTS=1 just campaign --stop-after build`, then AC-1 to AC-8;
   - `STATELENS_FALSE_INVARIANTS=1 just campaign --profile marshal --stop-after build`, then
     AC-9 to AC-13;
   - with `STATELENS_KB` set to a findings corpus, the queries of section 5.6, then AC-14
     and AC-15.
6. Change nothing outside `consensus/fuzz/statelens/`.

---

## 16. Known limitations

- Throughput is about 13 executions per second per process, so fuzzing needs many
  core-hours. Run the targets with `-fork=<N>`.
- The patch anchors in sections 7.2 and 8.3 follow the code. When one moves, the
  campaign stops with exit code 2 and the anchor in `statelens.py` must be updated.
- Agents are not deterministic: the same invariant can be bound differently in two
  campaigns. The plan and `instrumentation.diff` document each binding.
- A campaign instruments the checkout in place, so every campaign needs a fresh clone.
  The script refuses a checkout that an earlier campaign instrumented.
- The beacon components cover the Simplex actors and marshal's core, standard and coding
  (D28). Code outside them, such as `types.rs`, the backfill resolver or the application
  code, gets no beacon probes even when the knowledge base has findings about it.
- `kb find` and `kb grep` are lexical (D33), so a word query misses a finding whose wording
  differs. A component's queries do not depend on wording, because they start from
  `kb cites <its directory>`; the remedy for a word query is another query in the loop.
- Replicas without a participant index (`me() == None`) have no per-replica ghost
  state, so ghost-based checks skip them.
- The Twins tests are not part of the test gate (D2). The fuzz harness itself exercises
  Twins scenarios with the correct guard.
- The runtime module relies on the deterministic runtime running tasks on the calling
  thread (`Runner::start` calls `start_and_recover` on the same thread).

---

---

## Appendix A: `runtime/statelens.rs` (verbatim)

~~~rust
//! StateLens runtime support for an instrumented Simplex campaign.
//!
//! This file is a template kept in `consensus/fuzz/statelens/runtime/`. A campaign
//! copies it into the checkout it instruments as `consensus/src/simplex/statelens.rs`
//! and declares it with `pub mod statelens;`. It is never compiled on a committed
//! branch.
//!
//! It provides:
//! - the Byzantine guard: [set_compromised], [clear_compromised], [is_byzantine]
//!   and [should_check];
//! - a SanitizerCoverage counter table fed by state probes: [record] and [reset];
//! - the instrumentation macros `sl_probe!`, `sl_assert!` and `sl_implies!`,
//!   invoked as `crate::simplex::statelens::sl_probe!(...)`;
//! - ghost state: per replica ([Ghost], [with_ghost]) and shared by all honest
//!   replicas ([Global], [with_global]). It lives for one run: [reset] and every
//!   fresh deterministic runtime clear it, while a runtime resumed from a
//!   checkpoint (a crash-restart) keeps it;
//! - discretization helpers: [bucket], [delta], [flag], [pack] and [disc].
//!
//! Environment switches, each read once per process:
//! - `STATELENS_BYZANTINE` sets what instrumentation does for a compromised
//!   replica: `skip` (default) ignores it, `check` checks it like an honest
//!   replica, and `panic` panics at the first instrumented site it reaches.
//! - `STATELENS_FEEDBACK=0` leaves the counter table unregistered, so probes add
//!   no libFuzzer features.

// `cargo fuzz` sets `--cfg fuzzing`, which the workspace check-cfg list does not
// declare for this crate.
#![allow(unexpected_cfgs)]

pub use commonware_utils::Participant;
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fmt,
    hash::{Hash, Hasher},
    sync::{
        OnceLock,
        atomic::{AtomicU8, Ordering},
    },
};

/// Number of counters in the StateLens table.
pub const COUNTERS: usize = 1 << 16;

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

static TABLE: sancov::Counters<COUNTERS> = sancov::Counters::new();

thread_local! {
    static COMPROMISED: RefCell<BTreeSet<u32>> = const { RefCell::new(BTreeSet::new()) };
    static GHOSTS: RefCell<BTreeMap<u32, Ghost>> = const { RefCell::new(BTreeMap::new()) };
    static GLOBAL: RefCell<Global> = RefCell::new(Global::default());
}

/// What instrumentation does at a site reached by a compromised replica.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Byzantine {
    /// Skip the site: the Byzantine guard (default).
    Skip,
    /// Check the replica like an honest one.
    Check,
    /// Panic, which shows that compromised replicas reach instrumented sites.
    Panic,
}

impl Byzantine {
    /// Parses the value of `STATELENS_BYZANTINE`.
    fn parse(value: Option<&str>) -> Self {
        match value {
            None | Some("skip") => Self::Skip,
            Some("check") => Self::Check,
            Some("panic") => Self::Panic,
            Some(other) => {
                panic!("STATELENS_BYZANTINE must be skip, check or panic, not {other:?}")
            }
        }
    }
}

fn byzantine() -> Byzantine {
    static MODE: OnceLock<Byzantine> = OnceLock::new();
    *MODE.get_or_init(|| Byzantine::parse(std::env::var("STATELENS_BYZANTINE").ok().as_deref()))
}

/// Formats an optional participant index for panic messages.
struct Replica(Option<Participant>);

impl fmt::Display for Replica {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(me) => write!(f, "{}", me.get()),
            None => f.write_str("none"),
        }
    }
}

/// Publishes the participant indices of the compromised replicas of this run.
///
/// Called by the patched Twins runner before any engine starts.
pub fn set_compromised(indices: impl IntoIterator<Item = usize>) {
    COMPROMISED.with(|set| {
        let mut set = set.borrow_mut();
        set.clear();
        set.extend(
            indices
                .into_iter()
                .map(|index| u32::try_from(index).expect("participant index must fit in u32")),
        );
    });
}

/// Forgets the compromised set, so every replica is treated as honest.
pub fn clear_compromised() {
    COMPROMISED.with(|set| set.borrow_mut().clear());
}

/// Returns whether `me` is compromised in the current run.
///
/// A replica without a participant index is never compromised.
pub fn is_byzantine(me: Option<Participant>) -> bool {
    me.is_some_and(|me| COMPROMISED.with(|set| set.borrow().contains(&me.get())))
}

/// Returns whether instrumentation should observe and check replica `me`.
///
/// This is the Byzantine guard. Every StateLens macro calls it before
/// evaluating any other argument.
pub fn should_check(me: Option<Participant>) -> bool {
    if !is_byzantine(me) {
        return true;
    }
    match byzantine() {
        Byzantine::Skip => false,
        Byzantine::Check => true,
        Byzantine::Panic => panic!(
            "[statelens][BYZANTINE] replica={} compromised replica reached an instrumented site",
            Replica(me)
        ),
    }
}

/// Raw pointer to the counter bytes.
fn table() -> *mut u8 {
    // `Counters<N>` is `#[repr(transparent)]` over `UnsafeCell<[u8; N]>`.
    (&TABLE as *const sancov::Counters<COUNTERS>)
        .cast::<u8>()
        .cast_mut()
}

/// Prepares a fuzz input: zeroes the counter table, forgets the compromised set
/// and clears the ghost state. In a fuzzing build it also registers the table
/// with libFuzzer on first use, unless `STATELENS_FEEDBACK=0`.
///
/// Called by the StateLens fuzz target before every input.
pub fn reset() {
    #[cfg(fuzzing)]
    {
        static REGISTERED: std::sync::Once = std::sync::Once::new();
        REGISTERED.call_once(|| {
            if std::env::var("STATELENS_FEEDBACK").map_or(true, |value| value != "0") {
                TABLE.register();
            }
        });
    }
    // SAFETY: `table` points to `COUNTERS` bytes inside a static. `reset` runs on
    // the fuzzing thread between inputs, when no probe writes concurrently.
    unsafe { core::ptr::write_bytes(table(), 0, COUNTERS) };
    clear_compromised();
    forget_ghosts();
}

/// Forgets all ghost state.
///
/// Registered as the deterministic runtime's fresh-run hook, so history from an
/// earlier, independent run on this thread (for example another seed of the same
/// test) does not leak into the next run. A runtime resumed from a checkpoint (a
/// crash-restart) keeps the history.
fn forget_ghosts() {
    GHOSTS.with(|ghosts| ghosts.borrow_mut().clear());
    GLOBAL.with(|global| *global.borrow_mut() = Global::default());
}

/// Registers [forget_ghosts] with the deterministic runtime, once per process.
fn register_fresh_run_hook() {
    static REGISTERED: std::sync::Once = std::sync::Once::new();
    REGISTERED.call_once(|| {
        let _ = commonware_runtime::deterministic::STATELENS_FRESH_RUN.set(forget_ghosts);
    });
}

/// Hashes a probe site label at compile time (FNV-1a, 64 bits).
pub const fn site_hash(label: &str) -> u64 {
    let bytes = label.as_bytes();
    let mut hash = FNV_OFFSET;
    let mut i = 0;
    while i < bytes.len() {
        hash ^= bytes[i] as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
        i += 1;
    }
    hash
}

/// Maps a probe observation `(site, a, b)` to a counter index.
pub const fn cell(site: u64, a: u32, b: u32) -> usize {
    let values = ((a as u64) << 32) | b as u64;
    let mut x = site ^ values.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^= x >> 31;
    (x % COUNTERS as u64) as usize
}

/// Marks the counter of observation `(site, a, b)` as seen.
///
/// Presence only: a counter is 0 (not seen in this input) or 1 (seen), so a
/// state observed many times still yields a single libFuzzer feature.
pub fn record(site: u64, a: u32, b: u32) {
    let index = cell(site, a, b);
    // SAFETY: `index < COUNTERS`, so the pointer stays inside the table. Probes
    // only access the table atomically; the non-atomic zeroing in `reset` runs
    // when no probe executes.
    let counter = unsafe { AtomicU8::from_ptr(table().add(index)) };
    counter.store(1, Ordering::Relaxed);
}

/// Panics with the StateLens violation message for invariant `id`.
#[cold]
#[track_caller]
pub fn violation(me: Option<Participant>, id: &str, message: fmt::Arguments<'_>) -> ! {
    panic!("[statelens][{id}] replica={} {message}", Replica(me));
}

/// Buckets a count or distance: 0, 1, 2, 3-4, 5-8 and 9+ map to 0..=5.
pub const fn bucket(n: u64) -> u32 {
    match n {
        0 => 0,
        1 => 1,
        2 => 2,
        3..=4 => 3,
        5..=8 => 4,
        _ => 5,
    }
}

/// Buckets the signed distance `a - b`: 0..=5 when `a >= b`, 6..=10 when `a < b`.
pub const fn delta(a: u64, b: u64) -> u32 {
    if a >= b {
        bucket(a - b)
    } else {
        5 + bucket(b - a)
    }
}

/// Converts a boolean to 0 or 1.
pub const fn flag(value: bool) -> u32 {
    value as u32
}

/// Packs two small values, each below 2^16, into one probe value.
pub const fn pack(high: u32, low: u32) -> u32 {
    (high << 16) | (low & 0xffff)
}

/// Returns a stable code for the variant of an enum value, ignoring its payload.
pub fn disc<T>(value: &T) -> u32 {
    let mut hasher = Fnv(FNV_OFFSET);
    std::mem::discriminant(value).hash(&mut hasher);
    hasher.finish() as u32
}

/// FNV-1a hasher with a fixed seed, so codes are stable within a build.
struct Fnv(u64);

impl Hasher for Fnv {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 ^= u64::from(*byte);
            self.0 = self.0.wrapping_mul(FNV_PRIME);
        }
    }
}

/// Per-replica ghost state for cross-actor and cross-restart invariants.
///
/// Instrumentation adds `pub` fields here, each preceded by a
/// `// [statelens] ghost:INV-NNNN` comment. Every field type must implement
/// `Default`.
#[derive(Default)]
pub struct Ghost {}

/// Ghost state shared by all honest replicas, for `protocol` invariants.
///
/// Instrumentation adds `pub` fields here, each preceded by a
/// `// [statelens] ghost:INV-NNNN` comment. Every field type must implement
/// `Default`.
#[derive(Default)]
pub struct Global {}

/// Runs `f` on the ghost state of replica `me`, creating it on first use.
///
/// Returns `None`, without calling `f`, for a replica without a participant
/// index or one the guard skips. `f` must not call [with_ghost] or [with_global].
pub fn with_ghost<R>(me: Option<Participant>, f: impl FnOnce(&mut Ghost) -> R) -> Option<R> {
    register_fresh_run_hook();
    let index = me?.get();
    if !should_check(me) {
        return None;
    }
    Some(GHOSTS.with(|ghosts| f(ghosts.borrow_mut().entry(index).or_default())))
}

/// Runs `f` on the ghost state shared by all honest replicas.
///
/// Returns `None`, without calling `f`, when the guard skips `me`. `f` must not
/// call [with_ghost] or [with_global].
pub fn with_global<R>(me: Option<Participant>, f: impl FnOnce(&mut Global) -> R) -> Option<R> {
    register_fresh_run_hook();
    if !should_check(me) {
        return None;
    }
    Some(GLOBAL.with(|global| f(&mut global.borrow_mut())))
}

/// Records a state probe for replica `me`: `sl_probe!(me, "label", a, b)`.
///
/// `a` and `b` must convert into `u32` with `Into` (`bool`, `u8`, `u16`, `u32`),
/// so raw `u64` views or counts must go through [bucket] or [delta] first. The
/// site is `label` plus the call location, so every call site is distinct.
#[allow(unused_macros)]
macro_rules! sl_probe {
    ($me:expr, $label:literal, $a:expr, $b:expr $(,)?) => {{
        let me: ::core::option::Option<$crate::simplex::statelens::Participant> = $me;
        if $crate::simplex::statelens::should_check(me) {
            const SITE: u64 = $crate::simplex::statelens::site_hash(::core::concat!(
                $label,
                "@",
                ::core::file!(),
                ":",
                ::core::line!(),
                ":",
                ::core::column!()
            ));
            let a: u32 = ::core::convert::Into::<u32>::into($a);
            let b: u32 = ::core::convert::Into::<u32>::into($b);
            $crate::simplex::statelens::record(SITE, a, b);
        }
    }};
}

/// Asserts invariant `id` for replica `me`:
/// `sl_assert!(me, "INV-0001", cond, "format", args...)`.
#[allow(unused_macros)]
macro_rules! sl_assert {
    ($me:expr, $id:literal, $cond:expr, $($arg:tt)+) => {{
        let me: ::core::option::Option<$crate::simplex::statelens::Participant> = $me;
        if $crate::simplex::statelens::should_check(me) && !($cond) {
            $crate::simplex::statelens::violation(me, $id, ::core::format_args!($($arg)+));
        }
    }};
}

/// Asserts "if `pre` then `post`" for invariant `id` and records the probe
/// `(pre, post)`: `sl_implies!(me, "INV-0001", pre, post, "format", args...)`.
///
/// `post` is evaluated only when `pre` holds.
#[allow(unused_macros)]
macro_rules! sl_implies {
    ($me:expr, $id:literal, $pre:expr, $post:expr, $($arg:tt)+) => {{
        let me: ::core::option::Option<$crate::simplex::statelens::Participant> = $me;
        if $crate::simplex::statelens::should_check(me) {
            const SITE: u64 = $crate::simplex::statelens::site_hash(::core::concat!(
                $id,
                "@",
                ::core::file!(),
                ":",
                ::core::line!(),
                ":",
                ::core::column!()
            ));
            let pre: bool = $pre;
            let post: bool = pre && ($post);
            $crate::simplex::statelens::record(SITE, u32::from(pre), u32::from(post));
            if pre && !post {
                $crate::simplex::statelens::violation(me, $id, ::core::format_args!($($arg)+));
            }
        }
    }};
}

// `simplex` is declared inside a macro (`stability_scope!`), so `#[macro_export]`
// macros could not be called by path from this crate. Instrumented code calls
// `crate::simplex::statelens::sl_probe!(...)` through these re-exports instead.
#[allow(unused_imports)]
pub(crate) use {sl_assert, sl_implies, sl_probe};

#[cfg(test)]
mod tests {
    use super::*;

    fn evaluated() -> bool {
        panic!("post must not be evaluated when pre is false");
    }

    #[test]
    fn test_discretization() {
        let buckets: Vec<u32> = [0, 1, 2, 3, 4, 5, 8, 9, 1_000]
            .into_iter()
            .map(bucket)
            .collect();
        assert_eq!(buckets, vec![0, 1, 2, 3, 3, 4, 4, 5, 5]);
        assert_eq!(delta(7, 7), 0);
        assert_eq!(delta(9, 7), 2);
        assert_eq!(delta(7, 9), 7);
        assert_eq!(delta(0, u64::MAX), 10);
        assert_eq!(pack(3, 4), (3 << 16) | 4);
        assert_eq!(flag(true), 1);
        assert_eq!(disc(&Some(1u8)), disc(&Some(2u8)));
        assert_ne!(disc(&Some(1u8)), disc(&None::<u8>));
    }

    #[test]
    fn test_byzantine_mode_parsing() {
        assert_eq!(Byzantine::parse(None), Byzantine::Skip);
        assert_eq!(Byzantine::parse(Some("skip")), Byzantine::Skip);
        assert_eq!(Byzantine::parse(Some("check")), Byzantine::Check);
        assert_eq!(Byzantine::parse(Some("panic")), Byzantine::Panic);
    }

    #[test]
    #[should_panic(expected = "STATELENS_BYZANTINE must be skip, check or panic")]
    fn test_byzantine_mode_rejects_unknown_values() {
        let _ = Byzantine::parse(Some("0"));
    }

    #[test]
    fn test_guard_skips_compromised() {
        set_compromised([1]);
        assert!(is_byzantine(Some(Participant::new(1))));
        assert!(!is_byzantine(Some(Participant::new(0))));
        assert!(!is_byzantine(None));
        assert!(!should_check(Some(Participant::new(1))));
        crate::simplex::statelens::sl_assert!(
            Some(Participant::new(1)),
            "INV-TEST",
            false,
            "skipped"
        );
        crate::simplex::statelens::sl_implies!(
            Some(Participant::new(1)),
            "INV-TEST",
            true,
            false,
            "skipped"
        );
        clear_compromised();
        assert!(!is_byzantine(Some(Participant::new(1))));
    }

    #[test]
    #[should_panic(expected = "[statelens][INV-TEST] replica=0 fires 7")]
    fn test_assert_fires_for_honest() {
        clear_compromised();
        crate::simplex::statelens::sl_assert!(
            Some(Participant::new(0)),
            "INV-TEST",
            false,
            "fires {}",
            7
        );
    }

    #[test]
    fn test_implies_evaluates_post_lazily() {
        crate::simplex::statelens::sl_implies!(None, "INV-TEST", false, evaluated(), "never");
        crate::simplex::statelens::sl_implies!(None, "INV-TEST", true, true, "holds");
    }

    #[test]
    #[should_panic(expected = "[statelens][INV-TEST] replica=none broken")]
    fn test_implies_fires() {
        crate::simplex::statelens::sl_implies!(None, "INV-TEST", true, false, "broken");
    }

    #[test]
    fn test_probe_sets_cell() {
        crate::simplex::statelens::sl_probe!(None, "unit", true, 3u8);
        let site = site_hash("unit-direct");
        record(site, 3, 4);
        // SAFETY: `cell` returns an index below `COUNTERS`; the load is atomic.
        let value =
            unsafe { AtomicU8::from_ptr(table().add(cell(site, 3, 4))) }.load(Ordering::Relaxed);
        assert_eq!(value, 1);
    }

    #[test]
    fn test_ghost_state_skips_guarded_replicas() {
        set_compromised([3]);
        assert_eq!(with_ghost(None, |_| ()), None);
        assert_eq!(with_ghost(Some(Participant::new(2)), |_| 5), Some(5));
        assert_eq!(with_ghost(Some(Participant::new(3)), |_| 5), None);
        assert_eq!(with_global(None, |_| 6), Some(6));
        assert_eq!(with_global(Some(Participant::new(3)), |_| 6), None);
        clear_compromised();
    }

    #[test]
    fn test_fresh_runtime_forgets_ghost_state() {
        clear_compromised();
        assert_eq!(with_ghost(Some(Participant::new(4)), |_| ()), Some(()));
        assert!(GHOSTS.with(|ghosts| ghosts.borrow().contains_key(&4)));
        let _runner = commonware_runtime::deterministic::Runner::seeded(0);
        assert!(GHOSTS.with(|ghosts| ghosts.borrow().is_empty()));
    }
}
~~~

---

## Appendix B: fuzz target and runner hook

### B.1 `runtime/target.rs` (verbatim)

~~~rust
#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_consensus::simplex::statelens;
    use commonware_consensus_fuzz_simplex::{
        CodeCoverage, FuzzInput, SimplexCertificateMock, TwinsMutator, fuzz,
    };
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: FuzzInput| {
        statelens::reset();
        fuzz::<SimplexCertificateMock, TwinsMutator, CodeCoverage>(input);
        statelens::clear_compromised();
    });
}
~~~

`SimplexCertificateMock` uses the `cert_mock` certificate scheme, the only scheme
StateLens fuzz targets may use (D15). `CodeCoverage` keeps `state_cov` and
happens-before feedback off (R-FB-1). `TwinsMutator` forces the `N4F1C3` configuration.

### B.2 `[[bin]]` block appended to `consensus/fuzz/simplex/Cargo.toml` (verbatim)

~~~toml

[[bin]]
name = "simplex_statelens"
path = "fuzz_targets/simplex_statelens.rs"
test = false
doc = false
bench = false
required-features = ["twins"]
~~~

### B.3 Hook inserted into `run_twins_with_backend` (verbatim)

Inserted after the anchor line of section 7.2, edit 6, with this indentation:

~~~rust
    // [statelens] Publish the compromised set before any engine starts, and check
    // that every scheme's own index matches its position in `participants`.
    commonware_consensus::simplex::statelens::set_compromised(compromised.iter().copied());
    for (idx, scheme) in setup.schemes.iter().enumerate() {
        assert_eq!(
            commonware_cryptography::certificate::Scheme::me(scheme),
            Some(commonware_utils::Participant::from_usize(idx)),
            "[statelens] participant index mismatch"
        );
    }
~~~

In `TwinsMutator`, each compromised participant runs a real engine (the primary half),
which the guard skips, and a `Disrupter` (the secondary half), which runs no Simplex
actor code.

### B.4 Fresh-run hook in `runtime/src/deterministic.rs` (verbatim)

Inserted before `impl From<Config> for Runner {`, followed by a blank line:

~~~rust
// [statelens] Fresh-run hook: `Runner::new` calls the registered function, which
// forgets StateLens ghost state, so an independent run does not inherit history
// from an earlier run on the same thread. A restart from a checkpoint keeps it.
pub static STATELENS_FRESH_RUN: std::sync::OnceLock<fn()> = std::sync::OnceLock::new();
~~~

Inserted after `    pub fn new(cfg: Config) -> Self {`:

~~~rust
        // [statelens] A fresh runtime starts an independent run.
        if let Some(hook) = STATELENS_FRESH_RUN.get() {
            hook();
        }
~~~

Every fresh runtime goes through `Runner::new` (`From<Config>`, `seeded` and `timed` call
it), while a crash-restart resumes through `From<Checkpoint>`. The first end-to-end
campaign showed why this is needed: without it, a history invariant fired in tests that
run several seeds in one thread, because the ghost state of one seed leaked into the
next.

---

## Appendix C: `false-invariants/simplex/FALSE-0001.md` (verbatim)

~~~markdown
---
id: FALSE-0001
title: Deliberately false, never accept a nullification
source_kind: human
source_ref: consensus/fuzz/statelens/docs/SPEC.md (acceptance procedure AC-6)
scope: [replica, voter]
---

## Statement
The replica shall not accept a nullification certificate for any view.

## Rationale
Deliberately false. Nullifications are part of normal operation, for example when a
leader is slow or offline. A campaign that includes this invariant must panic with
[statelens][FALSE-0001], which shows that invariants are bound, checked and reported.

## Evidence
Workflow test, see SPEC.md section 14.
~~~

---

## Appendix D: `README.md` outline

1. What StateLens is, in three sentences: the two subsystems it covers and its three
   phases, with links to PRD.md and SPEC.md.
2. How to run a campaign safely: campaigns give the agent full control of the machine
   (D4) and instrument the checkout in place (D10). Clone the repository fresh on a
   dedicated machine or container, run the campaign and the fuzzers in that clone, and
   discard the clone afterwards. Never commit an instrumented checkout.
3. Prerequisites (section 5.2) and `config.env`.
4. Phase 1a: `just extract [--registry simplex|marshal] <kind> <source>...` with one example
   per kind, then review: every file in a registry is used by the next campaign that binds
   it; edit or delete drafts; `just check-invariants`.
5. The knowledge base: what `STATELENS_KB` points at, that a campaign's beacon step queries
   it while instrumenting, and the `kb` commands an operator can run by hand.
6. Phase 2: `just campaign`, `just campaign --profile marshal`, `just campaign --agent codex`,
   `--stop-after`. A campaign builds the StateLens targets and does not fuzz; `just fuzz
   <target>` is the convenience that runs a campaign and then fuzzes one of its targets, and
   `just clean` undoes what a campaign wrote so a checkout can be reused.
7. Phase 3: run the printed `run` commands, adding libFuzzer arguments such as `-fork=8`
   (section 7.10); which marshal variants have an adversary that runs Simplex or marshal code.
8. Results: the summary lines, exit codes, and `campaign/` (plan, diff, logs, prompts).
9. Investigating a panic (section 7.12).
10. Testing the workflow itself: `STATELENS_FALSE_INVARIANTS=1` (the campaign must panic on
   the deliberately false invariants), `STATELENS_BYZANTINE=panic` (guard test) and
   `STATELENS_FEEDBACK=0` (feedback comparison).

---

## Appendix E: `false-invariants/marshal/FALSE-0002.md` (verbatim)

~~~markdown
---
id: FALSE-0002
title: Deliberately false, never deliver a block above height 1
source_kind: human
source_ref: consensus/fuzz/statelens/docs/SPEC.md (acceptance procedure AC-10)
scope: [replica, core]
---

## Statement
The replica shall not deliver a finalized block above height 1 to the application.

## Rationale
Deliberately false. Marshal delivers every finalized block to the application in height
order, so any run that finalizes two blocks violates it. A marshal campaign that includes
this invariant must panic with [statelens][FALSE-0002], which shows that marshal
invariants are bound, checked and reported.

## Evidence
Workflow test, see SPEC.md section 8.6.
~~~

---

## Appendix F: wedge-scenario hook (verbatim)

Inserted after the anchor line of edit M3 (section 8.3), with this indentation:

~~~rust
        // [statelens] The Byzantine role runs a real engine and marshal behind the wedge:
        // publish it as compromised before any engine starts, and check that every
        // scheme's own index matches its position in `participants`.
        commonware_consensus::simplex::statelens::set_compromised([Role::Byzantine.index()]);
        for (idx, scheme) in schemes.iter().enumerate() {
            assert_eq!(
                commonware_cryptography::certificate::Scheme::me(scheme),
                Some(commonware_utils::Participant::from_usize(idx)),
                "[statelens] participant index mismatch"
            );
        }
~~~

`run_scenario` creates `schemes` with `P::setup` before this line and uses it afterwards,
so the loop only borrows it. The StateLens variant clears the compromised set after the
harness returns, as the Simplex target does (D7).
