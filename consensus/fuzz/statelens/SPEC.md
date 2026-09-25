# StateLens for Simplex: Technical Specification

| | |
|---|---|
| Implements | [PRD.md](PRD.md) |
| Audience | The coding agent that implements `consensus/fuzz/statelens/`, and fuzz operators |
| Verified against | commit `7cb6a3d58351d7545314c752f9d3f8535e8a7428` (see section 1.2) |

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

- `runtime/statelens.rs` (Appendix A): 9 unit tests pass inside `commonware-consensus`
  with the workspace's `warnings = "deny"` on stable, and the `cfg(fuzzing)` path
  compiles on the CI-pinned nightly. The file is `rustfmt`-clean with the repository
  configuration.
- The materialization edits (section 7.2), the fuzz target and the Twins runner hook
  (Appendix B): `cargo fuzz build` succeeds and the target runs.
- The Byzantine guard end to end: with `STATELENS_BYZANTINE=panic` the first input
  panics with `[statelens][BYZANTINE] replica=2`; replaying the saved artifact
  reproduces the panic; in the default mode the same input runs cleanly, and a
  30-second run produces no such panic. The index-mapping assertion in the hook never
  fired.
- The test gate (section 7.7) with sample instrumentation: 240 tests passed in 125 s
  on 16 cores.
- Throughput of the target with minimal instrumentation: about 13 executions per
  second per process.

---

## 2. Decisions

These decisions were made while writing this specification. The PRD states each of
them; the last column names the PRD requirement.

| ID | Decision | PRD requirement |
|---|---|---|
| D1 | Every file in `SL/invariants/` is active. Phase 1 writes there; humans review, edit and delete. There is no `status` field. | R-REG-1, R-P1-5 |
| D2 | The test gate runs the engine-level tests `simplex::tests::*` including the `slow` group, minus the Twins tests, plus the `simplex::statelens` self-tests. Only 7 of the 247 engine-level tests are outside the `slow` group, so a non-slow gate would check almost nothing. Twins tests run two live engines with one identity, which breaks per-replica ghost state. | R-P2-2 step 6 |
| D3 | Probes record presence: a counter is set to 1, never incremented. | R-FB-2 |
| D4 | Phase 2 agents run with full permissions in the checkout. Phase 1 agents run restricted. Campaigns MUST run on a dedicated machine or container. | R-AG-3 |
| D5 | The fuzz target `simplex_statelens` is added during a campaign to the existing `consensus/fuzz/simplex` package; no new package is created. `just run simplex_statelens` works unchanged. | G4, R-P2-2 step 1 |
| D6 | The macros are `macro_rules!` items re-exported with `pub(crate) use` and invoked by path: `crate::simplex::statelens::sl_implies!(...)`. `#[macro_export]` cannot work: `simplex` is declared inside `stability_scope!`, and macro-expanded `macro_export` macros cannot be called by absolute path from their own crate. | R-INS-4 |
| D7 | The Byzantine guard is built into the macros and into the ghost accessors, so no call site can forget it. The fuzz target calls `clear_compromised()` after `fuzz()` returns, not inside the runner, so compromised replicas stay guarded while the runtime shuts down. | R-INS-2, PRD section 8.4 |
| D8 | The runner hook also asserts that every scheme's own index equals its position in the participant list. | PRD section 8.4, AC-6 |
| D9 | `protocol`-scope invariants use a guarded ghost store shared by all honest replicas (`Global`, `with_global`). | R-INS-5 |
| D10 | A campaign runs in place in the operator's checkout, a fresh clone of the repository; StateLens never makes another clone. The campaign refuses a checkout with tracked changes outside `SL/` or with instrumentation from an earlier campaign, never commits, and records its changes in `SL/campaign/instrumentation.diff`. Uncommitted registry edits are used. | R-P2-1 |
| D11 | Tests use the `stable` toolchain; fuzz builds use the nightly pinned in `.github/workflows/slow.yml`. | R-P2-2 step 5 |
| D12 | Orchestration is one Python 3 script, `SL/scripts/statelens.py` (standard library only), wrapped by `SL/justfile`. | R-LAYOUT-1, R-AG-1 |
| D13 | No `Cargo.toml` is committed under `SL/`. `SL/runtime/*.rs` MUST stay `rustfmt`-clean, because CI's `just check-fmt` formats every `*.rs` file in the tree. | R-LAYOUT-2, R-NF-4 |
| D14 | Prompt files are named `analyst-<kind>.md`, one per source kind (`issue`, `design`, `comment`, `spec`, `paper`), plus a shared `analyst.md`. | R-LAYOUT-1, R-P1-2 |
| D15 | StateLens fuzz targets use only the `cert_mock` certificate scheme (`consensus/src/simplex/mocks/scheme.rs`, imported as `cert_mock` in `consensus/fuzz/core`). Every `fuzz::<P, ...>` call in a target template names a `P` whose `impl Simplex` in `consensus/fuzz/core/src/simplex.rs` sets `type Scheme = cert_mock::Scheme<...>`. At the reference commit these are `SimplexCertificateMock`, `SimplexCertificateMockAttributable`, `SimplexCertificateMockCustomRoundRobin` and `SimplexCertificateMockByzantineFirstLeader`; the committed target uses `SimplexCertificateMock`. No ed25519, BLS12-381 or secp256r1 scheme is used. The materialize step enforces this (section 7.2). The test gate is not affected. | R-P2-4 |

---

## 3. Committed layout

```
consensus/fuzz/statelens/
  PRD.md
  SPEC.md
  README.md                      operator guide (Appendix D)
  config.env                     defaults (section 5.1)
  justfile                       recipes (section 5.3)
  .gitignore                     two lines: `campaign/` and `extract/` (generated outputs)
  invariants/                    the registry; every INV-*.md is active
  false-invariants/
    FALSE-0001.md                deliberately false invariant for AC-5 (Appendix C)
  templates/
    invariant.md                 reference format (section 4.5)
  prompts/
    analyst.md                   Phase 1, shared part (section 12.1)
    analyst-issue.md             Phase 1, per kind (sections 12.2 to 12.6)
    analyst-design.md
    analyst-comment.md
    analyst-spec.md
    analyst-paper.md
    instrument.md                Phase 2, shared rules and API (section 12.7)
    instrument-invariants.md     Phase 2, bind invariants (section 12.8)
    instrument-beacons.md        Phase 2, beacon probes (section 12.9)
    repair.md                    Phase 2, compile repair (section 12.10)
  runtime/
    statelens.rs                 runtime support module (Appendix A)
    target.rs                    fuzz target, cert_mock scheme only (Appendix B.1, D15)
  scripts/
    statelens.py                 lint, extract, campaign (sections 5 to 7)
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

- One invariant per file: `SL/invariants/INV-NNNN.md`, where `NNNN` is a zero-padded
  decimal of at least 4 digits.
- False invariants live in `SL/false-invariants/FALSE-NNNN.md` and are used only when
  `STATELENS_FALSE_INVARIANTS=1` (section 7.1).
- The next ID is `1 + max(N)` over the existing `INV-N` files. Deleting the file with
  the highest ID lets its ID be reused; this is accepted.

### 4.2 Front matter

YAML front matter between two `---` lines. Keys, in this order:

| Key | Required | Value |
|---|---|---|
| `id` | yes | Equal to the file name without `.md`. |
| `title` | yes | One line, at most 80 characters. |
| `source_kind` | yes | `human`, `issue`, `design`, `comment`, `spec` or `paper`. |
| `source_ref` | yes | URL, path, `path:line`, document section, or paper page. |
| `scope` | yes | Inline list, one or more of `protocol`, `replica`, `voter`, `batcher`, `resolver`, `cross-actor`. |
| `author` | no | A person, or `claude`, `codex`, `claude/<model>`, `codex/<model>`. |

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
ghost state (section 8.4) and checked at the later action.

### 4.5 `templates/invariant.md` (verbatim)

~~~markdown
---
id: INV-NNNN
title: <one line, at most 80 characters>
source_kind: <human | issue | design | comment | spec | paper>
source_ref: <URL, path, path:line, document section, or paper page>
scope: [<one or more of: protocol, replica, voter, batcher, resolver, cross-actor>]
author: <person, or agent/model; optional>
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

`statelens.py lint [PATH...]` checks each file (default: all of `SL/invariants/*.md`
and `SL/false-invariants/*.md`) and prints `path: problem` for every violation:

1. File name matches `INV-\d{4,}\.md` in `invariants/` or `FALSE-\d{4,}\.md` in
   `false-invariants/`.
2. The file starts with `---`, and a second `---` line closes the front matter.
3. Every front-matter line is `key: value`. Required keys are present and non-empty;
   unknown keys are reported.
4. `id` equals the file stem.
5. `source_kind` is one of the allowed values.
6. `scope` is `[a, b, ...]` with allowed values only.
7. `## Statement`, `## Rationale` and `## Evidence` are present, in this order, and
   non-empty.
8. Only ASCII characters.

Exit code 0 when clean, 3 otherwise. EARS conformance is not linted; humans review it.

### 4.7 False invariants

`SL/false-invariants/FALSE-0001.md` (Appendix C) is a deliberately false invariant: a
working campaign must panic on it (AC-5). It follows the registry format with an ID
prefix of `FALSE`, and a campaign binds it only when `STATELENS_FALSE_INVARIANTS=1`.

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
~~~

Parsing: `KEY=VALUE` lines; `#` starts a comment line; values are not shell-expanded.
Precedence: command-line flag, then non-empty environment variable, then `config.env`.

Generated outputs stay inside the subproject and are ignored by git: `SL/campaign/` for
campaigns and `SL/extract/` for Phase 1 logs and paper text.

Environment-only switches:

| Variable | Effect |
|---|---|
| `STATELENS_FALSE_INVARIANTS=1` | Campaign also binds `SL/false-invariants/*.md`, next to the registry (AC-5). |
| `CARGO_TARGET_DIR` | Passed through. By default builds use the checkout's `target/`. |
| `STATELENS_BYZANTINE`, `STATELENS_FEEDBACK` | Read by the runtime module (section 8.5). |

### 5.2 Prerequisites

A fresh clone of the repository on a dedicated machine or container (D4, D10), with
`git`, `python3` (3.9 or later), `just`, `cargo` with the `stable` and pinned nightly
toolchains, `cargo-nextest`, `cargo-fuzz`, and the chosen agent CLI (`claude` or
`codex`), logged in. Phase 1 with `issue` sources also needs `gh` (logged in) or
network access for `curl`. Phase 1 with PDF papers uses `pdftotext` or the Python
`pypdf` module when available.

### 5.3 `justfile` (verbatim)

~~~
# StateLens recipes. See README.md.

set positional-arguments := true

# Turn sources into invariants: just extract <kind> <source>...
extract *args:
    python3 scripts/statelens.py extract "$@"

# Instrument this checkout, test and fuzz: just campaign [--agent A] [-- <libFuzzer args>]
campaign *args:
    python3 scripts/statelens.py campaign "$@"

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
| `extract` | `extract [--agent A] KIND SOURCE...` | 0 done (including zero files), 1 usage, 2 agent failed, 3 lint problems |
| `campaign` | `campaign [--agent A] [--stop-after STEP] [-- LIBFUZZER_ARGS...]` | 0 no panic, 1 usage, 2 setup or agent failure (including a checkout that is not fresh), 3 build failed, 4 test gate failed, 5 fuzzer crash |

`--stop-after` accepts `materialize`, `instrument`, `build` or `test`. It exists for
development and acceptance testing and is not a campaign parameter in the PRD sense.

Placeholders in prompt files have the form `{{NAME}}` (upper case). Rendering MUST fail
on a placeholder without a value. Every rendered prompt is saved next to its log.

---

## 6. Phase 1: extract

### 6.1 Sources

| Kind | Source syntax |
|---|---|
| `issue` | GitHub URL of an issue or pull request, or `owner/repo#N` |
| `design` | Local path or URL, with an optional `#section` suffix |
| `comment` | File or directory under `consensus/src/simplex`, optionally `path:line` or `path:start-end` |
| `spec` | Quint, TLA+ or Lean file, optionally `path:line` |
| `paper` | Local PDF or text file, or URL, with an optional `#page=N` suffix |

Several sources of one kind MAY be passed at once (R-P1-1).

### 6.2 Procedure

1. Validate `KIND` and that at least one source is given.
2. Record the content hash of every file in `SL/invariants/`.
3. Compute `NEXT_ID` (section 4.1).
4. For `paper`, convert each local `.pdf` source (ignoring a `#...` suffix) to text in
   `SL/extract/papers/<stem>.txt` with `pdftotext -layout`, falling back to `pypdf`. When
   neither is available, pass the PDF as is. List the text next to the source.
5. Render the prompt: `prompts/analyst.md`, a blank line, then `prompts/analyst-<KIND>.md`.
   Placeholders: `KIND`, `NEXT_ID`, `AUTHOR` (`claude` or `claude/<model>`, and likewise
   for codex), `TEMPLATE` (the content of `templates/invariant.md`), `SOURCES` (one
   `- <source>` line per source, with `(text: <path>)` appended for converted papers).
6. Run the agent with the Phase 1 invocation (section 11), working directory = the
   repository root, prompt on standard input. Log to
   `SL/extract/<UTC timestamp>-<kind>.log`.
7. New files = files that did not exist in step 2. Report any pre-existing file whose
   hash changed as a problem ("agent modified an existing invariant").
8. Lint the new files (section 4.6).
9. Print each new file with its title and the reminder: "Every file in invariants/ is
   used by the next campaign. Review, edit or delete these files first."

---

## 7. Phase 2: campaign

### 7.1 Preconditions and setup

A campaign runs in place in the checkout (D10); `repo` is its root
(`git rev-parse --show-toplevel`). StateLens never makes another clone.

1. Check the preconditions. Each failure exits with code 2 and a message that asks for a
   fresh clone:
   - `git status --porcelain --untracked-files=no` lists no path outside `SL/`;
   - neither `consensus/src/simplex/statelens.rs` nor
     `consensus/fuzz/simplex/fuzz_targets/simplex_statelens.rs` exists (an earlier
     campaign already instrumented this checkout).
2. `base = git rev-parse HEAD`.
3. Recreate `SL/campaign/` with `logs/`, `prompts/` and `meta.json`: `base`, `agent`,
   `model`, test and fuzz toolchains, start time, invariant IDs.
4. The invariants to bind are `SL/invariants/*.md`, plus `SL/false-invariants/*.md` when
   `STATELENS_FALSE_INVARIANTS=1`, sorted by ID. Uncommitted files are included.
5. Create `SL/campaign/plan.md` with this content, then fill in the values:

~~~markdown
# StateLens instrumentation plan

- Base commit: <base>
- Agent: <agent>
- Invariants: <count> (<ID, ID, ...>)

## Invariants

## Beacon probes

| Label | File and function | a | b | Beacon |
|---|---|---|---|---|
~~~

All steps run with working directory `repo` unless stated otherwise. The campaign never
commits, stages, stashes or resets anything, apart from the `git add --intent-to-add` of
section 7.2.

### 7.2 Step 1: materialize

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

Then run `git add --intent-to-add` on the two created files, so that `git diff` shows
them, and record the baseline snapshot for the scope check (section 7.5): every path that
`git status --porcelain --untracked-files=all` lists, with a hash of its content.

`sancov` is already a workspace dependency and is in `Cargo.lock`, so no network access
is needed. No workspace `Cargo.toml` edit is needed for `cfg(fuzzing)`: the module
allows `unexpected_cfgs` itself.

### 7.3 Step 2: bind invariants

1. Take the invariants of section 7.1 step 4. When there are none, skip to step 3 with a
   warning.
2. Split them into batches of 8.
3. For each batch, render `prompts/instrument.md`, a blank line, then
   `prompts/instrument-invariants.md`. Placeholders: `BASE`, `PLAN`
   (`consensus/fuzz/statelens/campaign/plan.md`), `CHECK` (section 7.6),
   `INVARIANT_IDS` (comma separated), `INVARIANTS` (for each file, a line
   `===== <path from repo root> =====` followed by its content).
4. Run the agent with the Phase 2 invocation (section 11). Save the prompt to
   `SL/campaign/prompts/invariants-<n>.md` and the output to
   `SL/campaign/logs/invariants-<n>.log`.
5. A non-zero agent exit aborts the campaign with exit code 2.

### 7.4 Step 3: beacon probes

For each actor in `voter`, `batcher` and `resolver`, render `prompts/instrument.md`, a
blank line, then `prompts/instrument-beacons.md`. Placeholders: `BASE`, `PLAN`, `CHECK`,
`ACTOR`, `ACTOR_DIR` (`consensus/src/simplex/actors/<actor>`). Run and log as in section
7.3, with `beacons-<actor>` as the file stem.

### 7.5 Step 4: finalize the plan and check scope

1. Parse `plan.md`: headings `### <ID>: <title>` and lines `- Status: bound|partial|unbound`.
2. For every registry ID without a heading, append a section with `Status: unbound` and
   `Notes: not processed by the agent`.
3. Take a new snapshot (section 7.2) and compare it with the baseline. Every path that is
   new, changed or gone since the baseline:
   - outside `consensus/src/simplex/` aborts the campaign with exit code 2
     ("instrumentation edited <path>"), except `Cargo.lock`, which the first build
     updates for the new `sancov` dependency;
   - under `consensus/src/simplex/mocks/` or `consensus/src/simplex/scheme/` produces a
     warning.
4. Count the deleted lines under `consensus/src/simplex/` (`git diff --numstat`), the
   added `sl_assert!`, `sl_implies!` and `sl_probe!` call sites, and the beacon table
   rows.
5. Append a `## Summary` section to the plan with the status counts, call-site counts,
   beacon count and deleted-line count. Deleted lines are expected to be 0; any other
   value must match the "Edited lines" entries of the plan.
6. Write `SL/campaign/instrumentation.diff` with the output of `git diff`.

### 7.6 Step 5: build and repair

Commands, run in order:

1. `CHECK`: `cargo +<test toolchain> check -p commonware-consensus --lib --tests`
2. `FUZZBUILD`: `cargo +<fuzz toolchain> fuzz build --fuzz-dir consensus/fuzz/simplex simplex_statelens`

The fuzz toolchain is `STATELENS_FUZZ_TOOLCHAIN`, or the value of `NIGHTLY_VERSION:` in
`.github/workflows/slow.yml`, or `nightly`.

On a failure, run a repair attempt: render `prompts/instrument.md`, a blank line, then
`prompts/repair.md`. Placeholders: `BASE`, `PLAN`, `CHECK`, `ATTEMPT`, `COMMAND` (the
failing command), `ERRORS` (its last 150 output lines). Run the agent, repeat the
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
gate is 240 tests and took 125 s on 16 cores at the verified commit.

### 7.8 Step 7: fuzz

In `consensus/fuzz`:

~~~
NIGHTLY_VERSION=<fuzz toolchain> just run simplex_statelens -- \
  -rss_limit_mb=4000 -print_final_stats=1 <LIBFUZZER_ARGS>
~~~

- Tee the output to `SL/campaign/logs/fuzz.log`.
- While the fuzzer runs, the script ignores `SIGINT`. The fuzzer receives Ctrl-C itself
  and exits, and then the script writes the summary.
- Any new file in `consensus/fuzz/simplex/artifacts/simplex_statelens/` means a crash:
  result `PANIC (fuzz)`, exit code 5. Otherwise the result is `NO PANIC`, exit code 0.
- The operator MAY pass `-fork=<N>` among `LIBFUZZER_ARGS` to use N cores. libFuzzer's
  fork mode also stops at the first crash.

### 7.9 Result reporting

`SL/campaign/summary.txt` and the console end with these lines (omit those that do not
apply):

~~~
statelens: checkout   <repo>
statelens: base       <base>
statelens: agent      <agent>
statelens: invariants <n> (bound <b>, partial <p>, unbound <u>)
statelens: sites      <k> assertion sites, <m> probe sites, <d> deleted lines
statelens: result     NO PANIC | PANIC (tests) | PANIC (fuzz) | BUILD FAILED | SETUP FAILED
statelens: panic      <first [statelens][...] line, or the first panic message>
statelens: artifact   consensus/fuzz/simplex/artifacts/simplex_statelens/<file>
statelens: replay     cd <repo>/consensus/fuzz && CONSENSUS_FUZZ_LOG=1 just run simplex_statelens simplex/artifacts/simplex_statelens/<file>
~~~

### 7.10 Investigation

The instrumented checkout stays as it is until the operator discards it. The operator
uses:

- `SL/campaign/plan.md`: how each invariant was bound;
- `SL/campaign/instrumentation.diff` (or `git diff`): every change the campaign made;
- `SL/campaign/logs/` and `SL/campaign/prompts/`;
- the replay line from the summary. Replay reproduces the panic in the same checkout
  (R-NF-2).

To locate the code for an invariant: `rg '\[statelens\] INV-0007' consensus/src`.

An instrumented checkout must not be committed or reused; the next campaign starts from a
fresh clone.

---

## 8. Runtime support: `statelens.rs`

The full source is in Appendix A. This section specifies its behavior.

### 8.1 Byzantine guard

| Item | Behavior |
|---|---|
| `set_compromised(indices)` | Replaces the compromised set with `indices` (participant indices). Called by the runner hook. |
| `clear_compromised()` | Empties the set. |
| `is_byzantine(me)` | `true` if `me` is `Some(p)` and `p` is in the set. `None` is never compromised. |
| `should_check(me)` | `true` for honest replicas. For compromised replicas it follows `STATELENS_BYZANTINE`: `false` for `skip` (default), `true` for `check`, and a panic with `[statelens][BYZANTINE]` for `panic`. Any other value panics with the list of allowed values. |

The set is thread-local. This is sound because the deterministic runtime runs every task
on the thread that calls `Runner::start`, and because nextest runs each test in its own
process.

### 8.2 Macros

All three evaluate `me` first and do nothing else when `should_check(me)` is `false`.

| Macro | Behavior |
|---|---|
| `sl_probe!(me, "label", a, b)` | Records `(site, a, b)`. `a` and `b` convert with `Into<u32>`, so `bool`, `u8`, `u16` and `u32` are accepted and `u64` values fail to compile. The site hash covers the label, file, line and column of the call. |
| `sl_assert!(me, "ID", cond, fmt...)` | Panics through `violation` when `cond` is false. |
| `sl_implies!(me, "ID", pre, post, fmt...)` | Records `(site, pre, post)`. Evaluates `post` only when `pre` holds. Panics when `pre && !post`. |

The panic message is `[statelens][<ID>] replica=<index|none> <message>`. The reported
location is the macro call site (`#[track_caller]`).

### 8.3 Counter table

- `sancov::Counters<65536>` in a static.
- `record` sets `cell(site, a, b)` to 1 with an atomic store (presence, D3).
- `reset()` zeroes the table, clears the compromised set and all ghost state. In a
  `cfg(fuzzing)` build it registers the table with libFuzzer once, unless
  `STATELENS_FEEDBACK=0`.
- Once the table is registered, libFuzzer stops printing `cov:` because the table has no
  PC table. Compare runs by `ft:`.

### 8.4 Ghost state

- `Ghost`: one per replica, keyed by participant index. The voter, batcher and resolver of
  a replica share it, and in engine-level tests it survives restarts of that replica.
- `Global`: one per run, shared by all honest replicas.
- `with_ghost(me, f)` and `with_global(me, f)` return `None` without calling `f` for a
  guarded replica; `with_ghost` also does so when `me` is `None`. The closures MUST NOT
  nest.
- Instrumentation adds `pub` fields with `Default` types to `Ghost` and `Global`, each
  marked `// [statelens] ghost:<ID>`.

### 8.5 Discretization helpers and switches

| Helper | Result |
|---|---|
| `bucket(n)` | 0, 1, 2, 3-4, 5-8, 9+ map to 0..=5 |
| `delta(a, b)` | `bucket(a - b)` when `a >= b`, else `5 + bucket(b - a)` (6..=10) |
| `flag(b)` | 0 or 1 |
| `pack(high, low)` | `(high << 16) \| (low & 0xffff)` |
| `disc(&value)` | Stable code of an enum variant, payload ignored |

| Switch | Default | Effect |
|---|---|---|
| `STATELENS_BYZANTINE` | `skip` | What instrumentation does for a compromised replica: `skip` ignores it (the guard), `check` checks it like an honest replica, `panic` panics at the first instrumented site it reaches (AC-6). |
| `STATELENS_FEEDBACK` | on | `0` leaves the table unregistered. |

---

## 9. Instrumentation conventions

The prompts in section 12.7 are normative for the agent. In summary:

| Topic | Rule |
|---|---|
| Editable code | Non-test code in `consensus/src/simplex/`, except `mocks/` and `scheme/`. New-field initializers may be added to struct literals anywhere, including tests. In `statelens.rs`, only `Ghost` and `Global` fields and private helpers. |
| Additions only | No deleted or changed logic. The only allowed edit of an existing line is wrapping an expression in a block, keeping its tokens; each such edit is listed in the plan. |
| Markers | `// [statelens] <tag>` above every added statement, block, field or item. Tags: `INV-NNNN`, `ghost:INV-NNNN`, `beacon:<label>`, `me`. |
| Replica index | `self.scheme.me()`; otherwise a `// [statelens] me` field of type `Option<Participant>`. |
| Side effects | None: no `await`, spawn, lock, runtime context, RNG, clock, network, storage, metrics or logging; no reordering or consuming of values. |
| Panics | Only through violations: saturating or checked arithmetic, no `unwrap` or `expect`, no out-of-bounds indexing. |
| Cost | O(1) per site, or bounded by the number of tracked views. |
| Warnings | Denied workspace-wide. Use full paths rather than new imports. |
| Discretization | No raw views, digests, keys, payloads or timestamps. Views relative to another known view. At most about 64 `(a, b)` pairs per probe. No replica index in probe values. |
| Adversarial input | Assert what the honest replica does or keeps, not what peers send. |
| Asynchrony | Cross-actor checks hold for every delivery delay the implementation allows. |

---

## 10. Instrumentation plan format

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

The script adds the `## Summary` section (section 7.5).

---

## 11. Agent invocation

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
  campaigns run on a dedicated machine or container.
- The script checks that the chosen CLI is on `PATH` before any other work.

---

## 12. Prompts (verbatim)

### 12.1 `prompts/analyst.md`

~~~markdown
# StateLens analyst: extract invariants

You are a senior security engineer who specializes in Byzantine fault tolerant
consensus. Read the sources listed at the end and write invariants for the StateLens
registry of the Simplex consensus implementation in this repository.

## Context

- `consensus/src/simplex` implements a modified Simplex consensus protocol. Leaders
  propose blocks for views. Replicas vote to notarize a proposal, to nullify a view
  (skip it), or to finalize a notarized proposal, and a quorum of votes of one kind
  forms a certificate (notarization, nullification, finalization). Each replica runs
  three actors: the voter (the view state machine), the batcher (vote collection and
  verification) and the resolver (fetching missing certificates). Replicas persist
  their votes in a journal and recover from it after a crash. The module docs in
  `consensus/src/simplex/mod.rs` describe the protocol; read them when a source leaves
  a concept unclear.
- Every file in `consensus/fuzz/statelens/invariants/` is used by the next fuzzing
  campaign. An agent turns each invariant into assertions inside honest replicas, and a
  fuzzer runs honest replicas next to Byzantine ones (equivocating, mutating messages,
  splitting the network) until an assertion fails. A wrong invariant costs a human
  investigation. A vague one cannot be checked.

## What makes a good invariant

- It holds in every execution for an honest replica, or, with scope `protocol`, for all
  honest replicas together. That includes executions with Byzantine replicas up to the
  fault threshold, arbitrary message delay, reordering and loss, timeouts, and crashes
  followed by journal recovery.
- It constrains what an honest replica does or keeps: votes it signs, messages it sends,
  certificates it accepts, state it persists, views it enters. It never requires a
  Byzantine replica to behave.
- It uses protocol terms (views, leaders, proposals, parents, votes, certificates,
  timeouts, the finalized tip, the journal). It never names Rust types, functions,
  fields or files; those go in "Observation hints".
- It is precise enough to decide, at any moment of an execution, whether it has been
  violated. Do not write "eventually" properties.
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

- Write one file per invariant: `consensus/fuzz/statelens/invariants/<ID>.md`.
- Use IDs starting at `{{NEXT_ID}}` and increasing by one with no gaps.
- Follow the template below exactly: the same front matter keys and section headings,
  in the same order. Delete optional sections you do not use.
- Set `source_kind: {{KIND}}` and `author: {{AUTHOR}}`. Make `source_ref` as precise as
  you can: URL, `path:line`, document section, or paper page.
- Plain ASCII only. Wrap lines at 100 characters.
- Do not modify or delete existing files, create other files, or write code.

When you finish, reply with a list of the files you wrote (ID, title, one line of
evidence), or with the reason you wrote none.

## Template

```markdown
{{TEMPLATE}}
```

## Example

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

## Sources

Kind: `{{KIND}}`

{{SOURCES}}
~~~

### 12.2 `prompts/analyst-issue.md`

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
- For a liveness bug, write the safety condition whose violation caused it, when one
  exists (for example "the replica shall not discard a certificate for a view above
  its finalized tip"). Do not write "eventually" properties.
- In Evidence, describe the violating scenario in two to five sentences and cite the
  issue, the pull request and the fixing commit.
- Write nothing for issues that are not about Simplex behavior (documentation, CI,
  build, performance tuning, other crates).
~~~

### 12.3 `prompts/analyst-design.md`

~~~markdown
## How to read a design document

- Read the listed documents: local paths, or URLs through your web fetch tool or
  `curl`. A `#section` suffix names the part to focus on; read the rest for context.
- Extract every rule the document states or implies an honest replica follows: voting
  rules, conditions for entering a view, timeout and nullification rules, certificate
  validity and use, parent and ancestry rules, persistence and recovery guarantees, and
  bounds on tracked state.
- Also extract the properties the design relies on in its safety argument.
- In source_ref give the document and the section heading. In Evidence quote or
  closely paraphrase the relevant sentence.
~~~

### 12.4 `prompts/analyst-comment.md`

~~~markdown
## How to read code comments

- The sources are files or directories under `consensus/src/simplex`, optionally with
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

### 12.5 `prompts/analyst-spec.md`

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

### 12.6 `prompts/analyst-paper.md`

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

### 12.7 `prompts/instrument.md`

~~~markdown
# StateLens instrumenter

You are instrumenting the Simplex consensus implementation for a StateLens fuzzing
campaign. Your changes turn English invariants into runtime assertions, and add state
probes that tell the fuzzer when an execution reached a new internal state.

## Where you are

- This checkout is a throwaway clone at commit `{{BASE}}`, instrumented in place for one
  fuzzing campaign. Nobody will review, merge or reuse your changes. The repository conventions in AGENTS.md and CLAUDE.md about public API
  stability, documentation, benchmarks, dependencies, commits and pull requests do not
  apply here. The rules in this prompt take precedence.
- Do not commit. Do not run the tests or the fuzzer; the campaign runs them after you.
  Do run the check command at the end of this prompt until it passes.
- Read `consensus/src/simplex/statelens.rs` first. It is the runtime support module.
- A fuzzer will run honest replicas next to Byzantine ones. Any panic you cause is
  reported to a human as a possible bug, so a false alarm wastes their time and a
  missed check hides a bug.

## Scope

- You may edit non-test code in `consensus/src/simplex/`, except `mocks/` and
  `scheme/`. Non-test code is code outside `#[cfg(test)]` items and `tests` modules.
  You may add initializers for new fields to struct literals anywhere, including tests,
  when the compiler requires them.
- In `statelens.rs` you may only add fields to `Ghost` and `Global`, and private helper
  functions.
- Do not edit anything else: no `Cargo.toml`, nothing under `consensus/fuzz/`, no
  other crate.

## Rules

1. Add, never remove. Do not delete or change existing logic. The only allowed change
   to an existing line is wrapping an existing expression in a block so that
   instrumentation can run next to it, keeping the original tokens (for example
   `A => f(),` becomes `A => { <instrumentation>; f() }`). List every such edit in the
   plan under "Edited lines".
2. Mark everything you add with a comment line `// [statelens] <tag>` directly above
   it. Tags: `INV-NNNN` for assertions and invariant probes, `ghost:INV-NNNN` for ghost
   fields and their updates, `beacon:<label>` for beacon probes, and `me` for code added
   only to make the replica index available.
3. Observe only honest replicas. The macros, `with_ghost` and `with_global` apply the
   Byzantine guard themselves. Always pass the replica's own index as `me`:
   `self.scheme.me()` wherever a scheme is in scope (the voter, batcher and resolver
   all hold one). Where it is not, add a `// [statelens] me` field of type
   `Option<crate::simplex::statelens::Participant>`, set where the struct is created.
   Never hard-code or guess an index.
4. No side effects on the protocol. Instrumentation must not `await`, spawn tasks, take
   locks, or use the runtime context, RNG, clock, network, storage, metrics or logging.
   It must not send or reorder messages, and must not move or consume values the
   original code uses later; clone small values if you need them after a move.
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
9. Actors run concurrently and exchange messages through mailboxes. A check that
   compares the voter, batcher and resolver of one replica must hold for every delivery
   delay the implementation allows, not only when the actors are in step.

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
  shared by its voter, batcher and resolver. `with_global(me, |g: &mut Global| ...)`
  gives one `Global` shared by all honest replicas, for `protocol` invariants. Both
  return `None` without running the closure for a skipped replica. Never nest them. Add
  the fields you need to `Ghost` or `Global`, with `Default` types.
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

### 12.8 `prompts/instrument-invariants.md`

~~~markdown
## Task: bind invariants {{INVARIANT_IDS}}

For each invariant below:

1. Read the Statement (EARS). Identify the trigger or state (`pre`) and the required
   response (`post`), or the single condition of a ubiquitous statement. Treat
   "Preconditions / assumptions" as part of `pre`. Treat "Observation hints" as leads,
   not as facts.
2. Find where the implementation establishes and uses the concepts. Trace with search,
   references and call hierarchy across the voter, batcher and resolver, including the
   mailbox messages between them and the journal replay path on restart.
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

Invariants:

{{INVARIANTS}}
~~~

### 12.9 `prompts/instrument-beacons.md`

~~~markdown
## Task: beacon probes for the {{ACTOR}} actor (`{{ACTOR_DIR}}`)

Add state probes that let the fuzzer tell apart executions that run the same code in
different internal states. Do not add assertions in this task.

1. Inventory the semantic beacons in the non-test code of `{{ACTOR_DIR}}` and the types
   it owns: enums that describe states, modes, reasons or outcomes; boolean and
   `Option` fields of per-view or per-round state; the conditions of `debug_assert!`,
   `assert!`, `expect("...")` and `unreachable!`; comments about orderings, races,
   recovery, or cases that "cannot happen".
2. For each beacon, find the transition sites (where the state is set or changed) and
   the decision sites (where it is read to choose what to do).
3. Choose probes in this order of priority:
   - transitions caused by side effects or asynchrony: the view advances while work is
     outstanding, a timeout races a certificate, a verification or certification result
     arrives after the state moved on, equivocation is detected after acceptance, state
     is rebuilt from the journal;
   - conditions set in one actor and used in another through mailbox messages;
   - state combinations that comments or assertions call out as fragile.
4. Probe shape: `sl_probe!(me, "{{ACTOR}}.<beacon>.<event>", a, b)`, with `(a, b)` the
   state before and after a transition, or the state and its context at a decision
   point. Use `disc` for enums, `flag` for booleans and options, `delta` and `bucket`
   for views and counts, and `pack` to put two small values on one side.
5. Budget: 20 to 60 probes for this actor. Avoid per-message hot loops unless the state
   there is interesting.
6. Add one row per probe to the "Beacon probes" table of the plan.
~~~

### 12.10 `prompts/repair.md`

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

---

## 13. Acceptance procedures

| AC | Procedure | Pass condition |
|---|---|---|
| AC-1 | For each agent: `just extract issue <URL of a real Simplex bug>`. | At least one new `invariants/INV-*.md`; `just check-invariants` reports no problem for it. |
| AC-2 | On `main` with the subproject committed: `git ls-files consensus/fuzz/statelens` contains no `Cargo.toml`; `just check-fmt`; `just lint`; `just test -p commonware-consensus`; the CI fuzz target listing for `consensus/fuzz/simplex`. | All behave exactly as without the subproject. |
| AC-3 | With at least one invariant: `just campaign`. | Materialize, instrument, plan, build and test gate complete, and the fuzzer starts. |
| AC-4 | In an instrumented checkout, two 10-minute runs on empty corpora: `STATELENS_FEEDBACK=0 just run simplex_statelens <empty dir A> -- -max_total_time=600` and the same without the variable on `<empty dir B>`. | The `ft:` value on the `DONE` line is higher with feedback. Compare `ft:`, not `cov:` (section 8.3). |
| AC-5 | `STATELENS_FALSE_INVARIANTS=1 just campaign`. | Result `PANIC (tests)` or `PANIC (fuzz)` with `[statelens][FALSE-0001]`. |
| AC-6 | In an instrumented checkout: `STATELENS_BYZANTINE=panic just run simplex_statelens -- -max_total_time=120`, then the same without the variable. | The first run panics with `[statelens][BYZANTINE]`; the second does not; `[statelens] participant index mismatch` never appears. Verified at the reference commit (section 1.2). |
| AC-7 | `just run simplex_statelens <artifact>` in the checkout of a crashing campaign. | The same `[statelens][...]` line as in the campaign. Verified for `BYZANTINE` (section 1.2). |
| R-NF-3 | Same duration and flags: `simplex_statelens` in an instrumented checkout, and `simplex_cert_mock_twins_mutator` in an uninstrumented checkout at the same commit. | exec/s from `-print_final_stats=1` are reported side by side; a slowdown above 2x is recorded as an instrumentation problem. |

---

## 14. Implementation order

1. Create the layout of section 3 with the verbatim files: `config.env`, `justfile`,
   `templates/invariant.md`, all prompts (section 12), `false-invariants/FALSE-0001.md`
   (Appendix C), `runtime/statelens.rs` (Appendix A) and `runtime/target.rs`
   (Appendix B.1). Create `invariants/` with a `.gitkeep` file.
2. Check the runtime templates:
   `rustfmt +<pinned nightly> --edition 2024 --config-path rustfmt.toml --check consensus/fuzz/statelens/runtime/*.rs`.
3. Implement `scripts/statelens.py` in this order: config and argument parsing, `lint`,
   prompt rendering, agent invocation, `extract`, then `campaign`, starting with the
   materialize step and `--stop-after materialize`.
4. Write `README.md` (Appendix D).
5. Validate: `just check-invariants false-invariants/FALSE-0001.md`;
   `STATELENS_FALSE_INVARIANTS=1 just campaign --stop-after build`; then AC-1 to AC-7.
6. Change nothing outside `consensus/fuzz/statelens/`.

---

## 15. Known limitations

- Throughput is about 13 executions per second per process, so a campaign needs many
  core-hours. Use `-fork=<N>`.
- The patch anchors in section 7.2 follow the code. When one moves, the campaign stops
  with exit code 2 and the anchor in `statelens.py` must be updated.
- Agents are not deterministic: the same invariant can be bound differently in two
  campaigns. The plan and `instrumentation.diff` document each binding.
- A campaign instruments the checkout in place, so every campaign needs a fresh clone.
  The script refuses a checkout that an earlier campaign instrumented.
- Replicas without a participant index (`me() == None`) have no per-replica ghost
  state, so ghost-based checks skip them.
- The Twins tests are not part of the test gate (D2). The fuzz harness itself exercises
  Twins scenarios with the correct guard.
- The runtime module relies on the deterministic runtime running tasks on the calling
  thread (`Runner::start` calls `start_and_recover` on the same thread).

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
//!   replicas ([Global], [with_global]);
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
    GHOSTS.with(|ghosts| ghosts.borrow_mut().clear());
    GLOBAL.with(|global| *global.borrow_mut() = Global::default());
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

---

## Appendix C: `false-invariants/FALSE-0001.md` (verbatim)

~~~markdown
---
id: FALSE-0001
title: Deliberately false, never accept a nullification
source_kind: human
source_ref: consensus/fuzz/statelens/SPEC.md (acceptance procedure AC-5)
scope: [replica, voter]
author: statelens
---

## Statement
The replica shall not accept a nullification certificate for any view.

## Rationale
Deliberately false. Nullifications are part of normal operation, for example when a
leader is slow or offline. A campaign that includes this invariant must panic with
[statelens][FALSE-0001], which shows that invariants are bound, checked and reported.

## Evidence
Workflow test, see SPEC.md section 13.
~~~

---

## Appendix D: `README.md` outline

1. What StateLens is, in three sentences, with links to PRD.md and SPEC.md.
2. How to run a campaign safely: campaigns give the agent full control of the machine
   (D4) and instrument the checkout in place (D10). Clone the repository fresh on a
   dedicated machine or container, run the campaign in that clone, and discard the clone
   afterwards. Never commit an instrumented checkout.
3. Prerequisites (section 5.2) and `config.env`.
4. Phase 1: `just extract <kind> <source>...` with one example per kind, then review:
   every file in `invariants/` is used by the next campaign; edit or delete drafts;
   `just check-invariants`.
5. Phase 2: `just campaign`, `STATELENS_AGENT=codex just campaign`, passing libFuzzer
   arguments (`python3 scripts/statelens.py campaign -- -fork=8`), `--stop-after`.
6. Results: the summary lines, exit codes, and `campaign/` (plan, diff, logs, prompts).
7. Investigating a panic (section 7.10).
8. Testing the workflow itself: `STATELENS_FALSE_INVARIANTS=1` (the campaign must panic on
   the deliberately false invariants), `STATELENS_BYZANTINE=panic` (guard test) and
   `STATELENS_FEEDBACK=0` (feedback comparison).
