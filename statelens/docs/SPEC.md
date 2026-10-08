# StateLens: Technical Specification

| | |
|---|---|
| Implements | [PRD.md](PRD.md) |
| Audience | The coding agent that implements `statelens/`, and fuzz operators |
| Verified against | commits `7cb6a3d583` and `2e56fa856e` (see section 1.2); marshal at commit `2649e4a668` (see section 8.1); qmdb at commit `290cdcf4c4` (see section 17.1); Target-State Synthesis at commit `37e01e1036` (see section 18.1) |

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
- `SL` is `statelens/`.
- Text marked "verbatim" MUST be copied exactly. Everything else describes behavior
  and leaves the implementation free.

### 1.2 What was verified

The following were built and exercised in a scratch checkout of the commit above:

- `runtime/statelens.rs` (Appendix A): its 10 unit tests of the time pass inside
  `commonware-consensus` (19 now, with those of `provider_me` and the read side, section 18.1)
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

Section 8.1 lists what was checked for marshal, at commit `2649e4a668`, section 17.1
what was checked for qmdb, at commit `290cdcf4c4`, and section 18.1 what was checked for
Target-State Synthesis, at commit `37e01e1036`.

`provider_me` (Appendix A, D27) was checked at commit `58d8c738e4` in a scratch checkout
materialized for the `marshal` profile: the runtime's 12 unit tests pass, among them one
showing that a provider other than `ConstantProvider` is not looked up at all, and a call
from `core::Actor::init`, the coding adapter and the shards engine compiles. The A/B that
motivated it ran at the same commit: a test that uses `RetiringProvider` passes, and fails
with only a creation-time provider lookup added to `Actor::init`.

Deriving a variant from every simplex target (D57) was checked at commit `3c7187e1d1`, in
scratch worktrees the script materialized for the `simplex` profile, without an agent. The
materialize step wrote the 21 variants and the four hooks of Appendix B.5, and the fuzz
package, variants included, checks with no error or warning. Six variants were built with
cargo-fuzz, and one temporary probe at the start of the batcher gave the guard a site:

- In the default mode, the ByzzFuzz, Chaos-Twins, audit and Mallory variants ran for one to
  two minutes each (2,573, 588, 515 and 1,198 inputs) with no panic and no participant
  index mismatch.
- With `STATELENS_BYZANTINE=panic`, the ByzzFuzz and Chaos-Twins variants panicked with
  `[statelens][BYZANTINE]` on their first input. The audit variant did so after 179 inputs
  once `-len_control=0` made inputs long enough to draw the RejectView choice; it drew none
  in 459 short ones. The Mallory variant did so after 86 inputs, and a replay of that input
  logs `amnesia_restart(node=0)` before the panic.
- In the same mode, the Standard and Chaos variants ran 503 and 127 inputs without it.

`kb search` (section 5.10) was exercised on this checkout at commit `7b5ab24d1f10`, without an
agent: a first build, an update with nothing changed, and queries about Simplex
certification, qmdb batches, findings and design documents, each with relevant hits. After a
review on 2026-10-06, no chunk of the rebuilt index exceeds the model's window by its
tokenizer, every chunk of the files that test-only declarations name is test code, and an
update interrupted before its manifest switch leaves the previous generation intact. Two
refreshes run at once, with a query between them, left one current and consistent
generation. The script tests of section 5.9 cover chunking, test code, updates,
interruption, overlapping refreshes and scope. No campaign has run with the search index
yet.

The knowledge base and the audit pass were first exercised with a real agent on 2026-10-05,
at commit `86eed8302c`, with Claude:

- A `kb` extraction (section 6, prompt 13.19) read the qmdb findings through the `kb`
  commands of section 5.6 and wrote the ten local invariants INV-0034 to INV-0043.
- A `qmdb` campaign then bound them. Its six beacon runs had the `kb` commands (section 7.4,
  prompt 13.9), and 17 of the 170 rows of its beacon table name a finding. Its two audit
  batches (steps 6 and 7 of section 7.3, prompt 13.15) added 18 checks and changed no
  status. The plan lint of section 7.5 step 3 and the `plan` line of section 7.9 reported no
  problem, and the targets built without a repair.
- Its test gate ran 2,289 tests. One failed for lack of file descriptors, with no
  `[statelens]` line, and fails the same way without instrumentation (section 17.6), so the
  campaign ended `PANIC (tests)` rather than `READY`.

The audit pass was added after a review of a `simplex` campaign found a binding labelled
`bound` whose action is committed in a handler the instrumentation never observed (section
11, D48). The `lint-plan` and `lint-prompts` commands of section 5.4 are also covered by the
script tests of section 5.9, as is the invariant selection of section 7.1 step 4 (D69), which
no campaign with a real agent has exercised yet.

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
| D5 | StateLens fuzz targets are added during a campaign to the existing `consensus/fuzz/simplex` package; no new package is created, and `just run <variant>` runs one like any other target. Each is derived from an existing target of that package rather than written, so there is no hand-written target to keep in step with the one it imitates, and it inherits its original's driver and `required-features`. | G4, R-S-P2-1 step 1 |
| D6 | The macros are `macro_rules!` items re-exported with `pub(crate) use` and invoked by path: `crate::simplex::statelens::sl_implies!(...)`, or `crate::qmdb::statelens::sl_implies!(...)` in the qmdb copy. `#[macro_export]` cannot work: `simplex` and `qmdb` are declared inside `stability_scope!`, and macro-expanded `macro_export` macros cannot be called by absolute path from their own crate. | R-INS-4 |
| D7 | The Byzantine guard is built into the macros and into the ghost accessors, so no call site can forget it. The fuzz target calls `clear_compromised()` after `fuzz()` returns, not inside the runner, so compromised replicas stay guarded while the runtime shuts down. | R-INS-2, PRD section 8.4 |
| D8 | The runner hook also asserts that every scheme's own index equals its position in the participant list. | PRD section 8.4, AC-7 |
| D9 | `protocol`-scope invariants use a guarded ghost store shared by all honest replicas (`Global`, `with_global`). | R-INS-5 |
| D10 | A campaign runs in place in the operator's checkout, a fresh clone of the repository; StateLens never makes another clone. The campaign refuses a checkout with tracked changes outside `SL/` or with instrumentation from an earlier campaign, never commits, and records its changes in `SL/campaign/instrumentation.diff`. Uncommitted registry edits are used. | R-P2-1 |
| D11 | Tests use the `stable` toolchain; fuzz builds use the nightly pinned in `.github/workflows/slow.yml`. | R-P2-2 step 5 |
| D12 | Orchestration is one Python 3 script, `SL/scripts/statelens.py` (standard library only), wrapped by `SL/justfile`. | R-LAYOUT-1, R-AG-1 |
| D13 | No `Cargo.toml` the workspace builds is committed under `SL/`. The one exception is the test-only crate `SL/differential/` (section 18.10.1, AC-25): its manifest carries an empty `[workspace]` table, so cargo's upward search stops there and the root workspace never lists or builds it, no CI job names it, and only `SL/scripts/differential.sh` builds it, in a scratch worktree. Every `*.rs` file under `SL/`, the runtime templates and the test crate included, MUST stay `rustfmt`-clean, because CI's `just check-fmt` formats every `*.rs` file in the tree. | R-LAYOUT-2, R-NF-4 |
| D14 | Prompt files are named `analyst-<kind>.md`, one per source kind (`issue`, `design`, `comment`, `spec`, `paper`), plus a shared `analyst.md`. Target-state extraction is the exception: one prompt, `state-analyst.md`, serves every kind (D60). | R-LAYOUT-1, R-P1-2 |
| D15 | StateLens fuzz targets use only the `cert_mock` certificate scheme (`consensus/src/simplex/mocks/scheme.rs`, imported as `cert_mock` in `consensus/fuzz/core`). Every call of a fuzz entry point in a simplex target, `fuzz::<P, ...>` or one of the `fuzz_*::<P, ...>` audit entry points, names a `P` whose `impl Simplex` in `consensus/fuzz/core/src/simplex.rs` sets `type Scheme = cert_mock::Scheme<...>`. At the reference commit these are `SimplexCertificateMock`, `SimplexCertificateMockAttributable`, `SimplexCertificateMockCustomRoundRobin` and `SimplexCertificateMockByzantineFirstLeader`; the simplex targets name `SimplexCertificateMock`, `SimplexCertificateMockByzantineFirstLeader` and `SimplexCertificateMockCustomRoundRobin`. No ed25519, BLS12-381 or secp256r1 scheme is used. The materialize step enforces this (section 7.2). The test gate is not affected. | R-P2-4 |
| D16 | Ghost state lives for one run. The campaign patches the deterministic runtime so that `Runner::new` calls a hook that clears it; independent runs in one test thread (for example the seeds of one test) no longer share history, while a crash-restart from a checkpoint keeps it (Appendix B.4). | R-INS-5, PRD section 8.4 |
| D17 | Registries are directories per subsystem: `invariants/simplex/`, `invariants/marshal/` and `invariants/qmdb/`, and likewise for false invariants. No invariant file lies directly under `invariants/` or `false-invariants/`. | R-REG-1, R-REG-8 |
| D18 | Each ID prefix has one global counter across all registries, so the marshal false invariant is FALSE-0002 and the qmdb one FALSE-0003. The lint rejects an ID that two files use. | R-REG-1, R-REG-8, R-M-REG-2 |
| D19 | Scope vocabularies are per registry (section 4.2). | R-REG-2 |
| D20 | Profiles are data in `statelens.py` (section 5.5). `--profile` defaults to `simplex`. | R-P2-1 |
| D21 | Both consensus subsystems use the runtime module at `consensus/src/simplex/statelens.rs` (Appendix A), and marshal code calls it as `crate::simplex::statelens::...`. The qmdb profile puts its own copy in the storage crate (D50). | G8 |
| D22 | The per-subsystem parts of the prompts live in `prompts/subsystems/` (sections 13.11 to 13.14, 13.17 and 13.18), and the shared prompts take them through placeholders. What differs between profiles in the shared prompts, the runtime module and the fuzz package, is a placeholder too (section 7.3). | R-P1-2 |
| D23 | A campaign does not run the fuzzer, in any profile. It ends after the test gate with the result `READY`, and prints, for each StateLens target, the command that runs it and the command that replays a crash. The operator runs the targets with `just run`, and chooses which ones, for how long, and with which libFuzzer arguments. The campaign passes no arguments to libFuzzer. Exit codes 5 and 6 are retired. | R-P2-2 step 7, R-P2-3, R-P3-1 |
| D31 | Beacon discovery happens inside the campaign's beacon step, not as a separate phase with its own artifact. The knowledge base is private and an instrumented checkout is never pushed, so nothing has to cross a reviewed boundary between them. | R-FB-4 |
| D32 | The knowledge base stays outside this repository and is read-only. `STATELENS_KB` names its roots, and an empty value disables beacon extraction and `extract kb` without affecting anything else. | R-KB-1 to R-KB-3 |
| D33 | Retrieval is a structured index over the findings' claim fields plus full-text search of their prose sections, and, for `kb search`, a local vector index (D58). No vector database and no hosted embedding service. | R-KB-4, R-KB-9 |
| D37 | A finding's state and remediation status are shown to the instrumenter, not used to filter findings out. Weak evidence costs coverage, not correctness. | R-KB-8 |
| D42 | The beacon step is an agent loop over actions (read code, the six `kb` queries, add a probe), not a fixed procedure. Reading code leads, and a query is what the agent does when its hypothesis needs developer context. How long to spend on a candidate is the agent's judgment; there is no step budget. | R-FB-4 |
| D43 | Entities are identified from a SCIP index built once before instrumentation, not from a language server queried during it, and startup is paid for one campaign rather than one query. Instrumentation moves the lines the index names, so the build snapshots the sources it indexed and each query rebases its hits through a diff instead of rebuilding: a diff of a file of this crate's median size costs a few milliseconds, against about eight minutes for an index. | R-AG-4 |
| D44 | The SCIP protobuf is decoded with the standard library, not a protobuf package, so the subproject keeps its stdlib-only rule. Only the five fields the four queries need are read. | R-AG-4, R-LAYOUT-2 |
| D45 | Sites in test code are hidden unless asked for. Nearly three quarters of the crate is test code sharing files with the code it exercises, so the unfiltered answer is mostly noise. | R-AG-4 |
| D46 | Read and write polarity comes from the syntax tree, not from a language server. The tree needs no project and costs a tenth of a second for a file, against a server's startup on every query, and it classifies a struct literal field as an initial value where the server calls it a read. | R-AG-5 |
| D47 | A name inside a macro body is reported as `macro`, not silently dropped and not guessed. Parsing does not expand macros, so the body is an unstructured token tree; dropping such sites would hide much of this crate's concurrency, which lives inside `select!`. | R-AG-5 |
| D55 | Invariants derived from knowledge-base findings (`extract kb`) are written to a local registry, `SL/invariants.local/<subsystem>/`, which git ignores and campaigns bind like the tracked one. A finding is private and the repository is public, so nothing derived from one is committed (R-KB-6); an operator who wants such an invariant shared rewrites it without the finding's detail and moves it by hand. IDs stay global across both. | R-KB-6, R-P1-7 |
| D56 | `extract --number N` bounds an extraction: the prompt asks for the N invariants the sources justify best and allows fewer, never more, and the script reports more than N as a problem. A quota would make the agent invent invariants to reach it. | R-P1-7 |
| D57 | The simplex profile derives a variant from every `simplex_*` target, as the marshal and qmdb profiles do, rather than from a curated list. Every runner that runs a real engine under a Byzantine identity therefore publishes that identity: the Twins runner (edit 6), and the ByzzFuzz, Chaos-Twins, audited Standard and Mallory runners (edits 9 to 12, Appendix B.5). The other drivers run none: Standard and FaultyNet make their Byzantine nodes `Disrupter`s, Mallory's Byzantine roles are adversary actors, and Chaos has no Byzantine node. Mallory's Honest-role node becomes Byzantine only through an amnesia restart, which its hook publishes. | G4, G5, R-S-NF-2 |
| D58 | `kb search` fuses two rankings by reciprocal rank: BM25 over words and identifier parts, and the cosine similarity of embeddings from a small pretrained model run on the CPU, all-MiniLM-L6-v2 unless `STATELENS_SEARCH_MODEL` names another. A small model misses exact identifiers, which BM25 finds, and BM25 misses paraphrase, which the model finds. The vectors are one flat file of 32-bit floats searched by brute force, which answers in milliseconds at this size, so there is no vector database. The script still imports with the standard library alone: numpy and sentence-transformers are loaded only to embed, and without them the search ranks by words. The index reads the code and the documentation at HEAD through git, so a hit's `path:line@commit` holds in an instrumented checkout and instrumentation never enters the index. | R-KB-9 |
| D48 | The instrument step ends with an audit pass over its own bindings, after the beacon probes so that no agent edits the audited tree, by the same agent and under the same rules, and the plan carries a `Sites` ledger the pass and `lint-plan` both read. A first pass writes a binding and its own status in one go, and nothing there compares the two, so a binding that watches where an action is decided rather than where it is committed passes as `bound`. | R-INS-8, R-P2-2 |
| D69 | A campaign binds every invariant of its profile's registries unless `--invariants` names a subset. The selection filters the set section 7.1 step 4 collects, so the order, the local registry and the false invariants are as without it, an id must name an invariant the profile would have bound, and beacon probes are not selectable, because they are feedback and not oracles. `meta.json` records the ids bound and the number available, and `lint-plan` expects sections for the ids bound whenever its profile is the campaign's, named or not. | R-P2-1, R-P2-5 |

D24 to D30 concern marshal only; they are in section 8.2. D49 to D54 concern qmdb only; they
are in section 17.2. D59 to D68 concern Target-State Synthesis; they are in section 18.2.

---

## 3. Committed layout

```
statelens/
  docs/
    PRD.md
    SPEC.md
  README.md                      operator guide (Appendix D)
  config.env                     defaults (section 5.1)
  justfile                       recipes (section 5.3)
  .gitignore                     `campaign/`, `extract/`, `scripts/__pycache__/`, `config.local.env`, `invariants.local/` and `target-states.local/`
  config.local.env               machine-specific and private overrides, ignored by git (section 5.1)
  invariants.local/              invariants derived from the knowledge base, ignored by git (D55)
  invariants/                    the registries; every INV-*.md is active (section 4.1)
    simplex/
    marshal/                     the marshal invariants
    qmdb/                        the qmdb invariants; a `.gitkeep` while it is empty
  target-states/                 the target-state cards; every TS-*.md is active (section 18.3)
    simplex/                     TS-0003.md and TS-0004.md; a `.gitkeep` while it is empty
    marshal/                     TS-0001.md, the worked card of section 18.3, and TS-0002.md
  target-states.local/           cards from sources that are not public, ignored by git (section 18.4)
  false-invariants/
    simplex/FALSE-0001.md        deliberately false invariant for AC-6 (Appendix C)
    marshal/FALSE-0002.md        deliberately false invariant for AC-10 (Appendix E)
    qmdb/FALSE-0003.md           deliberately false invariant for AC-19 (Appendix G)
  examples/                      worked analyses the Phase 2 prompts point agents at
    statelens_commonware_voter_example.md     the Simplex voter (sections 13.8, 13.9)
    statelens_commonware_marshal_example.md   marshal's deferred verification path
  templates/
    invariant.md                 reference format (section 4.5)
    target-state.md              card format (section 18.3)
  prompts/
    analyst.md                   Phase 1, shared part (section 13.1)
    analyst-issue.md             Phase 1, per kind (sections 13.2 to 13.6)
    analyst-design.md
    analyst-comment.md
    analyst-spec.md
    analyst-paper.md
    analyst-kb.md                Phase 1, knowledge-base findings (section 13.19)
    instrument.md                Phase 2, shared rules and API (section 13.7)
    instrument-invariants.md     Phase 2, bind invariants (section 13.8)
    instrument-beacons.md        Phase 2, beacon probes (section 13.9)
    instrument-audit.md          Phase 2, audit the bindings (section 13.15)
    discover-flow.md             method for tracing state across functions (section 13.16)
    repair.md                    Phase 2, compile repair (section 13.10)
    state-analyst.md             Phase 1, target states (sections 18.4 and 13.20)
    synthesize.md                synthesis, shared rules (sections 18.7 and 13.21)
    subsystems/
      simplex-analyst.md         Phase 1, Simplex part (section 13.11)
      marshal-analyst.md         Phase 1, marshal part (section 13.12)
      simplex-instrument.md      Phase 2, Simplex rules (section 13.13)
      marshal-instrument.md      Phase 2, marshal rules (section 13.14)
      qmdb-analyst.md            Phase 1, qmdb part (section 13.17)
      qmdb-instrument.md         Phase 2, qmdb rules (section 13.18)
      simplex-synthesize.md      synthesis, Simplex part (sections 18.7 and 13.22)
      marshal-synthesize.md      synthesis, marshal part (sections 18.7 and 13.23)
  runtime/
    statelens.rs                 runtime support module of every profile (Appendix A)
    target_states.rs             scaffold helper, copied to `<package>/src/target_states/mod.rs` (Appendix H)
  differential/                  test-only crate of the differential test (section 18.10.1, AC-25); outside the workspace
    Cargo.toml                   package `statelens-differential`, with an empty `[workspace]` table
    README.md                    what the test compares, how to run it, its limitations
    cards/                       TS-9001.md to TS-9007.md, one card per History the test replays (section 18.3 grammar)
    shim/                        `statelens-differential-shim`: compiles `runtime/statelens.rs` and
                                 `runtime/target_states.rs` by `#[path]`, byte-identical
    src/                         setup.rs, record.rs, digest.rs, cards/tsNNNN.rs, tests.rs
  scripts/
    statelens.py                 lint, lint-examples, lint-plan, lint-prompts, extract,
                                 kb, code, ast, targets, campaign, test-gate, synthesize,
                                 reach-verdict, coverage, clean
                                 (sections 5 to 7 and 18)
    test_statelens.py            tests for the quiet failures (section 5.9)
    differential.sh              the differential test's procedure (section 18.10.1, AC-25)
```

Constraints on committed files:

- Plain ASCII only (R-NF-5).
- The worked analyses in `examples/` name real functions and fields, and the Phase 2 prompts
  point agents at them, so `just check-examples` checks that every code name they cite still
  exists in the instrumented subsystems. A name that is not code, such as a knowledge-base
  claim field, is declared in the document with a
  `<!-- statelens-lint: not-code: a, b -->` line.
- No `Cargo.toml` the workspace builds anywhere under `SL/` (R-LAYOUT-2). The one exception
  is `SL/differential/`, a test-only crate outside the workspace: its manifest has an empty
  `[workspace]` table, its shim is a member of that workspace as a path dependency under it,
  `cargo metadata` at the repository root lists neither package, no CI job names them, and
  `SL/scripts/differential.sh` builds them only in a scratch worktree (section 18.10.1). Its
  lockfile is generated there and not committed. CI's formatting checks cover its files like
  any other in the tree: `just check-fmt` its `*.rs` files and `just check-toml-fmt` its two
  manifests.
- Every `*.rs` file under `SL/`, `runtime/*.rs` and `differential/` included, passes
  `rustfmt +<pinned nightly> --edition 2024 --check` with the repository `rustfmt.toml`.
- Nothing outside `SL/` is changed (R-LAYOUT-3), except the visibility change in
  `consensus/fuzz/marshal/src` the differential test imports through (section 18.10.1,
  AC-25): `pub(crate)` widened to `pub` on the scenario primitives the test crate uses, the
  two lint `#[allow]`s this needs, and nothing else; no logic, signature or doc change, and
  nothing under `consensus/src`.

---

## 4. Invariant registry

### 4.1 Files and IDs

- One invariant per file: `SL/invariants/<subsystem>/INV-NNNN.md`, where `<subsystem>` is
  `simplex`, `marshal` or `qmdb`, and `NNNN` is a zero-padded decimal of at least 4 digits.
- Invariants derived from knowledge-base findings live in the local registry,
  `SL/invariants.local/<subsystem>/INV-NNNN.md`, which git ignores (D55). Campaigns bind
  them with the tracked ones, and they follow the same format and lint.
- False invariants live in `SL/false-invariants/<subsystem>/FALSE-NNNN.md` and are used
  only when `STATELENS_FALSE_INVARIANTS=1` (section 7.1).
- IDs are global. The next ID is `1 + max(N)` over the `INV-N` files of all registries,
  local ones included, and likewise over the `FALSE-N` files. A local ID is invisible to
  other clones, so one can collide with a tracked ID added elsewhere; lint rule 9 reports
  it, and the local file is renumbered by hand. Deleting the file with the highest ID lets its ID
  be reused; this is accepted.
- Target-state cards (section 18.3) have their own prefix, `TS`, with one global counter over
  `SL/target-states/` and `SL/target-states.local/`, computed the same way.

### 4.2 Front matter

YAML front matter between two `---` lines. Keys, in this order:

| Key | Required | Value |
|---|---|---|
| `id` | yes | Equal to the file name without `.md`. |
| `title` | yes | One line, at most 80 characters. |
| `source_kind` | yes | `human`, `issue`, `design`, `comment`, `spec`, `paper` or `kb`. |
| `source_ref` | yes | URL, path, `path:line@commit` (section 4.6, rule 10), document section, or paper page. |
| `scope` | yes | Inline list, one or more of the registry's scope values (below). |

| Registry | Allowed `scope` values |
|---|---|
| `simplex` | `protocol`, `replica`, `voter`, `batcher`, `resolver`, `cross-actor` |
| `marshal` | `protocol`, `replica`, `core`, `resolver`, `standard`, `coding`, `application`, `cross-component`; here `resolver` is marshal's backfill resolver |
| `qmdb` | `database`, `proof`, `sync`, `any`, `current`, `immutable`, `keyless`, `store`; `database` is one database, `proof` proofs and their verification, `sync` a database built from a source, and the others the variant a property is about |

### 4.3 Body

Level-2 sections, in this order:

1. `## Statement` (required): one sentence in EARS form (section 4.4). It MUST NOT name
   implementation identifiers.
2. `## Rationale` (required): why it must hold.
3. `## Evidence` (required): what the source says. For `issue`, the violating
   scenario.
4. `## Preconditions / assumptions` (optional).
5. `## Observation hints` (optional, non-binding): where the concepts live in the code,
   including, for an action the Statement constrains, the site past which it is visible
   outside the replica or the database. Hints name functions, types and fields, not line
   numbers, because they describe the code a later campaign instruments and lines move.
6. `## Source excerpts` (generated, last): the lines the file cites, as they read at the
   commit each citation names, so a reader sees what the invariant was written against
   without fetching it. `statelens.py excerpts` writes it from the citations and
   `extract` runs it on the files the agent writes; nobody edits it by hand.

A line number means something only at one commit, so every line a file cites, in
`source_ref` or in the text, is written `path:line@commit` with the path from the
repository root; `line` may be a range or a list of ranges. Where a heading or a name is
enough, a file names it instead: a quote from a document may carry its section, and a
function, type or test is named rather than located. The registry pins its citations to
`55cd57fd2137`, the main commit its invariants were written against. Each excerpt is the
cited range, merged with the ranges of the same file and commit that overlap it or lie at
most one line away, copied verbatim except that a non-ASCII character is written as a `\u`
escape (rule 8).

### 4.4 EARS statements and how they are checked

The system is the one the registry's prompt context names (sections 13.11, 13.12 and
13.17). In the simplex and marshal registries it is "the replica" (one honest replica) or,
for scope `protocol`, "the protocol"; in the qmdb registry it is "the database" (one
database over its whole life, restarts included). The table writes it `<system>`.

| EARS pattern | Form | Checked with |
|---|---|---|
| Ubiquitous | `The <system> shall <response>.` | `sl_assert!(cond)` |
| State-driven | `While <state>, the <system> shall <response>.` | `sl_implies!(state, response)` |
| Event-driven | `When <trigger>, the <system> shall <response>.` | `sl_implies!(trigger, response)` where the response is committed |
| Unwanted behavior | `If <condition>, then the <system> shall <response>.` | `sl_implies!(condition, response)` |
| Complex | `While <state>, when <trigger>, the <system> shall <response>.` | `sl_implies!(state && trigger, response)` |

Prohibitions use `shall not`. History ("after", "once", "never again") is kept in
ghost state (section 9.4) and checked at the later action.

A Statement about an action is checked where the action is committed, not where it is
decided: the point past which it is visible outside the replica or the database. Where the
implementation splits the two across an await, a mailbox, a reply handler or a later call
(a batch is merkleized in one call and applied in another), the commit site carries the
check, because the state the decision read is not the state the code acted on. Section
10 states the rule and section 11 the coverage it claims.

### 4.5 `templates/invariant.md` (verbatim)

~~~markdown
---
id: INV-NNNN
title: <one line, at most 80 characters>
source_kind: <human | issue | design | comment | spec | paper>
source_ref: <URL, path, path:line@commit, document section, or paper page>
scope: [<one or more of the registry's scope values, listed in the prompt context>]
---

## Statement
<One EARS sentence about the system the prompt context names: "the replica", or "the
protocol" for scope protocol, in simplex and marshal; "the database" in qmdb.>

## Rationale
<Why it must hold: the protocol or design argument, or the reference that states it.>

## Evidence
<What the source says. For an issue: the violating scenario in two to five sentences. Cite a
line as path:line@commit, with the path from the repository root, or name the section or item.>

## Preconditions / assumptions
<Optional. Conditions or modeling assumptions under which the Statement is claimed.
Delete this section if unused.>

## Observation hints
<Optional and non-binding. Where the concepts live in today's code: name functions, types and
fields, not line numbers, which move. For an action the Statement constrains, name the site
past which it is visible outside the replica or the database, not only the one that decides
it. Delete this section if unused.>
~~~

### 4.6 Lint rules

`statelens.py lint [PATH...]` checks each file (default: every `*.md` in
`SL/invariants/*/` and `SL/false-invariants/*/`; `.gitkeep` files are ignored) and prints
`path: problem` for every violation:

1. The file is in `invariants/<subsystem>/` or `invariants.local/<subsystem>/` and named
   `INV-\d{4,}\.md`, or in `false-invariants/<subsystem>/` and named `FALSE-\d{4,}\.md`,
   where `<subsystem>` is a known registry. A Markdown file directly in `invariants/` or `false-invariants/` is a
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
10. Every line number names its file and the commit it was read at: `path:line@commit`,
    with a commit of 7 to 40 hex digits (section 4.3). Inside a git clone the citation is
    resolved: the path, from the repository root, exists at the commit, and the lines lie
    within it. A citation without a commit, a bare `line N` or `lines N-M`, and a GitHub
    `#L` link into a branch are problems, because each points at different code as the tree
    changes. The Source excerpts section is not scanned; rule 11 covers it.
11. Inside a git clone, a file that pins a citation has a `## Source excerpts` section, and
    it is exactly what `statelens.py excerpts` writes for those citations; a stale or
    missing one names the command that regenerates it.

Exit code 0 when clean, 3 otherwise. EARS conformance is not linted; humans review it.

`lint` also checks the target-state cards of section 18.3, by default every `*.md` in
`SL/target-states/*/` and `SL/target-states.local/*/`. Rules 1 to 11 apply to them with the
changes section 18.3 gives, and rules 12 (History) and 13 (Knobs), which section 18.3 states,
apply to cards only.

### 4.7 False invariants

Each registry has a deliberately false invariant, on which a working campaign must panic:
`SL/false-invariants/simplex/FALSE-0001.md` (Appendix C, AC-6),
`SL/false-invariants/marshal/FALSE-0002.md` (Appendix E, AC-10) and
`SL/false-invariants/qmdb/FALSE-0003.md` (Appendix G, AC-19). They follow the registry
format with an ID prefix of `FALSE`. A campaign binds those of its profile's subsystems,
and only when `STATELENS_FALSE_INVARIANTS=1`; `--invariants` then selects one as
`<registry>/FALSE-NNNN` like any other invariant (section 7.1 step 4).

---

## 5. Configuration and command line

### 5.1 `config.env` (verbatim)

~~~
# StateLens defaults. This file is tracked by git: keep machine-specific and private
# values out of it and put them in config.local.env, which git ignores and which
# overrides a value here. An environment variable with the same name overrides both,
# and `--agent` overrides STATELENS_AGENT.

# Agent CLI used by extract and campaign: claude or codex.
STATELENS_AGENT=claude

# Model passed to the agent CLI; empty means the CLI default.
STATELENS_CLAUDE_MODEL=claude-opus-5-5
STATELENS_CODEX_MODEL=gpt-5.6-sol

# Reasoning effort passed to the agent CLI; empty means the CLI default. Claude
# takes low, medium, high, xhigh or max; codex takes its own
# `model_reasoning_effort` levels. Pin both this and the model for a campaign you
# want to be able to compare with another.
STATELENS_CLAUDE_EFFORT=high
STATELENS_CODEX_EFFORT=high

# Toolchain for the test gate and the check command.
STATELENS_TEST_TOOLCHAIN=stable

# Toolchain for fuzz builds; empty means NIGHTLY_VERSION from
# .github/workflows/slow.yml.
STATELENS_FUZZ_TOOLCHAIN=

# Knowledge base roots for beacon extraction and for `just extract-invariants kb`,
# separated by `:`. Empty disables both; nothing else depends on it. Leave it empty
# here: a corpus root is a path on one machine and may name a private repository of
# findings, so it belongs in config.local.env or in the environment, never in this
# tracked file.
STATELENS_KB=

# Embedding model of `kb search`: a Hugging Face name or a local directory. `just
# search-index` downloads it when it is not on disk yet and embeds on the CPU; a
# query never uses the network.
STATELENS_SEARCH_MODEL=sentence-transformers/all-MiniLM-L6-v2

# Audit pass over the bindings, after the beacon step: 0 skips it. It costs one
# agent run per batch and is what keeps a plan's Status honest.
STATELENS_AUDIT=1
~~~

Parsing: `KEY=VALUE` lines; `#` starts a comment line; values are not shell-expanded.
Precedence: command-line flag, then non-empty environment variable, then `config.local.env`,
then `config.env`. The local file is ignored by git (section 3) and holds what is specific
to one machine or private, above all `STATELENS_KB`, so that a corpus root is never
committed by filling in the tracked file.

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
| `STATELENS_REACH=1` | Read by the scaffold helper: a scaffold prints its stage lines (section 18.8). `synthesize` sets it for its reach replays; an operator sets it to replay a scaffold's crash. |
| `STATELENS_REACH_CONTROL=1` | Read by the scaffold helper: the run is the control run, which withholds one event (section 18.8). `synthesize` sets it for the control run; an operator sets it, with `STATELENS_REACH=1`, to replay a control run's crash. |

Target-State Synthesis adds no key to `config.env`.

### 5.2 Prerequisites

A fresh clone of the repository on a dedicated machine or container (D4, D10), with
`git`, `python3` (3.9 or later), `just`, `cargo` with the `stable` and pinned nightly
toolchains, `cargo-nextest`, `cargo-fuzz`, and the chosen agent CLI (`claude` or
`codex`), logged in. Phase 1 with `issue` sources also needs `gh` (logged in) or
network access for `curl`. Phase 1 with PDF papers uses `pdftotext` or the Python
`pypdf` module when available. Beacon extraction needs `STATELENS_KB` to name at least
one readable corpus root. The code index (section 5.7) needs `rust-analyzer`; without it a
campaign warns and continues. `just coverage` (section 7.13) needs the fuzz toolchain's
`llvm-tools-preview` component. The `qmdb` test gate needs an open-file soft limit well above
256, the macOS default (section 17.6). `kb search` (section 5.10) needs the Python packages
numpy and sentence-transformers to rank by meaning, and ranks by words without them;
`just search-index` downloads its model the first time. No GPU is needed.

### 5.3 `justfile` (verbatim)

~~~
# StateLens recipes. See README.md.

set positional-arguments := true

# Turn sources into invariants: just extract-invariants [--registry R] [--number N] <kind> <source>...
extract-invariants *args:
    python3 scripts/statelens.py extract "$@"

# Turn sources into target-state cards: just extract-states [--registry R] [--number N] [--local] <kind> <source>...
extract-states *args:
    python3 scripts/statelens.py extract --states "$@"

# Instrument this checkout and build the StateLens targets: just campaign [--agent A] [--profile P] [--invariants LIST]...
campaign *args:
    python3 scripts/statelens.py campaign "$@"

# Write, build and check a scaffold per target-state card and base, after a campaign: just synthesize [--agent A] [--profile P] [--match GLOB]... [--redo]
synthesize *args:
    python3 scripts/statelens.py synthesize "$@"

# Run only the campaign's test gate on this checkout: just test [--profile P]
test *args:
    python3 scripts/statelens.py test-gate "$@"

# Fuzz a target a campaign built: just run <target> [-- -fork=8 -max_total_time=600]
run target *args:
    #!/usr/bin/env bash
    set -euo pipefail
    # A consensus target runs through consensus/fuzz, whose `run` finds its package.
    # Storage has one fuzz package and no recipes, so a qmdb target runs there
    # directly, on the toolchain consensus/fuzz would pick: NIGHTLY_VERSION, else
    # the pin CI uses, else `nightly`. A crash file is best given as an absolute
    # path, because each runs cargo-fuzz from its own directory.
    case "$1" in
      qmdb_*)
        pin=$(sed -n 's/^ *NIGHTLY_VERSION: *//p' ../.github/workflows/slow.yml | head -1)
        nightly="${NIGHTLY_VERSION-${pin:-nightly}}"
        cd .. && cargo ${nightly:+"+$nightly"} fuzz run --fuzz-dir storage/fuzz "$@" ;;
      *)
        cd ../consensus/fuzz && just run "$@" ;;
    esac

# Campaign, then fuzz: just fuzz <target|simplex|marshal|qmdb> [--fuzz-targets GLOB]... [--state-targets GLOB]... [--invariants LIST]... [--skip-campaign] [--parallel] [--tmux] [--state-reaching] [-- -fork=8]
fuzz target *args:
    #!/usr/bin/env bash
    set -euo pipefail
    # A profile name runs every target the profile builds, or with --fuzz-targets
    # the ones a shell pattern names; a target name runs that one. Every StateLens
    # variant is derived from a target of its own package, so it keeps that
    # package's prefix, and a name that is neither is refused rather than sent to
    # another profile by default. With --state-reaching, simplex and marshal run
    # their scaffolds instead of their variants: a synthesis follows the campaign,
    # --state-targets names the cards (TS-0003) and --fuzz-targets the bases the
    # scaffolds are written on, one scaffold per card and base (every base of the
    # profile without --fuzz-targets).
    target="$1"
    shift
    # Leading flags are ours; everything after them, or after `--`, is libFuzzer's.
    # libFuzzer's own flags take one dash, so an unknown double-dash flag before
    # `--` is refused rather than passed on.
    # --skip-campaign fuzzes the targets a campaign already built in this checkout,
    # whatever its result, because a campaign refuses an instrumented checkout.
    # --invariants LIST goes to the campaign, which binds only the invariants it
    # names, so it needs a campaign and a profile.
    # Both pattern flags reach the listing and the synthesis as --match, whose one
    # rule they split: a TS-NNNN pattern names a card, any other a fuzz target.
    fuzz_targets() {
        case "$1" in
          TS-*) echo "just fuzz: --fuzz-targets names fuzz targets; a card is --state-targets $1" >&2
                exit 1 ;;
        esac
        narrowed=yes; patterns+=(--match "$1")
    }
    state_targets() {
        case "$1" in
          TS-*) ;;
          *) echo "just fuzz: --state-targets names cards (TS-NNNN); a fuzz target is --fuzz-targets $1" >&2
             exit 1 ;;
        esac
        cards=yes; patterns+=(--match "$1")
    }
    parallel=no
    windows=no
    campaign=yes
    narrowed=no
    cards=no
    reaching=no
    selected=no
    patterns=()
    invariants=()
    while [ $# -gt 0 ]; do
      case "$1" in
        --skip-campaign)        campaign=no; shift ;;
        --parallel|--parallels) parallel=yes; shift ;;
        --tmux)                 parallel=yes; windows=yes; shift ;;
        --state-reaching)       reaching=yes; shift ;;
        --fuzz-targets=*)       fuzz_targets "${1#--fuzz-targets=}"; shift ;;
        --fuzz-targets)         [ $# -ge 2 ] || { echo "just fuzz: --fuzz-targets needs a pattern" >&2; exit 1; }
                                fuzz_targets "$2"; shift 2 ;;
        --state-targets=*)      state_targets "${1#--state-targets=}"; shift ;;
        --state-targets)        [ $# -ge 2 ] || { echo "just fuzz: --state-targets needs a pattern" >&2; exit 1; }
                                state_targets "$2"; shift 2 ;;
        --invariants=*)         selected=yes; invariants+=(--invariants "${1#--invariants=}"); shift ;;
        --invariants)           [ $# -ge 2 ] || { echo "just fuzz: --invariants needs a list of ids" >&2; exit 1; }
                                selected=yes; invariants+=(--invariants "$2"); shift 2 ;;
        --)                     shift; break ;;
        --*)                    echo "just fuzz: unknown flag $1" >&2; exit 1 ;;
        *)                      break ;;
      esac
    done
    # `cargo fuzz run` takes libFuzzer flags only after `--`, which the loop consumed.
    if [ $# -gt 0 ]; then set -- -- "$@"; fi
    case "$target" in
      simplex|marshal|qmdb) profile="$target"; every=yes ;;
      simplex_*)            profile=simplex;   every=no ;;
      marshal_*)            profile=marshal;   every=no ;;
      qmdb_*)               profile=qmdb;      every=no ;;
      *) echo "just fuzz: $target is not a profile or a simplex_/marshal_/qmdb_ target" >&2
         exit 1 ;;
    esac
    if [ "$reaching" = yes ] && [ "$every" = no ]; then
        echo "just fuzz: --state-reaching narrows a profile; name simplex or marshal" >&2
        echo "           (one scaffold runs with just run <scaffold>)" >&2
        exit 1
    fi
    if [ "$reaching" = yes ] && [ "$profile" = qmdb ]; then
        echo "just fuzz: --state-reaching takes simplex or marshal; qmdb has no target states" >&2
        exit 1
    fi
    if [ "$cards" = yes ] && [ "$reaching" = no ]; then
        echo "just fuzz: --state-targets needs --state-reaching" >&2
        exit 1
    fi
    if [ "$every" = no ] && [ "$narrowed" = yes ]; then
        echo "just fuzz: --fuzz-targets narrows a profile; name simplex, marshal or qmdb" >&2
        exit 1
    fi
    if [ "$selected" = yes ] && [ "$campaign" = no ]; then
        echo "just fuzz: --invariants selects what a campaign binds; drop --skip-campaign" >&2
        exit 1
    fi
    if [ "$selected" = yes ] && [ "$every" = no ]; then
        echo "just fuzz: --invariants selects what a campaign binds; name simplex, marshal or qmdb" >&2
        exit 1
    fi
    # The targets are listed before the campaign runs, so that a pattern naming
    # none fails at once rather than after it; with --state-reaching, so do a
    # selection of no card and a selected card with a lint problem. A read loop,
    # not `mapfile`: that is bash 4, and macOS ships bash 3.2, which also calls an
    # empty array unbound.
    listed=()
    if [ "$reaching" = yes ]; then
        listed=(--state-reaching)
    fi
    list() {
        local listing
        names=()
        if ! listing=$(python3 scripts/statelens.py targets --profile "$profile" ${listed[@]+"${listed[@]}"} ${patterns[@]+"${patterns[@]}"}); then
            echo "$listing" >&2
            exit 1
        fi
        while IFS= read -r name; do
            if [ -n "$name" ]; then names+=("$name"); fi
        done <<< "$listing"
    }
    if [ "$every" = yes ]; then
        list
    fi
    if [ "$campaign" = yes ]; then
        just campaign --profile "$profile" ${invariants[@]+"${invariants[@]}"}
    fi
    if [ "$every" = no ]; then
        just run "$target" "$@"
        exit 0
    fi
    # Synthesis writes a scaffold per selected card and base; a failure stops the
    # recipe with its exit code. Then only the scaffolds run, never the variants,
    # one window or run per scaffold, and the messages below count scaffolds.
    kind=target
    if [ "$reaching" = yes ]; then
        python3 scripts/statelens.py synthesize --profile "$profile" ${patterns[@]+"${patterns[@]}"}
        list
        if [ "${#names[@]}" -eq 0 ]; then
            echo "just fuzz: no scaffold for this selection; see the reports in campaign/reach/" >&2
            exit 1
        fi
        kind=scaffold
    fi
    here="$(pwd)"
    cores=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)

    if [ "$windows" = yes ]; then
        command -v tmux >/dev/null 2>&1 || {
            echo "just fuzz: --tmux needs tmux on PATH" >&2; exit 1; }
        session="statelens-$profile"
        if [ "$reaching" = yes ]; then session="$session-reach"; fi
        tmux has-session -t "$session" 2>/dev/null && {
            echo "just fuzz: tmux session $session already exists; kill it first with" >&2
            echo "           tmux kill-session -t $session" >&2; exit 1; }
        echo "just fuzz: ${#names[@]} ${kind}(s), one tmux window each, ${cores} core(s)" >&2
        for at in $(seq 0 $(( ${#names[@]} - 1 ))); do
            name="${names[$at]}"
            # The window stays open after the run so its result can be read.
            body="cd '$here' && just run '$name' $*; echo; echo '[$name finished; enter closes this window]'; read _"
            # Named after the target it was derived from, or for a scaffold its
            # base and card (simplex_cert_mock_ts0004), which is what
            # distinguishes the windows from each other.
            window="${name%_statelens}"
            if [ "$at" -eq 0 ]; then
                tmux new-session -d -s "$session" -n "$window" "bash -lc \"$body\""
            else
                tmux new-window -t "$session" -n "$window" "bash -lc \"$body\""
            fi
        done
        if [ -n "${TMUX:-}" ]; then
            tmux switch-client -t "$session"
        else
            echo "just fuzz: attaching; detach with ctrl-b d, and return with" >&2
            echo "           tmux attach -t $session" >&2
            tmux attach -t "$session"
        fi
        exit 0
    fi

    if [ "$parallel" = no ]; then
        # Sequential and unbounded means the first target never ends and the
        # rest never start, so say so rather than quietly imposing a limit.
        if [[ "$*" != *-max_total_time=* && "$*" != *-runs=[0-9]* ]]; then
            echo "just fuzz: no -max_total_time, so $kind 1 of ${#names[@]} runs until it" >&2
            echo "           stops and the rest wait. Use --parallel, --tmux, or pass" >&2
            echo "           -- -max_total_time=<seconds>." >&2
        fi
        echo "just fuzz: ${#names[@]} $profile ${kind}(s), in turn" >&2
        for name in "${names[@]}"; do
            echo "just fuzz: === $name ===" >&2
            just run "$name" "$@"
        done
        exit 0
    fi

    # Batches, because a pool that waits for one process at a time needs
    # `wait -n`, which is bash 4.3. libFuzzer's own `-fork=N` also takes cores,
    # so a whole profile at once would oversubscribe badly.
    jobs=${STATELENS_JOBS:-$(( cores / 4 > 0 ? cores / 4 : 1 ))}
    [ "$jobs" -gt "${#names[@]}" ] && jobs=${#names[@]}
    logs="campaign/logs"
    mkdir -p "$logs"
    echo "just fuzz: ${#names[@]} $profile ${kind}(s), $jobs at a time, ${cores} core(s)" >&2
    echo "just fuzz: output goes to $logs/<$kind>.run.log" >&2
    failed=()
    index=0
    while [ "$index" -lt "${#names[@]}" ]; do
        pids=()
        batch=()
        while [ "${#batch[@]}" -lt "$jobs" ] && [ "$index" -lt "${#names[@]}" ]; do
            name="${names[$index]}"
            batch+=("$name")
            index=$(( index + 1 ))
            echo "just fuzz: starting $name" >&2
            ( just run "$name" "$@" ) > "$logs/$name.run.log" 2>&1 &
            pids+=("$!")
        done
        for at in $(seq 0 $(( ${#pids[@]} - 1 ))); do
            if ! wait "${pids[$at]}"; then
                failed+=("${batch[$at]}")
            fi
        done
    done
    for name in "${names[@]}"; do
        printf 'just fuzz: %-58s %s\n' "$name" \
            "$(printf '%s\n' "${failed[@]:-}" | grep -qxF "$name" && echo FAILED || echo ok)" >&2
    done
    if [ "${#failed[@]}" -gt 0 ]; then
        echo "just fuzz: ${#failed[@]} ${kind}(s) failed; see $logs/<$kind>.run.log" >&2
        exit 1
    fi

# Coverage of the corpora the targets built: just coverage <simplex|marshal|qmdb|target...>
coverage *args:
    python3 scripts/statelens.py coverage "$@"

# Build the code index a campaign and the agents query: just code-index [--subsystem S]
code-index *args:
    python3 scripts/statelens.py code build "$@"

# Build or update the search index of `kb search`: just search-index [--rebuild]
search-index *args:
    python3 scripts/statelens.py search-index "$@"

# Ask the search index a question: just search [--registry R] [--path P] QUESTION...
search *args:
    python3 scripts/statelens.py kb search "$@"

# Identify an entity in the code: just code <defs|refs|callers|callees> <NAME>
code query name *args:
    python3 scripts/statelens.py code "$@"

# Read the syntax tree: just ast <sites|notes> [NAME] [path...]
ast query *args:
    python3 scripts/statelens.py ast "$@"

# Undo what a campaign or a synthesis wrote to this checkout: just clean [--yes]
clean *args:
    python3 scripts/statelens.py clean "$@"

# Check the worked analyses: just check-examples [path...]
check-examples *args:
    python3 scripts/statelens.py lint-examples "$@"

# Check the scripts: just check-scripts [TestClass]
check-scripts *args:
    python3 scripts/test_statelens.py "$@"

# Check invariant files: just check-invariants [path...]
check-invariants *args:
    python3 scripts/statelens.py lint "$@"

# Write the cited source lines into invariant files: just excerpts [--check] [path...]
excerpts *args:
    python3 scripts/statelens.py excerpts "$@"

# Check an instrumentation plan: just check-plan [--profile P] [path...]
check-plan *args:
    python3 scripts/statelens.py lint-plan "$@"

# Check the prompt copies in the specification: just check-prompts [--write]
check-prompts *args:
    python3 scripts/statelens.py lint-prompts "$@"
~~~

### 5.4 `scripts/statelens.py`

Standard library only; Python 3.9 compatible. The script finds the repository root with
`git rev-parse --show-toplevel` from its own directory, and prints progress lines
prefixed with `statelens:`.

| Subcommand | Usage | Exit codes |
|---|---|---|
| `lint` | `lint [PATH...]` | 0 clean, 3 problems |
| `excerpts` | `excerpts [--check] [PATH...]`; writes the Source excerpts section of each invariant file (default: every registry file and every card, section 18.3) from its pinned citations (section 4.3). With `--check` it writes nothing and lists the files whose section is missing or stale | 0 done, 3 stale files under `--check` |
| `extract` | `extract [--agent A] [--registry R] [--number N] [--states] [--local] KIND [SOURCE...]`, where `R` is `simplex` (default), `marshal` or `qmdb`; `N` bounds how many invariants the run writes (D56); `kb` reads knowledge-base findings and writes to the local registry (D55). With `--states` it writes target-state cards instead (section 18.4): `R` is `simplex` or `marshal`, `KIND` may also be `test` or `text`, a `kb` source may be one finding identifier, and `--local` sends the cards to the local card registry; `--local` without `--states` is a usage error | 0 done (including zero files), 1 usage, 2 agent failed, 3 problems: a lint problem, an existing invariant modified, a write outside the registry, or a change anywhere else in the worktree |
| `kb` | `kb modules [--registry R]`, `kb find [--registry R] TERM...`, `kb grep [--registry R] TEXT`, `kb cites [--registry R] PATH`, `kb show [--registry R] IDENTIFIER [SECTION]` (section 5.6), and `kb search [--registry R] [--path P]... [--source S]... [--tests] [-k N] QUESTION...` (section 5.10) | 0 done, including no hits, 1 usage, an identifier out of the registry's scope, a section that is not state-bearing, a section asked of a document, or no search index, 2 no readable corpus root, for every query but `search` |
| `search-index` | `search-index [--rebuild]`; builds or updates the index of `kb search` (section 5.10) | 0 built with the model, 2 built without it, so that `kb search` ranks by words only |
| `lint-examples` | `lint-examples [PATH...]`; with no path it checks every `*.md` in `examples/` | 0 clean, 3 problems |
| `lint-plan` | `lint-plan [--profile P] [PATH...]`; with no path it checks `SL/campaign/plan.md`, and with no `--profile` it takes the profile from `SL/campaign/meta.json`, else `simplex`, and expects a section only for the invariants that file lists under `invariants`, so the bare command the audit prompt gives checks what the campaign bound, a selection (section 7.1 step 4) included; `--profile` naming the campaign's profile does the same, and another profile expects every registry invariant of that profile. A section per expected invariant; a valid `Status`; the fields that status needs (section 11); a `Sites` ledger whose entries each name a source and say `checked` or `not checked`, and leave nothing unchecked when the status is `bound`; an assertion naming the invariant in the function of every entry marked `checked`; and, for every invariant the plan claims to bind, an `sl_assert!` or `sl_implies!` call in the instrumented code that names it. It judges the claims the plan makes; a commit site the ledger never names is what the audit pass (section 7.3) is for | 0 clean, 3 problems |
| `lint-prompts` | `lint-prompts [--write]`; compares every file in `prompts/` with its copy in section 13. `--write` refreshes the copies from the files and reports what it could not fix | 0 clean, 3 problems |
| `code` | `code build [--subsystem S]`, and `code defs|refs|callers|callees NAME [--tests] [--all]` (section 5.7) | 0 done, 1 usage, no index, or no symbol matching NAME |
| `coverage` | `coverage [--profile P] [TARGET...]`; replays the corpus of each StateLens target under coverage instrumentation and writes an HTML report per target plus a merged one (section 7.13). A positional name is a profile or a target, as `just fuzz` reads it; a scaffold's name is accepted like a variant's, and a profile covers its scaffolds with its variants (section 18.9). A target with no corpus is skipped | 0 done, 1 usage or an unknown target, 2 no corpus anywhere, no `llvm-tools-preview`, or a failed coverage run |
| `targets` | `targets [--profile P] [--state-reaching] [--match GLOB]...`; the StateLens targets `P` builds, one per line, which is what `just fuzz <profile>` reads rather than parsing a campaign summary. `--match` keeps the targets a shell pattern names, by variant name or by the original target's, and is what `just fuzz <profile> --fuzz-targets GLOB` passes. With `--state-reaching` it lists the scaffolds of the selected pairs (card, base) instead, and a `TS-NNNN` pattern names a card; `just fuzz` forwards `--state-targets` and `--fuzz-targets` alike as `--match`, having checked each pattern's form (section 18.9) | 0 done, 1 a pattern that names no target; with `--state-reaching`, 0 done, also with no scaffold yet, 1 no card and base selected or a selected card with a lint problem |
| `synthesize` | `synthesize [--agent A] [--profile P] [--match GLOB]... [--redo]`, where `P` is `simplex` or `marshal`, by default the profile of `SL/campaign/meta.json`; writes, builds and checks one scaffold per selected card on each selected base, every candidate base with no base pattern, on a checkout a campaign of `P` instrumented (section 18.6) | 0 at least one scaffold exists for the selection, 1 usage or nothing selected, 2 a failed precondition, an edit outside the edit contract's scope, a missing anchor, or a `--redo` that does not apply, 3 no scaffold built |
| `reach-verdict` | `reach-verdict --card CARD --module MODULE --canonical LOG [--canonical-code N] [--control LOG] [--control-code N]`; the reach verdict of one scaffold from replays captured outside synthesis, through the same `card_history`, `first_run` and `reach_verdict` the synthesis uses (section 18.8): prints the verdict, then the reasons, annotations and control reason one per line. `SL/scripts/differential.sh` is its caller (section 18.10.1) | 0 REACHED, 1 any other verdict |
| `test-gate` | `test-gate [--profile P]`; runs the test gate's command (section 7.7) on the checkout as it stands, then, for a profile that has them, the component tests, which are reported and not gated. With no `--profile` it takes the profile from `SL/campaign/meta.json` | 0 gate passed, 1 no profile, 4 gate failed |
| `ast` | `ast sites NAME [PATH...] [--writes-only] [--tests]`, `ast notes [--pattern RE] [PATH...] [--tests]`; a `PATH` is a file or a directory (section 5.8) | 0 done, including no sites, 1 usage or rust-analyzer absent |
| `clean` | `clean [--yes]`; without `--yes` it prints what it would undo and changes nothing. Files a campaign or an instrumenter added are deleted and paths that exist in `HEAD` are restored from it, the two told apart by asking `git ls-tree` rather than by reading a status code. Status is asked with `--untracked-files=all`, so a wholly untracked directory is named as its files rather than collapsed to one entry that is not a file to delete, and a directory that is left empty is removed while nothing in it is deleted unseen. With `--yes` it checks afterwards that nothing in scope still differs from `HEAD`. The scope includes the simplex and marshal fuzz packages, where synthesis writes (section 18.6), but not the `corpus/`, `artifacts/` and `coverage/` that git ignores there; under the simplex and marshal `src/target_states/`, which synthesis writes whole and a campaign refuses, it also deletes the files git ignores, and with `--yes` it reports such a directory that remains as a difference (exit 1) | 0 done, including a preview, which is not a failure; 1 something in scope still differs from `HEAD`, so the checkout is not reusable |
| `campaign` | `campaign [--agent A] [--profile P] [--invariants LIST]... [--stop-after STEP]`, where `P` is `simplex` (default), `marshal` or `qmdb`, and `LIST` is a comma-separated list of the invariants to bind instead of every invariant of the profile's registries, each `<registry>/INV-NNNN`, or a bare `INV-NNNN` when the profile binds one registry (section 7.1 step 4) | 0 ready (the StateLens targets are built and the test gate passed) or stopped after a step, 1 usage, 2 setup or agent failure (including a missing tool, a checkout that is not fresh, or a selection that names no invariant the profile collects), 3 build failed, 4 test gate failed; codes 5 and 6 are no longer used (D23) |

`--stop-after` accepts `materialize`, `index`, `instrument` or `build`. It exists for
development and acceptance testing and is not a campaign parameter in the PRD sense. A
campaign that stops this way exits with code 0 and reports the result
`STOPPED after <step>`.

Placeholders in prompt files have the form `{{NAME}}` (upper case). Rendering MUST fail
on a placeholder without a value. Every rendered prompt is saved next to its log.

### 5.5 Profiles

A campaign's profile selects what it binds, instruments, tests and builds (D20). Profiles
are data in `statelens.py`:

| Item | `simplex` | `marshal` | `qmdb` |
|---|---|---|---|
| Registries, in binding order | `simplex` | `simplex`, `marshal` | `qmdb` |
| Crate: check command, test gate and code index | `consensus` | `consensus` | `storage` |
| Runtime module (section 9) | `consensus/src/simplex/statelens.rs`, called as `crate::simplex::statelens` | the same | `storage/src/qmdb/statelens.rs`, called as `crate::qmdb::statelens` |
| Knowledge-base `module` filter, per component's subsystem | `consensus/simplex` and its submodules | the same, and `consensus/marshal` and its submodules | `storage/qmdb` and its submodules |
| Editable roots (scope check) | `consensus/src/simplex/` | `consensus/src/simplex/`, `consensus/src/marshal/` | `storage/src/qmdb/` |
| Warn-only paths | `consensus/src/simplex/mocks/`, `consensus/src/simplex/scheme/` | the same, and `consensus/src/marshal/mocks/` | `storage/src/qmdb/benches/` |
| Beacon components, as `ACTOR`: `ACTOR_DIR` | `voter`, `batcher`, `resolver`: `consensus/src/simplex/actors/<actor>` | the three of `simplex`; `marshal.core`: `consensus/src/marshal/core`; `marshal.standard`: `consensus/src/marshal/standard`; `marshal.coding`: `consensus/src/marshal/coding` | `qmdb.any`, `qmdb.current`, `qmdb.immutable`, `qmdb.keyless`, `qmdb.store`, `qmdb.sync`: `storage/src/qmdb/<variant>` |
| Materialize edits | Section 7.2, edits 1 to 12 | Section 7.2, edits 1 to 3 and 6 to 8, and edits M1 to M3 (section 8.3) | Section 7.2, edits 7 and 8, and edits Q1 to Q5 (section 17.3) |
| Cryptography check | D15 (section 7.2) | Section 8.4 | None: no target signs anything |
| Fuzz package | `consensus/fuzz/simplex` | `consensus/fuzz/marshal` | `storage/fuzz` |
| Fuzz targets it builds | One StateLens variant per `simplex_*` target in `consensus/fuzz/simplex/fuzz_targets/` | One StateLens variant per `marshal_*` target in `consensus/fuzz/marshal/fuzz_targets/` | One StateLens variant per `qmdb_*` target in `storage/fuzz/fuzz_targets/` |
| Test filter | Section 7.7 | Section 8.3, step 6 | Section 17.3, step 6 |
| Component tests after the gate | Section 7.7 | Section 7.7 | None: the gate runs every qmdb test |
| Scaffold declaration (section 18.6) | After the line `pub mod state_cov;` of `consensus/fuzz/simplex/src/lib.rs`, the line `pub mod target_states;` | After the line `pub mod scenarios;` of `consensus/fuzz/marshal/src/lib.rs`, the lines `#[cfg(feature = "mocks")]` and `pub mod target_states;` | None: Target-State Synthesis refuses qmdb |

A target belongs to the profile whose name starts its own: `simplex_*`, `marshal_*` and
`qmdb_*`. `just fuzz`, `just run` and `coverage` read a name that way, and a profile builds
variants only of targets named after it. A scaffold, `<base>_tsNNNN_statelens`, keeps its
base's prefix and so belongs to its base's profile (section 18.7).

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
| `kb grep TEXT` | Up to 40 snippets from the state-bearing sections and the documents, each with its identifier or path, the section name, and three lines of context, kept inside the section the hit is in |
| `kb cites PATH` | Up to 20 findings that cite a file under `PATH`, most citations first; per hit the identifier, state, how many citations, remediation status, `summary`, which of its files fall under `PATH`, and its symbols |
| `kb show IDENTIFIER [SECTION]` | One finding's claim block, the files and symbols it cites and the names of its state-bearing sections, or one of those sections. For a document, whose identifier is its path and which has neither, the whole text; a section asked of a document is refused |
| `kb search QUESTION` | Up to 10 snippets, or up to 40 with `-k`, ranked by meaning and by words, from the findings in scope, the `kb/` and `context/` documents, and this repository's comments, doc comments and Markdown (section 5.10) |

Each is `python3 statelens/scripts/statelens.py kb <subcommand>`. The
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
procedure: at each step it chooses between reading code, one of the six `kb` queries, and
writing a beacon. Reading code leads, because a candidate announces itself there as an enum, a
`debug_assert!`, a per-view flag or a comment about a race. A query is what the agent does
when its hypothesis needs context the source does not carry: what an assumption means, why it
matters, whether it has failed before, or which code manages the transition (D42). This is the paper's on-demand retrieval and its query refinement, within
one agent run. The campaign's instrumenter is the agent doing this, so retrieval and
instrumentation happen in one loop. Of the paper's Phase 2 frontier this project has the
call-graph half, in the code index of section 5.7. It has no data-flow tool, so following a
value through a computation is search and reading, and the findings' own citations stand in
for it.

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
(`consensus/simplex`), and a trailing file name is dropped. A value that normalizes to a
crate alone, such as `consensus` or `storage`, is too coarse to attribute and matches no
registry; the finding is indexed, and `kb modules` reports how many findings name only the
registry's crate, so an operator can see what was excluded.

**Determinism.** `kb find` ranks by: an exact `module` match above a submodule match; then
the number of distinct terms matched in `summary` and `tags`; then `valid` above `tested`
above `triaged` above `intake` above `invalid`. `kb grep` matches a case-insensitive
literal substring, never a regular expression, so the two backends of section 5.2 agree; it
orders hits by corpus root in the order `STATELENS_KB` lists them, then by path, then by
byte offset. All three of `kb find`, `kb cites` and `kb grep` truncate after their limit and say how many
hits were dropped. `kb cites` orders by citation count, then by the state rank above, then by
index order. Ties keep
index order, so one index gives one answer.

### 5.7 Code index

`rust-analyzer scip <crate>` writes a SCIP index of the profile's crate (section 5.5:
`consensus`, or `storage` for qmdb) to `extract/code-index.scip`: every definition and every
reference, keyed by a symbol string that tells a field from a same-named method.
`statelens.py code` answers four questions from it -- `defs`, `refs`, `callers`, `callees`
-- and `just code-index [--subsystem S]` builds it. There is one index at a time, of the
crate the last build indexed. Without `--subsystem` a build indexes the crate of the
campaign in the checkout, else the crate the current index describes, else consensus, so
a `just code-index` run in a campaign's checkout keeps the crate. Its paths are relative to that crate, whose directory the
index records as its project root (`Metadata.project_root`), so the loader reads the crate
from the index and makes every path relative to the repository; an index without one is
taken to be of consensus. The figures below were measured on consensus.

**Why an index and not a language server.** A server charges its startup on every invocation,
where an index is paid for once, before the campaign instruments anything (D43). The campaign
builds it in a step between materialize and instrument, and a failure there warns and
continues, because the sweep worked without one before it existed. A build writes beside the
index and moves its output into place only when it succeeded, with a snapshot of its own, so
a failed or interrupted build leaves the previous index whole for standalone queries. A
campaign whose build fails also removes that previous index and its snapshot, because it may
describe another crate: its agents then search, as the step announces, rather than query an
index that answers for the wrong code. rust-analyzer's output
goes to `extract/code-index.log` and not to the console: it logs at `ERROR` level for
conditions that do not stop the build, such as a definition inside a module a macro
declared, which it cannot name, and minutes of those lines on a console read as a failure.
The console shows the log's path, and the last lines of output when the build fails.

**Staying correct while the tree is edited.** Instrumentation edits the files the index
describes. Which function calls which survives that; line numbers do not, and a line number
is the whole answer, so a stale one is wrong rather than merely old. The build therefore
records the text of every file it indexed, in `extract/code-index-sources.json`, and a query
rebases each hit from that text onto the file as it now stands. A line inside an unchanged run
of text maps exactly; a line inside an edited run is reported `lost` rather than guessed; a
line that maps but no longer holds the name is reported `unverified`; and a file the snapshot
does not cover is reported `unindexed`. Every extent a query prints is rebased, its own header
included. Where an extent has two endpoints the more serious of the two notes is the one
reported, `lost` and `unindexed` above `unverified` above `moved`, because a start that merely
moved would otherwise hide an end that cannot be placed at all; and a line that is not a
location is printed as `?(N)`, naming the indexed line it came from without offering it as a
current one. Rebuilding instead
would cost about eight minutes each time, against a few milliseconds to diff a file of this
crate's median size, so the index is built once and the diff absorbs the sweep.

What no rebase can supply is an entity created after the build, so a query also states what it
cannot answer: how many indexed files have changed, how many are gone or unreadable, and how
many source files have appeared in the directories the index covers. A file counts as
appeared when it is newer than the snapshot, so a source no module declares, which the index
skips (a qmdb bench file, for example), is not reported on every query. That is settled by
comparing the snapshot with the tree before any result is chosen, not while hits are placed,
because otherwise the statement would depend on which files a query happened to touch: a query
that matched nothing, which is the answer most likely to be wrong on a moved tree, would have
reported a clean one. Reading the snapshotted text costs about a tenth of a second for this
crate, against seconds to diff it, so only the line maps stay lazy. Outside a campaign the
statement ends by advising `just code-index`, the remedy in every case. In a campaign's
checkout, changed and added files are the campaign's own instrumentation, which the rebase
exists to absorb, so the statement says that and advises no rebuild: advising one sent an
agent to report a working index as a tooling problem. A file that is gone or has no
snapshot is not an instrumentation edit, and still gets the advice.

**Reading it.** The index is protobuf, read with the standard library alone rather than a
package, so the subproject keeps its stdlib-only rule (D44). Five fields carry the answers;
the ones rust-analyzer leaves empty set the limits. It writes no relationships, so the index
has no trait-implementation edges, and it leaves the read and write role bits unset, so an
occurrence does not say which it is. A `local N` symbol is unique within its document only:
rust-analyzer numbers the locals of every file from zero, so `local 0` names an unrelated
binding in 218 of this crate's files, and the loader keys each local by the file that defines
it, where a global symbol is unique by construction. A local is visible only inside its
function, and the crate has 646 locals named `view` against 50 fields and methods, so a query
sets locals aside whenever a global carries the name and says how many it set aside; a name
that only locals carry is answered from them. It does populate the enclosing range of a
definition, and that is what makes callers and callees derivable: a reference belongs to
whichever definition's range contains its line, among the definitions that can contain code;
a local's range is its own binding, so a call on a `let` line belongs to the function, not to
the variable.

**Test sites.** Nearly three quarters of this crate is test code (82,401 lines of 114,177),
and it sits in the same files as the code it exercises, so neither the path nor the index
separates them. What is test code is the extent of each item carrying `#[cfg(test)]`, read
from the syntax tree of section 5.8. An attribute is a child of the item it applies to, so
the item is that attribute's nearest enclosing node and its range is what to exclude. The
item's own start offset will not identify it, because a doc comment or an earlier attribute
begins the item instead -- as the resolver module does, documenting its test module on the
line above the attribute. A file suffix will not do,
because an attribute may gate one item with production code after it -- `voter/mod.rs` gates
a single re-export at line 18, declares its configuration at 22, and only opens its test
module at 52, so a suffix rule would hide the configuration. A `mocks` file is test support
throughout. Test sites are hidden unless `--tests` is passed (D45), because without that the
answer is mostly noise: of the forty occurrences of the voter mailbox's `resolved`,
thirty-eight are tests and one is the sending actor. Without rust-analyzer there is no tree,
and the fallback looks only for a `#[cfg(test)] mod`, which is the shape that does run to the
end of a file.

### 5.8 Syntax trees

`rust-analyzer parse` reads one file on stdin and prints its concrete syntax tree with a byte
span on every node. It wants no cargo, no project and no index, and costs about a tenth of a
second for a file of two thousand lines, so `statelens.py ast` answers from it the two
questions section 5.7 cannot.

**Polarity.** The index records that a line mentions an entity, not whether it reads or
writes it, because the read and write role bits are unset. An assignment is a shape: the
token after the field expression is `=` or an `op=`. `ast sites` reports each site as a
write, an initial value in a struct literal, a `maybe`, or a read, which is what decides
whether a probe belongs there. A `maybe` is the field handed out, as the receiver of a method
call or by a `&mut` borrow, and is printed with what was done to it (`.push(..)`, `&mut`):
the tree carries no types, so `push` and `len` are one shape to it, and the prompts tell the
agent to read those sites rather than take them for reads, since `push`, `insert` and `take`
are transitions as much as an assignment is. `--writes-only` keeps them. For the same
reason a field and a method of one name are one spelling to the tree (D46). Identity comes
from the index, which also says which two or three files to parse rather than all of them.
A `PATH` given to either query may be a file or a directory, which stands for every `.rs`
file under it, so an actor's directory can be passed whole; a path that is neither is a
usage error.

**Macro bodies.** This command parses source, and parsing does not expand macros, so the body
of a macro invocation is one unstructured token tree: it holds the tokens but no expressions.
A name there can be neither a read nor a write by shape, so `ast sites` reports it as `macro`
rather than dropping it or guessing, and `ast notes` leaves such a comment without an item.
Containment is asked of the ancestor chain, so a body of any length is recognised; a bounded
search back through the nodes would treat a token deep inside a long body as though it were
outside a macro, and drop it.
This is not a rare corner in this crate, which puts much of its concurrency inside `select!`:
`view` has 183 such sites and `round` 179 (D47). A site reported this way has to be read.

**Comments.** A comment is a token here, so it can be told from the same words in code or in
a string, and `ast notes` pairs each comment block with the item it documents. A doc comment
and an attribute are both children of the item they belong to and both come before its
keyword, so a documented item is the nearest enclosing item that the comment leads, and
whether it leads is decided by looking for the item's first token that is neither. Comparing
start offsets instead fails as soon as anything precedes the comment. An ordinary comment
inside a body documents what follows it, bounded by the scope it sits in rather than by a
count of nodes, and a comment inside a macro body documents nothing, there being no
structured item of that body to name. Consecutive comment tokens are one block, because a doc comment of
several lines is several tokens and only the block documents the item. This is the material of the beacon step's first question, the comments
about orderings, races, recovery, and cases that cannot happen.

**Following a value.** Neither section answers what a data-flow tool would, and none of the
tools that do fits: one cannot follow a value across a call at all, another answers whether a
marked source reaches a marked sink from one chosen entry point, and none crosses an actor
mailbox. The agent is therefore the simulator, and these two sections are what confirms or
rejects each step it proposes. `prompts/discover-flow.md` (section 13.16) is that method,
and the instrumentation prompts point at it; it also carries the two bridges that do work
across a hop: the message variant names both the sending function and the handler arm, and
a dispatched request is followed to the handler that completes it, which is where an action
decided in one function becomes visible outside the replica.

### 5.9 Script tests

`just check-scripts` runs `scripts/test_statelens.py`, which covers the paths that fail
quietly rather than loudly: a result tuple compared against an exit code, a SCIP range read
as four elements when a definition on one line has three, and an assignment classified from
the wrong sub-expression. Each of these returned a plausible wrong answer, so each test is
written to fail without its fix. The tests need no network and no campaign; the ones that
read a syntax tree skip when rust-analyzer is absent. Two classes cover claims rather than
mechanics: `PlanClaims`, a plan whose `Status` promises more than its own `Sites` ledger or
the instrumented code supports, and `PromptCopies`, a prompt that has drifted from its
verbatim copy in section 13. `QmdbProfile` materializes the qmdb profile against the
checkout itself, without writing, and checks that it touches storage only. `SemanticSearch`
builds an index with a fake embedder, so no model is needed, and checks what each source
contributes, what an update embeds again, and what a query may reach. Target-State Synthesis
adds `TargetStateLint` (rules 12 and 13), `ExtractStates` (the new kinds, routing by
disclosure, the post-checks), `ScaffoldSelection` (patterns, the skip rule, `--redo`),
`Synthesize` (guards 1 to 6 of section 18.6.1, with stub agents, the test inventory, an
interrupted synthesis, revalidation after a card, `--redo` and the last check, an interrupted
revalidation completed by the next synthesis, and the last check's build), `SynthesisManifest` (the
renamed `[[bin]]` block), `ReachCheck` (the lines of section 18.8, each witness rejection
rule, truncation, the control, the verdicts and crash attribution) and `ReachVerdictCommand`
(the `reach-verdict` command: REACHED exits 0, a missed stage is PARTIAL with exit 1, a
missing control UNVERIFIED), and extends `Cleaning`,
`JustfileProfiles`, `PromptCopies` and `TestGate` (the forced nextest rendering and the
validation of a run's output). Tests write to
temporary directories only, never to `SL/`, and their fixture repositories commit unsigned,
so a global signing configuration cannot fail them.

### 5.10 Semantic search

`kb search` is the paper's on-demand retrieval: a question in plain words, answered with
ranked snippets that connect it to files and functions (R-KB-9, D58). It answers from an index
that `just search-index` builds in `SL/extract/search/`, which git ignores.

**What is indexed.** Four sources, cut along paragraphs into chunks of at most 1,000
characters, and a longer line between words, each part keeping its line number. With the
model loaded, a chunk is also halved until its heading and text together fit the model's
window, measured by its own tokenizer: 256 tokens for MiniLM. Characters say little about
tokens in identifier-heavy text, and the model ignores whatever lies past its window.

| Source | Chunks | Each carries |
|---|---|---|
| `finding` | The state-bearing sections of every finding, the only ones `kb show` serves | Identifier, section, state, modules, severity, remediation status, cited files and symbols |
| `kb` | The Markdown of each corpus root's `kb/` and `context/`, by heading; `config/` is not indexed | Path, heading, lines |
| `code` | Every comment block of every Rust file at HEAD: `//!` documents its module, `///` the item after it, and a plain comment the function or item it sits in | `path:line@commit`, the item, and whether it is test code |
| `doc` | Every Markdown file at HEAD outside `SL/`, by heading | `path:line@commit`, heading |

Lines marked `[statelens]` are never indexed. The code and the documentation are read from
the commit at HEAD through `git cat-file`, not from the worktree, so a hit's citation holds in
an instrumented checkout, and instrumentation never reaches the index. The item of a comment
comes from indentation rather than a parser: walking up, a less indented `impl`, `fn`,
`struct` or the like encloses it.

**Test code.** A file is test code when its path is test support (`mocks`, a `tests/` or
`benches/` directory), when a test-only declaration names it, `#[cfg(test)] mod name;` with
its `#[path]` if it has one, or when it opens with `#![cfg(test)]`. In any other file, each
item under a test-only `#[cfg(...)]` is test code, from the documentation and attributes
above it to the brace, `;` or `,` that ends it. Test-only means `test`, or an `all(...)` that
requires it; `any(test, ...)` is compiled into feature builds too and is not. A file merely
named `tests.rs` is not test code by its name.

**Files.** A build writes a new generation, a directory `generation-<n>/` holding
`chunks.jsonl`, each chunk with its text, its metadata and a hash of what is embedded, and
`vectors.f32`, one row of little-endian 32-bit floats per chunk. It writes the generation
under a temporary name and renames it into place whole; only then does it switch
`manifest.json` to name it, by an atomic rename, and remove every other generation. The
manifest records the generation, the model, the dimension, the commit, the count per
source, and why there are no vectors when there are none. An interrupted build leaves the
previous generation current and complete, and a generation whose files do not add up to
its manifest reads as no index, never as text paired with another text's vector.
Publication holds `SL/extract/search.lock` exclusively from staging to cleanup, and a query
holds it shared while it reads the manifest and the generation it names. Two refreshes at
once, a campaign's and a manual one, therefore take turns, and neither deletes the
generation the other made current or one a query is reading. The lock is advisory, lives
beside the index directory so that cleanup never removes it, and is released by the kernel
if its holder dies.

**Building and updating.** `just search-index` reads every source, reuses the vector of every
chunk whose embedded text is unchanged, and embeds the rest on the CPU. `--rebuild`, or a
model other than the one the manifest names, embeds everything again. The model is
`STATELENS_SEARCH_MODEL`, a Hugging Face name or a local directory. It is loaded from disk
first and downloaded only when it is not there, so a build that has the model needs no
network. Without numpy and sentence-transformers, or without the model, the index holds the
chunks without vectors and the command exits 2. A campaign updates the index during setup,
where it refreshes the knowledge-base index (section 7.4), before anything is instrumented,
and continues with a warning when it cannot.

**Querying.** `kb search --registry R QUESTION...` keeps the findings whose `module` passes the
registry's filter (R-KB-5), the documents, and the code and documentation, without test code
unless `--tests` is given. `--path` narrows the code and documentation to directories, and
`--source` narrows the search to some of the four sources. BM25 over words and identifier
parts ranks the chunks, and so does the cosine similarity of their embeddings to the
question's; reciprocal rank fusion merges the best 200 of each (D58). A query loads the model
with the hub offline, so it never uses the network; without vectors or the model it ranks by
words alone and says why. Ties keep index order, so one index gives one answer.

**Output.** Per hit: its source and where it is, which is a finding's identifier and section,
a document's path and lines, or a code or documentation `path:line@commit` with the item;
then up to four lines of its text, and for a finding its state, modules, severity,
remediation status and cited files and symbols. A last line gives the number of chunks in
scope, how they were ranked, and the commit of the code and documentation.

**Cost.** Measured on this checkout at commit `7b5ab24d1f10`, with all-MiniLM-L6-v2 on a laptop
CPU:

| | |
|---|---|
| Chunks | 41,172: 36,337 code, 1,270 doc, 3,357 finding, 208 kb |
| Index size | 63 MB of vectors and 22 MB of chunks |
| First build | 61 s, embedding 39,810 distinct chunks |
| Update with nothing changed | 12 s, embedding none; about 5 s of it measures chunks against the window |
| One query | about 3 s, most of it loading the model |

---

## 6. Phase 1: discover invariants

### 6.1 Sources

| Kind | Source syntax |
|---|---|
| `issue` | GitHub URL of an issue or pull request, or `owner/repo#N` |
| `design` | Local path or URL, with an optional `#section` suffix |
| `comment` | File or directory under the registry's source (`consensus/src/simplex`, `consensus/src/marshal` or `storage/src/qmdb`), optionally `path:line` or `path:start-end`; any other path is refused, and a path outside the repository is pointed to `kb` |
| `spec` | Quint, TLA+ or Lean file, optionally `path:line` |
| `paper` | Local PDF or text file, or URL, with an optional `#page=N` suffix |
| `kb` | Knowledge-base corpus roots, or none for `STATELENS_KB`. The findings whose `module` is in the registry's filter (section 5.6) are the sources. |

Several sources of one kind MAY be passed at once (R-P1-1). Local paths are relative to
the repository root, which is the agent's working directory. Target states are extracted
from these kinds and from `test` and `text` (section 18.4).

### 6.2 Procedure

1. Validate `KIND`, the registry, `--number` (at least 1), and that at least one source is
   given, except for `kb`. A `comment` source must lie under the registry's source. For
   `kb`, resolve the corpus roots as section 5.6 does, from the sources or else from
   `STATELENS_KB`, refresh the index, and take the findings whose `module` is in the
   registry's filter; none is an error (exit code 2). The agent's `kb` commands read the
   same roots, so the script sets `STATELENS_KB` to them for the agent.
2. Record the content hash of every file of the four registry trees, `SL/invariants/`,
   `SL/invariants.local/`, `SL/target-states/` and `SL/target-states.local/` (section 18.3),
   in all registries, whichever kind the run writes, because the local trees are ignored by
   git and so escape the worktree snapshot; and
   record the same whole-worktree snapshot Phase 2 takes for its scope check (section 7.5):
   every path `git status --porcelain --untracked-files=all` lists, with a hash of its
   content. A Phase 1 agent may write anywhere in the tree it runs in, and that tree is the
   operator's own, so the registry alone is not enough to watch.
3. Compute `NEXT_ID`, which is global (section 4.1).
4. For `paper`, convert each local `.pdf` source (ignoring a `#...` suffix) to text in
   `SL/extract/papers/<stem>-<digest>.txt`, where `<digest>` is the first 10 hex digits of
   the SHA-256 of the resolved path, so papers with the same file name do not overwrite
   each other. Convert with `pdftotext -layout`, falling back to `pypdf`. When
   neither is available, pass the PDF as is. List the text next to the source.
5. Render the prompt: `prompts/analyst.md`, a blank line, then
   `prompts/analyst-<KIND>.md`. Placeholders: `KIND`, `NEXT_ID`, `TEMPLATE` (the content
   of `templates/invariant.md`), `SOURCES` (one `- <source>` line per source, with
   `(text: <path>)` appended for converted papers, or for `kb` one line per finding with its
   state, severity, remediation status and summary), `REGISTRY` (the registry name),
   `DESTINATION` (`SL/invariants/<registry>`, or `SL/invariants.local/<registry>` for `kb`),
   `COUNT` (what `--number` asks, D56), `QUERY` (the `kb` commands of section 5.6, used by
   `analyst-kb.md`), `CONTEXT` (the content of `prompts/subsystems/<registry>-analyst.md`),
   `SOURCE_ROOT` (the registry's source, as in section 6.1) and `COMMIT`
   (`git rev-parse --short=12 HEAD`, the commit the agent pins every line it cites to).
   When a tracked file outside this subproject differs from `HEAD`, warn that a line the
   agent cites in it may not match the commit.
6. Run the agent with the Phase 1 invocation (section 12), or for `kb` the one that reaches
   the corpus only through the `kb` commands, working directory = the repository root,
   prompt on standard input. Log to
   `SL/extract/<UTC timestamp>-<kind>.log`.
7. New files = files that did not exist in step 2. Report any pre-existing file whose
   hash changed as a problem ("agent modified or deleted an existing invariant", or card),
   any new file outside the destination ("agent wrote outside the registry"), and, with
   `--number N`, more than N new files. Compare the
   worktree snapshot too, and report every path the agent changed outside the four registry
   trees ("agent changed a file outside invariants/"), excepting this subproject's own
   `extract/` and `campaign/`, which the script writes itself and names rather than
   trusting a `.gitignore` to hide.
8. Write the Source excerpts section of each new file that pins a citation (section 4.3),
   then lint the new files (section 4.6).
9. Print each new file with its title, the count against `--number` when given, and the
   reminder: "Every file in a registry is used by the next campaign that binds it. Review,
   edit or delete these files first." For `kb`, add that the files are in the ignored local
   registry and must not be committed as they are.

---

---

## 7. StateLens for Simplex

This chapter specifies StateLens for the Simplex subsystem: the campaign of the `simplex`
profile, which instruments the code and generates the fuzz target (Phase 2, sections 7.1
to 7.9), and how the operator runs the target (Phase 3, sections 7.10 to 7.12). Where a
rule depends on the profile, it says so; chapter 8 gives what differs for marshal, and
chapter 17 what differs for qmdb.

### 7.1 Preconditions and setup

A campaign runs in place in the checkout (D10); `repo` is its root
(`git rev-parse --show-toplevel`). StateLens never makes another clone.

1. Check the preconditions, in this order. Each failure exits with code 2; the last two
   ask for a fresh clone:
   - `cargo`, `cargo-nextest`, `cargo-fuzz` and `just` are on `PATH` (the agent CLI is
     checked before), so a missing tool fails before any agent time is spent;
   - none of `consensus/src/simplex/statelens.rs`, `storage/src/qmdb/statelens.rs`,
     `consensus/fuzz/simplex/fuzz_targets/*_statelens.rs`,
     `consensus/fuzz/marshal/fuzz_targets/*_statelens.rs`,
     `storage/fuzz/fuzz_targets/*_statelens.rs`, `consensus/fuzz/simplex/src/target_states/`
     and `consensus/fuzz/marshal/src/target_states/` exists (an earlier campaign of any
     profile, or a synthesis, already instrumented this checkout; the scaffolds' thin targets
     match the `*_statelens.rs` globs);
   - `git status --porcelain --untracked-files=no` lists no path outside `SL/`.
2. `base = git rev-parse HEAD`.
3. Recreate `SL/campaign/` with `logs/`, `prompts/` and `meta.json`: `base`, `agent`,
   `model`, `profile`, test and fuzz toolchains, start time, the IDs bound (`invariants`)
   and the number collected before any selection (`invariants_available`, step 4), and
   `targets` (the StateLens targets the campaign builds).
4. The invariants to bind are those of the profile's registries, in the order of section
   5.5. For each registry they are `SL/invariants/<subsystem>/*.md` and
   `SL/invariants.local/<subsystem>/*.md`, sorted by ID, then
   `SL/false-invariants/<subsystem>/*.md` when `STATELENS_FALSE_INVARIANTS=1`. Uncommitted
   files are included. With `--invariants LIST`, given once or more, keep of them only the
   ids the lists name, in the same order (D69). A list is comma-separated and blank items
   are ignored; an id is `<registry>/INV-NNNN`, or `<registry>/FALSE-NNNN` when the false
   invariants are collected; a bare `INV-NNNN` is qualified with the profile's only registry,
   and refused when the profile binds two (`--invariants: INV-0001 is a bare id, but the
   marshal profile binds 2 registries (simplex, marshal); write <registry>/INV-0001`). An id
   of a registry the profile does not bind, an id no collected file provides, and a
   selection that keeps nothing each exit with code 2, with a message that ends in
   `available: <registry>/<ID>, ...`. The selection changes this step's result and nothing
   else: the batches and the audit of section 7.3 cover the ids kept, and the beacon step
   (section 7.4) runs as always, because probes are feedback, not oracles. Lint every file
   of these directories (section 4.6), selected or not, and print any problem as a warning.
5. Create `SL/campaign/plan.md` with this content, then fill in the values; `<count>` and
   the lists per registry are the invariants step 4 bound, so with a selection the selected
   ones only, and a registry none of them belongs to reads `none`:

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

6. Print the setup line `campaign: profile <profile>, <n> invariant(s), <t> target(s) at
   <base> with <agent>`, with the first ten characters of `base`. With a selection the count
   reads `<k> of <n> invariant(s) bound (<registry>: <ID, ID, ...>; ...)` instead, where `<n>`
   is the number step 4 collected before the selection and `<k>` the number it kept.

All steps run with working directory `repo` unless stated otherwise. The campaign never
commits, stages, stashes or resets anything, apart from `git add --intent-to-add` on the
files the campaign creates (section 7.2) and on the files its agents create under the
profile's editable roots (section 7.5).

### 7.2 Step 1: materialize

This section gives the edits of the `simplex` profile. The `marshal` profile makes edits 1
to 3 and 6 to 8, and edits M1 to M3 with its own cryptography check (sections 8.3 and
8.4). The `qmdb` profile makes edits 7 and 8, and edits Q1 to Q5 (section 17.3).

Before any edit, the script checks the cryptography rule (D15). For every simplex target the
profile derives a variant from (section 5.5), and every call of a fuzz entry point in it,
`fuzz::<P` or `fuzz_<name>::<P`, `consensus/fuzz/core/src/simplex.rs` MUST contain
`impl Simplex for P {` with `type Scheme = cert_mock::Scheme<` inside that impl block. A
target that fails the check, or that contains no such call, aborts the campaign with exit
code 2 and a message that names the target and `P`.

Each edit that uses an anchor MUST find exactly one line equal to the anchor. A missing
or repeated anchor aborts the campaign with exit code 2 and a message that names the
file and the anchor.

| # | File | Edit |
|---|---|---|
| 1 | `consensus/src/simplex/statelens.rs` | Create as a copy of `SL/runtime/statelens.rs`. |
| 2 | `consensus/src/simplex/mod.rs` | After the line `pub mod types;` insert `pub mod statelens;`. |
| 3 | `consensus/Cargo.toml` | After the line `thiserror.workspace = true` insert `sancov.workspace = true`. |
| 4 | `consensus/fuzz/simplex/fuzz_targets/<stem>_statelens.rs`, one per variant | Derive from `<stem>.rs` (Appendix B.1). |
| 5 | `consensus/fuzz/simplex/Cargo.toml` | Append one `[[bin]]` block per variant, each derived from its original's (Appendix B.2). |
| 6 | `consensus/fuzz/core/src/lib.rs` | After the line `let compromised = case.compromised.iter().copied().collect::<HashSet<_>>();` (with four leading spaces) insert the hook of Appendix B.3. |
| 7 | `runtime/src/deterministic.rs` | Before the line `impl From<Config> for Runner {` insert the static of Appendix B.4. |
| 8 | `runtime/src/deterministic.rs` | After the line `pub fn new(cfg: Config) -> Self {` (with four leading spaces) insert the call of Appendix B.4. |
| 9 | `consensus/fuzz/simplex/src/byzzfuzz/runner.rs` | After the line `commonware_consensus_fuzz_core::setup_network::<P>(context, input).await;` (with eight leading spaces) insert the ByzzFuzz hook of Appendix B.5. |
| 10 | `consensus/fuzz/simplex/src/chaos/twins.rs` | After the line `let crash = (0..n).find(\|&idx\| idx != byz).expect("an honest index exists");` (with eight leading spaces) insert the Chaos-Twins hook of Appendix B.5. |
| 11 | `consensus/fuzz/simplex/src/lib.rs` | Before the line `// A Byzantine participant may behave correctly. For the audit` (with sixteen leading spaces) insert the audit hook of Appendix B.5. |
| 12 | `consensus/fuzz/simplex/src/mallory/runner.rs` | After the line `lifecycle::abort_tasks(mv).await;` (with four leading spaces) insert the Mallory hook of Appendix B.5. |

Anchors in the same file are applied from the bottom up, so earlier insertions do not
move later anchors.

Then run `git add --intent-to-add` on the files it created, so that `git diff` shows
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
   (`statelens/campaign/plan.md`), `CHECK` (section 7.6), `RUNTIME` and `RUNTIME_MODULE`
   (the profile's runtime module, as a path and as the path code calls it by, section
   5.5), `FUZZ_PACKAGE` (the profile's fuzz package), `INVARIANT_IDS` (comma separated),
   `INVARIANTS` (for each file, a line `===== <path from repo root> =====` followed by its
   content), `REGISTRY` (the batch's registry) and `SUBSYSTEM_RULES` (the content of
   `prompts/subsystems/<registry>-instrument.md`).
4. Run the agent with the Phase 2 invocation (section 12). Save the prompt to
   `SL/campaign/prompts/invariants-<registry>-<n>.md` and the output to
   `SL/campaign/logs/invariants-<registry>-<n>.log`.
5. A non-zero agent exit aborts the campaign with exit code 2.
6. After the beacon step of section 7.4, audit the bindings, unless `STATELENS_AUDIT`
   is `0`. It is the last agent pass, so the tree it reviews is the tree the plan lint of
   section 7.5 fingerprints and the build hands over (section 7.6). For each
   batch of step 2, render `prompts/instrument.md`, a blank line, then
   `prompts/instrument-audit.md`, with the placeholders of step 3, and run the agent as in
   step 4 with `audit-<registry>-<n>` as the file stem. The pass re-reads each Statement,
   enumerates the sites that commit the actions it names, adds the checks that are missing
   and can be added, and corrects the `Sites` ledger, the `Status` and the `Notes` of the
   plan section. A first pass writes both the binding and its own status, and nothing
   there compares the two; this is where a binding that is silently incomplete, rather
   than wrong, is found.
   The verdict is per batch, and a later batch edits the same files. After each batch the
   campaign keeps the text of every subsystem source and compares it with the batch
   before. A later batch that adds new items, or new StateLens checks beside existing
   code, changes nothing an earlier batch reviewed. One that changes or removes a line,
   adds other lines inside an existing function body (a `let` that shadows, an early
   `return`, a call that prunes a ghost history, a `/*`), or puts an attribute or a
   comment opener above an existing item, may have touched an earlier binding's
   assertion, ghost update or helper, which nothing reviews again: the bindings of every
   earlier batch are then reported unreviewed, with the batch and each edit, on the
   `coverage` line of section 7.9 and in the plan summary. The audit prompt tells the
   agent to add new items and checks rather than edit, for that reason.
7. Record the statuses before and after the pass. The ones that changed go in the summary
   (section 7.9) as `<ID> <before> -> <after>`.

### 7.4 Step 3: beacon probes

For each beacon component of the profile (section 5.5), render `prompts/instrument.md`, a
blank line, then `prompts/instrument-beacons.md`. Placeholders: `BASE`, `PLAN`, `CHECK`,
`RUNTIME`, `RUNTIME_MODULE` and `FUZZ_PACKAGE` as in section 7.3, `ACTOR` and `ACTOR_DIR`
from the profile table, `SUBSYSTEM_RULES` of the component's
subsystem, and `QUERY`, the knowledge-base commands of section 5.6 with the concrete command
line for each, carrying the `module` filter of the component's subsystem. Run and log as in
section 7.3, with `beacons-<ACTOR>` as the file stem. This step runs before the audit of
section 7.3 step 6, so that no agent edits the tree after the audit.

The agent discovers the beacons in this step. It reads the component's code, where a
candidate announces itself as a state enum, a `debug_assert!`, a per-view flag or a comment
about a race, and it queries the knowledge base when a candidate needs developer context the
source does not carry: what an assumption means, why it matters, whether it has failed
before, or which code manages the transition. The campaign resolves the corpus roots during
setup (section 7.1) and refreshes the index before the first agent step, so a query costs no
corpus walk. It also updates the search index of section 5.10 there, and `QUERY` carries the
`kb search` line whenever that index exists. When `STATELENS_KB` names no readable root, the
campaign says so, `QUERY` holds the `kb search` line at most, and the step proceeds from the
code and the search index.

### 7.5 Step 4: finalize the plan and check scope

1. Parse `plan.md`: headings `### <ID>: <title>` and lines `- Status: bound|partial|unbound`.
2. For every bound ID (section 7.1 step 4) without a heading, append a section with
   `Status: unbound` and `Notes: not processed by the agent`.
3. Run the plan lint of section 5.4 over `plan.md` and print each problem as a warning.
   The plan is the agent's own account of what it bound, so a problem here is reported to
   the operator rather than failing the campaign.
4. Take a new snapshot (section 7.2) and compare it with the baseline. Every path that is
   new, changed or gone since the baseline:
   - outside the profile's editable roots (section 5.5) aborts the campaign with exit
     code 2 ("instrumentation edited <path>"), except `Cargo.lock`, which the first build
     updates for the new `sancov` dependency;
   - under a warn-only path of the profile produces a warning;
   - with an added call of the read side of section 9.6 (`watch`, `unwatch`, `tick`, `mark`,
     `current_run`, `truncated`, `seen`, `sites`, `observations` or `note` of the runtime
     module), outside the runtime module itself, aborts the campaign with exit code 2
     ("instrumentation calls the read side: <path> (<names>)"), because the read side is for
     scaffolds. A call counts when the code reaches the function through the runtime module:
     by path (`statelens::seen`), through an alias the file gives the module (`rt::seen` after
     `statelens as rt` or `statelens::{self as rt}`), or by importing it by name
     (`statelens::{seen, ...}`), each once.
     Comments and string literals do not count, and neither does a bare `seen(`, because the
     read side's names are common words; a glob import of the module escapes the check
     (section 18.11). The counts are compared with the file at `base`, since materialize
     adds no such call under the editable roots.
5. Run `git add --intent-to-add` on every untracked file under the editable roots (files
   the agents created; no content is staged), so that `git diff` and the counts include
   them. Then count the deleted lines under the editable roots (`git diff --numstat`),
   the added `sl_assert!`, `sl_implies!` and `sl_probe!` call sites, and the beacon table
   rows.
6. Append a `## Summary` section to the plan with the status counts, the commit sites the
   `Sites` ledgers list and how many of them are not checked, the call-site counts, the
   assertion sites per instrumented source, the beacon-table row count and the deleted-line
   count. Deleted lines are expected to be 0; any other value must match the "Edited lines"
   entries of the plan. When the summary is rewritten after a repair that made the audit
   stale (section 7.6), an `Audit: stale` line names the files the repair changed.
7. Write `SL/campaign/instrumentation.diff` with the output of `git diff`.

### 7.6 Step 5: build and repair

Commands, run in order:

1. `CHECK`: `cargo +<test toolchain> check -p commonware-<crate> --lib --tests`, where
   `<crate>` is the profile's crate (section 5.5): `consensus`, or `storage` for qmdb.
2. `FUZZBUILD`: `cargo +<fuzz toolchain> fuzz build --fuzz-dir <fuzz package> <variant>`,
   for each StateLens variant of the profile in turn; the first failure is the one the
   repair step sees.

The fuzz toolchain is `STATELENS_FUZZ_TOOLCHAIN`, or the value of `NIGHTLY_VERSION:` in
`.github/workflows/slow.yml`, or `nightly`.

On a failure, run a repair attempt: render `prompts/instrument.md`, a blank line, then
`prompts/repair.md`. Placeholders: `BASE`, `PLAN`, `CHECK`, `RUNTIME`, `RUNTIME_MODULE`,
`FUZZ_PACKAGE`, `ATTEMPT`, `COMMAND` (the failing command), `ERRORS` (its last 150 output
lines), `SUBSYSTEM_RULES` (the parts of all the profile's subsystems, in the order of
section 5.5). Run the agent, repeat the section 7.5 scope check, then run both commands
again. After 3 failed attempts, exit with code 3. After a successful repair, run the plan
lint of section 7.5 step 3 again and rewrite the summary and
`SL/campaign/instrumentation.diff` (steps 5 to 7): a repair may remove or change an
assertion, and the lint count the campaign reports must describe the tree it hands over,
not the tree the audit saw.

The semantic audit of section 7.3 is not repeated, and the lint cannot stand in for it: a
repair that rewrites a condition under the same invariant id, site and function passes the
lint. So the campaign records what the audit's verdict stands for -- a digest of every file
under `consensus/src/simplex/`, `consensus/src/marshal/` and `storage/src/qmdb/`, the
sources the lint scans
(helpers and ghost state included, not only the macro calls), and of the plan without the
summary the script appends -- taken at the first plan lint, which follows the audit, the last agent pass. After a successful repaired build, every recorded
path whose digest differs is a file the repairs changed after the audit; the audit is then
stale, the plan summary says so, and the `coverage` line of section 7.9 reports the campaign
`UNVALIDATED` with those files, whatever the lint found. Only a campaign with a new audit
clears that. The repair prompt makes the agent downgrade the invariant and its ledger
rather than weaken a check, which the campaign cannot verify; the stale mark is what makes
that limit visible.

### 7.7 Step 6: test gate

~~~
cargo +<test toolchain> nextest run -p commonware-consensus --lib --no-fail-fast \
  --ignore-default-filter \
  --color never --message-format human --status-level pass --final-status-level fail \
  --success-output never --failure-output immediate \
  -E '(test(/^simplex::tests::/) & not test(/::test_twins/)) | test(/^simplex::statelens::/)'
~~~

Log to `SL/campaign/logs/test.log`. The reporter flags fix the output synthesis parses (section
18.6.1, guard 5); a flag overrides `NEXTEST_STATUS_LEVEL`, `CARGO_TERM_COLOR` and nextest's
user configuration. On failure, print the `FAIL` lines and every
`[statelens][` line, write the summary (section 7.9), and exit with code 4. The whole
gate is 240 tests and took 125 s on 16 cores at the verified commit. The `marshal`
profile adds the marshal tests (section 8.3, step 6). The `qmdb` profile runs the qmdb
tests of the storage crate instead, all of them gated, and has no component tests (section
17.3, step 6).

The fuzz targets are built before the gate runs, so a failed gate leaves them in place. A
failure without a `[statelens][` line is a test the instrumentation broke rather than an
invariant it caught, and the operator judges whether it reaches the targets: a test double
the harnesses do not use cannot. `just fuzz <profile|target> --skip-campaign` then fuzzes the
built targets without a new campaign, which would refuse the instrumented checkout.
After a fix to the instrumented checkout, `just test` runs this command alone, so the
fix is checked before fuzzing it.

**Component tests.** The gate is the engine-level tests: the ones that run whole replicas
against each other, where every actor produces the evidence the others' checks read. The
crate's other simplex tests drive one actor, type or scheme with states built by hand, where
a check that reads evidence another actor would have produced finds none, and a test may
deliberately construct the state an invariant forbids to see the component tolerate it.
Those tests are not the gate, but they are not hidden either: after the gate passes, the
campaign runs

~~~
cargo +<test toolchain> nextest run -p commonware-consensus --lib --no-fail-fast \
  --ignore-default-filter \
  --color never --message-format human --status-level pass --final-status-level fail \
  --success-output never --failure-output immediate \
  -E 'test(/^simplex::/) & not test(/^simplex::tests::/) & not test(/^simplex::statelens::/)'
~~~

logging to `SL/campaign/logs/test-components.log`, and names every failed test on the
`components` line of the summary (section 7.9). They are reported, not gated: a failure is
a mismatch between a check and a test that runs below the check's scope, for the operator
to judge, and it never changes the result. They are 516 tests and a few seconds once
built. `just test` runs them after the gate in the same way.

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
statelens: invariants <n> (bound <b>, partial <p>, unbound <u>)[; inactive in the fuzz targets: <ID>, ...]
statelens: audit      <ID> <before> -> <after>, ... | no status change [stale: a repair changed the tree after it]
statelens: plan       <n> commit site(s) listed, <u> not checked, <p> lint problem(s)
statelens: coverage   UNVALIDATED: <p> plan lint problem(s), so the code does not support the counts above; a repair changed <f> validated file(s) after the audit (<path>, ...), so the audit and the statuses describe the tree before it; run a campaign with a new audit before relying on them; no audit pass ran (STATELENS_AUDIT=0), so the statuses are the binding agent's own claims; audit batch <name> changed existing lines of <path>, ... after the verdict on <ID>, ..., which were not reviewed against them
statelens: sites      <k> assertion sites, <m> probe sites, <d> deleted lines
statelens: components <f> failed, not gated: <test>, ...; see campaign/logs/test-components.log | all passed
statelens: result     READY | STOPPED after <step> | PANIC (tests) | BUILD FAILED | SETUP FAILED
statelens: reason     <why the campaign stopped, for any result other than READY>
statelens: panic      <first [statelens][...] line, or the first panic message>
statelens: run        cd <repo>/statelens && NIGHTLY_VERSION=<fuzz toolchain> just run simplex_cert_mock_twins_mutator_statelens -- -rss_limit_mb=4000 -print_final_stats=1
statelens: replay     cd <repo>/statelens && CONSENSUS_FUZZ_LOG=1 NIGHTLY_VERSION=<fuzz toolchain> just run simplex_cert_mock_twins_mutator_statelens <repo>/consensus/fuzz/simplex/artifacts/simplex_cert_mock_twins_mutator_statelens/<crash file>
~~~

The `run` and `replay` lines appear only with `READY`, one pair per StateLens variant of
the profile. Both run through `SL/justfile`, whose `run` recipe finds the package that
defines the target: `consensus/fuzz`'s own `run` for a consensus target, `storage/fuzz`
for a `qmdb_*` one. The crash file is an absolute path, because cargo-fuzz runs in the
package's directory. The `replay` line is a template: the operator puts in the crash file
that libFuzzer wrote, and adds the `STATELENS_BYZANTINE` value of the run that found it
(section 7.11).

The `invariants` line names after the counts the invariants whose `Status` carries
`(inactive in the fuzz targets)` (section 11): bound or partial as the ledger says, but
never evaluated by the targets, so a silent campaign says nothing about them. The
`coverage` line appears when the plan lint reports problems, which it does after a
successful repaired build as well as after the audit (sections 7.5 and 7.6), and when a repair changed a file
the audit's verdict stands for (section 7.6), when no audit pass ran (`STATELENS_AUDIT=0`), and when a later audit batch changed or
removed lines after an earlier batch's verdict (section 7.3 step 6), each reason in its own
clause: `READY`
then means the targets are built and the gate passed, and nothing more, because the plan's
claims are not supported by the code, the audit describes a tree that is gone, nothing but
the binding agent vouched for the statuses, or some bindings were reviewed before a later
batch edited what they rest on. A clean
lint does not clear the second reason. The `components` line reports the component tests
of section 7.7, which run after a passed gate and never change the result.

The `<n>` of the `invariants` line counts the plan's sections, which section 7.5 step 2
completes for every invariant the campaign bound, so with `--invariants` (section 7.1 step
4) it is the selected invariants, and the status counts describe them alone. The number
available is in `meta.json` and in the setup line `<k> of <n> invariant(s) bound` of section
7.1 step 6, which the summary does not repeat.

### 7.10 Phase 3: running a target

Phase 3 is manual (D23). The operator runs the StateLens fuzz targets that a `READY`
campaign built, in the instrumented checkout. StateLens has no command for this phase.

The `run` lines of the summary (section 7.9) give one command per target. For the
`simplex` profile, in `SL/`:

~~~
NIGHTLY_VERSION=<fuzz toolchain> just run simplex_cert_mock_twins_mutator_statelens -- \
  -rss_limit_mb=4000 -print_final_stats=1
~~~

`just fuzz <profile>` (section 5.3) runs every target of a profile this way, in turn, in
parallel batches or in tmux windows, `--fuzz-targets GLOB` narrows it to the targets a
shell pattern names, and `just fuzz <target>` runs one.

- The operator chooses which targets to run and adds libFuzzer arguments as needed, for
  example `-fork=<N>` to use N cores, or `-max_total_time=<s>` to bound the run.
- A run ends when the target panics or the operator stops it. libFuzzer, including its
  fork mode, stops at the first crash.
- The operator should not pass `-artifact_prefix` or `-exact_artifact_path`, which move the
  crash file elsewhere, or any `-handle_*` switch, which can stop libFuzzer from reporting
  a crash and saving its input.
- PRD sections 8.4 and 9.4 list the simplex and marshal variants whose adversary runs
  Simplex or marshal code; only they exercise the Byzantine guard.

### 7.11 Phase 3: crashes and replay

- libFuzzer writes a crashing input to the artifact directory of the target's package:
  `consensus/fuzz/simplex/artifacts/<variant>/` for a simplex variant,
  `consensus/fuzz/marshal/artifacts/<variant>/` for a marshal variant, or
  `storage/fuzz/artifacts/<variant>/` for a qmdb one (R-ART-1).
- The `replay` line of the summary, with the crash file put in, replays the input in the
  same checkout, and replay reproduces the panic (R-NF-2).
- Replay with the `STATELENS_BYZANTINE` value of the run that found the crash. A
  guard-test crash exists only with `STATELENS_BYZANTINE=panic`, and `check` changes which
  replicas are checked; without the same value, the input may run cleanly. For example:
  `STATELENS_BYZANTINE=panic` followed by the `replay` line.
- For a Simplex variant, `CONSENSUS_FUZZ_LOG=1` also prints the decoded input; the
  marshal harnesses do not read it.

### 7.12 Phase 3: investigation

The instrumented checkout stays as it is until the operator discards it. The operator
uses:

- `SL/campaign/plan.md`: how each invariant was bound;
- `SL/campaign/instrumentation.diff` (or `git diff`): every change the campaign made;
- `SL/campaign/logs/` and `SL/campaign/prompts/`;
- the crash file, replayed as in section 7.11.

To locate the code for an invariant: `rg '\[statelens\] INV-0007' --type rust`.

An instrumented checkout must not be committed or reused for another campaign; the next
campaign starts from a fresh clone.

### 7.13 Phase 3: coverage

`statelens.py coverage [--profile P] [TARGET...]` (`just coverage`) answers what the
corpora a run built actually reach. It takes a profile name, single StateLens targets, or
neither, in which case it covers every target of the default profile; a name beginning
`simplex_`, `marshal_` or `qmdb_` selects its own profile, as `just fuzz` reads it.

For each target with a corpus, in the instrumented checkout:

1. `cargo +<fuzz toolchain> fuzz coverage --fuzz-dir <profile package> <target>`, which
   rebuilds the target with coverage instrumentation and replays its corpus. A target with
   no corpus is skipped with a warning, and a profile where none has one stops the command
   with exit code 2.
2. `llvm-cov show` writes `<package>/coverage/html/<target>/index.html`, scoped to the
   profile's editable roots (section 5.5), so the pages carry the code the campaign
   instruments rather than every crate the harness links.
3. `llvm-cov report` writes two summaries beside it: `<target>.<subsystem>.txt` for each
   root, which leaves out the profile's warn-only paths and so reports the instrumented
   code, and `<target>.workspace.txt`, which leaves out only dependencies and the standard
   library.
4. With more than one target, `llvm-profdata merge -sparse` combines the profiles and the
   same reports are written again as `unified`, against every target's binary.

`llvm-cov` and `llvm-profdata` come from the fuzz toolchain's own sysroot
(`lib/rustlib/<host>/bin`), because a coverage mapping is only readable by the LLVM that
wrote it; a missing `llvm-tools-preview` component stops the command with the `rustup`
line that installs it. The coverage build and the reports live under the fuzz package's
`coverage/`, which `.gitignore` already covers.

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
instrumentation, and AC-9 to AC-13. The knowledge base, the beacon step and the audit pass
(sections 5.6, 7.4 and 7.3) were first exercised with a real agent by the qmdb campaign of
section 1.2, not by a marshal campaign, and no run of the procedures of AC-14 to AC-17 is
recorded (AC-16 and AC-17 cover the audit pass and this subproject's own checks).

### 8.2 Decisions

| ID | Decision | PRD requirement |
|---|---|---|
| D24 | StateLens variants are generated from the existing marshal targets, with two anchored insertions each, rather than kept as templates. The variant set therefore always equals the target set. | R-M-P2-1 step 1 |
| D25 | The `marshal` profile derives variants only from the targets of `consensus/fuzz/marshal`, so it adds no simplex variant (section 7.2, edits 4 and 5). | R-M-P2-1 step 1 |
| D26 | The wedge scenario gets its own guard hook (Appendix F). The Twins targets use edit 6, and the other targets need no hook. | G5 |
| D27 | Marshal code learns `me` from one source, `statelens::provider_me` (Appendix A), and never by looking its scheme provider up or by reading `me()` from a scheme the implementation holds. A lookup is not a read: an application may count lookups against a scope and retire it. The helper reads a `ConstantProvider`, whose lookup only clones its scheme and which every harness uses, and reports any other provider, or a missing signing scheme, as an unknown index without looking it up. One source keeps every site of a component armed or inert together. The core actor calls it once when it is created and copies the result into its mailbox; the standard adapters read it there; coding calls it in the method that owns its provider. An unknown index leaves a site uninstrumented at run time; `None` never stands for it. | R-M-INS-1 |
| D28 | The marshal beacon components are `marshal.core`, `marshal.standard` and `marshal.coding`. The backfill resolver, application gates, ancestry and store modules have no identity of their own, so they are instrumented at their call sites in these components. | R-FB-4, R-M-FB-1 |
| D29 | The test gate of the `marshal` profile adds `test(/^marshal::/)` to the filter of section 7.7. | R-M-P2-1 step 6 |
| D30 | The campaign builds every StateLens variant and runs none of them (D23). The operator chooses which variants to fuzz. | R-M-P2-1 step 7, R-M-P3-1 |

### 8.3 The `marshal` campaign

A `marshal` campaign follows section 7, with these differences.

Step 1, materialize. First the cryptography check of section 8.4. Then edits 1 to 3 and
6 to 8 of section 7.2, and:

| # | File | Edit |
|---|---|---|
| M1 | `consensus/fuzz/marshal/fuzz_targets/<target>_statelens.rs`, for every `marshal_*` `<target>.rs` in that directory | Derive it from `<target>.rs` as Appendix B.1 says: `commonware_consensus::simplex::statelens::reset();` as the first line of the body of its `fuzz_target!`, and `commonware_consensus::simplex::statelens::clear_compromised();` as the last. |
| M2 | `consensus/fuzz/marshal/Cargo.toml` | For every variant, append a `[[bin]]` block with `name = "<target>_statelens"` and `path = "fuzz_targets/<target>_statelens.rs"`, followed by whichever of the `test`, `doc`, `bench` and `required-features` keys the original target's block has. |
| M3 | `consensus/fuzz/marshal/src/marshal/end_to_end/scenario.rs` | After the line `        let router = Router::new([participants[Role::Byzantine.index()].clone()]);` (eight leading spaces), insert the hook of Appendix F. |

As in section 7.2, a missing or repeated anchor aborts the campaign with exit code 2
before any edit is made. `git add --intent-to-add` also covers the variants.

Step 2, bind invariants (section 7.3): the batches of the simplex registry come first,
with the Simplex subsystem rules, then those of the marshal registry, with the marshal
subsystem rules. The audit pass of steps 6 and 7 covers the batches of both registries,
each with its own subsystem rules.

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
  --color never --message-format human --status-level pass --final-status-level fail \
  --success-output never --failure-output immediate \
  -E '(test(/^simplex::tests::/) & not test(/::test_twins/)) | test(/^simplex::statelens::/) | test(/^marshal::/)'
~~~

At the reference commit, the marshal part is 421 tests and took 70.6 s on 16 cores. A
marshal test that runs two live marshal actors under one identity would share ghost state
and must be excluded, as the Twins tests are. None is known at the reference commit.

Step 7, hand-over (section 7.8): the summary gives a `run` and a `replay` line for every
variant, in the order of `consensus/fuzz/marshal/fuzz_targets/`:

~~~
statelens: profile    marshal
statelens: run        cd <repo>/statelens && NIGHTLY_VERSION=<fuzz toolchain> just run <variant> -- -rss_limit_mb=4000 -print_final_stats=1
statelens: replay     cd <repo>/statelens && NIGHTLY_VERSION=<fuzz toolchain> just run <variant> <repo>/consensus/fuzz/marshal/artifacts/<variant>/<crash file>
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
| Replica index | Through `statelens::provider_me(&provider, epoch)`, never by looking a provider up, whether through `scoped`, `scheme` or a method of the implementation that calls one (D27). Core actor: called once in `Actor::init` at the epoch it starts in, kept in a `// [statelens] me` field of type `Option<Option<Participant>>` and copied into a field of the same type on the `core::Mailbox` it creates. Standard adapters: read from the mailbox they hold. Coding adapter and shards engine: called at the epoch of the round in hand. |
| Modules without identity | The backfill resolver, the application gates and validation, ancestry and store are instrumented at their call sites in the components, never inside. |
| Unknown identity | Never pass `None` for an index that could not be obtained. Leave the site without instrumentation, and say why in the plan; where `provider_me` decides at run time, guard the site with `if let Some(me) = ...`, or write `me.and_then(|me| ...)` where the site yields a value. |
| Discretization | Heights relative to the processed floor, the last delivered height or the finalized tip. Never raw heights, digests, commitments or shard indices. |

Every harness at the reference commit gives each validator a `ConstantProvider` over its
own scheme: the Twins stacks, the scenarios, the store target and the marshal test harness.
`provider_me` reads those without an effect, so the index is known from the moment the
actor is created, in every fuzz run and in every test that uses them. Other marshal tests
use other providers -- `VerifierProvider`, `RetiringProvider`, `MultiEpochProvider`,
`ChurningProvider` and `EmptyProvider` -- and two of those count lookups: an extra lookup
made by instrumentation consumed the scope `RetiringProvider` keeps for admission and
failed four tests in a campaign. With them the index is unknown, and the sites of the
component built with them stay uninstrumented, so those tests run its original code only.
That costs the test gate (section 7.7) some screening, and it is larger than it sounds:
every unit test of the shards engine builds it with `MultiEpochProvider`, or once with
`ChurningProvider` (53 tests at the reference commit, all of its malicious-shard tests
among them), so the gate screens shards-engine instrumentation only through the coding
tests, which build the engine with a `ConstantProvider` through the marshal test harness.
Core and standard sites are inert in four `VerifierProvider`, four `RetiringProvider` and
one `EmptyProvider` test, and the coding adapter in one `EmptyProvider` test. An alarm that
only adversarial shard input raises therefore appears first while fuzzing. When the scheme
a `ConstantProvider` holds has no signer, `provider_me` returns `Some(None)`: that replica
is known not to be a participant, and it is checked without ghost state.

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

The full source is in Appendix A. This section specifies its behavior. The consensus
profiles copy it unchanged to `consensus/src/simplex/statelens.rs`. A qmdb campaign copies
it to `storage/src/qmdb/statelens.rs` with every `simplex::statelens` path renamed to
`qmdb::statelens`, and without the tests that start at the line
`// [statelens] consensus only:`, which build Simplex signing schemes the storage crate does
not have (edit Q1, section 17.3). Both copies behave as below. qmdb passes `None` as `me`
at every site, so the guard checks every site and only `Global` holds its ghost state.

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

While a scaffold watches, `sl_probe!` and `sl_implies!` also append what they record to the
probe trace of section 9.6, inside the guard; `sl_assert!` records nothing and appends
nothing.

`sl_implies!` is feedback as well as an oracle, but only where its recorded pair can vary on
a passing execution. A `post` of `false` records only `(false, false)`, because a true `pre`
panics, and a site on the branch the replica takes only once it is about to violate the
invariant records one pair as well. The binding then adds a probe where the state is
classified, so that reaching the protected state is rewarded when the replica handles it
correctly (R-FB-3). A constant `true` `post` is not that case: the pair follows `pre`.

### 9.3 Counter table

- `sancov::Counters<65536>` in a static.
- `record` sets `cell(site, a, b)` to 1 with an atomic store (presence, D3).
- `reset()` zeroes the table, clears the compromised set and all ghost state, drops the
  probe trace of section 9.6 and sets its event sequence to 0. In a `cfg(fuzzing)` build it
  registers the table with libFuzzer once, unless `STATELENS_FEEDBACK=0`.
- Once the table is registered, libFuzzer stops printing `cov:` because the table has no
  PC table. Compare runs by `ft:`.

### 9.4 Ghost state

- `Ghost`: one per replica, keyed by participant index. All actors and components of a
  replica share it, in both consensus subsystems. qmdb has no participant index and no
  `Ghost`.
- `Global`: one per run, shared by all honest replicas.
- Lifetime: one run. `reset()` clears ghost state before every fuzz input, and the
  fresh-run hook (Appendix B.4) clears it whenever a fresh deterministic runtime is
  created, for example for each seed of a multi-seed test. A runtime resumed from a
  checkpoint (a crash-restart) keeps it. The hook is registered on the first ghost-state
  access, and by `reset()` (section 9.6).
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

`STATELENS_REACH` and `STATELENS_REACH_CONTROL` are read by the scaffold helper (section
18.7), not by this module.

### 9.6 Read side

The read side lets a scaffold (section 18.7) ask which probes fired during its input. It keeps
an ordered trace of the probe observations of one input, off unless a scaffold watches, and one
event sequence per input, which orders those observations and the scaffold helper's events
together. The counter table and the features of section 9.3 are unchanged.

~~~rust
/// Most observations the trace of one input keeps.
pub const TRACE_CAP: usize = 1 << 20;

/// One probe observation of a watched input. Its fields are private, so only the
/// runtime makes or changes one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Seen {
    label: &'static str,
    site: &'static str,
    me: Option<u32>,
    a: u32,
    b: u32,
    seq: u64,
    run: u32,
}

impl Seen {
    /// The `sl_probe!` label, or the invariant ID of an `sl_implies!` site.
    pub const fn label(self) -> &'static str {
        self.label
    }

    /// The call site, `concat!(file!(), ":", line!(), ":", column!())`.
    pub const fn site(self) -> &'static str {
        self.site
    }

    /// The participant index of the observing replica.
    pub const fn me(self) -> Option<u32> {
        self.me
    }

    /// The first recorded value; `pre` at an `sl_implies!` site.
    pub const fn a(self) -> u32 {
        self.a
    }

    /// The second recorded value; `pre && post` at an `sl_implies!` site.
    pub const fn b(self) -> u32 {
        self.b
    }

    /// The position of the observation in the event sequence of the input, from 1.
    pub const fn seq(self) -> u64 {
        self.seq
    }

    /// The runtime instance of the input that made it, from 1.
    pub const fn run(self) -> u32 {
        self.run
    }
}
~~~

| Item | Behavior |
|---|---|
| `pub fn watch()` | Starts an empty trace for this input. The event sequence goes on from its current value. Only the scaffold helper, `target_states/mod.rs`, calls it (guard 3, section 18.6.1). |
| `pub fn unwatch()` | Stops keeping observations and drops the trace. Only the scaffold helper calls it (guard 3, section 18.6.1). |
| `pub fn tick() -> u64` | Advances the event sequence and returns its new value, which is greater than every position issued earlier in the input, to an observation or by a `tick`. While not watching it returns 0 and advances nothing. Only the scaffold helper, `target_states/mod.rs`, calls it (guard 3, section 18.6.1); a recording wrapper stamps an entry through the helper's `stamp` (section 18.7). |
| `pub fn mark() -> u64` | The last position issued in the input, to an observation or by a `tick`, without advancing the sequence; 0 before the first. |
| `pub fn current_run() -> u32` | The runtime instance current on this thread, from 1; 0 before the first runtime of the input. The helper reads it for a `restart` line and for the `run` a stamp or an action records (section 18.7). |
| `pub fn truncated() -> Option<u64>` | The position of the first observation the trace dropped because it held `TRACE_CAP`, or `None` while it has dropped none; a later drop does not move it, and `watch`, `unwatch` and `clear_trace` reset it. A dropped observation still advances the sequence, so positions stay unique and ordered, and what the trace holds from that position on is incomplete. |
| `pub fn seen(label: &str, site: Option<&str>, since: u64, f: impl FnMut(&Seen) -> bool) -> Option<Seen>` | The earliest observation at or after position `since`, of the `run` current at the call, with `label`, at `site` when one is given, that `f` accepts. `None` while not watching. |
| `pub fn sites(label: &str) -> Vec<&'static str>` | The sites at which the trace holds `label`, in order of their first observation. A scaffold finds a site this way, never as a literal, because synthesis edits move lines. |
| `pub fn observations(since: u64) -> Vec<Seen>` | Every observation at or after position `since`, of every `run`, oldest first. |
| `#[doc(hidden)] pub fn note(me: Option<Participant>, label: &'static str, site: &'static str, a: u32, b: u32)` | While watching, advances the event sequence and appends an observation with the new value as its `seq`, unless the trace holds `TRACE_CAP` observations; `truncated` then keeps the position of the first one it drops. Only the macros call it. |

`Seen` has private fields and no public constructor, so only the runtime makes or changes one;
a scaffold reads it through its getters.

**Wiring.** `sl_probe!` and `sl_implies!` call `note` after `record`, inside the guard, with
their call site; `sl_implies!` does so before its violation branch, so a violating observation
is in the trace. The fresh-run hook (Appendix B.4) becomes `fresh_run`: it forgets ghost state
and then adds 1 to a thread-local run counter. `reset()` also calls the private `clear_trace()`,
which drops the trace and sets the run counter and the event sequence to 0, and registers the
hook, so the first runtime of every input has `run` 1, in replays and in fuzzing alike. A
runtime resumed from a checkpoint (`Runner::from(Checkpoint)`) and an engine restarted inside
one runtime keep `run`; a scaffold marks those boundaries (section 18.7).

**Lifetime.** One input. `reset()` drops the trace and the fresh-run hook does not, so a trace
spans every runtime of the input and each observation carries its `run`.

**Event sequence.** One thread-local counter per input, deterministic like the trace, which
advances only while a scaffold watches. Every observation and every helper event takes its own
value, its position: a witness read, an entry a recording wrapper stamps, a construction
action, a restart boundary, and the start and the mark of the handoff (section 18.7) each take
a `tick`. Positions are therefore unique and strictly ordered within an input, and two harness
actions with no observation between them still get distinct, ordered positions. `reset()` sets
the counter to 0, so positions are unique within one input only.

**Guard.** Observations are noted inside the guard, so under `skip`, the default, a compromised
replica is never observed. Under `check` it is, so a stage that reads the trace names its
replica. Reach replays run with `STATELENS_BYZANTINE` unset (section 18.8).

**Cost.** Not watching, which is every run but a scaffold's, costs a thread-local access and a
test per probe hit. Watching costs one increment and one `Seen` per hit, at most `TRACE_CAP`
`Seen` per input, freed by `unwatch` or `reset`. No I/O, lock, await or randomness (R-INS-3).

**Instrumentation never calls it.** The read side is for scaffolds: the Runtime API section of
prompt 13.7 says so; the scope check of section 7.5 refuses instrumentation that calls it, and
so does synthesis guard 3 (section 18.6.1).

**Placement.** The code goes before the line `// [statelens] consensus only:`, so the qmdb copy
(edit Q1) has it as well, and its doc comments name no `simplex::` path, which the script test
of the qmdb copy rejects. Its self-tests never call `reset()`, which zeroes the table that
the other tests share under plain `cargo test`; they call `clear_trace()`, which touches only
the thread-local trace, run counter and sequence. The read side adds 7 self-tests, so the
consensus copy has 19 and the qmdb copy 17 (section 18.1). `reset()` and the fresh-run hook's
registration use `OnceLock`, because the workspace's clippy configuration disallows
`std::sync::Once`.

---

## 10. Instrumentation conventions

The prompts in section 13.7 are normative for the agent. In summary:

| Topic | Rule |
|---|---|
| Editable code | A beacon run: its component directory and the code it calls (section 8.5). Otherwise the non-test code of the profile's subsystems (section 5.5): `consensus/src/simplex/`, except `mocks/` and `scheme/`, and for the `marshal` profile `consensus/src/marshal/`, except `mocks/`; for the `qmdb` profile `storage/src/qmdb/`, except `benches/`. Each invariant only in the code of its own subsystem. New-field initializers may be added to struct literals anywhere, including tests. In `statelens.rs`, only `Ghost` and `Global` fields and private helpers. |
| Additions only | No deleted or changed logic. The only allowed edit of an existing line is wrapping an expression in a block, keeping its tokens; each such edit is listed in the plan. |
| Markers | `// [statelens] <tag>` above every added statement, block, field or item. Tags: `INV-NNNN`, `ghost:INV-NNNN`, `beacon:<label>`, `ghost:beacon:<label>`, `me`. |
| Replica index | Simplex: `self.scheme.me()`; otherwise a `// [statelens] me` field of type `Option<Participant>`. Marshal: section 8.5. Never `None` for an index that could not be obtained. qmdb has no replicas and passes `None` at every site (section 17.4). |
| Non-interference | Observe program state without changing the semantics or control logic of the protocol or its implementation. Write only StateLens state: ghost state, probe counters, added `me` fields. No writes to existing variables, fields or collections (directly, through `&mut` methods or interior mutability); no methods whose reads change state that any code, tests included, can observe; no added `return`, `break`, `continue` or `?` that leaves or skips original code; no channel endpoints, `Arc`s (such as blocks) or values with a `Drop` effect kept in ghost state; no block clones; no `await`, spawn, lock, runtime context, RNG, clock, network, storage I/O, metrics or logging; no reordering or consuming of values. Exception: forcing a memoized decode (`Lazy::get`, `==` on a `Lazy`), even on original values, and keeping clones of decoded messages that hold `Bytes`, such as votes. |
| Panics | Only through violations: saturating or checked arithmetic, no `unwrap` or `expect`, no out-of-bounds indexing. |
| Cost | O(1) per site, or bounded by what the code tracks (the views of a replica, the operations of a batch). Ghost history outlives the implementation's pruning and is therefore not bounded by them: index it for the question the assertion asks, and maintain the index where the history is written, rather than walking it at the assertion. |
| Warnings | Denied workspace-wide. Use full paths rather than new imports. |
| Discretization | No raw views, heights, locations, digests, commitments, keys, values, payloads or timestamps. Views, heights and locations relative to another known one (a location against the inactivity floor or the log size). At most about 64 `(a, b)` pairs per probe, counted before the probe is written (`bucket` 6, `delta` 11, `flag` 2, an n-bit mask 2^n, `disc` the variant count, `pack` the product of what it packs), not estimated from the combinations a run is expected to reach; a smaller count only where the site bounds the input, with the bound in the plan. No replica index in probe values. |
| Adversarial input | Assert what the honest replica or the database does or keeps, not what peers, sources or provers send. |
| Asynchrony | Checks across actors, components or calls hold for every delivery delay and interleaving the implementation allows. |
| Commit sites | An invariant about an action is checked where the action becomes visible outside the replica or the database (a signature exists, a message reaches a mailbox or the broadcaster, a record is appended, a certificate is accepted, the view moves; a batch is applied, a commit becomes durable, a root, a value or a proof is returned), on every path that reaches it, including journal replay, recovery and retries. Where a decision and its commit are split across an await, a mailbox or a later call, the commit site carries the check; a check at the decision does not replace it. The plan lists every commit site and whether it is checked. |

---

## 11. Instrumentation plan format

Agents add sections under `## Invariants`:

~~~markdown
### INV-0007: <title>
- Status: bound | partial | unbound, followed by `(inactive in the fuzz targets)` when the
  targets never evaluate the check
- Reading: <pre and post, or the checked condition, in code terms>
- Sites: <one line per site that commits an action the Statement names: the action in
  plain words, then the file and the function in backticks (everything backticked after
  the file is read as a function), then `checked` or `not checked`, and for `not checked`
  the reason>
- Assertions: <file, function, macro and condition; one line each>
- Probes: <extra probes such as margins, or "none">
- Ghost state: <fields and where they are updated, or "none">
- Edited lines: <existing lines wrapped in blocks, or "none">
- Notes: <why partial or unbound; limitations, or "none">
~~~

`Status` is a claim about coverage, and a campaign that never panics is read as evidence
for it. `bound` means every commit site of every action the Statement names carries the
check and the condition checked is the Statement itself. `partial` means anything less: a
weaker condition, a site left out, a path left out, with the reason in `Notes`. `unbound`
means nothing was added, and such a section needs only `Status` and `Notes`. A binding
that watches the decision and not the commit is `partial`, however exact its condition.
A qualifier may follow the status, `partial (inactive in the fuzz targets)` or
`bound (inactive in the fuzz targets)`, for a binding whose `pre` no target of the
profile reaches, which the harness under `consensus/fuzz/<package>` decides (every target
uses the `cert_mock` scheme, which hides the signer set; a floor is reached only in marshal's
standard Twins targets, from `MarshalTwinsInput.floor`, and its actor store target, through
`StoreOp::SetFloor`), however many unit tests with real schemes reach it; the summary names such
invariants apart from the status counts, because activation is a different claim from
binding and a silent campaign says nothing about an inactive check.
`statelens.py lint-plan` (section 5.4) checks a section against its own ledger and against
the instrumented code, and that the plan is plain ASCII like the registry and the prompts.
The ledger is not taken on trust either: each entry names its source and its function in
backticks, which is how the lint reads it, and says `checked` or `not checked`; an entry
that says `checked` must have an assertion naming the invariant in the function it names,
so one assertion cannot certify every site of its file. The assertions are read out of the
code with a textual scan, after the comments and the `#[cfg(test)]` items of each file are
blanked (the test items come from the syntax tree of section 5.8, or from the `#[cfg(test)]
mod` fallback without it), so an assertion quoted in a comment or placed in a test module
certifies nothing. Items are located on the text with every literal blanked as well, so a
string spelling `fn` opens nothing: a site is attributed to the function whose body holds
it, qualified by the type of the `impl` block around it, and to nothing when no body does.
A ledger entry `Type::f` names that method alone, so neither `Other::f` nor a free function
`f` certifies it; a bare ledger name `f` is a less precise claim, satisfied by any function
or method of that name. `impl` blocks are the only containers modelled: a method of a trait
definition is attributed bare, and a function nested in a method carries the impl's type.
The type is kept as the `impl` header spells it, so a claim may give `prunable::Archive::sync`
or its tail `Archive::sync`, and a tail that fits two types in one file is reported as
ambiguous. A string literal that quotes
an assertion macro is blanked with the comments. Without
rust-analyzer the fallback knows only a `#[cfg(test)] mod`, so a gated function or impl
outside one counts as production there. The lint establishes that the plan and the code
agree, not that an assertion executes: that is the test gate's and the targets' part. What no lint can see is a commit site the ledger never
names; that is what the audit pass of section 7.3 is for, and why the summary also reports
the distribution of assertion sites over files, where a layer nobody checked shows up as a
file with none.

Agents also add rows to the beacon table:

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
| `claude` | `claude -p --output-format text [--model M] [--effort E] --permission-mode acceptEdits --allowedTools Read Grep Glob Write Edit WebFetch "Bash(gh:*)" "Bash(curl:*)"` | `claude -p --output-format text [--model M] [--effort E] --dangerously-skip-permissions` |
| `codex` | `codex exec -C <repo root> [-m M] [-c model_reasoning_effort=E] -s workspace-write -c sandbox_workspace_write.network_access=true -` | `codex exec -C <repo root> [-m M] [-c model_reasoning_effort=E] --dangerously-bypass-approvals-and-sandbox -` |

Notes:

- Both CLIs read `AGENTS.md` or `CLAUDE.md` from the working directory. The Phase 2
  prompt states that its rules take precedence during a campaign.
- Phase 2 agents have unrestricted access to the host (D4). The README MUST say that
  campaigns run on a dedicated machine or container. Being unrestricted is also what lets
  the instrumenter run the `kb` commands of section 5.6; its prompt says when to.
- The model `M` is `STATELENS_CLAUDE_MODEL` or `STATELENS_CODEX_MODEL` and the effort `E`
  is `STATELENS_CLAUDE_EFFORT` or `STATELENS_CODEX_EFFORT` (section 5.1). An empty value
  leaves the flag out, so the CLI's own default applies; a value is passed through
  unchecked, because each CLI owns its levels and is the one to reject a wrong one. Both
  go into `SL/campaign/meta.json`, so a campaign records what produced it.
- The script checks that the chosen CLI is on `PATH` before any other work, except that
  `synthesize` first reports usage errors and the preconditions that read
  `SL/campaign/meta.json` (section 18.6.2).
- `extract kb` runs Phase 1 with the corpus reachable only through the `kb` commands of
  section 5.6: `claude` gets `Read Grep Glob Write Edit WebFetch` and
  `"Bash(python3 statelens/scripts/statelens.py kb:*)"` instead of `gh` and `curl`, and
  `codex` runs in its workspace-write sandbox with the network off.
- `extract --states` runs as `extract` does: the Phase 1 invocation, or for `kb` the one
  above. `synthesize` runs its agent with the Phase 2 invocation (section 18.6): the agent
  builds its scaffold but never runs it, the script replays it (section 18.8), and the edit
  contract and its guards, not the agent CLI, bound what it changes.

---

## 13. Prompts (verbatim)

### 13.1 `prompts/analyst.md`

~~~markdown
# StateLens invariant analyst: extract invariants

You are a senior security engineer who specializes in the kind of system that Context
describes. Read the sources listed at the end and write invariants for the `{{REGISTRY}}`
registry of StateLens in this repository.

## Context

{{CONTEXT}}
- Every file in `{{DESTINATION}}/` is used by the next fuzzing campaign
  that binds this registry. An agent turns each invariant into assertions in the code, and a
  fuzzer drives the code with the adversary described above until an assertion fails. A
  wrong invariant costs a human investigation. A vague one cannot be checked.

## What makes a good invariant

- It holds in every execution for the system Context names, including every execution its
  adversary can cause.
- It constrains what the system does or keeps: the honest actions in Context. It never
  requires the adversary to behave.
- It uses the terms in Context. It never names Rust types, functions, fields or files;
  those go in "Observation hints".
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

Write the Statement as one sentence in one of these patterns, where `<system>` is the
system Context names (for example `replica`, written "the replica").

- Ubiquitous: `The <system> shall <response>.`
- State-driven: `While <state>, the <system> shall <response>.`
- Event-driven: `When <trigger>, the <system> shall <response>.`
- Unwanted behavior: `If <condition>, then the <system> shall <response>.`
- Complex: `While <state>, when <trigger>, the <system> shall <response>.`

Use `shall not` for prohibitions. If no pattern fits, write one precise sentence and
explain why in the Rationale.

## Output

- Write one file per invariant: `{{DESTINATION}}/<ID>.md`.
- {{COUNT}}
- Use IDs starting at `{{NEXT_ID}}` and increasing by one with no gaps.
- Follow the template below exactly: the same front matter keys and section headings,
  in the same order. Delete optional sections you do not use.
- Set `source_kind: {{KIND}}`. Make `source_ref` as precise as you can: URL,
  `path:line@{{COMMIT}}`, document section, or paper page.
- A line number means something only at one commit, and the code moves after you. Write
  every line you cite, in `source_ref` and in the text alike, as `path:line@{{COMMIT}}`
  (or `path:start-end@{{COMMIT}}`), with the path from the repository root;
  `{{COMMIT}}` is the commit of the tree you are reading. Never write a bare "line N".
  Where a heading or a name identifies the place, name it instead: a quote from a
  document can carry its section, and Observation hints, which describe the code a later
  campaign instruments, name functions, types and fields, never lines.
- Cite the whole comment, block or property that states what you rely on, as a range, not
  only its first line. Do not write a `## Source excerpts` section: when you finish, the
  script copies the lines you cite into it, as they read at `{{COMMIT}}`.
- Plain ASCII only. Wrap lines at 100 characters.
- Do not modify or delete existing files, create other files, or write code.

When you finish, reply with a list of the files you wrote (ID, title, one line of
evidence), or with the reason you wrote none.

## Template

```markdown
{{TEMPLATE}}
```

## Example

The example shows the format; it comes from the simplex registry, whose system is the
replica.

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
  and why that was wrong.
- Write the invariants the bug violated. Generalize beyond the specific fix so that the
  invariant also catches variants of the bug on other code paths, while staying true
  for every correct execution.
- Cover both sides of the bug where they apply: what the system must never do (the
  wrong action, or the state that made it crash), and what it must do instead at that
  moment. For example, a crash on a malformed message has two sides: the replica shall
  not panic on it, and the replica shall reject it and keep processing other messages.
- Also write the expected outcome: what the system should have produced in the reported
  situation, given the inputs it had (a vote, a certificate, a batch, a state change), as
  an event-driven statement.
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
- Extract every rule the document states or implies the system in Context follows, of
  the kinds listed in Context.
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
  `panic!` in non-test code. Ignore test modules, `mocks/` and `benches/`.
- Look for conditions the author relies on: "must", "never", "always", "only", "cannot
  happen because", "invariant", "at most", "before", "after". Each one is a candidate.
- Restate each candidate in the terms of Context. Keep Rust identifiers out of the Statement
  and put the code location and identifiers in "Observation hints".
- source_ref is `path:line@{{COMMIT}}` of the comment or assertion, with the path from the
  repository root.
- Skip comments that describe mechanics without stating a condition.
~~~

### 13.5 `prompts/analyst-spec.md`

~~~markdown
## How to read a formal specification

- The sources are Quint, TLA+ or Lean files, optionally with `:line`. Read the named
  invariants and temporal properties, the assertions, and the guards and effects of
  the actions that model the system in Context.
- Translate each invariant, and each action guard that encodes a safety rule (for
  example "vote to finalize only if the view was not nullified"), into an EARS
  statement about the system Context names. Keep the exact meaning.
- Record modeling assumptions the implementation may not share (a fixed number of
  replicas, bounded views, a static leader, no crashes) under "Preconditions /
  assumptions".
- source_ref is `path:line@{{COMMIT}}` of the property or action, with the path from the
  repository root, or a URL that names a commit for a specification outside it.
~~~

### 13.6 `prompts/analyst-paper.md`

~~~markdown
## How to read a paper

- The sources are papers or articles: a PDF or text file, or a URL, optionally with a
  page. When a text extraction is listed next to a PDF, read the extraction and use the
  PDF only for figures.
- Read the description of the protocol or data structure, the lemmas and theorems, and
  their proofs. Properties that the proofs rely on are the best candidates.
- The implementation may differ from the paper; Context says how it relates to it. When
  you are not sure that a property from the paper applies to the implementation, still
  write it and describe the doubt in the Rationale; a human will decide.
- source_ref is the paper title with page and section.
~~~

### 13.7 `prompts/instrument.md`

~~~markdown
# StateLens instrumenter

You are instrumenting code in this repository for a StateLens fuzzing campaign. Your
changes turn English invariants into runtime assertions, and add state probes that tell
the fuzzer when an execution reached a new internal state.

## Where you are

- This checkout is a throwaway clone at commit `{{BASE}}`, instrumented in place for one
  fuzzing campaign. Nobody will review, merge or reuse your changes. The repository conventions in AGENTS.md and CLAUDE.md about public API
  stability, documentation, benchmarks, dependencies, commits and pull requests do not
  apply here. The rules in this prompt take precedence.
- Do not commit. Do not run the tests or the fuzzer; the campaign runs the tests after you.
  Do run the check command at the end of this prompt until it passes.
- Read `{{RUNTIME}}` first. It is the runtime support module.
- A fuzzer will drive this code with the adversary the subsystem rules describe. Any
  panic you cause is reported to a human as a possible bug, so a false alarm wastes their
  time and a missed check hides a bug.

## Scope

- You may edit the non-test code that the subsystem rules below allow. Non-test code is
  code outside `#[cfg(test)]` items and `tests` modules.
  You may add initializers for new fields to struct literals anywhere, including tests,
  when the compiler requires them.
- In `statelens.rs` you may only add fields to `Ghost` and `Global`, and private helper
  functions.
- Do not edit anything else: no `Cargo.toml`, no fuzz target or harness, no other
  crate.

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
   without instrumentation and say so in the plan. A subsystem whose rules say it has no
   replicas passes `None` at every site, and the guard checks every one.
4. Observe, do not interfere. Instrumentation observes program state without changing the
   semantics or control logic of the protocol or its implementation: until an invariant is
   violated, the code takes the same branches, keeps the same state, and sends, writes and
   returns the same things as the original code. Write only StateLens state: ghost fields,
   `Ghost` and `Global`, and the `me` fields you add. Do not assign to or mutate existing
   variables, fields or collections, whether directly, through `&mut` methods, or through
   interior mutability (`Cell`, `RefCell`, atomics), and do not call methods whose reads
   change state that any code, tests included, can observe (for example an LRU `get` that
   changes the eviction order, or a scheme-provider lookup, which an application may count
   against the scope it serves). Exception: you may force a memoized decode, such as
   `Lazy::get` or `==` on a `Lazy`, even on original values. No other cache is exempt:
   filling `CodedBlock::shards`, for example, runs an erasure encode, can panic, and
   changes what `shard()` returns. Do not add a `return`, `break`, `continue` or `?` that
   can leave or skip original code. Do not keep in ghost state a handle whose count or
   lifetime any code, tests included, can observe: channel endpoints, `Arc`s such as
   blocks, or values whose `Drop` has an effect. Do not clone blocks; keep a block's
   digest and height instead. Clones of decoded messages that hold `Bytes`, such as votes,
   are fine. Do not `await`, spawn tasks, take locks, or use the runtime context, RNG,
   clock, network, storage I/O, metrics or logging. Do not send or reorder messages, and
   do not move or consume values the original code uses later; clone small values if you
   need them after a move.

   The trap worth naming: reading a short-circuited condition eagerly changes what runs.
   Given `if self.in_window(view) && !self.parent_ready(view) { return None; }`, hoisting
   both calls into locals makes `parent_ready` run even when `in_window` is false, which
   the original never did. Keep the guard:
   `let ready = if in_window { Some(self.parent_ready(view)) } else { None };`
5. No accidental panics. Only an invariant violation may panic. Use saturating or
   checked arithmetic (tests run with overflow checks). Do not use `unwrap`, `expect`,
   or indexing that can go out of bounds.
6. Bounded cost: O(1) per site, or bounded by what the code itself tracks (the views a
   replica tracks, the operations of one batch). Do not scan unbounded collections or
   allocate per message or per operation on hot paths unless an invariant requires it.
   Ghost history is the trap: you keep it precisely because it outlives the
   implementation's own pruning, so it is not bounded by what the code tracks.
   Index it for the question you will ask -- a second set holding only the entries you
   query, or a field holding the last one -- and keep the index up to date where you write
   the history. Never filter or walk the whole history at the assertion.
7. The workspace denies all warnings: no unused variables, imports or functions. Prefer
   full paths (`{{RUNTIME_MODULE}}::bucket(...)`) to new `use` lines.
8. Inputs are adversarial: a message a replica receives, or a proof or a sync response a
   database is given, can contain anything. Assert what the code itself does, keeps or
   accepts, not what its inputs claim, unless the invariant is about how it handles bad
   input.
9. Work is split across time. Actors and components run concurrently and exchange
   messages through mailboxes, and a database computes a batch in one call and applies
   it in another. A check that compares components must hold for every delivery delay
   and every interleaving the implementation allows, not only when they are in step. The
   same split decides where a check belongs: where the code decides to act in one
   function and performs the act in a later one, such as the handler of a reply,
   everything that happened in between is invisible at the first site, so the check goes
   where the act becomes visible outside: to peers, to the application, or on disk.

## Runtime API (`{{RUNTIME_MODULE}}`)

- `sl_assert!(me, "INV-NNNN", cond, "fmt", args...)` panics with
  `[statelens][INV-NNNN] replica=<i> <message>` when `cond` is false.
- `sl_implies!(me, "INV-NNNN", pre, post, "fmt", args...)` records the probe
  `(pre, post)` and panics when `pre` holds and `post` does not. `post` is evaluated
  only when `pre` holds.
- `sl_probe!(me, "label", a, b)` records the state `(a, b)` at this call site. `a` and
  `b` must be `bool`, `u8`, `u16` or `u32`.
- Invoke the macros by path, for example
  `{{RUNTIME_MODULE}}::sl_implies!(me, "INV-0007", pre, post, "...")`, with `me` obtained
  as the subsystem rules say.
- Discretization: `bucket(n: u64) -> u32` (0, 1, 2, 3-4, 5-8, 9+),
  `delta(a: u64, b: u64) -> u32` (signed distance, bucketed), `flag(bool) -> u32`,
  `pack(high: u32, low: u32) -> u32` (two values below 2^16), `disc(&value) -> u32`
  (enum variant code, payload ignored). Views convert with `view.get()`.
- Ghost state: `with_ghost(me, |g: &mut Ghost| ...)` gives one `Ghost` per replica,
  shared by all its actors and components. `with_global(me, |g: &mut Global| ...)` gives
  one `Global` shared by all honest replicas, for `protocol` invariants, and is the only
  ghost state of a subsystem without replicas. Both return `None` without running the
  closure for a skipped replica. Never nest them. Add the fields you need to `Ghost` or
  `Global`, with `Default` types. Ghost state lives for one run: it is cleared when a
  new run starts (every fuzz input, every seed of a test) and kept across a
  crash-restart within the run. Tests also start replicas, or open databases, on storage
  they wrote directly, standing for an earlier run, so no ghost history lies behind what
  such a replica restores. Where a check needs evidence of an earlier event, accept what
  the code itself holds -- a value passed along with the act, or one it restored from
  storage -- and rely on ghost history only for what the implementation keeps nowhere.
  `Ghost` is keyed by participant index, and a Twins run puts two engines behind one
  index, so history that must not merge across engines belongs in a
  `// [statelens] ghost:` field of the struct that owns it. To check it from another
  module, add a read-only accessor beside the field and tag it like the field; do not
  move the field to reach it.
- Assertion messages start with the invariant title and include the values involved,
  for example `"no finalize after nullify: view={} nullified={}"`.
- Never call the read side of the runtime (`watch`, `unwatch`, `tick`, `mark`,
  `current_run`, `truncated`, `seen`, `sites`, `observations` or `note`): it is for
  scaffolds, and the campaign stops at its scope check when instrumentation calls it.

## Discretization rules

- Never feed raw views, heights, locations, digests, keys, values, signatures, payloads or
  timestamps to a probe. Record positions relative to another the code knows, such as a
  view against the last finalized view (`delta(view.get(), last_finalized.get())`) or a
  location against the inactivity floor, and counts through `bucket`.
- Keep each probe's value space small: at most about 64 distinct `(a, b)` pairs. Count
  them before you write the probe, rather than trusting the spread to stay small in
  practice: `bucket` is 6 values, `delta` is 11 (it buckets the distance in each
  direction), `flag` is 2, a mask of n bits is 2^n, `disc` is the number of variants, and
  `pack` multiplies the two it packs. Multiply the two sides. Count fewer only where the
  site itself bounds the input, and say in the plan what bounds it. Over budget, drop a
  dimension or coarsen one into fewer categories.
- Do not include the replica index in probe values.

## The plan

Keep `{{PLAN}}` up to date, in plain ASCII. Add your sections and rows; do not rewrite
other parts.

For each invariant, add under `## Invariants`:

    ### INV-NNNN: <title>
    - Status: bound | partial | unbound, followed by `(inactive in the fuzz targets)`
      when the targets never evaluate the check
    - Reading: <pre and post, or the checked condition, in code terms>
    - Sites: <one line per site that commits an action the Statement names: the action
      in plain words, then the file and the function in backticks (everything backticked
      after the file is read as a function), then `checked` or `not checked`, and for
      `not checked` the reason>
    - Assertions: <file, function, macro and condition; one line each>
    - Probes: <extra probes such as margins, or "none">
    - Ghost state: <fields and where they are updated, or "none">
    - Edited lines: <existing lines wrapped in blocks, or "none">
    - Notes: <why partial or unbound; limitations, or "none">

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
   not as facts. "Source excerpts" show the code the invariant was written against, at the
   commit each names; the code may have moved or changed since, so find today's sites with
   the tools below rather than by those lines.
2. Find where the implementation establishes and uses the concepts. Trace with search,
   references and call hierarchy across the components the subsystem rules name,
   including the mailbox messages between them and the recovery path on restart.
   From the root of the repository, with
   `SL=statelens/scripts/statelens.py`, the command
   `python3 $SL code refs|callers|callees <NAME>` gives references and call hierarchy
   by symbol, which matters because names here collide: `proposal` is five different
   methods. `python3 $SL ast sites <NAME>` says which of those sites assign the state,
   which hand it out to a method or a `&mut` borrow (`maybe`, with the method name: the
   tree cannot tell `push` from `len`, so read those), and which only read it. Both hide
   test sites unless you pass `--tests`, and the
   `callers` of a mailbox method name the actor that sends the message. The guide
   `statelens/prompts/discover-flow.md` is the method for the cases
   where this is not enough.
3. Name the actions the Statement constrains, and find the commit site of each one: the
   point past which the action is visible outside the component that takes it, and the
   first point at which a violation is observable. A signature exists, a message is
   handed to a mailbox or to the broadcaster, a record is appended to the journal, a
   certificate is accepted, the view counter moves; a batch is applied, a commit becomes
   durable, a root, a value or a proof is returned. List every site that reaches it, on
   every path: the live one, the retry or rebroadcast, and replay or recovery after a
   restart.
4. Assert at the commit sites, not where the action was decided. The replica usually
   decides in one function and commits in another: it picks a parent and asks the
   application to build on it, and the proposal reaches the network in the handler of the
   reply, with every message the replica handled in between already applied. The state
   your `pre` reads at the decision is not the state the replica acted on, so a check
   there proves nothing about the action. Read the history inside the assertion, at the
   commit; the act's own parameters come from the decision, as they must, but the state
   you test against them is read here. Put the check after the last guard that can still
   abandon the act and before the call that performs it: a response the handler drops for
   a view the replica has left never reached the network, and asserting on it is a false
   alarm. Keep a second check at the decision
   site when it helps -- it names the cause, and its probe feeds the fuzzer -- but it
   never stands in for the commit site. That a later site "only records what the
   application returned" is not a reason to skip it: what the replica hands to the
   network is the action.
5. Map the EARS pattern to a macro. Ubiquitous: `sl_assert!`. State-driven,
   event-driven, unwanted behavior and complex: `sl_implies!(pre, post)`. For
   properties about history ("after", "once", "never again"), record the history in
   ghost state (`with_ghost` for one replica, `with_global` for scope `protocol` or for a
   subsystem without replicas, or a `// [statelens] ghost:` field when the history
   belongs to one object) and assert at the later action.
6. Add the probe the assertion cannot give. `sl_implies!` records `(pre, pre && post)`,
   which is what rewards the fuzzer for reaching a precondition -- unless that pair cannot
   vary on an execution that passes. It cannot when `post` is `false` (the only passing
   pair is `(false, false)`, since a true `pre` panics), and it cannot when the assertion
   sits on the branch the replica takes only once it is about to do the forbidden thing.
   Then the site teaches the fuzzer nothing: add a `sl_probe!` where the state is
   classified, recording the classification, so that reaching the protected state is
   rewarded even when the replica handles it correctly. A constant `true` `post` is not
   this case: the pair follows `pre` and already carries the feedback. For a numeric
   invariant, add a margin probe as well:
   `sl_probe!(me, "INV-NNNN/margin", {{RUNTIME_MODULE}}::bucket(distance), 0u8)`,
   where `distance` is how far the state is from a violation.
7. Be faithful: the code must check exactly the Statement. Never check something
   stronger, because that creates false alarms. If you can check only part of it, bind
   that part and set Status to `partial` with the reason. If you cannot bind it, add
   nothing for it and set Status to `unbound` with the reason. The status is a claim
   about coverage, and a campaign that never panics is read as evidence for whatever it
   claims. `bound` means every commit site of every action the Statement names carries
   the check, and the condition checked is the Statement itself. `partial` means
   anything less: a weaker condition, a site left out, a path left out. `unbound` means
   nothing was added. A binding that watches the decision and not the commit is
   `partial`, however exact its condition.
8. Add the invariant's section to the plan, with the `Sites` ledger: one line per commit
   site of step 3, naming the action in plain words, then the file and the function in
   backticks (everything backticked after the file is read as a function)
   (`` `actors/voter/actor.rs` `Actor::process_proposed` ``), then `checked` or
   `not checked` in those words, and for `not checked` the reason and the delivery order
   that escapes it. `lint-plan` reads this ledger: it finds the entry by the file, and a
   site you call `checked` has to carry an assertion naming this invariant in the function
   you name.

### Readings that look right and are too strong

Rule 7 is where bindings go wrong, and always in the same direction: a Statement is checked
more strictly than it is written, and the assertion fires on correct behavior. The patterns to
watch for:

- **A negative read as its converse.** "Nullification must not cancel certification work" does
  not say the work survives; something else may legitimately end it in the same moment. Assert
  that this event did not cause it, not that it is still there.
- **A permission read as an obligation.** "The replica may retry" does not mean it must. An
  invariant about what is allowed is not an invariant about what happens.
- **A local rule read as a global one.** Same-view often does not mean same-term, and same-term
  does not mean always. Bind the scope the Statement gives, not the widest one that parses.
- **A property read as a synchronous one.** Two components reach a state through mailboxes, so
  "after X, Y holds" is not checkable at X. Record the history in ghost state and assert at Y.
- **An accident of today's code read as the rule.** If the Statement is silent about ordering
  and the code happens to be ordered, do not assert the order.

When you find only a weaker form is checkable, that is a `partial`, not a licence to round up.

### Readings that look right and are too weak

The section above guards one direction: a check stronger than the Statement, which fires on
correct behavior and wastes a person's time. This is the other direction, and it is quieter.
The condition is faithful, but it is evaluated where the forbidden state cannot appear, so the
campaign stays silent and the silence is read as evidence. The patterns to watch for:

- **The decision mistaken for the action.** The check sits where the work starts -- a request
  issued, a candidate chosen, a handle stored -- rather than where it is performed. Everything
  the replica learns while the work is outstanding is invisible to it. This is rule 4.
- **One path of several.** The same vote is signed on the live path and restored by journal
  replay; a certificate arrives from the batcher and from the resolver; a message is sent once
  and rebroadcast on a timer. A check on one path is a check on one path.
- **A value captured too early.** A local read before an `await`, before the implementation's
  own update, or before a guard that can change the answer, is the old value. Read the state in
  the assertion itself, in the same statement sequence as the action.
- **A precondition the site cannot reach.** If a guard just above returns for exactly the state
  the Statement forbids, your `pre` is false there forever: the assertion runs on every pass,
  its probe records one pair, and nothing is ever checked. Find the site where the forbidden
  state survives, or record the gap and set `partial`.
- **Absence of evidence read as evidence.** A check that passes when the ghost record it
  needs is missing -- `is_none_or(..)`, `map_or(true, ..)` or `unwrap_or(true)` on the lookup
  -- accepts every case it never observed: a block the replica restored, a write nobody
  recorded and a different block at the same height all look alike. A missing record is
  unknown, not satisfied. Require positive evidence keyed by the exact identity (height and
  digest, view and signer), from what the replica holds or restored; where none can be had
  without changing behaviour, make the evidence part of `pre`, so the case is not evaluated
  rather than passed, say in the Notes which cases are unknown, and set `partial`.
- **Validity read from who sent it.** A vote, signature or certificate is valid because it
  verifies, not because an engine produced, signed or published it. The guard skips only the
  replicas a fuzz target marks compromised, and the tests the campaign gates on also run
  Byzantine participants it is never told about: the real engine with a scheme that corrupts
  what it signs, whose published votes every other replica rejects. A ghost record of what a
  signer published says that it was sent, not that it is valid. When `pre` needs a message to
  be valid, take that from a verification the observing replica completed, or from its own
  construction, keyed by the exact message. The subsystem rules name the tests that do this.
- **A binding the campaign never evaluates.** A `pre` that cannot hold in the fuzz targets
  leaves the check silent there however many unit tests exercise it. Read what the targets
  of this campaign do from their harness in `{{FUZZ_PACKAGE}}` rather than assuming it; the
  subsystem rules say what it is known to provide. When no target of the profile reaches
  `pre`, write `Status: partial (inactive in the fuzz targets)` (or `bound (inactive ...)`
  when the sites and condition are complete) and the reason in the Notes, so the campaign
  reports it apart from the bindings its silence speaks for; when some targets reach it and
  others do not, name them in the Notes.

A check you cannot imagine failing is either a theorem about the line above it or a check in
the wrong place. Say which, in the Notes.

Full worked analyses of Simplex and marshal are in `statelens/examples/`. They are reference
material: they *derive* invariants, which is Phase 1 work, while your job is to bind the ones
below, and their local labels (`INV-A1`, `M1` and so on) are not registry ids.

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
identify an entity with the code index; query the knowledge base with one of the commands
below; add a probe.

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
state it concerns, and the files and symbols it cites, and the design documents beside them.
`kb cites {{ACTOR_DIR}}` is the fastest way to see which findings are about the code in front
of you, and what they name. `kb search` takes a question in plain words and ranks by meaning
as well as by the words you chose, across the findings, the design documents, and the
comments, doc comments and Markdown of the whole repository. Ask it what the source raises
and does not answer -- why an assumption holds, what happens when it fails -- and read the
code a hit points at before you rely on it. When nothing is listed above, there is neither a
knowledge base nor a search index: work from the code alone.

A finding tells you which states have gone wrong before, so a state it describes is worth
probing even when the code looks unremarkable. It never tells you to add an assertion: a
finding is evidence, not a property, and this task adds probes only.

### The code index

You run from the root of the repository, so bind the script once:

    SL=statelens/scripts/statelens.py

    python3 $SL code defs|refs|callers|callees <NAME> [--tests]

Names collide: in consensus, `proposal` is five different methods, and `broadcast_notarize` is
both a field and a method of the same type. So when a name turns up in more places than you
expect, it is probably several entities, and `refs` separates them. Before you probe a field,
ask `refs` for every place that touches it, because the site you would miss by reading one
function is the one worth probing. To learn which actor sends a mailbox message, ask for the
`callers` of the mailbox method. Most of each crate is test code, and the index hides it unless
you pass `--tests`.

If the index is missing the campaign said so, and search and reading are the fallback.

### The syntax tree

    python3 $SL ast sites <NAME>    # written here, read there
    python3 $SL ast notes [PATH]    # comments about races and recovery

The index says a line mentions a field; it does not say whether the line changes it. Before
you probe a transition, ask `ast sites` for the write sites and the `maybe` sites. A write is
an assignment. A `maybe` is the field handed out, as the receiver of a method call or by a
`&mut` borrow, printed with what was done (`.push(..)`, `&mut`): the tree carries no types,
so it cannot tell `push` from `len`, and `push`, `insert`, `clear` and `take` are transitions
as much as an assignment is. Read each `maybe` site before you call the transition inventory
complete; the reads are the decisions. A site it marks `macro` sits inside a macro body,
which the tree does not structure, so read that one yourself; much of the consensus code's
concurrency is inside `select!`. `ast notes` is the fastest way to do step 1 below:
it finds the comments about orderings, races, recovery and cases that cannot happen, and
names the item each one documents.

When a candidate needs state followed across functions, actors or a restart, work through
`statelens/prompts/discover-flow.md`. There is no data-flow tool here, so you are the one simulating
the flow, and that method says how to propose a step and then make the tools confirm or
reject it.

### Beacons in the code

1. Inventory the semantic beacons in the non-test code of `{{ACTOR_DIR}}` and the types
   it owns: enums that describe states, modes, reasons or outcomes; boolean and
   `Option` fields of per-view, per-round or per-batch state; the conditions of `debug_assert!`,
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
   for views, locations and counts, and `pack` to put two small values on one side.
5. Budget: 20 to 60 probes for this component, and at most about 64 `(a, b)` pairs each.
   Count the pairs with the arithmetic of the discretization rules above before you write
   the probe: three bucketed counts on one side is already 216, and two unrestricted
   `delta`s are 121. Over budget, drop a dimension or coarsen one, rather than expecting
   the reachable combinations to be fewer. Avoid per-message hot loops unless the state
   there is interesting.
6. Add one row per probe to the "Beacon probes" table of the plan.

### What makes a probe worth adding

- A state is worth probing when its outcomes **run the same code**. If two outcomes take
  different branches, edge coverage already separates them and the probe adds nothing.
- Probe what the code decided and what it held, not what a peer or an input claimed.
- A finding tells you a state has gone wrong before, so it is worth probing even where the code
  looks unremarkable. It does not tell you to assert anything.
- Prefer a state established in one place and read in another, across a mailbox, a component
  boundary or a restart. Those are the states a single-function reading misses.

### Fitting a wide dimension into a pair

A dimension often has more parts than a pair holds. In order of preference:

1. Put the inputs on one side and the outcome on the other:
   `pack(flag(valid), flag(durable))` against `disc(&outcome)`.
2. Build a mask when several flags belong together:
   `flag(a) | flag(b) << 1 | flag(c) << 2`, against the outcome.
3. Keep related values at one site. A probe records only the presence of its own `(a, b)`
   pair: nothing joins sites, a shared label prefix means nothing to the fuzzer, and the
   view or round is not recorded, so two probes at two sites keep the marginal values and
   lose which value of one went with which of the other. To cover a relationship, emit the
   related, discretized values together at one site, carrying an earlier value there in
   bounded ghost state when it is read elsewhere (a field holding the last value; the round
   may key it, but never enters a probe). Never call something with side effects, and never
   force a value the original code computes only conditionally, to bring a value to a site:
   then probe the parts separately and say in the plan that the relationship is unobserved.

Full worked analyses of Simplex and marshal are in `statelens/examples/`. They are
reference material, not a pattern to copy: they also derive invariants, which is Phase 1 work,
and they use the vocabulary of the StateLens paper, which section 0 of each maps onto this
workflow. Do not let their shape decide what this component's states are -- the code does.
~~~

### 13.10 `prompts/repair.md`

~~~markdown
## Task: repair the instrumentation (attempt {{ATTEMPT}} of 3)

The instrumented tree does not build. Fix the instrumentation only: code marked
`// [statelens]`, and `{{RUNTIME}}`. Do not change existing code.
Do not weaken an assertion to make it compile: if an assertion cannot be written
faithfully, remove it, set its invariant to `unbound` in the plan with the reason, and mark
the sites it checked `not checked` in the `Sites` ledger. The plan lint runs again after
the repair, against the tree as you leave it.
Where `me` comes from a scheme or a provider, never fix a type error at a macro's `me` with
`.flatten()`, `.unwrap_or(None)` or `.and_then(|me| me)`: each turns an unknown index into
"not a participant", which turns the Byzantine guard off. The error means a guard is
missing: `if let Some(me) = ...` around the site, or `me.and_then(|me| ...)` where the site
yields a value. Never make a missing `me` available by looking a scheme provider up,
directly or through a method that does: obtain it as the subsystem rules say.
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
- System: `replica`, one honest replica; for scope `protocol`, `protocol`, all honest
  replicas together.
- Adversary: Byzantine replicas up to the fault threshold (equivocating, mutating
  messages, splitting the network), arbitrary message delay, reordering and loss,
  timeouts, and crashes followed by recovery from persistent state.
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
- System: `replica`, one honest replica; for scope `protocol`, `protocol`, all honest
  replicas together.
- Adversary: Byzantine replicas up to the fault threshold (equivocating, mutating
  messages, splitting the network), arbitrary message delay, reordering and loss,
  timeouts, and crashes followed by recovery from persistent state.
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
- Adversary: the fuzzer runs honest replicas next to Byzantine ones, which equivocate,
  mutate messages and split the network. Some targets of `consensus/fuzz/simplex` also
  crash honest replicas and restart them from their journal (the Chaos, Chaos-Twins and
  Mallory drivers), so journal replay runs while fuzzing.
- Byzantine participants the guard does not know: tests wrap a participant's scheme in
  `mocks::wrapped::Scheme`, which runs the real engine with a misbehaving scheme. With
  `Behavior::CorruptSignature`, used for participant 0 of the `test_invalid_*` tests in
  the test gate, every vote it signs carries a corrupted signature: its engine publishes
  those votes, and every other replica rejects them, so a count of distinct voters that
  includes them can reach a quorum no replica can certify. With `Behavior::RecoveryFailure`
  certificate assembly fails even from a valid quorum.
- Fuzz targets: every consensus target uses the `cert_mock` scheme, which hides the
  signer set.
- Replica index, in `consensus/src/simplex/` only (marshal code has its own rule):
  `self.scheme.me()` wherever a scheme is in scope. The batcher and the
  resolver actors hold one; the voter actor does not, because `Actor::new` moves the
  scheme into `StateConfig`, so read the index from its `State` through a
  `// [statelens] me` accessor rather than keeping a second copy. Where no scheme is
  reachable at all, add a `// [statelens] me` field of type
  `Option<crate::simplex::statelens::Participant>`, set where the struct is created.
- Asynchrony worth probing: the view advances while work is outstanding, a timeout races
  a certificate, a verification or certification result arrives after the state moved
  on, equivocation is detected after acceptance, state is rebuilt from the journal.
- Where the voter decides and where it commits are different functions, separated by a
  reply from the application: `State::try_propose` chooses the parent, and
  `Actor::process_proposed` records the payload and hands it to the broadcaster;
  `State::try_verify` chooses the candidate, and `Actor::process_verified` acts on the
  answer; `State::certify_candidates` dispatches certification, and
  `Actor::process_certified` turns the result into a finalize or a nullify. The replica
  handles certificates, votes and timeouts in between, so a check on the first site of a
  pair says nothing about what the second one does.
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
- Adversary: the fuzzer runs honest replicas next to Byzantine ones, which equivocate,
  mutate messages and split the network, and disrupts or poisons what marshal receives.
- Fuzz targets: every target uses the `cert_mock` scheme, which hides the signer set, and
  a floor is reached only where the harness provides one: the standard Twins targets start
  a node from a finalized floor (`MarshalTwinsInput.floor`), the actor store target
  installs floors at run time (`StoreOp::SetFloor`), and the other targets start at
  genesis.
- Replica index: the participant index of the replica's own signing scheme. Marshal holds a
  scheme provider, not a scheme, and a provider lookup is not a read: an application may
  count lookups against the scope it serves and retire it, as the standard tests'
  `RetiringProvider` and the shards engine tests' `ChurningProvider` do, so a lookup of
  yours can turn a later one of the implementation's into `None`. Never look a provider up
  yourself, whether by calling `scoped` or `scheme` or a method of the implementation that
  does, such as `Actor::scoped_for_height`. In marshal `me` has exactly one source,
  `crate::simplex::statelens::provider_me(&provider, epoch)`: for the `ConstantProvider`
  every harness uses it reads the index without an effect, and for any other provider it
  looks nothing up and returns `None`, an unknown index. The scope is not used, so pass any
  epoch in hand, such as `last_processed_round.epoch()` in `Actor::init`, or
  `Epoch::zero()`. Do not read `me()` from a scheme the implementation holds, even where one
  is in hand: under any other provider that site would be checked while its neighbours are
  not, and history one of them writes and another requires would be incomplete.
  - Core actor: call it once in `Actor::init`, keep the result in a `// [statelens] me`
    field of type `Option<Option<crate::simplex::statelens::Participant>>`, and copy it into
    a field of the same type on the mailbox `init` creates, so every holder of a mailbox
    clone can read it. `Mailbox::new` is a `const fn`: initialize the field to `None` there,
    set it by wrapping the `Mailbox::new(..)` expression in `init` in a block, and list that
    wrap under "Edited lines".
  - Standard adapters: read it from the core mailbox they hold.
  - Coding adapter and shards engine: call it in the `Marshaled` or `Engine` method that
    owns the provider. A task the adapter spawns, and the shards sub-states, hold no
    provider: call it in the method before the spawn, so the task captures the `Copy`
    result, or put the site in the `Engine` method that calls the sub-state. Never add a
    parameter to pass it down.
  - `Some(me)` is the index to pass, including `Some(None)` for a scheme with no signer: the
    replica is known not to be a participant. `None` is not an index. Guard the site with
    `if let Some(me) = ...`, so that under any other provider it stays uninstrumented at run
    time, as rule 3 requires for an index you could not obtain. Where the site yields a
    value, such as a `with_ghost` read whose result you keep, write
    `me.and_then(|me| crate::simplex::statelens::with_ghost(me, ...))`: it yields `None`, as
    a skipped replica does. Never pass `None` in its place, and never convert it with
    `.flatten()`, `.unwrap_or(None)` or `.and_then(|me| me)`: each turns an unknown index
    into "not a participant", and the Byzantine guard off. A type error at a macro,
    `with_ghost`, `with_global` or a helper that takes `me` means the guard is missing.
  - Say in each plan section that its sites take `me` from `provider_me`.
  - The backfill resolver, the application gates and validation, `ancestry.rs` and
    `store.rs` have no identity of their own. Instrument them at their call sites in the
    components above, never inside them.
- Asynchrony worth probing:
  - a finalization arrives before its block;
  - the floor moves while backfill is in flight;
  - a block arrives after its height was passed or pruned;
  - dispatch runs ahead of acknowledgements;
  - certification is requested before the block is available;
  - shards arrive out of order or after reconstruction;
  - state is rebuilt from the archives after a restart.
- Decision and commit are different sites here too: a request to the application, to the
  backfill resolver or to another component is issued in one place and its answer handled
  in another, a mailbox hop later. Before binding an invariant about an act -- delivering
  a block, acknowledging a height, certifying, repairing -- find the handler that performs
  the act and assert there. The dispatching site has not learned what arrived in between.
- Heights: record them relative to the processed floor, the last delivered height or the
  finalized tip, never raw. Never feed commitments or shard indices to a probe.
- Tests: marshal's tests seed archives and metadata directly to stand for an earlier run
  (`seed_inconsistent_restart_state`, `seed_processed_height`, `seed_cache_block`), and
  enqueue resolver deliveries whose local annotations no request of the actor created.
  Treat what the actor restores at startup as its own history, and an annotation on a
  delivery, such as `Annotation::Finalized`, as the actor's own request.
- Durability evidence is positive: a block is durable when the actor restored it (the
  archive read returned it, with its digest) or when a sync that started after its write
  completed. The absence of a write record says nothing -- the write may have gone
  unrecorded, or another block may hold the height -- so a check that passes on a missing
  record is `partial`, with the unknown case in the Notes, never `bound`.
~~~

### 13.15 `prompts/instrument-audit.md`

~~~markdown
## Task: audit the bindings of invariants {{INVARIANT_IDS}} of the {{REGISTRY}} registry

These invariants were bound earlier in this campaign, and `{{PLAN}}` records what was done.
Your job is to find the bindings that claim more coverage than they have, and to close the
gap where it can be closed. You are still the instrumenter: every rule above applies,
including "add, never remove".

A campaign that never panics is read as evidence that the bound invariants hold. That
reading is worth exactly as much as the sites the checks sit on, and nothing more. A check
in the wrong place is silent for the same reason a correct implementation is.

For each invariant below:

1. Read the Statement again, from the registry file printed below, not from the plan's
   `Reading`. A binding goes wrong where the reading went wrong, so re-derive `pre` and
   `post` before you look at what was instrumented.
2. Name every action the Statement constrains, and find the commit site of each one: the
   point past which the act is visible outside the component that takes it (a signature
   exists, a message is handed to a mailbox or to the broadcaster, a record is appended to
   the journal, a certificate is accepted, the view counter moves; a batch is applied, a
   commit becomes durable, a root, a value or a proof is returned). Find them with the
   code tools, from the root of the repository and with
   `SL=statelens/scripts/statelens.py`: `python3 $SL code refs|callers|callees <NAME>` and
   `python3 $SL ast sites <NAME>`. Include the paths that are easy to miss: journal replay
   and recovery after a restart, retries and rebroadcasts, and the handler that acts on
   the reply to a request sent earlier. The guide `statelens/prompts/discover-flow.md` is
   the method when this is not enough; its step 6 is about following a request to where
   it lands.
3. Compare that list with what is instrumented. `rg "\[statelens\] INV-NNNN" --type rust`
   gives the sites of one invariant. Mark each commit site `checked` or `not checked`. A
   check that runs where the action is decided, while the act happens in a later handler,
   leaves that site `not checked`: between the two the replica handles messages, and the
   state the check read is not the state it acted on.
4. Close each gap you can. Add the same condition the binding already checks, re-read at
   that site, with `me` obtained as the subsystem rules say, under the rules above. Ghost
   state in another module is reachable: add a read-only accessor beside the field. If the
   commit site needs a tolerance the first site did not -- a guard there made the
   condition safe, and here there is none -- close the gap with that tolerance and name it
   in the Notes; that is a close, not a strengthening. Where the site cannot carry the
   check at all -- the identity the subsystem rules require is nowhere in scope, or the
   site is outside the editable code -- add nothing and record why.
5. Check the other direction for each existing assertion: can its `pre` be true where it
   stands? If a guard just above returns for exactly the state the Statement forbids, or
   the condition restates the line above it, that assertion checks nothing. Add a check
   where the forbidden state survives if there is such a site, and say so in the Notes
   either way. Leave the original in place; you may add, never remove. Ask the same of the
   feedback: an assertion whose recorded pair cannot vary on a passing execution -- a
   `post` of `false`, or a site on the branch taken only once the replica is about to
   violate the invariant -- gives the fuzzer nothing, so add the classification probe of
   rule 6. Ask what the check does when its evidence is absent: a lookup that passes on
   `None` evaluates nothing for the cases it never observed, and such a binding is
   `partial` at best, with the unknown cases named in the Notes. And ask whether `pre` can
   hold at all in the fuzz targets, reading their harness in `{{FUZZ_PACKAGE}}` rather than
   assuming; the subsystem rules say what it is known to provide. A check that no target
   reaches, only unit tests, is `(inactive in the fuzz targets)`, and the Status says so;
   a check some targets reach names them in the Notes.
6. Update the invariant's section of the plan: the `Sites` ledger, the `Assertions` you
   added, a `Status` that matches the ledger under the rule of the binding task (`bound`
   only when every commit site is checked and the condition is the Statement itself), and
   Notes that name, for each unchecked site, the delivery order that escapes it. Downgrade
   a status whose claim you could not support. Do not raise one without having added the
   checks that justify it. Each entry gives the file and the function, and the ledger is
   checked against the code: an entry you call `checked` must carry an assertion naming
   this invariant in the file it names, so an unchecked site recorded as checked is a
   false record, not a shortcut.
7. Check what each binding costs where it runs. A check that filters or walks a ghost
   history is unbounded, because that history outlives the implementation's pruning: add
   the index the question needs, maintain it where the history is written, and use it.
   This is one of the two things you may change in instrumentation an earlier pass added;
   the other is an assertion that is wrong. "Add, never remove" is about the
   implementation's own code, not about a previous pass's instrumentation.
8. Change nothing else. Do not rewrite a faithful binding because you would have written it
   differently, do not strengthen a condition to make a status look better, and do not
   touch the sites of an invariant that is not in this batch. The beacon step has run
   before you; leave its probes and the beacon table of the plan alone. Add rather than
   edit: a line you change or remove may be another batch's assertion, ghost update or
   helper, and that batch's verdict was given on the line as it was. If a check of this
   batch needs a helper or an index to behave differently, add a new one beside it. The
   campaign compares the tree after each batch: a changed or removed line, a line other
   than a StateLens check added inside an existing function body, or an attribute or
   comment opener placed above an existing item marks every earlier batch's bindings
   unreviewed in the result. New items and new checks beside existing code do not.

Run the check command until it passes. Then run

    python3 statelens/scripts/statelens.py lint-plan

and fix what it reports about the invariants of this batch. It reads the ledger against the
code, so it catches a site recorded as checked that asserts nothing, an entry that gives no
verdict, and a `bound` that the ledger does not support. What it cannot catch is a commit
site the ledger never names, which is the part only you can do.

Reply with one line per invariant: the id, the status before and after, the sites you added,
and the gaps you left.

Invariants:

{{INVARIANTS}}
~~~

### 13.16 `prompts/discover-flow.md`

~~~markdown
## Method: semantic flow discovery

This is the method to follow when a beacon or an invariant needs state traced across
functions. It is not a task on its own: the beacon step adds probes, and Phase 1 writes
invariants. What this method produces is the evidence either of those needs.

StateLens has no data-flow tool. That is measured, not an oversight: the code index records
that a line mentions an entity, not what it does to it; syntax trees give that, but carry no
types; and the tools that do real information flow either cannot follow a value across a call
at all, or answer a different question (does a marked source reach a marked sink) from one
chosen entry point. Nothing crosses an actor mailbox.

So you are the flow simulator. **You propose; the tools confirm or reject.** A flow you
reasoned your way to and did not check is a guess, and must be labelled one.

### Your tools

You run from the root of the repository, so bind the script once:

    SL=statelens/scripts/statelens.py

    python3 $SL code refs <NAME>      # every occurrence, by symbol
    python3 $SL code callers <NAME>   # call sites, with the enclosing function
    python3 $SL code callees <NAME>   # what a definition calls
    python3 $SL code defs <NAME>      # definitions and their extents

    python3 $SL ast sites <NAME>      # write / maybe / init / read, per site
    python3 $SL ast notes [PATH]      # comments on races and recovery

    python3 $SL kb search|find|cites|grep|show

plus reading files and `rg`. All of `code` and `ast` hide test code unless given `--tests`,
because nearly three quarters of this crate is test code sharing files with the code it exercises.

The index knows identity, the tree knows shape, and they answer different halves of one
question. `code refs broadcast_notarize` gives six sites and will not confuse the field with
the method of that name; `ast sites broadcast_notarize` says which two of the six are writes.
A site it calls `maybe` is the field handed to a method or borrowed `&mut`, with the method
name printed: the tree has no types, so `push` and `len` look alike to it, and you read
those sites to tell a transition from a read. Neither tool knows types and shape at once, so
use both.

### Structural or semantic

Classify the question before choosing a tool.

Structural -- who calls this, where is this written, what does this read -- is what `code`
and `ast` answer. Do not ask the knowledge base first; it does not know this implementation,
it knows what has gone wrong in it.

Semantic -- why does nullification preserve this where finalization clears it, why must these
two rules agree, what property does this state implement -- is what `kb` is for. Reach for it
when you can say exactly what you know and exactly what you cannot explain, and start with
`kb search`, which takes that question in plain words and ranks snippets by meaning from the
findings, the design documents, and the repository's comments and documentation. The source
establishes what the code does; a finding or a comment explains why it matters, and may be
older than the code.

### The loop

1. **Name the beacon.** Its exact text, the symbol enclosing it, the concepts it mentions,
   and one sentence of hypothesis. `ast notes` is the fastest way to find beacons, and it
   names the item each comment documents. Do not turn a beacon into an invariant here.

2. **Find the state in code.** List three to five candidate fields, predicates or helpers the
   beacon might mean, most likely first. Check each with `code defs` and `code refs`. Drop
   the ones with no support. A name is a hint, not a definition: read the body.

3. **Establish, mutate, invalidate, consume.** For the confirmed state, use `ast sites` for
   the writes, the `maybe` sites and the reads, and `code callers` on each writer to learn
   who drives it. The
   write you would miss by reading one function is the one worth having: `broadcast_notarize`
   is written at `round.rs:697` when a vote is constructed and at `round.rs:746` when the
   journal is replayed. Both are reached from `Actor::run`, but by different paths, and a
   reading that found only the first would describe the latch as set once per view.

4. **Simulate, then check.** When no tool answers the next step, reason it out: given this
   write, which decisions plausibly depend on it; given this decision, which state plausibly
   determines it. Produce a ranked short list, three to five, then validate each with `code`
   or `ast`. Keep what survives. Report the rest as hypotheses or not at all.

5. **Cross the mailbox by name.** No tool connects a send to a receive, because they are in
   different spawned tasks. The message variant is in both, so: `code callers` on the mailbox
   method names the sending function, and the variant name finds the handler arm. The voter's
   `Mailbox::resolved` is called from `Actor::handle_resolver` at `resolver/actor.rs:595`, and
   the `Message::Verified` it sends is handled at `voter/actor.rs:790`. Note that `recovered`
   and `resolved` both send `Message::Verified`, differing only in a `from_resolver` flag --
   the handler cannot tell them apart from the variant, which is exactly the kind of state
   worth separating.

6. **Follow a request to where it lands.** A decision and the act it leads to are often in
   different functions, separated by an await on a reply. `Actor::try_propose`
   (`voter/actor.rs:369`) asks `State::try_propose` for a context, sends it to the automaton
   and keeps the receiver in `pending_propose`; the reply is awaited in the main `select!`,
   and `Actor::process_proposed` (`voter/actor.rs:683`) records the proposal and hands it to
   the broadcaster. In between, the replica handles everything else, including the results
   that decide whether the act is still legal. So find the far end before calling a state
   "decided here": `code callees` on the deciding function names the request method, `code
   refs` on the field holding the receiver names where it is awaited, and `code callers` on
   the recording method names the handler. Report the pair -- where it is decided, where it
   is committed -- and name what the replica can learn between them.

7. **Stop.** A thread is done when you can say what state matters, where it lives, where it
   is established, changed and read, why that matters, which locations support each claim,
   and what remains unproven. Abandon a thread earlier when the symbol only logs, when the
   relation is syntactic, when no behavior consumes the state, or when the evidence is
   already sufficient.

Expand three to five candidates at a step, not every neighbor. A symbol two calls away can
matter more than twenty direct callers.

### Evidence status

Label every relation you report:

    HYPOTHESIS               your reasoning, no tool run
    SOURCE_SUPPORTED         the source text or a comment says so
    STRUCTURALLY_VALIDATED   `code` or `ast` confirms the symbol, call, write or read
    RUNTIME_VALIDATED        a test reaches it, or a probe separated the states in a run

Never present a hypothesis as a property. The last status is reachable here, unlike in most
analysis: this subproject runs a fuzzer, so a state you cannot separate statically can be
separated by a probe and observed.

### What the findings become

Two different things, and the difference is not negotiable.

A **probe** is feedback. It cannot fail, so it needs only a state worth telling apart --
including a state that is legal but rare. Prefer a dimension whose outcomes run the same
code, because edge coverage already separates the ones that branch. Place it where the
implementation already computes the value: adding an evaluation that did not happen before
changes evaluation order, short-circuiting or side effects, and that is forbidden.

An **invariant** is an oracle. It can panic, so it is written down, reviewed by a person, and
only then bound to code. Propose one only after the relationship is understood, with its
text, the source evidence, the rationale, the evidence status, and its known exceptions. Do
not strengthen it past what the code claims: where the code documents an odd but tolerated
state, that exception belongs in the invariant.

When you are unsure which one a discovery deserves, it is a probe.

### Report

Give, in this order: the beacon and where it is; the state you found and its representation
in code; the steps you took, each as question, tool, result, interpretation, status; any
knowledge base query with why it was needed and what you rejected; the causal chain from
establishment through change and propagation to consumption and consequence; candidate probe
dimensions with the sites where the value is already computed; candidate invariants with
evidence and exceptions; and last, the questions you could not answer with the tools
available.

Do not invent a field, a function or a tool that does not exist. Keep separate what the
source proves, what the tools prove, what a finding explains, and what you are guessing.
~~~

### 13.17 `prompts/subsystems/qmdb-analyst.md`

~~~markdown
- `storage/src/qmdb` implements databases inspired by QMDB (Quick Merkle Database, arXiv
  2501.05262). A database's state is derived from an append-only log of operations. In the
  authenticated variants a Merkle structure over the log (an MMR or an MMB) gives the root
  that authenticates it: `any` (keyed; proves any value a key ever had, over an ordered or
  an unordered key space), `current` (an `any` database plus a bitmap of the active
  operations grafted onto the operations tree, so it also proves that a value is the
  current one), `immutable` (keyed values that are set once and never updated or deleted)
  and `keyless` (values appended and read back by location). `store` is a keyed store over
  the same kind of log, without authentication. Every variant changes through batches: a
  batch is created, mutations are staged on it, and it is applied; `commit` and `sync` make
  applied state durable. In the authenticated variants a batch is merkleized against the
  current state before it is applied, which gives the root that applying it would produce.
  A `store` batch is finalized into a changeset instead, and the store has no root and no
  proofs. Each commit carries an inactivity floor below which operations may be pruned.
  `sync` builds a database from an untrusted source up to a trusted target, and `verify`
  checks proofs against a root. The module docs in `storage/src/qmdb/mod.rs` and in the
  `mod.rs` of each variant describe the design; read them when a source leaves a concept
  unclear.
- System: `database`, one database over its whole life, restarts included.
- Adversary: arbitrary sequences of batches, including forks, chains and stale batches;
  crashes at any point, followed by recovery from what reached storage; storage faults;
  and, in sync and in proof verification, a source or a prover that answers with anything.
- Honest actions: the operations it appends, the roots it reports, the batches it accepts
  or rejects, what it makes durable and what it prunes, the state it recovers after a
  restart, the values and proofs it returns, and what a verifier or a sync target accepts.
- Terms: operations, locations, keys and values, active operations, the operation log,
  the root, batches (merkleized, applied, stale; in `store`, finalized changesets), commits,
  the inactivity floor, pruning, durability, recovery, proofs, sync targets.
- Example of a progress property that names its moment: "When a commit returns
  successfully, the database shall have made durable every operation it applied before
  the commit".
- Kinds of rules in design documents: root and proof rules, batch validity (staleness,
  chains, floors), commit and durability rules, recovery after a crash and initialization
  bounds, pruning bounds, activity tracking in `current`, sync rules, and bounds on
  in-memory state.
- Scope values: `database` (one database), `proof` (proofs and their verification),
  `sync` (a database built from a source), and the variant a property is about: `any`,
  `current`, `immutable`, `keyless`, `store`.
- In scope: the databases of `storage/src/qmdb`. The journals and Merkle structures they
  build on (`storage/src/journal`, `storage/src/merkle`) are not, though a qmdb invariant
  may rely on what they guarantee.
~~~

### 13.18 `prompts/subsystems/qmdb-instrument.md`

~~~markdown
### QMDB (`storage/src/qmdb/`)

- Editable code: non-test code in `storage/src/qmdb/`, except `benches/`. Call the runtime
  as `crate::qmdb::statelens::...`.
- Components: the variants `any/`, `current/`, `immutable/`, `keyless/` and `store/`, the
  sync engine in `sync/` with the `sync/` module of each variant, and the shared code they
  call: `mod.rs` (initialization and recovery), `chain.rs` (batch-chain validation),
  `bitmap.rs`, `operation.rs`, `verify.rs` and `compact/`. A beacon run for one variant
  may probe the shared code it calls.
- Adversary: the fuzzer drives a database through arbitrary sequences of batches, forks,
  stale batches, commits, pruning, crashes, storage faults and reopens, and feeds sync and
  proof verification with data from an untrusted source.
- No replicas: there is no participant index, so `me` is `None` at every site, and the
  guard checks every site. Use `with_global` for ghost state; `with_ghost` needs an index
  and always returns `None` here.
- Several databases can share one run, such as a sync source and its target, and one
  database can be reopened within a run. Ghost history in `Global` must keep distinct
  databases apart and follow one database across a reopen: key it by an identity the
  database keeps across a reopen, such as the partition its log uses. History that need
  not survive a reopen can live in a `// [statelens] ghost:` field of the database.
- Asynchrony worth probing: a batch merkleized against a state that another batch has
  since changed, a chain applied whole or from its tail, a background sync from
  `start_sync` still running while later batches are applied or the log is pruned,
  recovery from a log that runs past the last commit, a sync target that moves while
  requests are in flight, a proof checked against an older root.
- Decision and commit are different sites here too. In the authenticated variants
  `merkleize` computes the root a batch would give and `apply_batch` makes it the
  database's state; in `store`, `finalize` turns a batch into a changeset that
  `apply_batch` applies, with no root. `commit` or `sync` makes applied state durable
  later still, and another batch may be applied in between. Assert where the state
  changes or becomes durable, not where it was computed.
- Errors: a mutating method that returns an error consumes the database, so nothing can
  use it afterwards. Check on the success path, and read an error as the database
  refusing the act.
- Locations, floors and sizes: record them relative to one another (a location against
  the inactivity floor or the log size, the floor against the pruning boundary), never
  raw. Never feed keys, values, digests or roots to a probe.
- Tests build states by hand: they write logs directly, truncate or corrupt them, and
  reopen databases at chosen bounds. Treat what a database recovers at startup as its own
  history; where a check needs evidence of an earlier event, accept what the database
  holds or recovered.
- Fuzz targets: `storage/fuzz/fuzz_targets/qmdb_*.rs`. Each drives the variant its name
  says. Most run on the deterministic runtime, some reopen the database within a run,
  `qmdb_current_recovery` injects storage faults and restarts from checkpoints, the sync
  targets build a database from a source database, and `qmdb_verify_proof` checks proofs
  decoded from fuzzer bytes.
~~~

### 13.19 `prompts/analyst-kb.md`

~~~markdown
## How to read knowledge-base findings

- The sources are the findings of a private knowledge base, reported against this workspace,
  whose `module` belongs to this registry. Each is listed under Sources with its state,
  severity, remediation status and summary. Read them only through these commands, run from
  the root of the repository; there is no other way to the corpus:

{{QUERY}}

- Start with `show <identifier>` for a finding's claim block, then read its state-bearing
  sections: `Root Cause`, `Lifecycle Events`, `Exploitation Or Trigger Conditions` and
  `Context`. Then read the code it concerns as it is today: a finding cites files and lines
  of the revision it was reported against, and they may have moved.
- Reconstruct the bug: the state that triggered it, what the implementation did, and why
  that was wrong. Write the invariants the bug violated, generalized so that they also catch
  variants of the bug on other paths while staying true for every correct execution. Where a
  finding describes a crash, cover both sides: what the system must never do, and what it
  must do instead.
- A finding's state is evidence, not truth. One judged `invalid` describes behavior that was
  found correct, so it is no evidence of a rule: write an invariant from it only when the
  code or its documentation states the property. Prefer `valid` and `tested` findings, and
  say in the Rationale how strong the evidence is.
- Set `source_ref` to `finding <identifier>`. In Evidence, describe the violating scenario in
  two to five sentences in the terms of Context, without reproduction steps or exploit code,
  and cite the code it concerns as it reads at `{{COMMIT}}`.
- What you write stays out of git, in the local registry, because a finding is private.
  Write it as though it might be read anyway.
- Write nothing for a finding about tooling, tests, documentation or another crate.
~~~

### 13.20 `prompts/state-analyst.md`

~~~markdown
# StateLens state analyst: extract target states

You are a senior security engineer who specializes in the kind of system that Context
describes. Read the sources listed at the end and write target-state cards for the
`{{REGISTRY}}` registry of StateLens in this repository.

## Context

{{CONTEXT}}
- Every card in `{{DESTINATION}}/` is used by the next synthesis of this profile. After a
  fuzzing campaign, an agent turns each card into a dedicated fuzz target, a scaffold, that
  drives the card's History on an existing fuzz target, checks each event as it happens, hands
  off at the target state, and lets the fuzzer and the target's oracles run on from there. A
  History the protocol cannot produce wastes that work; a vague one cannot be driven or
  checked.

## What a target state is

- A state of honest replicas that only a specific history of events reaches: for example,
  "the replica is certifying a notarized proposal of a view it voted to nullify". It is
  worth reaching when a bug would show there, such as the precondition of a fixed bug, the
  state a test sets up, or a race a comment warns about, and random schedules rarely get
  there.
- It is never a property and never an oracle: no "shall", and no expected outcome. What the
  replica does next is judged by the assertions and oracles of the fuzz target, not by the
  card.
- Every event is one the protocol and the adversary in Context can produce. A Byzantine
  replica signs only with its own key: it may equivocate or lie in what it signs, but never
  forges an honest replica's vote or certificate. The fuzz targets use a mock certificate
  scheme, so a History never depends on a property of a real signature scheme.
- One state per card. Writing zero cards is a valid result.

## How to read the sources

- `test`: the source is `path:line` or `path:start-end` inside a test under
  `{{SOURCE_ROOT}}` or in the profile's fuzz package. Read the enclosing test, its helpers
  and the code it drives. The History follows the calls that build the state; the test's
  checks on that state become `Check` and `Holds` lines, and its assertions on the outcome
  are dropped. A message the test puts straight into a mailbox, a resolver or a journal
  becomes the protocol event that delivers the same input: the request it answers, the peer
  that sends it, the crash it stands for. `source_ref` is `path:line@{{COMMIT}} (<test
  name>)`.
- `text`: a file, or a literal that the script wrote to a file for you. `source_ref` is
  `text: <a short title you give it>`, or the path of the file the operator gave, never the
  copy the script made under `extract/`. Evidence quotes the passages that define the
  History verbatim, at most about 40 lines, and summarizes the rest. Confirm every event
  against the code, and drop one you cannot confirm.
- `issue`: read the issue or pull request completely: description, comments, linked issues,
  and the diff of the fix. Use `gh issue view <ref> --comments`, `gh pr view <ref>
  --comments` and `gh pr diff <ref>` when `gh` is available; otherwise the GitHub REST API
  with `curl`, or your web fetch tool. `source_ref` is the URL followed by `(merged as
  <commit>)`, or `(head <commit>)` for a pull request not merged yet (`gh pr view <ref>
  --json mergeCommit,headRefOid`). For a fix, the target state is the precondition the bug
  needed, not its bad outcome, and the tests the pull request adds are the main material.
  Evidence quotes the decisive sentences and pins the code the History runs against, as it
  reads at `{{COMMIT}}`.
- `kb`: the findings of a private knowledge base, listed under Sources, or one finding.
  Read them only through these commands, run from the root of the repository:

{{QUERY}}

  Start with `show <identifier>`, then read the state-bearing sections (`Root Cause`,
  `Lifecycle Events`, `Exploitation Or Trigger Conditions`, `Context`) and the code as it is
  today. A finding's state is evidence, not truth. `source_ref` is `finding <identifier>`.
  Evidence describes the state in the terms of Context, without reproduction steps or
  exploit code.
- `comment`: files or directories under `{{SOURCE_ROOT}}`, optionally with `:line` or
  `:start-end`. Look for situations the author warns about or relies on: "before", "after",
  "while", "races", "cannot happen because". `source_ref` is `path:line@{{COMMIT}}`.
- `design`, `spec`, `paper`: the protocol situation the source describes. `source_ref`
  names the document and its section, `path:line@{{COMMIT}}` of the property or action, or
  the paper's title, page and section. When a text extraction is listed next to a PDF, read
  the extraction.
- For every kind, confirm each event against the code at `{{COMMIT}}`: the History is what
  this implementation does, not what the source assumed.

## What is essential

- An event belongs to the History only if the state would differ without it: would a check
  on the state change? Everything else the source chooses is incidental (rule S7 of
  `consensus/fuzz/marshal/src/scenarios/specs/SPEC.md`): an arbitrary view, height, payload,
  leader, timestamp, delay or order.
- An incidental value becomes a knob, with the source's value first, or is dropped. Give a
  knob at least two values, each of which keeps the History possible; at most 16 knobs.
- An order the source picked arbitrarily becomes an `Order:` pair. An ordering knob varies
  only an order that `Order:` frees.
- A timing domain straddles the timeout it matters for: one value below it and one above.
- A knob never varies what the History makes essential.

## History

- Events `E1.` to `En.`, numbered from 1 without a gap, each at the start of a line. `En` is
  the event that brings about the target state.
- Each event starts with its actor and a colon: `harness` for what the fuzz harness does
  (configure the replicas, deliver or hold back a message, partition, crash, restart, or act
  as a Byzantine replica: "as B, sends R ..."), or the name of the honest replica that acts.
- Name the entities by short names: replicas (`R`, `B`, `Z`), views (`v`, `p1`), heights
  (`h`), payloads (`d`), epochs (`e`), incarnations (`i`). A name is a letter followed by
  letters or digits. A replica's name starts with a capital letter and every other entity's
  with a small one, because the reach check tells replicas apart by it; so an honest
  replica that is an event's actor has a capitalized name.
- After each of `E1` to `E(n-1)` comes one line indented by four spaces, `Check (<entities>):
  <what is observable once the event happened>`; after `En` one such line, `Holds
  (<entities>): <the target state as it holds at the handoff>`. The list names every entity
  the line relates; the actor of an event that a replica performs is in its list. Write `x as
  Ek` for an entity that event `Ek` bound, which must be in `Ek`'s list; a name without `as`
  is existential, "for some x".
- Write each line as something a harness observable or a probe can show at that moment:
  what a replica holds, signed, sent, requested or is doing, keyed by the entities, with
  their relations. For pending work, the `Holds` line says the work is still pending at the
  handoff.
- An event that restarts a replica binds the new incarnation, and a later line about that
  replica names it, as in `Holds (R as E1, i as E4): in incarnation i, R ...`.
- A line may continue on further lines indented by four spaces that start with neither
  `Check` nor `Holds`.
- An optional last line, `Order: Ei and Ej in either order`, with more pairs separated by
  `;`, frees those pairs; every other pair happens in numbered order.
- No probe label, because labels change with every campaign, and no implementation
  identifier outside Observation hints. Never an event the protocol cannot produce.

## Statement

One sentence, "While <conditions>, the replica <is doing or holds> <state>.", about honest
replicas, in the terms of Context, with no implementation identifiers.

## Output

- Read `statelens/target-states/marshal/TS-0001.md` first: it is the model card. Its
  `## Source excerpts` section is generated; do not write one.
- Write one file per target state: `{{DESTINATION}}/<ID>.md`.
- {{COUNT}}
- Use IDs starting at `{{NEXT_ID}}` and increasing by one with no gaps.
- Follow the template below exactly: the same front matter keys and section headings, in
  the same order. Delete the optional section if you do not use it. Set `source_kind:
  {{KIND}}`, and the scope values of the registry, listed in Context.
- The card is the record of its source: synthesis reads only the card and the code, and no
  raw input is kept. Put what is essential into the card: the decisive sentences quoted,
  the code pinned, every event confirmed.
- A line number means something only at one commit. Write every line you cite as
  `path:line@{{COMMIT}}` or `path:start-end@{{COMMIT}}`, with the path from the repository
  root, at most about 40 lines per range, and cite the whole block you rely on. Never write a
  bare "line N". Observation hints name functions, types, tests and INV ids, never lines.
- `{{DESTINATION}}` was chosen from the source's disclosure: a card from a private source
  goes to a registry that git ignores. Write every card as though it might be read anyway.
- Plain ASCII only. Wrap lines at 100 characters.
- Do not modify or delete existing files, create other files, or write code.

When you finish, reply with a list of the files you wrote (ID, title, one line of evidence),
or with the reason you wrote none.

## Template

```markdown
{{TEMPLATE}}
```

## Sources

Kind: `{{KIND}}`

{{SOURCES}}
~~~

### 13.21 `prompts/synthesize.md`

~~~markdown
# StateLens synthesizer: write a state-reaching fuzz target

You are writing a scaffold: a dedicated fuzz target that drives the History of one
target-state card on an existing fuzz target of this repository, its base, witnesses each of
its events with the probes a StateLens campaign installed and with harness observables, hands
off at the target state, and lets the fuzzer and the base's oracles run on from there.

## Where you are

- This checkout is a throwaway clone at commit `{{BASE}}`, instrumented in place by a
  StateLens campaign. Your changes are never merged; a human reviews the pair's diff. The
  repository conventions in AGENTS.md and CLAUDE.md about public API stability, documentation,
  benchmarks, dependencies, commits and pull requests do not apply here. The rules in this
  prompt take precedence.
- Do not commit. Do not run the tests, the scaffold, any fuzz target or the fuzzer: build
  only (section Building). The script replays your scaffold itself.
- Read `{{RUNTIME}}`, the runtime module of the campaign, `{{RUNTIME_MODULE}}`: its probes,
  and its read side (`seen`, `sites`, `observations`, `truncated`, `mark` and the `Seen`
  type, whose fields you read through its getters, such as `s.a()`), which a scaffold uses
  to ask which probes fired during its input. From the fuzz package it is
  `commonware_consensus::simplex::statelens`.
- Read `{{FUZZ_PACKAGE}}/src/target_states/mod.rs`, the helper the script wrote, for the
  exact signatures of the items this prompt names, and `{{PLAN}}`, the campaign's plan, for
  what each probe records (its beacon table) and which invariants are bound where.
- The probe labels and `sl_implies!` invariant IDs of this campaign, with where each is,
  from one scan. Lines move as you edit, so a scaffold looks a site up at run time with
  `sites(label)` and never writes one as a literal:

{{LABELS}}

## Task: card {{CARD_ID}}, attempt {{ATTEMPT}} (attempts run from 0 to 3)

The card, with its {{STAGES}} History events; its Source excerpts show the code it was
written against:

===== {{CARD_ID}} =====
{{CARD}}
===== end of {{CARD_ID}} =====

Write:

- the module `{{MODULE}}`, which holds everything the scaffold needs: its `fuzz` entry, its
  stages, and any recording wrapper;
- the thin target `{{FUZZ_PACKAGE}}/fuzz_targets/{{SCAFFOLD}}.rs`, on the base
  `{{BASE_TARGET}}` described below; exactly one thin target for this card on this base,
  and none on another base;
- any edit under the edit contract below that the scaffold needs elsewhere, each marked.

The script owns the package manifest, `Cargo.lock`, `target_states/mod.rs` (the helper,
followed by one `pub mod` line per module, yours included) and the line of the package's
`src/lib.rs` that declares `target_states`. It adds your scaffold's `[[bin]]` block, the
base's block with `name` and `path` renamed, after your attempt.

The base, `{{BASE_TARGET}}`: its name, the `fuzz_target!` closure header and entry call,
`required-features`, input type, and whether its runner is hooked:

{{BASE_DETAILS}}

## Edit contract

This is requirement R-TS-SYN-3, the one contract for every edit a synthesis makes:

> Scaffold synthesis operates on a disposable copy of the repository, following the same
> assumption as StateLens. The generator may modify source code when necessary to expose
> state, make existing functionality callable, add fuzz-only accessors or wrappers, or support
> scaffold execution and verification. Such modifications must not change the production
> behavior or protocol semantics of the system under test.
>
> Allowed examples include:
> - widening visibility of existing functions, fields, or types;
> - adding fuzz-only getters or read-side accessors;
> - adding re-exports;
> - adding wrappers around existing operations;
> - adding campaign/runtime observation code;
> - adding compile-time fuzz-only hooks that expose existing behavior;
> - restructuring code only where the transformation is demonstrably semantics-preserving.
>
> The generator must not modify production consensus logic, including:
> - state-transition rules;
> - branch conditions or protocol predicates;
> - ordering of protocol operations;
> - certificate or vote validation rules;
> - message handling semantics;
> - timeout behavior;
> - persistence/recovery semantics;
> - error handling that affects execution;
> - state mutations used by the production implementation.
>
> The principle is:
> - Allowed: change how existing behavior is exposed or observed
> - Forbidden: change what the protocol does
>
> Because synthesis runs on a disposable copy, generated modifications do not need to be
> suitable for upstream production code. They only need to preserve the behavior of the
> production logic being fuzzed.

How it applies here:

- Where: the paths the subsystem rules below name, which are the system under test and the
  profile's fuzz package. The fuzz package reaches `consensus/fuzz/core/` only through its
  own `src/`. Any other path is out of scope.
- Observation code is read-only code the scaffold calls: getters, accessors, recording
  wrappers, witness helpers. It never adds a counter feature, an assertion or ghost state;
  those come only from the campaign. Synthesis never instruments.

The script checks every attempt against the tree as the campaign left it, so a change an
earlier attempt made counts as if you made it now:

1. Scope: a change outside those paths, other than to `Cargo.lock`, stops the synthesis and
   restores the pair's edits; the operator then needs a fresh clone.
2. Manifests: no dependency change in any `Cargo.toml`. An edit to a file the script owns is
   restored, and your version is not built.
3. Instrumentation integrity: every `sl_probe!`, `sl_assert!` and `sl_implies!` call stays
   as it is (moving one within its file is fine); every line the campaign's instrumentation
   added stays, so no ghost update, `// [statelens]` field or runner hook is removed or
   changed; the runtime module stays byte-identical, and its declaration and the attributes
   above it stay, with no `#[path]` attribute added; no call of `with_ghost`, `with_global`,
   `record`, `note`, `violation`, `reset` or `clear_compromised` is added outside the helper
   and the thin targets; no `set_compromised` outside `target_states/`; no `tick`, `watch` or
   `unwatch` outside the helper; no call of the read side in the system under test; no `[statelens-reach]` or
   `[statelens-scaffold]` literal outside the helper; outside the helper, no print macro
   (`print!`, `println!`, `eprint!`, `eprintln!`), `stdout()` or `stderr()`, `from_raw_fd`,
   panic hook (`set_hook`, `take_hook`), `include!`, `include_str!`, `include_bytes!` or
   `#[path]` attribute, also in code you copy from elsewhere; and no Rust file in a path git
   ignores, such as a module or directory named `target`, which the repository ignores. A
   breach is not built, and it stays a breach in every later attempt until you revert it.
4. Marker: every changed hunk outside your module and thin target carries the comment
   `// [statelens] tss:{{CARD_ID}}`. An unmarked hunk is reported for review, and so is a
   hunk that changes or neighbors an `sl_*!` call or a line the campaign added.
5. Test gate: when the kept version changed the system under test, the campaign's tests run
   again; a test that passed in the campaign and now fails or no longer runs restores the
   pair's edits and records GATE FAILED.
6. Restore: a pair with no version built, or GATE FAILED, has its edits restored.

## Shapes

Pick one and record it in the module header.

- Shape A, pinned input, preferred where it fits: the base input's fields fix every event
  before `En`. `fuzz` splits and picks the knobs, opens the stages and checks the budget,
  pins those fields, resets the fields that depend on them, calls the base's entry by path
  with its generics, then evaluates `E1` to `E(n-1)` over the trace and the harness
  observables, calls `Stages::handoff` with the evaluation of `En`, and last `Stages::done`.
  The base's own schedule runs, no driver code is copied, and its oracles are untouched.
  Register the evaluation with `Stages::on_panic`, so a crash still reports what the trace
  shows.
- Shape B, online prefix, where Shape A cannot express the History: `fuzz` splits and picks
  the knobs, opens the stages and checks the budget, calls `set_compromised`, pins the
  fields, sets the base up, drives `E1` to `E(n-1)` online, calls `Stages::handoff` with a
  read of `En`'s witness, hands off to the base's free-running phase and oracles, and calls
  `Stages::done` after the last oracle. Call the base's setup by path; where only a
  monolithic driver can host the prefix, copy that driver verbatim into the module and cite
  it as `path::item@{{BASE}}`.

`pub fn fuzz` takes the base's input type and the generic parameters of the base's entry, in
order. The module opens with this header, which the script reads:

```rust
//! {{CARD_ID}} on {{BASE_TARGET}}
//! Shape: A | B
//! Knobs: raw_bytes[0..k]: [0] <knob>, [1] <knob>, ...
//! Stages: E1 <witness kind and what it reads>; E2 ...; ...
//! Control: withholds Ek | n/a
//! Injections: <each injection, with the INV ids whose ghost history it bypasses> | none
//! Missing: <each missing capability> | none
```

The thin target is the base's file with two changes: the `use` lines name your module
instead of the base's entry, and the body of its one `fuzz_target!`, whose closure parameter
stays the base's, is exactly these three statements:

```rust
    fuzz_target!(|input: <the base's input type>| {
        commonware_consensus::simplex::statelens::reset();
        <module>::fuzz::<the base entry's generic arguments>(input);
        commonware_consensus::simplex::statelens::clear_compromised();
    });
```

The first generic argument names the `cert_mock` scheme, as in the base, and the module names
no Simplex type with another scheme.

## Knobs

- The card's Knobs table lists them. `Knobs::split` takes the first K <= 16 bytes of the base
  input's own `raw_bytes`, zero-padded, as the first statement of `fuzz`; `Knobs::pick`
  takes the next one as `domain[byte % domain.len()]`, with the source value at index 0, so
  the empty input, the canonical input, replays the source's History.
- Each knob decodes to a valid value by construction: derive a view so that the required
  leader leads it, rather than hoping. An ordering knob indexes the orders `Order:` allows,
  the source order first.
- Pick every knob before any engine starts, then call `Stages::new("{{CARD_ID}}", {{STAGES}})`
  and `Stages::budget`, which takes the knobs, so none is picked later. Do both before you pin
  a field or perform any other action: until `Stages::new` nothing watches, so `Witness::act`
  takes position 0 and its stage has no position. The input type, the run recipe and the
  libFuzzer flags stay the base's; there is no seed corpus.
- Then pin the fields the History fixes, through `Witness::act` when a stage witnesses the
  pin, and reset the fields that depend on them as the base's decoder sets them under the pin
  (the subsystem rules name them).
- `Knobs::split`, `Knobs::pick` and `Stages::budget` raise the only errors attributed to a
  scaffold, before any engine starts: more than 16 knobs, more picked than split, a domain
  with fewer than two values, a prefix budget over the runtime deadline.

## Stages and witnesses

One stage per History event, `E1` to `En`, evaluated in the order you drive them. Bind the
card's entities to the concrete values you chose or observed, and record for each stage one
witness that establishes its whole `Check` or `Holds` line, its relations to earlier events
included. The kinds:

- `exact`: harness observables, one per part of the line, each keyed by the bound entities:
  a reporter map keyed by view or digest, a resolver or buffer recorder, a recording wrapper
  in your module, a network intercept record, or a local query without side effects. A query
  that subscribes, hints, fetches or verifies is not a witness: it would create or satisfy
  the state it checks. A map read after the run shows presence only; an entry carries a
  position only when a recording wrapper stamped it with `stamp` as it recorded it. A
  recording wrapper records synchronously and forwards every call and reply unchanged and at
  once: no await, delay, spawn, drop or reordering of its own.
- `intrinsic`: one probe observation, found with `seen` and a label from the list above, at a
  site whose two values come from one receiver. It identifies the replica `me` and the
  relation among that object's fields at that instant, and no view, digest or other
  identity, so it witnesses only a line whose entities other than one replica are all
  existential, and binds those to `?`. Two
  observations at different sites witness nothing together, and an observation whose
  subject its own site does not fix is no witness.
- `construction`: a harness action you performed through `Witness::act` or
  `Witness::act_async`, which take the action's position right before they perform it, and
  that cannot fail silently, such as a pinned elector or a certificate you built. It proves
  only that the action happened, never what a replica did with it, and only for an event
  whose actor is `harness`, never for `En`; in Shape A, only for an action before the base's
  entry is called. `act_async` takes a closure that makes the future: pass the call itself,
  never a future you made earlier, because some mailbox methods act when called, not when
  awaited.

A stage that no available witness binds is `unverifiable` with its reason, never held, and
never approximated; for `En`, record it with `Stages::unverifiable` before you call
`Stages::handoff`. Record stages only through the helper: `Stages::held(k, witness)` for
`E1` to `E(n-1)`, `Stages::missed`, `Stages::unverifiable` and `Stages::withheld`, and
`Stages::handoff` for `En`. Read the trace from `Stages::since()`. Never print anything:
the helper prints every line the script reads.

A witness record is checked again by the script, which downgrades a held stage to
`unverifiable` (`witness rejected: <rule>`) when:

- `as`: an `x as Ek` value differs from the value `Ek` bound, or is `?`;
- `bind`: an entity of the line is missing from the binding, written `name=value@Ek,...`;
- `evidence`: an `exact` or `construction` witness does not name every entity of the line
  with its bound value in its keys, written `name=value,...`, or an `exact` item's stamp is
  not that of an entry line with the same observable, key and value;
- `order`: a stage's position is not greater than that of an earlier stage it must follow,
  by the numbered order less the pairs `Order:` frees;
- `run`: a probe observation's runtime instance differs from that of an earlier stage's
  observation, with no marked restart between them;
- `incarnation`: a relation across a marked restart of a replica the line binds, whose
  binding does not name the incarnation that restart began, or names one that no restart
  began or that begins after the line's evidence;
- `intrinsic`: an intrinsic witness cites more than one observation, or binds a value other
  than `?` to an entity other than its replica, or a replica other than the observation's,
  which a site without a replica never matches;
- `construction`: a construction witness for `En`, or for an event whose actor is not
  `harness`.

Both stages of an ordered pair need a position: a probe observation, a stamped entry, or a
construction action. Presence-only evidence cannot order anything, so such a stage is
`unverifiable (no position)`; an `exact` witness has a position only when every item is
stamped. Values hold no space, comma, `@`, `[` or `]`; write a binding as `R=2@E1,v=5@E1`.

A held stage adds a feature that rewards inputs that get further. The first miss closes the
scripted prefix, except in the control run: drive no further event, call `Stages::handoff`,
which reports the handoff lost, and continue into the base's free-running phase and every
oracle.

Incarnations: mark every restart you drive with `restart(&[replicas])`, which returns `s`,
and bind the incarnation it began as `inc<s>`. In Shape A, add a marked call of `restart` to
the base's restart code (the subsystem rules name the known sites). A line that relates a
replica across a restart names the incarnation.

## Handoff and recovery

Handoff comes first; recovery is part of the continuation.

- Shape B drives `E1` to `E(n-1)` online, polling in simulated time, with a simulated-time
  deadline per stage: passing it is a miss, never a wait. Race every await on a reply of the
  system under test against the deadline with `commonware_macros::select!`; a dropped reply
  is a miss.
- `Stages::handoff` takes a plain closure that reads `En`'s witness and builds it inside the
  call, with no await or yield, and no value read before the call. The helper takes a
  position, calls it, and takes the handoff mark: the handoff holds only when nothing came
  between the read and the mark. If `En` does not hold then, it is missed, even if it held
  earlier. The positions date the read, not what it read, so give `En` an `exact` witness
  where one exists; an `intrinsic` one cites the latest observation at its site for its
  replica, found with `observations`, because `seen` returns the earliest and an older one
  may no longer hold.
- For a state defined by pending work or a withheld delivery, an `exact` observable shows
  the work still pending at the handoff: requested, and neither answered nor closed. Nothing
  the prefix does may complete, cancel or abandon it: never await its reply, drop its reply
  channel, or stop or restart its owner before the handoff.
- The continuation starts with every fault the prefix opened still in place: a crashed
  replica down, a partition, a held message. Release each no later than the base's first
  heal (GST), and start the base's liveness measurement after both. Network cuts go through
  the base's own fault input, as pinned partition fields, or are composed with the base's
  current cut; never heal the network yourself. Release crashed replicas and held messages at
  the handoff plus `d`, a knob in [0, the base's fault phase); a base without GST releases
  them before its liveness wait.
- The runtime deadline is the base's, which the subsystem rules give, plus the stage deadlines
  plus the largest release delay, which `Stages::budget` checks; for a base without one, pass
  `Duration::MAX`.
- Shape A imposes no cleanup, and its handoff is implicit: `En`'s witness, read in the handoff
  call after the run, counts only if it has a position and the trace holds a later
  observation of an honest replica in the same runtime instance.

## Control

The header names one withheld event, `Control: withholds Ek`, with k < n and `harness` as its
actor, chosen so that `En` cannot hold for the bound entities without it. Read
`STATELENS_REACH_CONTROL` only through `control()`; when it is set, skip `Ek`'s action, call
`Stages::withheld(k)`, and still drive every later event, the handoff check and the base's
oracles, so `En` gets an outcome. Write `Control: n/a` only when the card has no `harness`
event before `En` and every witness is `exact` or `construction`.

## Oracles

The base's free-running phase and every oracle run, called by path or copied verbatim, never
removed or weakened. In Shape A the base's oracles run inside its entry as they are, and a
History whose continuation they would not measure takes Shape B. In Shape B, re-base the
base's progress target on the handoff, in the measure the subsystem rules give for that base.
`Stages::done` follows the last oracle; returning before it reads as an oracle that never ran.
Stage checks are not oracles.

## Fabrication and the guard

- Events go through the network or the harness verbs. A scripted vote goes out only on its
  signer's own channel (INV-0008). A certificate you build names an honest signer only for a
  proposal that replica signed or would sign.
- List every injection, such as a journal seed, a floor start, a resolver delivery or a
  mailbox call, under `//! Injections:` with the INV ids whose ghost history it bypasses. The
  module never writes ghost state and never calls `record`.
- Shape B calls `commonware_consensus::simplex::statelens::set_compromised` with the indices
  it runs as real engines under a Byzantine identity, empty if none, before any engine
  starts; when the set is not empty, also check that every scheme's own index matches its
  position in `participants`, as the hooked runners do. Code copied from a hooked runner
  keeps its hook. Shape A relies on the base's hooked runner.

## Missing capabilities

A stage that needs what the edit contract cannot give, such as a new dependency, a change to
what the protocol does, or an item of `consensus/fuzz/core/` that is not public, is never
approximated: record it with `Stages::missed(k, "cannot: <capability>")`, list it under
`//! Missing:`, keep the prefix up to that stage and hand off; for `En`, record that miss
before you call `Stages::handoff`. A human adds the capability.

The prefix and witness code you write never panics on data of the system under test: no
`unwrap`, `expect` or index that its output decides, and no harness verb that panics on its
reply; a miss instead. Code copied verbatim from the base, and every oracle, keep their
panics: after the handoff a miss records nothing.

## Building

Build the scaffold with

    {{BUILD}}

until it builds with no errors and no warnings. If it reports that the package has no such
target, because the script writes the `[[bin]]` block only after your attempt, add that block
for the build (the base's block with `name` and `path` renamed) and remove it again before you
finish, leaving the manifest exactly as you found it. If you changed the system under test,
also run `{{CHECK}}`.

Never run the scaffold, any fuzz target, `cargo fuzz run` or `just run`: the script's replays
of fixed inputs are the only runs that judge a version, and a crash file any other run leaves
is treated as a finding. An attempt that changes no file ends the pair.

## Feedback

{{FEEDBACK}}

What each signal asks for:

- A veto, a guard, a build failure or a failed agent run: fix that, as reported.
- A miss with `cannot: <capability>`: nothing in the scaffold, unless an edit the contract
  allows, or another shape, gives the capability; otherwise a human adds it.
- `E1` missed: the setup: configuration, pinned and dependent fields, roles, elector or
  shape.
- A middle `Ek` missed: the event's content, recipient, channel or order; compare the
  trace's values and sites with what the stage expects.
- `En` missed, or the handoff lost: the knob domains, the timing, and what keeps the state
  pending at the handoff.
- `unverifiable`, or `witness rejected`: a witness that binds the relation: an intrinsic
  site for an existential line, otherwise an exact observable keyed by the bound entities,
  with positions where order matters.
- `weak` (the control still reaches `En` for the bound entities): withhold the event without
  which `En` cannot hold for them, or say in your reply that the History is not causal.
- A vacuous or missing control: name, or withhold, a later harness event before `En`; in the
  control run, drive every later event, the handoff check and the base's oracles.
- NO REPORT: use the helper, and never return before the base's oracles.
- SCAFFOLD ERROR: the reason the helper named.

Your earlier attempts' files are still in place: change them rather than start over, unless
the feedback asks for another shape.

## Subsystem rules

{{SUBSYSTEM_RULES}}

## Reply

Reply with: the shape; the witness of each stage; the knob layout; the injections; and the
missing capabilities.
~~~

### 13.22 `prompts/subsystems/simplex-synthesize.md`

~~~markdown
### Simplex (`consensus/src/simplex/`, `consensus/fuzz/simplex/`)

- Paths you may change: `consensus/src/simplex/`, the system under test, whose tests the
  script reruns when you change it, and the fuzz package `consensus/fuzz/simplex/`.
- Bases: every `simplex_*` target but Mallory, whose custom mutator a scaffold cannot reuse.
  Shape A fits a History that the fields of `FuzzInput` fix: the partition, the
  configuration, the certify choice and the block filter. The Chaos, ByzzFuzz and Twins
  schedules are drawn from the random stream that `raw_bytes` seeds, so no field pins them,
  and a History about them takes Shape B. The `_state_cov` and `_hb` targets add coverage
  tables, which cost throughput.
- Dependent fields of `FuzzInput`, reset as its decoder sets them when you pin what they
  depend on: `degraded_network` depends on `partition` and `configuration`, `certify` on
  `configuration`, `block_filter` on `configuration` and on the fault bound drawn from
  `required_containers`, the fault rounds of `strategy` on `required_containers`, and
  `optimistic_views` on `term_length`.
- Usable without an edit, because a module under `crate::target_states` sees the private
  items of the crate root: `run_standard_once`, `run_audited_standard_once_with`,
  `run_twins`, `MockTwinsBackend`, `configure_block_filter`, `spawn_disrupter_with_relay`
  and `install_chaos_panic_hook`, and `chaos::runner::run`. Also the public items of
  `consensus/fuzz/core`, among them `setup_network`, `bounded_fuzz_runtime_config`,
  `fuzz_runtime_timeout`, `spawn_filtered_honest_validator`, `run_twins_with_backend`, which
  is hooked, and the partition helpers `apply_partition`, `link_peers` and
  `scheduled_partition`; and the mock reporter's maps keyed by view (`leaders`,
  `notarizations`, `nullifies`, `nullifications`, `certifications`, `finalizations`), read
  after the run for presence, or through a recording wrapper for order.
- With a marked edit: `chaos::runner::{run_with, restart_durable, enact, check_safety}` and
  the internals of `chaos::twins`; under `consensus/src/simplex/`, an accessor such as one
  for the private fields of `mocks::twins::RoundScenario`, which only `cases` builds.
- Known restart sites, which get a marked call of `restart` when a scaffold runs them:
  `chaos::runner::restart_durable` (Chaos) and `chaos::twins::restart_honest`
  (Chaos-Twins). The list is guidance, not a complete one.
- `start_validator_engine` in `consensus/fuzz/core` is private and starts every engine from
  `Floor::Genesis`; a History that needs another floor copies it into the module with the
  floor as a parameter.
- The Chaos-Twins runner's gate is the pattern for a stage: wait for a replica's own state
  before acting, and do not act in the wrong state.
- The fault phase of `consensus/fuzz/core` is `FAULT_PHASE`, 30 s, so a release delay is a
  knob in [0 s, 30 s).
- Progress and deadline: `run_standard_once`, `run_audited_standard_once_with` and `run_twins`
  run under `bounded_fuzz_runtime_config`, whose deadline is
  `fuzz_runtime_timeout(input.required_containers, <prefix views>)`, with 0 prefix views, or
  `twins_prefix_views(..)` for `run_twins`; the Chaos, Chaos-Twins and ByzzFuzz runners set
  none. Each base keeps its own liveness measure, which a Shape B continuation counts from the
  handoff, and keeps the base's condition for measuring at all: `run_standard_once` and
  `run_audited_standard_once_with` wait only when `should_bound_standard_liveness(&input)`
  holds, that is a `Connected` partition (`Static` and `Adaptive` fail it), a valid
  configuration and `BlockFilterChoice::None`; otherwise they sleep `MAX_SLEEP_DURATION` and
  assert no liveness, so FaultyNet, whose partition `fuzz` always sets to `Adaptive`, never
  waits. Where they wait, every reporter's latest finalized view must reach
  `input.required_containers`, so the target is the latest finalized view at the handoff plus
  `input.required_containers`; the audited driver leaves the notarize-omission victim out of
  that wait and instead checks after the invariants that its pending finalize recoveries drain
  (`unresolved_finalize_recoveries`, one `MAX_SLEEP_DURATION` sleep,
  `check_finalize_recoveries_drained`), a check the continuation keeps; the Twins campaign
  counts `input.required_containers` finalizations of views after the Twins prefix
  (`observe_liveness`), so count only views after the handoff as well; the Twins mutator checks
  no liveness, so add none; Chaos, ByzzFuzz and Chaos-Twins measure from their own heal or
  recovery, which follows the handoff, so their targets stay as they are: the larger of
  `input.required_containers` and one view past the finalized view at the heal (Chaos: the
  highest, `liveness_target`; ByzzFuzz: each node's own, `reach_gst_and_check_liveness`), and
  for Chaos-Twins one view past the highest at its recovery.
- The scheme: the thin target names `SimplexCertificateMock` or another `cert_mock`
  instantiation of `consensus/fuzz/core`, as the base does.
- Missing, reported as `cannot:`: journal seeding, because the package has no
  `commonware-storage` dependency and no dependency may be added.
~~~

### 13.23 `prompts/subsystems/marshal-synthesize.md`

~~~markdown
### Marshal (`consensus/src/marshal/`, `consensus/fuzz/marshal/`)

- Paths you may change: `consensus/src/simplex/` and `consensus/src/marshal/`, the system
  under test, whose tests the script reruns when you change it, and the fuzz package
  `consensus/fuzz/marshal/`.
- Shape A first: `marshal_e2e_standard_deferred_cert_mock_scenarios`, whose
  `NotarizationBlockSplitScenarioInput` fixes a scripted `template` and its pre-GST
  `actions`, with the wedge's real Byzantine engine behind the runner's hook. The
  `*_twins_split_header` targets draw their Twins case from the stream `raw_bytes` seeds:
  `run_twins_with_backend` samples `twins::cases` from it and `case_selector` only indexes
  that sample, so no field pins the case, and a History about it takes Shape B; a fixed case
  needs a marked constructor for the private fields of `mocks::twins::Scenario` and
  `RoundScenario`, which only `cases` builds.
- Shape B uses, without an edit, the `pub(crate)` items of `scenarios`: the harness
  `FuzzScenarioStandardHarness`, its verbs and `finish`, `RecordingBuffer`,
  `ScenarioHandoff`, `RecordingResolver` and `init_injectable`; and
  `marshal::end_to_end::twins`. With a marked visibility edit: `scenarios::runner::run`,
  whose journal seeding before the engines start is how Simplex engines start from a
  reconstructed state, and the private modules `scenarios::{adversary, elector, strategy}`
  and `end_to_end::{input, runner, scenario}`.
- The scenario-prefix runner starts no engine during its prefix, so a History whose events
  need running engines, such as TS-0001's, takes an end-to-end base.
- Known restart site, which gets a marked call of `restart` when a scaffold runs it: the
  `StoreOp::Restart` arm of `marshal::store` (`marshal_actor_standard_store_cert_mock`),
  which restarts the marshal actor. The list is guidance, not a complete one.
- Of the scenario SPEC, `consensus/fuzz/marshal/src/scenarios/specs/SPEC.md`, rules S1, S2,
  S4, S7, I1 to I3 and I5 apply; S3 becomes the handoff check; S5 and R9 become `cannot:`;
  S0 and S6 do not apply, because the card and the module header cite the source, and I4
  does not, because the edit contract allows marked edits. Add no `ScenarioKind` variant.
- Only the victim, `Node::B`, has an injectable resolver, with one armed delivery at a time,
  and in `N4F1C3` node 0 has no marshal. The harness verbs that panic when the system under
  test does not answer (`await_wrapper` after 5 s, `verified` and `certified` on a write that
  is not durable) and the polls of the existing scenario prefixes, bounded to 64 rounds, are
  not used where a reply of the system under test decides: race the reply against the stage
  deadline instead.
- The fault phase is 12 s in the scenario-prefix runner and `FAULT_PHASE`, 30 s, in the
  end-to-end disrupter runner, so a release delay is a knob below the base's. Heights stop at
  the epoch ceiling (`BLOCKS_PER_EPOCH`): leave enough height below it after the handoff for
  the liveness measurement.
- Progress and deadline: no marshal base sets a runtime deadline, so `Stages::budget` takes
  `Duration::MAX`. Each base measures finalized heights against its own baseline, which a
  Shape B continuation counts from the handoff: the scenarios target, one block past each
  correct node's height at GST (`check_scenario_progress`); Twins, `input.trailing_blocks`
  blocks of views after the prefix (`wait_for_liveness`); the scenario-prefix runner, one
  block past each honest node's height at its heal, `input.required_containers` only ending
  the fault phase early; the disrupter and poison targets (`run_liveness_phases`),
  `input.required_containers`, or after a fault phase that ends without it, the larger of
  that and one block past each honest node's height at the heal; the store target checks no
  liveness.
- The scheme: every type argument of the thin target's call names a Simplex type with the
  `cert_mock` certificate scheme, such as `SimplexCertificateMock`, as the base does.
~~~

---

## 14. Acceptance procedures

| AC | Procedure | Pass condition |
|---|---|---|
| AC-1 | For each agent: `just extract-invariants issue <URL of a real Simplex bug>`. | At least one new `invariants/simplex/INV-*.md`; `just check-invariants` reports no problem for it. |
| AC-2 | On `main` with the subproject committed: `git ls-files statelens` lists no `Cargo.toml` other than `statelens/differential/Cargo.toml` and `statelens/differential/shim/Cargo.toml`, and `cargo metadata --format-version 1` at the root names neither `statelens-differential` nor `statelens-differential-shim`; `just check-fmt`; `just lint`; `just test -p commonware-consensus`; `just test -p commonware-storage`; the CI fuzz target listings for `consensus/fuzz/simplex`, `consensus/fuzz/marshal` and `storage/fuzz`. | All behave exactly as without the subproject. |
| AC-3 | `just check-invariants`; `git ls-files statelens/invariants statelens/false-invariants`; then `just extract-invariants --registry marshal comment consensus/src/marshal/mod.rs`. | No lint problem. Every invariant file is in a subsystem directory. The new files are in `invariants/marshal/`, numbered from the next global ID. |
| AC-4 | With at least one simplex invariant: `just campaign`, then the printed `run` command. | Materialize, instrument, plan, build and test gate complete, the result is `READY`, and the `run` command starts the fuzzer. |
| AC-5 | In an instrumented checkout, two 10-minute runs on empty corpora: `STATELENS_FEEDBACK=0 just run simplex_cert_mock_twins_mutator_statelens <empty dir A> -- -max_total_time=600` and the same without the variable on `<empty dir B>`. | The `ft:` value on the `DONE` line is higher with feedback. Compare `ft:`, not `cov:` (section 9.3). |
| AC-6 | `STATELENS_FALSE_INVARIANTS=1 just campaign`; if the result is `READY`, a short run of the printed `run` command. | Result `PANIC (tests)` with `[statelens][FALSE-0001]`, or a panic with it in the short run. |
| AC-7 | In an instrumented checkout, for each simplex variant: `STATELENS_BYZANTINE=panic just run <variant> -- -max_total_time=120`, then the same without the variable. `simplex_cert_mock_statelens`, whose `Standard` driver runs no engine under a Byzantine identity, is the negative control. | With the variable, the variants whose adversary runs a real Simplex engine (PRD section 8.4) panic with `[statelens][BYZANTINE]`, `simplex_cert_mock_audit_statelens` only once an input draws the RejectView choice and `simplex_cert_mock_mallory_statelens` only after an amnesia restart, and no other variant does. Without it, none does. `[statelens] participant index mismatch` never appears. Verified for the Twins runner at the reference commit, and for the hooks of Appendix B.5 with a temporary probe (section 1.2). |
| AC-8 | `just run simplex_cert_mock_twins_mutator_statelens <artifact>` in the checkout of a crashing Phase 3 run, with that run's `STATELENS_BYZANTINE` value. | The same `[statelens][...]` line as in that run. Verified for `BYZANTINE` (section 1.2). |
| AC-14 | With `STATELENS_KB` set to a findings corpus, run the queries of section 5.6 by hand for each registry: `kb modules`, `kb find`, `kb cites <a component directory>`, `kb grep`, `kb show`; then `just search-index` and `kb search` with a question. | Every command answers from the index; `find` and `cites` return only findings whose `module` is in that subsystem's filter; `cites` returns the findings that name files under the directory, with those files listed; `show` refuses a section that is not state-bearing and an identifier out of scope; `search` returns hits from the findings in scope, the documents, the code and the Markdown, never a finding out of scope or a section `show` refuses, and names `path:line@commit` and the item for a code hit. |
| AC-15 | `STATELENS_KB=` with a campaign. | The campaign warns that there is no knowledge base, renders the beacon step with no query commands, and still reaches `READY`. |
| AC-16 | A campaign with an invariant whose action is committed in a handler, then the same campaign with `STATELENS_AUDIT=0`. | With the pass: the invariant's `Sites` ledger names the commit site, the `Status` matches the ledger, and the `audit` and `plan` lines report it. Without it: no `audit` line, and the campaign still reaches `READY`. |
| AC-17 | `just check-plan` on a plan whose `bound` section leaves a commit site unchecked, and on a clean one; `just check-prompts` after editing a prompt, and after `--write`. | Exit 3 naming the section or the prompt, and exit 0 when clean. |
| AC-21 | With `STATELENS_KB` set to a findings corpus: `just extract-invariants --registry qmdb --number 3 kb`; then `just extract-invariants --registry qmdb comment <corpus root>`. | The first writes at most 3 new files, all in `invariants.local/qmdb/`, which `git status` does not list, and `just check-invariants` reports no problem for them. The second exits 1 and names the `kb` command instead. |
| AC-29 | On a fresh clone: `just campaign --profile marshal --invariants INV-0002`, `just campaign --invariants simplex/INV-9999`, `just campaign --invariants qmdb/INV-0001` and `just campaign --invariants ""`; then `just fuzz simplex --invariants INV-0002 --skip-campaign` and `just fuzz simplex_cert_mock --invariants INV-0002`; then `just campaign --invariants INV-0002 --stop-after instrument`. On another fresh clone, `just fuzz simplex --invariants INV-0002 -- -max_total_time=60`. | The four campaigns exit with code 2 and `SETUP FAILED` before any agent runs and leave the checkout fresh; the first names the `<registry>/INV-NNNN` form, the others end with `available: simplex/INV-0001, ...`. The two `just fuzz` refusals exit with code 1 and run nothing. The campaign that follows binds INV-0002 and nothing else: `SL/campaign/meta.json` has `"invariants": ["INV-0002"]` and the number of simplex invariants collected under `invariants_available`, the setup line reads `1 of <n> invariant(s) bound (simplex: INV-0002)`, `plan.md` reads `Invariants: 1 (simplex: INV-0002)` and has that one invariant section, the beacon prompts are rendered as without the flag, and `just check-plan` reports no missing section. The last runs `just campaign --profile simplex --invariants INV-0002` and then the variants. |
| R-NF-3 | Same duration and flags: `simplex_cert_mock_twins_mutator_statelens` in an instrumented checkout, and `simplex_cert_mock_twins_mutator` in an uninstrumented checkout at the same commit. | exec/s from `-print_final_stats=1` are reported side by side; a slowdown above 2x is recorded as an instrumentation problem. |

Section 8.6 gives the procedures for AC-9 to AC-13, and for R-NF-3 on the marshal
variants. Section 17.5 gives AC-18 to AC-20 for the qmdb profile. Section 18.10 gives AC-22
to AC-28, for Target-State Synthesis.

---

## 15. Implementation order

1. Create the layout of section 3 with the verbatim files: `config.env`, `justfile`,
   `templates/invariant.md`, all prompts with the subsystem parts (section 13),
   `false-invariants/simplex/FALSE-0001.md` (Appendix C),
   `false-invariants/marshal/FALSE-0002.md` (Appendix E),
   `false-invariants/qmdb/FALSE-0003.md` (Appendix G), `runtime/statelens.rs`
   (Appendix A). Create `invariants/simplex/`, `invariants/marshal/` and
   `invariants/qmdb/`, each with a `.gitkeep` file while it is empty. Invariant files
   that already exist go to their subsystem directory with `git mv`.
2. Check the runtime templates:
   `rustfmt +<pinned nightly> --edition 2024 --config-path rustfmt.toml --check statelens/runtime/*.rs`.
3. Implement `scripts/statelens.py` in this order: config and argument parsing, `lint`,
   prompt rendering, agent invocation, `extract`, the knowledge-base index and the `kb`
   commands, `lint-plan` and `lint-prompts`, then `campaign`. Implement `campaign`
   for the `simplex` profile first, starting with the materialize step and
   `--stop-after materialize`, then for the `marshal` profile (chapter 8), and then for the
   `qmdb` profile (chapter 17).
4. Write `README.md` (Appendix D).
5. Validate:
   - `just check-invariants`;
   - `STATELENS_FALSE_INVARIANTS=1 just campaign --stop-after build`, then AC-1 to AC-8;
   - `STATELENS_FALSE_INVARIANTS=1 just campaign --profile marshal --stop-after build`, then
     AC-9 to AC-13;
   - `STATELENS_FALSE_INVARIANTS=1 just campaign --profile qmdb --stop-after build`, then
     AC-18 to AC-20;
   - with `STATELENS_KB` set to a findings corpus, the queries of section 5.6, then AC-14
     and AC-15;
   - `just check-plan` and `just check-prompts` on the instrumented checkout, then AC-16
     and AC-17;
   - on a fresh clone, the refusals and the campaign of AC-29.
6. Then Target-State Synthesis (chapter 18), in this order: the read side (section 9.6) with
   its self-tests, the scope check of section 7.5 and the line of prompt 13.7; the card
   registry, its lint and TS-0001; extraction and `prompts/state-analyst.md`; the helper
   template; the selection, `targets --state-reaching`, `coverage`, `clean` and the refusal of
   section 7.1; `synthesize` with the guards of section 18.6.1 and the reach check; the
   synthesis prompts; the justfile; the README. Each verbatim copy in this document is added or
   updated with its file. Then AC-22 to AC-28 (section 18.10).
7. Change nothing outside `statelens/`, except the visibility change in
   `consensus/fuzz/marshal/src` of section 18.10.1 (AC-25).

---

## 16. Known limitations

- Throughput is about 13 executions per second per process, so fuzzing needs many
  core-hours. Run the targets with `-fork=<N>`.
- The patch anchors in sections 7.2, 8.3 and 17.3 follow the code. When one moves, the
  campaign stops with exit code 2 and the anchor in `statelens.py` must be updated.
- Agents are not deterministic: the same invariant can be bound differently in two
  campaigns. The plan and `instrumentation.diff` document each binding.
- A campaign instruments the checkout in place, so every campaign needs a fresh clone.
- The audit pass (section 7.3) is the same agent under the same rules as the pass it
  reviews, so it can repeat its own blind spot, and the `Sites` ledger it writes is what
  `lint-plan` judges: a commit site neither pass ever names escapes both. The campaign
  therefore also reports the assertion sites per source, where a layer nobody checked shows
  up as a source with none. The pass costs one agent run per batch of 8 invariants, and
  `STATELENS_AUDIT=0` skips it.
  The script refuses a checkout that an earlier campaign instrumented.
- The beacon components cover the Simplex actors, marshal's core, standard and coding
  (D28), and the qmdb variants and sync engine (D53). Code outside them, such as
  `types.rs`, the backfill resolver or the application code, gets no beacon probes even
  when the knowledge base has findings about it.
- `kb find` and `kb grep` are lexical (D33), so a word query misses a finding whose wording
  differs. A component's queries do not depend on wording, because they start from
  `kb cites <its directory>`; the remedy for a word query is another query in the loop.
- Replicas without a participant index (`me() == None`) have no per-replica ghost
  state, so ghost-based checks skip them.
- The Twins tests are not part of the test gate (D2). The fuzz harness itself exercises
  Twins scenarios with the correct guard.
- A target added to `consensus/fuzz/simplex` gets a variant in the next campaign (D57). If
  its driver runs a real engine under a Byzantine identity, it needs a hook like those of
  Appendix B.5; without one, the guard checks that replica as an honest one.
- The runtime module relies on the deterministic runtime running tasks on the calling
  thread (`Runner::start` calls `start_and_recover` on the same thread).
- `kb search` uses a small general-purpose model by default. Its window of 256 word pieces
  makes chunks short, it ranks identifiers poorly, which BM25 makes up for, and it knows
  nothing of Rust. A comment's item comes from indentation, so an unusual layout can name
  the wrong container, and a word longer than the window is left whole and truncated.
- The search index describes the commit it was built at. A hit's line holds at that
  commit, and the code index (section 5.7) says where the item is now.
- The index lock is a POSIX advisory `flock`, so the index belongs on a local file system,
  where every process that builds or queries it honors the lock.
- Section 18.11 lists the limitations of Target-State Synthesis.

---

## 17. StateLens for qmdb

This chapter specifies StateLens for the log-based databases of `storage/src/qmdb`: the
`qmdb` profile of PRD chapter 10. A `qmdb` campaign binds the qmdb registry, instruments
`storage/src/qmdb/`, and builds a StateLens variant of every `qmdb_*` target of
`storage/fuzz`. It follows chapter 7 with the differences of section 17.3, and the other
chapters apply to it unchanged. It shares the runtime template, the prompts and the script
with the consensus profiles and nothing else: no campaign instruments two crates (D49).

### 17.1 What was verified

At commit `290cdcf4c4`, in a scratch worktree materialized for the `qmdb` profile by the
script, without an agent and so without instrumentation:

- The anchors of edits Q2 and Q3, and of edits 7 and 8, each occur exactly once. All 17
  `qmdb_*` targets of `storage/fuzz/fuzz_targets/` derive a variant: 15 open their
  `fuzz_target!` block at the top level over `input: FuzzInput`, `qmdb_verify_proof` takes
  `data: &[u8]`, and `qmdb_current_mmb_prune_grow` is a one-line target (Appendix B.1). The
  generated runtime module and variants are `rustfmt`-clean.
- `cargo +stable check -p commonware-storage --lib --tests` passes, and the runtime's 10
  unit tests pass inside `commonware-storage` as `qmdb::statelens::tests::*`; with the read
  side of section 9.6 they are 17 (section 18.1).
- The test gate of section 17.3 passed: 2,289 tests, 428 of them in the `slow` group, in
  101 s on 16 cores.
- `cargo fuzz build` of `qmdb_current_mmb_prune_grow_statelens` and
  `qmdb_verify_proof_statelens` succeeds on the CI-pinned nightly. `just run
  qmdb_verify_proof_statelens -- -runs=20000` and `just fuzz
  qmdb_current_mmb_prune_grow_statelens --skip-campaign -- -max_total_time=15` run cleanly
  from `SL/`, on the toolchain read from `.github/workflows/slow.yml`; the second ran 13
  executions per second with a peak RSS of 460 MB.
- The `simplex` and `marshal` profiles materialize exactly the files they did before the
  `qmdb` profile was added.
- `STATELENS_FALSE_INVARIANTS=1 just campaign --profile qmdb` with a stub agent, a `claude`
  that reads its prompt and exits, reached `READY` in 20 minutes on a fresh worktree:
  materialize, the storage code index (45 MiB, 296 files), one invariant batch with
  FALSE-0003, six beacon runs and one audit run, the plan, the check, 17 fuzz builds and the
  test gate. The summary printed a `run` and a `replay` line for each of the 17 variants and
  no `components` line. Every rendered prompt names `storage/src/qmdb/statelens.rs` and
  `crate::qmdb::statelens`, and none keeps a placeholder.

A campaign with a real agent ran on 2026-10-05, at commit `86eed8302c` (section 1.2): it
instrumented, wrote the plan, audited and built, and its test gate failed only on the
open-file limit of section 17.6. Not verified: a repair, a `READY` result, AC-18 to AC-20,
the feedback of the StateLens table in a qmdb variant, and the throughput of the other
variants.

### 17.2 Decisions

| ID | Decision | PRD requirement |
|---|---|---|
| D49 | qmdb is a profile of its own, `qmdb`, with its own registry, subsystem prompts and false invariant. It shares the method, the runtime template, the prompts and the script with the consensus profiles. No campaign instruments two crates, so nothing is split or abstracted across them: the profile table names the crate, the runtime path and module, the anchors, the fuzz package and the tests. | G10 |
| D50 | The runtime module is the consensus template, copied to `storage/src/qmdb/statelens.rs` with `simplex::statelens` renamed to `qmdb::statelens` and the consensus-only tests left out (edit Q1). The Byzantine guard stays: qmdb passes `None` as `me`, which the guard always checks. | G8, R-Q-INS-1 |
| D51 | Variants are derived from every `qmdb_*` target of `storage/fuzz`, the same way as the consensus variants (Appendix B.1). The other storage targets fuzz the journals, archives and Merkle structures, which a qmdb campaign does not instrument. There is no cryptography check, because nothing in qmdb signs. | R-Q-P2-1 step 1, R-Q-P2-2 |
| D52 | The test gate runs every `qmdb::` test of `commonware-storage`, the `slow` group included, and there are no component tests: the qmdb tests drive whole databases through their API, which is what the instrumentation observes. | R-Q-P2-1 step 6 |
| D53 | The beacon components are the five variants and the sync engine: `qmdb.any`, `qmdb.current`, `qmdb.immutable`, `qmdb.keyless`, `qmdb.store` and `qmdb.sync`. The shared code (`mod.rs`, `chain.rs`, `bitmap.rs`, `operation.rs`, `verify.rs`, `compact/`) is probed from the components that call it. | R-Q-FB-1 |
| D54 | `just run` in `SL/` runs a `qmdb_*` target with `cargo fuzz run --fuzz-dir storage/fuzz` from the repository root, on the toolchain `consensus/fuzz` would pick, because storage has no fuzz recipes of its own; a consensus target goes through `consensus/fuzz`'s own `run`. | R-Q-P3-1 |

### 17.3 The `qmdb` campaign

A `qmdb` campaign follows section 7, with these differences.

Step 1, materialize. Edits 7 and 8 of section 7.2, and:

| # | File | Edit |
|---|---|---|
| Q1 | `storage/src/qmdb/statelens.rs` | Create from `SL/runtime/statelens.rs` (Appendix A): every `simplex::statelens` becomes `qmdb::statelens`, and everything from the line `// [statelens] consensus only:` to the end of the file is left out. |
| Q2 | `storage/src/qmdb/mod.rs` | After the line `pub mod verify;` insert `pub mod statelens;`. |
| Q3 | `storage/Cargo.toml` | After the line `thiserror.workspace = true` insert `sancov.workspace = true`. |
| Q4 | `storage/fuzz/fuzz_targets/<target>_statelens.rs`, for every `qmdb_*` `<target>.rs` in that directory | Derive it from `<target>.rs` as Appendix B.1 says, calling `commonware_storage::qmdb::statelens`. |
| Q5 | `storage/fuzz/Cargo.toml` | For every variant, append a `[[bin]]` block derived from the original's (Appendix B.2). |

As in section 7.2, a missing or repeated anchor aborts the campaign with exit code 2 before
any edit is made, and `git add --intent-to-add` covers the created files. There is no
runner hook: nothing in qmdb is compromised.

Step 2, bind invariants (section 7.3): the batches of the qmdb registry, with the qmdb
subsystem rules (section 13.18). The audit pass covers the same batches. With an empty
registry the step is skipped with a warning, and the campaign adds beacon probes only.

Step 3, beacon probes (section 7.4): one run for each of the six components of the profile
(section 5.5).

Step 4, plan and scope check (section 7.5): the editable root is `storage/src/qmdb/`, and an
edit under `storage/src/qmdb/benches/` is a warning.

Step 5, build (section 7.6): `CHECK` is
`cargo +<test toolchain> check -p commonware-storage --lib --tests`, and `FUZZBUILD` is
`cargo +<fuzz toolchain> fuzz build --fuzz-dir storage/fuzz <variant>`, run for each
variant in turn.

Step 6, test gate (section 7.7):

~~~
cargo +<test toolchain> nextest run -p commonware-storage --lib --no-fail-fast \
  --ignore-default-filter \
  --color never --message-format human --status-level pass --final-status-level fail \
  --success-output never --failure-output immediate \
  -E 'test(/^qmdb::/)'
~~~

The filter takes every qmdb test, the `slow` group included, and the runtime's own tests,
which are `qmdb::statelens::tests::*` in this copy. No component tests run after it (D52).

Step 7, hand-over (section 7.8): the summary gives a `run` and a `replay` line for every
variant, in file name order:

~~~
statelens: profile    qmdb
statelens: run        cd <repo>/statelens && NIGHTLY_VERSION=<fuzz toolchain> just run <variant> -- -rss_limit_mb=4000 -print_final_stats=1
statelens: replay     cd <repo>/statelens && NIGHTLY_VERSION=<fuzz toolchain> just run <variant> <repo>/storage/fuzz/artifacts/<variant>/<crash file>
~~~

Phase 3 (sections 7.10 to 7.13) applies to the variants. `STATELENS_BYZANTINE` has no
effect, because nothing is compromised.

### 17.4 Instrumentation conventions

These rules add to section 10 for qmdb code, and the qmdb subsystem rules (section 13.18)
give them to the agent.

| Topic | Rule |
|---|---|
| Editable code | Non-test code in `storage/src/qmdb/`, except `benches/`. A beacon run: its component directory and the shared code it calls. |
| Runtime | `crate::qmdb::statelens::...`. |
| Replica index | None. Every site passes `None` as `me`, and the guard checks it. |
| Ghost state | `Global` only, keyed by an identity a database keeps across a reopen, such as the partition its log uses, so that the databases of one run (a sync source and its target) never merge and a reopened database keeps its history. History that need not survive a reopen may live in a ghost field of the database itself. |
| Commit sites | `apply_batch` makes a merkleized batch, or in `store` a finalized changeset, the database's state, and `commit` or `sync` makes it durable; a check at `merkleize` or `finalize` stands for neither. A mutating method that returns an error consumes the database, so checks sit on its success path. |
| Discretization | Locations, floors and sizes relative to one another; never keys, values, digests or roots. |

### 17.5 Acceptance procedures

| AC | Procedure | Pass condition |
|---|---|---|
| AC-18 | With at least one qmdb invariant: `just campaign --profile qmdb`, then each printed `run` command. | Materialize (17 variants), instrument, plan, build and the test gate complete, the result is `READY` with one `run` line per variant, and each `run` command starts its variant. |
| AC-19 | `STATELENS_FALSE_INVARIANTS=1 just campaign --profile qmdb`. | Result `PANIC (tests)`, and `SL/campaign/logs/test.log` contains `[statelens][FALSE-0003]`. |
| AC-20 | `just run <variant> <artifact>` in the checkout of a crashing Phase 3 run. | The same `[statelens][...]` line as in that run. |
| R-NF-3 | With the same duration and flags: each variant in an instrumented checkout, and its original target in an uninstrumented checkout at the same commit. | The exec/s values are reported side by side. A slowdown above 2x is recorded as an instrumentation problem. |

### 17.6 Known limitations

- The qmdb registry starts empty, so a first campaign adds beacon probes only. Phase 1 fills
  it: `just extract-invariants --registry qmdb comment storage/src/qmdb/...`, and the other
  source kinds.
- There is no worked analysis of qmdb in `examples/`. The binding and beacon prompts name the
  Simplex and marshal ones as reference for the method.
- Every database of a run shares one `Global`. A binding that does not key its history per
  database (section 17.4) merges the histories of a sync source and its target.
- The code index covers one crate at a time: after a qmdb campaign, `just code` answers
  about storage until `just code-index --subsystem simplex` builds it for consensus again.
- The storage targets other than `qmdb_*` get no variant (D51), although qmdb builds on the
  journals and Merkle structures they fuzz.
- The anchors of edits Q2 and Q3 and the target shapes of Appendix B.1 follow the code; a
  change stops the campaign with exit code 2.
- The test gate fails at an open-file soft limit of 256, the macOS default:
  `qmdb::any::unordered::fixed::test::test_merkleize_cancellation_leaves_db_usable` runs on
  the tokio runtime, opens more blob files than that, and fails with `TooManyOpenFiles` and
  no `[statelens]` line. It fails the same way without instrumentation. Raise the limit in
  the shell that runs `just campaign`, `just fuzz` or `just test`, for example with
  `ulimit -n 65536`.

---

## 18. Target-State Synthesis

This chapter specifies Target-State Synthesis (PRD chapter 11) for the `simplex` and
`marshal` profiles. Phase 1 turns a test, an issue or pull request, a comment, a report or a
text into a reviewed card: one target state of honest replicas, and the history of events that
reaches it (sections 18.3 and 18.4). After a campaign, `synthesize` has an agent write one
scaffold per card and base, a dedicated fuzz target built on an existing target, its base: the
unit of synthesis is the pair (card, base), and a card is synthesized on every selected base.
The scaffold fixes the card's essential setup and history, leaves the uncertain values to
libFuzzer as knobs, and reports which events of the history it reached, witnessed by the
probes the campaign installed and by harness observables (sections 18.6 to 18.8). A reach check replays
each scaffold on fixed inputs, and its verdict drives up to three refinements. Every scaffold
that passes the vetoes and builds, and that the test gate does not restore (guard 5 of section
18.6.1), is fuzzed with `just fuzz <profile> --state-reaching` (section 18.9). qmdb is
refused.

The files this chapter adds, and its changes to `runtime/statelens.rs` and the justfile, are
reproduced verbatim elsewhere in this document: the prompts in sections 13.20 to 13.23, the
helper template in Appendix H, the justfile in section 5.3 and the runtime in Appendix A.
`templates/target-state.md` and TS-0001 are given verbatim in section 18.3.

### 18.1 What was verified

At commit `37e01e1036`, by reading the code and the libraries it uses:

- A module declared in a fuzz package's crate root sees the root's private items. In
  `consensus/fuzz/simplex/src/lib.rs`, `run_standard_once`, `run_audited_standard_once_with`,
  `run_twins`, `MockTwinsBackend`, `configure_block_filter`, `spawn_disrupter_with_relay` and
  `install_chaos_panic_hook` are private items of the crate root, so
  `crate::target_states::tsNNNN` uses them without an edit. `chaos::runner::run` is
  `pub(crate)`; `run_with`, `restart_durable`, `enact` and `check_safety` beside it are private.
- In `consensus/fuzz/marshal/src/`, `scenarios/mod.rs` declares `adversary`, `elector` and
  `strategy` private and its other modules `pub(crate)`, and `scenarios::runner::run` is a
  private function. `marshal/end_to_end/mod.rs` declares `input`, `runner` and `scenario`
  private. `FuzzScenarioStandardHarness`, `RecordingBuffer`, `ScenarioHandoff`,
  `RecordingResolver` and `init_injectable` are `pub(crate)`.
- Each declaration anchor occurs once: `pub mod state_cov;` in
  `consensus/fuzz/simplex/src/lib.rs`, and `pub mod scenarios;`, under
  `#[cfg(feature = "mocks")]`, in `consensus/fuzz/marshal/src/lib.rs`.
- The input types of the candidate bases, `FuzzInput`, `MarshalDisrupterInput`,
  `NotarizationBlockSplitScenarioInput`, `MarshalTwinsInput`, `MarshalScenarioPrefixInput` and
  `MarshalActorStoreInput`, implement `Arbitrary` by hand without `size_hint`, so libfuzzer-sys
  0.4.13 does not skip the empty input, and each decodes it. The first three then hold an
  empty `raw_bytes`, and the other three `[0]`.
- `corpus/`, `artifacts/` and `coverage/` of every fuzz package are ignored by git (the
  repository's `.gitignore`); a `crash-*` file libFuzzer writes anywhere else is not.
- libfuzzer-sys replaces the panic hook with one that runs the previous hook, which prints
  `panicked at <file>:<line>:<col>`, and then aborts, so a panic never unwinds out of a target.
- `simplex_cert_mock_mallory` is the only target with `fuzz_mutator!`.
- PR #4317 was merged as `85f85284d7`, an ancestor of `37e01e1036`, and the citations of the
  card in section 18.3 hold at `37e01e1036cb`.

With the implementation, at commit `8a0d2cef73`, in scratch worktrees the script materialized
for the `simplex` and `qmdb` profiles, without an agent and so without instrumentation:

- The runtime with its read side checks and passes `clippy -D warnings` in
  `commonware-consensus` and `commonware-storage` on stable, and its self-tests pass: 19 in
  the consensus copy (`simplex::statelens::`), 12 of them from before the read side, and 17
  in the qmdb copy, also with `--test-threads=1`.
- The helper, copied into both fuzz packages with the declarations of section 5.5 and a
  throwaway scaffold per package that uses every item of section 18.7 (Shape A on a base
  entry, Shape B with `Witness::act_async` from a spawned task), checks with no error or
  warning. Under `STATELENS_REACH=1` it printed 43 lines, every one matching the patterns of
  section 18.8, and each scaffold error of section 18.7 fired with its message.
- A thin target of that scaffold, built with `cargo fuzz build` on the CI-pinned nightly
  and replayed on the empty file: the canonical replay printed `handoff lost` after a missed
  stage, since no probe exists without instrumentation; the control replay printed
  `withheld`, kept the prefix open and printed `handoff holds` and `control=1`; a planted
  panic printed the helper's lines and then libFuzzer's, and the process aborted with exit
  code 77; an empty knob domain raised the scaffold error at a location in
  `target_states/mod.rs`. libFuzzer runs a passing input a second time inside the same
  replay, to look for leaks, so a passing replay printed its lines twice; a failing one
  printed them once (section 18.8).
- `synthesize` end to end, with a stub agent that wrote a Shape A scaffold of TS-0004 on
  `simplex_cert_mock`, after `campaign --stop-after materialize` and a READY summary written
  by hand: the fuzz build took about 2 minutes, the verdict was `UNREACHED 0/4`, a second run
  skipped the card, `--redo` undid it and synthesized it again, and `clean --yes` left
  nothing behind.

With the differential test of section 18.10.1, at commit `392b116687` with the uncommitted
visibility change and test crate, in the scratch worktree `SL/scripts/differential.sh` made:

- `commonware-consensus-fuzz-marshal` with the widened visibility passes
  `cargo +stable clippy --all-targets -- -D warnings`, `rustfmt --check` of the nine touched
  files on the pinned nightly, and `cargo +stable nextest run` (80 of 80 tests), so the change
  changed nothing the package tests.
- The two templates of `SL/runtime/` compile byte-identical under the shim, and
  `cargo metadata` at the repository root lists neither `statelens-differential` nor its
  shim.
- All 24 positive tests print `digest-equal=true` and are `REACHED n/n`, with no annotation
  and no `witness rejected` in any replay; each of the 6 negative controls gives, from a
  replay that ran to its digest line and a verdict the validator computed, an unequal
  digest or a verdict other than REACHED (the table of section 18.10.1); the whole procedure
  ends `differential: PASSED` about 180 s after the builds. After the review fixes of
  2026-10-08 (the script's `(ERROR)` rows, test manifest and per-run directory; TS-9005's
  `try_recv` at E2; TS-9006's E4 count), the run was repeated with the fuzz package's checks
  skipped, since that package did not change: the same 30 rows, `differential: PASSED`.
  After the verifier's leftovers (`(NOT CAUGHT)` matching REACHED annotated or not,
  TS-9006's stamp moved to E2), the whole procedure ran once more, the fuzz package's checks
  included: the same 30 rows, `differential: PASSED (+187s)`.

Not verified: a synthesis with a real agent or after a real campaign, AC-24 to AC-28 as
written (the differential test of AC-25 judges the primitives and a hand-written
reconstruction, never an agent's output), any marshal synthesis by an agent, and whether the
Phase 1 permissions of section 12 let the agent read a `text` file outside the repository (as
for `design` and `paper`).

### 18.2 Decisions

| ID | Decision | PRD requirement |
|---|---|---|
| D59 | Target states are a registry of their own: `SL/target-states/<subsystem>/TS-NNNN.md` for `simplex` and `marshal`, and the git-ignored `SL/target-states.local/<subsystem>/`. One global `TS` counter covers both (as D18), every card is active, and a card has no status field (as D1). A card is a reachability goal, never an oracle, and names no probe label, because labels change with every campaign. The registry reuses the invariant files' machinery: file names, lint and excerpts. | R-TS-REG-1 to R-TS-REG-4 |
| D60 | Phase 1 writes cards with `extract --states`, one prompt, `state-analyst.md`, for every kind, and the subsystem's analyst part. The kinds are those of section 6.1 plus `test` and `text`. A card goes to the local registry when its source is not public: `kb`, `text`, a path outside the repository, or a run with `--local`. The card is the record of its source: synthesis reads only the card and the code, and no raw input is archived. | R-TS-P1-1 to R-TS-P1-3 |
| D61 | The runtime template gains a read side (section 9.6): an ordered trace of the guarded probe observations of one input, off unless a scaffold watches, with the call site and the runtime instance of each; the fresh-run hook counts runtime instances. One event sequence per input gives every observation and every helper event (`tick`) its own position, so positions are unique and strictly ordered. Instrumentation never calls it. The counter table and the features are unchanged. | R-TS-FB-1, R-INS-3, R-INS-5 |
| D62 | `synthesize` is a step of its own, run after a campaign of the same profile on the checkout it instrumented. It never instruments: it adds no probe, assertion or ghost state. Its edits follow the edit contract (R-TS-SYN-3, section 18.6.1), whose guards 1 to 3 compare the tree with a baseline that the campaign's first synthesis takes and every later one reuses. Its agent runs with Phase 2 permissions (D4), as a second role with its own scope (amends R-INS-7). Pairs of a card and a base are synthesized one at a time, because they share one crate. qmdb is refused. | R-TS-SYN-1 to R-TS-SYN-4 |
| D63 | Scaffolds are written, not derived: an exception to D5, D24, D57 and Appendix B.1. Per pair (card, base) the agent writes a module `<package>/src/target_states/tsNNNN_<base>.rs` and a thin target `<base>_tsNNNN_statelens.rs` (Appendix B.6): a card yields one scaffold per selected base, and the agent chooses no base; the script owns `target_states/mod.rs` (the helper template and the `pub mod` lines), its anchored declaration in `<package>/src/lib.rs`, and the `[[bin]]` block, the base's renamed (Appendix B.2), which it writes after the agent's attempt; the agent adds the same block only for its own build and removes it again (section 18.7). The name keeps the `<profile>_` prefix and the `_statelens` suffix, so `just run`, the refusal of section 7.1, `clean` and `--fuzz-targets` keep working. Bases with `fuzz_mutator!` are excluded. D15 and the Byzantine guard apply. | R-TS-SC-1, R-TS-SYN-4, R-P2-4 |
| D64 | Knobs are the first K <= 16 bytes of the base input's own `raw_bytes`, zero-padded. A knob is `domain[byte % len]` with the source value as `domain[0]`, so the empty input is the canonical input and decodes to the source history. The input type, the `run` recipe and the libFuzzer flags are the base's; there is no seed corpus. | R-TS-SC-2, R-TS-NF-1 |
| D65 | One stage per History event. A stage is held only through a witness record that binds every entity of its line, from an `exact`, `intrinsic` or `construction` witness, and the script recomputes the records and rejects those that do not establish the line. Positions come from the event sequence (D61), and the helper takes them itself, for a stamped entry and for an action it performs, so order checks are strict, and an incarnation is named by the position of the restart that began it. A held stage adds the feature `(site_hash("TS-NNNN"), k, 0)`. The first miss closes the scripted prefix, except in the control run, and the input continues into the base's free-running phase and every oracle. Handoff comes before recovery: the target state is witnessed at the handoff instant, by a fresh read of `En`'s witness inside the handoff call, with every fault the prefix opened still in place, and those faults are released in the continuation, no later than the base's first heal. | R-TS-SC-3, R-TS-SC-4, R-TS-FB-2 |
| D66 | The reach check replays fixed inputs and does not fuzz: the canonical empty input, a control run that withholds one harness event, and a final canonical replay, each in individual-file mode with no corpus and no flags (a carve-out from D23 and R-P3-1). The agent builds its scaffold but never runs it: only these replays judge a version, and a crash file any other run leaves is kept as a finding candidate. Verdicts are reported only: every scaffold that passes the vetoes and builds, and that guard 5 does not restore, is fuzzed. Every failure of a replay is a finding candidate. Where it happened is diagnostic context only; the one failure attributed to the scaffold is an error the helper itself raises with `[statelens-scaffold]`, before any engine starts. | R-TS-SYN-5, R-TS-SYN-6 |
| D67 | Up to `REPAIR_ATTEMPTS` (3) further agent attempts per pair, driven by the verdict and its stage lines. Automatic repair covers only explicitly identified scaffold errors and the outcomes that are not failures. A finding candidate stops refinement for its pair, and that version is kept and fuzzed, never replaced by one that avoids the failure; if guard 5 restores it, its failure stays a finding candidate. Otherwise the best built version is kept. This is not iterative state discovery: there is no frontier. | R-TS-SYN-7 |
| D68 | `just fuzz simplex --state-reaching` and `just fuzz marshal --state-reaching` run the campaign (unless `--skip-campaign`), `synthesize`, and then the scaffolds only, through the existing sequential, `--parallel` and `--tmux` branches, in the session `statelens-<profile>-reach`. `--state-targets` selects card ids (`TS-0003`) and `--fuzz-targets` candidate bases, both repeatable and both forwarded as `--match`; a pattern of the other flag's form is refused, `--state-targets` needs `--state-reaching`, and each selected card yields one scaffold per selected base, every candidate base without `--fuzz-targets`. Unknown flags are refused (amends R-P2-5). | R-TS-P3-1, R-TS-P3-2 |

### 18.3 Target-state registry

**Files and IDs.** One card per file, `SL/target-states/<subsystem>/TS-NNNN.md`, where
`<subsystem>` is `simplex` or `marshal`, with a `.gitkeep` while a directory is empty. Cards
from sources that are not public live in `SL/target-states.local/<subsystem>/`, which git
ignores (section 18.4). The next ID is `1 + max(N)` over the `TS-N` files of both trees, as
for invariants (section 4.1); a local ID that collides with a tracked one is renumbered by
hand. Every card is active: a synthesis of profile `P` uses every card of
`target-states/P/` and `target-states.local/P/`.

**Front matter.** The five keys of section 4.2, in that order. `source_kind` also allows
`test` and `text`, and `scope` takes the registry's values. `source_ref` is:

| Kind | `source_ref` |
|---|---|
| `issue` | The URL, then `(merged as <commit>)`, or `(head <commit>)` for a pull request not merged yet |
| `test` | `path:line@commit (<test name>)` |
| `text` | `text: <title>`, or the path of the file given |
| `kb` | `finding <identifier>`, as for an invariant (prompt 13.19) |
| `human`, `design`, `comment`, `spec`, `paper` | As in section 4.2 |

**Sections**, in this order:

| Section | Required | Content |
|---|---|---|
| `## Statement` | yes | One sentence, "While <conditions>, the replica <is doing or holds> <state>.", about honest replicas, with no implementation identifiers (R-REG-4). |
| `## Rationale` | yes | What can go wrong in that state, and why reaching it matters. |
| `## Evidence` | yes | The source and what it shows, with pinned citations (section 4.3) of at most about 40 lines each. For `text`, the passages that define the History, quoted verbatim, and a summary of the rest. For a fix, the state the bug needed, not its bad outcome. |
| `## History` | yes | The events that reach the state, below. |
| `## Knobs` | yes | `None.`, or the table below. |
| `## Observation hints` | no | Functions, types, tests and INV ids that implement or watch the events. No line numbers and no probe labels. |
| `## Source excerpts` | generated | As in section 4.3, with the same note, which says "this invariant". |

**History.** Events `E1.` to `En.`, numbered from 1 without a gap. Each starts with its actor
and a colon: `harness` for what the scaffold does (configure, deliver, crash, script a
Byzantine replica), or the name of the honest replica that acts. It names the entities it
involves by short names: replicas (`R`, `B`), views (`v`, `p1`), payloads (`d`), certificates
and incarnations. A replica's name starts with a capital letter and every other entity's with a
small one: the reach check treats an actor other than `harness`, and an entity whose name
starts with a capital letter, as a replica (section 18.8). Each of `E1` to `E(n-1)` is followed by one indented `Check` line, what is
observable once the event happened; `En` is followed by one indented `Holds` line, the target
state as it holds at handoff. Each such line starts with the entities it binds, in parentheses.
`x as Ek` is the value event `Ek` bound to `x`; a name without `as` is existential, "for some
x", and the stage that witnesses the line binds it. An optional last line, `Order: Ei and Ej
in either order`, with more pairs, each of that form, separated by `;`, and an optional final
period, frees those pairs; every other pair of events happens in numbered order. A line may
continue on indented lines (the template indents by four spaces) that start with neither
`Check` nor `Holds`. For example:

~~~
E4. harness: as B, sends R a notarize vote for payload d in view v under a header that
    names p1.
    Check (R as E1, v as E1, d, p1 as E2): R is verifying the proposal of d for v under
    the header that names p1.
~~~

**Knobs.** `None.`, or a table `| Knob | Event | Domain | Source value |` of 1 to 16 rows, one
byte each (section 18.7). `Event` names the events the knob varies (`E5`, `E2-E4`, or a list
of those). `Domain` lists at least two values, the source value first, and `Source value`
repeats it: it is what byte 0 decodes to. A knob never varies what the History makes
essential, and an ordering knob varies only an order that `Order:` frees.

**Lint.** Rules 1 to 11 of section 4.6 apply to cards, with three changes: rule 1 takes
`TS-\d{4,}\.md` in `target-states/<subsystem>/` or `target-states.local/<subsystem>/`, with
`simplex` or `marshal` as `<subsystem>`; rule 5 also allows `test` and `text`; and rule 7
requires Statement, Rationale, Evidence, History and Knobs, in this order and non-empty. Two
rules apply to cards only:

12. History: events numbered `E1.` to `En.` without a gap, n >= 1, each at the start of a line,
    starting with an actor and a colon, the actor being `harness` or a name in the event's own
    entity list that starts with a capital letter, as a replica's does; exactly one indented
    `Check (` line after each of `E1` to `E(n-1)` and one
    indented `Holds (` line after `En`; every entity list non-empty, each entry a name
    (`[A-Za-z][A-Za-z0-9]*`) optionally followed by ` as E<k>`; every `as Ek` names an earlier
    event whose own entity list holds that name; and at most one `Order:` line, the last,
    starting at the beginning of a line,
    whose pairs, separated by `;`, each read `Ei and Ej in either order`, a final period
    allowed, and name only defined events. A line indented by any whitespace that starts with
    neither `Check` nor `Holds` continues the line above it, unless it starts with `Order:`,
    which is a problem. Whether an entity other than an actor that names a replica starts
    with a capital letter is for review.
13. Knobs: `None.`, or a table with exactly the header `| Knob | Event | Domain | Source value |`
    and a separator row of four cells, such as `|---|---|---|---|`, and 1 to 16 rows of four cells with no empty
    cell, whose Event cells each name at least one event and only defined events.

`just check-invariants` lints the cards with the invariants, with the same exit codes. Whether
a domain holds two values, a line is observable, or a History is causal is for review.

**`templates/target-state.md` (verbatim)**

~~~markdown
---
id: TS-NNNN
title: <one line, at most 80 characters>
source_kind: <human | issue | design | comment | spec | paper | kb | test | text>
source_ref: <URL (merged as <commit>) or (head <commit>), path:line@commit (test name), path or URL, text: <title>, or finding <identifier>>
scope: [<one or more of the registry's scope values, listed in the prompt context>]
---

## Statement
<One sentence: "While <conditions>, the replica <is doing or holds> <state>." About honest
replicas; no implementation identifiers.>

## Rationale
<What can go wrong in this state, and why reaching it matters.>

## Evidence
<The source and what it shows. Cite a line as path:line@commit, with the path from the
repository root, at most about 40 lines per range. For a text source, quote the passages that
define the History verbatim and summarize the rest. For a fix, describe the state the bug
needed, not its outcome.>

## History
E1. <actor: harness, or an honest replica's name>: <what happens, naming its entities>.
    Check (<entities it binds; one bound earlier is written x as Ek>): <what is observable
    once E1 happened>.
E2. <actor>: <the event that brings about the target state>.
    Holds (<entities>): <the target state as it holds at handoff>.
Order: <Optional: Ei and Ej in either order. Delete this line if unused.>

## Knobs
<Either the line None. or the table below, with 1 to 16 rows; keep one and delete this line.>
| Knob | Event | Domain | Source value |
|---|---|---|---|
| <name> | <Ek, or Ei-Ej> | <two or more values the fuzzer may choose, the source value first> | <the source's value> |

## Observation hints
<Optional and non-binding: functions, types, tests and INV ids that implement or watch the
events. No line numbers and no probe labels. Delete this section if unused.>
~~~

**Example.** `SL/target-states/marshal/TS-0001.md` is written by hand from PR #4317 and is the
example the Phase 1 prompt points at. As committed it reads as follows, followed by its
generated Source excerpts:

~~~markdown
---
id: TS-0001
title: Certifying a notarized proposal after rejecting another header of its payload
source_kind: issue
source_ref: https://github.com/commonwarexyz/monorepo/pull/4317 (merged as 85f85284d7)
scope: [replica, standard, cross-component]
---

## Statement
While the replica has rejected the proposal of view v under a header that names one parent,
has signed a nullify vote for v, and holds a notarization of the same payload under a header
that names another parent and that it did not sign, the replica is certifying that notarized
proposal.

## Rationale
The leader signs the parent separately from the payload, so a Byzantine leader can show one
payload under two headers, while certification is keyed by view and payload only. A verdict
computed under the rejected header and reused for the notarized one leaves the replica unable
to leave v: after its nullify vote it may not finalize v, and with the Byzantine replica silent
no nullification or finalization of v forms. The fix routes such verdicts to recovery; this
state is where a regression, or an untested variant such as a verification still pending
when certification starts, shows.

## Evidence
PR #4317 states: "A validator that correctly rejected one header cached false in the gate, and
certification of the honest notarization for the same (round, payload) then adopted that
cached verdict." Its end-to-end test drives the state with a real engine,
scripted_byzantine_parent_equivocation:
consensus/src/marshal/standard/mod.rs:2349-2352@37e01e1036cb. The variant in which
verification is still pending when certification starts is
pending_conflicting_verify_does_not_poison_certification:
consensus/src/marshal/standard/mod.rs:2220-2223@37e01e1036cb. The fix publishes a recover
outcome instead of a cached rejection:
consensus/src/marshal/application/gates.rs:19-26@37e01e1036cb and
consensus/src/marshal/standard/deferred.rs:803-812@37e01e1036cb.

## History
E1. harness: runs four replicas, R honest and B Byzantine, with B the leader of view v.
    Check (R, B, v): R's leader for v is B.
E2. harness: starts R from the finalized view p1, with the block of view p2 stored, whose
    parent is p1; the two other honest replicas certified p2 and R did not.
    Check (R as E1, p1, p2): R has finalized p1, stores the block of p2 and holds no
    certification of p2.
E3. harness: delivers a nullification of p2 to R.
    Check (R as E1, p2 as E2, v as E1): R holds a nullification of p2 and is in view v.
E4. harness: as B, sends R a notarize vote for payload d in view v under a header that
    names p1.
    Check (R as E1, v as E1, d, p1 as E2): R is verifying the proposal of d for v under
    the header that names p1.
E5. R: rejects that proposal and signs a nullify vote for v.
    Check (R as E1, v as E1, d as E4, p1 as E2): R's verification of d for v under the header
    that names p1 failed, and R broadcast its nullify vote for v.
E6. harness: delivers to R a notarization of d for v under a header that names p2, signed
    by B and the two other honest replicas.
    Check (R as E1, v as E1, d as E4, p2 as E2): R holds that notarization and did not sign
    it.
E7. R: starts certifying the notarized proposal.
    Holds (R as E1, v as E1, d as E4): R's certification of d for v is outstanding, and R
    holds its own nullify vote for v.
Order: E5 and E6 in either order.

## Knobs
| Knob | Event | Domain | Source value |
|---|---|---|---|
| p1, p2, v | E1-E3 | (1, 2, 3), (2, 3, 4), (5, 6, 7); the elector is pinned so that B leads v | (1, 2, 3) |
| E5 against E6 | E5-E6 | E5 first; E6 first, while R's verification is still pending, so R drops the stale rejection and signs its nullify vote on a timeout | E5 first |
| block of v | E4 | before E4; after E6; never, so R fetches it | before E4 |
| pause between harness actions | E3-E6 | 250, 0, 500, 1000 ms | 250 ms |

## Observation hints
GateOutcome and gates::drive in marshal's application code; certify of the deferred and
inline adapters; State::add_notarization and the certification candidates of the voter
state. INV-0044 (E5), INV-0047 (E7), INV-0013 (after E7).
~~~

The first cards, written by hand as `extract-states` writes a card, are TS-0001; TS-0002, from
the `test` source `consensus/src/marshal/standard/mod.rs:7027`, inside
`test_standard_finalized_delivery_rejects_epoch_mismatch`; TS-0003, from the `test` source
`consensus/src/simplex/mod.rs:3260`, `all_crash_after_nullify`; and TS-0004, a simplex card
from a `text`, which would go to the local registry and is tracked by hand: R votes nullify in
v, a notarization of v reaches R, and R dispatches certification of v. TS-0002 to TS-0004 pin
their citations at `8a0d2cef732b`. TS-0004 is expected to be
REACHED, with an `exact` witness for its last event (section 18.10) and seq-stamped evidence
for R's nullify vote too, from a transparent recording wrapper around R's reporter or vote
sender in `target_states/`: the reporter's `nullifies` map read after the run gives presence
only, which cannot order the vote (section 18.7).

### 18.4 Phase 1: extracting target states

`just extract-states [--agent A] [--registry simplex|marshal] [--number N] [--local] <kind>
<source>...` runs `statelens.py extract --states`. It follows section 6.2, with these
differences.

**Kinds.** Those of section 6.1, and two that only `--states` accepts; without it they exit
with code 1, as `--local` does without `--states`, and `--states` with `--registry qmdb`:

| Kind | Source syntax | How the agent reads it |
|---|---|---|
| `test` | `path:line` or `path:start-end` in a file under the registry's source (section 6.1) or the fuzz package of its profile (section 5.5); any other path, a line outside the file, a start after the end, or a file that `HEAD` does not have exits with code 1: a card cites its test at the commit the agent pins, so an untracked or merely staged test is committed first or given as `text` | The enclosing test, its helpers and the code it drives. The History follows the calls that build the state, and the test's assertions on the outcome are dropped. An incidental choice becomes a knob or is dropped (rule S7 of `consensus/fuzz/marshal/src/scenarios/specs/SPEC.md`). A message the test puts straight into a mailbox becomes the protocol event that delivers the same input. |
| `text` | A file, or a literal that the script writes to `SL/extract/<UTC timestamp>-text.txt`, or `-text-<n>.txt` when a run has several, for the agent to read. A source that is not a file and holds no whitespace exits with code 1 ("quote a text"): it is a mistyped path or a text that was not quoted | `source_ref` is `text: <title>` or the file's path, never the copy in `extract/`. Evidence quotes the passages that define the History verbatim, at most about 40 lines, and summarizes the rest. Every event is confirmed against the code or dropped. |

For the other kinds: an `issue` card's `source_ref` is the URL with the merge commit, or with
the head commit of a pull request not merged yet, which is extracted again after the merge to
pin its tests. Its Evidence pins the code the History runs against, normally `HEAD`; for a fix,
the target state is the precondition the bug needed, and the tests the pull request adds are
the main material. With `--states` a `kb` source may also be one finding identifier, resolved
as `kb show` resolves it; an unknown identifier, or one out of the registry's scope, exits with
code 1, as `kb show` does. A `comment`, `design`, `spec` or `paper` source describes a protocol
situation, each event of which is confirmed against the code.

**Routing by disclosure.** A card goes to `SL/target-states.local/<registry>/` when its source
is not public: a `kb` or `text` source, any source path outside the repository, and any run
with `--local`, for a private advisory or a private repository. Public URLs and paths in the
repository go to `SL/target-states/<registry>/`. A local card is shared by rewriting it
without private detail and moving it by hand, as D55 says for invariants.

**The card is the record.** Synthesis reads only the card and the code, so the card carries
what is essential, and no raw input is archived:

| Input | Kept as |
|---|---|
| Public issue or pull request | URL and commit in `source_ref`; the decisive sentences quoted and the code pinned in Evidence. It is fetched live at extraction; the prompt and log stay in `SL/extract/`. |
| Test, code comment | Pinned `path:line@commit`, copied into the generated Source excerpts |
| Text | The defining passages quoted in Evidence; the copy in `SL/extract/` is ignored by git |
| Finding, private advisory or issue | Stays where it lives (`STATELENS_KB`, R-KB-6); the card is local |
| Paper, design document | URL or path; a paper's text is cached in `SL/extract/papers/` |

A campaign and a synthesis run in a fresh clone, which has no ignored files, so the operator
copies `target-states.local/`, like `invariants.local/`, into it (Appendix D); `synthesize`
prints how many cards are tracked and how many local.

**Prompt.** `prompts/state-analyst.md`, rendered alone with the placeholders of section 6.2
step 5, where `TEMPLATE` is `templates/target-state.md`, `NEXT_ID` comes from the `TS`
counter, `DESTINATION` is the card tree, `COUNT` is worded for cards, and `CONTEXT` is
`prompts/subsystems/<registry>-analyst.md`. Its sections cover what a target state is (a state
of honest replicas that only a specific history reaches, never a property and never an
oracle); how to read each kind (the table above); what is essential and what incidental (would
a check on the state change; an incidental value becomes a knob, its source value first; an
arbitrary order becomes an `Order:` pair; a timing domain straddles the timeout it matters
for); the History format (an actor per event, the entities and their relations in every
`Check` and `Holds` line, no probe label, no implementation identifier outside Observation
hints, never an event the protocol cannot produce); and the output (one file per state in
`DESTINATION`, IDs from `NEXT_ID`, at most `COUNT`, citations pinned at `COMMIT`, no Source
excerpts, modelled on `SL/target-states/marshal/TS-0001.md`; zero cards is a valid result). Its
verbatim copy is section 13.20.

**Checks.** Steps 7 to 9 of section 6.2, over the four registry trees: an existing card or
invariant modified, a new file outside the destination, more than `--number` new files, and a
worktree change outside those trees, `SL/extract/` and `SL/campaign/` are problems.
The new cards get their Source excerpts and are linted with rules 1 to 13, and the reminder
reads "Every card is used by the next synthesis of its profile. Review, edit or delete these
files first.", with the note of section 6.2 step 9 for local cards. The exit codes are those of
`extract` (section 5.4).

### 18.5 Read side

A scaffold reads which probes fired through the read side of the runtime template, section
9.6: an ordered trace of the probe observations of one input, each with its call site and its
runtime instance, off unless a scaffold watches, and one event sequence that gives every
observation and every helper event its own position. Instrumentation never calls it.

### 18.6 Synthesis

#### 18.6.1 Edit contract

The edit contract is PRD R-TS-SYN-3. Synthesis runs on a disposable copy, the instrumented
checkout, and its edits may change how existing behavior is exposed or observed, never what
the protocol does. The rest of this chapter, prompt `synthesize.md` and the acceptance
procedures refer to R-TS-SYN-3 rather than restate what an edit may do.

- **Where.** The profile's editable roots (section 5.5: `consensus/src/simplex/`, and
  `consensus/src/marshal/` for `marshal`) and the profile's fuzz package
  (`consensus/fuzz/simplex/` or `consensus/fuzz/marshal/`), which reaches `consensus/fuzz/core/`
  only through its own `src/`. Any other path is out of scope.
- **Observation code** is read-only code the scaffold calls: getters, accessors, recording
  wrappers, witness helpers. It never adds a counter feature, an assertion or ghost state; those
  come only from the campaign.
- **Guards.** The script enforces these six. Whether an edit preserves what the protocol does
  is enforced by the prompt, which quotes R-TS-SYN-3 and restates the guards in the agent's
  terms, by the test gate, and by review of the pair's diff. Guards 1 to 3 are evaluated on the
  cumulative difference between the tree and the baseline `B`, which the campaign's first
  synthesis takes and stores, and every later synthesis of the campaign loads, so it never
  changes (section 18.6.2). `B`, its test inventory (guard 5), the content the script last
  wrote to its own files and the campaign's `instrumentation.diff` lie in `SL/campaign/`, which
  git ignores and an agent can write, so a synthesis reads them once, before `--redo` and
  before any pair, and compares only with those copies in memory. After every run of the agent,
  an interrupted one included, and when the synthesis ends, since the scaffolds the agent wrote
  run in the replays and the test gate after its last run, the script writes back from those
  copies, with a warning, each of these files that changed, and rewrites the baseline's index,
  `state.json`, so the next synthesis loads them unchanged. The guards are evaluated: before any
  card, after every attempt, again on the kept version right before it is built for fuzzing, and
  once more over the whole tree when synthesis finishes. No guard is evaluated against an
  attempt's snapshot, so a change an earlier attempt, or an earlier synthesis, left in place is
  judged in every later attempt as if that attempt had made it.
  1. Scope: a change outside the paths above and `Cargo.lock` stops synthesis with exit code 2
     ("synthesis edited <path>; use a fresh clone"), after the pair's edits inside them are
     restored. A path under `SL/` is compared with its state when the run started rather than
     with `B`, because the operator edits cards and prompts between syntheses; every other
     path is compared with `B`.
  2. Manifests: no `Cargo.toml` under the paths above changes, so no dependency is added. The
     package manifest, `Cargo.lock`, `target_states/mod.rs` and the declaration of
     `target_states` in `<package>/src/lib.rs` are the script's, and are compared with the
     content the script itself last wrote there, which it stores with `B`, or with `B` where
     it wrote nothing; a `Cargo.lock` that the script's own build updated counts as the
     script's write, and the declaration is compared by its structure: its lines directly
     after the anchor, and no other `pub mod target_states;` line. Any other `Cargo.toml` is
     compared with `B`. An agent's edits to these files are restored, with feedback, and the
     version is not built; the declaration is restored by inserting it again.
  3. Instrumentation integrity: no `sl_probe!`, `sl_assert!` or `sl_implies!` call added,
     removed or changed, compared per file with `B` as the multiset of call texts, without
     whitespace or a trailing comma, so a call that only moves within its file, or is only
     reformatted, is unchanged; every non-blank line that `SL/campaign/instrumentation.diff`
     adds to a file under the paths above still in its file, compared per file as a
     multiset with surrounding whitespace ignored, so no ghost update, field marked
     `// [statelens]` or runner hook (Appendices B.5 and F) is removed or changed; the
     runtime module byte-identical to `B`, because the witness checks rely on its trace, so
     observation code lives elsewhere, and its declaration, with the attribute lines directly
     above it, as in `B`; no call
     of `with_ghost`, `with_global`, `record`, `note`, `violation`, `reset` or
     `clear_compromised` added outside `target_states/mod.rs` and the scaffold thin targets,
     each of the shape step 2.4 checks, under the editable roots or in the fuzz package; no
     call of `set_compromised` added outside `target_states/`; no call of `tick`, `watch` or
     `unwatch` added outside `target_states/mod.rs`, because a new trace would drop the
     truncation the helper checks; no call of the read side (section 9.6) added under the
     editable roots; no `[statelens-reach]` or `[statelens-scaffold]` literal, outside comments,
     added outside `target_states/mod.rs`; no print macro (`print!`, `println!`, `eprint!`,
     `eprintln!`), `stdout(` or `stderr(` handle, `from_raw_fd`, panic hook (`set_hook`,
     `take_hook`), include macro (`include!`, `include_str!`, `include_bytes!`) or `#[path`
     attribute, outside comments and string literals, added to a Rust file other than
     `target_states/mod.rs`, because a print can forge a helper line however its literal is
     spelled, a panic hook can swallow an assertion's panic, and an included file or a
     `#[path]` module can hold code the guards never read; and no Rust file that git ignores
     under the editable roots or the package's `src/` and `fuzz_targets/`, because cargo
     compiles it out of sight of git: the repository's `.gitignore` ignores every path named
     `target`, so a module named `target` is one. A call counts when the code reaches the
     function through the runtime module, as section 7.5 step 4 defines it, and the counts
     are compared per file with `B`. These are text checks; section 18.11 says what they
     miss. A breach is a veto, with feedback. The script does not restore
     it, and it stays a breach, vetoed again with the same feedback, in every later attempt
     that still contains it, until the agent reverts it.
  4. Marker: every changed hunk of the pair's diff against `S0` outside the pair's module and
     thin target carries the comment `// [statelens] tss:TS-NNNN`. A hunk without it is
     annotated `unmarked edit`, for review. A hunk whose changed lines are, or directly
     neighbor, an `sl_probe!`, `sl_assert!` or `sl_implies!` call or a line the campaign
     added is annotated `edit beside instrumentation`, for review, because such an edit can
     disable an assertion it leaves unchanged, with `if false` or a `cfg`, which guard 3 does
     not see.
  5. Test gate: when the kept version of a pair changed a file under the editable roots, the
     script runs the profile's test gate (section 7.7) again. The run passes only when its
     output is usable and every test that fails, or that the inventory names and no longer
     runs, is one the inventory records as failing; otherwise the pair's edits are restored
     and GATE FAILED is recorded. Output is usable when, with ANSI escapes stripped, it has
     exactly one nextest `Summary` line for a complete run of at least one test; its passed
     count, and its failed, exec failed and timed out counts together, add up to the run
     count and equal the tests whose last status line before the summary passes and the tests
     nextest lists as failing after it; and the exit code is 0 exactly when no test failed. A
     build failure, a cancelled run or any other unusable output fails the gate. The
     inventory is the tests the gate passed and failed on the tree as the campaign left it,
     taken with `B` (section 18.6.2).
  6. Restore: on NOT BUILT and GATE FAILED the pair's edits are restored on every path. An
     interrupt or another error also restores them, once the command it stopped is killed
     with everything it started, and after the attempt's version, its replay outputs and a
     note naming the step that stopped are kept (section 18.6.2). A synthesis
     killed before it restored them is undone by the next one (section 18.6.2, Once per run).
     `just clean` restores the editable roots and the simplex and marshal fuzz packages, but
     not the `corpus/`, `artifacts/` and `coverage/` that git ignores there, so it also deletes
     `target_states/`, the files git ignores there included, and the thin targets.

#### 18.6.2 The step

**Command.** `just synthesize [--agent A] [--profile simplex|marshal] [--match GLOB]...
[--redo]` runs `statelens.py synthesize`. With no `--profile` it takes the profile from
`SL/campaign/meta.json`.

**Preconditions.** A usage error, `--profile qmdb` among them, exits with code 1, and a
failed precondition with code 2. Usage errors and the preconditions that read `meta.json` are
reported before the agent CLI is checked, an exception to section 12:

- `SL/campaign/meta.json` names the profile, its `base` equals `HEAD`, and its invariants
  include no `FALSE-` ID, because a false invariant panics in every scaffold;
- `SL/campaign/summary.txt` reports `READY` or `PANIC (tests)`;
- the profile's runtime module (section 5.5) exists and contains `pub fn watch(`; otherwise
  "this checkout predates the read side or was cleaned; use a fresh clone";
- `SL/campaign/plan.md` exists;
- the agent CLI and `cargo-fuzz` are on `PATH`;
- the selection below is not empty (otherwise exit code 1), and its cards are lint-clean;
- `<package>/src/target_states/` does not exist unless `SL/campaign/reach/baseline/` does,
  since an instrumented checkout without a baseline cannot be judged.

The fuzz toolchain is the one `meta.json` records. Synthesis never instruments: it adds no
probe, assertion or ghost state.

**Selection.** One function serves `synthesize` and `targets --state-reaching` (section 18.9).

- The cards are every `TS-*.md` of `SL/target-states/<profile>/` and
  `SL/target-states.local/<profile>/`; synthesis prints how many are tracked and how many
  local (the `cards` line of the console below).
- The candidate bases are the profile's targets (section 5.5), less those whose file contains
  `fuzz_mutator!`.
- A pattern that starts with `TS-` is a shell pattern over card IDs (`TS-0003`, `TS-000*`).
  Any other pattern names a base, for each card, when it matches, as `select_targets`
  matches, one of `<base>`, `<base>_statelens`, `<base>_tsNNNN` and `<base>_tsNNNN_statelens`,
  so `<base>_tsNNNN` selects that base for that card only; with no such pattern every
  candidate base is selected. A card is selected when no `TS-` pattern was given or one names
  it, and at least one base is selected for it. Each selected base makes a pair (card, base)
  with it, and the pair is the unit of synthesis: a card on b selected bases yields b
  scaffolds, and the agent chooses no base. The pairs run in card order, then in the order of
  the bases' files.
- A pair is named `TS-NNNN_<base>` wherever the script keeps something per pair: reports,
  attempt directories, revalidation directories, the keys of `revalidation.json` and the
  pending snapshot. A pair has a scaffold when its thin target `<base>_tsNNNN_statelens.rs`
  exists; a report without one is the NOT BUILT or GATE FAILED case. A pair with a report,
  `SL/campaign/reach/TS-NNNN_<base>.md`, is skipped, printing `skipped:` and one of "TS-NNNN
  on <base> was synthesized as <scaffold>; use --redo" and "TS-NNNN on <base> was synthesized
  without a scaffold; use --redo"; the card's other pairs are synthesized as usual.
- `--redo` first reverse-applies the diff of each selected pair that has a report,
  `SL/campaign/reach/TS-NNNN_<base>.diff`, in reverse selection order, less its sections for
  the package manifest and `target_states/mod.rs`; a diff that does not apply cleanly exits
  with code 2, unless it applies forward: an undo that an interrupt stopped before the pair's
  reports moved already reverse-applied it, so it is not applied again, with a warning. It
  then removes the pair's `[[bin]]` block from the manifest, by the scaffold's exact name, so
  a sibling pair's block survives, and its line from `target_states/mod.rs`, because a block
  that a later pair's block follows does not reverse-apply. It then moves the pair's reports
  to `TS-NNNN_<base>.<stamp>.md`, `TS-NNNN_<base>.<stamp>.diff` and `TS-NNNN_<base>.<stamp>/`,
  so a preserved failure is never deleted, and rewrites every path under
  `SL/campaign/reach/TS-NNNN_<base>/` in the moved report and in its attempts' `replay.txt`
  and `interrupted.txt` to `TS-NNNN_<base>.<stamp>/`, so their lines still name the files they
  kept. It also moves `<package>/artifacts/<scaffold>/` of the pair's scaffold, the crash
  files fuzzing wrote for the undone version, to `TS-NNNN_<base>.<stamp>/artifacts/<scaffold>/`;
  the scaffold's corpus stays. Then it synthesizes the pair again. An attempt directory
  `TS-NNNN_<base>/` left without a report, by an interrupted synthesis, is moved and rewritten
  the same way before the pair is synthesized. When an undone diff changed a file other than
  its thin target, the package manifest, `target_states/mod.rs` and `Cargo.lock`, its own
  module included, since the modules are public siblings of one crate and one can use
  another's items, while the thin target is a crate of its own, which no module can use, the
  script records the revalidation it owes in `SL/campaign/reach/revalidation.json`, under the
  pair's name, once `git apply -R --check` accepts that diff and before it reverse-applies it,
  and every scaffold whose report records a verdict (Once per run), the card's other pairs
  included, is then, before any pair, built, logged to
  `SL/campaign/logs/fuzz-build-<scaffold>-after-redo.log`, and replayed, canonical, control
  and final, in `SL/campaign/reach/TS-MMMM_<b>/after-redo/`, and its report takes the new
  verdict under `## Revalidation after --redo`, as revalidation does (Finish), with a warning
  when it stands worse. No pair is rolled back for it. A scaffold that no longer builds gets
  the verdict `NOT BUILT (no longer builds)`, with a warning; it is not revalidated again, and
  the last check's build exits with code 2 unless a later pair's edits make it build. The
  record is deleted once every scaffold is revalidated. A synthesis that stops before then, by
  an interrupt or any other error, leaves the record, and says so when it stops during the
  revalidation, so the next synthesis completes the revalidation before any pair, whatever it
  selects and with or without `--redo`; until then, the reports keep their earlier verdicts.

**Once per campaign.** The first synthesis after a campaign, the one that finds no
`SL/campaign/reach/baseline/`, takes the baseline `B` before any pair: the content of every
file that git does not ignore under the editable roots and the fuzz package, of every Rust
file that git ignores under the editable roots and the package's `src/` and `fuzz_targets/`
(guard 3 vetoes those), and of `Cargo.lock`, the file set of `S0` below, with the worktree state of section 6.2 step 2. It writes `B` to
`SL/campaign/reach/baseline/`, where the script also keeps the content it last wrote to each
of its own files (guard 2), updated on every such write. Every later synthesis of the
campaign, `--redo` included, loads `B` from there, so `B` never changes; a new campaign
recreates `SL/campaign/`, which discards it. Guards 1 to 3 are evaluated against `B` (section
18.6.1). With `B` it takes guard 5's test inventory, `SL/campaign/reach/baseline/tests.json`:
the tests passed and failed in the campaign's `logs/test.log` when that log begins with this
gate's command line and its output is usable (section 18.6.1, guard 5; a campaign that ended
`READY` exited 0, one that ended `PANIC (tests)` did not). Otherwise it runs the test gate once
on the tree as the campaign left it, logged to `SL/campaign/logs/test-baseline.log`, and keeps
that run's inventory; unusable output there exits with code 2 before any pair. When the
campaign ended `READY`, a test that fails in that run contradicts the campaign's own gate, a
flaky or killed test, and it also exits with code 2 before any pair, so the inventory never
excuses it. A baseline without `tests.json` exits with code 2.

**Once per run.** First, a `SL/campaign/reach/pending/` whose pair has no report is the `S0` of
a synthesis that stopped without restoring that pair's edits, killed for example: the script
restores it and drops the pair's line from `target_states/mod.rs`, with a warning, then deletes
`pending/`, and a revalidation record the pair wrote (Finish) stays; one whose pair has a
report is only deleted, and one that cannot be read, or names no pair, exits with code 2. Then, before `--redo` reverse-applies a diff and before any pair, the script checks
guards 1 to 3 against `B`; a failure exits with code 2 ("the checkout differs from the
synthesis baseline: <path>; use a fresh clone"), so a breach an earlier synthesis left behind,
such as an out-of-scope edit, never passes. The script then inserts the declaration of section
5.5 after the profile's anchor, unless it is there; a missing or repeated anchor exits with
code 2. It writes `SL/campaign/reach/empty`, a file of 0 bytes. After `--redo` and before any
pair, it reads the report of every scaffold in the package whose card exists, for revalidation
(Finish), and keeps them in memory, each under its pair's name; a scaffold without a card or
without a report that records a verdict is not revalidated, with a warning. It then completes
the revalidation `revalidation.json` records, this run's `--redo`'s or one an earlier synthesis
left, after an undo or a rollback (Finish), and deletes the record; a record that cannot be
read exits with code 2. A record that holds more than one kind, `--redo` with the last check or with a
rollback, revalidates once, under a joined heading such as `## Revalidation after the last
check and --redo`.

**Per pair.** Pairs run one after another, because they share one crate; two pairs of one
card are two transactions, each with its own module, thin target, attempts, build, replays,
verdict and report. For each, in a block that, on an interrupt or any other error, first kills
the command that was running (the agent, a build, a replay or the test gate) with everything
it started, then preserves what the attempt holds, then restores `S0` and drops the pair's
line from `target_states/mod.rs` before exiting; a revalidation record the pair wrote (Finish)
stays, with a line that says so. Every command the script runs is in its own process group, so the kill reaches what the
command started and the terminal's interrupt reaches the script alone, which kills the
command; a `SIGTERM` or a `SIGHUP` to the script takes the same path. Preserving does three
things. It sweeps what a run of the scaffold left while the agent ran (step 2.2). It keeps the
version a stray failure came from, unless it is already kept; when synthesis stops during an
attempt's run or its sweep, the attempt's stray failures are the failures in its `swept/`,
those a sweep that stopped had already moved included. It writes
`SL/campaign/reach/TS-NNNN_<base>/attempt-<a>/interrupted.txt`: the step that stopped and why, where the
kept version is, and the exit code of each replay that finished, with the `run` and `replay`
lines of one that failed, and of one that stopped after it left a crash file, and, when a
revalidation (step 3) stopped, its directory and the crash files its replays left there. The
replays' crash files and logs stay in `attempt-<a>/`; during step 3, `<a>` is the kept
version's attempt:

1. Write `target_states/mod.rs`: the template `SL/runtime/target_states.rs`, then a
   `pub mod tsNNNN_<base>;` line for every module in the directory and this pair's. Then snapshot
   `S0`: the file set of `B` above. Restoring a snapshot rewrites those files and deletes the
   files created under the same paths since, ignored ones other than those Rust files excepted;
   a symbolic link an edit put at one of those paths is removed, never written through, and
   nothing is written below a directory a link replaced, with a warning, since guard 1 names
   that directory. `S0` is what the pair's restores return to and what its diff is taken against; no guard is
   evaluated against it. `S0` is kept in `SL/campaign/reach/pending/`, the pair's name, its file
   list and a copy of each file that differs from `B`, written aside and renamed so that it is
   whole or absent, until the pair's report is written or its edits are restored.
2. For attempt `a` from 0 to `REPAIR_ATTEMPTS` (3):
   1. Write the package manifest as it was in `S0`, so the agent always finds it without a
      scaffold block. Snapshot `Sa`, with the worktree state of section 6.2 step 2 and the
      files step 2.2 sweeps. `Sa` serves only the sweep and the stop rule of step 2.8; no
      guard is evaluated against it. Render `prompts/synthesize.md` with the placeholders
      below, and run the agent with the Phase 2 invocation (section 12); the prompt and the
      log are `SL/campaign/prompts/synthesize-TS-NNNN_<base>-<a>.md` and
      `SL/campaign/logs/synthesize-TS-NNNN_<base>-<a>.log`. A non-zero exit is a failed attempt and
      becomes feedback; it does not stop synthesis. Its tree is still swept and checked, so
      guard 1 still stops synthesis, and its version is vetoed, never built.
   2. Sweep what a run of the scaffold left during the attempt, the files of these kinds that
      `Sa` does not list: untracked `crash-*`, `oom-*`, `timeout-*`, `leak-*` and `slow-unit-*`
      files anywhere in the worktree, and entries of `<package>/corpus/<scaffold>/` and
      `<package>/artifacts/<scaffold>/`, which git ignores, so the scope check cannot see
      them, and, since the sweep looks for every `*_tsNNNN_statelens` of the card, those of
      a sibling pair's scaffold that the run left. They are moved, never deleted, to
      `SL/campaign/reach/TS-NNNN_<base>/attempt-<a>/swept/`, with a warning. The
      agent never runs its scaffold (section 18.7), so a `crash-*`, `oom-*`, `timeout-*` or
      `leak-*` file among them is a finding candidate, annotated `stray failure`: refinement
      of the pair stops after this attempt, and the attempt's verdict is CRASH (finding
      candidate) when its version passes the vetoes and builds; otherwise the file stays a
      finding candidate in `swept/`.
   3. An attempt after the first that changed no file and left no stray failure is not
      checked or built again: its tree is the one the previous attempt was judged on, and it
      ends the pair (step 2.8), recorded as "no change, which ends the pair". Otherwise check
      guards 1 to 3 on the cumulative difference between the tree and `B`, and guard 4 on the
      pair's diff against `S0`.
   4. Vetoes. Each becomes feedback, and the version is not built: guard 2 or 3, against `B`,
      so a guard 3 breach an earlier attempt made is vetoed again while it remains; no thin
      target `<base>_tsNNNN_statelens.rs` for the pair's base, or a new thin target of the card
      on another base, or a scaffold thin target in the package, this pair's or another's,
      whose `fuzz_target!` body is not the three statements of Appendix B.6; no module
      `tsNNNN_<base>.rs`, or a module whose header does not name the card, the pair's base and
      a shape; the cryptography
      check of D15 (section 7.2, or section 8.4 for marshal) failing for the thin target, or,
      for simplex, the module naming a Simplex type whose scheme is not `cert_mock`; and a
      Shape B module that never calls `set_compromised` (the guard rule of section 18.7). The
      Shape A half of that rule needs no veto: a Shape A module calls its base's entry, whose
      runner keeps the hook the campaign installed (Appendices B.3 to B.5 and F), because
      guard 3 keeps every line the campaign added. `BASE_DETAILS` tells the agent whether the
      pair's base is hooked, from the runner its `fuzz_target!` calls.
   5. Manifest: the script writes the package manifest as it was in `S0`, with the scaffold's
      block, the base's renamed (Appendix B.2).
   6. Build: `cargo +<fuzz toolchain> fuzz build --fuzz-dir <package> <scaffold>`, logged to
      `SL/campaign/logs/fuzz-build-<scaffold>-<a>.log`. A failure becomes feedback: the command
      and its last 150 lines. The agent runs the same command during its attempt (section
      18.7); since the manifest has no scaffold block then, the prompt tells it to add the
      block for its build and remove it again, leaving the manifest as it found it, which
      guard 2 checks.
   7. Reach check (section 18.8). Before the canonical replay, the script keeps the version as
      built in `attempt-<a>/`: `version.diff`, its diff against `S0`, and `version/`, a copy of
      every file it created or changed. An attempt that left a stray failure keeps the version
      it left the same way, right after the sweep. The version, every path it changed since
      `S0`, is kept with its verdict. Only a version that passed guards 1 to 3 against `B` gets
      here, so only such a version can be kept.
   8. Stop at REACHED, at a CRASH (finding candidate), after an attempt that left a stray
      failure (step 2.2), after an attempt that changed no file, and after the last attempt.
      Otherwise the feedback of section 18.8 goes to the next attempt.
3. Finish:
   - A CRASH (finding candidate) keeps the version that failed (D67). Otherwise the best built
     version is kept: by verdict, REACHED, UNVERIFIED, PARTIAL, UNREACHED, NO REPORT, then
     SCAFFOLD ERROR; then by the stages held; then the later attempt. The kept version is
     restored: `S0`, then every path it changed. Guards 1 to 3 are checked against `B` once
     more, right before the build for fuzzing; a guard 2 or 3 failure, which the checks of
     step 2.3 make impossible, restores `S0` and records NOT BUILT. The kept version is then
     built again, and a build that fails restores `S0` and records NOT BUILT. Its canonical
     input is replayed once more, in `attempt-<a>/final/`: stage lines that differ from the
     stored ones are annotated `nondeterministic`, and a failure is a CRASH (finding
     candidate) as well.
   - Guard 5: when the kept version changed a file under the editable roots, the test gate
     runs, logged to `SL/campaign/logs/test-TS-NNNN_<base>.log`, and a run that fails guard 5
     (section 18.6.1) restores `S0` and records GATE FAILED; the report names each failing or
     no longer running test, or `(unusable output: <reason>)`. The files a failed replay left
     stay in `attempt-<a>/`, beside the version that failed, `version.diff`, which the report
     names, and `version/`. A kept CRASH (finding candidate)
     stays one: the verdict reads `GATE FAILED (finding candidate in attempt-<a>/)`, on the
     console as well.
   - Revalidation: the pairs share one tree, so when the kept version, still kept after guard
     5, changed a file other than its thin target, the package manifest, `target_states/mod.rs`
     and `Cargo.lock`, its own module included, since the modules are public siblings of one
     crate and one can use another's items, while the thin target is a crate of its own, which
     no module can use, every other scaffold in the package, of this synthesis or an earlier
     one, the card's other pairs included, whose card exists and whose report records a
     verdict (Once per run), is built again, logged to
     `SL/campaign/logs/fuzz-build-<scaffold>-after-TS-NNNN_<base>.log`, and replayed,
     canonical, control and final (section 18.8), in
     `SL/campaign/reach/TS-MMMM_<b>/after-TS-NNNN_<base>/`. A scaffold stands worse when it no longer
     builds, when it gains or loses CRASH (finding candidate), or when its verdict comes later
     in the order of the first bullet, or holds fewer stages under the same verdict (k counts
     for REACHED, UNVERIFIED, PARTIAL and UNREACHED only). At the first that stands worse,
     `S0` is restored, the pair's line is dropped from `target_states/mod.rs`, and the verdict
     is `NOT BUILT (breaks TS-MMMM_<b>)`, with `, finding candidate in attempt-<a>/` over a
     kept CRASH (finding candidate) or `, stray failure` when an attempt left one; the report
     says why and names `attempt-<a>/version.diff`. That scaffold is then built and replayed
     once more in `TS-MMMM_<b>/without-TS-NNNN_<base>/`, and the pair's report records the
     result; a verdict that still stands worse is written to that scaffold's report, under
     `## Revalidation without TS-NNNN_<base>`, with a warning. Otherwise each revalidated
     report takes the new verdict on its `Verdict` line and a section `## Revalidation after
     TS-NNNN_<base>`: the cause, the verdict
     before and now, the reasons, the replays' directory and, for a CRASH (finding candidate),
     its crash line; the report's `## Run and replay` lines are rewritten for the scaffold's
     latest check, so they reproduce that failure, with `STATELENS_REACH_CONTROL=1` for the
     control replay, or carry the placeholder when it has none. Before the first of those
     reports changes, the script records in `revalidation.json` the revalidation a restore of
     the pair's edits would owe, as `a rollback` of the pair, the way `--redo` records an
     undo, and it deletes the record once the pair's report is written. A restore after that
     point, by an interrupt, any other error or the recovery of a killed synthesis (Once per
     run), leaves the record, and the next synthesis revalidates every scaffold before any
     pair, in `TS-MMMM_<b>/after-rollback/`, under `## Revalidation after a rollback`; until
     then, those reports keep the verdicts the restored edits gave them. A kept version always
     changes its module, so a pair revalidates every other scaffold that stands, the card's
     other pairs included; only a pair with none revalidates nothing. A revalidation directory
     that exists stays as it is,
     since a report may name it; the new replays go to `<directory>.<stamp>/`, which the
     report's section names.
   - When no version built, every attempt vetoed or failing to build, `S0` is restored and the
     verdict is NOT BUILT, or `NOT BUILT (stray failure)` when an attempt left one.
   - `target_states/mod.rs` loses the line of a pair that has no scaffold.
   - The script writes `SL/campaign/reach/TS-NNNN_<base>.md` and
     `SL/campaign/reach/TS-NNNN_<base>.diff`.

**Last check.** When every pair is done, guards 1 to 3 are checked once more over the whole
tree against `B`, every kept version together. A guard 1 failure exits with code 2. A guard 2
failure, which should be impossible, writes the script's files back, with a warning. A guard 3
failure, which should be impossible too, restores each pair whose diff touches the failing
file to its `S0`, by undoing the pair as `--redo` does, in reverse synthesis order, and records
it NOT BUILT, printing its line again with `(last check)`, and its report names its
`attempt-<a>/version.diff`; a failing path that no pair's diff touches is written back from
`B`. An undone diff, which takes the pair's module away, is revalidated as `--redo` does, in
`TS-MMMM_<b>/after-last-check/`, under `## Revalidation after the last check`, and recorded in
`revalidation.json` before the undo in the same way. So no version is
fuzzed with an assertion or probe call, a line the campaign added, or the runtime module
changed in its text; what these text checks miss is in section 18.11.
Every scaffold in the package, of this synthesis or an earlier one, is then built once more,
also when the run synthesized no pair, logged to
`SL/campaign/logs/fuzz-build-<scaffold>-last.log`; one that does not build exits with code 2
("the last check: the scaffold <scaffold> does not build; see <log>, and undo the pair whose
edits broke it with --redo or use a fresh clone"). This catches a break that no pair's diff
shows, such as a helper template changed between syntheses, and a scaffold an earlier
synthesis recorded `NOT BUILT (no longer builds)`, which is never handed over while it does
not build.

**Placeholders.** `BASE`, `PLAN`, `CHECK`, `RUNTIME`, `RUNTIME_MODULE` and `FUZZ_PACKAGE`, as
in section 7.3 step 3, and:

| Placeholder | Value |
|---|---|
| `CARD_ID`, `CARD` | The card's ID, and its text with its Source excerpts |
| `STAGES` | n, the number of History events, as a bare integer |
| `MODULE` | `<package>/src/target_states/tsNNNN_<base>.rs`, the pair's module |
| `SCAFFOLD` | `<base>_tsNNNN_statelens`, the pair's thin target |
| `BASE_TARGET` | The pair's base |
| `BASE_DETAILS` | For that base: its name, the closure header and the entry call of its `fuzz_target!`, its `required-features`, its input type, and whether its runner is hooked (Appendices B.3 to B.5 and F) |
| `LABELS` | Every `sl_probe!` label and `sl_implies!` ID under the editable roots, with its `path:line`, from one scan |
| `BUILD` | The build command of step 2.6, with the scaffold's name |
| `ATTEMPT`, `FEEDBACK` | The attempt number, and the feedback of section 18.8, or "none: first attempt" |
| `SUBSYSTEM_RULES` | The content of `prompts/subsystems/<profile>-synthesize.md` |

**Outputs.** In the checkout, never committed and removed by `clean`: the modules,
`target_states/mod.rs`, the thin targets, the `[[bin]]` blocks, the declaration line and the
pairs' other edits. In `SL/campaign/reach/`, per pair: `TS-NNNN_<base>.md`, titled `TS-NNNN on
<base>: <title>`, with the card and its title, the shape, base and scaffold, the verdict and
its annotations, each stage's outcome, witness kind and record, the handoff, the attempts and
their verdicts, the crash attribution, the labels and sites read, the run and replay lines of
its latest check, and its revalidations; `TS-NNNN_<base>.diff`, the kept version against `S0`,
the script's own edits included, and empty when the pair's edits were restored;
`TS-NNNN_<base>/attempt-<a>/`, the replays of each attempt (section 18.8), the files
step 2.2 swept, `version.diff`, the attempt's version against `S0`, and `version/`, a copy of
every file it created or changed, which holds what a diff cannot, such as a binary file. Both
are written before the first replay of every version that built, and right after the sweep
for one that left a stray failure, so a failure stays reproducible after a restore or an
interrupt. `interrupted.txt` is written for an attempt during which synthesis stopped, and,
for a kept CRASH (finding candidate), `replay.txt`, its `run` and `replay` lines;
`TS-NNNN_<base>/after-TS-MMMM_<b>/`, `TS-NNNN_<base>/without-TS-MMMM_<b>/`,
`TS-NNNN_<base>/after-redo/`, `TS-NNNN_<base>/after-last-check/` and
`TS-NNNN_<base>/after-rollback/`, the replays of a revalidation (Finish, `--redo` and Last
check), each `<directory>.<stamp>/` when it exists already. And once: `baseline/`, the
baseline `B`, guard 5's test inventory `tests.json`, and the content the script last wrote to
its own files; `revalidation.json`, the revalidation an undo owes, or a restore of a pair whose
revalidation rewrote reports (Finish), keyed by the pair's name and removed when it completes
or when that pair's report is written; and `pending/`, the `S0` of the pair in progress, with
the pair's name, removed when the pair ends. Prompts and logs go to `SL/campaign/prompts/` and
`SL/campaign/logs/`, named `synthesize-TS-NNNN_<base>-<a>` and `test-TS-NNNN_<base>`.

**Console.** One line per pair, then a `run` and a `replay` line per scaffold of the
selection, a skipped pair's included, none with a libFuzzer argument:

~~~
statelens: cards      <n> tracked, <m> local
statelens: TS-NNNN    skipped: TS-NNNN on <base> was synthesized as <scaffold>; use --redo
statelens: TS-NNNN    <verdict>[ (<annotation>, ...)]   <scaffold | no scaffold on <base>>[; <crash note>]
statelens: synthesis  <k> pair(s), <s> scaffold(s); reports in statelens/campaign/reach/
statelens: run        cd <repo>/statelens && NIGHTLY_VERSION=<fuzz toolchain> just run <scaffold>
statelens: replay     cd <repo>/statelens && STATELENS_REACH=1 [<replay env> ]NIGHTLY_VERSION=<fuzz toolchain> just run <scaffold> <repo>/<package>/artifacts/<scaffold>/<crash file>
~~~

`<replay env>` is the profile's, as in section 7.9, and the crash file is one that fuzzing
wrote. `<k>` counts the pairs synthesized in this run and `<s>` every scaffold of the
selection; the card's ID opens each pair's line, and its base ends it, in the scaffold's name
or after `no scaffold on`. The line of a CRASH (finding candidate) names, in its crash note,
the replay that failed, and its `replay` line takes the crash file kept in
`SL/campaign/reach/TS-NNNN_<base>/attempt-<a>/`, or `SL/campaign/reach/empty`, the input every replay
runs, when the replay left no crash file. For a canonical
replay the line adds that the scaffold fails on its canonical input, which libFuzzer runs
first, so its `run` line reproduces the failure at once. For the control run the `replay`
line also sets `STATELENS_REACH_CONTROL=1`, and the line says that the canonical input does
not reproduce it. For a `stray failure` it names the swept file, also when the pair's
verdict is not CRASH (finding candidate), because the attempt that left the file was not
built: "a run of the agent's left <file>, a finding candidate". A `<repo>` or crash-file path
that holds a space is quoted for the shell, so each line runs as printed.

**Exit codes.** 0 when at least one scaffold exists for the selection, a skipped pair's
included; 1 usage, or nothing selected; 2 a failed precondition, a checkout that differs from
`B` before any pair, a test inventory that cannot be taken or read (Once per campaign), a
`pending/` or `revalidation.json` that cannot be read (Once per run), guard 1, a missing or repeated anchor, a
`--redo` that does not apply, or a scaffold the last check cannot build; 3 no scaffold built,
every selected pair ending NOT BUILT or GATE FAILED.

**Clean.** `clean` (section 5.4) adds the simplex and marshal fuzz packages to its scope, while
`storage/fuzz` keeps the file-level scope of a qmdb campaign, so it deletes `target_states/`,
the files git ignores there included, and the thin targets and restores every file edited
there; the `corpus/`, `artifacts/` and `coverage/` that git ignores there stay, and the
editable roots were in scope already. `SL/campaign/reach/` stays, as all of `campaign/` does.

### 18.7 Scaffold contract

Prompt `synthesize.md` gives these rules to the agent, and its subsystem parts the simplex and
marshal rules below; their verbatim copies are sections 13.21 to 13.23. It sends the agent to
`target_states/mod.rs` for the exact signatures of the helper. Its sections: where the agent
is; the task, which names the pair's module (`MODULE`), its thin target (`SCAFFOLD`) and its
one base (`BASE_TARGET`, `BASE_DETAILS`), so the agent chooses no base; the edit contract
(R-TS-SYN-3 quoted, and guards 1 to 6 restated in the agent's
terms, since the guards' own text cites sections the agent cannot see); shapes; knobs; stages
and witnesses; handoff and recovery; the control; oracles; fabrication and the guard; missing
capabilities; building (build with `BUILD`, the full command for the pair's scaffold, adding
the scaffold's `[[bin]]` block, the base's
with `name` and `path` renamed, for that build when cargo reports no such target and removing
it again, because the script writes the block only after the attempt and guard 2 restores an
agent's edit to the manifest; never run the scaffold or the fuzzer: the script's reach check
is the only replay); the feedback; the subsystem rules; and the reply (shape, the witness of
each stage, knob layout, injections, missing capabilities).

**Shapes.** The agent picks one and records it in the module header.

- **Shape A, pinned input**, preferred where it fits: the base input's fields fix every event
  before `En`, for example the scenario `template` and `actions` of
  `NotarizationBlockSplitScenarioInput`, or the partition, configuration and certify choice of
  `FuzzInput`. `fuzz` splits and picks the knobs, calls `Stages::new` and `Stages::budget`,
  pins the fields, resets the fields that depend on them, calls the base's entry by path with
  its generics, then evaluates `E1` to `E(n-1)` over the trace and the harness observables,
  calls `Stages::handoff` with the evaluation of `En`, and last `Stages::done`. The base's own
  schedule runs, no driver code is copied, and its oracles are untouched.
- **Shape B, online prefix**, where Shape A cannot express the History: `fuzz` splits and picks
  the knobs, calls `Stages::new`, `Stages::budget` and `set_compromised`, pins the fields, sets
  the base up, drives `E1` to `E(n-1)`, calls `Stages::handoff` with the read of `En`'s
  witness, hands off to the base's free-running phase and oracles, and calls `Stages::done`
  after the last oracle. The base's setup is called by path; where only a monolithic driver can
  host the prefix, that driver is copied verbatim into the module, citing `path::item@commit`.

**Naming and entry.** For the pair (card, base) the module is
`<package>/src/target_states/tsNNNN_<base>.rs` and the scaffold `<base>_tsNNNN_statelens`; its
thin target (Appendix B.6) calls `tsNNNN_<base>::fuzz`. Both names carry the base, so the pairs
of one card are distinct modules of one crate and distinct targets of one package. `pub fn fuzz`
takes the base's input type and the generic parameters of the base's entry, in order. Its
first statements split and pick the knobs, and `Stages::new` and `Stages::budget`, which takes
the knobs, come before any engine starts and before any action a stage witnesses: while nothing
watches, `Witness::act` takes position 0. The module opens with this header, which the script
reads:

~~~rust
//! TS-NNNN on <base>
//! Shape: A | B
//! Knobs: raw_bytes[0..k]: [0] <knob>, [1] <knob>, ...
//! Stages: E1 <witness kind and what it reads>; E2 ...; ...
//! Control: withholds Ek | n/a
//! Injections: <each injection, with the INV ids whose ghost history it bypasses> | none
//! Missing: <each missing capability> | none
~~~

A module without a `Control:` line has no control (section 18.8). A header that names another
base than the pair's, like a second thin target of the card on another base, is vetoed
(section 18.6.2 step 2.4).

**Knobs** (D64). `Knobs::split` takes the first K <= 16 bytes of the base input's own
`raw_bytes`, zero-padded, and leaves the rest, which stays non-empty if it was. Knob i is
`domain[raw[i] % domain.len()]`, with the source value at index 0, so the empty input, the
canonical input, decodes to the source history. Each knob decodes to a valid value by
construction (a view is derived so that the required leader leads it), and an ordering knob
indexes the orders `Order:` allows, the source order first. The fields the History fixes are
pinned, and the fields that depend on them are reset as the base's decoder sets them under the
pin: in `FuzzInput`, `degraded_network` depends on `partition` and `configuration`, `certify`
on `configuration`, `block_filter` on `configuration` and on the fault bound drawn from
`required_containers`, the fault rounds of `strategy` on `required_containers`, and
`optimistic_views` on `term_length` (`consensus/fuzz/core/src/lib.rs`). The input type,
the `run` recipe and the libFuzzer flags are the base's, and there is no seed corpus.

**Stages and witnesses** (D65). One stage per History event, `E1` to `En`, evaluated in the
order the scaffold drives them. The scaffold binds the card's entities to concrete values, the
replicas, views and payloads it chose or observed, and records for each stage one witness that
establishes the whole `Check` or `Holds` line, its relations to earlier events included:

| Kind | What it is | What it establishes |
|---|---|---|
| `exact` | One or more harness observables, one per part of the line, each keyed by the bound entities: a reporter map keyed by view or digest, a resolver or buffer recorder, a recording wrapper in `target_states/`, a network intercept record, or a local query without side effects | Presence of the entry. An order only when each entry carries its own position, which a recording wrapper takes through the helper's `stamp` as it records the entry; a map read after the run establishes presence only. A query that subscribes, hints, fetches or verifies is not a witness: it would create or satisfy the state it checks. A recording wrapper records synchronously and forwards every call and reply unchanged and at once: no await, delay, spawn, drop or reordering of its own. |
| `intrinsic` | One probe observation at a site whose `a` and `b` are computed from one receiver | The replica, `me`, and the relation among that object's fields at that instant, but no view, digest or other identity. It witnesses only a line whose entities other than one replica are all existential. |
| `construction` | A harness action the scaffold performed itself, through the helper's `Witness::act`, and that cannot fail silently, such as a pinned elector or a certificate it built | That the action happened, at the position the helper took right before performing it, and nothing a replica did with it: a line about what a replica holds, verifies or is in needs an `exact` or `intrinsic` witness. Only for an event whose actor is `harness`, never for `En`; in Shape A, only for an action performed before the base's entry is called. |

For example, in a simplex campaign at base `0552fd66c8`, the beacon
`voter.round.set_certify_handle` packs the round's decision code into `b`, with 1 for a nullify
vote the replica built or replayed. One observation there with that code witnesses "R queued
certification for some view in which R had already built or restored its own nullify vote".
It witnesses neither a nullification certificate nor the `v` of an earlier event, and a
nullification observed at one site followed by a certification observed at another witnesses
nothing. A probe observation whose subject is not fixed by its own site is not a witness. A
stage whose entities or relations no available witness binds is `unverifiable`, not missed (for
`En`, recorded with `Stages::unverifiable` before `Stages::handoff`), and so is a stage whose
witness is read at or after the position of the first observation the trace dropped at
`TRACE_CAP` (`truncated()`, section 9.6; `unverifiable (trace truncated)`), which adds no
feature.

**Witness records.** A stage is held only through the helper, `Stages::held(k, witness)` for
`E1` to `E(n-1)` and `Stages::handoff` for `En`, which prints the record (section 18.8) with
`read=`, the position the witness took when it was built: its read for an `exact` or
`intrinsic` witness, and for a `construction` witness the position `Witness::act` took for the
action. The scaffold prints nothing itself (guard 3): only the helper prints the lines the
script reads. A record
carries `bind=`, every entity of the line with its value and the event that bound it, such as
`R=2@E1,v=5@E1`, and the evidence, which names the entities it is keyed by as
`<name>=<value>`: for an `exact` witness, per observable,
the entities of its key, the value read and the entry's position when it has one; for a
`construction` witness the action, the entities it fixes and the action's position; for an
`intrinsic` witness its observation, which identifies only the replica `me`, so it binds every
other entity to `?`. A stage's position is the largest position its evidence carries; an
`exact` witness with an item that has no stamp has none, since that entry may come after any
other.
Positions are unique (section 9.6), so the script compares them strictly. It recomputes each
record and makes a held stage `unverifiable`, with `witness rejected: <rule>`, `<rule>` being
the name in parentheses, when:

- an `x as Ek` value differs from the value `Ek` bound to `x`, or is `?`, or `Ek` bound no
  value, having no `held` line (`as`);
- an entity of the line's list is missing from `bind=` (`bind`);
- an `exact` or `construction` witness does not name every entity of the line whose `bind=`
  value is not `?` with that value, in an `exact` item's key or the action's list, names one
  of them there with another value, or names none; an incarnation `inc<s>` is exempt, since
  the `incarnation` rule checks it, and the value an `exact` item read does not count; or an
  `exact` item's `seq=` is not that of an earlier `entry` line with the same observable, key
  and value (`evidence`);
- a stage's position is not greater than that of an earlier stage it must follow, by the
  numbered order less the pairs `Order:` frees (`order`);
- a probe observation's `run` differs from that of an earlier stage's observation, with no
  `restart` line between them (`run`);
- for a replica the line binds, a `restart` line of that replica lies between the line's
  position and that of an earlier stage an `as Ek` links it to, and `bind=` gives no entity
  of the line the incarnation `inc<s>` that the last restart of that replica in that span
  began; or
  `bind=` gives an entity an incarnation `inc<s>` that no `restart` line's `seq=` names, which
  needs no position, or that begins after the line's position (`incarnation`, below);
- an `intrinsic` witness cites more than one observation, or `bind=` gives a value other than
  `?` to an entity of its line other than one replica, or gives that replica a value other
  than the observation's `me`, which a site without a replica, `me` `-`, never matches
  (`intrinsic`);
- a `construction` witness is used for `En`, or for an event whose actor in the card's History
  is not `harness` (`construction`).

A record that breaks several rules is rejected for the first in this order: `bind`, `as`,
`evidence`, `intrinsic`, `construction`, then the position check below (`no position`), then
`order`, `run` and `incarnation`. Which entities are replicas follows the naming convention of
section 18.3.

Both stages of an ordered pair need a position, in either shape: a stage that the numbered
order or the `Order:` line requires to follow an earlier stage, and every earlier stage it
must follow; and, when a `restart` line names a replica a line binds, that line and every
earlier stage an `as Ek` links it to. A position is a probe observation's `seq`, an `exact`
entry's stamp, or a `construction` action's position. Presence-only evidence, such as a
reporter map read after the run, cannot establish an order, so such a held stage, earlier or
later, is `unverifiable (no position)`. Stages that `Order:` frees need no position relative
to each other.

A held stage adds the feature `(site_hash("TS-NNNN"), k, 0)` through the existing `record`, so
fuzzing rewards inputs that get further; R-FB-6 holds, because features are only added. The
first miss closes the scripted prefix, except in the control run: the remaining events are not
driven, the scaffold calls `Stages::handoff`, which prints `handoff lost`, and the input
continues into the base's free-running phase and every oracle.

**Incarnations.** A runtime resumed from a checkpoint and an engine restarted inside one
runtime keep `run` (section 9.6). They are incarnation boundaries: the scaffold marks every
restart it drives with the helper's `restart(replicas)`, and in Shape A it adds a marked call of
it to the restart code of a base that restarts replicas, an edit under section 18.6.1; the
subsystem rules below name the known restart sites as guidance. A relation across a boundary
holds only if the line names the incarnation the restart began: the scaffold binds that
incarnation to `inc<s>`, `<s>` being the `seq=` that `restart` printed and returned, and a
line that binds no entity to it is rejected (above). `restart` takes a position of its own, so
two restarts of a replica with no observation between them begin two distinct incarnations,
and a relation that names the first while its evidence lies after the second is rejected.
Whether the card names both incarnations is for review, so the script annotates every
`restart` line between two stages that an `as Ek` links `relation across restart`; a restart
that no call marks it cannot see (section 18.11).

**Handoff and recovery** are separate, and handoff comes first.

- Shape B drives `E1` to `E(n-1)` online, polling in simulated time, with a simulated-time
  deadline per stage: passing it is a miss, never a wait. Every await on a SUT reply is raced
  against the deadline, and a dropped reply is a miss.
- The handoff check witnesses `En`'s `Holds` line at the handoff instant. It requires a fresh,
  uninterrupted read of `En`'s witness: the scaffold passes the read to `Stages::handoff` as a
  plain closure, which the helper calls between a tick of its own and the handoff mark, so no
  await or yield can come between the read and the mark, and a witness built before the call
  predates that tick. In addition, no probe observation may take a position between the read
  (`read=`) and the mark (`mark=`). Every observation and helper event takes a position, so the
  helper reports `handoff holds` only when `mark=` is `read=` + 1, which shows both, and the
  script rechecks it from the lines (section 18.8). Those positions date the read, not what
  it read: an `intrinsic` witness built inside the call may cite an old observation that a
  later one at the same site, of the same replica, contradicts. So `En` takes an `exact`
  witness where one exists, and an `intrinsic` one cites the latest observation at its site
  for its replica, found with `observations` rather than `seen`, which returns the earliest
  (section 18.11). For a state defined by pending work or a
  withheld delivery, an `exact` observable shows the operation still pending at that instant,
  the request recorded and neither answered nor closed (rule S3 of the scenario SPEC: the
  defining state is present at handoff). Nothing the prefix does may complete, cancel or
  abandon that work: the scaffold never awaits its reply, drops its reply channel, or stops or
  restarts its owner before the handoff. If `En` does not hold at handoff it is missed (`not
  held at handoff`), even if it held earlier, and the continuation still runs.
- The continuation starts with every fault the prefix opened still in place: a crashed replica
  down, a partition, a held message. Recovery is part of the continuation and never precedes
  handoff. Every such fault is released no later than the base's first heal (GST), and the
  base's liveness measurement starts after both. Network cuts go through the base's own fault
  input, as pinned partition fields that the base installs and heals, or are composed with the
  base's current cut; the scaffold never heals the network on its own. Crashed replicas and
  withheld messages are released at handoff plus `d`, a knob in [0, the base's fault phase):
  12 s in the marshal scenario-prefix runner, 30 s (`FAULT_PHASE`) in `consensus/fuzz/core`,
  which the marshal end-to-end disrupter runner uses. A base without GST releases them before
  its liveness wait starts.
- The runtime deadline is the base's (`fuzz_runtime_timeout(..)` for the simplex Standard,
  audited and Twins drivers; the Chaos and ByzzFuzz runners and every marshal base set none,
  and a scaffold of one passes `Duration::MAX` to `Stages::budget` instead) plus the stage
  deadlines plus the largest release delay.
- A marshal prefix leaves enough height below the epoch ceiling (`BLOCKS_PER_EPOCH`) for the
  liveness measurement after the handoff; the subsystem rules say so. The script cannot
  measure that height, so it is for review of the module (section 18.11).
- Shape A imposes no cleanup, and its handoff is implicit: `En`'s witness, read in the handoff
  call after the run, counts only if it has a position and the trace holds a later guarded
  observation of an honest replica in the same `run`, which `Stages::handoff` prints as
  `next=`; otherwise `En` is `unverifiable (no continuation)`.

**Control.** The module header names one withheld event, `Ek`, with k < n and `harness` as its
actor. The scaffold reads `STATELENS_REACH_CONTROL` only through the helper's `control()`, and
when it is set skips `Ek`'s action and records `Ek` as withheld. In the control run a miss
does not close the prefix: the scaffold still drives every later event, the handoff check and
the base's oracles, so `En` gets a line and the run prints its `reach` and `done` lines. Where
the card has no `harness` event before `En`, the header says `Control: n/a`, which section 18.8
accepts only when every witness is `exact` or `construction`.

**Oracles.** The base's free-running phase and every oracle run, called by path or copied
verbatim, never removed or weakened. In Shape A the base's oracles run inside its entry
unchanged, so a History whose continuation they would not measure takes Shape B. In Shape B,
progress targets are re-based on the handoff, in the base's own measure, which the Simplex and
Marshal rules below give; without that the canonical run could have nothing left to do.
`done` follows the last oracle. Stage checks and verdicts are not oracles.

**No fabrication** (rule I5 of the scenario SPEC). Events go through the network or the harness
verbs. A scripted vote goes out only on its signer's own channel (INV-0008). A certificate the
scaffold builds names an honest signer only for a proposal that replica signed or would sign.
Every injection, such as a journal seed, a floor start, a resolver delivery or a mailbox call,
is listed in `//! Injections:` with the INV ids whose ghost history it bypasses (section 8.7).
The module never writes ghost state and never calls `record` itself.

**Guard.** A Shape B scaffold calls `set_compromised` with the indices it runs as real engines
under a Byzantine identity, empty if none, before any engine starts, with the index check of
Appendix B.3 when the set is not empty. Code copied from a hooked runner keeps its hook. Shape
A relies on the base's hooked runner (Appendices B.3 to B.5 and F).

**Missing capabilities.** A stage that needs what the edit contract cannot give, such as a new
dependency, a change to what the protocol does, or an item of `consensus/fuzz/core/` that is
not public, is never approximated: the scaffold records the stage as missed with
`cannot: <capability>`, lists it under `//! Missing:`, keeps the prefix up to that stage and
hands off. For `En` it records that miss before it calls `Stages::handoff`, which then reports
the handoff lost. A human adds the capability with an ordinary commit.

**Panics.** The prefix and witness code a scaffold adds never panics on SUT data: no `unwrap`,
`expect` or index that SUT output decides, and no harness verb that panics on a SUT reply; a
miss instead. The only panics it adds are the helper's scaffold errors, below; the base's
oracles and the code copied verbatim from its driver keep theirs, since a miss after the
handoff records nothing.

**Simplex** (`subsystems/simplex-synthesize.md`, section 13.22).

- Bases: every `simplex_*` target but Mallory. Shape A fits a History that the fields of
  `FuzzInput` fix (partition, configuration, certify choice, block filter). The chaos, ByzzFuzz
  and Twins schedules are drawn from the random stream `raw_bytes` seeds, so no field pins them,
  and a History about them takes Shape B. The `_state_cov` and `_hb` targets add coverage
  tables, which cost throughput.
- Usable without an edit: the crate root's private drivers of section 18.1 and
  `chaos::runner::run`; the public items of `consensus/fuzz/core`, among them `setup_network`,
  `bounded_fuzz_runtime_config`, `fuzz_runtime_timeout`, `spawn_filtered_honest_validator`,
  `run_twins_with_backend` (hooked, Appendix B.3) and the partition helpers; and the mock
  reporter's maps keyed by view (`leaders`, `notarizations`, `nullifies`, `nullifications`,
  `certifications`, `finalizations`), read after the run for presence or through a recording
  wrapper for order.
- With a marked edit (section 18.6.1): `chaos::runner::{run_with, restart_durable, enact,
  check_safety}` and the internals of `chaos::twins`; under `consensus/src/simplex/`, which the
  test gate then reruns over, an accessor such as one for the private fields of
  `mocks::twins::RoundScenario`, which only `cases` builds.
- Known restart sites, which get a marked `restart` call when a scaffold runs them (section
  18.7): `chaos::runner::restart_durable` (Chaos) and `chaos::twins::restart_honest`
  (Chaos-Twins). The list is guidance, not a complete one.
- `start_validator_engine` in `consensus/fuzz/core` is private and starts every engine from
  `Floor::Genesis`; a History that needs another floor copies it into the module with the floor
  as a parameter. The Chaos-Twins runner's gate is the pattern for a stage: wait for a replica's
  own state before acting, and do not act in the wrong state.
- Progress and deadline: `run_standard_once`, `run_audited_standard_once_with` and `run_twins`
  run under `bounded_fuzz_runtime_config`, whose deadline is
  `fuzz_runtime_timeout(input.required_containers, <prefix views>)`, with 0 prefix views, or
  `twins_prefix_views(..)` for `run_twins`; the Chaos, Chaos-Twins and ByzzFuzz runners set
  none. Each base keeps its own liveness measure, which a Shape B continuation counts from the
  handoff (Oracles, above), and the base's condition for measuring at all: the standard and
  audited drivers wait only under `should_bound_standard_liveness` (a `Connected` partition, a
  valid configuration and `BlockFilterChoice::None`) and otherwise sleep `MAX_SLEEP_DURATION`
  with no liveness assertion, so FaultyNet, whose partition is always `Adaptive`, never waits;
  where they wait, the target is the latest finalized view at the handoff plus
  `input.required_containers`; the audited driver excludes the notarize-omission victim from
  that wait and keeps its post-invariant recovery-drain check
  (`unresolved_finalize_recoveries`, `check_finalize_recoveries_drained`); the Twins campaign
  counts `input.required_containers` finalizations of views after the Twins prefix
  (`observe_liveness`), and only views after the handoff count; the Twins mutator checks no
  liveness, and none is added; Chaos, ByzzFuzz and Chaos-Twins measure from their own heal or
  recovery, which follows the handoff, so their targets stay: the larger of
  `input.required_containers` and one view past the finalized view at the heal, the highest
  node's for Chaos (`liveness_target`) and each node's own for ByzzFuzz
  (`reach_gst_and_check_liveness`), and one view past the highest at its recovery for
  Chaos-Twins.
- Missing, reported as `cannot:`: journal seeding, because the package has no
  `commonware-storage` dependency and guard 2 forbids adding one.

**Marshal** (`subsystems/marshal-synthesize.md`, section 13.23).

- Shape A first: `marshal_e2e_standard_deferred_cert_mock_scenarios`, whose
  `NotarizationBlockSplitScenarioInput` fixes a scripted template and its pre-GST actions, with
  the wedge's real Byzantine engine behind the hook of Appendix F. The `*_twins_split_header`
  targets draw their Twins case from the stream `raw_bytes` seeds (`run_twins_with_backend`
  samples `twins::cases` from it; `case_selector` only indexes that sample), so no field pins
  the case, and a History about it takes Shape B; a fixed case needs a marked constructor for
  the private fields of `mocks::twins::Scenario` and `RoundScenario`.
- Shape B uses, without an edit, the `pub(crate)` items of `scenarios` named in section 18.1
  (the harness, its verbs and `finish`) and `marshal::end_to_end::twins`. With a marked
  visibility edit: `scenarios::runner::run`, whose journal seeding before the engines start is
  how Simplex engines start from a reconstructed state, and the private modules
  `scenarios::{adversary, elector, strategy}` and `end_to_end::{input, runner, scenario}`.
- The scenario-prefix runner starts no engine during its prefix, so a History whose events need
  running engines, such as TS-0001's, takes an end-to-end base.
- Known restart site, which gets a marked `restart` call when a scaffold runs it (section
  18.7): the `StoreOp::Restart` arm of `marshal::store`
  (`marshal_actor_standard_store_cert_mock`), which restarts the marshal actor. The list is
  guidance, not a complete one.
- Of the scenario SPEC (`consensus/fuzz/marshal/src/scenarios/specs/SPEC.md`), rules S1, S2,
  S4, S7, I1 to I3 and I5 apply; S3 becomes the handoff check, S5 and R9 become `cannot:`; S0
  and S6 do not apply, because the card and the module header cite the source, and I4 does
  not, because R-TS-SYN-3 allows marked edits under the editable roots. No `ScenarioKind`
  variant is added.
- Only the victim, `Node::B`, has an injectable resolver, with one armed delivery at a time,
  and in `N4F1C3` node 0 has no marshal. The harness verbs that panic when the SUT does not
  answer (`await_wrapper` after 5 s, `verified` and `certified` on a write that is not durable),
  and the polls of the existing scenario prefixes in `scenarios.rs`, bounded to 64 rounds, are
  not used where a SUT reply decides; the scaffold races the reply against its stage deadline
  instead.
- Progress and deadline: no marshal base sets a runtime deadline, so `Stages::budget` takes
  `Duration::MAX`. Each base measures finalized heights against its own baseline, which a
  Shape B continuation counts from the handoff: the scenarios target, one block past each
  correct node's height at GST (`check_scenario_progress`); Twins, `input.trailing_blocks`
  blocks of views after the prefix (`wait_for_liveness`); the scenario-prefix runner, one block
  past each honest node's height at its heal, `input.required_containers` only ending the fault
  phase early; the disrupter and poison targets (`run_liveness_phases`),
  `input.required_containers`, or after a fault phase that ends without it, the larger of that
  and one block past each honest node's height at the heal; the store target checks no
  liveness.

**Helper template.** `SL/runtime/target_states.rs`, copied to `<package>/src/target_states/mod.rs`
(section 18.6), calls the runtime module of the profile's crate by path, is `rustfmt`-clean, and
is never compiled on a committed branch. Its verbatim copy is Appendix H. Its state, like the
trace's, is per thread: the thread that calls `Stages::new` owns the stages. Its code lies in
a private module, `imp`, of `mod.rs`, which re-exports the items below: a scaffold module is
a child of `target_states`, and a child module may use every private item of its parent, so
code in `mod.rs` itself would let a scaffold print a `[statelens-reach]` line through the
helper's own printer, or build a `Witness` or a `Stamp` field by field; the private items of
`imp` are out of its reach. Its self-tests (`imp::tests`, `#[cfg(test)]`) fill the trace to
`TRACE_CAP`, change state past it, and check the `truncated` line, `unverifiable (trace
truncated)` for a later stage and for `En` with no feature, and `handoff lost`, and a handoff
that holds without a cut, an `En` recorded `unverifiable` before the handoff, which keeps its
reason and loses the handoff, and, with `STATELENS_REACH` unset, a miss that records no `trace`
line and a handoff that records `next=-`; they run with
`cargo +stable nextest run -p <package> --lib target_states::` in a checkout synthesis wrote
`mod.rs` to. Under `cfg(test)` the helper also records each line it prints and each feature it
adds in thread-local lists the tests read.

| Item | Behavior |
|---|---|
| `Knobs::split(card: &'static str, raw: &mut Vec<u8>, k: usize) -> Knobs` | First forgets the stages an earlier input left on its thread, so a scaffold error before `Stages::new` prints none of them. Takes the first `k` bytes of `raw`, zero-padded, and leaves the rest; a tail left empty from a non-empty `raw` becomes `[0]`. It takes the card's ID because it runs before `Stages::new`, and its scaffold errors name the card. |
| `Knobs::pick<T: Copy>(&mut self, domain: &[T]) -> T` | The next knob: `domain[byte % domain.len()]`. It cannot return a value for an empty domain, so a domain of fewer than two values is a scaffold error. |
| `control() -> bool` | Whether `STATELENS_REACH_CONTROL=1`, read once. |
| `Stages::new(card: &'static str, n: u32) -> Stages` | Calls `watch()`, opens the prefix phase and prints `phase prefix`, and installs the panic hook below, once per process. Lines print only under `STATELENS_REACH=1`, read once; the work that only feeds them, the trace lines of a miss and the handoff's `next=`, runs only then. |
| `Stages::budget(&self, knobs: Knobs, prefix: Duration, runtime: Duration)` | Called before any engine starts, and takes the knobs, so none is picked later: the stage deadlines plus the largest release delay, against the runtime deadline. |
| `stamp(observable: &str, key: &str, value: &str) -> Stamp` | A recording wrapper's call as it records an entry: takes a `tick()`, prints `entry` with it, and returns it as an opaque `Stamp` that only `stamp` makes, with the `run` current when it was taken; `Stamp::seq()` reads its position and cannot make one. The script checks every stamp an `exact` item carries against its `entry` line anyway (section 18.8). Returns a stamp of position 0 and prints nothing while not watching. A free function, so a wrapper can call it. |
| `Witness::exact(bind, reads: &[(observable, key, value, stamp: Option<Stamp>)])`, `Witness::intrinsic(bind, seen: Seen)` | A witness and its bindings, `bind` written `name=value@Ek,...`, and each `key` naming the entities it fixes as `name=value,...`. Each takes a `tick()` when it is built, its `read=`. An `exact` witness's position is its latest stamp's, and it has none when an item has no stamp; an `intrinsic` witness's is its observation's `seq`. |
| `Witness::act(bind, action, perform: impl FnOnce() -> T) -> (T, Witness)`, `Witness::act_async(bind, action, perform: P) -> impl Future<Output = (T, Witness)> + use<T, F, P>`, with `P: FnOnce() -> F` and `F: Future<Output = T>` | The only way to make a `construction` witness: takes a `tick()`, the action's position and the witness's `read=`, right before it calls `perform`, which performs the action, and returns `perform`'s result with the witness, so the position is the action's and everything the action causes comes after it. `act_async` takes its tick when its future is first polled, and only then calls `perform` and awaits the future it returns, so an action that takes effect when it is called, as a mailbox method that queues its message at the call does, still comes after its position; its future borrows neither `bind` nor `action`. `action` names the verb and the entities it fixes as `verb[name=value,...]`; a bare verb is printed `verb[]`. Before `Stages::new` nothing watches: the position is 0, and the stage has none. |
| `Stages::held(&mut self, k: u32, witness: Witness) -> bool` | Stage `k` held: prints the record with the witness's `read=`, records the stage feature, and moves `since()` forward to the stage's position + 1, or to its `read=` + 1 when it has none, never back. Stages may be recorded in any order. A call for stage n, which only `Stages::handoff` records, for a stage that already has an outcome, for an event number outside 1 to n, or once the prefix is closed does nothing and returns `false`. A witness whose `read=` is at or after the position `truncated()` returns makes the stage `unverifiable (trace truncated)` instead, with no feature. Returns `true` only when it recorded the stage held. |
| `Stages::missed(&mut self, k: u32, detail: &str)`, `unverifiable(&mut self, k: u32, reason: &str)`, `withheld(&mut self, k: u32)` | The other outcomes, with the same calls doing nothing, except that `missed` records stage n when its detail starts with `cannot:`, and `unverifiable` records stage n, for an `En` that no available witness binds; after either, `Stages::handoff` calls no `read` and prints `handoff lost`. The first miss closes the prefix, except in the control run, and prints up to 64 trace lines from the stage's start. A miss recorded once `truncated()` returns a position is `unverifiable (trace truncated)` instead and closes nothing, unless its detail starts with `cannot:`. |
| `Stages::open(&self) -> bool`, `Stages::since(&self) -> u64` | Whether the prefix is open; the position from which the next stage reads the trace. |
| `restart(replicas: &[u32]) -> u64` | Takes a `tick()`, `s`, as an incarnation boundary of `replicas`, prints it, and returns `s`, which names the incarnation it began, `inc<s>`: two restarts never share it, even with no observation between them. Returns 0 and prints nothing while not watching. A free function, so a base's restart code can call it. |
| `Stages::handoff(&mut self, read: impl FnOnce() -> Option<Witness>)` | Decides the handoff itself. It takes a `tick()`; then, when stage n has no outcome and the prefix is open, calls `read`, a plain closure that cannot await or yield; then it takes the handoff mark, a `tick()`, `mark=`, and records `En` held with the witness `read` returned, printing its record, or missed (`not held at handoff`) on `None`. Once the trace dropped an observation at or before `mark=`, `En` is `unverifiable (trace truncated)` instead, whatever `read` returned, and the handoff is lost. The handoff holds when `En` was held in this call and `mark=` is its `read=` + 1: the witness was built inside the call, after the first tick, and no observation or other event came between the read and the mark. Prints `handoff holds|lost mark=<m> next=<run>:<seq>|-`, where `next` is the first observation after `En`'s position, in the `run` of that position, of a replica that is not compromised (Shape A, section 18.7), then `phase continuation` and the `reach` line; closes the prefix and calls `unwatch()`. A second call does nothing. |
| `Stages::on_panic(&mut self, evaluate: fn(&mut Stages))` | Shape A: the evaluation of the stages, which the panic hook runs over the trace so far, handing it a `Stages` handle so that it records the stages through the helper. |
| `Stages::done(&mut self)` | Prints `done`. |

**Truncation.** Once `truncated()` returns a position `s`, the helper prints `truncated seq=<s>`
once per input, at its first event after the cut: a position it takes or a stage it records, so
the line precedes every stage line evaluated after the cut.

The panic hook is chained in front of the one libfuzzer-sys installed. For a panic on the
thread that called `Stages::new`, under `STATELENS_REACH=1`, it first prints `panic` with the
location and the first line of the message of the panic it handles, then the phase,
the stage lines recorded so far and, in Shape A, those the registered evaluation finds in the
trace; a stage whose witness the hook cannot read prints `unverifiable (crashed)`. Then the
libfuzzer-sys hook prints the panic location and aborts; a panic inside the evaluation aborts
at once, after the `panic` line. The phase is `prefix` before the handoff and `continuation`
after it; in Shape A, `continuation` once `En` is found held. The hook prints the phase before
it runs the evaluation, so in Shape A the script reads the phase as `continuation` when an
`En` `held` line follows the `panic` line. A failure that is not a panic
takes the last `phase` line printed; in Shape A, whose stages are evaluated after the run, the
phase of one during the run is unknown.

**Scaffold errors.** The helper raises a panic with the message `[statelens-scaffold] TS-NNNN
<reason>` only in `Knobs::split`, `Knobs::pick` and `Stages::budget`, which run before any
engine starts, so the conditions depend only on the scaffold's own code and knob bytes, never
on SUT output: more than 16 knobs, or more knobs picked than split; an empty domain, or one
with a single value; and a budget whose prefix exceeds the runtime deadline. These functions
are not `#[track_caller]`, so the panic's location is in `target_states/mod.rs`. Every other
helper call checks without panicking, as the table says. `Knobs::split` and `Knobs::pick` run
before `Stages::new`, so their errors print no `[statelens-reach]` line, only the message and
location libfuzzer-sys prints. Section 18.8 classes such a failure as SCAFFOLD ERROR.

### 18.8 Reach check

The reach check replays fixed inputs and does not fuzz (D66). Each attempt replays the
canonical input and then runs the control; the kept version replays the canonical input once
more (section 18.6.2).

**A replay.** The binary is the fuzz build's release output:
`$CARGO_TARGET_DIR/<host>/release/<scaffold>` when `CARGO_TARGET_DIR` is set, a relative value
taken from the checkout's root, where the build runs, and otherwise
`target/<host>/release/<scaffold>` or `<package>/target/<host>/release/<scaffold>`, both
checked as `coverage` checks its build. It runs in individual-file mode on
`SL/campaign/reach/empty`, with `SL/campaign/reach/TS-NNNN_<base>/attempt-<a>/<replay>/` as its
working directory, `<replay>` being `canonical`, `control` or, for the kept version's last
replay, `final`: libFuzzer reads no corpus and gets no flag from the script, and a crash file
lands in that directory, beside the replay's log, `replay.log`. The environment sets
`STATELENS_REACH=1`, and `STATELENS_REACH_CONTROL=1` for the control run only, and leaves
`STATELENS_BYZANTINE` unset, so the guard skips compromised replicas. The script kills a replay,
with everything it started, after 1,500 s, whether or not the replay's own process still runs,
longer than libFuzzer's default `-timeout` of 1,200 s, and classes the kill as `timeout`.

**Lines.** The helper prints, and the script parses:

~~~
[statelens-reach] TS-NNNN E<k>/<n> held <kind> bind=<name>=<value>@E<j>[,...] <evidence> read=<s>
[statelens-reach] TS-NNNN E<k>/<n> missed[ <detail>]
[statelens-reach] TS-NNNN E<k>/<n> unverifiable[ <reason>]
[statelens-reach] TS-NNNN E<k>/<n> withheld
[statelens-reach] TS-NNNN entry <observable>[<name>=<value>,...]=<value> seq=<s>
[statelens-reach] TS-NNNN restart <replica>[,...]|- seq=<s> run=<r>
[statelens-reach] TS-NNNN trace <run>:<seq>:<me>:<label>@<site>:<a>:<b>
[statelens-reach] TS-NNNN truncated seq=<s>
[statelens-reach] TS-NNNN handoff holds|lost mark=<m> next=<run>:<seq>|-
[statelens-reach] TS-NNNN phase prefix|continuation
[statelens-reach] TS-NNNN reach <k>/<n> control=0|1
[statelens-reach] TS-NNNN panic <file>:<line>:<col>|-[ <first line of the message>]
[statelens-reach] TS-NNNN done
~~~

`<kind>` is `exact`, `intrinsic` or `construction`, and `<evidence>` is, in that order: one
`exact=<observable>[<name>=<value>,...]=<value> seq=<s|->` per observable read;
`obs=<run>:<seq>:<me>:<label>@<site>:<a>:<b>`; or `action=<verb>[<name>=<value>,...] seq=<s>`.
Every `<seq>` and every number after `seq=`, `read=` and `mark=` is a position of the event
sequence (section 9.6): an `entry` line's `seq=` is the position `stamp` took for the entry; an
`exact` item's `seq=` is that of its stamp, or `-`; an action's `seq=` is the position
`Witness::act` took right before it performed the action, so a construction stage has a
position like any other; a `restart` line's `seq=` is the position
of the boundary, which names the incarnation `inc<s>`; `read=` is the position the witness
took when it was built; and `mark=` is the handoff's own. `truncated seq=` is the position of
the first observation the trace dropped at `TRACE_CAP` (section 9.6), printed once. The helper
keeps the fields apart.
It first drops the whitespace at the ends of a key, of an action's entity list and of
`bind=`, and next to each `,` and `=` in them and each `@` in `bind=`, so `R=2@E1, v=5@E1`
binds `v`, and trims a verb. Then in an observable or a verb it writes whitespace, `,`, `@`,
`=`, `[` and `]` as `_`, in a value the same except `=`, and an empty one of these as `-`; a
key writes whitespace, `@`, `[` and `]` as `_`, keeps its `,` and `=` and may be empty; and in
`bind=` the remaining whitespace becomes `_`. `?` is the value of an entity a witness does not identify;
`<me>` is `-` for a site without a replica, and `<site>` is `<file>:<line>:<column>`. An `exact`
witness with no read leaves its evidence empty, so two spaces come before `read=`. `missed
cannot: <capability>` is a missing capability, and `missed not held at handoff` the handoff's
own miss. Up to 64 `trace` lines follow a miss, from the start of the missed stage. A handoff
prints its `handoff`, `phase continuation` and `reach` lines in that order. `reach` counts the
stages the helper recorded as held; `control=1` marks the control run. `done` follows the last
oracle. A `panic` line names `-` when the panic has no location. The prefix
`[statelens-reach]` keeps these lines apart from `[statelens][`, which section 7.9 reads, but a
`panic` line can quote a `[statelens][INV-...]` message, so the script drops the
`[statelens-reach]` lines before it calls `first_panic`. A line matches

~~~
^\[statelens-reach\] (TS-\d{4,}) (?:E(\d+)/(\d+) (held|missed|unverifiable|withheld)\b ?(.*)|entry ([^\[\s]+)\[([^\]\s]*)\]=(\S+) seq=(\d+)|restart (\S+) seq=(\d+) run=(\d+)|trace (\S+)|handoff (holds|lost) mark=(\d+) next=(\d+:\d+|-)|reach (\d+)/(\d+) control=([01])|phase (prefix|continuation)|panic (\S+) ?(.*)|truncated seq=(\d+)|done)$
~~~

and the rest of a `held` line matches `^(exact|intrinsic|construction) bind=(\S+) (.*) read=(\d+)$`,
an `exact` item `exact=([^\[\s]+)\[([^\]\s]*)\]=(\S+) seq=(\d+|-)`, an `intrinsic` observation
`obs=(\d+):(\d+):(\d+|-):([^@\s]+)@([^\s:]+:\d+:\d+):(\d+):(\d+)`, and an action
`action=([^\[\s]+)\[([^\]\s]*)\] seq=(\d+)`. The script recomputes every witness record from these lines
(section 18.7), and the handoff: `handoff holds` counts only when `En` is held, by the `held`
line that directly precedes the `handoff` line and that only the handoff call prints, its
witness is not rejected, and the handoff's `mark=` is that line's `read=` + 1, so the witness
was read inside the handoff call and no observation or other event came between the read and
the mark. When the timing fails, because `En`'s `held` line is not the one directly before
the `handoff` line, `mark=` is not its `read=` + 1, or the helper printed `handoff lost`, `En`
is missed (`handoff lost`) and the verdict is PARTIAL; when the timing holds but `En`'s
witness is rejected, `En` is `unverifiable`. When the replay printed a `truncated seq=<s>`
line, anywhere among the card's lines, the script takes the smallest `<s>` and, after the
timing check and before the witness rules, makes every stage still held whose `held` line's
`read=` is `<s>` or later `unverifiable (trace truncated)`, and `En` too when `handoff holds`
with a `mark=` of `<s>` or later; the handoff then does not hold, so the verdict cannot be
REACHED. A cut after the handoff mark changes nothing. In Shape A, `En` is `unverifiable (no
continuation)` when its witness has no position, or `next=` is `-` or not after that
position, or, for a probe observation, of another `run`. A stage without a line, when no
stage before it missed, is `unverifiable (no line)`, and a `withheld` line in the canonical
run is `unverifiable` too. A stage or `reach` line whose `n` is not the card's, and lines
printed under another card's ID, make the replay NO REPORT.

libFuzzer runs a passing input a second time in the same replay, to look for leaks, so a
passing replay prints its lines twice; a failing one prints them once. The script reads the
card's lines of one run of the input and ignores the rest: a run opens with the `phase prefix`
line `Stages::new` prints, and the panic hook reprints the phase after its `panic` line, so a
`phase prefix` line that a `panic` line of its run precedes opens none. It keeps the run that
printed a `panic` line, else the first, so a later run never completes an earlier one's report
and a failure in a later run is read in that run's phase.

**The control run.** It replays the canonical input with `STATELENS_REACH_CONTROL=1`, and the
scaffold withholds the event the header names, which prints `withheld`. The control is vacuous
when its `Ek` is not a `harness` event before `En`, when the run prints no `withheld` line for
`Ek`, when a stage before `Ek` misses or binds other values than in the canonical run, when a
stage after `Ek` and before `En` has no line or is withheld too, since that omission could
explain the miss by itself, when `En` has neither a `held` nor a `missed` line, or when the
run is not a complete report: it printed no `reach` or no `done` line, or lines under another
card's ID or another `n`. It is `weak` when `En` is held for the bound entities, which ignores
witness rejections in the control run, since they usually come from the withheld event. An
entity the control's witness leaves out of `bind=`, or binds to `?`, does not tell the states
apart, and neither does a value the control witness's own key, or the earlier stage it cites
as `as Ej`, contradicts: the control is weak unless an entity both witnesses bind to a value,
one the control's own evidence does not contradict, has another value in the control run. A
`Control:` line that names neither `withholds Ek` nor `n/a` is vacuous, and so is a control
with no replay.
`Control: n/a` is accepted only when the card has no `harness` event before `En` and every
witness is `exact` or `construction`, and is annotated `control n/a` either way. A module
without a `Control:` line has no control, annotated `control missing`. A vacuous control has
no annotation; the report gives its reason.

**Verdicts.** From the canonical run, its control and the kept version's last replay:

| Verdict | Condition |
|---|---|
| REACHED n/n | Every stage held and no witness rejected, `handoff holds` and `done`; the control is not vacuous and does not hold `En` for the bound entities, or is `n/a` where that is accepted |
| UNVERIFIED k/n | No stage missed, but a stage is `unverifiable` or a witness was rejected; or the control is vacuous, `weak` or missing; or `Control: n/a` where it is not accepted. `k` counts the stages held. |
| PARTIAL k/n | A stage after `E1` is the first to miss; `k` counts the stages held before it, and the report lists the earlier stages that did not hold; `handoff lost` misses `En` |
| UNREACHED 0/n | `E1` missed |
| NO REPORT | The replay did not fail but printed no `reach` or no `done` line: the helper was not used, or the scaffold returned before the base's oracles; or its lines name another card or another `n` |
| CRASH (finding candidate) | A replay failed, below, unless the failure is the next row's, or a run of the agent's left a crash file (`stray failure`, section 18.6.2). Any failure other than a scaffold error makes the version CRASH, even beside one. The report gives its kind, phase, location and stage lines. |
| SCAFFOLD ERROR | The replay's first panic is the helper's `[statelens-scaffold]` error (section 18.7), at a location in `target_states/mod.rs` |
| NOT BUILT | No version passed the vetoes and built; as `NOT BUILT (breaks TS-MMMM_<b>)`, the kept version made the standing scaffold of TS-MMMM on `<b>`, a pair of the same card included, stand worse, and its edits were restored (section 18.6.2, Finish) |
| GATE FAILED | The kept version's edits under the editable roots made a test of the gate fail, or no longer run, that the inventory does not record as failing, or the gate's output was unusable (guard 5); over a kept CRASH, `GATE FAILED (finding candidate in attempt-<a>/)` |

The script computes `k` after rejecting witnesses; the `reach` line is the helper's count,
before them. Verdicts are reported only. Every card with a kept version, every verdict but NOT
BUILT and GATE FAILED, has a scaffold, and `--state-reaching` fuzzes it.

**Crash attribution.** A failure of a replay, canonical, control or final, in either phase, is a
panic, a `[statelens][INV-...]` or `[statelens][BYZANTINE]` message, a harness oracle's
failure, a sanitizer report, an out-of-memory or leak report, a runtime timeout or stall, or
the script's kill. Every one is kept in `SL/campaign/reach/TS-NNNN_<base>/attempt-<a>/`, with its
crash file, its log, its replay line (`replay.txt` for a kept one, `interrupted.txt` when
synthesis stopped before the attempt ended) and the version that failed (`version.diff` and
`version/`), kept before its replays start, and every one but a scaffold error is a finding
candidate, which a human triages as any crash (R-P3-2). Its kind
comes from the log: `timeout` (`ERROR: libFuzzer: timeout`, or the kill), `oom` (`ERROR:
libFuzzer: out-of-memory`), `leak` (`ERROR: LeakSanitizer`), `sanitizer` (another sanitizer's
`ERROR:`), and otherwise `panic`, with the line `first_panic` picks, or the message `exit code
N` when a replay exits non-zero with no message the script recognizes. The report gives the
phase, from the `phase` lines (section 18.7), `unknown` for a Shape A failure that is not a
panic unless the last `phase` line is `continuation`, and the location: the one the helper's
`panic`
line or the chained default panic hook prints, `panicked at <file>:<line>:<col>`, which for an
invariant is the SUT line, because `violation` is `#[track_caller]`; or else the first frame
outside the standard library of the sanitizer's stack. It also says whether the pair's diff
added or moved that line, with the annotation `location in TS-NNNN diff`.

Where a failure happened is diagnostic context only. A line the pair's diff added or moved does
not make the failure the scaffold's: a production assertion moved into an exposed helper, or
an accessor that exposes corruption made earlier, fails for the SUT's reasons. The only failure
attributed to the scaffold is the helper's own `[statelens-scaffold]` error, SCAFFOLD ERROR,
recognized by the message prefix and a location in `target_states/mod.rs` (the card ID in the
message is not checked); the same message raised elsewhere is a CRASH. A
CRASH (finding candidate) stops refinement for its pair, and that version is the one kept and
fuzzed (section 18.6.2), unless guard 5 restores it, which leaves it a finding candidate; if
triage shows a fault of the scaffold, the operator synthesizes the pair again with
`--redo --match <base>_tsNNNN`, or the whole card with `--redo --match TS-NNNN`.

**Annotations.** `nondeterministic` (the last replay's stage lines differ from the stored
ones), `weak`, `control n/a` and `control missing` (the control), `unbound label <label>` (a
label the module passes to `seen` or `sites` that no `sl_probe!` or `sl_implies!` site under
the editable roots names), `missing: <capability>` (from the header, one per item separated by
`;`), `unmarked edit` and `edit beside instrumentation` (guard 4), `relation across restart`
(section 18.7), `stray failure` (section 18.6.2), and `location in TS-NNNN diff`.

**Feedback.** The next attempt's `FEEDBACK` holds the verdict, its stage, `truncated` and trace
lines, the vetoes and guard findings, the build's last lines, and the verdicts of the earlier
attempts, with what each signal asks for:

| Signal | What to fix |
|---|---|
| A veto, a guard, a build failure, or the agent's exit code | That, as reported |
| `Ek` missed with `cannot: <capability>` | Nothing in the scaffold, unless an edit the contract allows, or another shape, gives the capability; otherwise a human adds it |
| `E1` missed | The setup: configuration, pinned and dependent fields, roles, elector or shape |
| A middle `Ek` missed | The event's content, recipient, channel or order; the trace's `a`, `b` and sites against what the stage expects |
| `En` missed, or `handoff lost` | Knob domains, timing, and what keeps the state pending at handoff |
| `unverifiable`, or `witness rejected` | A witness that binds the relation: an intrinsic site for an existential line, otherwise an exact observable keyed by the bound entities, with positions where order matters |
| `weak`, with bound witnesses | Withhold the event without which `En` cannot hold for these entities, or report that the History is not causal |
| A vacuous or missing control | Name, or withhold, a later harness event before `En`; in the control run, drive every later event, the handoff check and the base's oracles |
| NO REPORT | Use the helper, and never return before the base's oracles |
| SCAFFOLD ERROR | The reason the helper named |

A miss with `cannot:` takes its own row wherever its stage is; the `E1`, middle and `En` rows
are for the other misses. The `cannot` row does not send the agent to another base: a base
that has the capability is a pair of its own (section 18.6.2). Automatic repair covers only
these. A CRASH (finding candidate) gets no feedback, because refinement stops (D67).

### 18.9 Running

**`just fuzz <profile> --state-reaching`** (D68). For
`just fuzz simplex --parallel --tmux --state-reaching --state-targets TS-0004 --fuzz-targets "simplex_cert_*"`:

1. The flag loop takes `--state-reaching`, and refuses any other flag that starts with `--`
   before `--` ("just fuzz: unknown flag <flag>", exit code 1); without that refusal
   `--state-reaching` falls to `*) break` and reaches libFuzzer with every flag after it.
   `--state-targets TS-0004` and `--fuzz-targets "simplex_cert_*"` become `--match TS-0004
   --match 'simplex_cert_*'`, in the order given, and no libFuzzer argument is left. Each
   pattern flag takes the `=` form too and may be repeated; a value missing after one ("just
   fuzz: --fuzz-targets needs a pattern", "just fuzz: --state-targets needs a pattern"), a
   `TS-` pattern given to `--fuzz-targets` ("just fuzz: --fuzz-targets names fuzz targets; a
   card is --state-targets <pattern>"), any other pattern given to `--state-targets` ("just
   fuzz: --state-targets names cards (TS-NNNN); a fuzz target is --fuzz-targets <pattern>")
   and `--state-targets` without `--state-reaching` ("just fuzz: --state-targets needs
   --state-reaching") each exit with code 1.
   `--state-reaching` with a single target ("just fuzz: --state-reaching narrows a profile;
   name simplex or marshal", followed by "(one scaffold runs with just run <scaffold>)") or
   with `qmdb` ("just fuzz: --state-reaching takes simplex or marshal; qmdb has no target
   states") exits with code 1. `--invariants LIST` and `--invariants=LIST`, given once or
   more, are kept for the campaign; a value missing after `--invariants` ("just fuzz:
   --invariants needs a list of ids"), the flag with `--skip-campaign` ("just fuzz:
   --invariants selects what a campaign binds; drop --skip-campaign") and the flag with a
   single target ("just fuzz: --invariants selects what a campaign binds; name simplex,
   marshal or qmdb") each exit with code 1 before anything is listed or run.
2. `statelens.py targets --profile simplex --state-reaching --match TS-0004 --match
   'simplex_cert_*'` exits with code 1 when no card and base are selected or a selected card
   has a lint problem, so a bad selection fails before the campaign. Otherwise it lists the
   scaffolds of the selected pairs (card, base) that exist, if any.
3. `just campaign --profile simplex`, followed by each `--invariants LIST` given, unless
   `--skip-campaign`. A failed campaign stops the recipe, as it does without the flag.
4. `statelens.py synthesize --profile simplex --match TS-0004 --match 'simplex_cert_*'`, one
   scaffold per selected pair (section 18.6.2). A non-zero exit code stops the recipe: 2, among
   them guard 1 and a checkout that differs from `B`, or 3, no scaffold built.
5. `targets --state-reaching` lists the scaffolds of the selection again; an empty list exits
   with code 1 ("just fuzz: no scaffold for this selection; see the reports in
   campaign/reach/").
6. The tmux, sequential and parallel branches of section 5.3 run unchanged over that list: the
   tmux session is `statelens-simplex-reach`, refused if it exists; each window is named
   `${name%_statelens}`, for example `simplex_cert_mock_ts0004`; logs go to
   `SL/campaign/logs/<scaffold>.run.log`; and each runs `just run <scaffold>` with the
   libFuzzer arguments given after `--`, none here.

The command opens one window per `simplex_cert_*` base of TS-0004, one per scaffold that
built: every simplex base but Mallory matches, 20 at `HEAD`. `--fuzz-targets simplex_cert_mock`
opens one, `simplex_cert_mock_ts0004`; with `--state-targets "TS-000*"` or no
`--state-targets`, and the cards TS-0003 and TS-0004 present, every pair of both cards gets a
window. No variant runs with `--state-reaching`, and without it nothing changes. For
`just fuzz simplex --state-reaching --state-targets TS-0004 --fuzz-targets "simplex_cert_mock_twins_*" --invariants "simplex/INV-0001,simplex/INV-0002" -- -max_total_time=3600`,
step 3 runs `just campaign --profile simplex --invariants simplex/INV-0001,simplex/INV-0002`,
which binds those two invariants (section 7.1 step 4), TS-0004 is synthesized on each of the
eight `simplex_cert_mock_twins_*` bases, `simplex_cert_mock_twins_campaign` and
`simplex_cert_mock_twins_mutator` with their `_audit`, `_hb` and `_state_cov` siblings, and the
eight scaffolds, `<base>_ts0004_statelens` each, for example
`simplex_cert_mock_twins_campaign_ts0004_statelens`, run in turn, each with
`-max_total_time=3600`; the recipe's messages count scaffolds (`8 simplex scaffold(s), in
turn`).

**justfile.** New recipes `extract-states` (`python3 scripts/statelens.py extract --states
"$@"`) and `synthesize` (`python3 scripts/statelens.py synthesize "$@"`). In `fuzz`, the header
comment lists `[--fuzz-targets GLOB]...`, `[--state-targets GLOB]...`, `[--state-reaching]` and
`[--invariants LIST]...`, the last of which the `campaign` header also lists, and the flag
loop, the two pattern functions, the refusals, the listing, the synthesis, the second listing
and the session name are as above. Section 5.3 reproduces the file.

**`targets --state-reaching`.** `targets [--profile P] --state-reaching [--match GLOB]...`
prints the scaffolds of the selected pairs of section 18.6.2 whose thin target exists, one per
line, in selection order. It exits with code 1 when no card and base are selected or a selected
card has a lint problem, and with code 0 otherwise, also when no scaffold exists yet.

**Run and replay.** A scaffold is a fuzz target of its package: `just run <scaffold>` runs it,
and libFuzzer runs the empty input, the canonical input, first. Its `run` line carries no
libFuzzer argument; the variants' lines of section 7.9 are unchanged. A crash is triaged and
replayed as in section 7.11 (R-P3-2), and with `STATELENS_REACH=1` the replay also prints the
stage lines of section 18.8. In Phase 3 the stage features show how far fuzzed inputs get.

**Coverage and clean.** `just coverage` accepts a scaffold's name, and a profile name covers its
scaffolds with its variants (section 7.13). `just clean` removes what synthesis wrote (section
18.6.2).

### 18.10 Acceptance procedures

Synthesis runs with a real agent unless a stub agent is named: a `claude` on `PATH` that reads
its prompt and makes the edit the procedure gives. Synthesis procedures run on a fresh clone of
the profile after a campaign that ended `READY` or `PANIC (tests)`.

| AC | Procedure | Pass condition |
|---|---|---|
| AC-22 | `just check-invariants` with TS-0001 committed. For each agent: `just extract-states --registry marshal test consensus/src/marshal/standard/mod.rs:7027`; `just extract-states --registry simplex test consensus/src/simplex/mod.rs:3260`; `just extract-states --registry simplex text "<a paragraph describing TS-0004>"`; `just extract-states --registry marshal issue https://github.com/commonwarexyz/monorepo/pull/4317`; and, with `STATELENS_KB` set, `just extract-states --registry marshal kb <finding id>`. Then the refusals: a `test` path outside the roots, `--registry qmdb`, and `just extract-invariants test <path>`. Last, a `test` extraction with `--local`. | No lint problem. Each extraction writes lint-clean cards with a pinned `source_ref`; the `issue` card is deleted as a duplicate of TS-0001. The refusals exit with code 1. The `text`, `kb` and `--local` cards are written only to `target-states.local/`, which `git status` does not list. Once TS-0002 to TS-0004 are committed (TS-0004 moved by hand), `just check-invariants` reports no problem. |
| AC-23 | The runtime self-tests in the test gate (section 7.7), and the helper's self-tests (section 18.7) in a checkout synthesis wrote `mod.rs` to. Then a campaign whose stub instrumenter adds a call of `seen` under the editable roots. | The self-tests pass: watching; `tick` and the observations sharing one strictly increasing sequence, so that two ticks with no observation between them, and observations and ticks interleaved, get distinct, ordered positions; `mark` returning the last position without advancing; `clear_trace`, which `reset` calls, starting the sequence again, so positions are unique within one input only; `seen` finding the earliest match at or after a position, `site` and `run`, a guarded replica absent from the trace, the pairs `sl_implies!` notes, the cap, past which `truncated()` returns the position of the first dropped observation, which a later drop does not move and `watch` and `unwatch` reset, and the sequence still advances, `sites`, and the run counter of the fresh-run hook. The helper's self-tests pass: after a state change past the cap, `truncated seq=<s>` once, `unverifiable (trace truncated)` with no feature for a later stage and for `En`, and `handoff lost`; without a cut, `handoff holds`; an `En` recorded `unverifiable` before the handoff keeps its reason and loses the handoff; with `STATELENS_REACH` unset, a miss records no `trace` line and the handoff records `next=-`. The campaign stops in the scope check with exit code 2, naming the file. |
| AC-24 | `just synthesize --profile simplex --match simplex_cert_mock_chaos_ts0003 --match simplex_cert_mock_ts0004`, which pins each card to one base, the family of PRD section 11.4, so the selection is the two pairs (TS-0003, `simplex_cert_mock_chaos`) and (TS-0004, `simplex_cert_mock`). Then one stub agent per guard of section 18.6.1: an edit outside the scope, then `just synthesize` once more, and then that edit undone with `git checkout`; a dependency added to the package manifest; an `sl_probe!` added; a two-attempt stub, each of whose attempts writes a valid module and thin target, whose first attempt removes or alters an `sl_assert!` call and whose second makes an unrelated edit and leaves that change in place, and a variant whose second attempt reverts the change; a ghost update deleted, and the `set_compromised` call of the Chaos-Twins hook (Appendix B.5) changed; a `#[path]` attribute on the runtime module's declaration; the runtime module changed; a `[statelens-reach]` literal in the module; a `statelens::watch()` call in the module; an `eprintln!` call, a `set_hook` call and an `include!` in the module; a module under a directory named `target`; a marked accessor under `consensus/src/simplex/` that keeps the test gate passing, and one that fails it; an unmarked hunk in the fuzz package; a marked `if false` around an unchanged `sl_assert!` call. Then a stub that never builds, with one pair selected, and one that exits with a non-zero code. Then, with `NEXTEST_STATUS_LEVEL=fail` and `CARGO_TERM_COLOR=always` set, the marked accessor that fails the test gate again, and one that keeps the crate building but a test of the gate from compiling; and, on a fresh checkout whose campaign `logs/test.log` was removed before the first synthesis, the passing accessor. Then three two-pair stubs, over the two pairs above: one whose second pair changes the first pair's module so that its thin target no longer builds, one whose second pair adds a marked accessor under `consensus/src/simplex/`, followed by `just synthesize --redo --match simplex_cert_mock_ts0004`, interrupted (`SIGINT`) during TS-0003's revalidation replays, and then `just synthesize --match simplex_cert_mock_ts0004` with a stub that writes only TS-0004's module and thin target, and one whose second pair writes only its own module and thin target. Then one card on two bases, `just synthesize --profile simplex --match TS-0004 --match simplex_cert_mock --match simplex_cert_mock_faulty_net`, on a checkout without TS-0004's reports, with a stub that writes a module and thin target per pair; then the same command again; then `just synthesize --redo --match simplex_cert_mock_ts0004`. | The scaffolds, `simplex_cert_mock_chaos_ts0003_statelens` and `simplex_cert_mock_ts0004_statelens`, build, and the console prints their verdicts, one `TS-NNNN` line per pair, and `run` and `replay` lines without libFuzzer arguments; TS-0004 is REACHED. No `corpus/` or `artifacts/` entry exists for them, and `git status` lists only paths section 18.6.1 allows. The stubs: exit code 2 with the pair's edits restored, and the next synthesis exits with code 2 before any pair, naming the path; the manifest restored with feedback; vetoes for the probe, the runtime module, the literal, the `watch` call, the print, the panic hook, the include and the ignored module; the two-attempt stub vetoed in every attempt with the same guard 3 feedback, the stub changing nothing after its second attempt, which ends the pair, NOT BUILT, and the `sl_assert!` call as in `B` after the pair, while its variant's second attempt builds; vetoes for the ghost update, the hook and the `#[path]` attribute; the test gate run again, passing and then GATE FAILED with the edit restored; `unmarked edit`; `edit beside instrumentation`; NOT BUILT and exit code 3, with the pair's files restored and every variant still building; and a failed attempt after which the other pair is synthesized. Under the changed nextest settings, the failing accessor is GATE FAILED naming the failing test, and the one that breaks a test's build is GATE FAILED with `(unusable output: no nextest summary line)`; `SL/campaign/reach/baseline/tests.json` lists the gate's tests; without the campaign log, the gate runs once on the tree as the campaign left it, logged to `logs/test-baseline.log`, before any pair, and the accessor passes the gate. The first two-pair stub is `NOT BUILT (breaks TS-0003_simplex_cert_mock_chaos)` with its edits restored and TS-0003's verdict and report, `TS-0003_simplex_cert_mock_chaos.md`, unchanged; the accessor's pair keeps its scaffold and TS-0003's report gains `## Revalidation after TS-0004_simplex_cert_mock`, and after the `--redo`, which removes the accessor, is interrupted with exit code 130, leaving TS-0003's verdict unchanged and `SL/campaign/reach/revalidation.json`, the next synthesis adds `## Revalidation after --redo`, before TS-0004 is synthesized again, and deletes that record; the third revalidates TS-0003 too, under `## Revalidation after TS-0004_simplex_cert_mock`; the last check builds every scaffold. The card on two bases gives two scaffolds, `simplex_cert_mock_ts0004_statelens` and `simplex_cert_mock_faulty_net_ts0004_statelens`, two reports and two diffs, `TS-0004_simplex_cert_mock.*` and `TS-0004_simplex_cert_mock_faulty_net.*`, two `pub mod` lines in `target_states/mod.rs`, a `run` line each, and the second pair revalidates the first, whose report gains `## Revalidation after TS-0004_simplex_cert_mock_faulty_net`; the second command prints two `skipped: TS-0004 on <base> was synthesized as <scaffold>; use --redo` lines, one per pair; the `--redo` of one pair moves `TS-0004_simplex_cert_mock.*` to `TS-0004_simplex_cert_mock.<stamp>.*`, leaves the other pair's thin target and `[[bin]]` block in place, and its report gains `## Revalidation after --redo`. |
| AC-25 | The procedure of AC-24 for TS-0001 and TS-0002 on a `marshal` checkout, with `--profile marshal` and the pairs (TS-0001, `marshal_e2e_standard_deferred_cert_mock_twins_split_header`) and (TS-0002, `marshal_e2e_standard_deferred_cert_mock_poison`), the families of PRD section 11.4, selected as `--match <base>_ts0001 --match <base>_ts0002`; the card on two bases uses `marshal_e2e_standard_deferred_cert_mock_poison` and `marshal_e2e_coding_cert_mock_poison`. Then a stub scaffold of TS-0001 that builds `E7`'s witness while R's certification is outstanding, and passes it to `Stages::handoff` only after that certification has completed. Then the differential test of section 18.10.1: `SL/scripts/differential.sh` from the checkout, with `DIFFERENTIAL_SCRATCH` naming a directory with 25 GB free. | As AC-24 for the real agent. TS-0001's report shows the pending-state handoff check: `handoff holds`, with `E7` witnessed by an `exact` observable that shows R's certification still outstanding at the handoff instant. The stub's report shows `handoff lost`, with a `mark=` greater than `E7`'s `read=` + 1, and PARTIAL 6/7. The differential test prints the table of section 18.10.1 and `differential: PASSED`: the fuzz package's clippy, rustfmt and tests pass with the widened visibility, the 30 tests listed are the 30 expected, every positive test has equal digests and `REACHED n/n` with no annotation, and every negative control is caught, by the digest or by the validator's verdict of a replay that ran to its digest line (no row carries `(FAILED)`, `(NOT CAUGHT)` or `(ERROR)`); the worktree and its target directory are gone afterwards, the logs stay in `<scratch>/run.XXXXXX/logs/`, and `git status` of the checkout is as before. The test compares the settled state after `finish` of hand-written prefixes; it establishes neither state equality at the handoff mark nor anything about an agent's scaffold. |
| AC-26 | Two canonical replays of each scaffold of AC-24 and AC-25. Stub scaffolds, one per witness rejection rule of section 18.7: an `as Ek` value that differs, and one that `Ek` bound to `?`; an entity missing from `bind=`; an `exact` key without an entity of the line; positions against the History's order; a foreign `run`; a relation across a `restart` line whose incarnation the line does not bind; an `intrinsic` witness with a wrong `me`, one citing two observations, and one giving a view a value; a `construction` witness for `En`, and one for an event whose actor is not `harness`. Two stubs of an ordered pair with presence-only evidence: one for the later stage, and one for the earlier stage while the later is stamped. A stub that performs two harness actions A and then B, with no probe observation between them, for events the History orders A before B, each with a `construction` witness; and one that performs B before A. A stub that restarts one replica twice with no probe observation between the restarts, and whose later line, related by an `as Ek` to a stage before both restarts, names the incarnation the first restart began while its evidence lies after the second. Stubs with a vacuous control, a `weak` control, no `Control:` line, and `Control: n/a` with an `intrinsic` witness. A stub that prints `[statelens-reach]` itself, and one that prints `[statelens-scaffold]` itself. Stubs whose prefix raises an invariant's panic, panics on a line the pair's diff added or moved, makes a sanitizer report in an accessor it added, and fails in the control run only. A stub agent that runs its scaffold and leaves a crash file. A stub with an empty knob domain. A stub with a missed stage. A stub that fills the trace to `TRACE_CAP`, changes the state past the cap, and reads in the handoff the latest observation the trace kept. A stub whose canonical replay fails, with synthesis interrupted (`SIGINT`) during the control replay. | The two replays print the same stage lines. Each rejection stub is UNVERIFIED with `witness rejected: <its rule>`, each presence-only stub UNVERIFIED with `unverifiable (no position)`, and each control stub UNVERIFIED. The two actions get distinct positions, A's smaller, and both stages hold in the first stub; the second is UNVERIFIED with `witness rejected: order`. The two restarts print distinct `seq=` values, so two incarnations, and the stub that names the first is UNVERIFIED with `witness rejected: incarnation`. The printing stubs are vetoed. Each failing stub is CRASH (finding candidate), with refinement stopped after that attempt and its crash file in `attempt-<a>/`; `just run <scaffold>` reproduces the first three, the second and third carry `location in TS-NNNN diff`, and the fourth's `replay` line sets `STATELENS_REACH_CONTROL=1`. The stray crash file is in `attempt-<a>/swept/`, and that attempt is CRASH (finding candidate) with `stray failure`. The empty domain is SCAFFOLD ERROR, and refinement continues. The missed stage prints `handoff lost`, `reach k/n` and then `done`. The truncation stub prints `truncated seq=<s>` and is UNVERIFIED with `unverifiable (trace truncated)`; the same lines with `En` held, `read=` at or after `<s>` and `handoff holds` are UNVERIFIED too. The interrupted synthesis exits with code 130 with the pair's edits restored, and `TS-NNNN_<base>/attempt-<a>/` holds the canonical crash file and log, `version.diff`, which `git apply --check` accepts on the tree before the pair, `version/`, and `interrupted.txt`, which names the pair, the control replay as the step that stopped and gives the canonical replay's `run` and `replay` lines. |
| AC-27 | On a checkout of AC-24: `just fuzz simplex --parallel --tmux --state-reaching --state-targets TS-0004 --fuzz-targets "simplex_cert_*" --skip-campaign`; the same with `--fuzz-targets simplex_cert_mock`, with `--fuzz-targets "simplex_cert_mock_twins_*"`, with `--state-targets "TS-000*"` and with `--fuzz-targets "nothing*"`; then `just fuzz simplex --bogus`, `just fuzz simplex --state-targets TS-0003`, `just fuzz simplex --state-reaching --fuzz-targets TS-0003`, `just fuzz simplex --state-reaching --state-targets "simplex_cert_*"`, `just fuzz qmdb --state-reaching` and `just fuzz simplex_cert_mock --state-reaching`. | The first opens the session `statelens-simplex-reach` with one window per `simplex_cert_*` base of TS-0004 whose scaffold built, 20 pairs at `HEAD`, and none for a variant, each running `just run <scaffold>` with no added argument, the message saying `20 scaffold(s), one tmux window each`; `simplex_cert_mock` opens one window, `simplex_cert_mock_ts0004`; `simplex_cert_mock_twins_*` opens eight, `simplex_cert_mock_twins_campaign_ts0004` to `simplex_cert_mock_twins_mutator_state_cov_ts0004`; `TS-000*` opens one window per scaffold of TS-0003's and TS-0004's pairs; `nothing*` fails before synthesis. The last six exit with code 1. |
| AC-28 | `just clean --yes` on a checkout of AC-24 or AC-25; then `just campaign` on a checkout that has `<package>/src/target_states/`. For a scaffold that runs a real engine under a Byzantine identity (a non-empty `set_compromised` in Shape B, or a Shape A base whose hook compromises one), a canonical replay with `STATELENS_BYZANTINE=panic`. | After `clean` every path in its scope, the fuzz packages included, matches `HEAD`, and no `target_states/` or thin target is left. The campaign exits with code 2. The replay panics with `[statelens][BYZANTINE]`; with no such scaffold, this check is recorded as not applicable. |
| R-TS-NF-3 | With the same duration and flags, each scaffold and its base's variant, in the same instrumented checkout. | The exec/s values are reported side by side. |

#### 18.10.1 Differential test of the primitives (AC-25)

The scenario prefixes of `consensus/fuzz/marshal/src/scenarios/scenarios.rs` are hand-written
reconstructions of six marshal standard tests (PRD section 11.2) that check the state they
reach at the handoff through `finish`. They are the one human-written definition of such
states the repository has, so they serve as the differential oracle of the helper primitives:
for each source test, a hand-written TSS prefix built from the helper of Appendix H and the
same harness verbs, as `prompts/synthesize.md` and section 18.7 prescribe for a scaffold,
must leave the cluster in the same state as the scenario's prefix and must be judged REACHED
by the reach check of section 18.8. The test is `SL/differential/`, a test-only crate outside
the workspace (section 3), and `SL/scripts/differential.sh` runs it. Neither instruments the
system under test, starts an engine or runs libFuzzer: this tests the method, not a campaign.

Procedure (`SL/scripts/differential.sh`; `DIFFERENTIAL_SCRATCH` names the scratch directory,
`$TMPDIR/statelens-differential` by default, under which every run gets a directory of its
own, `run.XXXXXX` from `mktemp -d`; it needs about 25 GB of free disk, the `stable`
toolchain with nextest, and the pinned nightly's rustfmt, `DIFFERENTIAL_RUSTFMT`):

1. `git worktree add --detach <scratch>/run.XXXXXX/wt-diff HEAD`, one directory per run, so
   concurrent runs share nothing and the trap removes only what the run created; `rsync` of
   `SL/` and `consensus/fuzz/marshal/` into it, so the uncommitted visibility change and the
   crate are present; `CARGO_TARGET_DIR` inside the worktree; the root `Cargo.lock` copied
   beside the crate's manifest, so cached versions are reused. The script never builds in
   the checkout it runs from, and a trap removes the worktree with its target directory.
2. The fuzz package: `cargo +stable clippy -p commonware-consensus-fuzz-marshal --all-targets
   -- -D warnings`, `rustfmt --check` of the nine touched files, and `cargo +stable nextest
   run -p commonware-consensus-fuzz-marshal`, which shows the visibility change changed
   nothing (`SKIP_FUZZ_CHECKS=1` skips this step).
3. `rustfmt --check` of the crate and `cargo +stable test --manifest-path
   SL/differential/Cargo.toml --lib --no-run`.
4. The 30 tests of the table below, checked against `-- --list`: a listing that differs (a
   missing, extra or duplicate name, a test moved into a nested module) is an error, exit 2,
   before any replay, so no test is skipped silently. Each runs in a process of its own with
   `--exact`, `--test-threads=1` and `--nocapture`, twice: the canonical replay under
   `STATELENS_REACH=1`, with `DIFFERENTIAL_DIGESTS=<logs>` (`<logs>` is
   `<scratch>/run.XXXXXX/logs/`) so both digests land in `<test>.{a,b}.digest`, and the
   control replay under `STATELENS_REACH_CONTROL=1` as well; stdout and stderr captured per
   replay (`<test>.<canonical|control>.{out,log}`).
5. `python3 scripts/statelens.py reach-verdict --card cards/TS-NNNN.md --module
   src/cards/tsNNNN.rs --canonical <log> --canonical-code <exit> --control <log>
   --control-code <exit>` for every test, the negatives included, so a wrong prefix can be
   REACHED there and the check stays live; the verdict goes to `<test>.verdict`.
6. A table `| test | digest equal | verdict |`; `differential: PASSED` and exit 0 when every
   positive test has exit 0, `digest-equal=true` and `REACHED n/n`, and every negative ran
   to its digest line (exit 0) and got a verdict the validator computed (`REACHED`,
   `UNVERIFIED`, `PARTIAL` or `UNREACHED` `k/n`), with an unequal digest or a verdict other
   than REACHED; `differential: FAILED` and exit 1 otherwise, with `(FAILED)` beside a
   positive's verdict, `(NOT CAUGHT)` beside a negative's with equal digests and a REACHED
   verdict, annotated or not (an annotation is informational, never a rejected witness),
   and `(ERROR)` beside a negative's whose replay crashed, printed no digest line or got no
   computed verdict (a traceback, `CRASH`, `NO REPORT`): an error of the run, not a caught
   control. The validator's exit code cannot tell these apart, since it is 1 for every
   verdict but REACHED, so the script checks the verdict's shape. Logs stay in
   `<scratch>/run.XXXXXX/logs/`, printed at the end.

The test. One `#[test]` per card, marshal variant and configuration runs two prefixes on the
same setup: `src/setup.rs` is a verbatim copy of the SETUP block and harness construction of
`scenarios::runner::run@392b116687` (`scenarios/runner.rs:139-264`, the one private function
the test cannot import), with the stamping wrappers of `src/record.rs` (a `StampingResolver`,
`StampingBuffer` and `StampingReporter`, which forward every call unchanged and `stamp` the
entries they record) around the three arguments of `start_with_buffer` on both sides, and the
input bytes are `FuzzRng::new(vec![0u8; 64])`, the canonical input. Side A calls
`scenarios::drive::<P, M>(kind, &mut harness)` unmodified and then `finish`. Side B resets the
runtime module, splits the knobs (none), builds `Stages` with a budget of `STAGE_DEADLINE`
(5 s of simulated time) per stage and `Duration::MAX`, sets an empty compromised set, calls
the fresh-run hook where the materialized `Runner::new` would, and drives the card's History
from `src/cards/tsNNNN.rs`: one stage per event, a `construction` witness (`Witness::act`,
`Witness::act_async`) for a `harness` event, an `exact` witness read back from the recorder's
stamped entries for a replica event, every reply of the system under test raced against the
stage deadline, a pending reply established at its stage by `try_recv` on the receiver the
prefix holds, a side-effect-free query that leaves an empty channel awaitable, and stamped
only then (TS-9005 and TS-9006 stamp `verify=pending` at E2 on `Empty`, never at the call; a
verdict or a dropped sender there misses E2), a count a later stage must preserve read back as
the value an earlier stage observed, not as nonzero (TS-9006's E4 requires E2's
`subscription` count), `En` read freshly inside the closure of `Stages::handoff`, then
`finish` when every stage held and this is not the control run, and `Stages::done`. Each
module opens with the header of section 18.7 (`Shape: B`, `Control: withholds E1`, its
injections). Both sides
then take the digest of `src/digest.rs`, and the test asserts `reached` and equal digests;
side B never sees side A's digest. The digest first settles the cluster (no pending
application acknowledgement and stable processed positions, within 64 rounds, else a panic),
since the two sides never share a schedule, and then prints, with every multiset sorted and
every read side-effect-free (`Get*` mailbox queries, shared counters and maps, and the
runtime's durable storage read without opening a blob): what `finish` reads; the recorded
resolver fetches, the active and targeted fetches, the armed delivery and the unconsumed
delivery verdicts (`RecordingResolver::auto_delivery` and `delivery_responses`); buffer
subscriptions and sends; held blocks by digest, verified blocks by view, finalizations and
info by height, the application tip, deliveries and pending acknowledgements; every node's
storage partition by partition (the certificate and block caches, the finalized archives, the
application metadata, through `Context::scan` and `logical_blob`) with one `storage_audit` of
the whole runtime; the handoff description; the ledger and the canonical chain.

The imports. The crate depends by path on `commonware-consensus-fuzz-marshal` (feature
`mocks`), `commonware-consensus` (`mocks`), `commonware-consensus-fuzz-core`,
`commonware-cryptography` (`mocks`), `commonware-runtime` (`test-utils`), `commonware-utils`,
`commonware-p2p` (`mocks`), `commonware-resolver`, `commonware-actor`, `commonware-codec`,
`commonware-macros`, `bytes` and `futures`; the shim adds `sancov`. The two committed
templates are compiled byte-identical by `SL/differential/shim/`: `extern crate self as
commonware_consensus;` and `extern crate self as commonware_runtime;` put the shim into its
own extern prelude under both names, so the helper's one import,
`commonware_consensus::simplex::statelens::{self, Seen}`, resolves to
`#[path = "../../../../runtime/statelens.rs"] pub mod statelens;` under a `simplex` module,
and the runtime's `commonware_runtime::deterministic::STATELENS_FRESH_RUN` to a local
`OnceLock<fn()>`; the helper is `#[path = "../../../runtime/target_states.rs"] pub mod
target_states;`. The runtime's tail after `// [statelens] consensus only:` is `#[cfg(test)]`,
so it is compiled out when the shim is built as a dependency, and no `sl_probe!`,
`sl_assert!` or `sl_implies!` is invoked anywhere in the crate. No copy, `sed` or edit of the
templates is involved; `SL/runtime/` is byte-identical to `HEAD`.

The visibility change. `consensus/fuzz/marshal/src` makes the scenario primitives the crate
imports `pub` instead of `pub(crate)`, the one change outside `SL/` (section 3; PRD
R-LAYOUT-3): the module declarations `scenarios::{environment, harness, input,
recording_resolver, scenarios}`, `marshal::end_to_end::{app, twins}` and `twins::stack`
(`scenarios::runner` stays `pub(crate)`, hence the verbatim setup copy); the `Scenario` trait
and `drive`; `FuzzScenarioStandardHarness`, its verbs and `finish`; `ScenarioHandoff` and its
types; `RecordingBuffer`, `RecordingResolver` with its two injection fields `auto_delivery`
and `delivery_responses`, which the digest reads, and `init_injectable`; the setup pieces of
`app` and `twins::stack` (`setup_validator`, `setup_network`, `register_engine_networks`,
`genesis_block`, `MarshalChoice`, `TwinsMarshal`, `AlwaysAcceptBlockBuilderApp`,
`BlockContextRegistry`, `DeliveryReporter`, `ProgressHandle`) and the aliases `B`, `Ctx`,
`PublicKeyOf` and `SchemeOf`; the input types. Every changed line is the keyword, except
three reflows rustfmt makes for the shorter keyword and two `#[allow]`s the lints then
require (`async_fn_in_trait` on the now-pub `Scenario` trait, `clippy::new_without_default`
on `ProgressHandle::new`). No logic, signature or doc changes; nothing under `consensus/src`
changes (scenario SPEC G5 and R8). Items that sit in now-pub signatures become `pub` with
them (`ApplicationChoice` and `FaultyConfig` in the `TwinsBlockBuilder` trait, `FetchRecord`,
`TargetedRecord`, `CertificateKind`, `PrefixCertificate`), and the harness verb set is
widened whole, since one half `pub(crate)` would be the worse surface. A read-only accessor
for the resolver's injection fields would be cleaner than reading them, but is not a
visibility change.

Scenarios covered. Seven cards over the six source tests, `SL/differential/cards/TS-9001.md`
to `TS-9007.md`, in the grammar of section 18.3 with their generated Source excerpts (`just
excerpts differential/cards/TS-NNNN.md` after a citation changes) and pinned to
`392b116687`. They are not cards of a registry: the `9NNN` ids and the location outside the
card trees keep them out of `lint`'s default discovery, out of synthesis and out of the
registries' counter, so `lint` reaches them only when they are named, and then reports
their location (rule 1) and nothing else; rules 2 to 13 pass. `reach-verdict` checks their
ID and History through `card_history`, not the whole card:

| Card | Source test (`consensus/src/marshal/standard/mod.rs`) | Scenario kind | Stages | Tests |
|---|---|---|---|---|
| TS-9001 | `test_standard_certify_missing_candidate_fetches_by_round` | `StandardCertifyMissingCandidateFetchesByRound` | 4 | deferred and inline, N4F0C4 and N4F1C3 |
| TS-9002 | `test_standard_certify_first_block_fetches_genesis_parent` | `StandardCertifyFirstBlockFetchesGenesisParent` | 5 | the same four |
| TS-9003 | `test_standard_verify_height_lie_parent_fetch_is_round_bound`, Deferred: rejected at certify | `StandardVerifyHeightLieParentFetchIsRoundBound` | 7 | deferred, N4F0C4 and N4F1C3 |
| TS-9004 | the same test, Inline: rejected at verify | the same | 5 | inline, N4F0C4 and N4F1C3 |
| TS-9005 | `test_standard_certify_bumps_notarized_fetch_for_pending_verify` | `StandardCertifyBumpsNotarizedFetchForPendingVerify` | 5 | the four |
| TS-9006 | `test_standard_verify_missing_candidate_waits_without_fetching` | `StandardVerifyMissingCandidateWaitsWithoutFetching` | 4 | the four |
| TS-9007 | `test_standard_get_block_by_height_and_latest` | `StandardGetBlockByHeightAndLatest` | 6 | the four |

Expected result, observed at `392b116687` with the uncommitted trees (`differential: PASSED`
about 180 s after the builds; no positive verdict carries an annotation, and no replay prints
`witness rejected`):

| test | digest equal | verdict | caught by |
|---|---|---|---|
| `ts9001_{deferred,inline}_{n4f0c4,n4f1c3}` (4) | true | REACHED 4/4 | - |
| `ts9002_{deferred,inline}_{n4f0c4,n4f1c3}` (4) | true | REACHED 5/5 | - |
| `ts9003_deferred_{n4f0c4,n4f1c3}` (2) | true | REACHED 7/7 | - |
| `ts9004_inline_{n4f0c4,n4f1c3}` (2) | true | REACHED 5/5 | - |
| `ts9005_{deferred,inline}_{n4f0c4,n4f1c3}` (4) | true | REACHED 5/5 | - |
| `ts9006_{deferred,inline}_{n4f0c4,n4f1c3}` (4) | true | REACHED 4/4 | - |
| `ts9007_{deferred,inline}_{n4f0c4,n4f1c3}` (4) | true | REACHED 6/6 | - |
| `neg_ts9001_dropped_arm` | false | PARTIAL 0/4 | digest and validator |
| `neg_ts9001_notarization_to_c` | false | REACHED 4/4 | digest (storage) |
| `neg_ts9002_armed_garbage` | false | REACHED 5/5 | digest (`armed`) |
| `neg_ts9002_stale_handoff_read` | true | PARTIAL 4/5 (`handoff lost`) | validator |
| `neg_ts9005_swapped_arm_verify` | true | UNVERIFIED 4/5 (`witness rejected: order`) | validator |
| `neg_ts9007_finalization_to_c` | false | PARTIAL 1/6 | digest and validator |

Negative controls. Each `neg_*` test runs a deliberately wrong TSS prefix, a `Twist` of the
card module, and must give an unequal digest or a verdict other than REACHED, from a replay
that ran to its digest line and a verdict the validator computed (step 6; a crash, a missing
digest line or an unparsed verdict is `(ERROR)`, not a caught control): E1, the armed
delivery, dropped (TS-9001: certify never resolves, so the prefix misses every stage and B
lacks the block); the view-1 notarization also reported to node C (TS-9001: the mailbox has
no query for cached certificates, so only C's durable certificate cache, two blobs more under
`cache-cache-0-notarizations-*`, tells the sides apart, while the validator says REACHED);
`En`'s witness built before the handoff call (TS-9002: `handoff lost`, with `mark=` more than
one past `read=`); a garbage delivery left armed on the victim (TS-9002: `armed=true` against
`armed=false`, which the fuzzing phase would otherwise inherit silently, caught by the digest
alone); two order-relevant harness events performed in reverse with the stages recorded in
card order (TS-9005: `witness rejected: order`); a finalization delivered to node C (TS-9007:
C fetches the block, so side B reaches no handoff and the verdict is PARTIAL). Further wrong
prefixes that were tried, and how they were caught: a block timestamp changed (digest), the
block also `verified` on C (`finish` panics: `node C must lack block`), a third harness event
dropped (digest and PARTIAL), a handoff without awaiting certify (PARTIAL 3/4), a parent
persisted before its child (digest and PARTIAL 2/7).

What the test establishes, and what it does not. It establishes the fidelity of the
primitives and of a reconstruction: a prefix written from the helper of Appendix H and the
harness verbs, following the rules of section 18.7 and `prompts/synthesize.md` (one stage per
event, witnesses from exact observables or constructions, `En` read inside the handoff, no
fabrication), leaves the cluster, after `finish` and once it has settled, in the same state
as the human-written scenario prefix of the same source test, by a definition of that state,
the digest, written independently of both and wider than `finish`; and the reach check of
section 18.8 accepts such a prefix as REACHED and rejects, or the digest tells apart, the
wrong ones above. It does not establish that the two states are equal at the handoff mark:
the digest is taken after `finish` and after a settle whose mailbox reads let the cluster
progress and clean up, an observation procedure rather than a snapshot of the handoff
instant, so a prefix that skips a barrier the scenario takes, so that an event is still in
flight at its handoff, settles to the same state and is not told apart (a barrier before a
report, or after a drop, skipped: equal digests and REACHED), by design of the digest; the
handoff-instant claims of a stage are the witness rules' (section 18.7), not the digest's.
It establishes nothing about agent output:
the TSS prefixes are hand-written, so whether an agent writes such a prefix from a card is
what AC-24 and AC-25 with a real agent judge, and no agent-generated scaffold has been run
through it. It uses no probe, so every witness is `exact` or `construction`, the `intrinsic`
kind is not exercised, and the run counter is what the fresh-run hook makes it (1). It
covers the marshal standard harness only, two marshal variants and two configurations, with
no engine, no libFuzzer and no knob. And both sides run the same system under test, so the
digest comparison cannot see a regression of that system: only side A's reference
assertions (`finish` and the scenario's own `assert_eq!`s) can.

### 18.11 Known limitations

- Most probe values carry no view, digest or other identity, so a probe binds few entities, and
  many stages need an exact observable or end `unverifiable`. A beacon a later campaign adds is
  the remedy; synthesis never adds one.
- A Shape A crash reports only the stages its trace witnesses: the panic hook cannot read an
  exact observable the crashed run held, so those stages print `unverifiable (crashed)`. The
  phase of a Shape A failure that is not a panic may be unknown.
- An engine restart that no `restart` call marks is invisible to the script, and whether a
  relation across a marked one names both incarnations is for review; so is whether a base's
  restart code got its marked call.
- The agent never runs its scaffold, so it learns how a version behaves only from the
  feedback of the script's replays.
- A verdict comes from one input, the source values. How often fuzzed inputs reach the state
  shows only in Phase 3, through the stage features and `STATELENS_REACH=1` replays.
- The knobs are the first bytes of `raw_bytes`, the last field of the input, so a mutation that
  changes how many bytes the earlier fields take shifts which bytes become knobs. This is
  accepted.
- Agents are not deterministic, so two syntheses of one pair differ. A pair costs at most four
  agent runs, their builds and replays, a test gate when it changed the editable roots, and a
  build and three replays of every other scaffold that stands, since a module can use a
  sibling module.
- A card on b selected bases is b pairs, each with its own attempts, builds, replays and gate,
  and each kept pair revalidates every other standing scaffold, the card's other pairs
  included: a card on all 20 simplex bases (21 targets less Mallory; marshal has 13) costs up
  to 20 syntheses and 20 x (S - 1) revalidation builds with three replays each, S being the
  scaffolds that stand when each pair finishes. `--fuzz-targets`, or `<base>_tsNNNN` patterns
  to `synthesize`, bound it. Accepted: the scaffolds of one card on different bases are
  different fuzz targets, and which base reaches the state is what the pairs find out.
- Revalidation compares an earlier scaffold with the verdict its report records, read at the
  start of each synthesis, and `--redo` undoes a pair by its `TS-NNNN_<base>.diff` as it reads
  it; a report or diff an agent of an earlier synthesis rewrote is not detected.
  A change outside every pair's diff, such as a helper template edited between syntheses, is
  not replayed: only the last check's build sees it. An undo by `--redo` or by the last check,
  and a restore of a pair's edits after its revalidation rewrote reports, are revalidated the
  same way; one an interrupt stops, or that a restore leaves, is completed by the next
  synthesis, and until then the reports keep their earlier verdicts, or those the restored
  edits gave them. A synthesis killed after a pair's report is written and before its record is
  deleted revalidates once more, naming a rollback that did not happen. No pair is rolled back
  for an undo, and a scaffold it leaves unbuildable is recorded `NOT BUILT (no longer builds)`
  even when a later pair of the same run makes it build again, until a `--redo` of its pair.
- The guards check where edits are, what they leave of the instrumentation, and their markers,
  against the baseline the campaign's first synthesis took. Whether an edit preserves what the
  protocol does rests on the prompt, the test gate, which runs the engine-level tests only
  (D2), and review of `campaign/reach/TS-NNNN_<base>.diff`.
- Injections escape ghost history (section 8.7) and can raise false alarms; the module header
  lists them.
- A state internal to a Byzantine replica cannot be witnessed under the guard.
- A checkout instrumented before the read side existed, or cleaned, cannot synthesize; it
  needs a fresh clone and a campaign.
- A test that drives one actor through its mailbox, as TS-0002's does, becomes a History of the
  protocol events that deliver the same inputs (section 18.4), which a cluster may reach rarely,
  or only with a capability the harness lacks, reported as `cannot:`.
- `TRACE_CAP` can cut a long Shape A run short; a stage whose witness is read at or after the
  cut, and `En` when the cut comes at or before the handoff mark, is `unverifiable (trace
  truncated)` and adds no feature, and the handoff is lost. Positions keep advancing past the cut, so the order of what is kept stays exact.
- The helper checks when `En`'s witness was built, inside the handoff call, not where its
  values came from: a closure that builds it from values read before the call is not detected
  by the positions. The prompt forbids it, and review of the module is what catches it. The
  same holds for an `intrinsic` witness of `En` that cites an old observation, which a later
  observation at its site of the same replica contradicts: the reach lines carry no trace
  that would show it, so the prompt asks for an `exact` witness of `En` where one exists, or
  the latest observation, and review checks it.
- Likewise, the helper takes the positions of stamped entries and of actions itself, but
  whether a stamping wrapper sits on the path of the system under test and stamps an entry
  when it records it, and whether the `perform` a scaffold passes to `Witness::act` performs
  the action the witness names, is left to review of the module.
- The scope check of section 7.5 and guard 3 count a call of a runtime function only when the
  code reaches it through the runtime module, by path, alias (`as rt`, `{self as rt}`) or named
  import. A glob import of the module followed by a bare call escapes both; review of the
  instrumentation diff and of the pair's diff is what catches it.
- Guard 3 compares text. It stops the plain forms of a forged reach line, a panic hook, an
  included file and an ignored module, not every spelling: a write to a file opened at
  `/dev/stderr`, or a call of another crate's function that prints, escapes it. An edit that
  disables an assertion it leaves unchanged, with `if false`, a `cfg` or an early `return`,
  passes guard 3; the annotation `edit beside instrumentation` points review at such hunks
  when they touch the instrumented lines, and review of `campaign/reach/TS-NNNN_<base>.diff`
  is what catches the rest.
- `B`, its test inventory, the content the script last wrote to its own files, and the
  campaign's `instrumentation.diff` lie in `SL/campaign/`, which git ignores and a synthesis
  agent can write. A synthesis reads them once, before any agent runs, and holds them in
  memory, so no attempt can change what that run compares with, and after every run of the
  agent and when the synthesis ends the script writes back what changed there; only a
  synthesis killed before it ends leaves such an edit, in these files or in
  `SL/campaign/reach/pending/`, for the next synthesis to read.
- A synthesis killed outright (`SIGKILL`) cannot kill its agent, which runs in its own process
  group and may keep writing; the next synthesis restores `S0` (section 18.6.2, Once per run)
  and should start only after that agent has ended.
- A dangling symbolic link, or one to a directory, that an edit leaves in the scope is not
  listed and survives a restore; nothing compiles or reads it.
- An archived `run` or `replay` line names the scaffold, which after `--redo` holds the
  replacement version or none, so an archived failure replays only after its `version.diff`
  is applied.
- Guard 1 compares `SL/` with its state at the start of each synthesis, not with `B`, so a
  change an earlier synthesis made there is not detected.
- The helper's state is per thread, as the trace is: a panic on a thread other than the one
  that called `Stages::new` prints no stage lines, and neither does a scaffold error raised
  before `Stages::new`.
- Whether a marshal prefix leaves enough height below the epoch ceiling for the liveness
  measurement is not measured; review of the module checks it.
- The differential test of section 18.10.1 judges hand-written prefixes, never an agent's,
  and compares the settled state after `finish`, not the state at the handoff mark, so a
  prefix whose event is still in flight at its handoff is not told apart from one that
  waited. Its digest lists storage partitions by the names
  `setup_validator` and the marshal actor use, so a renamed partition drops out of the
  per-node listing silently while the `storage_audit` line still covers it, and it reads
  `RecordingResolver`'s injection fields directly, since an accessor would not be a
  visibility change.

---

## Appendix A: `runtime/statelens.rs` (verbatim)

~~~rust
//! StateLens runtime support for an instrumented campaign.
//!
//! This file is a template kept in `statelens/runtime/`. A campaign copies it into
//! the checkout it instruments as the `statelens` module of the subsystem it
//! instruments, and declares it with `pub mod statelens;`: as
//! `consensus/src/simplex/statelens.rs` for the simplex and marshal profiles, and as
//! `storage/src/qmdb/statelens.rs` for the qmdb profile, where its paths name `qmdb`
//! and the consensus-only tests at the end of the file are left out. It is never
//! compiled on a committed branch.
//!
//! It provides:
//! - the Byzantine guard: [set_compromised], [clear_compromised], [is_byzantine]
//!   and [should_check], and [provider_me] for a component that has a scheme
//!   provider but no scheme;
//! - a SanitizerCoverage counter table fed by state probes: [record] and [reset];
//! - the instrumentation macros `sl_probe!`, `sl_assert!` and `sl_implies!`,
//!   invoked as `crate::simplex::statelens::sl_probe!(...)`;
//! - ghost state: per replica ([Ghost], [with_ghost]) and shared by all honest
//!   replicas ([Global], [with_global]). It lives for one run: [reset] and every
//!   fresh deterministic runtime clear it, while a runtime resumed from a
//!   checkpoint (a crash-restart) keeps it;
//! - discretization helpers: [bucket], [delta], [flag], [pack] and [disc];
//! - the read side, for the target-state scaffolds only: while a scaffold
//!   [watch]es, an ordered trace of the probe observations of one input ([Seen],
//!   [seen], [sites], [observations], [truncated]), and one event sequence per
//!   input that orders those observations and the scaffold helper's events
//!   ([tick], [mark]). Instrumentation never calls it.
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

use commonware_cryptography::certificate::{ConstantProvider, Provider, Scheme as _};
pub use commonware_utils::Participant;
use std::{
    any::TypeId,
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
    static TRACE: RefCell<Trace> = const { RefCell::new(Trace::new()) };
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

/// Returns the replica index a component that holds a scheme provider can use as
/// `me`, without a lookup anyone can observe.
///
/// A provider lookup is not a read: an application may count lookups against the
/// scope it serves and retire it, so an extra one can turn a later lookup of the
/// implementation's into `None`. The only provider whose lookups are known to
/// change nothing is [ConstantProvider], which clones its scheme, and it is the one
/// every fuzz harness uses. For it, this returns `Some` of the scheme's index
/// (`Some(None)` for a scheme that is not a participant). For any other provider it
/// makes no lookup and returns `None`, and so it does when the provider has no
/// signing scheme for `scope`: the index is unknown, and the caller must leave its
/// sites uninstrumented rather than pass `None` as `me`, which would turn the
/// Byzantine guard off. `scope` is not used for a [ConstantProvider], so any one in
/// hand will do.
pub fn provider_me<P: Provider>(provider: &P, scope: P::Scope) -> Option<Option<Participant>> {
    if TypeId::of::<P>() != TypeId::of::<ConstantProvider<P::Scheme, P::Scope>>() {
        return None;
    }
    provider.scheme(scope).map(|scheme| scheme.me())
}

/// Raw pointer to the counter bytes.
fn table() -> *mut u8 {
    // `Counters<N>` is `#[repr(transparent)]` over `UnsafeCell<[u8; N]>`.
    (&TABLE as *const sancov::Counters<COUNTERS>)
        .cast::<u8>()
        .cast_mut()
}

/// Prepares a fuzz input: zeroes the counter table, forgets the compromised set,
/// clears the ghost state, and drops the probe trace, so the event sequence and
/// the run counter start again at 0. In a fuzzing build it also registers the
/// table with libFuzzer on first use, unless `STATELENS_FEEDBACK=0`.
///
/// Called by the StateLens fuzz target before every input.
pub fn reset() {
    #[cfg(fuzzing)]
    {
        static REGISTERED: OnceLock<()> = OnceLock::new();
        REGISTERED.get_or_init(|| {
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
    clear_trace();
}

/// Forgets all ghost state.
fn forget_ghosts() {
    GHOSTS.with(|ghosts| ghosts.borrow_mut().clear());
    GLOBAL.with(|global| *global.borrow_mut() = Global::default());
}

/// Starts an independent run: forgets all ghost state, then counts the runtime
/// instance of the input.
///
/// Registered as the deterministic runtime's fresh-run hook, so history from an
/// earlier, independent run on this thread (for example another seed of the same
/// test) does not leak into the next run. A runtime resumed from a checkpoint (a
/// crash-restart) keeps the history and the run number.
fn fresh_run() {
    forget_ghosts();
    TRACE.with(|trace| {
        let mut trace = trace.borrow_mut();
        trace.run = trace.run.saturating_add(1);
    });
}

/// Registers [fresh_run] with the deterministic runtime; only the first call of the
/// process sets it.
fn register_fresh_run_hook() {
    let _ = commonware_runtime::deterministic::STATELENS_FRESH_RUN.set(fresh_run);
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

/// Most observations the trace of one input keeps.
pub const TRACE_CAP: usize = 1 << 20;

/// One probe observation of a watched input. Its fields are private, so only the
/// runtime makes or changes one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Seen {
    label: &'static str,
    site: &'static str,
    me: Option<u32>,
    a: u32,
    b: u32,
    seq: u64,
    run: u32,
}

impl Seen {
    /// The `sl_probe!` label, or the invariant ID of an `sl_implies!` site.
    pub const fn label(self) -> &'static str {
        self.label
    }

    /// The call site, `concat!(file!(), ":", line!(), ":", column!())`.
    pub const fn site(self) -> &'static str {
        self.site
    }

    /// The participant index of the observing replica.
    pub const fn me(self) -> Option<u32> {
        self.me
    }

    /// The first recorded value; `pre` at an `sl_implies!` site.
    pub const fn a(self) -> u32 {
        self.a
    }

    /// The second recorded value; `pre && post` at an `sl_implies!` site.
    pub const fn b(self) -> u32 {
        self.b
    }

    /// The position of the observation in the event sequence of the input, from 1.
    pub const fn seq(self) -> u64 {
        self.seq
    }

    /// The runtime instance of the input that made it, from 1.
    pub const fn run(self) -> u32 {
        self.run
    }
}

/// The read side's state on this thread: the trace of one input, its event
/// sequence and its run counter.
struct Trace {
    /// Whether a scaffold watches, so observations are kept and the sequence advances.
    watching: bool,
    /// The position of the first observation dropped because the trace held
    /// [TRACE_CAP], if any.
    truncated: Option<u64>,
    /// The last position issued in the input.
    seq: u64,
    /// The runtime instance current on this thread, counted by [fresh_run].
    run: u32,
    /// The observations, in order of their positions.
    seen: Vec<Seen>,
}

impl Trace {
    const fn new() -> Self {
        Self {
            watching: false,
            truncated: None,
            seq: 0,
            run: 0,
            seen: Vec::new(),
        }
    }
}

/// Drops the trace, sets the run counter and the event sequence to 0, and
/// registers the fresh-run hook, so the first runtime of the input has run 1.
///
/// [reset] calls it. Self-tests call it instead of [reset], because it touches
/// only the thread-local trace, run counter and sequence.
fn clear_trace() {
    register_fresh_run_hook();
    TRACE.with(|trace| *trace.borrow_mut() = Trace::new());
}

/// Starts an empty trace for this input. The event sequence goes on from its
/// current value.
pub fn watch() {
    TRACE.with(|trace| {
        let mut trace = trace.borrow_mut();
        trace.watching = true;
        trace.truncated = None;
        trace.seen = Vec::new();
    });
}

/// Stops keeping observations and drops the trace.
pub fn unwatch() {
    TRACE.with(|trace| {
        let mut trace = trace.borrow_mut();
        trace.watching = false;
        trace.truncated = None;
        trace.seen = Vec::new();
    });
}

/// Advances the event sequence and returns its new value, which is greater than
/// every position issued earlier in the input. While not watching it returns 0
/// and advances nothing.
///
/// Only the scaffold helper calls it.
pub fn tick() -> u64 {
    TRACE.with(|trace| {
        let mut trace = trace.borrow_mut();
        if !trace.watching {
            return 0;
        }
        trace.seq = trace.seq.saturating_add(1);
        trace.seq
    })
}

/// The last position issued in the input, to an observation or by a [tick],
/// without advancing the sequence; 0 before the first.
pub fn mark() -> u64 {
    TRACE.with(|trace| trace.borrow().seq)
}

/// The runtime instance current on this thread, from 1; 0 before the first
/// runtime of the input.
pub fn current_run() -> u32 {
    TRACE.with(|trace| trace.borrow().run)
}

/// The position of the first observation the trace dropped because it held
/// [TRACE_CAP], or `None` while it has dropped none. A dropped observation still
/// advances the sequence, so what the trace holds from that position on is
/// incomplete.
pub fn truncated() -> Option<u64> {
    TRACE.with(|trace| trace.borrow().truncated)
}

/// The earliest observation at or after position `since`, of the run current at
/// the call, with `label`, at `site` when one is given, that `f` accepts. `None`
/// while not watching.
///
/// Find a site with [sites], never as a literal: edits move lines.
pub fn seen(
    label: &str,
    site: Option<&str>,
    since: u64,
    mut f: impl FnMut(&Seen) -> bool,
) -> Option<Seen> {
    let (mut index, run) = TRACE.with(|trace| {
        let trace = trace.borrow();
        trace.watching.then(|| {
            (
                trace.seen.partition_point(|seen| seen.seq < since),
                trace.run,
            )
        })
    })?;
    loop {
        // `f` runs outside the borrow, so it may read the trace itself.
        let candidate = TRACE.with(|trace| {
            let trace = trace.borrow();
            let rest = trace.seen.get(index..)?;
            let offset = rest.iter().position(|seen| {
                seen.run == run && seen.label == label && site.is_none_or(|site| site == seen.site)
            })?;
            Some((rest[offset], index + offset + 1))
        });
        let (candidate, next) = candidate?;
        if f(&candidate) {
            return Some(candidate);
        }
        index = next;
    }
}

/// The sites at which the trace holds `label`, in order of their first observation.
pub fn sites(label: &str) -> Vec<&'static str> {
    TRACE.with(|trace| {
        let mut sites = Vec::new();
        for seen in trace
            .borrow()
            .seen
            .iter()
            .filter(|seen| seen.label == label)
        {
            if !sites.contains(&seen.site) {
                sites.push(seen.site);
            }
        }
        sites
    })
}

/// Every observation at or after position `since`, of every run, oldest first.
pub fn observations(since: u64) -> Vec<Seen> {
    TRACE.with(|trace| {
        let trace = trace.borrow();
        let start = trace.seen.partition_point(|seen| seen.seq < since);
        trace.seen[start..].to_vec()
    })
}

/// While watching, advances the event sequence and appends an observation with
/// the new value as its position, unless the trace holds [TRACE_CAP]
/// observations, in which case [truncated] keeps the position of the first one it
/// dropped. Only the macros call it, inside the guard, after [record].
#[doc(hidden)]
pub fn note(me: Option<Participant>, label: &'static str, site: &'static str, a: u32, b: u32) {
    TRACE.with(|trace| {
        let mut trace = trace.borrow_mut();
        if !trace.watching {
            return;
        }
        trace.seq = trace.seq.saturating_add(1);
        if trace.seen.len() >= TRACE_CAP {
            if trace.truncated.is_none() {
                trace.truncated = Some(trace.seq);
            }
            return;
        }
        let seen = Seen {
            label,
            site,
            me: me.map(|me| me.get()),
            a,
            b,
            seq: trace.seq,
            run: trace.run,
        };
        trace.seen.push(seen);
    });
}

/// Records a state probe for replica `me`: `sl_probe!(me, "label", a, b)`.
///
/// `a` and `b` must convert into `u32` with `Into` (`bool`, `u8`, `u16`, `u32`),
/// so raw `u64` views or counts must go through [bucket] or [delta] first. The
/// site is `label` plus the call location, so every call site is distinct. While
/// a scaffold watches, the observation is also appended to the trace.
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
            $crate::simplex::statelens::note(
                me,
                $label,
                ::core::concat!(
                    ::core::file!(),
                    ":",
                    ::core::line!(),
                    ":",
                    ::core::column!()
                ),
                a,
                b,
            );
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
/// `post` is evaluated only when `pre` holds. While a scaffold watches, the
/// observation is also appended to the trace, before a violation panics.
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
            $crate::simplex::statelens::note(
                me,
                $id,
                ::core::concat!(
                    ::core::file!(),
                    ":",
                    ::core::line!(),
                    ":",
                    ::core::column!()
                ),
                u32::from(pre),
                u32::from(post),
            );
            if pre && !post {
                $crate::simplex::statelens::violation(me, $id, ::core::format_args!($($arg)+));
            }
        }
    }};
}

// The subsystem module is declared inside a macro (`stability_scope!`), so
// `#[macro_export]` macros could not be called by path from this crate. Instrumented
// code calls `crate::simplex::statelens::sl_probe!(...)` through these re-exports instead.
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
            "skipped by the guard"
        );
        crate::simplex::statelens::sl_implies!(
            Some(Participant::new(1)),
            "INV-TEST",
            true,
            false,
            "skipped by the guard"
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

    // The read-side tests call `clear_trace`, never `reset`, which zeroes the
    // counter table the other tests share under plain `cargo test`.

    #[test]
    fn test_read_side_is_off_unless_watched() {
        clear_trace();
        crate::simplex::statelens::sl_probe!(None, "unwatched", true, 1u8);
        assert_eq!(tick(), 0, "no position while not watching");
        assert_eq!(mark(), 0);
        assert!(observations(0).is_empty());
        assert_eq!(seen("unwatched", None, 0, |_| true), None);
        watch();
        crate::simplex::statelens::sl_probe!(None, "watched", true, 2u8);
        let trace = observations(0);
        assert_eq!(trace.len(), 1);
        let only = trace[0];
        assert_eq!(
            (only.label(), only.me(), only.a(), only.b()),
            ("watched", None, 1, 2)
        );
        assert_eq!((only.seq(), only.run()), (1, 0));
        let site: Vec<&str> = only.site().rsplitn(3, ':').collect();
        assert_eq!(site.len(), 3, "the site is file:line:column");
        assert_eq!(site[2], file!());
        assert!(site[0].parse::<u32>().is_ok() && site[1].parse::<u32>().is_ok());
        unwatch();
        assert!(observations(0).is_empty());
        assert_eq!(tick(), 0);
        crate::simplex::statelens::sl_probe!(None, "watched", true, 2u8);
        assert_eq!(mark(), 1, "unwatch keeps the sequence");
        watch();
        assert!(observations(0).is_empty(), "watch starts an empty trace");
        assert_eq!(tick(), 2, "the sequence goes on from its current value");
        clear_trace();
    }

    #[test]
    fn test_ticks_and_observations_share_one_sequence() {
        clear_trace();
        watch();
        let first = tick();
        let second = tick();
        assert_eq!(
            (first, second),
            (1, 2),
            "two ticks get distinct, ordered positions"
        );
        crate::simplex::statelens::sl_probe!(Some(Participant::new(0)), "shared", true, 0u8);
        let third = tick();
        crate::simplex::statelens::sl_probe!(None, "shared", false, 0u8);
        let positions: Vec<u64> = observations(0).iter().map(|seen| seen.seq()).collect();
        assert_eq!(positions, vec![3, 5]);
        assert_eq!(third, 4);
        assert_eq!(mark(), 5, "mark is the last position");
        assert_eq!(mark(), 5, "mark does not advance");
        assert_eq!(observations(5).len(), 1);
        assert_eq!(tick(), 6);
        clear_trace();
        assert_eq!(mark(), 0, "clear_trace starts the sequence again");
        assert_eq!(tick(), 0, "and stops watching");
        watch();
        assert_eq!(tick(), 1, "positions are unique within one input only");
        clear_trace();
    }

    #[test]
    fn test_seen_finds_the_earliest_match() {
        clear_trace();
        clear_compromised();
        watch();
        for value in 0u8..3 {
            crate::simplex::statelens::sl_probe!(Some(Participant::new(1)), "earliest", value, 0u8);
        }
        crate::simplex::statelens::sl_probe!(Some(Participant::new(2)), "earliest", 1u8, 0u8);
        crate::simplex::statelens::sl_probe!(None, "other", 1u8, 0u8);
        let found = sites("earliest");
        assert_eq!(found.len(), 2, "one site per call");
        assert_eq!(sites("other").len(), 1);
        assert!(sites("absent").is_empty());
        let first = seen("earliest", None, 0, |_| true).expect("first");
        assert_eq!((first.seq(), first.a(), first.site()), (1, 0, found[0]));
        let later = seen("earliest", None, 2, |_| true).expect("at or after");
        assert_eq!((later.seq(), later.a()), (2, 1));
        let accepted = seen("earliest", None, 0, |seen| seen.a() == 1).expect("accepted");
        assert_eq!(accepted.seq(), 2);
        let at_site = seen("earliest", Some(found[1]), 0, |seen| seen.a() == 1).expect("site");
        assert_eq!((at_site.seq(), at_site.me()), (4, Some(2)));
        assert_eq!(seen("earliest", Some(found[0]), 4, |_| true), None);
        assert_eq!(seen("earliest", None, 0, |seen| seen.a() == 7), None);
        assert_eq!(seen("absent", None, 0, |_| true), None);
        clear_trace();
    }

    #[test]
    fn test_guarded_replicas_are_not_observed() {
        clear_trace();
        set_compromised([1]);
        watch();
        crate::simplex::statelens::sl_probe!(Some(Participant::new(1)), "guarded", true, 0u8);
        crate::simplex::statelens::sl_implies!(
            Some(Participant::new(1)),
            "INV-TEST",
            true,
            false,
            "skipped by the guard"
        );
        crate::simplex::statelens::sl_probe!(Some(Participant::new(0)), "guarded", true, 0u8);
        let trace = observations(0);
        assert_eq!(trace.len(), 1);
        assert_eq!(
            (trace[0].me(), trace[0].seq()),
            (Some(0), 1),
            "a skipped hit takes no position"
        );
        clear_compromised();
        clear_trace();
    }

    #[test]
    fn test_implies_notes_its_pair() {
        clear_trace();
        watch();
        crate::simplex::statelens::sl_implies!(None, "INV-PAIR", false, evaluated(), "never");
        crate::simplex::statelens::sl_implies!(None, "INV-PAIR", true, true, "holds");
        let violated = std::panic::catch_unwind(|| {
            crate::simplex::statelens::sl_implies!(None, "INV-PAIR", true, false, "broken");
        });
        assert!(violated.is_err());
        let pairs: Vec<(u32, u32)> = observations(0)
            .iter()
            .filter(|seen| seen.label() == "INV-PAIR")
            .map(|seen| (seen.a(), seen.b()))
            .collect();
        assert_eq!(
            pairs,
            vec![(0, 0), (1, 1), (1, 0)],
            "the violation is in the trace"
        );
        clear_trace();
    }

    #[test]
    fn test_trace_cap() {
        clear_trace();
        watch();
        for _ in 0..TRACE_CAP {
            note(None, "cap", "cap.rs:1:1", 0, 0);
        }
        assert_eq!(truncated(), None);
        note(None, "cap", "cap.rs:1:1", 1, 0);
        let first = TRACE_CAP as u64 + 1;
        assert_eq!(
            truncated(),
            Some(first),
            "an observation past the cap is dropped, and its position kept"
        );
        assert_eq!(TRACE.with(|trace| trace.borrow().seen.len()), TRACE_CAP);
        assert_eq!(mark(), first, "a dropped observation takes a position");
        assert_eq!(tick(), first + 1);
        note(None, "cap", "cap.rs:1:1", 2, 0);
        assert_eq!(truncated(), Some(first), "the first dropped position stays");
        assert_eq!(mark(), first + 2);
        assert_eq!(seen("cap", None, 0, |seen| seen.a() != 0), None);
        unwatch();
        assert_eq!(truncated(), None, "unwatch forgets the cut");
        watch();
        assert_eq!(truncated(), None, "watch starts an uncut trace");
        clear_trace();
        assert_eq!(truncated(), None);
    }

    #[test]
    fn test_fresh_runtime_counts_runs() {
        clear_trace();
        clear_compromised();
        assert_eq!(current_run(), 0);
        watch();
        crate::simplex::statelens::sl_probe!(None, "runs", true, 0u8);
        let _first = commonware_runtime::deterministic::Runner::seeded(0);
        assert_eq!(current_run(), 1, "the first runtime of an input has run 1");
        crate::simplex::statelens::sl_probe!(None, "runs", true, 1u8);
        let _second = commonware_runtime::deterministic::Runner::seeded(1);
        crate::simplex::statelens::sl_probe!(None, "runs", true, 2u8);
        let runs: Vec<(u32, u32)> = observations(0)
            .iter()
            .map(|seen| (seen.run(), seen.b()))
            .collect();
        assert_eq!(runs, vec![(0, 0), (1, 1), (2, 2)], "the trace spans runs");
        let current = seen("runs", None, 0, |_| true).expect("current run");
        assert_eq!(
            (current.run(), current.b()),
            (2, 2),
            "seen reads the current run"
        );
        clear_trace();
        assert_eq!(current_run(), 0);
        let _third = commonware_runtime::deterministic::Runner::seeded(2);
        assert_eq!(current_run(), 1);
        clear_trace();
    }
}

// [statelens] consensus only: these tests build Simplex signing schemes, so a campaign
// that puts this module in another crate leaves out everything from this line on.
#[cfg(test)]
mod provider_tests {
    use super::*;

    /// A provider that counts its lookups, as an application that retires a scope
    /// after a number of them would.
    #[derive(Clone)]
    struct CountingProvider {
        scheme: std::sync::Arc<crate::simplex::scheme::ed25519::Scheme>,
        lookups: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Provider for CountingProvider {
        type Scope = ();
        type Scheme = crate::simplex::scheme::ed25519::Scheme;

        fn scoped(
            &self,
            _: (),
        ) -> Option<commonware_cryptography::certificate::Scoped<Self::Scheme>> {
            self.lookups.fetch_add(1, Ordering::Relaxed);
            Some(commonware_cryptography::certificate::Scoped::scheme(
                self.scheme.clone(),
            ))
        }
    }

    #[test]
    fn test_provider_me_reads_a_constant_provider() {
        let commonware_cryptography::certificate::mocks::Fixture {
            schemes, verifier, ..
        } = crate::simplex::scheme::ed25519::fixture(
            &mut commonware_utils::test_rng(),
            b"statelens",
            4,
        );
        let expected = schemes[2].me();
        assert!(expected.is_some());
        let provider = ConstantProvider::<_, ()>::new(schemes[2].clone());
        assert_eq!(provider_me(&provider, ()), Some(expected));
        // A scheme that is not a participant is known to be one: `Some(None)`.
        let provider = ConstantProvider::<_, ()>::new(verifier);
        assert_eq!(provider_me(&provider, ()), Some(None));
    }

    #[test]
    fn test_provider_me_leaves_any_other_provider_alone() {
        let commonware_cryptography::certificate::mocks::Fixture { schemes, .. } =
            crate::simplex::scheme::ed25519::fixture(
                &mut commonware_utils::test_rng(),
                b"statelens",
                4,
            );
        let provider = CountingProvider {
            scheme: std::sync::Arc::new(schemes[0].clone()),
            lookups: Default::default(),
        };
        assert_eq!(provider_me(&provider, ()), None, "the index is unknown");
        assert_eq!(
            provider.lookups.load(Ordering::Relaxed),
            0,
            "an unknown provider must not be looked up"
        );
    }
}
~~~

---

## Appendix B: fuzz target and runner hook

### B.1 Deriving a variant

A StateLens fuzz target is not written; it is derived from an existing target of the
profile's package, so that no hand-written copy has to be kept in step with the target it
imitates. `<stem>_statelens.rs` is `<stem>.rs` with two lines inserted into the body of its
`fuzz_target!`, which call the runtime module of the profile's crate (section 5.5):

~~~rust
    fuzz_target!(|input: FuzzInput| {
        commonware_consensus::simplex::statelens::reset();
        // ... the target's own body, unchanged ...
        commonware_consensus::simplex::statelens::clear_compromised();
    });
~~~

The opening line is the only one matching `^( *)fuzz_target!\(\|[a-z_]+: [^|]+\| \{$`, at
any indent and with any parameter (`input: FuzzInput`, `data: &[u8]`); the body ends at the
first line after it that is `});` at the same indent. The first line is inserted after the
opening line and the second before the closing one, both indented one level deeper. A
one-line target, `fuzz_target!(|input: FuzzInput| fuzz(input));`, is first written as a
block whose body is the expression as a statement, which is what the closure returns anyway.
A file with no such target, or with two, aborts the campaign with exit code 2. A qmdb
variant calls `commonware_storage::qmdb::statelens`; nothing compromises a database, so its
`clear_compromised()` is a no-op kept for uniformity. Paths are written in full so that the
variant needs no `use` the original does not have. Which targets a profile derives from is
section 5.5. A consensus target must use the `cert_mock` certificate scheme, the only scheme
a StateLens fuzz target may use (D15), which is checked as the first type argument of its
call of a fuzz entry point, `fuzz::<...>` or `fuzz_<name>::<...>`.

The one exception is a scaffold of Target-State Synthesis (D63): an agent writes its thin
target, whose shape B.6 gives and the script checks (section 18.6).

### B.2 The variant's `[[bin]]` block

The block appended to the package manifest is the original target's own block with `name` and
`path` renamed to the variant, so `required-features` and every other key are inherited
rather than assumed:

~~~toml

[[bin]]
name = "<stem>_statelens"
path = "fuzz_targets/<stem>_statelens.rs"
test = false
doc = false
bench = false
required-features = ["twins"]
~~~

`required-features` above is the value for a `twins` target; `simplex_cert_mock` carries
`["base"]` instead, and a hardcoded block would have been wrong for it.

A scaffold's block is its base target's block renamed the same way, with `name` and `path`
naming `<base>_tsNNNN_statelens`, and the script writes it (section 18.6).

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
actor code. In `TwinsCampaign` both halves are real engines, and the guard skips both.

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

### B.5 Hooks in the other simplex runners (verbatim)

Four simplex runners besides Twins run a real engine under a Byzantine identity, so the
`simplex` profile patches each to publish it before that engine starts, with the index check
of B.3 (D57). Without its hook, Chaos-Twins would also merge the histories of the twin's two
engines, which share one participant index and so one `Ghost`, and Mallory's restarted node
would be checked against the history of the incarnation it forgot.

Edit 9, ByzzFuzz, inserted after its anchor in `setup_engines`, where `schemes` is in scope:

~~~rust
    // [statelens] ByzzFuzz runs a real engine at `BYZANTINE_IDX` and rewrites what it
    // sends: publish it as compromised before any engine starts, and check that every
    // scheme's own index matches its position in `participants`.
    commonware_consensus::simplex::statelens::set_compromised([BYZANTINE_IDX]);
    for (idx, scheme) in schemes.iter().enumerate() {
        assert_eq!(
            commonware_cryptography::certificate::Scheme::me(scheme),
            Some(commonware_utils::Participant::from_usize(idx)),
            "[statelens] participant index mismatch"
        );
    }
~~~

Edit 10, Chaos-Twins, inserted after the twin's index `byz` is chosen and before the twin's
two engines start:

~~~rust
        // [statelens] The twin runs two real engines under `byz`: publish it as
        // compromised before any engine starts, and check that every scheme's own
        // index matches its position in `participants`.
        commonware_consensus::simplex::statelens::set_compromised([byz]);
        for (idx, scheme) in schemes.iter().enumerate() {
            assert_eq!(
                commonware_cryptography::certificate::Scheme::me(scheme),
                Some(commonware_utils::Participant::from_usize(idx)),
                "[statelens] participant index mismatch"
            );
        }
~~~

Edit 11, the audited Standard runner, inserted at the top of the branch where an input that
drew the RejectView choice gives a Byzantine participant a real engine. Otherwise the
Byzantine participants are `Disrupter`s and the hook does not run:

~~~rust
                // [statelens] Here a Byzantine participant runs a real engine: publish
                // the Byzantine participants as compromised before it starts, and check
                // that every scheme's own index matches its position in `participants`.
                commonware_consensus::simplex::statelens::set_compromised(0..config.faults as usize);
                for (idx, scheme) in schemes.iter().enumerate() {
                    assert_eq!(
                        commonware_cryptography::certificate::Scheme::me(scheme),
                        Some(commonware_utils::Participant::from_usize(idx)),
                        "[statelens] participant index mismatch"
                    );
                }
~~~

Edit 12, Mallory, inserted in `restart` after the old incarnation's tasks are aborted and
before the new one starts. Only an amnesia restart, which rebuilds the node on empty
storage, makes it Byzantine; a durable restart replays its journal and stays honest:

~~~rust
    // [statelens] An amnesia restart brings this node back on empty storage, where it
    // may sign what it signed before, and Mallory counts it as Byzantine from here on:
    // publish it as compromised before the new incarnation starts, and check that its
    // scheme's own index is its position in `participants`.
    if amnesia {
        commonware_consensus::simplex::statelens::set_compromised([mv.idx()]);
        assert_eq!(
            commonware_cryptography::certificate::Scheme::me(mv.scheme()),
            Some(commonware_utils::Participant::from_usize(mv.idx())),
            "[statelens] participant index mismatch"
        );
    }
~~~

A variant clears the compromised set after its driver returns, as every variant does (D7).

### B.6 A scaffold's thin target

The agent writes `<package>/fuzz_targets/<base>_tsNNNN_statelens.rs` (section 18.7). It is
its base's file with two changes: the body of its `fuzz_target!` is exactly three
statements, `reset();`, the call of the module's `fuzz` with the base entry's generic
arguments, and `clear_compromised();`, with the runtime's path written in full; and the `use`
lines name the module instead of the base's entry. The closure parameter is the base's, so
the input type is too. For a scaffold of TS-0003 on `simplex_cert_mock_chaos`, the pair whose
module is `ts0003_simplex_cert_mock_chaos`:

~~~rust
#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_consensus_fuzz_simplex::{
        Chaos, CodeCoverage, FuzzInput, SimplexCertificateMock,
        target_states::ts0003_simplex_cert_mock_chaos,
    };
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: FuzzInput| {
        commonware_consensus::simplex::statelens::reset();
        ts0003_simplex_cert_mock_chaos::fuzz::<SimplexCertificateMock, Chaos, CodeCoverage>(input);
        commonware_consensus::simplex::statelens::clear_compromised();
    });
}
~~~

The script checks that the pair's thin target exists and that no new `*_ts0003_statelens.rs`
of another base appeared, since a sibling pair's thin target is written by that pair, that its
one `fuzz_target!` matches the opening line of B.1 with the base's closure parameter, and that
the body is these three statements, the module's name being the pair's; after every attempt it
checks that body in every scaffold's thin target, because guard 3 exempts only thin targets of
this shape (section 18.6.2 step 2.4). The cryptography check
of D15 then reads `fuzz::<SimplexCertificateMock` as it does in a variant.

---

## Appendix C: `false-invariants/simplex/FALSE-0001.md` (verbatim)

~~~markdown
---
id: FALSE-0001
title: Deliberately false, never accept a nullification
source_kind: human
source_ref: statelens/docs/SPEC.md (acceptance procedure AC-6)
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

1. What StateLens is, in three sentences: the three subsystems it covers and its three
   phases, with links to PRD.md and SPEC.md.
2. How to run a campaign safely: campaigns give the agent full control of the machine
   (D4) and instrument the checkout in place (D10). Clone the repository fresh on a
   dedicated machine or container, run the campaign and the fuzzers in that clone, and
   discard the clone afterwards. Never commit an instrumented checkout.
3. Prerequisites (section 5.2) and `config.env`, including `STATELENS_AUDIT` and the
   model and effort of the agent CLI, which are the CLI's own defaults unless pinned;
   rust-analyzer for the code index, and that its `ERROR` lines in
   `extract/code-index.log` are expected (section 5.7).
4. Phase 1: `just extract-invariants [--registry simplex|marshal|qmdb] <kind> <source>...`
   with one example per kind, then review: every file in a registry is used by the next
   campaign that binds it; edit or delete drafts; `just check-invariants`.
5. The knowledge base: what `STATELENS_KB` points at, that a campaign's beacon step queries
   it while instrumenting, and the `kb` commands an operator can run by hand.
6. Phase 2: `just campaign`, `just campaign --profile marshal`,
   `just campaign --profile
   qmdb`, `just campaign --agent codex`, `--stop-after`, and `--invariants LIST` to bind
   only the invariants it names, with the two id forms and what the selection leaves
   unchanged. What
   the steps do, including the audit pass over the bindings and the plan lint. A campaign
   builds the StateLens targets and does not fuzz; `just fuzz
   <target>` is the
   convenience that runs a campaign and then fuzzes one of its targets, and `just clean`
   undoes what a campaign wrote so a checkout can be reused.
7. Phase 3: run the printed `run` commands, or `just fuzz <profile>`, adding libFuzzer
   arguments such as `-fork=8` after `--` (section 7.10), and that an unknown flag with two
   dashes before `--` is refused; which marshal variants have an adversary that runs Simplex
   or marshal code, and that qmdb has none.
8. Target-State Synthesis (chapter 18), for simplex and marshal: `just extract-states
   [--registry simplex|marshal] [--local] <kind> <source>...` with an example for `test`,
   `issue` and `text`, then review the cards; that cards from sources that are not public go to
   the ignored `target-states.local/`, and that `target-states.local/` and `invariants.local/`
   must be copied into the fresh clone a campaign runs in; `just synthesize` after a campaign,
   or `just fuzz <profile> --state-reaching [--state-targets GLOB] [--fuzz-targets GLOB]`
   for campaign, synthesis and fuzzing in one go; the reports in `campaign/reach/` and what
   each verdict means; that every scaffold that builds is fuzzed whatever its verdict, and a
   CRASH (finding candidate) is triaged like any crash, rerunning the card with `--redo` when
   triage shows a scaffold fault; that synthesis edits the checkout under the edit contract
   and `campaign/reach/TS-NNNN_<base>.diff` is what to review; replaying a scaffold's crash with
   `STATELENS_REACH=1`.
9. Coverage: `just coverage <profile|target...>` after a run, scaffolds included, what it
   writes under the fuzz package's `coverage/html/`, and that the fuzz toolchain needs
   `llvm-tools-preview` (section 7.13).
10. Results: the summary lines, exit codes, and `campaign/` (plan, diff, logs, prompts), and
   what a plan section's `Status` and `Sites` ledger claim, which `just check-plan` rechecks.
11. Investigating a panic (section 7.12).
12. Testing the workflow itself: `STATELENS_FALSE_INVARIANTS=1` (the campaign must panic on
   the deliberately false invariants), `STATELENS_BYZANTINE=panic` (guard test),
   `STATELENS_FEEDBACK=0` (feedback comparison) and `STATELENS_AUDIT=0` (skip the audit
   pass); and the differential test of the TSS primitives against the marshal scenario
   prefixes, `scripts/differential.sh` (section 18.10.1): what it compares, that it builds
   only in a scratch worktree, what it establishes and what it does not.

---

## Appendix E: `false-invariants/marshal/FALSE-0002.md` (verbatim)

~~~markdown
---
id: FALSE-0002
title: Deliberately false, never deliver a block above height 1
source_kind: human
source_ref: statelens/docs/SPEC.md (acceptance procedure AC-10)
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

---

## Appendix G: `false-invariants/qmdb/FALSE-0003.md` (verbatim)

~~~markdown
---
id: FALSE-0003
title: Deliberately false, never grow the log past 64 operations
source_kind: human
source_ref: statelens/docs/SPEC.md (acceptance procedure AC-19)
scope: [database]
---

## Statement
The database shall not hold more than 64 operations in its log, counting the operations
it has pruned.

## Rationale
Deliberately false. Every commit appends to the log, and the qmdb tests and fuzz targets
write far more than 64 operations, so almost any of them violates it. A qmdb campaign that
includes this invariant must panic with [statelens][FALSE-0003], which shows that qmdb
invariants are bound, checked and reported.

## Evidence
Workflow test, see SPEC.md section 17.5.
~~~

---

## Appendix H: `runtime/target_states.rs` (verbatim)

The scaffold helper template of section 18.7.

~~~rust
//! Target-State Synthesis helper for the scaffolds of one fuzz package.
//!
//! This file is a template kept in `statelens/runtime/`. A synthesis copies it to
//! `<package>/src/target_states/mod.rs`, followed by one `pub mod tsNNNN_<base>;` line per
//! scaffold module, in a checkout a campaign instrumented. It is never compiled on a
//! committed branch.
//!
//! A scaffold splits and picks its knobs ([Knobs]), opens its stages
//! ([Stages::new]) and checks its budget ([Stages::budget]) before any engine
//! starts. It records each stage `E1` to `E(n-1)` through a [Witness]
//! ([Stages::held]) or another outcome, and the last one, `En`, through
//! [Stages::handoff], which decides the handoff. The helper takes every position
//! of the event sequence itself: a witness read, an entry a recording wrapper
//! stamps ([stamp]), an action ([Witness::act]), a restart boundary ([restart]),
//! and the start and the mark of the handoff. It prints the lines the reach check
//! parses, adds the feature of every held stage, and raises the only errors
//! attributed to a scaffold, all before any engine starts.
//!
//! Once the trace drops an observation at its cap, what it holds from that position
//! on is incomplete, so the helper prints a `truncated` line with the position, at
//! its first event after the cut, and neither a stage read at or after the cut nor
//! a handoff whose mark follows it holds.
//!
//! Environment switches, each read once per process:
//! - `STATELENS_REACH=1` prints the `[statelens-reach]` lines on stderr.
//! - `STATELENS_REACH_CONTROL=1` makes [control] true: the control run.

// A scaffold module is a child of this one, and a child module can use every
// private item of its parent. The helper's code is therefore in a private module of
// its own, `imp`, whose private items no scaffold can reach, and this one
// re-exports its API.
pub use imp::{Knobs, Stages, Stamp, Witness, control, restart, stamp};

mod imp {
    use commonware_consensus::simplex::statelens::{self, Seen};
    use std::{cell::RefCell, fmt, future::Future, io::Write as _, sync::OnceLock, time::Duration};

    /// Most knobs a scaffold splits.
    const MAX_KNOBS: usize = 16;

    /// Most `trace` lines a miss prints.
    const TRACE_LINES: usize = 64;

    /// The reason of a stage read after the trace dropped an observation.
    const TRUNCATED: &str = "(trace truncated)";

    thread_local! {
        static STATE: RefCell<State> = const { RefCell::new(State::new()) };
    }

    /// Whether `STATELENS_REACH=1`: the lines print only then.
    fn reach() -> bool {
        static REACH: OnceLock<bool> = OnceLock::new();
        *REACH.get_or_init(|| std::env::var("STATELENS_REACH").is_ok_and(|value| value == "1"))
    }

    /// Whether `STATELENS_REACH_CONTROL=1`, read once: the control run, in which the
    /// scaffold withholds the event its header names and a miss does not close the
    /// prefix.
    pub fn control() -> bool {
        static CONTROL: OnceLock<bool> = OnceLock::new();
        *CONTROL.get_or_init(|| {
            std::env::var("STATELENS_REACH_CONTROL").is_ok_and(|value| value == "1")
        })
    }

    /// Prints one line of card `card`, under `STATELENS_REACH=1`.
    fn emit(card: &str, line: &str) {
        if card.is_empty() {
            return;
        }
        #[cfg(test)]
        tests::LINES.with(|lines| lines.borrow_mut().push(line.to_string()));
        if reach() {
            let text = format!("[statelens-reach] {card} {line}\n");
            let _ = std::io::stderr().write_all(text.as_bytes());
        }
    }

    /// Adds the feature of stage `k` of card `card`, which held.
    fn feature(card: &str, k: u32) {
        #[cfg(test)]
        tests::FEATURES.with(|features| features.borrow_mut().push(k));
        statelens::record(statelens::site_hash(card), k, 0);
    }

    /// Takes a position of the event sequence for a helper event, and notices a cut.
    fn position() -> u64 {
        let seq = statelens::tick();
        truncation();
        seq
    }

    /// The position of the first observation the trace dropped at its cap, or `None`.
    /// The first time it finds one while stages are open on this thread, it prints
    /// the `truncated` line.
    fn truncation() -> Option<u64> {
        let seq = statelens::truncated()?;
        let card = STATE.with(|state| {
            let mut state = state.borrow_mut();
            let first = !std::mem::replace(&mut state.noticed, true);
            first.then_some(state.card)
        });
        if let Some(card) = card {
            emit(card, &format!("truncated seq={seq}"));
        }
        Some(seq)
    }

    /// Raises a scaffold error. Only the checks that run before any engine starts
    /// call it, so the error depends on the scaffold's own code and knob bytes.
    #[cold]
    fn scaffold_error(card: &str, reason: fmt::Arguments<'_>) -> ! {
        panic!("[statelens-scaffold] {card} {reason}");
    }

    /// `text` with every character `bad` accepts, and whitespace, replaced by `_`,
    /// or `-` when it is empty, so a line keeps its fields apart.
    fn token(text: &str, bad: &[char]) -> String {
        if text.is_empty() {
            return "-".to_string();
        }
        text.chars()
            .map(|c| {
                if c.is_whitespace() || bad.contains(&c) {
                    '_'
                } else {
                    c
                }
            })
            .collect()
    }

    /// `text` without the whitespace at its ends and next to each of `separators`,
    /// so `R=2@E1, v=5@E1` keeps its entities apart.
    fn tidy(text: &str, separators: &[char]) -> String {
        let separator = |c: char| separators.contains(&c);
        let mut out = String::with_capacity(text.len());
        for piece in text.split_inclusive(separator) {
            let part = piece.strip_suffix(separator).unwrap_or(piece);
            out.push_str(part.trim());
            out.push_str(&piece[part.len()..]);
        }
        out
    }

    /// An observable or a verb.
    fn field_name(text: &str) -> String {
        token(text, &['[', ']', ',', '@', '='])
    }

    /// A key, `name=value,...`, which may be empty.
    fn field_key(text: &str) -> String {
        let text = tidy(text, &[',', '=']);
        if text.is_empty() {
            return text;
        }
        token(&text, &['[', ']', '@'])
    }

    /// A value read or bound.
    fn field_value(text: &str) -> String {
        token(text, &['[', ']', ',', '@'])
    }

    /// A detail or reason: the rest of its line.
    fn field_detail(text: &str) -> String {
        text.replace(['\n', '\r'], " ")
    }

    /// An action, `verb[name=value,...]`; a bare verb fixes no entity.
    fn field_action(text: &str) -> String {
        let (verb, entities) = match text.split_once('[') {
            Some((verb, rest)) => (verb, rest.strip_suffix(']').unwrap_or(rest)),
            None => (text, ""),
        };
        format!("{}[{}]", field_name(verb.trim()), field_key(entities))
    }

    /// `bind`, `name=value@Ek,...`, as one field of its line.
    fn field_bind(bind: &str) -> String {
        token(&tidy(bind, &[',', '=', '@']), &[])
    }

    /// The knobs of a scaffold: the first bytes of its base input's `raw_bytes`.
    #[derive(Debug)]
    pub struct Knobs {
        card: &'static str,
        bytes: Vec<u8>,
        next: usize,
    }

    impl Knobs {
        /// Forgets the stages of an earlier input on this thread, so a scaffold
        /// error before [Stages::new] prints none of them. Then takes the first `k`
        /// bytes of `raw`, zero-padded, for card `card`, and leaves the rest; a tail
        /// left empty from a non-empty `raw` becomes `[0]`. More than 16 knobs is a
        /// scaffold error.
        pub fn split(card: &'static str, raw: &mut Vec<u8>, k: usize) -> Self {
            STATE.with(|state| *state.borrow_mut() = State::new());
            if k > MAX_KNOBS {
                scaffold_error(card, format_args!("more than {MAX_KNOBS} knobs: {k}"));
            }
            let had_bytes = !raw.is_empty();
            let mut bytes: Vec<u8> = raw.drain(..k.min(raw.len())).collect();
            bytes.resize(k, 0);
            if had_bytes && raw.is_empty() {
                raw.push(0);
            }
            Self {
                card,
                bytes,
                next: 0,
            }
        }

        /// The next knob: `domain[byte % domain.len()]`, so byte 0 picks
        /// `domain[0]`, the source value. A domain with fewer than two values, or
        /// more knobs picked than split, is a scaffold error.
        pub fn pick<T: Copy>(&mut self, domain: &[T]) -> T {
            if domain.len() < 2 {
                scaffold_error(
                    self.card,
                    format_args!(
                        "knob {} has a domain of {} value(s); it needs two or more",
                        self.next,
                        domain.len()
                    ),
                );
            }
            let Some(&byte) = self.bytes.get(self.next) else {
                scaffold_error(
                    self.card,
                    format_args!("more knobs picked than split ({})", self.bytes.len()),
                );
            };
            self.next += 1;
            domain[usize::from(byte) % domain.len()]
        }
    }

    /// The position an entry took when a recording wrapper stamped it. Only [stamp]
    /// makes one.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Stamp {
        seq: u64,
        run: u32,
    }

    impl Stamp {
        /// The entry's position; 0 when nothing watched.
        pub const fn seq(self) -> u64 {
            self.seq
        }
    }

    /// Stamps an entry a recording wrapper records, as it records it: takes a
    /// position, prints the `entry` line with it and returns it. Returns a stamp of
    /// position 0 and prints nothing while not watching.
    ///
    /// `observable` names what the wrapper records, `key` the entities the entry is
    /// keyed by, `name=value,...`, and `value` the value it records.
    pub fn stamp(observable: &str, key: &str, value: &str) -> Stamp {
        let seq = position();
        let run = statelens::current_run();
        if seq != 0 {
            emit(
                &card(),
                &format!(
                    "entry {}[{}]={} seq={seq}",
                    field_name(observable),
                    field_key(key),
                    field_value(value)
                ),
            );
        }
        Stamp { seq, run }
    }

    /// Marks an incarnation boundary of `replicas`, a restart the scaffold drives or
    /// a base's restart code runs: takes a position `s`, prints the `restart` line
    /// and returns `s`, which names the incarnation the restart began, `inc<s>`.
    /// Returns 0 and prints nothing while not watching.
    pub fn restart(replicas: &[u32]) -> u64 {
        let seq = position();
        if seq != 0 {
            let list: Vec<String> = replicas.iter().map(u32::to_string).collect();
            let list = if list.is_empty() {
                "-".to_string()
            } else {
                list.join(",")
            };
            emit(
                &card(),
                &format!("restart {list} seq={seq} run={}", statelens::current_run()),
            );
        }
        seq
    }

    /// The card of the stages open on this thread, or an empty string.
    fn card() -> String {
        STATE.with(|state| state.borrow().card.to_string())
    }

    /// What establishes a held stage, with the entities it binds.
    #[derive(Clone, Debug)]
    pub struct Witness {
        kind: &'static str,
        bind: String,
        evidence: String,
        /// The position the witness took when it was built.
        read: u64,
        /// The largest position its evidence carries, with its run; none for an
        /// `exact` witness with an item that has no stamp.
        position: Option<(u64, u32)>,
    }

    impl Witness {
        /// An `exact` witness: harness observables, one per part of the line, each
        /// read as `(observable, key, value, stamp)`, with the entry's stamp when the
        /// observable has one. `bind` is `name=value@Ek,...`, and each `key` names
        /// the entities it is keyed by, `name=value,...`. Its position is its latest
        /// stamp's, and it has none when an item has no stamp. Takes a position, its
        /// `read=`.
        pub fn exact(bind: &str, reads: &[(&str, &str, &str, Option<Stamp>)]) -> Self {
            let read = position();
            let evidence: Vec<String> = reads
                .iter()
                .map(|(observable, key, value, stamp)| {
                    let seq = stamp
                        .filter(|stamp| stamp.seq != 0)
                        .map_or_else(|| "-".to_string(), |stamp| stamp.seq.to_string());
                    format!(
                        "exact={}[{}]={} seq={seq}",
                        field_name(observable),
                        field_key(key),
                        field_value(value)
                    )
                })
                .collect();
            let stamps: Option<Vec<Stamp>> = reads
                .iter()
                .map(|read| read.3.filter(|stamp| stamp.seq != 0))
                .collect();
            let position = stamps
                .and_then(|stamps| stamps.into_iter().max_by_key(|stamp| stamp.seq))
                .map(|stamp| (stamp.seq, stamp.run));
            Self {
                kind: "exact",
                bind: field_bind(bind),
                evidence: evidence.join(" "),
                read,
                position,
            }
        }

        /// An `intrinsic` witness: one probe observation whose values come from one
        /// receiver. It identifies only the replica `me`, so `bind` gives every other
        /// entity `?`. Takes a position, its `read=`.
        pub fn intrinsic(bind: &str, seen: Seen) -> Self {
            let read = position();
            Self {
                kind: "intrinsic",
                bind: field_bind(bind),
                evidence: format!("obs={}", observation(seen)),
                read,
                position: Some((seen.seq(), seen.run())),
            }
        }

        /// A `construction` witness: takes a position right before it calls
        /// `perform`, which performs the harness action, and returns `perform`'s
        /// result with the witness. `action` is `verb[name=value,...]`. Before
        /// [Stages::new] nothing watches, so the position is 0 and the witness has
        /// none.
        pub fn act<T>(bind: &str, action: &str, perform: impl FnOnce() -> T) -> (T, Self) {
            let seq = position();
            let run = statelens::current_run();
            let result = perform();
            (
                result,
                Self::construction(field_bind(bind), field_action(action), seq, run),
            )
        }

        /// [Witness::act] for an action that is awaited: the returned future, when
        /// first polled, takes the position and only then calls `perform` and awaits
        /// the future it returns, so an action that takes effect when it is called
        /// still comes after its position.
        pub fn act_async<T, F, P>(
            bind: &str,
            action: &str,
            perform: P,
        ) -> impl Future<Output = (T, Self)> + use<T, F, P>
        where
            F: Future<Output = T>,
            P: FnOnce() -> F,
        {
            let bind = field_bind(bind);
            let action = field_action(action);
            async move {
                let seq = position();
                let run = statelens::current_run();
                let result = perform().await;
                (result, Self::construction(bind, action, seq, run))
            }
        }

        fn construction(bind: String, action: String, seq: u64, run: u32) -> Self {
            Self {
                kind: "construction",
                bind,
                evidence: format!("action={action} seq={seq}"),
                read: seq,
                position: (seq != 0).then_some((seq, run)),
            }
        }
    }

    /// An observation as `<run>:<seq>:<me>:<label>@<site>:<a>:<b>`.
    fn observation(seen: Seen) -> String {
        let me = seen
            .me()
            .map_or_else(|| "-".to_string(), |me| me.to_string());
        format!(
            "{}:{}:{me}:{}@{}:{}:{}",
            seen.run(),
            seen.seq(),
            seen.label(),
            seen.site(),
            seen.a(),
            seen.b()
        )
    }

    /// The outcome of a stage.
    enum Outcome {
        Held(Witness),
        Missed(String),
        Unverifiable(String),
        Withheld,
    }

    /// The stages of the card open on this thread. [Stages] is a handle to it, so
    /// the panic hook can evaluate and report them.
    struct State {
        /// The card, or an empty string before the first [Stages::new].
        card: &'static str,
        n: u32,
        /// Whether stage `k` has an outcome, at `k - 1`.
        settled: Vec<bool>,
        /// The stages recorded as held.
        held: u32,
        /// Whether the `truncated` line was printed.
        noticed: bool,
        since: u64,
        open: bool,
        handed_off: bool,
        phase: &'static str,
        /// The stage lines printed so far.
        lines: Vec<String>,
        evaluate: Option<fn(&mut Stages)>,
    }

    impl State {
        const fn new() -> Self {
            Self {
                card: "",
                n: 0,
                settled: Vec::new(),
                held: 0,
                noticed: false,
                since: 0,
                open: false,
                handed_off: false,
                phase: "prefix",
                lines: Vec::new(),
                evaluate: None,
            }
        }
    }

    /// The stages `E1` to `En` of one card.
    #[derive(Debug)]
    pub struct Stages {
        _private: (),
    }

    impl Stages {
        /// Opens the stages of card `card` with `n` History events: watches the
        /// trace, opens the prefix phase and prints `phase prefix`, and installs the
        /// panic hook, once per process.
        pub fn new(card: &'static str, n: u32) -> Self {
            install_hook();
            statelens::watch();
            STATE.with(|state| {
                *state.borrow_mut() = State {
                    card,
                    n,
                    settled: vec![false; n as usize],
                    open: true,
                    ..State::new()
                }
            });
            emit(card, "phase prefix");
            Self { _private: () }
        }

        /// Takes the knobs, so none is picked later, and checks the budget before any
        /// engine starts: `prefix`, the stage deadlines plus the largest release
        /// delay, exceeding `runtime`, the runtime deadline, is a scaffold error.
        pub fn budget(&self, knobs: Knobs, prefix: Duration, runtime: Duration) {
            drop(knobs);
            if prefix > runtime {
                scaffold_error(
                    &card(),
                    format_args!(
                        "budget: the prefix {prefix:?} exceeds the runtime deadline {runtime:?}"
                    ),
                );
            }
        }

        /// Stage `k` held: prints its record, adds its feature, moves
        /// [Stages::since] past its position and returns `true`. Does nothing and
        /// returns `false` for stage n, which only [Stages::handoff] records, for a
        /// stage that has an outcome, for an event number outside 1 to n, and once
        /// the prefix is closed. A witness read at or after the position of the first
        /// observation the trace dropped makes the stage `unverifiable (trace
        /// truncated)` instead, with no feature, and returns `false`.
        pub fn held(&mut self, k: u32, witness: Witness) -> bool {
            settle(k, Outcome::Held(witness), false)
        }

        /// Stage `k` missed, with `detail`, or `cannot: <capability>`. The first miss
        /// closes the prefix, except in the control run, and prints up to 64 trace
        /// lines from the stage's start. A miss after the trace dropped an
        /// observation is `unverifiable (trace truncated)` instead, and closes
        /// nothing, unless it is a `cannot:`. Stage n takes only a `cannot:`, after
        /// which [Stages::handoff] reports the handoff lost.
        pub fn missed(&mut self, k: u32, detail: &str) {
            settle(k, Outcome::Missed(detail.to_string()), false);
        }

        /// Stage `k` is unverifiable, for `reason`: no available witness binds it.
        /// For stage n, call it before [Stages::handoff], which then reports the
        /// handoff lost.
        pub fn unverifiable(&mut self, k: u32, reason: &str) {
            settle(k, Outcome::Unverifiable(reason.to_string()), true);
        }

        /// Stage `k` was withheld: the control run skipped its action.
        pub fn withheld(&mut self, k: u32) {
            settle(k, Outcome::Withheld, false);
        }

        /// Whether the prefix is open.
        pub fn open(&self) -> bool {
            STATE.with(|state| state.borrow().open)
        }

        /// The position from which the next stage reads the trace.
        pub fn since(&self) -> u64 {
            STATE.with(|state| state.borrow().since)
        }

        /// Decides the handoff. Takes a position; then, when stage n has no outcome
        /// and the prefix is open, calls `read`, which must read `En`'s witness and
        /// cannot await; then takes the handoff mark, and records `En` held with the
        /// witness `read` returned, or missed on `None`. The handoff holds when `En`
        /// was held in this call and the mark directly follows the witness's read.
        /// Once the trace dropped an observation at or before the mark, `En` is
        /// `unverifiable (trace truncated)` instead and the handoff is lost. Prints
        /// the handoff, `phase continuation` and the `reach` line, closes the prefix
        /// and stops watching. Does nothing when called again.
        pub fn handoff(&mut self, read: impl FnOnce() -> Option<Witness>) {
            let Some((card, n, pending)) = STATE.with(|state| {
                let state = state.borrow();
                let last = (state.n as usize).checked_sub(1);
                let pending =
                    state.open && last.is_some_and(|last| state.settled.get(last) == Some(&false));
                (!state.handed_off).then_some((state.card, state.n, pending))
            }) else {
                return;
            };
            position();
            let witness = pending.then(read);
            let mark = position();
            let cut = truncation().is_some_and(|seq| seq <= mark);
            let mut evidence = None;
            if let Some(witness) = witness {
                let outcome = match witness {
                    _ if cut => Outcome::Unverifiable(TRUNCATED.to_string()),
                    Some(witness) => {
                        evidence = Some((witness.read, witness.position));
                        Outcome::Held(witness)
                    }
                    None => Outcome::Missed("not held at handoff".to_string()),
                };
                if !settle(n, outcome, true) {
                    evidence = None;
                }
            }
            let holds = evidence.is_some_and(|(read, _)| read != 0 && mark == read + 1);
            // Reading the trace copies it, so `next=` is read only for a line that
            // prints.
            let next = evidence
                .and_then(|(_, position)| position)
                .filter(|_| reach())
                .and_then(|(seq, run)| {
                    statelens::observations(seq.saturating_add(1))
                        .into_iter()
                        .find(|seen| {
                            seen.run() == run
                                && !statelens::is_byzantine(
                                    seen.me().map(statelens::Participant::new),
                                )
                        })
                })
                .map_or_else(
                    || "-".to_string(),
                    |seen| format!("{}:{}", seen.run(), seen.seq()),
                );
            let held = STATE.with(|state| {
                let mut state = state.borrow_mut();
                state.open = false;
                state.handed_off = true;
                state.phase = "continuation";
                state.held
            });
            statelens::unwatch();
            let verdict = if holds { "holds" } else { "lost" };
            emit(card, &format!("handoff {verdict} mark={mark} next={next}"));
            emit(card, "phase continuation");
            emit(
                card,
                &format!("reach {held}/{n} control={}", u8::from(control())),
            );
        }

        /// Shape A: registers the evaluation of the stages, which the panic hook runs
        /// over the trace so far.
        pub fn on_panic(&mut self, evaluate: fn(&mut Self)) {
            STATE.with(|state| state.borrow_mut().evaluate = Some(evaluate));
        }

        /// Prints `done`, after the last oracle.
        pub fn done(&mut self) {
            emit(&card(), "done");
        }
    }

    /// Records the outcome of stage `k`, and returns whether it recorded it held.
    /// `last` lets the handoff, the panic hook and [Stages::unverifiable] record
    /// stage n; a `cannot:` miss records it too. Once the trace dropped an
    /// observation, a miss other than a `cannot:`, and a witness read at or after the
    /// dropped position, are `unverifiable (trace truncated)`.
    fn settle(k: u32, outcome: Outcome, last: bool) -> bool {
        let cut = truncation();
        let outcome = match outcome {
            Outcome::Held(witness) if cut.is_some_and(|seq| witness.read >= seq) => {
                Outcome::Unverifiable(TRUNCATED.to_string())
            }
            Outcome::Missed(text) if cut.is_some() && !text.starts_with("cannot:") => {
                Outcome::Unverifiable(TRUNCATED.to_string())
            }
            outcome => outcome,
        };
        let last = last || matches!(&outcome, Outcome::Missed(text) if text.starts_with("cannot:"));
        let control = control();
        let recorded = STATE.with(|state| {
            let mut state = state.borrow_mut();
            let n = state.n;
            let index = (k as usize).checked_sub(1)?;
            if !state.open || k > n || (k == n && !last) || state.settled.get(index) != Some(&false)
            {
                return None;
            }
            state.settled[index] = true;
            let start = state.since;
            let line = match &outcome {
                Outcome::Held(witness) => {
                    state.held += 1;
                    let next = witness
                        .position
                        .map_or(witness.read, |(seq, _)| seq)
                        .saturating_add(1);
                    state.since = state.since.max(next);
                    format!(
                        "E{k}/{n} held {} bind={} {} read={}",
                        witness.kind, witness.bind, witness.evidence, witness.read
                    )
                }
                Outcome::Missed(text) => {
                    if !control {
                        state.open = false;
                    }
                    with_detail(format!("E{k}/{n} missed"), text)
                }
                Outcome::Unverifiable(text) => with_detail(format!("E{k}/{n} unverifiable"), text),
                Outcome::Withheld => format!("E{k}/{n} withheld"),
            };
            state.lines.push(line.clone());
            Some((state.card, line, start))
        });
        let Some((card, line, start)) = recorded else {
            return false;
        };
        emit(card, &line);
        match outcome {
            Outcome::Held(_) => {
                feature(card, k);
                true
            }
            Outcome::Missed(_) => {
                // Reading the trace copies it, so it is read only for lines that print.
                if reach() {
                    for seen in statelens::observations(start).into_iter().take(TRACE_LINES) {
                        emit(card, &format!("trace {}", observation(seen)));
                    }
                }
                false
            }
            Outcome::Unverifiable(_) | Outcome::Withheld => false,
        }
    }

    /// `head`, then `text` as the rest of the line when there is one.
    fn with_detail(head: String, text: &str) -> String {
        if text.is_empty() {
            head
        } else {
            format!("{head} {}", field_detail(text))
        }
    }

    /// Chains the helper's panic hook in front of the current one (libFuzzer's),
    /// once per process.
    fn install_hook() {
        static INSTALLED: OnceLock<()> = OnceLock::new();
        INSTALLED.get_or_init(|| {
            let previous = std::panic::take_hook();
            std::panic::set_hook(Box::new(move |info| {
                report_panic(info);
                previous(info);
            }));
        });
    }

    /// Prints the `panic` line, the phase and the stage lines so far; in Shape A, the
    /// stages the registered evaluation finds in the trace; and `unverifiable
    /// (crashed)` for every stage of the open prefix the hook cannot read.
    fn report_panic(info: &std::panic::PanicHookInfo<'_>) {
        if !reach() {
            return;
        }
        let Some((card, phase, lines, evaluate)) = STATE.with(|state| {
            let state = state.try_borrow().ok()?;
            (!state.card.is_empty()).then(|| {
                (
                    state.card,
                    state.phase,
                    state.lines.clone(),
                    state.evaluate.filter(|_| !state.handed_off),
                )
            })
        }) else {
            return;
        };
        let location = info.location().map_or_else(
            || "-".to_string(),
            |location| {
                format!(
                    "{}:{}:{}",
                    location.file(),
                    location.line(),
                    location.column()
                )
            },
        );
        let payload = info.payload();
        let message = payload
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
            .unwrap_or("Box<dyn Any>");
        let first = message.lines().next().unwrap_or("");
        emit(card, &with_detail(format!("panic {location}"), first));
        emit(card, &format!("phase {phase}"));
        for line in &lines {
            emit(card, line);
        }
        let mut stages = Stages { _private: () };
        if let Some(evaluate) = evaluate {
            evaluate(&mut stages);
        }
        let n = STATE.with(|state| {
            state
                .try_borrow()
                .ok()
                .filter(|state| !state.handed_off)
                .map_or(0, |state| state.n)
        });
        for k in 1..=n {
            settle(k, Outcome::Unverifiable("(crashed)".to_string()), true);
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        thread_local! {
            /// The lines the helper printed on this thread, without their prefix and card.
            pub(super) static LINES: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
            /// The stages whose feature the helper added on this thread.
            pub(super) static FEATURES: RefCell<Vec<u32>> = const { RefCell::new(Vec::new()) };
        }

        /// Opens `n` stages of `card` with no knobs, forgetting what earlier tests on
        /// this thread printed.
        fn open(card: &'static str, n: u32) -> Stages {
            LINES.take();
            FEATURES.take();
            let knobs = Knobs::split(card, &mut Vec::new(), 0);
            let stages = Stages::new(card, n);
            stages.budget(knobs, Duration::ZERO, Duration::ZERO);
            stages
        }

        /// Notes `count` observations of replica 0 in state `a`, as a probe would.
        fn observe(a: u32, count: usize) {
            for _ in 0..count {
                let me = Some(statelens::Participant::new(0));
                statelens::note(me, "state", "state.rs:1:1", a, 0);
            }
        }

        /// The observation at position `seq`.
        fn at(seq: u64) -> Seen {
            let found = statelens::observations(seq);
            assert_eq!(found.first().map(|seen| seen.seq()), Some(seq));
            found[0]
        }

        /// The index of the first of `lines` that starts with `start`.
        fn find(lines: &[String], start: &str) -> Option<usize> {
            lines.iter().position(|line| line.starts_with(start))
        }

        #[test]
        fn test_stages_read_after_the_cut_are_unverifiable() {
            let mut stages = open("TS-9001", 3);
            observe(1, 1);
            let first = at(statelens::mark());
            assert!(
                stages.held(1, Witness::intrinsic("R=0@E1", first)),
                "a stage read before the cut holds"
            );
            observe(1, statelens::TRACE_CAP - 1);
            assert_eq!(statelens::truncated(), None, "the trace is full, not cut");
            let kept = statelens::mark();
            observe(0, 1);
            let cut = statelens::truncated().expect("the trace drops the state change");
            assert_eq!(cut, kept + 1);
            let stale = at(kept);
            assert_eq!(stale.a(), 1, "the latest observation kept is stale");
            assert!(
                !stages.held(2, Witness::intrinsic("R=0@E2", stale)),
                "a stage read after the cut does not hold"
            );
            stages.handoff(|| Some(Witness::intrinsic("R=0@E3", stale)));
            let lines = LINES.take();
            assert_eq!(lines.len(), 8, "{lines:#?}");
            assert_eq!(lines[0], "phase prefix");
            assert!(lines[1].starts_with("E1/3 held intrinsic bind=R=0@E1 obs="));
            assert_eq!(lines[2], format!("truncated seq={cut}"));
            assert_eq!(lines[3], "E2/3 unverifiable (trace truncated)");
            assert_eq!(lines[4], "E3/3 unverifiable (trace truncated)");
            assert!(lines[5].starts_with("handoff lost mark="), "{}", lines[5]);
            assert_eq!(lines[6], "phase continuation");
            assert_eq!(lines[7], "reach 1/3 control=0");
            assert_eq!(FEATURES.take(), vec![1], "none for a stage after the cut");
            assert_eq!(statelens::truncated(), None, "the handoff stops watching");
        }

        #[test]
        fn test_handoff_cannot_hold_across_a_cut() {
            let mut stages = open("TS-9002", 2);
            observe(1, 1);
            let first = at(statelens::mark());
            assert!(stages.held(1, Witness::intrinsic("R=0@E1", first)));
            observe(1, statelens::TRACE_CAP - 1);
            let kept = statelens::mark();
            let mut cut = None;
            stages.handoff(|| {
                let witness = Witness::intrinsic("R=0@E2", at(kept));
                // The state changes between the read and the mark, past the cap.
                observe(0, 1);
                cut = statelens::truncated();
                Some(witness)
            });
            let cut = cut.expect("the trace drops the state change");
            let lines = LINES.take();
            let truncated = find(&lines, "truncated").expect("the cut is printed");
            assert_eq!(lines[truncated], format!("truncated seq={cut}"));
            assert_eq!(find(&lines[truncated + 1..], "truncated"), None, "once");
            let last = find(&lines, "E2/2").expect("En has a line");
            assert!(truncated < last, "{lines:#?}");
            assert_eq!(lines[last], "E2/2 unverifiable (trace truncated)");
            assert!(lines[last + 1].starts_with("handoff lost mark="));
            assert!(find(&lines, "reach 1/2 control=0").is_some());
            assert_eq!(FEATURES.take(), vec![1]);
        }

        #[test]
        fn test_handoff_holds_without_a_cut() {
            let mut stages = open("TS-9003", 2);
            observe(1, 1);
            let first = at(statelens::mark());
            assert!(stages.held(1, Witness::intrinsic("R=0@E1", first)));
            observe(1, 1);
            let last = statelens::mark();
            stages.handoff(|| Some(Witness::intrinsic("R=0@E2", at(last))));
            let lines = LINES.take();
            assert_eq!(find(&lines, "truncated"), None);
            let last = find(&lines, "E2/2 held intrinsic").expect("En holds");
            assert!(lines[last + 1].starts_with("handoff holds mark="));
            assert!(find(&lines, "reach 2/2 control=0").is_some());
            assert_eq!(FEATURES.take(), vec![1, 2]);
        }

        #[test]
        fn test_unverifiable_last_stage_loses_the_handoff() {
            let mut stages = open("TS-9004", 2);
            observe(1, 1);
            let first = at(statelens::mark());
            assert!(stages.held(1, Witness::intrinsic("R=0@E1", first)));
            stages.unverifiable(2, "no observable binds v");
            stages.handoff(|| unreachable!("En has an outcome"));
            let lines = LINES.take();
            let last = find(&lines, "E2/2").expect("En has a line");
            assert_eq!(lines[last], "E2/2 unverifiable no observable binds v");
            assert!(
                lines[last + 1].starts_with("handoff lost mark="),
                "{lines:#?}"
            );
            assert!(find(&lines, "reach 1/2 control=0").is_some(), "{lines:#?}");
            assert_eq!(FEATURES.take(), vec![1]);
        }

        #[test]
        fn test_lines_that_do_not_print_read_no_trace() {
            let mut stages = open("TS-9005", 2);
            observe(1, 2);
            stages.missed(1, "deadline");
            let lines = LINES.take();
            let traced = lines
                .iter()
                .filter(|line| line.starts_with("trace "))
                .count();
            assert_eq!(traced, if reach() { 2 } else { 0 }, "{lines:#?}");
            let mut stages = open("TS-9005", 1);
            observe(1, 1);
            let last = statelens::mark();
            observe(1, 1);
            stages.handoff(|| Some(Witness::intrinsic("R=0@E1", at(last))));
            let lines = LINES.take();
            let handoff = find(&lines, "handoff holds mark=").expect("the handoff holds");
            assert_eq!(lines[handoff].ends_with(" next=-"), !reach(), "{lines:#?}");
        }
    }
}
~~~
