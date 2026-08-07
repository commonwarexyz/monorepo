# UNO formal-specification and model-checking handoff

> **Paused checkpoint, 6 August 2026.** This handoff's original “next task” and two-module inventory
> are now historical. `docs/uno-protocol.qnt` has 5,089 lines and three modules, including the
> two-participant `uno_composed` byte-level bridge. Its current SHA-256 is
> `dde48576de33b8993cdc340a01a9019f842ae61bb91a15c996af834f32b75965`. Its immediate predecessor,
> SHA-256 `ee66bfc46088ffd9b1ccd1aa5779ff59f05bff7b44aaa72c48cd9446a33465f4`, typechecked with the
> command below. A later full-diff audit found and corrected that checkpoint's generation-2
> predecessor fixture: it claimed ordinary `R` but encoded the `M` guard and CRCs. Because formal
> execution remains paused, the corrected current artifact has not yet been typechecked.
> Development runs found the intended broken-generation counterexample and completed
> several shallow pair-fixed obligations, but later edits mean that no final-current-hash Apalache
> matrix is complete. The exact-A recovery run was manually stopped (`exit=137`,
> `OOMKilled=false`) when the user paused formal-model execution. Do not resume a checker merely to
> complete this handoff. `docs/uno-model-checking.md` now distinguishes current evidence, older
> development evidence, OOM/interrupted attempts, and pending checks. On resumption, run one heavy
> checker at a time with the established 44 GiB JVM profile and the approximately 58.75 GiB Docker
> ceiling; do not repeat low-memory calibration. The paper now specifies commit-biased recovery:
> rejection before exact code-last `A` is provisional and may become new after a torn abort-body
> repair; exact `A` is irreversible old, and no caller mutation, destructive payload change, or
> payload/slot reuse is permitted while a distinguishable rejected generation lacks it.
> Proof-preserving predecessor finalization is allowed. A byte-for-byte canonical lower-generation
> pre-attempt source, including its own exact lower-generation witness, has no distinguishable new
> generation to consume.

> **Post-handoff workspace update.** The branch was externally advanced to
> `5ecb6c433c0392cd9fc7f6d7ab9cafc1b4a69cea` (`progress`), which tracks the six UNO artifacts and
> changes no Rust relative to `26a532dd6`. After explicit authorization, commit
> `c5597b66670f31c71795e9c2cd02d195e711af10` adds the reviewed cancellation-ownership repair and
> regressions without changing the R13 on-disk format. The workspace-state inventory below is
> preserved as the historical starting checkpoint. Fresh Linux/ext4 and Rust/cancellation review
> results and exact validation commands are recorded in `docs/uno-model-checking.md`; formal-model
> execution remains paused. The current TeX rebuilt successfully as a 25-page, 257,917-byte PDF
> with SHA-256
> `68b469865c29dc74a3f7ebcd6109a651bde927f37df37fccb14d81c3e3a4a354`.

> **Confirmed target-protocol blocker.** A final full-diff audit and an independent byte-level
> reconstruction confirmed that the one-phase proposed R14 prepare does not bind the adjacent
> generation-independent witness to the issued candidate-generation guard. Old two-member topology
> bytes and issued-new three-member candidate bytes can form an exact checksummed two-member ring,
> publishing two participants while the third remains old. This requires no CRC collision,
> generation skip, incarnation reuse, or external namespace mutation. The paper now withdraws the
> unconditional theorem and records only a conditional conjecture. The current two-participant
> `uno_composed` model starts witnesses from zero and cannot express this old-two/new-three trace.
> The next action requires an architecture choice: (A) two-phase code-last prepare, which adds a
> second ordered durability layer and is the correctness-first recommendation; (B) a splice-binding
> root-to-witness commitment with a stronger computational assumption; or (C) narrowing away
> admitted-but-unacknowledged atomicity. Formal execution remains paused until that choice is made.

This document is a session handoff for continuing the UNO protocol audit in a fresh Codex session.
It records the exact local state, user requirements, work completed, known correctness gaps, and
reproducible validation commands. Do not infer that an item is complete merely because it appears
in the specification: the paper deliberately distinguishes the proposed R14 protocol from the
checked-in R13 implementation.

## Historical starting objective

The session began with the objective of making the UNO formal specification sound under adversarial
review and using a real model checker (Quint with Apalache), not a home-grown state-machine
explorer. The original next task was to close the gap between the separate byte-provenance and
group-control abstractions by adding a small composed, byte-level, two-participant model. That model
now exists, but the confirmed three-participant witness-provenance counterexample above supersedes
this historical objective. The current next action is the architecture choice in the checkpoint.

The explicitly authorized cancellation repair is complete. Do not make further Rust changes to
implement any witness-provenance option unless the user selects that architecture and authorizes
implementation work.

## Historical workspace state (original handoff)

- Repository: `/Users/patrickogrady/code/monorepo-pr-4368`
- Branch: `pr/4368`
- HEAD: `26a532dd6` (`origin/explore-runtime-atomics`)
- HEAD subject: `[runtime] Clean stranded tombstones during partition recovery`
- Docker image already built: `uno-quint:0.32.0`
- Quint: 0.32.0
- Apalache: 0.56.1

At the original handoff, the following files were intentionally untracked and contained the work.
They are tracked by `5ecb6c433` now, but must still not be reset, cleaned, or overwritten:

```text
docs/uno-model-checking.md
docs/uno-protocol-spec.pdf
docs/uno-protocol-spec.tex
docs/uno-protocol.qnt
docs/uno-quint.Dockerfile
```

This handoff file was also untracked at that checkpoint and is tracked now.

The existing presentation is tracked and clean:

```text
docs/uno-v2-atomic-storage.tex
docs/uno-v2-atomic-storage.pdf
```

At handoff creation, the paper source was newer than its PDF:

```text
2026-08-06 00:15:08 docs/uno-protocol-spec.tex
2026-08-05 23:00:24 docs/uno-protocol-spec.pdf
```

That stale original PDF has since been rebuilt. The current PDF dimensions and digest are recorded
in the checkpoint at the top of this file. The presentation PDF was already current relative to its
source at the original handoff.

## Non-negotiable user requirements and corrections

1. Use Apalache or Quint. The user explicitly rejected a custom state-machine checker.
2. The storage crash model is **not prefix persistence**. Before a successful durability barrier,
   any subset of every issued write's addressed bytes may survive, torn at arbitrary byte
   boundaries.
3. The same fault model applies to recovery and repair. Abort roots, final materialization roots,
   truncation, tombstone cleanup, unlink, and directory repair may themselves be interrupted by
   another crash.
4. Model real batches, including mixed append/update-as-append, rewind/resize, and delete—not a
   prepare-only toy model.
5. Model partial deletion: some unlinks/directory updates may survive while others do not.
6. Be explicit about what the model does and does not say about Linux/ext4. Do not call the Quint
   model an ext4 model or a proof of the Rust implementation.
7. Keep analysis adversarial. A passing bounded run is evidence, not an unbounded proof.
8. AIO experimentation was explicitly dropped. Do not resume the legacy-AIO prototype or present
   it as active work.
9. UNO is intended as an atomic wrapper over an ordinary V1 `Blob`; if a narrow filesystem/backend
   capability is needed, pipe it through the ordinary abstraction rather than bypassing it.
10. Preserve ordinary V0/V1 behavior and the current public usage. The atomic API is ALPHA and may
    change, but mainline non-atomic storage must not be undermined.

## Target architecture in one paragraph

UNO wraps each ordinary blob with a private root page and append-only payload. A batch writes each
participant's payload once at its final location and publishes a checksummed local successor link
plus an invisible prepared root. The links form a canonical ring; a complete exact ring is the
distributed commit certificate. Every participant can then independently materialize to an `M`
root or a deletion tombstone `T`. There is no global coordinator, manifest, WAL, global lock, or
global sync order. Per-file durability obligations are independent and may be issued concurrently,
but there is no guarantee that the filesystem/device coalesces them into one physical flush.

The target mutation vocabulary is append, rewind, and delete. It deliberately does not promise
single-copy atomic arbitrary in-place overwrite; that requires undo/redo logging, COW/patch mapping,
or a volume-like allocator and reclamation scheme.

## Important distinction: checked-in R13 versus proposed R14

The source tree at `26a532dd6` reports R13 roots and L14 links:

```text
storage/runtime/src/storage/atomic.rs
  CWUNOR13, CWUNOP13, CWUNOB13, CWUNOM13, CWUNOT13, CWUNOW13

storage/runtime/src/storage/batch/coordinator.rs
  CWUNOL14
```

The paper's safety argument is for a proposed **R14** root format, not the current R13 codec. R14
uses one generation-colored state/guard byte:

```text
chi(g, state) = 1 + 6 * (g mod 3) + state_index
```

This guard prevents an old same-slot final spelling, a torn new prepare, and a later torn abort from
accidentally synthesizing an exact final root that was never issued. R14 also requires:

- consecutive, nonwrapping generation lineage;
- canonical full-slot preparation;
- rejected generations consumed with a predecessor-equivalent abort authority;
- code-last abort publication: barrier all 111 non-guard header bytes, then write and barrier the
  one-byte abort guard;
- only exact group-bound `M/T` roots plus their witness may act as final group certificates;
- ordinary `R` roots are not group certificates.
- an authority-bearing witness must have disk-observable issuance provenance; exact CRC validation
  alone does not supply it.

Do not describe the checked-in R13 implementation as satisfying the proposed R14 conditions, and
do not describe the current one-phase target as having an unconditional theorem.

## Original artifact inventory (superseded by the top checkpoint)

### `docs/uno-protocol-spec.tex`

Approximately 2,055 lines. It is written like a conference protocol paper and includes:

- vocabulary, objects, identities, API observations, and safety target;
- an explicit arbitrary-subset addressed-byte crash model;
- a Linux/ext4 refinement boundary;
- backing-blob geometry, root and witness layouts;
- preparation, decision, materialization, deletion, ring discovery, and missing-participant recovery;
- generation-colored R14 state guard and code-last abort protocol;
- invariants, lemmas, a conditional safety conjecture, liveness conditions, cost discussion, and
  API semantics;
- source-to-spec correspondence;
- a candid implementation-refinement status section with concrete blockers and counterexamples;
- executable-model scope and audit checklist.

The Linux/ext4 section intentionally states that the paper assumes a supported local-filesystem
profile rather than modeling JBD2. The intended initial profile is local non-DAX ext4 with normal
journal replay, working barriers/flushes, and `data=ordered` or `data=journal`. A successful
`fdatasync` establishes the relevant file-data/size frontier; directory-entry durability requires a
directory `fsync`. `RWF_DSYNC` is not `RWF_ATOMIC`. `data=writeback`, `nobarrier`, `noload`, devices
that lie about flushes, misdirected writes, and neighboring-block damage are outside the conditional safety envelope
unless separately refined.

### `docs/uno-protocol.qnt`

At the original handoff this was approximately 1,197 lines and had two modules:

1. `uno_group`
   - one, two, or three participants;
   - each participant independently append, rewind, or remove;
   - independent prepare/payload/link outcomes;
   - decision derived from disk evidence;
   - interruptible code-last abort repair;
   - interruptible `M/T` finalization;
   - post-decision physical rewind;
   - issued unlink sets with arbitrary crash-surviving subsets;
   - recovery observations decoded from local state rather than assigned directly from a ghost goal;
   - focused cut-point initializers `initRejected`, `initDecided`, and `initFinalized`.

2. `uno_slot`
   - finite byte-cell provenance abstraction;
   - arbitrary powersets of addressed cells survive each unsynced write;
   - crash always loses volatile recovery phase and barrier credit;
   - abort repair writes header only, never the witness;
   - deliberate generation-uncolored negative control (`initBuggy`);
   - generation-colored, code-last target (`initFixed`).

At that checkpoint the model header and paper both admitted that these modules were disconnected
abstractions. The later `uno_composed` module closed that two-participant structural gap but not the
three-participant witness-provenance gap recorded at the top of this handoff.

### `docs/uno-model-checking.md`

At the original handoff it contained the pinned Docker commands and fault abstraction but still
needed the composed-model ledger. The current file now distinguishes final-hash, development,
interrupted, and pending evidence; do not quote any result outside the category in which it is
recorded.

### `docs/uno-quint.Dockerfile`

Pins the actual tools. Continue using it rather than installing Java or Apalache directly on the
host.

## Historical validation state at original handoff

The model artifact present at the original handoff typechecked successfully with:

```sh
docker run --rm \
  -v uno-quint-cache:/root/.quint \
  -v "$PWD/docs":/model:ro -w /tmp \
  uno-quint:0.32.0 \
  typecheck /model/uno-protocol.qnt
```

Important: the image entrypoint is already `quint`. Do **not** run
`uno-quint:0.32.0 quint typecheck ...`; that accidentally launches the REPL and can produce an
irrelevant `write EPIPE` message.

Historical bounded results obtained before the current artifact:

- generation-uncolored slot negative control: violation found within depth 5 (expected);
- generation-colored/code-last slot model: no violation through depth 8;
- expanded group model: no violation through depth 6;
- randomized group simulation: 10,000 samples, 24 steps, no violation;
- focused cut-point initializers typechecked and passed a shallow reachability check.

These runs preceded later model edits. Treat them as historical evidence only. The current digest
has not been typechecked because formal execution is paused. A 100,000-sample/30-step randomized
run was stopped because it was too slow; never claim it passed.

## Known target and implementation blockers

The paper intentionally does not hide these:

- **Target witness provenance is unsound.** The one-phase proposed R14 prepare can reconstruct an
  exact never-issued smaller ring from an older same-parity witness and issued-new candidate bytes.
  This blocks the unconditional conjecture independently of every Rust correspondence issue and
  requires the architecture choice recorded at the top of this handoff.

The checked-in implementation additionally has these refinement blockers:

1. **Namespace shape is not fully checked.** Hard-link aliases can make two logical participants
   write the same inode. Existing-file open can follow a symlink while recovery uses no-follow
   behavior, creating live/recovery disagreement.
2. **A newer tombstone can lose to an older complete ring.** Current stale-witness suppression does
   not give a newer exact `T` precedence over every older ring, so a partially unlinked deletion can
   resurrect data.
3. **R13 permits exact unissued authority synthesis.** Generation-independent state magic allows a
   non-prefix mixture of old final, torn prepare, and torn abort bytes to reconstruct a canonical
   final header never issued by the protocol.
4. **Ordinary roots are not valid group certificates.** Current recovery can use an `R` root that
   carries no group identity as evidence for a stale group.
5. **Rejected witnesses can survive payload reuse.** Without durable reject-and-consume, later
   payload written at reused offsets can accidentally make an old witness validate.
6. **Missing successor partition causes an availability failure.** Current ordered-delete recovery
   can propagate `ENOENT` instead of using independent local `M/T` authority.
7. **Integrity geometry has acknowledged-reopen gaps.** Empty chunk completion and malformed rewind
   units can stage a root that admission accepts but ordinary reopen rejects.

The earlier cancellation-ownership blocker was repaired after explicit Rust authorization. Tokio
open/scan/remove and direct Tokio/io_uring publication now become self-driving after namespace
admission, with exact post-unlink, recovery-truncate, and carried-materialization regressions. This
does not repair or validate the remaining R13/R14 format and correspondence blockers above.

These are implementation-refinement blockers, not all defects in the abstract R14 protocol. A fresh
session should keep that distinction explicit.

## Findings from adversarial review of the model

The latest adversarial review found the model useful but still too easy in several ways:

- `uno_slot` groups many bytes into semantic cells. It catches the known checksum-byte splice but
  is not a concrete all-byte codec model.
- `uno_group` and `uno_slot` are disconnected. A property proved in each does not mechanically show
  the byte-decoded roots drive the group recovery transition.
- The model covers only one generation transition. It does not yet exercise post-abort reuse,
  same-slot reuse two generations later, or overlapping successor groups.
- Append/rewind/remove are represented by semantic flags and lengths rather than a concrete payload
  byte store.
- The namespace abstraction models partial unlink but not full inode incarnation/recreation,
  rename/create, or directory-journal replay.
- It is not a Rust refinement model and has no async cancellation/owned-guard state.

Two findings were already repaired in the current model:

- crash no longer preserves volatile recovery phase or body-barrier credit;
- after a partial unlink, independently final/missing participants can re-enter cleanup instead of
  getting stuck because the old exact-tombstone predicate no longer holds.

## Historical next task: add a composed byte-level model

This task was completed by adding `uno_composed`. The design notes below are retained as provenance,
not as the current instruction. The next task is instead to select and model one of the three
witness-provenance contracts in the top checkpoint.

Add a third Quint module, preferably `uno_composed`, with a deliberately small state space but a
real end-to-end connection between bytes and group observations.

Recommended scope:

- exactly two participants;
- independently choose append, rewind, or remove for each;
- represent each participant's 112-byte R14 root header as `offset -> byte`, not semantic whole-field
  atoms;
- model the adjacent witness bytes separately and require an exact reciprocal two-node ring;
- use concrete canonical old, prepared, abort, materialized/tombstone byte vectors;
- include all four real CRC32C bytes for those representative vectors so accidental byte equality is
  preserved;
- every unsynced root/witness/repair write chooses an arbitrary powerset of **addressed byte
  offsets** from the current disk image;
- append has concrete old/new logical length plus payload-valid evidence;
- rewind has a smaller selected length and permits physical truncation only after decision;
- remove reaches exact `T`, then namespace unlink can survive for either, both, or neither name;
- recovery must classify bytes first and derive the group decision from exact decoded roots and
  witnesses—never from a ghost goal;
- abort body and abort guard remain two separately barriered phases, and a crash may occur during or
  after either;
- final `M/T` writes are ordinary interruptible writes;
- opening each participant derives `old`, `new`, or `absent` from recovered bytes/name state;
- assert that the observed pair is entirely old or entirely the intended new vector and that an
  acknowledged decision always recovers new.

The composed module is not required to model all participant counts. Its purpose is to bridge the
codec/provenance and two-node ring/control-flow reasoning. Keep `uno_group` for participant-scale
and mixed-operation control flow, and keep `uno_slot` as the fast negative control.

Representative CRC32C bytes previously computed for a candidate concrete R14 encoding are below.
Recheck the generator assumptions before treating these as format fixtures:

```text
p0 append old       206, 89,138, 39
p0 append prepared  149, 33, 64, 79
p0 append abort     132, 68,  9,  4
p0 append final      38, 69,200,209
p0 rewind old       206, 89,138, 39
p0 rewind prepared   62,143,127, 26
p0 rewind abort     132, 68,  9,  4
p0 rewind final     141,235,247,132
p0 remove old       206, 89,138, 39
p0 remove prepared   10, 55,217,168
p0 remove abort     132, 68,  9,  4
p0 remove final     254,106,185, 96
p1 append old       223,247,180,218
p1 append prepared  161,230,220,178
p1 append abort     149,234, 55,249
p1 append final      18,130, 84, 44
p1 rewind old       223,247,180,218
p1 rewind prepared   38, 48,231, 49
p1 rewind abort     149,234, 55,249
p1 rewind final     149, 84,111,175
p1 remove old       223,247,180,218
p1 remove prepared   27,153,231, 85
p1 remove abort     149,234, 55,249
p1 remove final     239,196,135,157
```

The assumptions used for that table were:

- root magic bytes are ASCII `CWUNO14` followed by the colored guard;
- old generation `1`, candidate generation `3` (representing same-slot reuse with a two-generation
  gap), old length `5`, append length `7`, rewind length `2`;
- state order `P=0, B=1, R=2, A=3, M=4, T=5`;
- integrity fields zero/unbound;
- 64-byte old tag byte `i` is `(17 + 13*p + 3*i) mod 256`;
- append tag byte `i` is `(91 + 13*p + 5*i) mod 256`;
- rewind tag byte `i` is `(121 + 13*p + 5*i) mod 256`;
- remove retains the old tag;
- checksum domain `_COMMONWARE_RUNTIME_ATOMIC_LOG_ROOT`.

This proposed model is intentionally more concrete than the current paper target. If its constants
do not exactly match the intended R14 codec, fix the model or label it representative; do not imply
it validates checked-in R13 bytes.

## Historical suggested execution order (superseded)

Do not follow the checker steps below while formal execution remains paused. After an architecture
choice, use the current ordered obligations in `docs/uno-model-checking.md` instead.

1. Read the repository `AGENTS.md` instructions from the user/session and inspect `git status`.
2. Read this handoff and all of:
   - `docs/uno-protocol-spec.tex`
   - `docs/uno-protocol.qnt`
   - `docs/uno-model-checking.md`
   - `docs/uno-quint.Dockerfile`
3. Typecheck the untouched current model to establish a baseline.
4. Implement `uno_composed` incrementally; typecheck after each structural block.
5. Add a deliberate negative control that removes generation coloring or code-last abort and ensure
   Apalache finds the known unissued-final counterexample.
6. Run bounded checks on the corrected composed model. Start shallow, then increase depth using
   focused reachable-cut initializers so repair/delete paths are not hidden by setup depth.
7. Rerun `uno_slot` negative and positive controls and every `uno_group` initializer on the final
   file.
8. Update `docs/uno-model-checking.md` with exact commands, depths, wall times, and limitations.
9. Update the paper's executable-model section to describe the composed module and its actual bound.
10. Rebuild `docs/uno-protocol-spec.pdf`.
11. Dispatch fresh adversarial reviews with separate scopes:
    - formal/model soundness and abstraction fairness;
    - Linux/ext4 refinement assumptions;
    - correspondence to the Rust implementation and cancellation behavior.
12. Resolve every actionable finding or record it candidly as a blocker/limitation. Repeat until a
    fresh full review has no unaddressed specification defect.

## Reproducible commands

Run from the repository root.

Build the pinned tool image if needed:

```sh
docker build -f docs/uno-quint.Dockerfile -t uno-quint:0.32.0 .
```

Typecheck:

```sh
docker run --rm \
  -v uno-quint-cache:/root/.quint \
  -v "$PWD/docs":/model:ro -w /tmp \
  uno-quint:0.32.0 \
  typecheck /model/uno-protocol.qnt
```

Expected-broken slot model (must find a violation; nonzero exit is success for this negative test):

```sh
docker run --rm \
  -v uno-quint-cache:/root/.quint \
  -v "$PWD/docs":/model:ro -w /tmp \
  uno-quint:0.32.0 \
  verify /model/uno-protocol.qnt \
  --main=uno_slot --init=initBuggy --step=step \
  --invariant=safe --max-steps=5 --verbosity=1
```

R14 target slot model:

```sh
docker run --rm \
  -v uno-quint-cache:/root/.quint \
  -v "$PWD/docs":/model:ro -w /tmp \
  uno-quint:0.32.0 \
  verify /model/uno-protocol.qnt \
  --main=uno_slot --init=initFixed --step=step \
  --invariant=safe --max-steps=8 --verbosity=1
```

Group model (increase bounds only after shallow runs succeed):

```sh
docker run --rm \
  -v uno-quint-cache:/root/.quint \
  -v "$PWD/docs":/model:ro -w /tmp \
  uno-quint:0.32.0 \
  verify /model/uno-protocol.qnt \
  --main=uno_group --init=init --step=step \
  --invariant=safe --max-steps=6 --verbosity=1
```

Randomized simulation is supplementary evidence only:

```sh
docker run --rm \
  -v "$PWD/docs":/model:ro -w /tmp \
  uno-quint:0.32.0 \
  run /model/uno-protocol.qnt \
  --main=uno_group --init=init --step=step \
  --invariants=safe --max-steps=24 --max-samples=10000 \
  --seed=0x4368 --backend=typescript --verbosity=1
```

Compile the paper using the available LaTeX toolchain. Check which compiler is installed first; in
the previous session the intent was to use `tectonic`. A typical command is:

```sh
tectonic --keep-logs --keep-intermediates docs/uno-protocol-spec.tex
```

Confirm where the compiler writes the PDF and move/update only the intended
`docs/uno-protocol-spec.pdf`. Do not use shell redirection or ad-hoc file-generation tricks for
source edits; use `apply_patch`.

## Relevant implementation entry points

```text
storage/runtime/src/atomic_api.rs
storage/runtime/src/storage/atomic.rs
storage/runtime/src/storage/uno.rs
storage/runtime/src/storage/batch/coordinator.rs
storage/runtime/src/storage/tokio/mod.rs
storage/runtime/src/storage/tokio/unix.rs
storage/runtime/src/storage/iouring.rs
storage/runtime/src/storage/faulty.rs
storage/runtime/src/utils/buffer/paged/atomic.rs
```

Useful exact anchors are listed in the paper's `Implementation correspondence` table. Prefer names
over line numbers because the branch may advance.

## What counts as done

Do not call the work complete until all of the following are true:

- the paper cleanly distinguishes abstract R14 safety from current R13 implementation status;
- the fault model says arbitrary subsets of all unsynced writes, including repair writes;
- mixed append/rewind/delete and partial deletion are represented;
- a composed model derives recovery from concrete byte images and an exact ring;
- a deliberate broken variant produces a counterexample;
- corrected bounded checks pass at documented bounds on the final file;
- all commands and limitations are recorded in `uno-model-checking.md`;
- the PDF is rebuilt from the final TeX without unresolved layout/reference errors;
- a fresh adversarial review finds no unrecorded specification defect;
- remaining Rust mismatches are listed as blockers rather than waved away.

## Session instability note

The previous session repeatedly displayed:

```text
Responses HTTPS request failed: error sending request for url
(https://chatgpt.com/backend-api/codex/responses)
```

Those were Codex response-transport failures, not repository, Docker, Quint, or Apalache failures.
Local edits and completed tool invocations remained intact. One misleading `write EPIPE` came from
invoking `quint` twice despite the Docker image already using it as the entrypoint; the correct
typecheck command above exited successfully for the recorded predecessor artifact.

## Current copy/paste prompt for the next session

```text
Continue the UNO formal-specification and model-checking work in:

  /Users/patrickogrady/code/monorepo-pr-4368

First read the repository instructions and then read this handoff completely:

  /Users/patrickogrady/code/monorepo-pr-4368/docs/uno-handoff.md

Preserve all existing work. Do not run git clean, reset the UNO artifacts, replace them from HEAD,
stage, commit, or push without explicit authorization. The branch is `pr/4368` at
`c5597b66670f31c71795e9c2cd02d195e711af10`; compare the complete work to
`26a532dd658fbee10137ad185da087548d9b114c`.

The goal is to make the UNO protocol specification sound under adversarial review. Use the pinned
Quint 0.32.0 + Apalache 0.56.1 Docker image (`uno-quint:0.32.0`); do not build a custom model
checker. The storage fault model is that ANY subset of every unsynced write's addressed bytes may
survive—not a prefix—and recovery/repair writes may crash and tear in exactly the same way.

The two-participant composed model exists, but fresh adversarial review confirmed that it
underapproximates a real old-two/new-three exact-witness splice. The proposed one-phase R14 target
therefore has no unconditional admitted-window theorem. Before changing or running the model, ask
the user to choose: (A) two-phase code-last prepare, the correctness-first noncryptographic repair;
(B) a root-to-witness splice-binding commitment with an explicit stronger computational
assumption; or (C) an acknowledged-prefix-only contract that withdraws admitted-but-unacknowledged
atomicity. Do not silently choose among those materially different contracts.

Once a contract is selected, follow `docs/uno-model-checking.md`: add an old `H={a,b}` / new
`G={a,b,c}` physical regression whose broken control reproduces the mixed vector and whose repaired
variant blocks it, then run the complete pinned Quint/Apalache matrix on the final hash. Do not claim
the current R13 Rust implementation satisfies the proposed R14 conditions or conditional
conjecture.

AIO work was explicitly dropped. Do not resume it. The cancellation-ownership Rust repair is
already committed and reviewed; do not make additional Rust changes without explicit authorization.

Start by showing `git status`, confirming the artifact hashes, and asking for the architecture
decision above. Formal execution remains paused until that choice is made. If it resumes, run one
checker at a time with the established 44 GiB JVM heap and approximately 58.75 GiB Docker ceiling;
do not repeat low-memory calibration.
```
