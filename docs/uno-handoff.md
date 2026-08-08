# UNO specification and Kani handoff

> **Authoritative restart checkpoint: 7 August 2026.** This file supersedes earlier handoff
> language claiming that the current Kani source has a completed proof matrix. Complete 30- and
> 36-harness matrices exist for older source snapshots. Pre-execution adversarial review and
> regression fixes have produced 42 proof harnesses and changed the codec, composed, and protocol
> sources; those current sources have **not** received a recorded full matrix. Do not transfer the
> older results to them.

The normative proposal is R14-2P, the two-phase code-last protocol. The checked-in production
implementation remains R13 and is not claimed to satisfy R14-2P. The Kani crate is a bounded,
specification-only model. Production Rust and AIO work are out of scope unless the user explicitly
authorizes them.

## Start here

1. Read the repository-root `AGENTS.md` completely.
2. Read this file completely.
3. Show `git status --short --branch` and confirm the commit and dirty artifacts below before
   changing anything.
4. Preserve all existing work. In particular, `docs/uno-kani-model/` is intentionally untracked;
   do not clean, reset, or replace it from `HEAD`.
5. Do not resume Quint or Apalache. Kani is the selected executable formal method. After the Kani
   work and reviews are genuinely complete, remove every remaining Quint/Apalache artifact as
   described below.
6. Do not start with a broad proof matrix. First reconcile the current source, documentation, and
   historical evidence. When proofs are resumed, run one harness at a time with no timeout or
   memory ceiling. The user explicitly asked not to use low-memory calibration runs.

No Kani, CBMC, Quint, or Apalache process was active when this checkpoint was written. No formal
model or test command was run while preparing this handoff.

## Repository state at this checkpoint

- Worktree: `/Users/patrickogrady/code/monorepo-pr-4368`
- Branch: `pr/4368`
- `HEAD`: `44196f356af4ef7cd12bb924c8a8c9d29cde0f5a` (`progress`)
- Required lineage commit `26a532dd6` is an ancestor of `HEAD`.
- `git diff --check` was clean immediately before the handoff rewrite.
- No production Rust file appeared in the dirty-worktree status.

The status before this handoff rewrite was:

```text
 M docs/uno-handoff.md
 M docs/uno-model-checking.md
 M docs/uno-protocol-spec.pdf
 M docs/uno-protocol-spec.tex
?? docs/uno-kani-model/
?? docs/uno-protocol-spec.aux
?? docs/uno-protocol-spec.log
?? docs/uno-protocol-spec.out
```

The TeX source is newer than the PDF, so the PDF is stale. The generated `.aux`, `.log`, and `.out`
files are temporary build artifacts; remove them after a successful final rebuild, retaining the
PDF. Preserve unrelated dirty work.

## Protocol decision and negative control

R14-2P is the correctness-first reference:

1. For every participant, issue the candidate payload/length update and every candidate-slot byte
   except root offset 7. Complete that participant's file durability operation.
2. Wait for a group-wide join. Every participant must have the exact body, witness, payload
   evidence, and live phase-one durability credit from the same candidate execution.
3. Only then issue each participant's one-byte, generation-colored prepared guard at root offset 7
   and complete a second file durability operation.
4. A crash clears every live durability credit. Recovery may decode a surviving exact prepared
   guard but may never manufacture one.
5. Rejection uses the same code-last order for the abort root: establish every non-guard abort byte,
   then issue its one-byte state guard. Recovery/repair writes may crash and tear under the same
   arbitrary-subset rule as ordinary writes.
6. No removal unlink is enabled until every participant has an independent durable final root.

The storage fault model is deliberately strong: **any subset of every unsynced write's addressed
bytes may survive**. It is not a prefix model. This applies equally to append, rewind/truncate,
remove, recovery, abort, and final-repair writes.

R14-1P deliberately omits the group-wide body barrier before prepared guards and is retained only
as a negative control. Its fixed trace starts from an older exact two-member witness at `a,b`,
rewinds to exact empty generation-two authorities, admits a legal generation-three three-member
append, and retains an arbitrary subset of issued bytes. The resulting exact synthetic two-member
ring publishes `a,b` while `c` remains old. This requires neither a checksum collision nor a
generation skip. The deliberately broken harness must fail only its intended atomicity assertion
and must reach its counterexample cover.

## Current Kani source: reviewed, proof-pending snapshot

The executable model is [`uno-kani-model`](uno-kani-model/README.md). It has three layers:

- `src/codec.rs`: physical proposed-R14 fixtures. Native tests use real CRC32C and full 2,048-byte
  slots. Kani quotients a slot to the 466 decoded root/wrapper/link bytes and gives every addressed
  retained byte an independent survival selector. Omitted bytes are fixed zero and unread.
  Wrapper/root checksum validation is erased under Kani as a conservative over-approximation;
  payload equality uses collision-free finite opaque tokens.
- `src/composed.rs`: twelve independently torn candidate byte-equivalence cells per participant,
  three exact-decoded fallback cells for authority/payload/extent, an explicit one-to-three-member
  ring decoder, active-count-aware atomicity, decoded operations and observations, distinct
  logical/suffix evidence, exact operation projection, mixed append/rewind/remove, and the broken
  one-phase control.
- `src/protocol.rs`: a bounded one-to-three-participant lifecycle abstraction with the group-wide
  phase-one join, crash-cleared body and phase-two completion credits, recovery-inert guard-sync
  history, no recovery prepared-guard writer, arbitrary phase-two guard crash cuts, one-authority
  abort selection with an explicit terminal admission action that blocks peer mutation until
  normalization, code-last abort, final repair,
  arbitrary unlink subsets, and retained semantic provenance.

Static source inventory at the checkpoint:

- 42 `#[kani::proof]` harnesses: 17 codec, 6 composed, and 19 protocol. There are 41 positive
  obligations with 52 positive cover declarations and one deliberately broken negative harness
  with one counterexample cover.
- 40 native `#[test]` functions: 17 codec, 5 composed, and 18 protocol.

These counts are only a source inventory. They are not execution results.

Pre-execution review first fixed empty-subset abort-body classification, stored-checksum
overconstraint, and boolean fallback authority. A later fresh review added regressions for active
one/two-member composed rings, exact operation projection, one-authority abort selection, volatile
phase-two completion credit, and arbitrary phase-two guard crash cuts. A fresh post-fix review then
added failing regressions for exact bridge group identity and explicit mutation admission; the
latter exposed a missing action at compilation. All regressions pass after the fixes. Full
post-format validation passes for the hashes below: format checking, all 40 native tests, Clippy
with warnings denied, and discovery of exactly 42 harnesses. The proof matrix is still pending; no
proof result is recorded for these hashes.

Current file hashes:

| File | SHA-256 |
|---|---|
| `docs/uno-kani-model/Cargo.toml` | `1ea006476cbd398a0879d59c47d573df4dc38fbc82cc11f1c0129be58e051aef` |
| `docs/uno-kani-model/Cargo.lock` | `e6c55013776fcd28a9af1b707fcdd41f45a18c079a1c00999b37caf9d3be7b0f` |
| `docs/uno-kani-model/README.md` | `a297bb204e0b4a139990054d7e417b22de6127608f63964fce36fad347516051` |
| `docs/uno-kani-model/src/lib.rs` | `fea94108026c13f1ad55c409e0be3006c399a6c1ce4a05d13d06e96beba0af0d` |
| `docs/uno-kani-model/src/codec.rs` | `b4eab34c636c80420567a40e027923f0ee39204fe9bbf0ef23576d2c8ef04076` |
| `docs/uno-kani-model/src/composed.rs` | `671daae27ec9ba28d0bbb9a38fb054a161e6b87ed588244b9e79564f474cc771` |
| `docs/uno-kani-model/src/protocol.rs` | `c66fae4345aec25e6d89db535e60e3020515eed5353f5f295736623428be91cb` |

Recompute all hashes before recording final results. A source change invalidates proof reuse for the
changed source and any downstream claim that depends on it.

## Historical 36-harness matrix: valid only for its exact hashes

The ledger also records a later completed 36-harness matrix for codec
`233ea437b97298317309ec230368eb23dbcdd98d4424fcd268c390959d9ac34e`, composed
`b831a62be5bbfe8eda2fae9ffed2a5cf5db91a958e770082bc8d2c85dcbe76df`, and protocol
`10165120c0dabcc12009493c10d4d7e7af4b031e7ebdb3f77dbe0060661fbce4`. All 35 positive
harnesses passed, checking 31,064 properties and satisfying 33/33 positive covers. The negative
harness failed only its intended assertion and reached its cover. Those results are historical and
do not apply to any live model source hash above.

## Historical 30-harness matrix: valid only for its exact hashes

`docs/uno-model-checking.md` records a real sequential matrix run using Kani 0.67.0, bundled CBMC
6.8.0, and CaDiCaL. For the exact older hashes below, all 29 positive harnesses passed, checking
25,011 properties and satisfying 26/26 positive covers. The deliberately broken harness failed
only its intended atomicity assertion and reached its counterexample cover. The maximum reported
resident set was 4,013,195,264 bytes, with zero swap and no imposed timeout or memory ceiling.

Those results apply only to this historical snapshot:

| File | Historical SHA-256 |
|---|---|
| `Cargo.toml` | `1ea006476cbd398a0879d59c47d573df4dc38fbc82cc11f1c0129be58e051aef` |
| `Cargo.lock` | `e6c55013776fcd28a9af1b707fcdd41f45a18c079a1c00999b37caf9d3be7b0f` |
| `README.md` | `dd3416e6677a37f3ac45476f155483bf405f770a374d44a371daf412230f1cf2a` |
| `src/lib.rs` | `fea94108026c13f1ad55c409e0be3006c399a6c1ce4a05d13d06e96beba0af0d` |
| `src/codec.rs` | `a73e0df69bd1921c349d315bba60331245bf397616700249b47c651910c3964b` |
| `src/composed.rs` | `c28e12c51d3c76473af5eb1491e7cb1ce5054d7908ac486628656981012b3bf7` |
| `src/protocol.rs` | `5fc8acbf6dc7c4cc00e203f134942f04e1403533690f42c050a2ceaf76297df0` |

The 30-harness/29-positive/25,011-property wording predates the live source. Preserve it only as
historical evidence and never present it as the result for the current 42-harness source.

Ten current harness names did not exist in the historical matrix:

- `codec::proofs::abort_body_tears_cannot_promote_an_incomplete_prepare_set`
- `codec::proofs::every_append_payload_tear_requires_exact_suffix_evidence`
- `codec::proofs::every_final_tear_retains_disk_decision_evidence`
- `codec::proofs::physical_all_append_candidate_fields_are_self_consistent`
- `codec::proofs::rewind_requires_exact_retained_prefix_evidence`
- `codec::proofs::root_checksum_abstraction_accepts_arbitrary_stored_checksum_bytes`
- `codec::proofs::wrapper_checksum_abstraction_accepts_arbitrary_stored_checksum_bytes`
- `composed::proofs::every_pre_guard_body_subset_with_exact_fallbacks_recovers_old`
- `composed::proofs::old_observation_requires_an_exact_fallback_decode`
- `protocol::proofs::empty_abort_body_survival_preserves_the_source_classification`

Four historical names are absent from the current source, having been renamed or strengthened:

- `codec::proofs::every_final_tear_preserves_the_exact_witness`
- `codec::proofs::physical_code_last_candidate_matches_composed_ring`
- `composed::proofs::every_pre_guard_body_subset_with_exact_authorities_recovers_old`
- `composed::proofs::old_observation_requires_an_exact_authority`

The protocol source hash also changed even though most protocol harness names did not. Historical
results therefore do not transfer to those current harnesses either.

## Exact proof boundary

Even after a fresh 42-harness matrix succeeds, the result remains bounded and decomposed:

- physical fixtures use exactly three participants, generations one through three, and four-byte
  payload pieces;
- the mixed vector is append to logical length eight/physical extent 8,200, rewind to logical
  length two/physical extent 8,196, and remove with physical extent 8,196;
- the composed model uses twelve candidate and three fallback byte-equivalence cells per participant
  rather than every physical byte;
- the protocol induction is unbounded in transition count only within its fixed one-to-three-member
  state quotient; and
- the mixed physical bridge harness is intended to prove selected field projections, while separate physical
  harnesses check the all-append and splice fixtures; no single mechanized refinement theorem maps
  every arbitrary physical disk image through every composed cell to every protocol
  transition. In particular, retained semantic provenance in the protocol layer is not derived
  from raw bytes by one end-to-end harness.

Do not describe the work as an arbitrary-participant, arbitrary-payload, arbitrary-generation,
production-Rust, filesystem, cancellation, namespace, or public-API proof. Coarser byte-equivalence
classes and collision-free checksum tokens are authorized only when they conservatively preserve
arbitrary-subset survival and the negative control; review that claim rather than assuming it.

## Checked-in R13 and review boundaries

The current implementation does not implement the generation-colored R14 root grammar or either
R14-2P prepare phase. Known independent blockers include:

- a newer tombstone can lose to an older complete ring;
- an ordinary root is not a group-bound final certificate;
- generation-independent R13 state spellings permit exact unissued authority reconstruction under
  arbitrary-subset survival;
- a rejected witness can become selectable again after payload-offset reuse;
- one fixed-chunk/integrity path can admit a noncanonical candidate;
- direct-regular-file and distinct-inode participant preconditions are not fully enforced for a
  pre-populated namespace; and
- missing retained successors remain an availability boundary.

The branch separately contains a cancellation-ownership repair for the R13 runtime. It makes
admitted namespace and publication work self-driving after caller cancellation. That repair does
not change the storage format, solve the R14 blockers, or establish R13 conformance. Review Rust and
cancellation correspondence, but do not implement production changes without explicit permission.
AIO was explicitly dropped; do not resume it.

The intended Linux profile is direct regular files on one local ext4 filesystem with normal JBD2
replay, enabled barriers, truthful successful file and directory durability operations, and no
external namespace mutation. File and directory durability are separate. The profile excludes at
least `data=writeback`, DAX, symlink participants, hard-link aliases, casefold directories,
encryption or other byte-transforming stacks not separately refined, lying device caches, media
loss, and Byzantine mutation. Short, unsupported, or error returns are not successful durability
operations. Length extension may expose zero-filled bytes where application data did not survive.
The arbitrary-subset model is a conservative specification assumption, not a claimed description
of ext4's exact journaling behavior.

## Completion plan for the next session

### 1. Reconcile before executing

- Confirm status, branch, commit ancestry, current hashes, static harness inventory, and absence of
  active proof processes.
- Read the current Kani source and diff it against the historical hashes/results. Check every new
  abstraction for under-approximation, unconstrained semantic oracles, vacuity, missing action
  branches, checksum misuse, and unsupported composition.
- Reconcile `docs/uno-model-checking.md` and `docs/uno-protocol-spec.tex` so stale historical results
  cannot be mistaken for current results. Until the current matrix exists, say **pending**, not
  passed.

### 2. Validate and run the current snapshot

Run cheap validation first from `docs/uno-kani-model`:

```sh
cargo fmt --manifest-path Cargo.toml -- --check
cargo test --manifest-path Cargo.toml
cargo clippy --manifest-path Cargo.toml --all-targets -- -D warnings
cargo kani list
```

Then freeze and record the exact current hashes and harness inventory. Run all current proof
harnesses sequentially, one at a time, with no timeout, no memory cap, no unwind override, and no
disabled checks:

```sh
cd docs/uno-kani-model
/usr/bin/time -l -p cargo kani \
  --harness '<fully-qualified-harness>' \
  --solver cadical \
  --output-format=terse
```

Use the installed Kani 0.67.0/CBMC 6.8.0 toolchain unless a deliberate, documented toolchain change
is required. Record the exact command, tool versions, hash set, per-harness result, property and
cover counts, elapsed time, and peak RSS. All positive harnesses must pass. The broken harness must
fail only its intended assertion and reach its cover. Treat any other failure, timeout, incomplete
unwind, unsupported reachable construct, or missing cover as a blocker. Do not silently weaken the
fault model or proof bounds to make a run finish. If the machine cannot provide enough memory, stop
and report that concrete blocker instead of retrying with undersized budgets.

### 3. Update artifacts and conduct fresh reviews

- Make `docs/uno-model-checking.md` an exact ledger for the final hashes. Keep older results clearly
  labeled historical if retained.
- Update the paper to match only demonstrated results and the exact model boundary.
- Rebuild the PDF from the final TeX:

```sh
tectonic --keep-logs --keep-intermediates docs/uno-protocol-spec.tex
```

- Inspect the log and references, record final page count, size, and SHA-256, then remove `.aux`,
  `.log`, and `.out` while retaining the PDF.
- Perform fresh, independent adversarial reviews of:
  1. formal soundness and composition;
  2. Linux/ext4 assumptions against primary upstream sources; and
  3. Rust correspondence and cancellation ownership at the current commit.
- Fix every specification/model/documentation defect found. If a fix changes model source, invalidate
  dependent results and rerun them. State any unresolved issue candidly as a blocker.
- Only if the cancellation correspondence conclusion depends on current test evidence, run the
  focused regressions appropriate to the platform. Do not make production Rust changes without
  authorization.

### 4. Remove the retired checker only at genuine completion

The only remaining repository paths found by a case-insensitive `quint|apalache` search at this
checkpoint were tracked files:

- `docs/uno-protocol.qnt`
- `docs/uno-quint.Dockerfile`

Local Docker artifacts also remained:

- image `uno-quint:0.32.0` (observed image ID `ff922469d7c6`)
- volume `uno-quint-cache`

After every useful obligation is represented in the validated Kani work and all final reviews are
complete, delete those repository files and exact local Docker artifacts. Verify the exact image and
volume names immediately before removal. Then search the working tree, excluding `.git`, to prove
that no case-insensitive `quint` or `apalache` trace remains. Finish with `git diff --check` and a
full status report. Do not perform this cleanup early: the old files remain recovery evidence until
the replacement is complete.

## Permissible final claim

Only after the current hash-frozen matrix and reviews complete may the final text say:

> The complete bounded Kani matrix passes for the stated R14-2P physical, composed, and lifecycle
> abstractions, and its one-phase control produces the expected mixed-vector counterexample. The
> layers are not joined by a general mechanized refinement theorem. No result establishes ext4,
> public-API, cancellation, or production-Rust refinement, and the checked-in R13 implementation is
> not claimed to satisfy the proposed R14 theorem.

Until then, replace “passes” with “is pending for the current source snapshot.”

## Copy-paste prompt for the next session

```text
Continue the UNO formal-specification work in:

  /Users/patrickogrady/code/monorepo-pr-4368

First read the repository-root AGENTS.md completely, then read this authoritative handoff completely:

  /Users/patrickogrady/code/monorepo-pr-4368/docs/uno-handoff.md

Preserve every existing change. The untracked docs/uno-kani-model directory is intentional; do not
clean, reset, or replace it from HEAD. Start by showing git status, confirming branch pr/4368 and
that commit 26a532dd6 remains an ancestor, recomputing the handoff hashes/harness counts, and checking
that no formal-model process is already running.

The handoff's central warning is binding: the recorded completed 30- and 36-harness Kani matrices
belong to older exact source snapshots. The reviewed current source has 42 harnesses and changed
codec, composed, and protocol files. Do not claim the old results for the current source. Reconcile
and adversarially review the current model before executing it, then run the current harnesses sequentially with more
than enough memory from the outset: no memory ceiling, no timeout, no low-memory calibration, no
unwind override, and no disabled checks. Record exact hashes, commands, tool versions, bounds,
per-harness results, property/cover counts, elapsed time, and peak RSS. Every positive harness must
pass; the deliberately broken one-phase variant must fail only its intended assertion and reach its
counterexample cover. Do not weaken arbitrary-subset byte survival, including for recovery and
repair writes.

Update docs/uno-model-checking.md and docs/uno-protocol-spec.tex to match only the final demonstrated
results, rebuild and inspect docs/uno-protocol-spec.pdf, and perform fresh adversarial reviews of
formal soundness, Linux/ext4 assumptions, and Rust correspondence/cancellation. Fix every
specification/model/documentation defect or report a concrete blocker. Do not change production Rust
without explicit authorization. AIO remains dropped. Never claim the current R13 implementation
satisfies the proposed R14 theorem.

Kani is the selected executable method; do not resume Quint or Apalache. Only after the Kani work
and reviews are genuinely complete, delete every Quint/Apalache repository and exact local Docker
artifact listed in the handoff, verify no trace remains outside .git, and finish with git diff
--check plus a full status report. Continue autonomously with concise progress updates until the
review is clean or a concrete blocker requires my decision.
```
