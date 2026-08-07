# UNO bounded model checking

This is a paused validation checkpoint, not a final clean bill of health. Formal-model execution was
stopped on 6 August 2026 at the user's request so that the evidence and open obligations could be
recorded. No Quint or Apalache result from an earlier model revision is presented as validation of
the current artifact.

The executable model is [`uno-protocol.qnt`](uno-protocol.qnt). At this checkpoint its SHA-256 is:

```text
dde48576de33b8993cdc340a01a9019f842ae61bb91a15c996af834f32b75965
```

The artifact has 5,089 lines. The repository is on branch `pr/4368` at
`c5597b66670f31c71795e9c2cd02d195e711af10`. Its parent
`5ecb6c433c0392cd9fc7f6d7ab9cafc1b4a69cea` tracks the UNO documentation/model artifacts on top of
Rust revision `26a532dd658fbee10137ad185da087548d9b114c`; `c5597b666` adds the reviewed
cancellation-ownership repair and regressions. The target paper is
[`uno-protocol-spec.tex`](uno-protocol-spec.tex). The reviewed Rust revision still has R13 roots and
L14 links. The model describes a proposed R14 generation-colored, code-last-abort protocol; it does
not establish that the R13 implementation satisfies those conditions. Fresh full-diff review also
confirmed that the proposed one-phase R14 target lacks exact-witness issuance provenance, so its
unconditional group crash-atomicity theorem has been withdrawn in favor of a conditional
conjecture.

## Toolchain and resource policy

All commands run from the repository root and use the existing pinned image
`uno-quint:0.32.0`: Quint 0.32.0 with Apalache 0.56.1. No custom state-machine checker was used,
and this work does not require building another image. The local image ID at this checkpoint is
`sha256:ff922469d7c68c97402fef13e949ed11bacc7a6879fc4834650b976665ad012d`.

The immediately preceding model checkpoint, SHA-256
`ee66bfc46088ffd9b1ccd1aa5779ff59f05bff7b44aaa72c48cd9446a33465f4`, typechecked with the exact
handoff command:

```sh
docker run --rm \
  -v uno-quint-cache:/root/.quint \
  -v "$PWD/docs":/model:ro -w /tmp \
  uno-quint:0.32.0 \
  typecheck /model/uno-protocol.qnt
```

Result: exit 0. A later full-diff audit found that the composed fixture's claimed generation-2
ordinary-`R` predecessor used the generation-2 `M` guard and matching CRCs. The current artifact
corrects the guard from 17 to 15, replaces the independently recomputed participant CRCs with
`243c885d` and `3592b6a0`, and asserts those bytes in `changedOffsetQuotient`. Formal execution
remains paused, so this corrected SHA-256 has not yet been typechecked. The image entrypoint is
already `quint`; adding another `quint` argument is wrong.

After early heap exhaustion showed that these formulas are memory-intensive, Docker Desktop's VM
ceiling was raised to 63,083,999,232 bytes (approximately 58.75 GiB). Subsequent heavy checks used
one checker at a time with this exact prefix:

```sh
docker run --rm \
  -e 'JVM_ARGS=-Xmx44g -XX:+UseCompressedOops -XX:ObjectAlignmentInBytes=16' \
  -v uno-quint-cache:/root/.quint \
  -v "$PWD/docs":/model:ro -w /tmp \
  uno-quint:0.32.0 \
  verify /model/uno-protocol.qnt
```

Future runs should start with that generous profile, or a larger known-safe profile if the host
ceiling is raised. Predictable low-heap calibration runs should not be repeated. A named container's
empty shell exit is not a result: inspect both its exit code and `OOMKilled`, and require Apalache's
own `[ok]` or `[violation]` line.

Results in this report use strict categories. `PASS` means a completed `[ok]` run for the exact
initializer, step relation, invariant, bound, and artifact shown. `EXPECTED VIOLATION` means
Apalache produced the intended negative-control or reachability counterexample, not merely a
nonzero process exit. `OOM` and `INTERRUPTED` are inconclusive. `PENDING` means the obligation has
not been run on the recorded artifact. A passing safety implication is kept separate from a
counterexample to a deliberately negated cover predicate, which is the evidence that a staged state
was actually reachable.

## What the three modules model

### `uno_slot`

The fast slot model separates the decoder-relevant provenance of generation, the single state/color
guard, logical body, each of the four CRC32C bytes, and the witness. Each unsynchronized write
chooses an arbitrary powerset of its addressed cells. The resulting disk image is the base for the
next recovery write, so recovery and repair may tear repeatedly. It includes an intentionally
generation-uncolored negative control and the colored, code-last-abort target.

This is a decoder-cell abstraction, not an all-112-byte codec proof.

### `uno_group`

The group model covers one to three symbolic participants, independently chosen append, rewind, and
remove operations, payload evidence, decision, interruptible abort/final repair, post-decision
rewind truncation, tombstones, and arbitrary subsets of issued unlinks. It explores control flow at
a larger participant scale but represents roots semantically.

### `uno_composed`

The composed bridge fixes exactly two participants and connects byte-derived disk evidence to the
ring/recovery control flow. It includes:

- concrete 112-byte representative R14 root headers with four independent CRC32C bytes;
- generation-1 same-slot source, generation-2 predecessor `R`, and generation-3 candidate lineage;
- an exact compact 16-byte fixed-ring witness abstraction, kept separate from the roots;
- all nine ordered append/rewind/remove operation-pair wrappers;
- a seven-byte payload store, append suffix evidence, rewind length/truncate state, and remove state;
- independent arbitrary-subset survivor masks for each participant's prepare, recovered-`R`, abort,
  final, witness, and payload writes, plus independent old/new scalar outcomes for physical file-length
  updates;
- two-participant abort-body tears over every one of the 111 non-guard addresses, followed by the
  separately issued one-byte guard;
- arbitrary none/either/both survival for the two issued namespace unlinks; and
- observations computed from decoded disk roots, exact witnesses, payload/length, and namespace
  state rather than assigned from a ghost outcome.

The recovery rule is commit-biased. Before an exact abort root exists, a rejected disk
classification is provisional: an interrupted abort-body repair can leave a byte image that now
proves the complete candidate and must be finalized as new. An exact code-last `A` takes precedence
over its stale witness and makes old irreversible. No caller mutation, destructive truncate or
overwrite, or payload/slot reuse is enabled while rejection remains provisional; proof-preserving
predecessor finalization is allowed.

The current composed old-observation cut is stricter than the paper's group-level ring breaker: its
`finishOld` action requires both participants to be locally `oldReady` (each candidate slot is exact
`A` or the canonical pre-attempt image). It does not yet validate the intermediate paper route in
which one exact `A` suppresses the ring while a peer still has a stale `B` witness and must be
normalized before that peer becomes mutable. That correspondence obligation remains pending.

More importantly, `uno_composed` fixes the ring to two participants and overlays each
generation-three witness on `zeroWitness`. A real reused same-parity slot can instead contain an
exact generation-one wrapped witness for a different participant set. The model therefore cannot
express the confirmed old-two/new-three witness splice in which exact issued generation-three roots
and candidate fields combine with an older two-member topology and byte-spliced wrapper CRCs. Its
positive results do not prove that a decoded ring is the ring actually issued by the admitted
prepare.

Some pair-fixed tractability cuts sample only addressed offsets whose target value differs from the
current value. For an overwrite this is an exact quotient: choosing survival for an
addressed-but-unchanged byte cannot change the resulting disk image, and the model checks the
`changedOffsetQuotient` equalities. Joint prepare, full 111-address abort-body, and full 112-address
final cuts retain every addressed offset, including source-equal addresses. Other focused relations
use predicate-specific dependency projections---for example none, one distinguishing offset, or all
changed body offsets---or staged successful-barrier summaries. Those runs establish only the named
projected obligation. No full crash action uses semantic byte grouping, whole-CRC atomicity, or a
prefix tear.

## Recorded Apalache evidence

### Current-file evidence

No Quint or Apalache command has completed on SHA-256 `dde48576...`. The prior `ee66bfc...` artifact
completed only the typecheck above; the final Apalache matrix was not run before execution was
paused. Independent CRC32C reconstruction confirmed that the prior predecessor bytes
`9858f7a3`/`89f6c95e` encoded guard 17 (`M`) and that the corrected bytes
`243c885d`/`3592b6a0` encode guard 15 (ordinary `R`) under the declared checksum domain.

### Post-audit staged development checks

The following commands completed on a post-audit development revision of the composed model. The
file was edited afterward, so these are useful regression evidence but not results for the current
SHA-256. Every command used the 44 GiB prefix above, followed by the exact arguments shown.

| Scope | Exact arguments after the model path | Bound | Result | Elapsed |
|---|---|---:|---|---:|
| append/rewind disk-derived decision | `--main=uno_composed --init=initAR --step=beginRecoveryAR --invariant=canonicalDecisionFromDisk --max-steps=1 --verbosity=1` | 1 | `[ok] No violation found` | 219.385 s |
| append/rewind exact final roots and rewind length | `--main=uno_composed --init=initCanonicalDecidedAR --step=completeCanonicalFinalsAR --invariant=canonicalFinalAndTruncateSound --max-steps=1 --verbosity=1` | 1 | `[ok] No violation found` | 205.868 s |
| append/remove unlink authorization | `--main=uno_composed --init=initCanonicalFinalizedAD --step=issueCanonicalUnlinksAD --invariant=canonicalUnlinkIssueScalarSound --max-steps=1 --verbosity=1` | 1 | `[ok] No violation found` | 169.928 s |
| double-remove arbitrary-subset unlink crash | `--main=uno_composed --init=initCanonicalUnlinksIssuedDD --step=crashDuringUnlink --invariant=canonicalUnlinkCrashScalarSound --max-steps=1 --verbosity=1` | 1 | `[ok] No violation found` | 167.777 s |
| clean append/remove disk decoder | `--main=uno_composed --init=initCanonicalCleanAD --step=stutter --invariant=cleanDiskDecodesAD --max-steps=1 --verbosity=1` | 1 | `[ok] No violation found` | 601.005 s |
| observation stores disk decoder outputs | `--main=uno_composed --init=initCanonicalCleanAD --step=observeCanonicalCleanedAD --invariant=canonicalObservedScalarSound --max-steps=1 --verbosity=1` | 1 | `[ok] No violation found` | 570.226 s |
| simultaneous append/rewind abort-body classification, two independent 111-address powersets | `--main=uno_composed --init=initJointAbortBodiesAR --step=beginRecoveryAR --invariant=fixedRecoveryClassificationAR --max-steps=1 --verbosity=1` | 1 | `[ok] No violation found` | 1,233.652 s |

The last run's named container reported exit 0 and `OOMKilled=false`. These shallow checks are
deliberately staged: each isolates one real arbitrary-subset write or one exact barrier-success
refinement rather than hiding the same formula behind several setup transitions.

### Deliberately broken control

At model checkpoint SHA-256
`414695120f3ae2581cea1c37a3f4980b8834c4f9c7a8d63a08fb68b62e051368`, Apalache found the intended
counterexample when generation-byte provenance was omitted. The run used a 24 GiB JVM heap:

```sh
docker run --rm \
  -e 'JVM_ARGS=-Xmx24g' \
  -v uno-quint-cache:/root/.quint \
  -v "$PWD/docs":/model:ro -w /tmp \
  uno-quint:0.32.0 \
  verify /model/uno-protocol.qnt \
  --main=uno_composed --init=initComposedRejected0 \
  --step=buggyGenerationStep --invariant=generationDecisionSound \
  --max-steps=2 --verbosity=1
```

Result: `[violation] Found an issue` after 898.690 s, expected process exit 1. This is evidence that
the negative control is live and that the property detects the known omitted-generation defect. It
must still be rerun on the final current file before final validation is claimed.

### Other evidence at checkpoint `414695...`

The same older checkpoint also produced the following recorded development results. The original
terminal record retained the scope and elapsed result but not every complete command tuple, so they
are not presented as reproducible final-file checks:

| Scope | Result | Elapsed |
|---|---|---:|
| changed-offset quotient, including prepared-to-`R` bytes | `[ok]` | 48.629 s |
| rejected-root classification, participant 0 / participant 1 | `[ok]` / `[ok]` | 71.700 s / 78.437 s |
| shared-generation abort action and discriminator, participants 0 / 1 | `[ok]` / `[ok]` | about 71 s each |
| all 111 addressed abort-body bytes exclude guard installation, participants 0 / 1 | `[ok]` / `[ok]` | about 77 s each |
| recovery after shared-generation repair, participant 0 | `[ok]` | 499.531 s |
| joint final evidence from independent five-offset `B/A` mixtures | `[ok]` | 122.524 s |
| full 112-address final action from a mixture | `[ok]` | 87.448 s |
| joint prepare with independent root/witness/payload masks and scalar old/new length outcomes | `[ok]` | 90.938 s |
| mixed prepared/ordinary-`R` recovery | `[ok]` | 502.631 s |

These runs motivated the current structure; they do not substitute for rerunning named commands on
the final file.

## Interrupted and resource-limited attempts

None of the following is a safety result:

| Attempt | Resource/bound | Outcome |
|---|---|---|
| aggregate canonical lifecycle | 24 GiB heap, depth 3 | manually interrupted at about 24 minutes after review found the aggregate path incomplete |
| two duplicated full staged formulas | 12 GiB heap | Java heap exhaustion at about 13 minutes |
| generic pair-dispatched decision | 32 GiB heap | Java heap exhaustion at about 25 minutes |
| generic pair-dispatched decision | 44 GiB heap | container cgroup OOM; `OOMKilled=true` |
| refined but still generic decision | 44 GiB heap | container cgroup OOM |
| generic unlink authorization | 44 GiB heap | container cgroup OOM |
| duplicated full observation action/invariant | 44 GiB heap | container cgroup OOM |
| exact-`A` recovery on the current development file | 44 GiB heap | stopped at the user's pause request; exit 137, `OOMKilled=false` |

The early 12/24/32 GiB attempts should not be repeated as heap calibration. The later 44 GiB OOMs
show a formula-shape problem at the available host limit, not permission to weaken the storage fault
model. The response was to use pair-fixed, staged obligations. Joint/full crash obligations retain a
genuine powerset of every addressed byte; projected and barrier-summary obligations retain only the
dependencies needed by their explicitly named invariant and are reported as such. No empty
container exit was counted as success.

## Fresh Linux/ext4 and Rust/cancellation reviews

Fresh read-only reviews were completed on 6 August 2026 with model execution still paused.

The Linux/ext4 review checked the paper against the upstream Linux
[`fsync(2)`](https://man7.org/linux/man-pages/man2/fsync.2.html),
[`pwritev2(2)`](https://man7.org/linux/man-pages/man2/pwritev2.2.html),
[ext4/JBD2](https://docs.kernel.org/filesystems/ext4/journal.html),
[ext4 mount and data-mode](https://docs.kernel.org/admin-guide/ext4.html), and
[fscrypt](https://docs.kernel.org/filesystems/fscrypt.html) documentation. The file and directory
barrier claims, `RWF_DSYNC` range obligation, normal-JBD2-replay boundary, and exclusions for
`data=writeback`, disabled barriers, and DAX remain supportable. The paper was tightened to:

- define zero-fill when a length extension survives without every addressed byte;
- say that `RWF_DSYNC` proves at least the completed range but may persist unrelated data, and that
  short or unsupported/error returns cannot be treated as synchronized success; and
- exclude ext4 casefold directories, fscrypt/inline encryption, and other byte-transforming stacks
  from the initial profile unless they separately refine the old-or-issued application-byte model.

The arbitrary-subset byte envelope remains an explicit conservative device/application-visible
assumption, not a property proved by ext4 journaling. The composed model already uses zero as the
old image at append offsets beyond the old length and chooses physical length independently; no
Quint source change was needed for the zero-fill clarification.

The initial Rust correspondence/cancellation review used tip `5ecb6c433`, whose Rust tree is exactly
`26a532dd6`. It found that detached batch workers and `recover_namespace` already retained owned
namespace authority, but four observer-owned paths did not: Tokio open/scan recovery, Tokio remove
through unlink/directory durability/invalidation, ordinary Tokio recovery `set_len`, and direct
synchronous publication while Tokio or io_uring materialized an older carried group.

After explicit authorization for Rust implementation work, the reviewed branch repairs those
ownership gaps:

- Tokio `open_versioned_inner`, `scan`, and `remove` move their owned namespace guard, storage
  handle, and owned arguments into a self-driving Tokio task. Caller cancellation drops only the
  result observer; the task retains the guard through recovery, namespace mutation, directory
  durability, generation/V2-state invalidation, and cleanup.
- The runtime-agnostic UNO wrapper routes admitted direct synchronous publication through the same
  backend `Publisher::spawn` mechanism used by `start_sync`. Its task owns the armed mutation guard,
  so cancellation cannot release either backend's publication namespace while carried-decision
  materialization continues.
- Test-only gates cover queued open/scan/remove work, the exact post-unlink/pre-directory-sync
  removal boundary, the exact recovery `set_len` boundary followed by an acknowledged append, and
  carried-group materialization during a direct synchronous write. The publication regression is
  compiled and run for both Tokio and Linux io_uring.

This closes the concrete cancellation races recorded by the initial review, subject to the paper's
fail-stop rule for runtime shutdown, task panic, or indeterminate mutable I/O errors. It does not
repair the R13 format/provenance, abort-normalization, integrity, aliasing, or availability blockers
and does not establish that the current implementation refines the proposed R14 theorem.

### Rust and Linux validation

Formal-model execution remained paused throughout this Rust-only repair;
`docs/uno-protocol.qnt` was not changed. On the macOS arm64 host (`rustc 1.97.1`):

```sh
cargo fmt --all -- --check
git diff --check
just test -p commonware-runtime test_canceled_
just test -p commonware-runtime
cargo clippy --locked --all-targets -p commonware-runtime -- -D warnings -A clippy::missing-const-for-fn
```

Results: formatting and diff checks exited 0; all five cancellation tests passed; the full runtime
suite passed 841/841 tests with four profile-filtered skips in 24.939 seconds; and the
toolchain-qualified Clippy command exited 0 in 8.52 seconds. The unsuppressed repository command

```sh
just clippy -p commonware-runtime
```

exited 101 before reaching `commonware-runtime`: Rust 1.97.1 reports the pre-existing
`clippy::missing_const_for_fn` lint at `cryptography/src/crc32/mod.rs:146`. That file is outside this
change. The qualified command suppresses only that named lint and leaves every other warning denied.

Docker Desktop provided a Linux 6.12.76 arm64 kernel, 18 CPUs, and 63,083,999,232 bytes
(approximately 58.75 GiB) of container memory. The final Linux io_uring regression ran with the
repository mounted read-only and Docker's seccomp filter disabled for `io_uring_setup`:

```sh
docker run --rm --platform linux/arm64 --security-opt seccomp=unconfined -v "$PWD":/workspace:ro -v commonware-cargo-registry:/usr/local/cargo/registry -v commonware-cargo-git:/usr/local/cargo/git -v commonware-pr4368-target:/target -w /workspace -e CARGO_TARGET_DIR=/target rust:1.96-bookworm sh -c 'uname -srmo && rustc --version && cargo test --locked -p commonware-runtime --features iouring-storage test_canceled_direct_publish_retains_namespace_until_materialized -- --nocapture'
```

Result: exit 0 with `rustc 1.96.1`; the Linux-only io_uring regression passed 1/1, with 953 tests
filtered out. Enabling `iouring-storage` initially exposed three Tokio-specific coordinator tests
and one Tokio-only helper that were not feature-gated even though the Tokio storage module is
mutually exclusive with io_uring storage. The final test-only cfg correction excludes those tests
from the io_uring matrix without changing either backend's production behavior.

Both Linux feature matrices then passed Clippy with the same unrelated CRC-helper lint suppressed:

```sh
docker run --rm --platform linux/arm64 --security-opt seccomp=unconfined -v "$PWD":/workspace:ro -v commonware-cargo-registry:/usr/local/cargo/registry -v commonware-cargo-git:/usr/local/cargo/git -v commonware-pr4368-target:/target -w /workspace -e CARGO_TARGET_DIR=/target rust:1.96-bookworm sh -c 'rustup component add clippy && cargo clippy --locked --all-targets -p commonware-runtime --features iouring-storage -- -D warnings -A clippy::missing-const-for-fn && cargo clippy --locked --all-targets -p commonware-runtime --features iouring-network -- -D warnings -A clippy::missing-const-for-fn'
```

Result: exit 0; the storage and network feature checks completed in 6.43 and 6.86 seconds.
Without the single named suppression, Linux Clippy exits 101 on the same unchanged
`cryptography/src/crc32/mod.rs:146` lint.

Fresh post-repair adversarial reviews then found no Linux/ext4 paper defect and no actionable Rust
cancellation defect. The Linux review rechecked `RWF_DSYNC`, short-write handling, file versus
directory barriers, JBD2 replay, delayed allocation/unwritten zero-fill, casefold, fscrypt, DAX, and
the explicit truthful-device assumptions against upstream Linux sources. The Rust review traced
every new ownership boundary and all Publisher implementations. Its sole documentation finding was
that the Linux command/result had not yet been placed beside the execution claim; the ledger above
resolves that finding. Residual limits remain explicit: no power-cut ext4 refinement test was run,
the model contains no syscall/cancellation state, and runtime shutdown, panic, or indeterminate
mutable-I/O errors remain subject to fail-stop recovery.

A subsequent fresh full-diff audit found one formal fixture defect: the generation-2 predecessor
was described as ordinary `R` but encoded with the generation-2 `M` guard and CRCs. The current
source contains the correction and explicit fixture assertions. That source change invalidates the
prior typecheck as current-file evidence and requires a new final full-diff formal review after the
paused checker matrix resumes. The same audit found no additional actionable Rust, Linux/ext4,
ledger, or paper defect. It also identified that seeding a generation-three witness overlay from
all-zero bytes does not explore stale generation-one witness-byte mixtures. A later independent
full-diff review converted that concern into the confirmed theorem blocker below.

The first post-fix full-diff audit confirmed the corrected guard and CRCs but found one stale paper
sentence that still attributed the repaired namespace-ownership gap to the current branch. The
refinement remark now scopes that gap to the `26a532dd6` R13 baseline and distinguishes the reviewed
cancellation repair from the remaining format, authority, witness, integrity, and namespace-shape
counterexamples.

### Confirmed witness-provenance counterexample

The final frozen-state review and a separate byte-level verifier independently confirmed that the
one-phase proposed target can recover a mixed vector without a CRC collision. Start with a durable
generation-one independently finalized group `H={a,b}`, select generation-two ordinary `R`
predecessors, then admit generation-three append group `G={a,b,c}` into the reused same-parity
slots. Crash after the full-slot writes are issued but before any `G` prepare barrier succeeds.
Arbitrary per-address survival can retain exact issued `B3` roots and new candidate/payload fields
at `a,b`, retain `H`'s group ID/count/ordinals and `a<->b` topology, and retain no `G` update at `c`.
Recovery accepts the exact synthetic two-member ring, publishes `a,b`, and leaves `c` old.

The independent fixture uses equal-length 338-byte links. Its old/new/hybrid wrapper CRC32C values
are `47ad25a0`/`c3bcb36c`/`47ad256c` for `a` and
`73a8b16e`/`47775580`/`7377b16e` for `b`; every hybrid checksum byte is selected from the old or
issued-new checksum at that address and exactly checks the hybrid link. Relative to each 2 KiB
slot, the new-byte survivor masks are:

```text
a: 7,15,32-35,44-111,127,187,203,211,228-231,240-307,315,323,340-343,352-419,436-439
b: 7,15,32-35,44-111,125,187,203,211,228-231,240-307,315,323,340-343,352-419,436-439
c: empty
```

The trace uses consecutive generations, distinct fresh group IDs and incarnations, canonical slot
and link encodings, valid payload descriptors, and no external namespace mutation. It is exact
reconstruction, which the paper's trusted-medium assumption explicitly requires the protocol to
handle. No Quint or Apalache command was run for this review.

The smallest complete repair under the existing noncryptographic fault model is two-phase,
code-last batch prepare: synchronize the candidate payload/length obligation and every non-guard
byte of the exact 2 KiB slot, then issue and synchronize only the generation-colored `B` guard.
That adds a second ordered durability layer. Preserving one layer requires a new root-to-witness
splice-binding commitment and a stronger computational assumption; otherwise the
admitted-but-unacknowledged atomicity guarantee must be withdrawn. This architecture choice is the
current concrete blocker.

### Paper rebuild

The paper was rebuilt after the review corrections with:

```sh
tectonic --keep-logs --keep-intermediates docs/uno-protocol-spec.tex
```

Result: exit 0. The final PDF has 25 pages, is 257,917 bytes, and has SHA-256
`68b469865c29dc74a3f7ebcd6109a651bde927f37df37fccb14d81c3e3a4a354`. The compiler emitted
underfull-box layout warnings but no unresolved-reference, overfull-box, or compilation error.
Generated `.aux`, `.log`, and `.out` intermediates were inspected and then discarded; only
[`uno-protocol-spec.pdf`](uno-protocol-spec.pdf) is retained.

## Checks still required before a final claim

Execution is paused with these obligations open:

1. Choose the witness-provenance contract: two-phase code-last prepare, a splice-binding
   commitment with an explicit computational assumption, or a narrowed admitted-window guarantee.
2. Extend or replace `uno_composed` with exact old `H={a,b}` and new `G={a,b,c}` physical witnesses,
   all wrapper/link/CRC bytes independently tearable, and observations for all three admitted
   participants. The unordered control must reproduce the confirmed mixed vector; the selected
   repair must block it.
3. Freeze the resulting `uno-protocol.qnt` and rerun its typecheck.
4. Rerun the deliberately broken generation control and require Apalache to find its counterexample.
5. Rerun the positive `uno_slot` and `uno_group` obligations on that exact file.
6. Run every pair-fixed composed stage for `AA`, `AR`, `AD`, `RA`, `RR`, `RD`, `DA`, `DR`, and
   `DD`: joint prepare/`R` classification, provisional rejection and exact-`A` old precedence,
   interrupted abort body and guard, payload evidence, final root and rewind repair, unlink issue and
   arbitrary partial survival, cleanup, and disk-derived observation.
7. Add or run explicit expected-failure cover predicates so each staged successor is demonstrably
   reachable rather than an implication passing vacuously.
8. Complete the exact-`A`-to-old observation check that was interrupted at this pause, then add the
   one-`A` ring-suppression/per-peer-normalization route or narrow the paper to match the composed
   model.
9. Record the exact final SHA-256, command, bound, result, elapsed time, exit code, and OOM status for
   every run.
10. Perform the fresh formal-soundness review after the final model stops changing. Repeat the
   Linux/ext4 or Rust/cancellation reviews after any relevant paper, platform-envelope, or Rust
   change; the post-repair reviews above cover the current paper and Rust diff.

Until the witness-provenance architecture is selected, modeled, and re-reviewed, the current status
is “confirmed target-protocol blocker,” not “model checked,” “proof complete,” or “implementation
conformant.” The reviewed Rust change closes the concrete
cancellation-ownership races above, but the remaining R13/R14 correspondence defects are
independent implementation-conformance blockers even if every model obligation later passes.

## Explicit abstraction limits

Even a clean final matrix would remain bounded evidence for:

- exactly two participants in the composed bridge and one to three in the symbolic group model;
- one generation-1/generation-2/generation-3 lineage window;
- a seven-byte representative payload;
- physical file-length persistence as an independent old/new scalar rather than a byte-level model
  of filesystem inode metadata;
- focused step relations that may use predicate-specific dependency projections rather than the
  corresponding full addressed-byte powerset;
- one fixed reciprocal compact-ring encoding, not the complete physical L14 codec and padding;
- local old observation only after both participants are `oldReady`, not the paper's intermediate
  one-`A` ring-break state;
- a closed-world two-name namespace with partial unlink, but no inode recreation, alias, symlink,
  rename, or directory-journal state machine; and
- protocol transitions, not Linux/ext4 delayed allocation, JBD2, syscall/cancellation ownership, or
  a refinement mapping to the Rust implementation.

CRC32C is treated as collision-free over externally checked representative byte vectors. Passing
Apalache bounds cannot establish arbitrary participant count, arbitrary generations, codec
conformance, liveness, ext4 behavior, or Rust/API reachability.
