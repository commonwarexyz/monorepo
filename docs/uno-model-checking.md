# UNO bounded model checking

This is a paused validation checkpoint, not a final clean bill of health. Formal-model execution was
stopped on 6 August 2026 at the user's request so that the evidence and open obligations could be
recorded. No Quint or Apalache result from an earlier model revision is presented as validation of
the current artifact.

The executable model is [`uno-protocol.qnt`](uno-protocol.qnt). At this checkpoint its SHA-256 is:

```text
ee66bfc46088ffd9b1ccd1aa5779ff59f05bff7b44aaa72c48cd9446a33465f4
```

The artifact has 5,075 lines. The repository is on branch `pr/4368` at
`26a532dd658fbee10137ad185da087548d9b114c`; the UNO files are intentionally untracked. The target
paper is [`uno-protocol-spec.tex`](uno-protocol-spec.tex). That checked-in Rust revision has R13
roots and L14 links. The model and theorem describe a proposed R14
generation-colored, code-last-abort protocol; they do not establish that the R13 implementation
satisfies the R14 theorem.

## Toolchain and resource policy

All commands run from the repository root and use the existing pinned image
`uno-quint:0.32.0`: Quint 0.32.0 with Apalache 0.56.1. No custom state-machine checker was used,
and this work does not require building another image. The local image ID at this checkpoint is
`sha256:ff922469d7c68c97402fef13e949ed11bacc7a6879fc4834650b976665ad012d`.

The current file typechecked with the exact handoff command:

```sh
docker run --rm \
  -v uno-quint-cache:/root/.quint \
  -v "$PWD/docs":/model:ro -w /tmp \
  uno-quint:0.32.0 \
  typecheck /model/uno-protocol.qnt
```

Result: exit 0. The image entrypoint is already `quint`; adding another `quint` argument is wrong.

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

Only the typecheck above is a completed check of SHA-256 `ee66bfc...`. The final Apalache matrix was
not run before execution was paused.

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

## Checks still required before a final claim

Execution is paused with these obligations open:

1. Freeze the final `uno-protocol.qnt` and rerun its typecheck.
2. Rerun the deliberately broken generation control and require Apalache to find its counterexample.
3. Rerun the positive `uno_slot` and `uno_group` obligations on that exact file.
4. Run every pair-fixed composed stage for `AA`, `AR`, `AD`, `RA`, `RR`, `RD`, `DA`, `DR`, and
   `DD`: joint prepare/`R` classification, provisional rejection and exact-`A` old precedence,
   interrupted abort body and guard, payload evidence, final root and rewind repair, unlink issue and
   arbitrary partial survival, cleanup, and disk-derived observation.
5. Add or run explicit expected-failure cover predicates so each staged successor is demonstrably
   reachable rather than an implication passing vacuously.
6. Complete the exact-`A`-to-old observation check that was interrupted at this pause, then add the
   one-`A` ring-suppression/per-peer-normalization route or narrow the paper to match the composed
   model.
7. Record the exact final SHA-256, command, bound, result, elapsed time, exit code, and OOM status for
   every run.
8. Perform fresh formal-soundness, Linux/ext4, and Rust-correspondence/cancellation reviews after the
   final model and paper stop changing.

Until that matrix and the fresh reviews complete, the current status is “promising bounded
development evidence with known pending obligations,” not “model checked,” “proof complete,” or
“implementation conformant.”

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
