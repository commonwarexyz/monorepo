# Candidate C (the WAL backend): implementation plan

## 0. What this plan is

The build plan for candidate C: blobs stay ordinary files, and one write-ahead log per family owns the namespace, the atomic blobs' logical lengths, and (transiently) small payloads. C's purpose is multi-blob atomicity -- a crash exposes either all of a logical group's changes or none -- delivered without a chunk allocator, and with migration that avoids payload copying for the common case (V1 adoption is a header stamp; V0 relocation and below-floor promotion do copy, once, and are rare).

The specification is `wal-backend-design.md` revision 2, in worktree `4368`. That document is the *what*. This is the *when, in what order, and how do we know it works*.

Revision 2 leaves seven design questions open, and this plan adds six more plus one decision that is yours rather than mine. Rather than gating the build behind a design phase, each question is assigned to the phase that owns it and must close before that phase's code is written. They are listed inline below and collected in §10.

## 1. Where this sits

**Terms.** A *family* is the set of partitions that must be able to transact together, and it is the unit of WAL ownership: one `.wal/{family}.cww` per family, one committer, one failure domain. Families are declared in config (exact-partition rules, optional prefix rules) and a partition's existing catalog residency is authoritative once set. Cross-family transactions are rejected. The intended family is one logical structure -- an oversized journal's index plus values, a QMDB's log plus merkle components -- not a whole node.

**On main.** `Storage` is `open` / `open_versioned` / `remove` / `scan`. `Blob` is `read_at` / `read_at_buf` / `write_at` / `resize` / `sync` / `start_sync` (`runtime/src/lib.rs:607-803`). No batch trait, no atomic blob, no multi-blob commit group. Backends are `tokio`, `iouring`, `memory`, plus the `metered` / `audited` / `faulty` wrappers. The shared conformance suite is `runtime/src/storage/tests::run_storage_tests` (`runtime/src/storage/mod.rs:91`). Blob files carry a V1 header: 4 KiB region, data at 4096; V0 is the bare 8-byte prelude with data at offset 8 (`storage/header.rs:149`, `:286`).

**On this branch.** The volume backend (`runtime/src/storage/volume/`, 4,171 lines, 734 runtime tests green), plus `volume-design.md`. It collapses concurrent syncs within a partition to one barrier and moves blob namespace operations off the filesystem, requiring no consumer changes. It has no transactions and was designed not to have them. C does not replace it; §11 forces that decision explicitly.

**Unmerged.** PR #4368 carries the atomic and batch trait surface plus a federated per-file backend. The traits are backend-agnostic and C needs them. The backend stays unmerged as the audited reference, with one reversal condition: if a consumer needs multi-blob atomicity before C reaches milestone M2, land the federated backend as an interim. ALPHA permits replacing it later without a migration path.

**The master rule (M), because everything below depends on it.** A byte of blob-file content, a dentry, or a directory may become *load-bearing* -- meaning some durable WAL record or snapshot asserts state that depends on it -- only after a completed barrier on the file or directory holding it, issued and completed before the asserting record was written.

Revision 2 exists because two adversarial reviews found 25 findings in revision 1, four of them critical and all four the same bug: a mechanism that made file state load-bearing without that barrier. Revision 2 promoted M to the design's master rule and made every mechanism cite it. Phase A turns it into a machine-checked invariant.

## 2. The trait surface (phase T)

C is a backend. The traits land independently of which backend implements them, and this phase is coordination on Patrick's PR rather than code. It blocks phases E through H, so open it first even though nothing depends on it yet.

**What lands:** the atomic blob trait, the batch trait with `start_apply` returning a self-driving handle whose `Ok` proves durable commitment, and the generation-token discipline that makes stale and foreign handles fail closed.

**Amendments before the traits freeze:**

- `WriteOptions` on `append`.
- **Open question T1: the `Blob` contract on atomic blobs.** Not "can sync work at all" -- it can, cleanly: `sync` on an atomic blob can be *defined* as a transaction of one Publish (`sync(b) == apply([Publish(b)])`), which is conceptually what #4368 already does and what this plan's own kernel critique of it proposed. The real questions are narrower and all trait-level: should generic `Blob::sync` publish the pending epoch (over-delivery) or error; does `start_sync` return its handle before durability; which positional writes and resizes are rejected on an atomic row; and does `open_versioned` of an atomic row return a narrowed handle (spec §2 says yes). Settle them in the *trait*, not per backend -- the federated backend needs the same answers.
- A typed batch-rejection error rather than a bare `Io(InvalidInput)`.
- Descriptor and record room reserved for `Create` in batches. C makes creation-in-batch nearly free (one more record) and the trait must not foreclose it.
- Replace the deletion-batch documentation at `runtime/src/lib.rs:821-823`, which assumes eager unlink, with normative lazy semantics rather than a loosened sentence: completion means catalog truth (the name is free, the generation is invalidated, handles degrade to read-after-remove); the physical dentry may persist indefinitely; same-name recreation eagerly unlinks the predecessor before the create acknowledges, safe because the DeleteBlob record is durable first (spec §8). Each clause gets a conformance test, because the federated backend behaves differently and consumers must be able to rely on the weaker contract.
- **Open question T2: where the pipelining gap lives.** Spec §3 has `start_apply` validate, stage, await the entire G1-G5 cycle, then return an already-resolved handle -- which satisfies the letter of the trait and provides no useful asynchronous gap at all, as the external review observed. The alternative is volume's `start_sync` shape: return after validation and staging, and let the *handle's* resolution prove durable commitment. That moves the durability proof from `start_apply`'s return to the handle, which is a change to the trait's stated semantics, not a backend detail -- it belongs in the phase T conversation next to T1.

**Fallback if #4368 stalls:** define the traits in a separate small PR and let the federated backend adopt them later. Worse for review, but it unblocks.

## 3. Type design

The specification describes mechanisms. This section fixes the types that carry them, because that is what decides whether the result is elegant or a pile of `u64`s guarded by comments. Eight decisions, all made here rather than left to implementation.

### 3.1 `Frontier` and `Pending`: trust, not just durability

An atomic blob tracks four offsets. Revision 2 names three of them `committed_len`, `applied_len`, `durable_applied`, and the external review of this plan caught both of us -- spec and plan -- conflating two different things inside the third. `durable_applied` is defined in spec §6 as physical fdatasync coverage, but lowered by a *logical* CommitAtomic at replay in spec §2. Those are different quantities, and the scenario that splits them is now this section's centerpiece:

```text
committed = applied = durable = 100
publish a rewind to 50            (fence lifts; no file operation has run)
append 10 inline bytes            (offsets 50..60, WAL-resident)
publish
```

The overlay must now cover `[50, 60)`. But if its lower bound is physical durability, still 100, the range is `[100, 60)` -- nonsense. The repair is one concept, split in two:

- **physical durability**: which file bytes a completed fdatasync covers. Never decreases without a real truncate.
- **trust**: the prefix of the file recovery may serve as current logical content. A committed rewind lowers it immediately, with no file operation at all.

```rust
/// The four offsets of one atomic blob, and the only place their ordering is enforced.
struct Frontier {
    visible:   u64,  // end of staged content; what reads see
    committed: u64,  // published by a durable record; WAL truth
    applied:   u64,  // prefix of CURRENT-GENERATION content physically written to the file
    trusted:   u64,  // prefix of `applied` recovery may serve: durable AND current-generation
}
```

`applied` is generation-scoped on purpose: a rewind drops it, because bytes above the cut are stale-generation even though they physically exist. The physical file being longer than everything is not an offset in the lattice at all -- it is a scheduled obligation:

```rust
/// Work a rewind created that has not discharged yet. Both may be set at once.
struct Pending {
    fence:    Option<u64>,  // rewound below `committed`; lifts when the rewind publishes
    truncate: Option<u64>,  // file physically longer; must run before the next apply
}
```

The invariants, now unconditional except the fence:

- `trusted <= applied <= visible`
- `trusted <= committed`
- `committed <= visible`, unless fenced -- the fence is what makes a staged rewind below the published length well-formed.
- the overlay covers `[trusted, committed)`, always a real range.

The governing principle -- and it is the inverse of what the first draft of this section claimed: **lowering trust is always free; raising trust requires proof.** `trusted` rises to `n` only when bytes `[trusted, n)` were applied after the last rewind that cut below them and a `Barrier` (§3.2) completed after those writes. It falls whenever a rewind publishes. Physical durability never justifies trust by itself, which is exactly the lesson of the scenario above.

Walking the scenario through the type: `rewind(50)` clamps `visible` and `applied` to 50, sets both obligations. The rewind's publication sets `committed = trusted = 50` and lifts the fence. The inline append raises `visible`, its publication raises `committed` to 60, `trusted` stays 50, overlay is `[50, 60)`. The pending truncate runs before any later apply (spec §6's ordering rule, now a precondition on `apply` rather than a discipline), so stale generation-old bytes can never sit where a wave would cover them. At the next checkpoint, K1 materializes the overlay into the file, K2's barrier covers it, and `trusted` catches up.

Snapshots and the recovery disposition table read `trusted` and nothing else; there is no accessor for `applied`. The full transition table -- concurrent clones, a second rewind stacking on an undischarged `Pending` -- is deliberately not frozen here: it is phase E's entry criterion. The scenario above needs inline records to exist, so it is phase F's first named test; its bulk-only cousin (rewind, then bulk reappend over the same range) is phase E's. This model change is also a spec amendment, recorded as such.

One more type belongs here, because its shape is a correctness fence rather than a convenience. The overlay holds committed bytes that live only in the WAL, covering `[trusted, committed)`. Inline appends are append-only by definition, so that range is always **one contiguous run** -- the overlay is `Option<(u64, Bytes)>`, never a map of scattered ranges.

That is not a simplification for its own sake. A map would make it representable for an inline record to assert content in the middle of a blob, which is the hazard that makes the equivalent mechanism in a chunked volume need two-pass recovery over ownership. Keeping the type contiguous is what confines C's inline hazard to a blob's own tail, where overlay-ordered replay handles it. Any future pressure to widen inlining beyond append-only tails shows up as a change to this type, which is exactly where it should be visible.

### 3.2 `Barrier`: rule M as a value, not a discipline

Those four criticals were not "waved to the wrong offset." They skipped the wave entirely. That bug class dies if a barrier is a value you must hold:

```rust
/// Proof that a synchronization wave completed. Produced only by the committer's G2.
struct Barrier { /* covered set: file -> offset */ }
```

Records that assert file state take one by reference at construction: `CommitAtomic::new(blob, len, &barrier)` cannot be called without a completed wave in hand, and `Frontier` cannot raise `trusted` without one either. Be precise about what the token proves, because the external review is right that an offset prefix is not enough: a wave happened, before the record. It does not prove the covered bytes are the generation the record asserts (a rewind-and-rewrite below the covered offset would stale it), and directory durability is not an offset at all. Those checks are the checker's job. The honest division: the token makes "skipped the wave entirely" -- the shape of all four rev-1 criticals -- unrepresentable; the checker proves the wave covered the right *content*.

The checker itself is a `Medium` wrapper, `Checked<M>`, in the mold of the `audited` and `faulty` storage wrappers this repo already has. It tracks, per file, a mutation generation (bumped by every write and truncate) and the (offset, generation) pairs each completed fdatasync covered, plus dentry and directory identity for renames and dir fsyncs. A record's assertions name content -- file, range, generation, dentries -- and admission rejects any assertion the wrapper has not seen covered *at that generation*. Because it wraps the trait rather than living inside the simulator, it composes over `Sim` in every crash test and over `Fs` in integration tests -- rule M stays machine-checked against real files, not just simulated ones.

### 3.3 Two blob cores; the handle surface belongs to T1

The first draft of this section decided the handle surface unilaterally -- sibling types, cross-kind opens as errors -- and the external review correctly caught it contradicting both of its own dependencies. PR #4368's traits make `AtomicBlob` extend `Blob`, and spec §2 says a plain `open_versioned` of an atomic row *succeeds* with narrowed behavior (only `open_atomic_versioned` of an ordinary row errors), precisely so that generic code that reopens blobs by name -- section discovery, recovery walks, the paged writers -- keeps working over migrated partitions. Sibling types with typed cross-kind errors would break every such caller. That trade is the substance of T1, and this plan does not get to pre-empt it.

What this plan does decide is the layer underneath: two *cores*, not one struct with a `kind` field. The ordinary core is today's contract byte for byte and contains no atomic code to regress; the atomic core owns a `Frontier`, the tail buffer, and the publication path. Whatever handle shape T1 settles on -- supertrait, narrowed `Blob` impl, or both -- is a thin view over those cores. The one hard requirement the cores impose on T1: every mutation of an atomic core routes through its publication path, so a narrowed `Blob` handle can *reject* operations but can never bypass the frontier.

### 3.4 `Frame`: four decode outcomes

Record decoding must separate what can be separated. Volume's `Frame::Record | End | Corrupt` (`format.rs:348-352`) folds a clean zero terminator and a torn tail into one `End`, and the external review is right that the information is free at decode time. C uses four:

- `Record` -- valid frame.
- `CleanEnd` -- leading zero byte: nothing was ever written here.
- `TornTail` -- short frame or checksum failure: a write started and did not complete. (A bit-flip under a valid length also lands here; that is inherent, and stopping replay is the safe direction for both.)
- `Corrupt` -- a frame whose checksum *passes* but whose body is malformed. Tearing cannot produce this; it is always a hard error.

One pushback on the review, though, because it affects recovery cost claims: `CleanEnd` does **not** license skipping the tail scrub. A drain is one contiguous write, and byte-granularity tearing can persist *later* bytes of that write while the first byte stays zero -- a clean-looking end with a live record fragment past it, waiting to splice onto the next epoch's appends. The scrub is therefore unconditional; what bounds it is that only the final unacknowledged drain can tear, so the window is one maximum drain, read-first so clean opens write nothing. The variant split buys triage (`Corrupt` is an alarm, `TornTail` is Tuesday), not a scrub exemption. Volume's `record_torn_tail_is_end` / `record_corruption_is_not_end` tests carry over with the sharper names.

### 3.5 The `Medium` seam, and why it differs from volume's

Volume is `Storage<S: crate::Storage>`: it composes over another backend, so its whole I/O surface is the public `Blob` trait and deterministic crash testing came free. C cannot do that. Its correctness argument is *about* per-file barriers, dentries, and directory durability, none of which the `Blob` trait exposes. So C is `Storage<M: Medium>` over a lower seam: create, open, read, write, fdatasync, rename, unlink, set_len, directory fsync.

That is a real cost -- a new trait, two implementations -- bought for two real things. First, the simulated medium runs the actual protocol rather than a model of it, which is what makes the rule-M checker and deterministic mid-batch crashes possible at all. Second, the protocol exists *once*: per-runtime differences (tokio's blocking pool, io_uring submission) live inside `Fs` variants below the seam, so there are no twin orchestrators to keep in sync -- the exact disease finding D13 diagnosed in #4368, where the memory backend modelled a protocol the real backends implemented separately.

Mechanics, fixed now because they are performance decisions: `Medium` methods are async in the repo idiom (`impl Future<Output = Result<T, Error>> + Send`), writes take `impl Into<IoBufs>` so multi-buffer writes are vectored rather than coalesced by copying, and the trait is constructed by runtime-owning code -- paths, the sidecar lock, and a committer spawn function are injected exactly as volume injects its `Spawn` (`volume/mod.rs:66`). Generic code never discovers filesystem paths and never names a runtime.

### 3.6 Naming decisions

One vocabulary per concept, audited against the module family:

- **`adopt` and `promote`.** Revision 2 calls two different conversions `AdoptBlob` and `MigrateBlob`, which read as synonyms. Adopt is a pre-existing file joining the catalog; promote is an ordinary blob becoming atomic. Rename the record to `PromoteBlob` and propose `promote_atomic` for the trait method in phase T.
- **Watermarks lose their suffixes** and become the parallel set of §3.1: `visible`, `committed`, `applied`, `trusted`.
- **`wave` is the only word for G2**, `barrier` the only word for a completed fdatasync, and `flush` appears in measurement prose only. Revision 2 uses all three loosely; the code should not.
- **`family` is the transaction and failure domain, `partition` the namespace**, and neither is ever called a volume, because that name belongs to the other backend.

### 3.7 What is shared with the volume backend, and when that is decided

Volume already contains a committer with group commit, parity roots, checkpoint-with-extent, three-outcome record decoding, and a crash harness with the three-valued model. C rebuilds all of it. Roughly 1,500 lines are plausible extraction candidates.

Do not extract speculatively. Two backends with one shared abstraction, designed before the second one exists, is how the wrong abstraction gets frozen. Build C's versions, and revisit at the end of phase C, when both shapes are visible and the differences are facts rather than guesses. The crash harness and the three-valued model are the likeliest genuine wins; the committers are likeliest to look similar and behave differently.

### 3.8 Hot paths, with budgets

Elegance in this codebase is measured on the hot path. Three paths matter; their budgets are fixed now so every later choice is checked against them.

1. **Inline publication** (the consensus-vote shape, the hottest durability event in the system). The caller's payload arrives as `Bytes` and is staged by reference, not copied. Publication encodes one record frame into the committer's scratch buffer -- owned by the committer, cleared between cycles, never reallocated in steady state -- and the WAL append is one vectored write, so payload travels caller's `Bytes` to kernel with no intermediate copy. Budget: one blob-lock acquisition to stage, one WAL flush for the whole drain, zero steady-state allocations beyond what the record set itself requires.

2. **Ordinary sync.** Not a hot path *here*, by construction: it never enters the committer, so its budget is "byte-for-byte today" and phase C's benchmark row enforces exactly that.

3. **Atomic read.** Resolve which of the tail buffer, the overlay, and the file serve each span under one blob-lock acquisition, then do the file I/O with the lock released -- volume's resolve-then-pin pattern (`volume/blob.rs:68`). This is a lesson already paid for: 4368's atomic read held the state mutex across the physical read and serialized every reader on the blob (finding R7). The resolve/IO split is the structural fix, adopted from day one. Single-source reads pass the caller's buffer straight through; only genuinely multi-source reads assemble into scratch.

One shared rule underneath all three: **no lock is ever held across a `Medium` call.** Locks order state transitions; I/O happens on resolved, pinned state. The committer is the one component that serializes WAL I/O, and it does so by being a single task, not by holding locks.

## 4. Module plan

`runtime/src/storage/wal/`, joining the existing `stability_scope!(ALPHA { ... })` block at `runtime/src/storage/mod.rs:48`. Each module's exposed surface, not just its filename:

| module | exposes | owns the invariant that |
|---|---|---|
| `mod.rs` | `Storage<M>`, `Config` | a partition resolves to exactly one family, stickily |
| `medium.rs` | `Medium` trait, `Fs`, `Sim`, `Checked<M>` | nothing above it can perform I/O another way |
| `format.rs` | `Header`, `Root`, `Record`, `Frame` | bytes decode to exactly one of record / clean end / torn tail / corrupt |
| `catalog.rs` | `Catalog`, `BlobId`, `Generation` | ids are monotonic and never reused; stale handles fail closed |
| `state.rs` | `Frontier`, `Pending`, `Overlay`, `TailBuffer` | trust never rises without a `Barrier`; only `trusted` is reachable by snapshots; the overlay is one contiguous tail run |
| `wal.rs` | `Family` (open, recover, replay, checkpoint) | a valid root always names a complete snapshot |
| `committer.rs` | `Committer`, `Barrier` | no record is written before its wave completes; buffers are reused, never regrown per cycle |
| `blob.rs` | `Blob`, `AtomicBlob` | an atomic blob cannot be mutated except through its publication path |
| `adopt.rs` | `adopt`, `extract` | a legacy file is either intact or fully converted, never between |
| `batch.rs` | `start_apply` | validation completes before any side effect |
| `tests/` | conformance, crash harness, three-valued model | -- |

Shared files touched: `runtime/src/storage/header.rs` (V3 layout, see phase D), `runtime/src/storage/mod.rs` (registration), `runtime/src/lib.rs` (traits, via phase T).

Telemetry: the `metered` wrapper already supplies external per-operation metrics, and the volume backend ships without its own registry, so C does not need one to be consistent. It should still expose committer-internal series that no wrapper can see -- drain depth, wave width, flush counts by class, checkpoint pause, lazy-queue backlog -- because those are what a p99 regression gets diagnosed from. Keep the cardinality small.

## 5. Build phases

One branch, good commits, decomposed into PRs after the work converges. Sizing is rough non-test lines plus a risk grade, not calendar time.

### Phase A: the medium seam, WAL format, and recovery

*~1,200-1,800 lines. Risk: medium. The format is a one-way door once anything writes it.*

Two sub-milestones with a real seam between them, because the second is rewritable and the first is not: **A0** is `Medium`, `Fs`, `Sim`, and `Checked<M>` -- the ground everything else stands on -- and **A1** is the format, replay, and checkpoint. A0 merges before A1 grows on top of it.

One deliberate scope cut, from the external review's observation that checkpoint K1 applies overlay tails that do not exist until phase E: A1 builds the checkpoint for **namespace-only state** -- catalog snapshot, extent rotation, root flip -- and phase E extends K1/K2 with overlay materialization when the overlay is real. Building the "complete" checkpoint in A would mean writing it against imagined types and rewriting it in E.

Builds `Medium` (§3.5), `Frame` (§3.4), and the format types. In order:

1. `Medium` plus `Fs`, `Sim`, and the `Checked<M>` wrapper. `Sim` models the crash rule exactly: a completed fdatasync on a file is a barrier *for that file only*; between barriers any subset of issued writes to it may survive with arbitrary byte-granularity tearing; there is no cross-file ordering whatsoever.
2. WAL header page, parity root slots, record framing (varint length, body, CRC32C salted with WAL incarnation and epoch nonce, exact-increment seq, `TXN_END` buffering, `CONTINUED` reassembly).
3. The record set of spec §2, under the §3.6 naming.
4. Replay: catalog and overlay construction in journal order, end-of-log via the durably-zeroed extent, torn-tail versus corruption discrimination through `Frame`.
5. Checkpoint K1-K5.

**Open question A1: record-extent placement and fragmentation policy.** Roots locate the record space by offset and length, so each checkpoint may place its new extent anywhere free and the WAL grows by file extension. The placement rule, the reuse rule for space outside the two live extents, and the fragmentation bound all need settling before K1 is written.

**The rule-M checker**, the runtime half of §3.2, lands here as `Checked<M>`. Every record declares which file bytes, dentries, and directories it asserts, and admission rejects any record whose assertions the wrapper has not seen covered at the asserted generation. Between this and the `Barrier` token -- which makes "skipped the wave entirely" unrepresentable -- an M violation fails a test at the moment it is written rather than surfacing as a lost acknowledged write in one unlucky interleaving.

**Done means:** the format round-trips under fuzz (record and root decoders, plus the replay state machine); replay of any prefix is a prefix of replay of the whole; the crash harness interrupts at every point in K1-K5 and every recovery converges; the rule-M checker is wired and green. No `Storage` implementation exists yet.

### Phase B: the committer

*~700 lines. Risk: medium.*

Builds `Committer` and `Barrier` (§3.2). The G1-G5 cycle: bounded drain, synchronization wave, contiguous record append, WAL barrier, acknowledge and apply. One word in that list is a known trap and gets pinned now: G5's "apply" is the **in-memory catalog delta only**. Payload file writes complete *before* G2 -- that is the whole point of the wave -- and no `CommitAtomic` is constructed until the wave it cites has returned. Writing payload at G5 is revision 1's critical bug wearing the cycle's vocabulary; the normative order is: complete payload applies, wave, then records, then WAL barrier, then in-memory application. In this phase the only records are namespace ones, so the wave carries dentry fsyncs and nothing else -- but G2 already mints the `Barrier` token, so the discipline is in place before any record asserts file content.

The committer is one task per family, spawned through an injected spawn function on the volume precedent (`volume/mod.rs:66`), and it owns its scratch: the drain vector and the record encode buffer persist across cycles, cleared rather than dropped, so a steady-state cycle allocates nothing (§3.8). The drain's append is one vectored write of all frames. Shutdown is part of the contract, not an afterthought: dropping the family's last handle closes the committer's channel and the task drains and exits -- volume left "verify no task leak" as an open item; here it is a phase B test.

Includes the elision protocol with drain-close capture and the semantics-free `BarrierRider`, the poison doctrine (WAL failure poisons the family; a blob-file or directory fsync failure poisons that blob's generation and taints), and the lazy-work executor as the committer's idle lane with bounded backpressure that forces inline execution when exceeded.

The wave-failure taint rule -- transitive per-blob abort propagation across a drain -- is *built* here and only partly exercisable, since the only wave members are directories. Its deterministic tests across multi-blob batches and `DeletePartition` land in phase E, where the wave syncs blob files. Do not mark taint done at the end of B.

**Open question B1: does `BarrierRider` need any replay-time assertion?** It currently has none by design, since giving it semantics is exactly what broke revision 1. Verify nothing in replay or recovery depends on its presence, and if nothing does, pin that with a test rather than leaving it implicit.

**Done means:** group commit demonstrably collapses K namespace operations to one barrier; directory-fsync failure poisons and taints as specified; and poison follows the exact rule, pinned here: poison is scoped to the live instance (family or generation), every subsequent mutation through it fails, and it does not persist as a flag -- a process restart runs recovery, which judges the on-disk state on its own evidence, and a genuinely bad device re-poisons itself on the next failure. "Sticky across reopen" means reopening through the same poisoned instance, not across recovery.

### Phase C: routing, startup rails, and `Storage`/`Blob` for ordinary blobs

*~900 lines. Risk: low-medium.*

Two things, together because neither is useful alone.

**The rails.** Family definitions in config, exact-partition rules overriding prefix rules, residency stickiness with existing catalog residency authoritative, the `.wal/` reserved namespace rejected through the public wrapper, the sidecar lock acquired unconditionally by the dispatcher, startup enumeration of every configured family, and `Io(Unsupported)` for cross-family batches. Startup order: make prior storage durable, take the lock, enumerate, recover every family, build the residency map, validate config, then serve. A config change that would rehome a resident partition is a startup error.

**The backend.** Builds `Catalog` and the ordinary `Blob` of §3.3 -- the atomic handle does not exist yet, which is the point: the path that must stay identical to today is written with no atomic code in it. WAL owns the namespace; the file owns content and physical length. Ordinary `write_at`, `resize` (immediate `set_len`), and `sync` (fdatasync on the blob's own fd) never touch the committer and behave byte-for-byte as today. `scan` reads the catalog, never `readdir`. Creation stages `CreateBlob` and rides group commit. Removal is a record with a lazy incarnation-guarded unlink. The recursive dentry rule fires on the first durability event, including a first `WriteOptions::SYNC` write.

This is a complete, useful backend on its own. With no atomic blobs at all it still delivers creation without directory fsyncs, removal and teardown as records, and catalog-backed scan.

**Open question C1: K2's unlink-directory fsyncs against the recursive dentry rule when the partition directory is itself being removed.** The recursive rule syncs up to the root; a directory being unlinked in the same checkpoint makes that walk ambiguous. Settle the ordering before lazy unlinks are written.

**Done means:** `run_storage_tests` passes over both media; the crash harness passes across the spec's §5.4 file-state disposition matrix; ordinary-blob crash semantics are demonstrably identical to the per-file backend; startup rejects every malformed-config and dual-residency shape.

### Phase D: adoption

*~600 lines. Risk: high. This is C's whole advantage over a family volume, and it is a crash protocol in its own right.*

Deliberately early. Phase C is not deployable without it, since you cannot point C at a directory that already has data, and migration territory generated seven of the speculative volume's 53 findings -- find those while the surface is small.

**Open question D1: the V3 header layout is a shared-file change.** Adoption needs a 16-byte incarnation in the blob header, and it cannot be smuggled into V1: V1 validation requires every byte from `PARSE_LEN` to the 4096 data offset to be zero, else `InvalidPadding` (`storage/header.rs:182-187`). So this is a genuine format addition to `runtime/src/storage/header.rs`, a file every backend shares, with its own compatibility and downgrade surface. Design the layout and its interaction with existing torn-creation healing before touching `adopt.rs`.

- **V1 files:** `AdoptBlob` record with a barrier, then the in-place 4 KiB header rewrite to V3, then fdatasync. A crash between record and stamp, or mid-stamp, is re-stamped idempotently by the provenance-gated recovery arm, because the row supplies every field.
- **V0 files:** payload begins at byte 8, so this is a data relocation, not a header rewrite. **Spec §10's ordering is wrong here, and this plan amends it.** The spec renames the replacement over the live name *before* writing `AdoptBlob`; a crash in that window leaves a V3 file with no catalog row, and recovery's orphan sweep -- which cannot distinguish it from a lazily-unlinked deleted blob, because a checkpoint erases deleted rows entirely -- may unlink the only copy. Destructive rename requires durable intent first: (1) `RelocateIntent` record, barriered; (2) stage the replacement (V3 header, payload at 4096) under a temp name, fdatasync; (3) rename over the live name, dentry wave; (4) `RelocateComplete`. Recovery with an open intent re-derives the state -- V0 at the live name means redo, matching V3 means complete, a temp is discarded -- and the orphan sweep never touches a file named by an open intent. One full copy per V0 blob, once, and V0 blobs are rare legacy.
- **Completion before user code runs.** Every legacy blob in a WAL-routed partition is adopted before serving. Deferring per-open lets catalog-only `scan` hide un-adopted blobs from journal section discovery and silently empty them.
- **Downgrade.** Stamped V3 files hard-error under old software by design. The offline extraction tool (V3 back to V1 headers, then retire the WAL) is valid after a clean shutdown -- but the tool itself can crash mid-run over thousands of files, so it is a resumable protocol, not a loop: durable extraction intent first; the WAL stays intact and authoritative throughout; rewrite and fsync every header; complete lazy unlinks and sync their directories; verify no atomic overlay content remains unmaterialized; only then retire the WAL, and only after that may old software start. Interrupting it at any step and re-running converges. **The tool ships in this phase, not later.** A migration without a reverse is not a migration anyone should accept.

**Open question D2: adoption cost at very large legacy trees.** Adoption must complete before user code runs, so a tree with 10^5 or 10^6 blobs turns startup into a bounded but possibly long stall. Either establish the bound is acceptable or design a resumable adoption that still satisfies the completeness requirement.

**Done means:** adoption completes correctly from every crash point, on trees containing V0, V1, already-V3, orphan, and mid-relocation files; the extraction tool converges from interruption at every step of its protocol and the result round-trips; adoption wall-clock is measured at 10^3 and 10^5 file counts.

**Milestone M2.** C is a drop-in replacement for the per-file backend on an existing storage directory: full conformance suite, full crash harness, adoption from a real tree, no consumer code changed. Call it what it is: a **proof milestone, not a deployment target**. At M2 the adoption stamp is one-way, no atomic blob exists, and an unchanged consumer gains namespace wins but no sync-path improvement -- nobody should adopt a one-way format for that. What M2 proves is the part whose failure modes are silent: the format, the medium seam, the crash harness, and the migration protocol. The value proposition ships at M3.

### Phase E: atomic blobs, bulk path only

*~900 lines. Risk: high.*

Builds `Frontier` and `Pending` (§3.1), `Overlay`, `TailBuffer`, and the `AtomicBlob` handle of §3.3, including its read path under the §3.8 budget: spans resolved across tail buffer, overlay, and file under one lock acquisition, I/O with the lock released. The synchronization wave at G2 now has blob-file members, so `Barrier` becomes load-bearing rather than ceremonial. `CommitAtomic` takes one by reference and cannot be constructed without it. The rewind fence: staged and immediately visible by clamp, but crossing the last published length fences appends and tail writes until the caller-awaited publication acknowledges. Pending-truncate ordering under the blob lock before any later apply to that file.

The taint rule's real tests land here, now that the wave has blob-file members.

No inline in this phase, so every publication takes the wave and small atomic syncs cost two rounds. That is temporary and phase F fixes it. The reason to separate E from F is that the overlay's replay materialization is the novel hazard in this design, and it is far easier to get right on a base where the only overlay entries are lengths.

**Open question E1: the full `Frontier` transition table.** §3.1 fixes the model -- trust versus physical durability -- and walks the rewind-then-inline scenario. It does not freeze the table: which lock serialises two clones publishing concurrently, whether a second rewind may stack on an undischarged `Pending`, and the exact stage-versus-publish moment each offset moves. That table is phase E's entry criterion; the §3.1 scenario itself waits for phase F, where inline records exist.

**Done means:** two-blob atomic publication is all-or-nothing across every crash point; `trusted` is the only offset any snapshot or recovery path can reach, enforced by `Frontier`'s surface rather than by convention; rewind publication, pending-truncate ordering, rewind-then-bulk-reappend over the same range, and concurrent cloned-handle publications each have a named test; the rewind fence lifts at the awaited publication and never at an unrelated batch's barrier; taint propagates transitively across multi-blob batches and `DeletePartition`.

### Phase F: the inline path

*~500 lines. Risk: high. The one genuinely novel mechanism in C.*

`InlineAppend` records, the per-blob tail buffer with its aggregate cap (`INLINE_MAX` 64 KiB per append, `INLINE_EPOCH_MAX` 1 MiB per publication), overflow forcing the epoch to the bulk path, and overlay-ordered replay materialization.

The hazard, precisely: inline records are content assertions that outlive their barrier, and replay must not re-materialize them over later acknowledged bytes. C's version is within-blob only, and §3.1's contiguous overlay type is what keeps it that way. The fix is that replay materializes inline content *through the overlay* in journal order, so a rewind truncates the overlay entry before a later bulk record is reached, and file writes defer to the post-replay checkpoint. **Write the §3.1 rewind-then-inline scenario as a failing test before the mechanism exists** -- phase E already proved its bulk-only cousin.

**Fallback, decided in advance.** If F does not converge, C ships without inline. The cost is two sequential flushes on small atomic syncs instead of one, which taxes the hottest durability path in the system. That is a real regression and a reason to work hard on F, but not a reason to abandon C: the atomicity guarantee and the migration story are unaffected.

**F1, reclassified: the spill region is a successor design, not a fallback.** If §7's measurements show the N-file bulk wave is expensive at QMDB shapes, one response is letting overflow payload spill into a WAL-file-resident region: same file as the record, one barrier, bounded memory. But the external review is right that this quietly changes payload authority, write amplification, checkpoint cadence, recovery, the WAL's blast radius, and the salvage story -- the exact claims C is chosen for. It is a different design that happens to share a committer, the same relationship D has to C. If the wave measurement goes badly, the decision is between C-as-specified, that successor, and the family volume -- made deliberately, with the numbers, not invoked as a patch. Nothing in phases A through I depends on it.

**Done means:** the 1-round / 1-flush accounting for all-inline groups is measured, not asserted; rewind-then-reappend and every overflow-boundary case pass the harness; inline write amplification is measured against the spec's stated ~3x lifetime figure.

### Phase G: `BatchStorage::start_apply`

*~400 lines. Risk: medium.*

Validation strictly before any side effect: canonicalize descriptors, dedup identical and reject conflicting per-blob mutations, reject non-atomic handles, reject stale and foreign handles by instance check plus generation token, reject out-of-bounds rewinds and cross-family participation. Then stage one multi-record transaction under the participants' blob locks in canonical order, enqueue, and return per whatever T2 settled. An empty batch returns ready with no cycle. Rejection is atomic because all checks precede all staging.

Two questions must be closed before this code: **G1** -- a taint-aborted batch is a *post*-validation failure, which contradicts "rejection changes nothing"; its error surface and retry semantics determine what the handle resolves to -- and **T2** from phase T, whether the durability proof rides the return or the handle, which decides whether this method pipelines at all.

**Done means:** the trait's own conformance pins pass, with the handle semantics stated exactly -- validation rejection stages nothing and changes no committed state; once a batch is admitted, dropping the handle does not cancel it (self-driving means the work proceeds unobserved); and a failed or interrupted durability operation is indeterminate per the three-valued model, never assumed absent. `removed.sync()` errors via the token.

### Phase H: promotion to atomic

*~300 lines. Risk: medium-high.*

Turns an ordinary blob into an atomic one (`PromoteBlob`, §3.6). Serialized behind the blob's in-flight records, then a synchronization wave completing before the record is staged with the wave-observed length. Prior-handle isolation is the subtle part: migration replaces the generation but not the inode, so the successor treats the migrated length as an inherited floor, and the first successor mutation that would rewrite below it copies that region into a staged replacement file that takes over the name, while prior handles keep the old inode and are clamped at their generation's length. Pure appends and inline publications never trigger the copy.

**Open question H1: the copy-on-write-below-floor protocol's crash windows.** A staged replacement plus rename, under an existing WAL row, in a design where the row already asserts a length. Enumerate the windows before writing the copy.

### Phase I: the Oversized pilot

*Size unknown until the writer spike lands; the earlier ~400-line figure was not credible. Risk: high.*

Oversized is the right first consumer: its index and value live in genuinely separate partitions (`storage/src/journal/segmented/oversized.rs:84-87`), it is the cleanest instance of the half-published-pair problem, and its repair code is self-contained enough that removing it is a reviewable change on its own.

**Open question I1, and the phase's entry criterion: the paged-writer conflict.** "Convert section blobs to atomic" is not a two-line swap, because the journals' paged writers rewrite the tail page in place as it fills -- and after a sync, that page is *committed* content, which is exactly the write an atomic blob forbids below `committed`. The options are an append-only page discipline (never rewrite a published page; publish only whole pages, or move the partial-page rewrite into the pending epoch), or a writer redesign. Scope this as a spike -- read the actual writer and section-recovery paths, produce the design and a line estimate -- before any phase I code. Rollover, prune, and section creation likely move too.

Then: place index and value in one family. Convert section blobs to atomic under whatever discipline the spike lands on. Restructure append to stage both sides and publish one batch rather than calling two independent sync paths. Route rewind, prune, section creation, and deletion through batches.

**Keep the pair-repair code.** It comes out in a separate change, only after crash-equivalence tests demonstrate the formerly repaired states are unreachable. Deleting recovery code on the strength of a design argument is how you find out the argument was wrong.

**Milestone M3.** Oversized runs on C end to end, and the recovery-code reduction is counted in deleted lines rather than promised.

## 6. Test architecture

Five layers, in place by the end of phase A or B, not retrofitted.

1. **Conformance.** `run_storage_tests` against C over both media. This is the contract every backend shares and it is cheap to keep green.
2. **The rule-M checker.** Phase A, the runtime half of §3.2. A `Medium` wrapper, so it runs inside every crash test over `Sim` and every integration test over `Fs` -- the master rule stays machine-checked against real files too.
3. **Crash simulation.** Deterministic seeded interruption at every enumerated point, with the per-file no-cross-file-ordering model and byte-granularity tearing. Points, at minimum: each of G1-G5; each of K1-K5; the adoption stamp and the relocation rename; the promotion wave and its below-floor copy; the first-dentry fsync; lazy unlink; the inline overflow boundary.
4. **The three-valued model.** The volume work established that an errored operation is *indeterminate*, not absent: a create whose barrier failed may legitimately surface after recovery. The model encodes Ok / indeterminate / absent for every operation, or it will report correct behavior as a bug and miss real ones.
5. **Fuzz.** Record and root decoders, and the replay state machine, over adversarial byte streams. Note that `storage/fuzz` sits outside the workspace and needs its own `cargo check` after any change to shared sync paths.

Properties worth pinning explicitly: replay of any prefix is a prefix of replay of the whole; every acknowledged operation survives every crash point after its acknowledgment; no unacknowledged operation is ever *required* to survive; no record is ever admitted whose assertions are uncovered at their asserted generation.

Validation per phase: `just test -p commonware-runtime <filter>` while iterating, `just clippy -p commonware-runtime` on the changed crate, `just lint` before each phase closes (it runs the pinned-nightly `check-fmt`, docs, features, and `check-stability` -- stable `cargo fmt --check` proves nothing here), and `just pre-pr` before decomposition. Add `just udeps` if dependencies change, and the WASM build after any `storage/` change.

## 7. Measurement and acceptance

Measurement comes after the code works; nothing below gates implementation. Every row of spec §4's barrier-accounting table is a claim, and each gets a test that counts flushes directly rather than inferring them from wall clock. Benchmarks go in the standalone harness at `runtime/src/storage/benches/` (real filesystem, real hardware), and the `compare_backends` shape already on this branch is the pattern to follow.

One note, flagged rather than smuggled: the external review argued the N-file-wave measurement should precede everything, since its outcome bears on whether C is the right build at all. That was this plan's original shape and it was removed on your instruction, which stands. The wave experiment needs none of C's code -- it is raw fdatasync patterns over the existing harness -- so it *can* run concurrently with phase A without delaying anything, and having the number before the format freezes at A1 is strictly more information. Say the word and it runs in parallel; the plan does not gate on it.

Vague outcomes do not produce decisions, so every row below runs under a registered protocol, written down *before* the row runs: the baseline it is compared against, the hardware class, the payload and participant distribution, the p50/p99 and throughput thresholds, the maximum tolerable startup or checkpoint pause where applicable, and the action a failure triggers. The "what would falsify" column names the failure shape; the registered protocol turns it into a number and a consequence.

| after phase | measured | what would falsify |
|---|---|---|
| C | ordinary sync, create, remove, scan against the per-file backend | any ordinary-path regression at all -- ordinary blobs are supposed to be unchanged |
| C | teardown of a 10-partition tree | no improvement over per-file unlink ceremonies |
| D | adoption wall-clock at 10^3 and 10^5 files | startup cost that makes adoption-before-serving untenable |
| E | bulk atomic publication, N in {1,2,4,8,16,32}, at 256 KiB / 1 MiB / 4 MiB | the N-file wave costs materially more than a single barrier at QMDB shapes; triggers F1 |
| E | QMDB commit shape, traced from the real consumer before the row is frozen (the stateful path is a wider multi-partition full-sync, not an assumed 4-participant `start_sync`), synchronous and pipelined | same, on the shape that actually governs |
| F | all-inline group of K blobs; inline write amplification; steady-state allocations per publication (heaptrack or count hooks) | fails to reach 1 round / 1 flush, amplification far above 3x, or per-cycle allocation that grows with K |
| F | checkpoint pause and cadence under inline-driven WAL growth | visible p99 stalls at realistic rates |
| I | end-to-end Oversized against per-file and volume backends | slower than today with no compensating recovery-code deletion |

Run the phase E and F rows on at least two devices with different flush economics -- a PLP-backed enterprise NVMe where a flush is near-free, and a consumer NVMe or cloud block device where it is milliseconds. One machine's numbers decide nothing.

## 8. Rollout

Behind a backend selection, defaulting off, with the volume and per-file backends unchanged. ALPHA means the format can change without a migration path *until a consumer depends on it*, which is exactly why phase I keeps the pair-repair code and why the extraction tool ships in phase D.

The first deployment that adopts is one-way for un-upgraded software. That is a real operational commitment, made once and deliberately after M3, not incrementally as phases land.

## 9. Risk register

| # | risk | grade | response |
|---|---|---|---|
| R1 | Rule M violations. All four rev-1 criticals were this. | high | Two layers: the `Barrier` token (§3.2) makes skipping a wave unrepresentable, and the generation-aware checker catches wrong-range and wrong-generation residue. Best defense in the plan and cheap. |
| R2 | The inline overlay does not converge. | high | Phase F isolated behind a working bulk path, convergence test written before the mechanism, decided fallback (ship without inline). |
| R3 | Adoption crash protocol. Seven of the speculative volume's findings were migration territory. | high | Phase D early while the surface is small; every crash point enumerated; extraction tool ships with it. |
| R4 | The bulk wave costs materially more than a family volume's two flushes. The `compare_backends` result on this branch (16-wide `join_all(sync)`, volume 4.8x faster) is a hint in that direction, though it varies flush count and file count together so it does not isolate the mechanism. | high | Measured at phase E on both device classes. If material, the architecture decision reopens with the numbers on the table: C as specified, the family volume, or the separately designed spill successor (§ phase F). No option is a patch. |
| R5 | Trait surface blocked on #4368. | medium | Phase T opens first and runs in parallel. Fallback: traits in a small standalone PR. |
| R6 | Two backends to maintain forever. | medium | §11 forces the decision instead of letting it default; §3.7 defers the sharing question to the end of phase C rather than guessing at it now. |
| R7 | Scope. The per-phase figures are floors: volume's simpler format, recovery, and committer alone run ~2,250 non-test lines, and C adds cross-file crash simulation, directory state, the checker, adoption, and the atomic layer. Expect 7,000-9,000 non-test plus 4,500-6,000 test lines, and phase I is unsized until its spike. | medium | M2 is a genuine exit point (a proof milestone, per phase D); A0 merges alone; every phase ends green. |
| R8 | Eleven open design questions distributed across phases, plus one decision (V1). A phase that starts before its question closes will encode the wrong answer. | medium | Each is named in its phase and listed in §10. Closing one is the first task of its phase, not a parallel activity. |

## 10. Open design questions, collected

Each question closes before its phase's code is written; the last two rows are a reclassification and a decision.

| id | phase | question |
|---|---|---|
| T1 | T | The atomic handle surface: `AtomicBlob: Blob` supertrait vs siblings, cross-kind open behavior, and what `sync` / `resize` / arbitrary `write_at` mean on an atomic blob. §3.3 states the conflict; the trait decides. |
| T2 | T | Where the pipelining gap lives: durability proof on `start_apply`'s return (spec §3, no gap) or on the handle (volume's `start_sync` shape). |
| A1 | A | Record-extent placement, reuse, and fragmentation policy. |
| B1 | B | Whether `BarrierRider` needs any replay-time assertion. |
| C1 | C | K2's unlink-directory fsyncs against the recursive dentry rule when the partition directory is itself removed. |
| D1 | D | The V3 header layout as a shared-file change to `header.rs`, and its downgrade surface. |
| D2 | D | Adoption cost at very large legacy trees, given completion must precede serving. |
| E1 | E | The full `Frontier` transition table: clone serialisation, stacked rewinds, stage-vs-publish moments. §3.1 fixed the model; the table is E's entry criterion. |
| G1 | G | The wave-failure taint rule against `start_apply`'s atomic rejection. |
| H1 | H | The copy-on-write-below-floor protocol's crash windows. |
| I1 | I | The paged-writer conflict: an append-only page discipline for atomic section blobs, scoped by a spike before any phase I code. |
| S1 | end of C | Which of volume's ~1,500 shareable lines to extract, once both shapes are visible (§3.7). |
| F1 | -- | Reclassified: the spill region is a successor design (phase F), not an open question on this plan's path. |
| V1 | -- | Volume's future: keep both, retire volume, or fold width collapse into C. Blocks phase C's final shape (see §11), not phases A0-B. |

## 11. What this plan does not claim

It does not claim C removes all consumer recovery code. Structures whose components are ordinary random-write blobs -- the metadata stores in particular -- have no rollback-safe transactional representation, and their recovery phases remain until they get one. That binds every candidate equally and sets a floor of about two rounds for QMDB's full sync no matter which backend wins.

It does not claim the flush-count wins reach unmigrated consumers. Spec §4 is explicit: every consumer today uses ordinary blobs, which never enter C's committer, so an unchanged consumer gets creation, removal, teardown, and namespace wins and **no sync-path flush reduction whatsoever**. The volume backend on this branch does collapse ordinary-sync width without adoption. That is a genuine capability C trades away for file-as-truth simplicity, and it forces a decision this plan will not make for you: if C lands, does volume stay? Keep both, retire volume, or fold width collapse into C's ordinary path. Two `Storage` implementations means two conformance surfaces and two crash harnesses in perpetuity, and the answer changes what phase C's ordinary path has to do.

It does not claim C is safer than the family volume in every dimension. Both designs have a hard part. C's is rule M -- waves, recursive dentries, two watermarks, taint propagation. The family volume's is a chunk allocator. The argument for C is not that its hard part is smaller. A rule-M bug can lose acknowledged data too -- revision 1's criticals did exactly that. The defensible asymmetry is different: rule M is a property you can state per record, instrument at admission, and machine-check in every test (§3.2), while allocator ownership is a global invariant whose violation puts one blob's bytes inside another and is only as checkable as the replay that notices. Easier to express, easier to instrument, easier to catch at the moment of the mistake. In a codebase whose first design constraint is treating every value as adversarial, that is what the choice actually buys.

## 12. Next step

Start A0: `Medium`, `Fs`, `Sim`, and `Checked<M>` -- no open question gates it. A1 (format, replay, namespace checkpoint) follows once A1's extent-placement question closes. Phase T runs in parallel as coordination with Patrick.

Three things I need from you, none blocking A0: the volume decision (V1 in §10, argued in §11 -- it now shapes phase C, so it wants an answer before C starts); when to open the trait conversation on #4368 (T1 and T2 both live there, and T1 also gates the header work in D); and whether the wave experiment runs in parallel with phase A (§7's note -- your call, the plan does not gate on it).
