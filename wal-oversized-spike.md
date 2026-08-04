# Oversized on the WAL backend: the writer spike (I1)

Scopes phase I of `wal-plan.md`. Verdict up front: converting Oversized's sections to atomic blobs is a section-format redesign, not an adapter. The earlier ~400-line figure was off by roughly 4x, but the redesign *deletes more than it adds conceptually*, because the WAL's guarantees make the paged writer's entire self-defense apparatus unnecessary for atomic sections.

## 1. What Oversized actually does today

Two structures per section, in two partitions (`oversized.rs:82-90`):

- **Index**: `segmented::fixed::Journal`, fixed-size entries through the *paged* writer -- physical pages carry dual CRC slots (`buffer/paged/mod.rs:30-43`). The dual slots exist because the writer **rewrites the partial tail page in place** as it fills: each rewrite covers the whole physical page, resubmitting already-committed prefix bytes byte-identically, with two checksum slots so a torn rewrite cannot destroy the committed prefix's valid checksum.
- **Values**: `segmented::glob::Glob` through `buffer::Write`, appends at tracked offsets (`glob.rs:108,182`).

An append writes the value first, then the index entry pointing at it (`oversized.rs:435`). A sync is `try_join(index.sync, values.sync)` -- two parallel barriers (`oversized.rs:503`).

**The pair-repair code this exists to delete** is the module's own recovery doctrine (`oversized.rs:23-55`): backward-scan each section for the last entry whose glob reference is in bounds *and* whose value checksum verifies, rewind the index past it, remove orphan value sections, make all recovery truncations durable before serving. Plus the checkpoint-restore variant of the same.

## 2. The conflict, precisely

An atomic blob never writes below its committed length. The paged writer's tail-page rewrite writes below the committed length *by design* on every partial-page flush -- that is the one operation the dual-CRC machinery exists to make safe. So "convert section blobs to atomic" cannot keep the paged writer. This confirms the external review's P0; the interesting part is what replaces it.

## 3. The replacement: the overlay is the tip buffer

The paged writer solves torn tail pages with dual CRC slots. The WAL solves torn tails with inline records and exact end-of-log. These are the same problem, and an atomic section needs only one solution:

- The atomic blob's WAL-side tail (inline records, ≤64 KiB per publication) *is* the partial-page buffer. A publication of a partial tail inlines those bytes into the WAL record; the blob file is untouched below the committed length.
- When enough bytes accumulate, the bulk path writes them **once, at final offsets, page-aligned** -- never rewriting a committed byte. Fixed-size index entries make "publish only at entry boundaries" natural.
- Torn-tail detection, CRC slots, page replay, and the read-side partial-page rules all collapse: the WAL record checksum is the only integrity apparatus the committed tail needs, and file bytes below `trusted` are never re-verified at recovery.

The same shape serves the glob (values are pure appends already). And the crown: **append becomes one batch** -- value bytes and index entry publish atomically -- so section recovery is `open()`. The backward scan, the range check, the lazy checksum doctrine, the orphan sweep, and the durable-rewind-before-serving rules all become unreachable.

## 4. What phase I actually is

1. An **atomic section writer** in `runtime/src/utils/buffer` or beside the journal: append-only, page-aligned bulk applies, no CRC slots. Modest: it is a simplification of `Write`, not an extension of `paged`.
2. A **fixed-journal variant** (or mode) whose sections are atomic blobs and whose replay reads entries with no per-page validation. The current `fixed.rs` + paged replay is ~1,500 lines; the atomic variant is smaller but new.
3. **Glob over atomic blobs**: near-mechanical (already append-only).
4. **Oversized composition**: append stages value + index into one batch; sync becomes `apply`; rewind/prune/section-rollover through batches. Section *creation* in a batch needs the trait surface to permit it (the phase T amendment already asks for this).
5. **Crash-equivalence tests**, then pair-repair deletion as its own change.

Estimate: **~1,500-2,500 lines changed/new**, dominated by (2) and (5), with the old paths kept until equivalence is proven. Prerequisites unchanged: the phase T traits (T1/T2) and phase E/F of the WAL backend. Nothing here starts before those; everything here is now sized rather than guessed.

## 5. One measurement note for §7 of the plan

Oversized sync today = 2 parallel fdatasyncs per section group. Under the WAL: all-inline publication = 1 WAL fdatasync; bulk = value-file fdatasync + WAL fdatasync (2, sequential). The interesting benchmark row is therefore *append-heavy small-value* workloads (inline wins outright) versus *large-value* workloads (parity in count, one round worse in sequence, pipelined by `start_apply` per T2's resolution).
