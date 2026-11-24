# Intents: readers that share a page read in flight

The decisions behind a new runtime fuzz target for the shared reads of the page cache
(`runtime/src/utils/buffer/paged/cache.rs`). The target drives the public `Sealed` read API with
several concurrent readers on the deterministic runtime, and uses the runtime's
`MigratingReadBlob` test mock (`runtime/src/mocks.rs`, feature `test-utils`) to keep a backend
read in flight for one scheduler turn, so that a second reader can join it.

Background: the page cache lets a reader that misses a page join a read of that page, or of a
batch holding it, that is already in flight, instead of reading it again. No fuzz target reaches
that code today: the `buffer` target awaits one operation at a time, and on the plain memory blob
a read never stays in flight. `runtime/fuzz/SPEC.md` names concurrency in storage as a non-goal
of its targets so far; this target is the first step into it.

All decisions below were taken on 2026-11-24.

## Hypothesis and intention

1. The shared reads of the page cache can deliver wrong bytes, lose a wakeup so that a joined
   reader never finishes, or let a cancelled reader take a live fetch away from the readers that
   joined it. A fuzz target with several readers, a read that stays in flight, and readers that
   cancel a pending read can show these failures.

## Scope of the first version

2. Several readers over one small shared cache read one immutable sealed blob; some readers
   cancel a pending read after its first poll. Read failures and a live writer are future work.
3. A new target in `runtime/fuzz/fuzz_targets/`. The `buffer` target stays as it is.
4. Construction of every scenario: one immutable sealed blob of full pages whose bytes encode the
   page and the offset (so a wrong page cannot compare equal by accident); the shared cache is
   cleared after sealing; the blob is wrapped as `MigratingReadBlob::new(blob, false)`; shared
   reads stay in the full-page region; the cache capacity is fuzzed; the baseline has more pages
   than the cache.
5. Read forms: `read_at`, `read_into` and `read_ranges_into`, with same-page reads,
   page-crossing reads, and sorted non-overlapping range lists whose pages overlap the pages of
   other readers.
6. Cancellation: a reader polls one public read future once; if it is pending and the reader's
   drop flag for that read is set, that future is dropped and counted as one cancellation, and the
   reader task goes on with its next read. A read that is ready on its first poll is checked, not
   cancelled.

## Input

7. A hand-written typed `FuzzInput`, with the runtime seed in its first bytes and small bounded
   counts for readers, pages, cache capacity and operations per reader. Each operation picks a
   read form, bounded ranges and a drop flag. `FuzzRng` fills the details a short input does not
   hold. The empty-corpus and minimal-decodable baseline has at least two readers that share one
   uncached full page, and at least one of them survives. The spec sets the small maximums.

## Checks

8. Bytes: every read that completes returns exactly the bytes of the model.
9. Completion: every surviving reader task, and every read that was not cancelled, finishes
   before a fixed deadline of simulated time; a runtime stall is also a failure. This replaces an
   earlier answer of the same day ("a runtime stall only"), which could miss a reader that waits
   while other tasks still run.
10. A cancellation changes nothing for the other readers: checks 8 and 9 still hold for them.
11. Backend reads, standalone fetch: when two waiters on one uncached page are both registered
    before any cancellation and at least one of them survives, that page is read from the blob
    exactly once. The input-driven scenario arranges this case; no fixed scenario runs beside it.
12. Backend reads, batches: not asserted. The cache allows a page to be read twice there. The
    per-page counts are recorded in the acceptance evidence only, with the allowed duplication
    explained.

## Definition of done

13. The spec is accepted, and acceptance tests written from the spec pass.
14. A short run from the empty corpus reaches four behaviours: a join of a standalone page fetch;
    a join of a batch with its delivery; a cancelled standalone waiter with a survivor; a
    cancelled batch subscriber with a survivor. Line numbers appear only in the evidence.
15. Two planted faults, each an exact patch in a scratch copy with its changed expression, its
    triggering input trace and the check that must fail: a wrong page delivered (the bytes check
    fails); a cancelled reader that loses the fetch for the others (the completion check or the
    strict count fails). Each plant proves only its named check.
16. One fixed input run twice gives the same trace, results and counts.
17. A clean smoke run, whose command and duration the spec names.
18. The spec states what this proof does not show.
22. A limit of the construction, accepted: with a read held for one poll, a cancelled standalone
    waiter never leaves a second waiter still pending on the same fetch, because the second waiter
    drives the fetch to completion in the turn it joins. So the standalone behaviour of item 14 is
    a standalone waiter cancelled after a second waiter registered on the same fetch generation,
    which then completes with the right bytes and one backend read; the planted "lost fetch" fault
    of item 15 is placed in the batch path, where a cancelled joiner can leave a pending survivor.
    The case of a standalone fetch kept alive for a pending survivor is a stated limit and future
    work (for example a fuzz-side wrapper that holds a read for several turns).

## Out of scope

19. Real threads: the deterministic runtime runs one task at a time, so lock-order races are out
    of reach; the one-turn hold of the mock is enough to make readers join.
20. Several blobs sharing one cache, partial tail pages, corruption and read errors, invalid or
    out-of-range reads, live writes, recovery, replay and prefetch, synchronous cache-only reads,
    `read_up_to` and `read_many_into`.
21. In scope: eviction, and reader cancellation as defined in item 6.
