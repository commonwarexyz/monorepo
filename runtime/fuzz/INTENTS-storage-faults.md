# Intents: `storage_faults`, the runtime storage contract under faults and crashes

## 1. Hypothesis and target

1. The next runtime iteration looks for **faults and recovery** bugs: what the runtime's own storage
   contract promises when operations fail and when the process crashes (1.1; Future work 5 and 6 of
   `runtime/fuzz/SPEC.md`).
2. A **new target, `storage_faults`**, in `runtime/fuzz`. It runs on the **deterministic runtime
   only**, with its fault injection (`with_storage_fault_config`, `runtime/src/storage/faulty.rs`),
   and judges every run against a **model of the public `Storage` and `Blob` contract**. It does
   not compare with tokio (1.5, 1.9).
3. Its job is the **base contract, with no consumer on top**. The ten `storage/fuzz/*_recovery`
   targets already run consumers under faults; the spec studies all ten by name, and says
   what `storage_faults` reuses from them and what it checks that they do not (1.11, 2.16).

## 2. What one run does

4. One run combines **injected operation failures** (open, read, write, sync, resize, remove,
   scan) and **simulated crashes** (restart from a checkpoint, with unsynced writes and resizes kept
   or lost by `PartialWriteMode`, Prefix or Subset) (1.6).
5. It covers **every public deterministic `Storage` and `Blob` entry point** and both sync styles
   (for example `open_versioned`, `read_at_buf`, `read_many`, `start_read_many`,
   `WriteOptions::SYNC`, `start_sync`, dropped handles, removal by name and by whole partition).
   Each exception is named and justified in the spec (2.7).
6. `start_sync`: covered with its handle awaited and dropped, on the current backend. A crash in the
   middle of an accepted sync is not reachable there; the spec records it as a limit (2.8).
7. Operations are **sequential**. Crashes happen **between operations**, never inside one (1.12).
8. **A few crash and recovery cycles per input**: one mandatory baseline crash, a small bounded
   number more chosen by the input; a recovered session may arm faults again before the next crash;
   a final fault-free check ends the run (3.4).
9. **The fault window.** Faults are armed only around operations the input selects; an
   input-selected open, read or scan may fail. Recovery reopens and every read, scan or open the
   oracle makes run with faults off (2.10, 3.2).
10. **The empty input** runs a full no-fault cycle: open, write, read, sync, crash and restart,
    reopen, read and scan at least one blob. The input adds operations and explicit fault windows on
    top (2.11; fuzzing guide, "Empty Corpus Requirements").

## 3. The oracle

11. **After a crash** (the contract model): start from the durable image; every unsynced
    successful write and resize, in issue order, may be kept in any subset of its bytes (or its size
    change kept or lost). Any image reachable this way passes; anything else fails (2.1).
12. **A successful reopen is a durability cut**: for that file generation, all data readable when
    the reopen returns must survive a later crash, and earlier pending crash choices are retired
    (3.5; `runtime/src/lib.rs:692-701`).
13. **After an injected failed write**, two kinds:
    - a **write fault**: bytes outside its range keep their durable values; inside the range, the bytes
      `faulty.rs` keeps become **durable at once** (no later keep-or-lose choice). A failed write past the
      old end extends the blob to its highest kept byte, the gap filled with zeros;
    - a **sync fault in a fused `write_at(..., SYNC)`**: all bytes are applied, none is durable, and they
      tear at a crash like an unsynced write; the caller still gets an error (`faulty.rs:854-865`).
14. **After an injected failed resize**: the old length or one intermediate length; the
    intermediate length is always replayed at a crash (2.4, 3.1).
15. **Sync**: a successful sync makes every earlier completed write and resize durable, also after
    an earlier failed sync, with no rewrite. A failed fused `write_at(..., SYNC)` is a failed write
    (2.3; `runtime/src/lib.rs:993-1000`).
16. **Namespace**: named and whole-partition removal, reads through old handles, recreating a
    removed name as a new blob, and scan after a crash compared as an unordered set; a failed
    injected remove changes nothing (2.9).
17. **No allowlist** in `storage_faults`. Any exception needs a separate decision and a
    narrow entry. The RF-1 to RF-3 entries stay in `storage_differential` only (2.12, 1.4). Named
    coverage exception for RF-2 (issue #5752): `storage_faults` issues empty non-SYNC writes only at
    offsets inside the blob; RF-2 stays covered by `storage_differential.`

## 4. Build rules

18. **Public API only**: nothing changes under `runtime/src` (1.2).
19. **The model code is shared**: the common operations and model transitions move from
    `fuzz_targets/storage_differential.rs` into `runtime/fuzz/src`, with `storage_differential`'s
    behaviour unchanged (its corpus keeps its meaning); `storage_faults` adds the fault and crash
    rules on top (1.5, 2.15).
20. **Determinism**: a fixed input run twice gives the same operation trace, injected results,
    crash images and oracle result. Oracle reads must not change the fault schedule. The target
    never reads the wall clock (2.14, 3.3).
21. **Run time**: 50 ms per input is a performance target, measured on a named host over fixed
    inputs. The target meets it with deterministic count and size bounds only (2.13, 3.3).

## 5. Definition of done (2.6)

22. The spec is updated and independently reviewed (1.3, 1.14).
23. Tests written from the spec, by someone other than the target's author, pass, with **one negative control per invariant**
    (`runtime/src` is on the tests-from-spec list).
24. A **10-minute smoke run** from an empty corpus shows no crash and no false positive.
25. **A planted runtime bug is found**: a patch kept outside the repository, applied only in a disposable
    git worktree, where `storage_faults` must catch it; the worktree is then removed. The repository tree
    and the delivered diff never contain the plant (2.5).

Recorded limit of the proof (2.6, 1.13): it shows the deterministic fault model only, not a real
disk, not tokio under faults, and not every possible bug.

## 6. Out of scope

- Fault and crash testing on tokio (1.9).
- Concurrency in storage, and crashes inside an operation (1.12).
- Any change under `runtime/src`, including `cfg(fuzzing)` hooks (1.2).
- A strict mode that disables the existing allowlist (1.4).
- io_uring, the network differential, and the other Future work rows not named above (1.1).

## 7. Open for the spec

1. Exact deterministic bounds: operation count, names, blobs, offsets, bytes, and the maximum
   number of extra crash and recovery cycles.
2. The acceptance host, the fixed input set, the repetition count and the measurement rule for the
   50 ms target.
3. Every exception to full public `Storage` and `Blob` coverage, each justified; the mid-`start_sync`
   crash kept as a backend limit.
4. The invariants, one negative control for each, and the single planted runtime fault.
5. The extraction boundary of the shared model, and the check that `storage_differential`'s
   behaviour stays unchanged.
