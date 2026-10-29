# Vendored mimalloc

This directory is a copy of the `src` and `include` trees of
[mimalloc](https://github.com/microsoft/mimalloc) at the tag recorded in
`VERSION`, plus its `LICENSE`, with the backports described below.
`build.rs` compiles `src/static.c` (the upstream amalgamation) into the
`commonware-allocator` crate, and the crate's `src/mimalloc/ffi.rs` declares
the handful of functions the wrapper uses.

## Backports

### Statistics merge threshold

Each thread keeps its allocation statistics to itself until it merges them
into the totals `mi_stats_get` reads. Without the threshold, a thread merges
only when it collects (every 10,000 allocations that miss its fast path),
exits, or reads statistics itself. Freeing a block into a page another thread
abandoned charges the free to the freeing thread, and every huge block is
freed that way. A thread that only frees memory other threads allocated then
never merges, and the allocated bytes in the totals grow without bound.

The changes backport the `stats_merge_threshold` option from mimalloc v3.6
([microsoft/mimalloc#1410](https://github.com/microsoft/mimalloc/issues/1410))
and the merge cost fix that followed it:

- `include/mimalloc.h` appends `mi_option_stats_merge_threshold` to
  `mi_option_t`.
- `src/options.c` adds its entry with a 4 MiB default
  (`MI_DEFAULT_STATS_MERGE_THRESHOLD`). Upstream raised the default from
  512 KiB to 4 MiB after v3.6.0
  ([microsoft/mimalloc#1458](https://github.com/microsoft/mimalloc/issues/1458)).
- `src/page.c` merges a thread's statistics at the end of
  `mi_theap_page_merge_stats` once the thread has allocated and freed that
  many bytes since its last merge. The vendored release keeps no per-thread
  totals of allocated and freed bytes, so the check derives them from the
  normal and huge byte counters. A merge resets those counters, so they hold
  only the bytes since the last merge.
- `src/stats.c` skips zero statistics when `mi_stat_count_add_mt` merges a
  thread's statistics into its heap
  ([microsoft/mimalloc@e83c5605](https://github.com/microsoft/mimalloc/commit/e83c560535a32e2323f9f7bee2fb643bdd2ed1fe)).
  A thread that allocates and frees large blocks merges often, and most of
  its statistics are zero, so skipping them saves an atomic add apiece.

## Updating

Download the release tarball for the new tag, replace `src`, `include`, and
`LICENSE` with its copies, update `VERSION`, and run the crate's tests. They
check the linked version and exercise every binding. One test derives the
option enum values and the alignment constant the wrapper mirrors from the
new headers, so it catches a renumbering.

`Config::DEFAULT` sets every option `Config` covers, so a release that changes
one of those defaults has no effect until `Config::DEFAULT` adopts it. The
`default_config` test compares `Config::DEFAULT` with the defaults mimalloc
starts with and fails when they differ.
