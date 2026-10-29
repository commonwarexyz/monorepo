# Vendored mimalloc

This directory is a copy of the `src` and `include` trees of
[mimalloc](https://github.com/microsoft/mimalloc) at the tag recorded in
`VERSION`, plus its `LICENSE`, with the one local change described below.
`build.rs` compiles `src/static.c` (the upstream amalgamation) into the
`commonware-allocator` crate, and `src/mimalloc/ffi.rs` declares the handful
of functions the wrapper uses.

## Local change: statistics merge threshold

Each thread keeps its allocation statistics to itself until it merges them
into the totals `mi_stats_get` reads. Without this change a thread merges only
when it collects (every 10,000 allocations that miss its fast path), exits, or
reads statistics itself, and freeing a block into a page another thread
abandoned, as every huge block is, charges the free to the freeing thread. A
thread that mostly frees other threads' memory then never merges, and the
allocated bytes in the totals grow without bound.

The change backports the `stats_merge_threshold` option from mimalloc v3.6
([microsoft/mimalloc#1410](https://github.com/microsoft/mimalloc/issues/1410)):

- `include/mimalloc.h` appends `mi_option_stats_merge_threshold` to
  `mi_option_t`.
- `src/options.c` adds its entry. It defaults to
  `MI_DEFAULT_STATS_MERGE_THRESHOLD`, 4 MiB, the default upstream adopted after
  v3.6.0 shipped 512 KiB
  ([microsoft/mimalloc#1458](https://github.com/microsoft/mimalloc/issues/1458)).
- `src/page.c` merges a thread's statistics at the end of
  `mi_theap_page_merge_stats` once the thread has allocated and freed that
  many bytes since its last merge. This version keeps no allocated or freed
  totals per thread, so the change derives them from the normal and huge byte
  counters, which a merge resets.

`diff -r` against the tarball of the recorded tag shows exactly these edits.
Drop them when updating to a release that includes
`mi_option_stats_merge_threshold`, and check that release's default before
relying on it.

## Updating

Download the release tarball for the new tag, replace `src`, `include`, and
`LICENSE` with the copies from the tarball, update `VERSION`, and run the
crate's tests: they check the linked version and exercise every binding, and
one derives the option enum values and alignment constant the wrapper mirrors
from the new headers, so a renumbering is caught there.

`Config::DEFAULT` spells out its option values, so a release that changes a
default changes nothing until `Config::DEFAULT` does. The `default_config`
test compares the two and fails when they diverge.
