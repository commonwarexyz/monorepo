//! Raw bindings to the vendored mimalloc, limited to what the wrapper uses.
//!
//! Signatures follow the headers in `mimalloc/include` for the version recorded
//! in `mimalloc/VERSION`. Functions that dereference no pointer and have no
//! value precondition are declared `safe`. Each `unsafe` function documents
//! what its caller must uphold.

#![allow(non_camel_case_types)]

use std::ffi::{c_int, c_long, c_void};

/// Opaque arena identifier. The wrapper only passes null.
pub type mi_arena_id_t = *mut c_void;

/// Runtime option identifier (an index into mimalloc's option table).
pub type mi_option_t = c_int;

/// A statistic that rises and falls, with its cumulative total, peak, and
/// current value.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct mi_stat_count_t {
    pub total: i64,
    pub peak: i64,
    pub current: i64,
}

/// A statistic that only grows.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct mi_stat_counter_t {
    pub total: i64,
}

/// Layout version of [`mi_stats_t`] (`MI_STAT_VERSION` in
/// `mimalloc-stats.h`). mimalloc raises it on every incompatible change.
pub const MI_STAT_VERSION: usize = 5;

/// Index of the last size bin (`MI_BIN_HUGE`).
pub const MI_BIN_HUGE: usize = 73;

/// Number of chunk bins (`MI_CBIN_COUNT`).
pub const MI_CBIN_COUNT: usize = 6;

/// Declares [`mi_stats_t`] with the statistics of the `MI_STAT_FIELDS` list
/// in `mimalloc-stats.h`, in order, and records the list as `STAT_FIELDS`
/// for the test that compares it with the header.
macro_rules! mi_stats {
    ($($kind:ident $field:ident,)*) => {
        /// mimalloc's statistics. The caller sets `size` and `version`, and
        /// mimalloc fills the rest only when both match its own.
        ///
        /// The header aligns the first statistic to 8 bytes, and `align(8)`
        /// gives the struct the same alignment on targets that align `i64` to
        /// 4 bytes.
        #[repr(C, align(8))]
        pub struct mi_stats_t {
            pub size: usize,
            pub version: usize,
            $(pub $field: $kind,)*
            pub _stat_reserved: [mi_stat_count_t; 4],
            pub _stat_counter_reserved: [mi_stat_counter_t; 4],
            pub malloc_bins: [mi_stat_count_t; MI_BIN_HUGE + 1],
            pub page_bins: [mi_stat_count_t; MI_BIN_HUGE + 1],
            pub chunk_bins: [mi_stat_count_t; MI_CBIN_COUNT],
        }

        /// The statistics as `(type, name)` in declaration order.
        #[cfg(test)]
        pub const STAT_FIELDS: &[(&str, &str)] = &[$((stringify!($kind), stringify!($field)),)*];
    };
}

mi_stats! {
    mi_stat_count_t pages,
    mi_stat_count_t reserved,
    mi_stat_count_t committed,
    mi_stat_counter_t reset,
    mi_stat_counter_t purged,
    mi_stat_count_t page_committed,
    mi_stat_count_t pages_abandoned,
    mi_stat_count_t threads,
    mi_stat_count_t malloc_normal,
    mi_stat_count_t malloc_huge,
    mi_stat_counter_t malloc_requested,
    mi_stat_counter_t mmap_calls,
    mi_stat_counter_t commit_calls,
    mi_stat_counter_t reset_calls,
    mi_stat_counter_t purge_calls,
    mi_stat_counter_t arena_count,
    mi_stat_counter_t malloc_normal_count,
    mi_stat_counter_t malloc_huge_count,
    mi_stat_counter_t malloc_guarded_count,
    mi_stat_counter_t arena_rollback_count,
    mi_stat_counter_t arena_purges,
    mi_stat_counter_t pages_extended,
    mi_stat_counter_t pages_retire,
    mi_stat_counter_t page_searches,
    mi_stat_counter_t page_searches_count,
    mi_stat_count_t segments,
    mi_stat_count_t segments_abandoned,
    mi_stat_count_t segments_cache,
    mi_stat_count_t _segments_reserved,
    mi_stat_count_t heaps,
    mi_stat_count_t theaps,
    mi_stat_count_t pages_os_abandoned,
    mi_stat_count_t pages_os_allocated,
    mi_stat_counter_t pages_reclaim_on_alloc,
    mi_stat_counter_t pages_reclaim_on_free,
    mi_stat_counter_t pages_reabandon_full,
    mi_stat_counter_t pages_unabandon_busy_wait,
    mi_stat_counter_t heaps_delete_wait,
    mi_stat_counter_t pages_stat_updates,
    mi_stat_counter_t pages_stat_update_count,
    mi_stat_counter_t profile_samples,
}

unsafe extern "C" {
    /// Allocates `size` bytes, or returns null if the allocation fails.
    pub safe fn mi_malloc(size: usize) -> *mut c_void;

    /// Allocates `size` zeroed bytes, or returns null if the allocation fails.
    pub safe fn mi_zalloc(size: usize) -> *mut c_void;

    /// Resizes the block at `p` to `newsize` bytes, in place or by moving it,
    /// or returns null if the allocation fails. `p` must be null or a live
    /// block from this allocator. A non-null result consumes `p`, and a null
    /// result leaves it live.
    pub fn mi_realloc(p: *mut c_void, newsize: usize) -> *mut c_void;

    /// Allocates `size` bytes aligned to `alignment`, or returns null if
    /// `alignment` is not a power of two or the allocation fails.
    pub safe fn mi_malloc_aligned(size: usize, alignment: usize) -> *mut c_void;

    /// Allocates `size` zeroed bytes aligned to `alignment`, or returns null
    /// if `alignment` is not a power of two or the allocation fails.
    pub safe fn mi_zalloc_aligned(size: usize, alignment: usize) -> *mut c_void;

    /// Resizes the block at `p` to `newsize` bytes aligned to `alignment`, in
    /// place or by moving it, or returns null if `alignment` is not a power of
    /// two or the allocation fails. `p` must be null or a live block from this
    /// allocator and may have any alignment. A non-null result consumes `p`,
    /// and a null result leaves it live.
    pub fn mi_realloc_aligned(p: *mut c_void, newsize: usize, alignment: usize) -> *mut c_void;

    /// Frees the block at `p`. When `size` is at most `MI_SMALL_SIZE_MAX`
    /// and `alignment` is at most `size`, mimalloc finds the block's page by
    /// aligning `p` down to the small page size and skips the page-metadata
    /// lookup. `p` must be null or a live block from this allocator that is
    /// aligned to `alignment` and has at least `size` usable bytes.
    pub fn mi_free_size_aligned(p: *mut c_void, size: usize, alignment: usize);

    /// Returns the size of the block mimalloc allocates for `size` bytes.
    pub safe fn mi_good_size(size: usize) -> usize;

    /// Returns whether `p` lies in memory mimalloc manages. It looks `p` up in
    /// the page map without reading through it, so any address is accepted.
    pub safe fn mi_is_in_heap_region(p: *const c_void) -> bool;

    /// Returns the linked mimalloc version number.
    pub safe fn mi_version() -> c_int;

    /// Initializes mimalloc for the process. Only the first call has an effect.
    pub safe fn mi_process_init();

    /// Returns the alignment mimalloc gives an arena's start. A managed range
    /// that starts unaligned loses the bytes before its first aligned address.
    pub safe fn mi_arena_min_alignment() -> usize;

    /// Returns the size of an arena chunk. mimalloc manages arenas in whole
    /// chunks and rejects a smaller range.
    pub safe fn mi_arena_min_size() -> usize;

    /// Returns the arena object-size limit in force. mimalloc rounds the
    /// `arena_max_object_size` option up to a slice and clamps it between one
    /// slice and its own ceiling.
    pub safe fn mi_arena_max_object_size() -> usize;

    /// Returns the value of `option`. The first read of an option initializes
    /// it from the environment, so a read can write the option table.
    pub safe fn mi_option_get(option: mi_option_t) -> c_long;

    /// Sets `option` to `value`. Callers must bound `value`, because mimalloc
    /// does unchecked arithmetic with options, such as adding the purge delay
    /// to its clock.
    pub fn mi_option_set(option: mi_option_t, value: c_long);

    /// Reserves `size` bytes from the operating system as a new arena and
    /// returns 0, or `ENOMEM` on failure. `arena_id` must be null or writable.
    pub fn mi_reserve_os_memory_ex(
        size: usize,
        commit: bool,
        allow_large: bool,
        exclusive: bool,
        arena_id: *mut mi_arena_id_t,
    ) -> c_int;

    /// Hands the mapping at `start` to mimalloc as a new arena and returns
    /// whether mimalloc accepted it. On true, mimalloc uses the mapping for the
    /// rest of the process. On false, it keeps no reference to it.
    ///
    /// `start` must begin a mapping of `size` bytes owned by this process, and
    /// the flags must describe it truthfully. `arena_id` must be null or
    /// writable.
    pub fn mi_manage_os_memory_ex(
        start: *mut c_void,
        size: usize,
        is_committed: bool,
        is_pinned: bool,
        is_zero: bool,
        numa_node: c_int,
        exclusive: bool,
        arena_id: *mut mi_arena_id_t,
    ) -> bool;

    /// Fills `stats` with the process's statistics and returns true, or
    /// writes nothing and returns false if `stats` is null or its `size` or
    /// `version` differ from the linked mimalloc's. `stats` must be null or
    /// point to a writable [`mi_stats_t`].
    pub fn mi_stats_get(stats: *mut mi_stats_t) -> bool;
}
