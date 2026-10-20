//! Raw bindings to the vendored mimalloc, limited to what the wrapper uses.
//!
//! Signatures follow the headers in `mimalloc/include` for the version recorded
//! in `mimalloc/VERSION`. Functions that dereference no pointer and have no
//! value precondition are declared `safe`. Each `unsafe` function documents
//! what its caller must uphold.

#![allow(non_camel_case_types)]

use std::ffi::{c_char, c_int, c_long, c_void};

/// Opaque arena identifier. The wrapper only passes null.
pub type mi_arena_id_t = *mut c_void;

/// Runtime option identifier (an index into mimalloc's option table).
pub type mi_option_t = c_int;

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

    /// Frees the block at `p`. `p` must be null or a live block from this
    /// allocator.
    pub fn mi_free(p: *mut c_void);

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

    /// Formats mimalloc's statistics as NUL-terminated JSON, or returns null on
    /// failure. `buf` must be null or writable for `buf_size` bytes. A non-null
    /// `buf` with a nonzero `buf_size` receives the text, cut off if it does
    /// not fit, and is returned. Otherwise the result is a new allocation that
    /// the caller must free with [`mi_free`].
    pub fn mi_stats_get_json(buf_size: usize, buf: *mut c_char) -> *mut c_char;
}
