//! Raw bindings to the vendored mimalloc, limited to what the wrapper uses.
//!
//! Signatures follow `mimalloc/include/mimalloc.h` for the version recorded
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
    pub safe fn mi_malloc(size: usize) -> *mut c_void;
    pub safe fn mi_zalloc(size: usize) -> *mut c_void;

    /// `p` must be null or a live block from this allocator, which the call
    /// consumes when it returns non-null. On null, `p` stays live.
    pub fn mi_realloc(p: *mut c_void, newsize: usize) -> *mut c_void;

    pub safe fn mi_malloc_aligned(size: usize, alignment: usize) -> *mut c_void;
    pub safe fn mi_zalloc_aligned(size: usize, alignment: usize) -> *mut c_void;

    /// `p` must be null or a live block from this allocator with at least
    /// `alignment`, which the call consumes when it returns non-null. On null,
    /// `p` stays live.
    pub fn mi_realloc_aligned(p: *mut c_void, newsize: usize, alignment: usize) -> *mut c_void;

    /// `p` must be null or a live block from this allocator, which the call
    /// consumes.
    pub fn mi_free(p: *mut c_void);

    pub safe fn mi_good_size(size: usize) -> usize;

    /// Looks `p` up in the page map without reading through it, so any
    /// address is accepted.
    pub safe fn mi_is_in_heap_region(p: *const c_void) -> bool;

    pub safe fn mi_version() -> c_int;
    pub safe fn mi_process_init();
    pub safe fn mi_arena_min_alignment() -> usize;
    pub safe fn mi_arena_min_size() -> usize;
    pub safe fn mi_arena_max_object_size() -> usize;
    pub safe fn mi_option_get(option: mi_option_t) -> c_long;

    /// Callers must bound `value`, because mimalloc does unchecked arithmetic
    /// with options, such as adding the purge delay to its clock.
    pub fn mi_option_set(option: mi_option_t, value: c_long);

    /// `arena_id` must be null or writable.
    pub fn mi_reserve_os_memory_ex(
        size: usize,
        commit: bool,
        allow_large: bool,
        exclusive: bool,
        arena_id: *mut mi_arena_id_t,
    ) -> c_int;

    /// `start` must begin a mapping of `size` bytes owned by this process, and
    /// the flags must describe it truthfully. `arena_id` must be null or
    /// writable. On true, mimalloc uses the mapping for the rest of the
    /// process. On false, it keeps no reference to it.
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

    /// `buf` must be null or writable for `buf_size` bytes. The result is
    /// NUL-terminated or null.
    pub fn mi_stats_get_json(buf_size: usize, buf: *mut c_char) -> *mut c_char;
}
