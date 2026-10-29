//! [mimalloc](https://github.com/microsoft/mimalloc) is a general-purpose
//! allocator that serves each size class from thread-local pages carved out
//! of arenas of operating system memory, returns an object freed by any
//! thread to the page it came from, and purges freed arena memory back to
//! the operating system after a delay.
//!
//! This module installs mimalloc as the global allocator through
//! [`MiMalloc`], a [`GlobalAlloc`] whose [`Config`] lives in the binary and
//! is applied by the first allocation. [`Effective`] reports the options in
//! force and [`Stats`] reports allocator statistics.
//!
//! # Configuration timing
//!
//! mimalloc creates its first arena at the first allocation, which happens
//! before `main` on most targets. [`MiMalloc`] applies its [`Config`] on that
//! allocation, so the purge policy is in force before any memory is freed and
//! a reservation is the first arena threads search.
//!
//! # Linking
//!
//! The crate declares `links = "mimalloc"`, so Cargo rejects a dependency
//! graph in which another package, such as `libmimalloc-sys`, declares the
//! same key.
//!
//! Enable the `local-dynamic-tls` feature when the crate is built into a
//! shared library that is loaded with `dlopen`. Without it, mimalloc uses
//! initial-exec thread-local storage on targets other than musl. That storage
//! comes from a static block the loader sizes at startup, and a library
//! loaded later may not fit in it. The feature also has mimalloc free what
//! memory it can when the library is unloaded.
//!
//! # Page geometry
//!
//! mimalloc carves arenas into slices and derives its page sizes from the
//! slice. Slices form chunks, and chunks form the metadata groups of an
//! arena. One group looks like this with the default slice on 64-bit targets:
//!
//! ```text
//! one metadata group: 8 chunks, 256 MiB
//!         |<----- ARENA_MAX_OBJECT_SIZE: 7 chunks, 224 MiB ------>|
//! +-------+-------+-------+-------+-------+---------------+-------+
//! |chunk 0|chunk 1|chunk 2|chunk 3|chunk 4|page of its own|chunk 7|
//! +-------+-------+-------+-------+-------+---------------+-------+
//! |       |
//! |       '-------------------------------------------------------.
//! |                                                               |
//! +--------+--------+---------+-----------------+-----------------+
//! |  page  | small  | medium  |      large      |                 |
//! |metadata|1 slice |8 slices |    64 slices    |       ...       |
//! |  table | 64 KiB | 512 KiB |      4 MiB      |                 |
//! +--------+--------+---------+-----------------+-----------------+
//!          |<------>| ARENA_SLICE_SIZE
//! |<----------- ARENA_CHUNK_SIZE: 512 slices, 32 MiB ------------>|
//! ```
//!
//! Objects up to [`LARGE_OBJECT_LIMIT`] come from thread-local pages at the
//! cost of a free-list operation. Larger objects get a page of their own,
//! which costs an arena operation per allocation and free.
//!
//! The crate's `large-objects-*` features raise the limit at build time by
//! scaling the slice ([`ARENA_SLICE_SIZE`]) and with it every page. The
//! geometry applies to the whole process, so only binaries should enable
//! them. The largest enabled feature wins.
//!
//! # Large objects
//!
//! Where an allocation lives depends on its size and alignment:
//!
//! ```text
//! allocation (size, alignment)
//!   |
//!   +-- alignment >= metadata group (256 MiB) ---> null
//!   |
//!   +-- alignment > ARENA_SLICE_SIZE (64 KiB) ---> page of its own,
//!   |                                              mapped from the OS
//!   v
//! size <= LARGE_OBJECT_LIMIT (512 KiB)?
//!   | yes                             | no
//!   v                                 v
//! shared page of its size class       page of its own
//!   |                                 |
//!   '----------------+----------------'
//!                    v
//! page <= Config::arena_max_object_size?
//!   | yes                             | no
//!   v                                 v
//! arena -- no room, no new arena ---> OS mapping
//! ```
//!
//! A shared page outlives its objects for reuse. A page of its own is sized
//! to the object rounded up (by as much as 4 MiB for the largest), and
//! freeing the object releases it. The exception is a small object aligned
//! beyond a slice and freed by another thread, which holds its page until the
//! owning thread collects.
//!
//! An arena keeps a released page until the [`Purge`] policy purges it. A
//! page spanning several chunks (see [`ARENA_CHUNK_SIZE`]) needs that many
//! consecutive free chunks, so a fragmented arena can make mimalloc reserve a
//! new arena or, failing that, map the page from the operating system. Such
//! a page is unmapped on release, so each allocation pays for system calls
//! and fresh page faults.
//!
//! Pages above [`Config::arena_max_object_size`] are mapped from the
//! operating system the same way. The limit defaults to and is capped at
//! [`ARENA_MAX_OBJECT_SIZE`], the largest page an arena can hold. A limit below
//! the largest shared page also maps the shared pages of larger size classes
//! from the operating system. Those pages are still kept for reuse.
//!
//! Alignments of a whole metadata group or more are refused with null, which
//! a [`GlobalAlloc`] caller reports as an allocation error.
//!
//! # Example
//!
//! ```no_run
//! use commonware_allocator::mimalloc::{Config, MiMalloc, Purge, Reserve, Status};
//! use std::time::Duration;
//!
//! #[global_allocator]
//! static GLOBAL: MiMalloc = MiMalloc::new(Config {
//!     purge: Purge::After(Duration::from_secs(10)),
//!     reserve: Some(Reserve::pinned(2 << 30)),
//!     ..Config::DEFAULT
//! });
//!
//! fn main() {
//!     assert!(commonware_allocator::mimalloc::is_global_allocator());
//!     println!("{:?}", Status::read());
//! }
//! ```

mod ffi;
pub mod metrics;

use ffi as mi;
use std::{
    alloc::{GlobalAlloc, Layout},
    ffi::{c_long, c_void},
    hint::spin_loop,
    mem, ptr,
    sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
    time::Duration,
};

/// mimalloc options the wrapper reads or writes, numbered as `mi_option_t` in
/// the vendored `mimalloc.h`. A test checks the values against that header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
enum OptionId {
    /// Commit policy for arenas mimalloc reserves on demand: 0 on first use,
    /// 1 eagerly, 2 eagerly where the system overcommits or large OS pages
    /// are allowed.
    ArenaEagerCommit = 4,
    /// Whether a purge decommits memory rather than resetting it (flag).
    PurgeDecommits = 5,
    /// Whether arenas may be backed by large OS pages (flag).
    AllowLargeOsPages = 6,
    /// Milliseconds a freed arena range waits before it may be purged: -1
    /// never purges, 0 purges on free.
    PurgeDelay = 15,
    /// Base size of arenas reserved on demand, in KiB.
    ArenaReserve = 23,
    /// Factor applied to the purge delay for arena memory.
    ArenaPurgeMult = 24,
    /// Transparent huge pages: 0 disallowed, 1 allowed, 2 allowed with
    /// purging in whole huge pages.
    AllowThp = 43,
    /// Largest page an arena may hold, in KiB.
    ArenaMaxObjectSize = 45,
    // TODO(#5483): Update the vendored mimalloc to a release that includes
    // this option and drop the backport described in mimalloc/README.md.
    /// Bytes a thread allocates and frees between merges of its statistics
    /// into the process totals, or 0 to merge only when the thread collects
    /// or exits.
    StatsMergeThreshold = 48,
}

impl OptionId {
    fn get(self) -> c_long {
        mi::mi_option_get(self as mi::mi_option_t)
    }

    fn set(self, value: c_long) {
        // SAFETY: callers pass flags, KiB sizes bounded by `size_option`,
        // delays bounded by `MAX_PURGE_DELAY`, or byte counts mimalloc only
        // compares. They run inside `apply` under the `OptionsGuard`, so no
        // reader observes a partial write.
        unsafe { mi::mi_option_set(self as mi::mi_option_t, value) }
    }
}

/// Bytes handed to mimalloc as pinned arenas. mimalloc accounts only for
/// memory it mapped itself, so these are reported separately in
/// [`Stats::pinned_bytes`].
static PINNED_BYTES: AtomicU64 = AtomicU64::new(0);

/// Serializes access to mimalloc's option table, which holds plain C values.
/// Configuration and [`Effective::read`] hold it. mimalloc reads options only
/// inside allocations, which wait until configuration is published. The guard
/// never allocates because configuration runs inside `alloc`.
static OPTIONS_LOCK: AtomicBool = AtomicBool::new(false);

struct OptionsGuard;

impl OptionsGuard {
    fn lock() -> Self {
        while OPTIONS_LOCK
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            spin_loop();
        }
        Self
    }
}

impl Drop for OptionsGuard {
    fn drop(&mut self) {
        OPTIONS_LOCK.store(false, Ordering::Release);
    }
}

/// Log2 of the arena slice size. Without a `large-objects-*` feature it is
/// mimalloc's default (`13 + MI_SIZE_SHIFT` in the vendored `types.h`).
const ARENA_SLICE_SHIFT: u32 = if cfg!(feature = "large-objects-4mb") {
    19
} else if cfg!(feature = "large-objects-2mb") {
    18
} else if cfg!(feature = "large-objects-1mb") {
    17
} else {
    13 + size_of::<usize>().trailing_zeros()
};

/// Size of an arena slice, the unit mimalloc carves arenas into and the
/// smallest page size.
pub const ARENA_SLICE_SIZE: usize = 1 << ARENA_SLICE_SHIFT;

/// Size of an arena chunk, the unit reservations are rounded down to (see
/// [`Reserve::bytes`]). It is 512 slices, or 32 MiB at the default slice on
/// 64-bit targets.
pub const ARENA_CHUNK_SIZE: usize = 64 * size_of::<usize>() * ARENA_SLICE_SIZE;

/// Largest allocation served from a shared thread-local page. It is eight
/// slices: 512 KiB by default, or the size named by an enabled
/// `large-objects-*` feature. Larger objects get a page of their own, which
/// costs an arena operation per allocation and free.
pub const LARGE_OBJECT_LIMIT: usize = size_of::<usize>() * ARENA_SLICE_SIZE;

/// Largest page an arena can hold, and so the cap on
/// [`Config::arena_max_object_size`]. mimalloc keeps page metadata at the
/// start of every metadata group, so a page spans at most the group's other
/// chunks: seven chunks, or 224 MiB at the default slice on 64-bit targets.
pub const ARENA_MAX_OBJECT_SIZE: usize = (size_of::<usize>() - 1) * ARENA_CHUNK_SIZE;

/// When memory freed back to an arena is purged (decommitted) to the
/// operating system.
///
/// The policy covers arena memory only. Pages above
/// [`Config::arena_max_object_size`] and objects aligned beyond a slice are
/// mapped directly and unmapped on release. Pinned reservations (see
/// [`Reserve`]) are never purged.
///
/// When the kernel supports transparent huge pages and they are allowed (the
/// default), a purge releases only whole 2 MiB granules freed since the
/// arena's last purge. A smaller freed range stays resident until its
/// neighbors are freed too.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purge {
    /// Never purge arena memory.
    Never,
    /// Purge freed memory after a delay. The first free into an arena after a
    /// purge sets a deadline this far ahead, and the arena is purged at the
    /// first collection after it. A thread collects every 10,000 allocations
    /// that miss its fast path by default, so a process that allocates rarely
    /// can keep freed memory well past the deadline. Delays above
    /// [`MAX_PURGE_DELAY`] are clamped, and one below a millisecond purges
    /// each page as it is freed.
    After(Duration),
}

/// When the arenas mimalloc reserves on demand commit their memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EagerCommit {
    /// Commit each slice when it is first used.
    Never,
    /// Commit the whole arena when it is reserved.
    Always,
    /// Commit eagerly on systems that overcommit memory or when large OS pages
    /// are allowed, and on first use elsewhere.
    IfOvercommit,
}

/// Longest purge delay [`Purge::After`] applies (about 24 days). mimalloc
/// stores the delay in milliseconds in a C `long`, which is 32 bits on some
/// platforms.
pub const MAX_PURGE_DELAY: Duration = Duration::from_millis(i32::MAX as u64);

/// Memory reserved from the operating system before the first allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reserve {
    /// Bytes to reserve, rounded down to whole [`ARENA_CHUNK_SIZE`] chunks. A
    /// reservation below one chunk fails.
    pub bytes: usize,
    /// Pinned memory is mapped by this crate and handed to mimalloc as an
    /// arena that is never purged. Unpinned memory is reserved through
    /// mimalloc and purged like any other arena, unless the kernel granted it
    /// large OS pages. On Linux, both get transparent huge page advice when
    /// [`Config::transparent_huge_pages`] allows it.
    pub pinned: bool,
    /// Touch every page of a pinned reservation up front so first use never
    /// faults. Ignored for unpinned reservations.
    pub prefault: bool,
}

impl Reserve {
    /// A pinned reservation that is faulted in on first use.
    pub const fn pinned(bytes: usize) -> Self {
        Self {
            bytes,
            pinned: true,
            prefault: false,
        }
    }

    /// A reservation managed and purged by mimalloc.
    pub const fn unpinned(bytes: usize) -> Self {
        Self {
            bytes,
            pinned: false,
            prefault: false,
        }
    }
}

/// Configuration applied by [`MiMalloc`] on its first allocation.
///
/// [`Config::DEFAULT`] holds mimalloc's defaults, with the arena object-size
/// limit capped at [`ARENA_MAX_OBJECT_SIZE`]. Set the fields to change and
/// take the rest from it with `..Config::DEFAULT`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    /// When freed memory is purged back to the operating system.
    pub purge: Purge,
    /// Memory reserved before the first allocation.
    pub reserve: Option<Reserve>,
    /// Whether mimalloc may back arenas with large (2 MiB) OS pages when the
    /// kernel grants them. Large-page arenas are never purged, are not
    /// swappable, and come from the kernel's huge page pool.
    pub allow_large_os_pages: bool,
    /// Whether the process may use transparent huge pages. On Linux this also
    /// sets the process flag the kernel consults for every mapping, replacing
    /// any value inherited from the parent process.
    pub transparent_huge_pages: bool,
    /// When the arenas mimalloc reserves on demand commit their memory.
    pub arena_eager_commit: EagerCommit,
    /// Base size of the arenas mimalloc reserves on demand once existing
    /// arenas are full, rounded up to KiB. mimalloc reserves at least two
    /// chunks per arena and grows the size with the arena count and for
    /// larger requests.
    ///
    /// Zero disables on-demand arenas. Pages that no existing arena can hold
    /// are then mapped from the operating system and unmapped on release.
    pub arena_reserve: usize,
    /// Largest page carved from an arena, in bytes, rounded up to a slice and
    /// clamped between one slice and [`ARENA_MAX_OBJECT_SIZE`]. Larger pages
    /// are mapped from the operating system and unmapped on release, so a
    /// lower limit keeps occasional huge buffers from holding arena memory.
    /// See the module docs on large objects.
    pub arena_max_object_size: usize,
    /// Bytes a thread may allocate and free before it merges its allocation
    /// statistics into the process totals that [`Stats`] reads. A smaller
    /// value keeps those totals closer to the truth but merges more often,
    /// and each merge adds every statistic into shared atomics. A thread that
    /// allocates or frees blocks at least this large merges on every one.
    ///
    /// Zero merges only when a thread collects or exits, so
    /// [`Stats::allocated_bytes`] can drift without bound while threads free
    /// each other's memory.
    pub stats_merge_threshold: usize,
}

impl Config {
    /// mimalloc's defaults, with the arena object-size limit capped at
    /// [`ARENA_MAX_OBJECT_SIZE`].
    pub const DEFAULT: Self = Self {
        purge: Purge::After(Duration::from_secs(4)),
        reserve: None,
        allow_large_os_pages: false,
        transparent_huge_pages: !cfg!(target_os = "android"),
        arena_eager_commit: EagerCommit::IfOvercommit,
        arena_reserve: if size_of::<usize>() > 4 {
            1 << 30
        } else {
            128 << 20
        },
        arena_max_object_size: ARENA_MAX_OBJECT_SIZE,
        stats_merge_threshold: 4 << 20,
    };
}

impl Default for Config {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Outcome of the reservation requested by [`Config::reserve`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReserveOutcome {
    /// No reservation was requested.
    NotRequested,
    /// The reservation is a pinned arena that is never purged.
    Pinned,
    /// The reservation is an ordinary arena managed by mimalloc.
    Reserved,
    /// The operating system or mimalloc refused the reservation. Allocation
    /// continues from on-demand arenas.
    Failed,
}

/// Process-wide configuration state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    /// Whether a [`MiMalloc`] has configured the process, which happens on
    /// its first allocation.
    pub configured: bool,
    /// Outcome of the requested reservation.
    pub reserve: ReserveOutcome,
}

impl Status {
    /// Reads whether the process has been configured and how the
    /// reservation went.
    pub fn read() -> Self {
        let Some(outcome) = STATE.load(Ordering::Acquire).checked_sub(1) else {
            return Self {
                configured: false,
                reserve: ReserveOutcome::NotRequested,
            };
        };
        let reserve = match outcome {
            x if x == ReserveOutcome::Pinned as u8 => ReserveOutcome::Pinned,
            x if x == ReserveOutcome::Reserved as u8 => ReserveOutcome::Reserved,
            x if x == ReserveOutcome::Failed as u8 => ReserveOutcome::Failed,
            _ => ReserveOutcome::NotRequested,
        };
        Self {
            configured: true,
            reserve,
        }
    }
}

/// Largest alignment `mi_malloc` can satisfy (`MI_MAX_ALIGN_SIZE` in the
/// vendored `types.h`, checked by a test). A size that is a multiple of 16
/// maps to a size class whose blocks are all 16-byte aligned.
const MALLOC_ALIGNMENT: usize = 16;

/// Alignment every `mi_malloc` block has regardless of size.
const WORD_ALIGNMENT: usize = size_of::<usize>();

/// Whether a plain `mi_malloc` block of `size` bytes is aligned to `align`,
/// so the aligned entry points can be skipped.
#[inline]
const fn malloc_satisfies(size: usize, align: usize) -> bool {
    align <= WORD_ALIGNMENT || (align <= MALLOC_ALIGNMENT && size & (align - 1) == 0)
}

/// Zero until a [`MiMalloc`] has configured the process, then the
/// [`ReserveOutcome`] plus one.
static STATE: AtomicU8 = AtomicU8::new(0);

/// mimalloc as a `#[global_allocator]` with a [`Config`] applied on the first
/// allocation.
///
/// Configuration is process-wide. The first instance to serve an allocation
/// applies its [`Config`], and later instances never apply theirs.
/// [`Status::read`] reports the outcome.
pub struct MiMalloc {
    config: Config,
}

impl MiMalloc {
    /// Creates an allocator that requests `config`.
    pub const fn new(config: Config) -> Self {
        Self { config }
    }

    /// Returns the configuration this allocator requests.
    pub const fn config(&self) -> &Config {
        &self.config
    }

    #[inline]
    fn ensure_configured(&self) {
        if STATE.load(Ordering::Acquire) == 0 {
            self.configure();
        }
    }

    /// Applies the configuration once. Concurrent first allocations wait on
    /// the options guard and then find the state set. Nothing here allocates
    /// through Rust, so the first allocation cannot recurse.
    #[cold]
    #[inline(never)]
    fn configure(&self) {
        let _guard = OptionsGuard::lock();
        if STATE.load(Ordering::Relaxed) != 0 {
            return;
        }
        let outcome = apply(&self.config);
        STATE.store(outcome as u8 + 1, Ordering::Release);
    }
}

// SAFETY: mimalloc is thread-safe and the configuration state is accessed
// through atomics. Layouts that `malloc_satisfies` rejects use the aligned
// entry points, and mimalloc frees and reallocates blocks from either.
unsafe impl GlobalAlloc for MiMalloc {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.ensure_configured();
        if malloc_satisfies(layout.size(), layout.align()) {
            mi::mi_malloc(layout.size()) as *mut u8
        } else {
            mi::mi_malloc_aligned(layout.size(), layout.align()) as *mut u8
        }
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        self.ensure_configured();
        if malloc_satisfies(layout.size(), layout.align()) {
            mi::mi_zalloc(layout.size()) as *mut u8
        } else {
            mi::mi_zalloc_aligned(layout.size(), layout.align()) as *mut u8
        }
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // The layout lets mimalloc find a small block's page without looking
        // up its metadata.
        // SAFETY: GlobalAlloc requires `ptr` to be a block currently
        // allocated by this allocator with `layout`, so it has at least
        // `layout.size()` usable bytes and is aligned to `layout.align()`.
        unsafe { mi::mi_free_size_aligned(ptr as *mut c_void, layout.size(), layout.align()) }
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // Route by the new size. When plain `mi_malloc` satisfies it, the
        // block `mi_realloc` returns is aligned whether it stays in place or
        // moves, and a moved block lands in its exact size class. The aligned
        // entry point can pad a moved block into the next class.
        // SAFETY: GlobalAlloc requires ptr to come from this allocator with the given layout.
        unsafe {
            if malloc_satisfies(new_size, layout.align()) {
                mi::mi_realloc(ptr as *mut c_void, new_size) as *mut u8
            } else {
                mi::mi_realloc_aligned(ptr as *mut c_void, new_size, layout.align()) as *mut u8
            }
        }
    }
}

/// Applies `config` to the process-wide mimalloc instance. The caller holds
/// the [`OptionsGuard`].
fn apply(config: &Config) -> ReserveOutcome {
    mi::mi_process_init();
    match config.purge {
        Purge::Never => OptionId::PurgeDelay.set(-1),
        Purge::After(delay) => {
            // mimalloc 3 purges only arenas and scales their delay by the
            // arena multiplier, so a multiplier of one applies the delay as
            // given.
            OptionId::PurgeDelay.set(purge_millis(delay));
            OptionId::ArenaPurgeMult.set(1);
        }
    }
    OptionId::ArenaEagerCommit.set(match config.arena_eager_commit {
        EagerCommit::Never => 0,
        EagerCommit::Always => 1,
        EagerCommit::IfOvercommit => 2,
    });
    OptionId::AllowLargeOsPages.set(c_long::from(config.allow_large_os_pages));
    set_transparent_huge_pages(config.transparent_huge_pages);
    OptionId::ArenaReserve.set(size_option(config.arena_reserve.div_ceil(1024)));
    OptionId::StatsMergeThreshold
        .set(c_long::try_from(config.stats_merge_threshold).unwrap_or(c_long::MAX));

    // Cap the limit at `ARENA_MAX_OBJECT_SIZE`. mimalloc's own ceiling admits
    // pages no arena can hold, and it reserves a futile arena for each before
    // mapping from the operating system.
    let limit = size_option(config.arena_max_object_size.div_ceil(1024));
    OptionId::ArenaMaxObjectSize.set(limit.min(size_option(ARENA_MAX_OBJECT_SIZE / 1024)));
    match config.reserve {
        None => ReserveOutcome::NotRequested,
        Some(reserve) => {
            let Some(size) = whole_chunks(reserve.bytes) else {
                return ReserveOutcome::Failed;
            };
            if reserve.pinned {
                return manage_pinned(size, reserve.prefault);
            }

            // Allow large pages as mimalloc does for its on-demand arenas. Its
            // mapping code checks `allow_large_os_pages` first, and the
            // permission also enables transparent huge page advice.
            // SAFETY: the arena identifier output is null, so nothing is
            // written through it.
            let err =
                unsafe { mi::mi_reserve_os_memory_ex(size, true, true, false, ptr::null_mut()) };
            if err == 0 {
                ReserveOutcome::Reserved
            } else {
                ReserveOutcome::Failed
            }
        }
    }
}

/// Rounds `bytes` down to whole arena chunks, or `None` below one chunk.
/// mimalloc uses only whole chunks, so the remainder is never mapped.
fn whole_chunks(bytes: usize) -> Option<usize> {
    let chunk = mi::mi_arena_min_size();
    Some(bytes / chunk * chunk).filter(|size| *size > 0)
}

/// Bounds a size option in KiB so mimalloc's value in bytes fits a `c_long`.
fn size_option(kib: usize) -> c_long {
    kib.min(c_long::MAX as usize / 1024) as c_long
}

/// A purge delay in the milliseconds mimalloc stores, bounded by
/// [`MAX_PURGE_DELAY`].
fn purge_millis(delay: Duration) -> c_long {
    delay.min(MAX_PURGE_DELAY).as_millis() as c_long
}

/// Computes the arena purge delay from the raw options as mimalloc does. A
/// negative factor disables purging, and an overflowing product falls back to
/// the bare delay.
fn arena_purge_delay(delay: c_long, mult: c_long) -> Option<Duration> {
    if delay < 0 || mult < 0 {
        return None;
    }
    let (delay, mult) = (delay as u64, mult as u64);
    let total = delay
        .checked_mul(mult)
        .filter(|total| c_long::try_from(*total).is_ok())
        .unwrap_or(delay);
    Some(Duration::from_millis(total))
}

/// Applies the transparent huge page policy.
///
/// mimalloc sets the Linux process flag only when it initializes at load,
/// while the option keeps steering its huge page advice and purge
/// granularity. The flag is therefore set here in both directions.
fn set_transparent_huge_pages(allowed: bool) {
    // mimalloc's default (2) allows huge pages and purges at huge-page
    // granularity so purging does not split them.
    OptionId::AllowThp.set(if allowed { 2 } else { 0 });
    #[cfg(target_os = "linux")]
    // SAFETY: this prctl takes integer arguments only.
    unsafe {
        libc::prctl(
            libc::PR_SET_THP_DISABLE,
            libc::c_ulong::from(!allowed),
            0,
            0,
            0,
        );
    }
}

/// Maps `size` bytes of anonymous memory, a whole number of chunks, and
/// hands them to mimalloc as a pinned, committed arena.
///
/// The mapping includes slack for mimalloc's arena alignment and is trimmed
/// at both ends before the handover.
fn manage_pinned(size: usize, prefault: bool) -> ReserveOutcome {
    let alignment = mi::mi_arena_min_alignment();
    let Some(len) = size.checked_add(alignment) else {
        return ReserveOutcome::Failed;
    };
    // SAFETY: anonymous mapping with no file descriptor.
    let base = unsafe {
        libc::mmap(
            ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if base == libc::MAP_FAILED {
        return ReserveOutcome::Failed;
    }
    let Some(start) = (base as usize).checked_next_multiple_of(alignment) else {
        // SAFETY: the mapping was created above and never handed out.
        unsafe { libc::munmap(base, len) };
        return ReserveOutcome::Failed;
    };
    let head = start - base as usize;
    let tail = len - head - size;
    // SAFETY: both slack ranges lie inside the mapping created above and are
    // never handed to mimalloc.
    unsafe {
        if head > 0 {
            libc::munmap(base, head);
        }
        if tail > 0 {
            libc::munmap((start + size) as *mut c_void, tail);
        }
    }

    // Advise huge pages as mimalloc does for its own arenas, so a kernel in
    // madvise mode backs the reservation with them.
    #[cfg(target_os = "linux")]
    if OptionId::AllowThp.get() != 0 {
        // SAFETY: the range is a live private mapping owned by this function.
        unsafe { libc::madvise(start as *mut c_void, size, libc::MADV_HUGEPAGE) };
    }
    if prefault {
        // SAFETY: every touched address lies inside the retained range.
        unsafe {
            let page = libc::sysconf(libc::_SC_PAGESIZE).max(4096) as usize;
            let mut offset = 0;
            while offset < size {
                ptr::write_volatile((start + offset) as *mut u8, 0);
                offset += page;
            }
        }
    }

    // SAFETY: the range is a live private mapping that nothing else uses.
    // mimalloc owns it for the rest of the process if the call returns true.
    let managed = unsafe {
        mi::mi_manage_os_memory_ex(
            start as *mut c_void,
            size,
            true,
            true,
            true,
            -1,
            false,
            ptr::null_mut(),
        )
    };
    if managed {
        PINNED_BYTES.fetch_add(size as u64, Ordering::Relaxed);
        ReserveOutcome::Pinned
    } else {
        // SAFETY: mimalloc keeps no reference to a mapping it refused, so the
        // aligned remainder is still owned here and unused.
        unsafe { libc::munmap(start as *mut c_void, size) };
        ReserveOutcome::Failed
    }
}

/// Returns whether the global allocator is this crate's mimalloc, installed
/// directly through [`MiMalloc`] or wrapped by another allocator. It checks a
/// probe allocation against mimalloc's heap region.
pub fn is_global_allocator() -> bool {
    let probe = Box::new(0u8);
    mi::mi_is_in_heap_region(ptr::from_ref::<u8>(&probe).cast())
}

/// Returns the linked mimalloc version as `major * 10000 + minor * 100 + patch`.
pub fn version() -> u32 {
    mi::mi_version() as u32
}

/// Returns the block size mimalloc allocates for `size` bytes: its size
/// class, or above the largest class, `size` rounded up to an OS page. The
/// page serving such a block may be larger.
pub fn good_size(size: usize) -> usize {
    mi::mi_good_size(size)
}

/// The options mimalloc is running with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Effective {
    /// Arena purge delay (mimalloc's purge delay times its arena multiplier),
    /// or `None` if purging is disabled.
    pub purge: Option<Duration>,
    /// Whether a purge decommits memory rather than resetting it.
    pub purge_decommits: bool,
    /// Arena commit policy as mimalloc stores it (0 lazy, 1 eager, 2 eager on
    /// systems that overcommit or when large OS pages are allowed).
    pub arena_eager_commit: i64,
    /// Whether arenas may use large OS pages.
    pub allow_large_os_pages: bool,
    /// Whether mimalloc may use transparent huge pages.
    pub transparent_huge_pages: bool,
    /// Base size of arenas reserved on demand, before mimalloc grows it with
    /// the arena count.
    pub arena_reserve: usize,
    /// Largest page carved from an arena: the configured limit rounded up to
    /// a slice and clamped between one slice and [`ARENA_MAX_OBJECT_SIZE`].
    pub arena_max_object_size: usize,
    /// Bytes a thread allocates and frees between merges of its statistics
    /// into the process totals, or 0 if it merges only when it collects or
    /// exits.
    pub stats_merge_threshold: usize,
}

impl Effective {
    /// Reads the current option values.
    pub fn read() -> Self {
        let _guard = OptionsGuard::lock();

        // `c_long` is 32 bits on some platforms, so the cast is not always a
        // no-op.
        #[allow(clippy::unnecessary_cast)]
        let arena_eager_commit = OptionId::ArenaEagerCommit.get() as i64;
        Self {
            purge: arena_purge_delay(OptionId::PurgeDelay.get(), OptionId::ArenaPurgeMult.get()),
            purge_decommits: OptionId::PurgeDecommits.get() != 0,
            arena_eager_commit,
            allow_large_os_pages: OptionId::AllowLargeOsPages.get() != 0,
            transparent_huge_pages: OptionId::AllowThp.get() != 0,
            arena_reserve: usize::try_from(OptionId::ArenaReserve.get())
                .unwrap_or(0)
                .saturating_mul(1024),
            arena_max_object_size: mi::mi_arena_max_object_size(),
            stats_merge_threshold: usize::try_from(OptionId::StatsMergeThreshold.get())
                .unwrap_or(0),
        }
    }
}

/// Process-wide allocator statistics, excluding allocations that C libraries
/// make through the system allocator.
///
/// Operating system accounting (reservations, commits, purges, mappings,
/// arenas, threads) is current when read.
///
/// Allocation counters ([`Self::allocated_bytes`],
/// [`Self::allocated_peak_bytes`], [`Self::pages`],
/// [`Self::huge_allocations`], [`Self::huge_bytes`]) are kept by each thread
/// and merged into these totals once the bytes it has allocated and freed
/// since its last merge reach [`Config::stats_merge_threshold`], and whenever
/// it collects, exits, or reads statistics. Each thread holds back less than
/// that threshold, plus blocks on its own pages that it has not yet counted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Bytes mimalloc has mapped from the operating system for its arenas,
    /// page map, and directly mapped pages. Pinned reservations are counted
    /// in [`Self::pinned_bytes`] instead.
    pub reserved_bytes: u64,
    /// Bytes of pinned reservations, which are never purged.
    pub pinned_bytes: u64,
    /// Bytes currently committed, as mimalloc accounts them. On systems that
    /// overcommit, an eagerly committed on-demand arena counts as its slices
    /// are first used, while an unpinned [`Reserve`] counts in full and then
    /// again as its slices are first used. On Unix, a purge does not lower
    /// the figure.
    pub committed_bytes: u64,
    /// Peak committed bytes.
    pub committed_peak_bytes: u64,
    /// Bytes currently allocated to callers, counted in block sizes (so
    /// including size-class rounding).
    pub allocated_bytes: u64,
    /// Sum of the separately tracked peaks of normal and huge allocations,
    /// which can exceed their combined peak.
    pub allocated_peak_bytes: u64,
    /// Cumulative bytes purged back to the operating system.
    pub purged_bytes: u64,
    /// Cumulative purge operations.
    pub purge_calls: u64,
    /// Cumulative arena-level purge passes.
    pub arena_purges: u64,
    /// Cumulative memory mappings requested from the operating system.
    pub mmap_calls: u64,
    /// Cumulative commit operations.
    pub commit_calls: u64,
    /// Pages (mimalloc's unit of size-class storage) currently in use. A page
    /// is counted when the thread that allocated it merges its statistics but
    /// leaves the count as soon as another thread frees it, so the count can
    /// run low by the pages each thread allocated since its last merge.
    pub pages: u64,
    /// Threads currently known to the allocator.
    pub threads: u64,
    /// Arenas currently managed.
    pub arenas: u64,
    /// Cumulative allocations larger than the largest size class, each
    /// served by a page of its own.
    pub huge_allocations: u64,
    /// Cumulative bytes of those allocations.
    pub huge_bytes: u64,
}

impl Stats {
    /// Reads the current statistics, or `None` if the linked mimalloc's
    /// statistics layout differs in size or version from the vendored header.
    pub fn read() -> Option<Self> {
        // SAFETY: `mi_stats_t` holds only integers, and all-zero bits are a
        // valid integer.
        let mut raw: mi::mi_stats_t = unsafe { mem::zeroed() };
        raw.size = size_of::<mi::mi_stats_t>();
        raw.version = mi::MI_STAT_VERSION;
        // SAFETY: `raw` is a writable `mi_stats_t` with its size and version
        // set.
        if !unsafe { mi::mi_stats_get(&mut raw) } {
            return None;
        }
        Some(Self {
            reserved_bytes: unsigned(raw.reserved.current),
            pinned_bytes: PINNED_BYTES.load(Ordering::Relaxed),
            committed_bytes: unsigned(raw.committed.current),
            committed_peak_bytes: unsigned(raw.committed.peak),
            allocated_bytes: unsigned(raw.malloc_normal.current)
                + unsigned(raw.malloc_huge.current),
            allocated_peak_bytes: unsigned(raw.malloc_normal.peak) + unsigned(raw.malloc_huge.peak),
            purged_bytes: unsigned(raw.purged.total),
            purge_calls: unsigned(raw.purge_calls.total),
            arena_purges: unsigned(raw.arena_purges.total),
            mmap_calls: unsigned(raw.mmap_calls.total),
            commit_calls: unsigned(raw.commit_calls.total),
            pages: unsigned(raw.pages.current),
            threads: unsigned(raw.threads.current),
            arenas: unsigned(raw.arena_count.total),
            huge_allocations: unsigned(raw.malloc_huge_count.total),
            huge_bytes: unsigned(raw.malloc_huge.total),
        })
    }
}

/// Converts a statistic to `u64`, reading a negative value as zero. Threads
/// merge their adjustments into the shared counts at different times, so a
/// snapshot can catch a count below zero.
fn unsigned(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const RESERVE_BYTES: usize = 2 * ARENA_CHUNK_SIZE;
    const PURGE_DELAY: Duration = Duration::from_secs(3600);

    /// A limit between slice boundaries, so the rounding is observable.
    const MAX_OBJECT: usize = ARENA_CHUNK_SIZE + 1;

    /// A merge threshold other than mimalloc's default, so applying it is
    /// observable.
    const STATS_MERGE_THRESHOLD: usize = 3 << 20;

    #[global_allocator]
    static GLOBAL: MiMalloc = MiMalloc::new(Config {
        purge: Purge::After(PURGE_DELAY),
        reserve: Some(Reserve::pinned(RESERVE_BYTES)),
        transparent_huge_pages: false,
        arena_max_object_size: MAX_OBJECT,
        stats_merge_threshold: STATS_MERGE_THRESHOLD,
        ..Config::DEFAULT
    });

    #[test]
    fn config_is_applied_before_use() {
        let status = Status::read();
        assert!(status.configured);
        assert_eq!(status.reserve, ReserveOutcome::Pinned);
        assert_eq!(OptionId::PurgeDelay.get(), 3_600_000);
        assert_eq!(OptionId::ArenaPurgeMult.get(), 1);
        assert_eq!(OptionId::AllowThp.get(), 0);
        assert_eq!(
            OptionId::StatsMergeThreshold.get(),
            STATS_MERGE_THRESHOLD as c_long
        );
        let effective = Effective::read();
        assert_eq!(effective.purge, Some(PURGE_DELAY));
        assert!(effective.purge_decommits);
        assert!(!effective.transparent_huge_pages);
        assert_eq!(effective.stats_merge_threshold, STATS_MERGE_THRESHOLD);
        #[cfg(target_os = "linux")]
        // SAFETY: this prctl takes integer arguments only.
        unsafe {
            assert_eq!(libc::prctl(libc::PR_GET_THP_DISABLE, 0, 0, 0, 0), 1);
        }
        assert!(is_global_allocator());
        assert_eq!(version(), 30503);
        assert_eq!(good_size(4096), 4096);
        assert_eq!(good_size(4096 + 32), 5120);
    }

    #[test]
    fn purge_delay_is_bounded_and_mirrors_mimalloc() {
        assert_eq!(purge_millis(Duration::MAX), c_long::from(i32::MAX));
        assert_eq!(purge_millis(Duration::from_millis(5)), 5);
        assert_eq!(arena_purge_delay(1000, 4), Some(Duration::from_secs(4)));
        assert_eq!(arena_purge_delay(0, 4), Some(Duration::ZERO));
        assert_eq!(arena_purge_delay(-1, 4), None);
        assert_eq!(arena_purge_delay(1000, -1), None);
        assert_eq!(
            arena_purge_delay(c_long::MAX, 2),
            Some(Duration::from_millis(c_long::MAX as u64))
        );
    }

    #[test]
    fn arena_object_limit_rounds_up_and_is_bounded() {
        // Bytes round up to KiB, and mimalloc rounds KiB up to a slice.
        // Oversized values are bounded so their value in bytes fits a `c_long`.
        assert_eq!(
            OptionId::ArenaMaxObjectSize.get(),
            (ARENA_CHUNK_SIZE / 1024 + 1) as c_long
        );
        assert_eq!(
            Effective::read().arena_max_object_size,
            ARENA_CHUNK_SIZE + ARENA_SLICE_SIZE
        );
        assert_eq!(size_option(usize::MAX), c_long::MAX / 1024);
    }

    #[test]
    fn constants_match_vendored_headers() {
        // `mi_option_t` enumerators number from zero in declaration order. The
        // legacy aliases at the end have explicit values and are skipped.
        let header = include_str!("../../mimalloc/include/mimalloc.h");
        let body = header
            .split_once("typedef enum mi_option_e {")
            .and_then(|(_, rest)| rest.split_once("} mi_option_t;"))
            .map(|(body, _)| body)
            .expect("mimalloc.h must declare the mi_option_t enum");
        let mut value = -1;
        let ids: HashMap<&str, i32> = body
            .lines()
            .map(|line| {
                line.split("//")
                    .next()
                    .unwrap()
                    .trim()
                    .trim_end_matches(',')
            })
            .filter(|entry| !entry.is_empty() && !entry.contains('='))
            .map(|name| {
                value += 1;
                (name, value)
            })
            .collect();
        for (id, name) in [
            (OptionId::ArenaEagerCommit, "mi_option_arena_eager_commit"),
            (OptionId::PurgeDecommits, "mi_option_purge_decommits"),
            (
                OptionId::AllowLargeOsPages,
                "mi_option_allow_large_os_pages",
            ),
            (OptionId::PurgeDelay, "mi_option_purge_delay"),
            (OptionId::ArenaReserve, "mi_option_arena_reserve"),
            (OptionId::ArenaPurgeMult, "mi_option_arena_purge_mult"),
            (OptionId::AllowThp, "mi_option_allow_thp"),
            (
                OptionId::ArenaMaxObjectSize,
                "mi_option_arena_max_object_size",
            ),
            (
                OptionId::StatsMergeThreshold,
                "mi_option_stats_merge_threshold",
            ),
        ] {
            assert_eq!(
                ids.get(name),
                Some(&(id as i32)),
                "{name} must carry its vendored mi_option_t value"
            );
        }

        let types = include_str!("../../mimalloc/include/mimalloc/types.h");
        let max_align: usize = types
            .lines()
            .find_map(|line| line.strip_prefix("#define MI_MAX_ALIGN_SIZE"))
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|value| value.parse().ok())
            .expect("types.h must define MI_MAX_ALIGN_SIZE as an integer");
        assert_eq!(max_align, MALLOC_ALIGNMENT);
    }

    #[test]
    fn stats_layout_matches_vendored_header() {
        // `mi_stats_t` is mirrored field by field, so its layout must follow
        // the `MI_STAT_FIELDS` list, the counter shapes, the bin counts, and
        // the version in `mimalloc-stats.h`. mimalloc refuses to fill a
        // mismatched size or version at runtime, but a reordering that keeps
        // the size would read wrong values.
        let header = include_str!("../../mimalloc/include/mimalloc-stats.h");

        // The version and the last size bin index must match their defines.
        let define = |name: &str| -> usize {
            header
                .lines()
                .find_map(|line| line.strip_prefix(&format!("#define {name}")))
                .and_then(|rest| rest.split_whitespace().next())
                .map(|value| value.trim_matches(|c| c == '(' || c == ')' || c == 'U'))
                .and_then(|value| value.parse().ok())
                .unwrap_or_else(|| panic!("mimalloc-stats.h must define {name} as an integer"))
        };
        assert_eq!(define("MI_STAT_VERSION"), mi::MI_STAT_VERSION);
        assert_eq!(define("MI_BIN_HUGE"), mi::MI_BIN_HUGE);

        // Chunk bins are the enumerators declared before `MI_CBIN_COUNT`.
        let chunk_bins = header
            .split_once("typedef enum mi_chunkbin_e {")
            .and_then(|(_, rest)| rest.split_once("MI_CBIN_COUNT"))
            .map(|(body, _)| body.matches("MI_CBIN_").count())
            .expect("mimalloc-stats.h must declare the mi_chunkbin_e enum");
        assert_eq!(chunk_bins, mi::MI_CBIN_COUNT);

        // `MI_STAT_FIELDS` must list the mirrored statistics in order. Its
        // body is the run of lines that end with a backslash.
        let fields: Vec<(&str, &str)> = header
            .lines()
            .skip_while(|line| !line.starts_with("#define MI_STAT_FIELDS()"))
            .skip(1)
            .take_while(|line| line.trim_end().ends_with('\\'))
            .filter_map(|line| {
                let entry = line.trim().trim_end_matches('\\').trim();
                let entry = entry.split("/*").next().unwrap().trim();
                let (kind, rest) = entry.split_once('(')?;
                let name = rest.split_once(')')?.0.trim();
                let kind = match kind.trim() {
                    "MI_STAT_COUNT" => "mi_stat_count_t",
                    "MI_STAT_COUNTER" => "mi_stat_counter_t",
                    other => panic!(
                        "MI_STAT_FIELDS entry {other} must be MI_STAT_COUNT or MI_STAT_COUNTER"
                    ),
                };
                Some((kind, name))
            })
            .collect();
        assert_eq!(fields, mi::STAT_FIELDS);

        // The counter structs must have the mirrored members in order, and
        // the statistics struct must declare each mirrored array.
        let body = |name: &str| -> &str {
            header
                .split_once(&format!("typedef struct {name}"))
                .and_then(|(_, rest)| rest.split_once('{'))
                .and_then(|(_, rest)| rest.split_once('}'))
                .map(|(body, _)| body)
                .unwrap_or_else(|| panic!("mimalloc-stats.h must declare {name}"))
        };
        let members = |body: &str| -> Vec<String> {
            body.lines()
                .filter_map(|line| line.trim().split_once(';'))
                .map(|(declaration, _)| {
                    declaration.split_whitespace().collect::<Vec<_>>().join(" ")
                })
                .collect()
        };
        assert_eq!(
            members(body("mi_stat_count_s")),
            ["int64_t total", "int64_t peak", "int64_t current"]
        );
        assert_eq!(members(body("mi_stat_counter_s")), ["int64_t total"]);
        let stats = body("mi_stats_s");
        for array in [
            "mi_stat_count_t _stat_reserved[4]",
            "mi_stat_counter_t _stat_counter_reserved[4]",
            "mi_stat_count_t malloc_bins[MI_BIN_HUGE+1]",
            "mi_stat_count_t page_bins[MI_BIN_HUGE+1]",
            "mi_stat_count_t chunk_bins[MI_CBIN_COUNT]",
        ] {
            assert!(
                members(stats).iter().any(|member| member == array),
                "mimalloc-stats.h must declare {array}"
            );
        }

        // Only `size` and `version` precede the first statistic, and the
        // header and the mirror both align it to 8 bytes.
        let (header_fields, _) = stats
            .split_once("mi_decl_align(8)")
            .expect("mimalloc-stats.h must align the first statistic to 8 bytes");
        assert_eq!(members(header_fields), ["size_t size", "size_t version"]);
        assert_eq!(align_of::<mi::mi_stats_t>(), 8);
    }

    #[test]
    fn fast_paths_hand_out_aligned_memory() {
        // Both branches of every entry point return aligned memory and free
        // each other's blocks. Each layout keeps several blocks live because
        // consecutive blocks of a word-multiple size class alternate between
        // word and 16-byte alignment, so one block can be aligned by chance.
        for (size, align) in [
            (100usize, 1usize),
            (100, 8),
            (100, 16),
            (1, 16),
            (8, 16),
            (16, 16),
            (24, 16),
            (32, 16),
            (48, 16),
            (3, 8),
            (100, 64),
            (4096, 4096),
            (100, 4096),
        ] {
            let layout = Layout::from_size_align(size, align).expect("layout must be valid");
            // SAFETY: valid non-zero layouts, and every pointer is freed below.
            unsafe {
                let mut live = Vec::new();
                for _ in 0..16 {
                    let a = GLOBAL.alloc(layout);
                    assert!(
                        !a.is_null() && (a as usize).is_multiple_of(align),
                        "the pointer must be non-null and aligned for {layout:?}"
                    );
                    let z = GLOBAL.alloc_zeroed(layout);
                    assert!(
                        !z.is_null() && (z as usize).is_multiple_of(align),
                        "the pointer must be non-null and aligned for {layout:?}"
                    );
                    assert!(std::slice::from_raw_parts(z, size).iter().all(|b| *b == 0));
                    live.push((a, z));
                }
                let grown = Layout::from_size_align(10_000, align).expect("layout must be valid");
                for (a, z) in live {
                    let r = GLOBAL.realloc(a, layout, grown.size());
                    assert!(
                        !r.is_null() && (r as usize).is_multiple_of(align),
                        "the pointer must be non-null and aligned for {layout:?}"
                    );
                    GLOBAL.dealloc(r, grown);
                    GLOBAL.dealloc(z, layout);
                }
            }
        }
    }

    #[test]
    fn realloc_shrink_keeps_alignment() {
        // Shrinking a 16-byte aligned block to 8 bytes must use the aligned
        // path, because blocks of the 8-byte class are 16-byte aligned only
        // every other block.
        let layout = Layout::from_size_align(48, 16).expect("layout must be valid");
        let shrunk = Layout::from_size_align(8, 16).expect("layout must be valid");
        // SAFETY: valid non-zero layouts, and every pointer is freed below.
        unsafe {
            let live: Vec<*mut u8> = (0..16).map(|_| GLOBAL.alloc(layout)).collect();
            for p in live {
                let r = GLOBAL.realloc(p, layout, shrunk.size());
                assert!(
                    !r.is_null() && (r as usize).is_multiple_of(16),
                    "the pointer must be non-null and aligned for {shrunk:?}"
                );
                GLOBAL.dealloc(r, shrunk);
            }
        }
    }

    #[test]
    fn realloc_grows_into_the_exact_size_class() {
        // Growing a 16-byte aligned block to a multiple of 16 takes the plain
        // path, so the moved block is in its exact size class and must move
        // again to grow by 16 bytes. A block padded by the aligned path would
        // have room and stay in place.
        let layout = Layout::from_size_align(4096, 16).expect("layout must be valid");
        let grown = Layout::from_size_align(8192, 16).expect("layout must be valid");
        let widened = Layout::from_size_align(8192 + 16, 16).expect("layout must be valid");
        // SAFETY: each pointer came from GLOBAL with the layout it was last
        // allocated or resized to, and the block is freed below.
        unsafe {
            let p = GLOBAL.realloc(GLOBAL.alloc(layout), layout, grown.size());
            assert!(!p.is_null() && p.addr().is_multiple_of(16));
            let q = GLOBAL.realloc(p, grown, widened.size());
            assert!(!q.is_null() && q.addr().is_multiple_of(16));
            assert_ne!(q, p, "a block of its exact size class must move to grow");
            GLOBAL.dealloc(q, widened);
        }
    }

    #[test]
    fn stats_reflect_reservation_and_huge_allocations() {
        let before = Stats::read().expect("stats must be available");

        // The pinned reservation serves the tests' small working set, so
        // mimalloc maps only its page map, far less than an on-demand arena.
        // Another test adds a second pinned arena, so the count may exceed one.
        assert!(before.pinned_bytes >= RESERVE_BYTES as u64);
        assert!(before.arenas >= 1);
        assert!(before.reserved_bytes < RESERVE_BYTES as u64);
        assert!(before.committed_bytes > 0);
        assert!(before.threads >= 1);

        let largest = vec![1u8; LARGE_OBJECT_LIMIT];
        let after = Stats::read().expect("stats must be available");
        assert_eq!(after.huge_allocations, before.huge_allocations);
        drop(largest);

        let size = LARGE_OBJECT_LIMIT + 1;
        let block = vec![1u8; size];
        let after = Stats::read().expect("stats must be available");
        assert!(after.huge_allocations > before.huge_allocations);
        assert!(after.huge_bytes >= before.huge_bytes + size as u64);
        assert!(after.allocated_bytes >= before.allocated_bytes + size as u64);
        drop(block);
        let released = Stats::read().expect("stats must be available");
        assert!(released.allocated_bytes < after.allocated_bytes);
    }

    #[test]
    fn reservations_are_trimmed_to_chunks() {
        let chunk = mi::mi_arena_min_size();
        assert_eq!(chunk, ARENA_CHUNK_SIZE);
        assert_eq!(whole_chunks(chunk - 1), None);
        assert_eq!(whole_chunks(chunk + chunk / 2), Some(chunk));
        assert_eq!(whole_chunks(usize::MAX), Some(usize::MAX / chunk * chunk));
        let before = PINNED_BYTES.load(Ordering::Relaxed);
        assert_eq!(manage_pinned(chunk, true), ReserveOutcome::Pinned);
        assert_eq!(PINNED_BYTES.load(Ordering::Relaxed) - before, chunk as u64);
    }

    #[test]
    fn stats_clamp_negative_counts() {
        // A negative count reads as zero, and a positive one is unchanged.
        assert_eq!(unsigned(-1), 0);
        assert_eq!(unsigned(i64::MAX), i64::MAX as u64);
    }

    #[test]
    fn smallest_size_class_pages_stay_within_mimalloc_block_counts() {
        // mimalloc counts a page's blocks in 16-bit fields. With
        // `large-objects-4mb`, a 512 KiB page of 8-byte blocks stays within
        // that limit only because the page header takes a few blocks. Fill more
        // than one such page and check that every block is distinct and no page
        // holds more blocks than it can count.
        const COUNT: usize = u16::MAX as usize + 4096;
        let boxes: Vec<Box<u8>> = (0..COUNT).map(|i| Box::new(i as u8)).collect();
        let mut addresses: Vec<usize> = boxes.iter().map(|b| ptr::from_ref(&**b).addr()).collect();
        addresses.sort_unstable();
        addresses.dedup();
        assert_eq!(addresses.len(), COUNT);
        let mut blocks_per_page: HashMap<usize, usize> = HashMap::new();
        for address in &addresses {
            *blocks_per_page
                .entry(address / ARENA_SLICE_SIZE)
                .or_default() += 1;
        }
        assert!(
            blocks_per_page
                .values()
                .all(|count| *count <= u16::MAX as usize)
        );
        assert!(boxes.iter().enumerate().all(|(i, b)| **b == i as u8));
    }

    #[test]
    fn unpinned_and_default_configs_are_constructible() {
        let defaulted = MiMalloc::new(Config::DEFAULT);
        assert_eq!(defaulted.config(), &Config::default());
        assert!(!Reserve::unpinned(1).pinned);
    }

    #[test]
    fn configuration_is_process_wide() {
        // Allocating through a second instance leaves the process state and
        // the options GLOBAL applied unchanged.
        let other = MiMalloc::new(Config {
            purge: Purge::Never,
            ..Config::DEFAULT
        });
        let before = Status::read();
        assert!(before.configured);
        let layout = Layout::new::<u64>();
        // SAFETY: a valid non-zero layout, and the block is freed below.
        unsafe {
            let block = other.alloc(layout);
            assert!(!block.is_null());
            other.dealloc(block, layout);
        }
        assert_eq!(Status::read(), before);
        assert_eq!(OptionId::PurgeDelay.get(), 3_600_000);
    }
}
