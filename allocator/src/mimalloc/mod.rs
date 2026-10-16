//! A [`GlobalAlloc`] wrapper around mimalloc whose configuration lives in the
//! binary rather than in environment variables.
//!
//! # Configuration timing
//!
//! mimalloc reads its options lazily and creates its first arena at the first
//! allocation, which happens before `main` on most targets. An option set
//! from `main` therefore takes effect late, and a reservation made from
//! `main` becomes a second arena that threads search only after the
//! automatic one. [`MiMalloc`] applies its [`Config`] on the first allocation
//! it serves instead, so a reservation is the first arena and the purge
//! policy is in force before any memory is freed.
//!
//! # Example
//!
//! ```no_run
//! use commonware_allocator::mimalloc::{Config, MiMalloc, Purge, Reserve};
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
//!     println!("{:?}", GLOBAL.status());
//! }
//! ```

mod ffi;

use ffi as mi;
use std::{
    alloc::{GlobalAlloc, Layout},
    ffi::{CStr, c_long, c_void},
    hint::spin_loop,
    ptr,
    sync::atomic::{AtomicU8, AtomicU64, Ordering},
    time::Duration,
};

/// Runtime options the wrapper reads or writes, with their `mi_option_t`
/// values from the vendored `mimalloc.h`. A test derives the values from
/// that header, so an upgrade that renumbers the enum fails there instead of
/// configuring the wrong option.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
enum OptionId {
    ArenaEagerCommit = 4,
    PurgeDecommits = 5,
    AllowLargeOsPages = 6,
    PurgeDelay = 15,
    ArenaReserve = 23,
    ArenaPurgeMult = 24,
    AllowThp = 43,
}

impl OptionId {
    fn get(self) -> c_long {
        mi::mi_option_get(self as mi::mi_option_t)
    }

    fn set(self, value: c_long) {
        // SAFETY: callers pass flags, sizes in KiB that fit `c_long` once
        // multiplied back, or a purge delay bounded by `MAX_PURGE_DELAY`.
        unsafe { mi::mi_option_set(self as mi::mi_option_t, value) }
    }
}

/// Bytes handed to mimalloc as pinned arenas by this process. mimalloc's own
/// accounting covers only memory it mapped itself, so pinned reservations
/// are reported separately in [`Stats::pinned_bytes`].
static PINNED_BYTES: AtomicU64 = AtomicU64::new(0);

/// When memory freed back to an arena is purged (decommitted) to the
/// operating system.
///
/// Purging is time based and covers arena memory, which backs every
/// allocation except objects too large or too aligned for an arena; those
/// are mapped directly and unmapped on free whatever the policy. Memory in a
/// pinned reservation (see [`Reserve`]) is never purged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purge {
    /// Keep mimalloc's default: its purge delay times its arena multiplier
    /// (four seconds in mimalloc 3.5).
    Default,
    /// Never purge arena memory.
    Never,
    /// Purge freed memory once it has stayed unused for at least this long.
    /// Delays above [`MAX_PURGE_DELAY`] are clamped to it.
    After(Duration),
}

/// Longest purge delay [`Purge::After`] applies (about 24 days): mimalloc
/// adds the delay in milliseconds to its clock in a C `long`, so the bound
/// keeps that sum in range on every platform.
pub const MAX_PURGE_DELAY: Duration = Duration::from_millis(i32::MAX as u64);

/// Memory reserved from the operating system before the first allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reserve {
    /// Bytes to reserve. mimalloc manages arenas in 32 MiB chunks of 64 KiB
    /// slices, so the amount is rounded down to whole chunks and
    /// reservations below one chunk fail.
    pub bytes: usize,
    /// Pinned memory is mapped by this crate and handed to mimalloc as an
    /// arena that is never purged, whatever the [`Purge`] policy. It needs no
    /// huge-page configuration. Unpinned memory is reserved through mimalloc
    /// and purged like any other arena unless the kernel granted it large OS
    /// pages (see [`Config::allow_large_os_pages`]).
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
/// Every field has a "leave mimalloc's default" value, so
/// [`Config::DEFAULT`] changes nothing and environment variables keep working.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    /// When freed memory is purged back to the operating system.
    pub purge: Purge,
    /// Memory reserved before the first allocation.
    pub reserve: Option<Reserve>,
    /// Whether mimalloc may back arenas with large (2 MiB) OS pages when the
    /// kernel grants them. Large-page arenas are never purged; the pages are
    /// not swappable and come out of the kernel's huge-page pool.
    pub allow_large_os_pages: bool,
    /// Whether the process may use transparent huge pages (`None` keeps the
    /// current state: allowed unless the environment disabled them). On
    /// Linux this sets the process flag the kernel consults for every
    /// mapping; elsewhere it only informs mimalloc. Huge pages cut page
    /// faults and TLB misses for large buffers but can raise resident memory
    /// for processes dominated by small objects, and purging then works at
    /// 2 MiB granularity.
    pub transparent_huge_pages: Option<bool>,
    /// Whether arenas are committed eagerly rather than on first use. `None`
    /// keeps mimalloc's default (eager only on systems that overcommit).
    pub arena_eager_commit: Option<bool>,
    /// Size of each arena mimalloc reserves on demand once existing arenas
    /// are full. `None` keeps mimalloc's default (1 GiB, growing with the
    /// arena count).
    pub arena_reserve: Option<usize>,
}

impl Config {
    /// Leaves every mimalloc option at its default.
    pub const DEFAULT: Self = Self {
        purge: Purge::Default,
        reserve: None,
        allow_large_os_pages: false,
        transparent_huge_pages: None,
        arena_eager_commit: None,
        arena_reserve: None,
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
    /// The operating system or mimalloc refused the reservation; allocation
    /// continues from automatically reserved arenas.
    Failed,
}

/// What [`MiMalloc`] has done so far.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    /// Whether the configuration has been applied (it is applied by the first
    /// allocation, so this is false only before any allocation happened).
    pub configured: bool,
    /// Outcome of the requested reservation.
    pub reserve: ReserveOutcome,
}

const UNCONFIGURED: u8 = 0;
const CONFIGURING: u8 = 1;
const CONFIGURED: u8 = 2;

/// Largest alignment `mi_malloc` can satisfy without the aligned entry points
/// (`MI_MAX_ALIGN_SIZE` in the vendored `mimalloc/types.h`). Every block is
/// word aligned: size classes are word multiples and pages start their
/// blocks word aligned. Size classes that are multiples of 16 start their
/// blocks 16-byte aligned as well, and every size that is a multiple of 16
/// maps to such a class, so those layouts skip the aligned entry points and
/// their validity check and small-block alignment probe. A test checks the
/// constant against the header.
const MALLOC_ALIGNMENT: usize = 16;

/// Alignment every `mi_malloc` block has regardless of size.
const WORD_ALIGNMENT: usize = size_of::<usize>();

/// Alignment up to which `mi_realloc_aligned` itself delegates to the plain
/// reallocation path (`sizeof(uintptr_t)`), so calling `mi_realloc`
/// directly is equivalent and skips the wrapper.
const REALLOC_ALIGNMENT: usize = size_of::<usize>();

/// Whether plain `mi_malloc` satisfies `layout`'s alignment.
#[inline]
const fn malloc_satisfies(layout: &Layout) -> bool {
    let align = layout.align();
    align <= WORD_ALIGNMENT || (align <= MALLOC_ALIGNMENT && layout.size().is_multiple_of(align))
}

/// mimalloc as a `#[global_allocator]` with a [`Config`] applied on the first
/// allocation.
///
/// Construction is `const`, so a configured allocator can be a `static`
/// directly. Applying the configuration performs no Rust allocation, so the
/// first allocation cannot recurse into the allocator.
pub struct MiMalloc {
    config: Config,
    state: AtomicU8,
    reserve: AtomicU8,
}

impl MiMalloc {
    /// Creates an allocator that applies `config` on its first allocation.
    pub const fn new(config: Config) -> Self {
        Self {
            config,
            state: AtomicU8::new(UNCONFIGURED),
            reserve: AtomicU8::new(ReserveOutcome::NotRequested as u8),
        }
    }

    /// Returns the configuration this allocator applies.
    pub const fn config(&self) -> &Config {
        &self.config
    }

    /// Reports whether the configuration has been applied and how the
    /// reservation went.
    pub fn status(&self) -> Status {
        let reserve = match self.reserve.load(Ordering::Acquire) {
            x if x == ReserveOutcome::Pinned as u8 => ReserveOutcome::Pinned,
            x if x == ReserveOutcome::Reserved as u8 => ReserveOutcome::Reserved,
            x if x == ReserveOutcome::Failed as u8 => ReserveOutcome::Failed,
            _ => ReserveOutcome::NotRequested,
        };
        Status {
            configured: self.state.load(Ordering::Acquire) == CONFIGURED,
            reserve,
        }
    }

    #[inline]
    fn ensure_configured(&self) {
        if self.state.load(Ordering::Acquire) != CONFIGURED {
            self.configure();
        }
    }

    /// Applies the configuration exactly once. Concurrent first allocations
    /// wait for the configuring thread; nothing here allocates through Rust.
    #[cold]
    #[inline(never)]
    fn configure(&self) {
        match self.state.compare_exchange(
            UNCONFIGURED,
            CONFIGURING,
            Ordering::Acquire,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                let outcome = apply(&self.config);
                self.reserve.store(outcome as u8, Ordering::Release);
                self.state.store(CONFIGURED, Ordering::Release);
            }
            Err(CONFIGURING) => {
                while self.state.load(Ordering::Acquire) != CONFIGURED {
                    spin_loop();
                }
            }
            Err(_) => {}
        }
    }
}

// SAFETY: mimalloc is thread-safe, and the configuration state is only touched
// through atomics.
unsafe impl GlobalAlloc for MiMalloc {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.ensure_configured();
        if malloc_satisfies(&layout) {
            mi::mi_malloc(layout.size()) as *mut u8
        } else {
            mi::mi_malloc_aligned(layout.size(), layout.align()) as *mut u8
        }
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        self.ensure_configured();
        if malloc_satisfies(&layout) {
            mi::mi_zalloc(layout.size()) as *mut u8
        } else {
            mi::mi_zalloc_aligned(layout.size(), layout.align()) as *mut u8
        }
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        // SAFETY: GlobalAlloc requires ptr to come from this allocator.
        unsafe { mi::mi_free(ptr as *mut c_void) }
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: GlobalAlloc requires ptr to come from this allocator with the given layout.
        unsafe {
            if layout.align() <= REALLOC_ALIGNMENT {
                mi::mi_realloc(ptr as *mut c_void, new_size) as *mut u8
            } else {
                mi::mi_realloc_aligned(ptr as *mut c_void, new_size, layout.align()) as *mut u8
            }
        }
    }
}

/// Applies `config` to the process-wide mimalloc instance.
fn apply(config: &Config) -> ReserveOutcome {
    mi::mi_process_init();
    match config.purge {
        Purge::Default => {}
        Purge::Never => OptionId::PurgeDelay.set(-1),
        Purge::After(delay) => {
            // mimalloc scales the delay by its arena multiplier, and arenas
            // are the only purge path in version 3, so a multiplier of one
            // makes the configured delay the effective one.
            OptionId::PurgeDelay.set(purge_millis(delay));
            OptionId::ArenaPurgeMult.set(1);
        }
    }
    if let Some(eager) = config.arena_eager_commit {
        OptionId::ArenaEagerCommit.set(c_long::from(eager));
    }
    if config.allow_large_os_pages {
        OptionId::AllowLargeOsPages.set(1);
    }
    if let Some(allowed) = config.transparent_huge_pages {
        set_transparent_huge_pages(allowed);
    }
    if let Some(bytes) = config.arena_reserve {
        // Size options are stored in KiB and read back multiplied, so the
        // product must fit the option type.
        let kib = (bytes / 1024).min(c_long::MAX as usize / 1024) as c_long;
        OptionId::ArenaReserve.set(kib);
    }
    match config.reserve {
        None => ReserveOutcome::NotRequested,
        Some(reserve) if reserve.pinned => manage_pinned(reserve),
        Some(reserve) => {
            // SAFETY: the arena identifier output is null, so nothing is
            // written through it.
            let err = unsafe {
                mi::mi_reserve_os_memory_ex(
                    reserve.bytes,
                    true,
                    config.allow_large_os_pages,
                    false,
                    ptr::null_mut(),
                )
            };
            if err == 0 {
                ReserveOutcome::Reserved
            } else {
                ReserveOutcome::Failed
            }
        }
    }
}

/// A purge delay in the milliseconds mimalloc stores, bounded by
/// [`MAX_PURGE_DELAY`].
fn purge_millis(delay: Duration) -> c_long {
    delay.min(MAX_PURGE_DELAY).as_millis() as c_long
}

/// The delay after which mimalloc purges unused arena memory, computed from
/// the raw options the way its arena code does: a negative factor disables
/// purging, and a product that does not fit falls back to the bare delay.
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
/// mimalloc reads this option when it initializes at load time. A later
/// value still steers its madvise calls and purge granularity for new
/// mappings, but the process-wide flag that disables transparent huge pages
/// on Linux is only touched during that initialization, so the wrapper
/// maintains the flag itself, in both directions.
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

/// Maps anonymous memory and hands it to mimalloc as a pinned, committed
/// arena.
///
/// mimalloc needs an arena aligned to its minimum arena alignment and uses
/// it in whole chunks of its minimum arena size, so the request is rounded
/// down to chunks, mapped with alignment slack, and trimmed on both ends
/// before the handover. Only the retained range is prefaulted and counted in
/// [`Stats::pinned_bytes`].
fn manage_pinned(reserve: Reserve) -> ReserveOutcome {
    let alignment = mi::mi_arena_min_alignment();
    let chunk = mi::mi_arena_min_size();
    let size = reserve.bytes / chunk * chunk;
    if size == 0 {
        return ReserveOutcome::Failed;
    }
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
    if reserve.prefault {
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
    // SAFETY: the range is a live private mapping that nothing else uses;
    // mimalloc takes it over for the rest of the process.
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
        // SAFETY: the aligned remainder of the mapping was never handed out.
        unsafe { libc::munmap(start as *mut c_void, size) };
        ReserveOutcome::Failed
    }
}

/// Returns whether the process's global allocator is the mimalloc linked by
/// this crate, installed through [`MiMalloc`] directly or wrapped by another
/// allocator.
///
/// A fresh allocation is checked against that instance's heap region.
pub fn is_global_allocator() -> bool {
    let probe = Box::new(0u8);
    // SAFETY: the probe is a valid pointer for the duration of the call.
    unsafe { mi::mi_is_in_heap_region(ptr::from_ref::<u8>(&probe).cast()) }
}

/// Returns the linked mimalloc version as `major * 10000 + minor * 100 + patch`.
pub fn version() -> u32 {
    mi::mi_version() as u32
}

/// Returns the size mimalloc actually allocates for a request of `size`
/// bytes (its size class, or the page-rounded size above the largest class).
pub fn good_size(size: usize) -> usize {
    mi::mi_good_size(size)
}

/// Collects freed memory now: returns completed pages to the arenas and,
/// when `force` is set, purges them to the operating system without waiting
/// for the purge delay. Purging must be enabled ([`Purge::Never`] disables
/// it) and pinned reservations are never purged. Only the calling thread's
/// allocation counters are merged into [`Stats`] by this.
pub fn collect(force: bool) {
    mi::mi_collect(force);
}

/// The options mimalloc is running with, whether set by a [`Config`], the
/// environment, or its defaults.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Effective {
    /// Purge policy: `None` never purges, otherwise the delay after which
    /// unused arena memory is purged (mimalloc's purge delay times its arena
    /// multiplier).
    pub purge: Option<Duration>,
    /// Whether a purge decommits memory rather than resetting it.
    pub purge_decommits: bool,
    /// Arena commit policy as mimalloc stores it (0 lazy, 1 eager, 2 eager on
    /// overcommitting systems).
    pub arena_eager_commit: i64,
    /// Whether arenas may use large OS pages.
    pub allow_large_os_pages: bool,
    /// Whether mimalloc may use transparent huge pages.
    pub transparent_huge_pages: bool,
    /// Size of arenas reserved on demand.
    pub arena_reserve: usize,
}

impl Effective {
    /// Reads the current option values.
    pub fn read() -> Self {
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
        }
    }
}

/// Process-wide allocator statistics.
///
/// Memory accounting against the operating system (reservations, commits,
/// purges, mappings, arenas, threads) and the process figures are current
/// when read. Allocation counters ([`Self::allocated_bytes`],
/// [`Self::allocated_peak_bytes`], [`Self::pages`],
/// [`Self::huge_allocations`], [`Self::huge_bytes`]) are kept per thread and
/// folded into the process totals when that thread collects (which mimalloc
/// does every 10,000 allocations that miss its fast path), reads statistics
/// itself, or exits, so they reflect each thread's last merge rather than
/// its live state. Per-size-class counts are not included.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Bytes reserved from the operating system across all arenas.
    ///
    /// Covers memory mimalloc mapped itself; pinned reservations handed over
    /// by this crate are in [`Self::pinned_bytes`].
    pub reserved_bytes: u64,
    /// Bytes of pinned reservations handed to mimalloc by this crate; this
    /// memory is never purged.
    pub pinned_bytes: u64,
    /// Bytes currently committed.
    pub committed_bytes: u64,
    /// Peak committed bytes.
    pub committed_peak_bytes: u64,
    /// Bytes currently handed out to callers, as the allocator accounts them
    /// (block sizes, so including size-class rounding).
    pub allocated_bytes: u64,
    /// Peak bytes handed out, as the sum of the separately tracked normal
    /// and huge-object peaks, so it can exceed the peak of their sum.
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
    /// Pages (mimalloc's unit of size-class storage) currently in use.
    pub pages: u64,
    /// Threads currently known to the allocator.
    pub threads: u64,
    /// Arenas currently managed.
    pub arenas: u64,
    /// Cumulative allocations served by a singleton page (objects larger than
    /// the largest size class).
    pub huge_allocations: u64,
    /// Cumulative bytes of those allocations.
    pub huge_bytes: u64,
    /// Resident set size as reported to the allocator.
    pub resident_bytes: u64,
    /// Peak resident set size.
    pub resident_peak_bytes: u64,
    /// Cumulative page faults (zero where the platform does not report them).
    pub page_faults: u64,
}

impl Stats {
    /// Reads the current statistics, or `None` if mimalloc could not produce them.
    pub fn read() -> Option<Self> {
        let mut buf = vec![0u8; 64 * 1024];
        // SAFETY: the buffer is writable for its full length and mimalloc
        // NUL-terminates what it writes, or returns NULL.
        let json = unsafe {
            let p = mi::mi_stats_get_json(buf.len(), buf.as_mut_ptr().cast());
            if p.is_null() {
                return None;
            }
            CStr::from_ptr(p).to_str().ok()?
        };
        let (mut rss, mut rss_peak, mut commit, mut commit_peak, mut faults) = (0, 0, 0, 0, 0);
        // SAFETY: every out-pointer is valid; unused outputs are null.
        unsafe {
            mi::mi_process_info(
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut rss,
                &mut rss_peak,
                &mut commit,
                &mut commit_peak,
                &mut faults,
            );
        }
        Some(Self {
            reserved_bytes: current(json, "reserved"),
            pinned_bytes: PINNED_BYTES.load(Ordering::Relaxed),
            committed_bytes: commit as u64,
            committed_peak_bytes: commit_peak as u64,
            allocated_bytes: current(json, "malloc_normal") + current(json, "malloc_huge"),
            allocated_peak_bytes: peak(json, "malloc_normal") + peak(json, "malloc_huge"),
            purged_bytes: scalar(json, "purged"),
            purge_calls: scalar(json, "purge_calls"),
            arena_purges: scalar(json, "arena_purges"),
            mmap_calls: scalar(json, "mmap_calls"),
            commit_calls: scalar(json, "commit_calls"),
            pages: current(json, "pages"),
            threads: current(json, "threads"),
            arenas: scalar(json, "arena_count"),
            huge_allocations: scalar(json, "malloc_huge_count"),
            huge_bytes: total(json, "malloc_huge"),
            resident_bytes: rss as u64,
            resident_peak_bytes: rss_peak as u64,
            page_faults: faults as u64,
        })
    }
}

/// Returns the text following `"key":` in `json`, or an empty string.
fn value<'a>(json: &'a str, key: &str) -> &'a str {
    let needle = format!("\"{key}\":");
    json.find(&needle)
        .map_or("", |at| json[at + needle.len()..].trim_start())
}

/// Parses the leading unsigned integer of `text`.
fn integer(text: &str) -> u64 {
    let digits = text.trim_start();
    let end = digits
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(digits.len());
    digits[..end].parse().unwrap_or(0)
}

/// A scalar field such as `"purged": 123`.
fn scalar(json: &str, key: &str) -> u64 {
    integer(value(json, key))
}

/// A sub-field of a count object such as `"pages": { "total": 1, "peak": 2, "current": 3 }`.
fn count(json: &str, key: &str, part: &str) -> u64 {
    let object = value(json, key);
    if !object.starts_with('{') {
        return 0;
    }
    let end = object.find('}').unwrap_or(object.len());
    scalar(&object[..end], part)
}

fn current(json: &str, key: &str) -> u64 {
    count(json, key, "current")
}

fn total(json: &str, key: &str) -> u64 {
    count(json, key, "total")
}

fn peak(json: &str, key: &str) -> u64 {
    count(json, key, "peak")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const RESERVE_BYTES: usize = 64 << 20;
    const PURGE_DELAY: Duration = Duration::from_secs(3600);

    #[global_allocator]
    static GLOBAL: MiMalloc = MiMalloc::new(Config {
        purge: Purge::After(PURGE_DELAY),
        reserve: Some(Reserve::pinned(RESERVE_BYTES)),
        transparent_huge_pages: Some(false),
        ..Config::DEFAULT
    });

    #[test]
    fn config_is_applied_before_use() {
        let status = GLOBAL.status();
        assert!(status.configured);
        assert_eq!(status.reserve, ReserveOutcome::Pinned);
        assert_eq!(OptionId::PurgeDelay.get(), 3_600_000);
        assert_eq!(OptionId::ArenaPurgeMult.get(), 1);
        assert_eq!(OptionId::AllowThp.get(), 0);
        let effective = Effective::read();
        assert_eq!(effective.purge, Some(PURGE_DELAY));
        assert!(effective.purge_decommits);
        assert!(!effective.transparent_huge_pages);
        #[cfg(target_os = "linux")]
        // SAFETY: this prctl takes integer arguments only.
        unsafe {
            assert_eq!(libc::prctl(libc::PR_GET_THP_DISABLE, 0, 0, 0, 0), 1);
        }
        assert!(is_global_allocator());
        assert_eq!(version(), 30503);
        // Debug builds pad every block, so exact size classes only hold in
        // the production build.
        #[cfg(not(feature = "debug"))]
        {
            assert_eq!(good_size(4096), 4096);
            assert_eq!(good_size(4096 + 32), 5120);
        }
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
    fn constants_match_vendored_headers() {
        // Enumerators of `mi_option_t` number from zero in declaration order;
        // the legacy aliases at the end carry explicit values and are skipped.
        let header = include_str!("../../mimalloc/include/mimalloc.h");
        let body = header
            .split_once("typedef enum mi_option_e {")
            .and_then(|(_, rest)| rest.split_once("} mi_option_t;"))
            .map(|(body, _)| body)
            .expect("mi_option_t enum in mimalloc.h");
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
        ] {
            assert_eq!(ids.get(name), Some(&(id as i32)), "{name}");
        }

        let types = include_str!("../../mimalloc/include/mimalloc/types.h");
        let max_align: usize = types
            .lines()
            .find_map(|line| line.strip_prefix("#define MI_MAX_ALIGN_SIZE"))
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|value| value.parse().ok())
            .expect("MI_MAX_ALIGN_SIZE in types.h");
        assert_eq!(max_align, MALLOC_ALIGNMENT);
        assert_eq!(REALLOC_ALIGNMENT, size_of::<*const ()>());
    }

    #[test]
    fn fast_paths_hand_out_aligned_memory() {
        // Both branches of every entry point hand out usable, correctly
        // aligned memory and accept each other's pointers on release. Several
        // live blocks per layout matter: consecutive blocks of a word-multiple
        // size class alternate between word and 16-byte alignment, so a single
        // allocation can look aligned by chance.
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
            let layout = Layout::from_size_align(size, align).expect("valid layout");
            // SAFETY: valid non-zero layouts; every pointer is freed below.
            unsafe {
                let mut live = Vec::new();
                for _ in 0..16 {
                    let a = GLOBAL.alloc(layout);
                    assert!(
                        !a.is_null() && (a as usize).is_multiple_of(align),
                        "{layout:?}"
                    );
                    let z = GLOBAL.alloc_zeroed(layout);
                    assert!(
                        !z.is_null() && (z as usize).is_multiple_of(align),
                        "{layout:?}"
                    );
                    assert!(std::slice::from_raw_parts(z, size).iter().all(|b| *b == 0));
                    live.push((a, z));
                }
                let grown = Layout::from_size_align(10_000, align).expect("valid layout");
                for (a, z) in live {
                    let r = GLOBAL.realloc(a, layout, grown.size());
                    assert!(
                        !r.is_null() && (r as usize).is_multiple_of(align),
                        "{layout:?}"
                    );
                    GLOBAL.dealloc(r, grown);
                    GLOBAL.dealloc(z, layout);
                }
            }
        }
    }

    #[test]
    fn stats_reflect_reservation_and_huge_allocations() {
        let before = Stats::read().expect("stats available");
        // A pinned reservation is the first arena, so no automatic arena was
        // needed for the tests' small working set.
        assert!(before.pinned_bytes >= RESERVE_BYTES as u64);
        assert!(before.arenas >= 1);
        assert!(before.committed_bytes > 0);
        assert!(before.threads >= 1);

        let block = vec![1u8; 4 << 20];
        let after = Stats::read().expect("stats available");
        assert!(after.huge_allocations > before.huge_allocations);
        assert!(after.huge_bytes >= before.huge_bytes + (4 << 20));
        assert!(after.allocated_bytes >= before.allocated_bytes + (4 << 20));
        drop(block);
        let released = Stats::read().expect("stats available");
        assert!(released.allocated_bytes < after.allocated_bytes);
    }

    #[test]
    fn pinned_reservations_are_trimmed_to_chunks() {
        let chunk = mi::mi_arena_min_size();
        let before = PINNED_BYTES.load(Ordering::Relaxed);
        let reserve = Reserve {
            bytes: chunk + chunk / 2,
            pinned: true,
            prefault: true,
        };
        assert_eq!(manage_pinned(reserve), ReserveOutcome::Pinned);
        assert_eq!(PINNED_BYTES.load(Ordering::Relaxed) - before, chunk as u64);
        assert_eq!(
            manage_pinned(Reserve::pinned(chunk - 1)),
            ReserveOutcome::Failed
        );
    }

    #[test]
    fn parser_handles_scalars_and_count_objects() {
        let json = r#"{
  "process": { "rss_current": 10, "page_faults": 7 },
  "pages": { "total": 949, "peak": 631, "current": 630 },
  "pages_abandoned": { "total": 1, "peak": 1, "current": 1 },
  "purged": 83492864,
  "malloc_huge": { "total": 67108864, "peak": 67108864, "current": 0 },
  "arena_count": 1
}"#;
        assert_eq!(scalar(json, "purged"), 83492864);
        assert_eq!(current(json, "pages"), 630);
        assert_eq!(total(json, "malloc_huge"), 67108864);
        assert_eq!(scalar(json, "arena_count"), 1);
        assert_eq!(scalar(json, "missing"), 0);
        assert_eq!(current(json, "purged"), 0);
    }

    #[test]
    fn unpinned_and_default_configs_are_constructible() {
        let defaulted = MiMalloc::new(Config::DEFAULT);
        assert_eq!(defaulted.config(), &Config::default());
        assert!(!defaulted.status().configured);
        assert!(!Reserve::unpinned(1).pinned);
    }
}
