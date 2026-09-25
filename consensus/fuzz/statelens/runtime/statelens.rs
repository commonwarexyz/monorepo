//! StateLens runtime support for an instrumented Simplex campaign.
//!
//! This file is a template kept in `consensus/fuzz/statelens/runtime/`. A campaign
//! copies it into the checkout it instruments as `consensus/src/simplex/statelens.rs`
//! and declares it with `pub mod statelens;`. It is never compiled on a committed
//! branch.
//!
//! It provides:
//! - the Byzantine guard: [set_compromised], [clear_compromised], [is_byzantine]
//!   and [should_check];
//! - a SanitizerCoverage counter table fed by state probes: [record] and [reset];
//! - the instrumentation macros `sl_probe!`, `sl_assert!` and `sl_implies!`,
//!   invoked as `crate::simplex::statelens::sl_probe!(...)`;
//! - ghost state: per replica ([Ghost], [with_ghost]) and shared by all honest
//!   replicas ([Global], [with_global]). It lives for one run: [reset] and every
//!   fresh deterministic runtime clear it, while a runtime resumed from a
//!   checkpoint (a crash-restart) keeps it;
//! - discretization helpers: [bucket], [delta], [flag], [pack] and [disc].
//!
//! Environment switches, each read once per process:
//! - `STATELENS_BYZANTINE` sets what instrumentation does for a compromised
//!   replica: `skip` (default) ignores it, `check` checks it like an honest
//!   replica, and `panic` panics at the first instrumented site it reaches.
//! - `STATELENS_FEEDBACK=0` leaves the counter table unregistered, so probes add
//!   no libFuzzer features.

// `cargo fuzz` sets `--cfg fuzzing`, which the workspace check-cfg list does not
// declare for this crate.
#![allow(unexpected_cfgs)]

pub use commonware_utils::Participant;
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fmt,
    hash::{Hash, Hasher},
    sync::{
        OnceLock,
        atomic::{AtomicU8, Ordering},
    },
};

/// Number of counters in the StateLens table.
pub const COUNTERS: usize = 1 << 16;

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

static TABLE: sancov::Counters<COUNTERS> = sancov::Counters::new();

thread_local! {
    static COMPROMISED: RefCell<BTreeSet<u32>> = const { RefCell::new(BTreeSet::new()) };
    static GHOSTS: RefCell<BTreeMap<u32, Ghost>> = const { RefCell::new(BTreeMap::new()) };
    static GLOBAL: RefCell<Global> = RefCell::new(Global::default());
}

/// What instrumentation does at a site reached by a compromised replica.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Byzantine {
    /// Skip the site: the Byzantine guard (default).
    Skip,
    /// Check the replica like an honest one.
    Check,
    /// Panic, which shows that compromised replicas reach instrumented sites.
    Panic,
}

impl Byzantine {
    /// Parses the value of `STATELENS_BYZANTINE`.
    fn parse(value: Option<&str>) -> Self {
        match value {
            None | Some("skip") => Self::Skip,
            Some("check") => Self::Check,
            Some("panic") => Self::Panic,
            Some(other) => {
                panic!("STATELENS_BYZANTINE must be skip, check or panic, not {other:?}")
            }
        }
    }
}

fn byzantine() -> Byzantine {
    static MODE: OnceLock<Byzantine> = OnceLock::new();
    *MODE.get_or_init(|| Byzantine::parse(std::env::var("STATELENS_BYZANTINE").ok().as_deref()))
}

/// Formats an optional participant index for panic messages.
struct Replica(Option<Participant>);

impl fmt::Display for Replica {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(me) => write!(f, "{}", me.get()),
            None => f.write_str("none"),
        }
    }
}

/// Publishes the participant indices of the compromised replicas of this run.
///
/// Called by the patched Twins runner before any engine starts.
pub fn set_compromised(indices: impl IntoIterator<Item = usize>) {
    COMPROMISED.with(|set| {
        let mut set = set.borrow_mut();
        set.clear();
        set.extend(
            indices
                .into_iter()
                .map(|index| u32::try_from(index).expect("participant index must fit in u32")),
        );
    });
}

/// Forgets the compromised set, so every replica is treated as honest.
pub fn clear_compromised() {
    COMPROMISED.with(|set| set.borrow_mut().clear());
}

/// Returns whether `me` is compromised in the current run.
///
/// A replica without a participant index is never compromised.
pub fn is_byzantine(me: Option<Participant>) -> bool {
    me.is_some_and(|me| COMPROMISED.with(|set| set.borrow().contains(&me.get())))
}

/// Returns whether instrumentation should observe and check replica `me`.
///
/// This is the Byzantine guard. Every StateLens macro calls it before
/// evaluating any other argument.
pub fn should_check(me: Option<Participant>) -> bool {
    if !is_byzantine(me) {
        return true;
    }
    match byzantine() {
        Byzantine::Skip => false,
        Byzantine::Check => true,
        Byzantine::Panic => panic!(
            "[statelens][BYZANTINE] replica={} compromised replica reached an instrumented site",
            Replica(me)
        ),
    }
}

/// Raw pointer to the counter bytes.
fn table() -> *mut u8 {
    // `Counters<N>` is `#[repr(transparent)]` over `UnsafeCell<[u8; N]>`.
    (&TABLE as *const sancov::Counters<COUNTERS>)
        .cast::<u8>()
        .cast_mut()
}

/// Prepares a fuzz input: zeroes the counter table, forgets the compromised set
/// and clears the ghost state. In a fuzzing build it also registers the table
/// with libFuzzer on first use, unless `STATELENS_FEEDBACK=0`.
///
/// Called by the StateLens fuzz target before every input.
pub fn reset() {
    #[cfg(fuzzing)]
    {
        static REGISTERED: std::sync::Once = std::sync::Once::new();
        REGISTERED.call_once(|| {
            if std::env::var("STATELENS_FEEDBACK").map_or(true, |value| value != "0") {
                TABLE.register();
            }
        });
    }
    // SAFETY: `table` points to `COUNTERS` bytes inside a static. `reset` runs on
    // the fuzzing thread between inputs, when no probe writes concurrently.
    unsafe { core::ptr::write_bytes(table(), 0, COUNTERS) };
    clear_compromised();
    forget_ghosts();
}

/// Forgets all ghost state.
///
/// Registered as the deterministic runtime's fresh-run hook, so history from an
/// earlier, independent run on this thread (for example another seed of the same
/// test) does not leak into the next run. A runtime resumed from a checkpoint (a
/// crash-restart) keeps the history.
fn forget_ghosts() {
    GHOSTS.with(|ghosts| ghosts.borrow_mut().clear());
    GLOBAL.with(|global| *global.borrow_mut() = Global::default());
}

/// Registers [forget_ghosts] with the deterministic runtime, once per process.
fn register_fresh_run_hook() {
    static REGISTERED: std::sync::Once = std::sync::Once::new();
    REGISTERED.call_once(|| {
        let _ = commonware_runtime::deterministic::STATELENS_FRESH_RUN.set(forget_ghosts);
    });
}

/// Hashes a probe site label at compile time (FNV-1a, 64 bits).
pub const fn site_hash(label: &str) -> u64 {
    let bytes = label.as_bytes();
    let mut hash = FNV_OFFSET;
    let mut i = 0;
    while i < bytes.len() {
        hash ^= bytes[i] as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
        i += 1;
    }
    hash
}

/// Maps a probe observation `(site, a, b)` to a counter index.
pub const fn cell(site: u64, a: u32, b: u32) -> usize {
    let values = ((a as u64) << 32) | b as u64;
    let mut x = site ^ values.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^= x >> 31;
    (x % COUNTERS as u64) as usize
}

/// Marks the counter of observation `(site, a, b)` as seen.
///
/// Presence only: a counter is 0 (not seen in this input) or 1 (seen), so a
/// state observed many times still yields a single libFuzzer feature.
pub fn record(site: u64, a: u32, b: u32) {
    let index = cell(site, a, b);
    // SAFETY: `index < COUNTERS`, so the pointer stays inside the table. Probes
    // only access the table atomically; the non-atomic zeroing in `reset` runs
    // when no probe executes.
    let counter = unsafe { AtomicU8::from_ptr(table().add(index)) };
    counter.store(1, Ordering::Relaxed);
}

/// Panics with the StateLens violation message for invariant `id`.
#[cold]
#[track_caller]
pub fn violation(me: Option<Participant>, id: &str, message: fmt::Arguments<'_>) -> ! {
    panic!("[statelens][{id}] replica={} {message}", Replica(me));
}

/// Buckets a count or distance: 0, 1, 2, 3-4, 5-8 and 9+ map to 0..=5.
pub const fn bucket(n: u64) -> u32 {
    match n {
        0 => 0,
        1 => 1,
        2 => 2,
        3..=4 => 3,
        5..=8 => 4,
        _ => 5,
    }
}

/// Buckets the signed distance `a - b`: 0..=5 when `a >= b`, 6..=10 when `a < b`.
pub const fn delta(a: u64, b: u64) -> u32 {
    if a >= b {
        bucket(a - b)
    } else {
        5 + bucket(b - a)
    }
}

/// Converts a boolean to 0 or 1.
pub const fn flag(value: bool) -> u32 {
    value as u32
}

/// Packs two small values, each below 2^16, into one probe value.
pub const fn pack(high: u32, low: u32) -> u32 {
    (high << 16) | (low & 0xffff)
}

/// Returns a stable code for the variant of an enum value, ignoring its payload.
pub fn disc<T>(value: &T) -> u32 {
    let mut hasher = Fnv(FNV_OFFSET);
    std::mem::discriminant(value).hash(&mut hasher);
    hasher.finish() as u32
}

/// FNV-1a hasher with a fixed seed, so codes are stable within a build.
struct Fnv(u64);

impl Hasher for Fnv {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 ^= u64::from(*byte);
            self.0 = self.0.wrapping_mul(FNV_PRIME);
        }
    }
}

/// Per-replica ghost state for cross-actor and cross-restart invariants.
///
/// Instrumentation adds `pub` fields here, each preceded by a
/// `// [statelens] ghost:INV-NNNN` comment. Every field type must implement
/// `Default`.
#[derive(Default)]
pub struct Ghost {}

/// Ghost state shared by all honest replicas, for `protocol` invariants.
///
/// Instrumentation adds `pub` fields here, each preceded by a
/// `// [statelens] ghost:INV-NNNN` comment. Every field type must implement
/// `Default`.
#[derive(Default)]
pub struct Global {}

/// Runs `f` on the ghost state of replica `me`, creating it on first use.
///
/// Returns `None`, without calling `f`, for a replica without a participant
/// index or one the guard skips. `f` must not call [with_ghost] or [with_global].
pub fn with_ghost<R>(me: Option<Participant>, f: impl FnOnce(&mut Ghost) -> R) -> Option<R> {
    register_fresh_run_hook();
    let index = me?.get();
    if !should_check(me) {
        return None;
    }
    Some(GHOSTS.with(|ghosts| f(ghosts.borrow_mut().entry(index).or_default())))
}

/// Runs `f` on the ghost state shared by all honest replicas.
///
/// Returns `None`, without calling `f`, when the guard skips `me`. `f` must not
/// call [with_ghost] or [with_global].
pub fn with_global<R>(me: Option<Participant>, f: impl FnOnce(&mut Global) -> R) -> Option<R> {
    register_fresh_run_hook();
    if !should_check(me) {
        return None;
    }
    Some(GLOBAL.with(|global| f(&mut global.borrow_mut())))
}

/// Records a state probe for replica `me`: `sl_probe!(me, "label", a, b)`.
///
/// `a` and `b` must convert into `u32` with `Into` (`bool`, `u8`, `u16`, `u32`),
/// so raw `u64` views or counts must go through [bucket] or [delta] first. The
/// site is `label` plus the call location, so every call site is distinct.
#[allow(unused_macros)]
macro_rules! sl_probe {
    ($me:expr, $label:literal, $a:expr, $b:expr $(,)?) => {{
        let me: ::core::option::Option<$crate::simplex::statelens::Participant> = $me;
        if $crate::simplex::statelens::should_check(me) {
            const SITE: u64 = $crate::simplex::statelens::site_hash(::core::concat!(
                $label,
                "@",
                ::core::file!(),
                ":",
                ::core::line!(),
                ":",
                ::core::column!()
            ));
            let a: u32 = ::core::convert::Into::<u32>::into($a);
            let b: u32 = ::core::convert::Into::<u32>::into($b);
            $crate::simplex::statelens::record(SITE, a, b);
        }
    }};
}

/// Asserts invariant `id` for replica `me`:
/// `sl_assert!(me, "INV-0001", cond, "format", args...)`.
#[allow(unused_macros)]
macro_rules! sl_assert {
    ($me:expr, $id:literal, $cond:expr, $($arg:tt)+) => {{
        let me: ::core::option::Option<$crate::simplex::statelens::Participant> = $me;
        if $crate::simplex::statelens::should_check(me) && !($cond) {
            $crate::simplex::statelens::violation(me, $id, ::core::format_args!($($arg)+));
        }
    }};
}

/// Asserts "if `pre` then `post`" for invariant `id` and records the probe
/// `(pre, post)`: `sl_implies!(me, "INV-0001", pre, post, "format", args...)`.
///
/// `post` is evaluated only when `pre` holds.
#[allow(unused_macros)]
macro_rules! sl_implies {
    ($me:expr, $id:literal, $pre:expr, $post:expr, $($arg:tt)+) => {{
        let me: ::core::option::Option<$crate::simplex::statelens::Participant> = $me;
        if $crate::simplex::statelens::should_check(me) {
            const SITE: u64 = $crate::simplex::statelens::site_hash(::core::concat!(
                $id,
                "@",
                ::core::file!(),
                ":",
                ::core::line!(),
                ":",
                ::core::column!()
            ));
            let pre: bool = $pre;
            let post: bool = pre && ($post);
            $crate::simplex::statelens::record(SITE, u32::from(pre), u32::from(post));
            if pre && !post {
                $crate::simplex::statelens::violation(me, $id, ::core::format_args!($($arg)+));
            }
        }
    }};
}

// `simplex` is declared inside a macro (`stability_scope!`), so `#[macro_export]`
// macros could not be called by path from this crate. Instrumented code calls
// `crate::simplex::statelens::sl_probe!(...)` through these re-exports instead.
#[allow(unused_imports)]
pub(crate) use {sl_assert, sl_implies, sl_probe};

#[cfg(test)]
mod tests {
    use super::*;

    fn evaluated() -> bool {
        panic!("post must not be evaluated when pre is false");
    }

    #[test]
    fn test_discretization() {
        let buckets: Vec<u32> = [0, 1, 2, 3, 4, 5, 8, 9, 1_000]
            .into_iter()
            .map(bucket)
            .collect();
        assert_eq!(buckets, vec![0, 1, 2, 3, 3, 4, 4, 5, 5]);
        assert_eq!(delta(7, 7), 0);
        assert_eq!(delta(9, 7), 2);
        assert_eq!(delta(7, 9), 7);
        assert_eq!(delta(0, u64::MAX), 10);
        assert_eq!(pack(3, 4), (3 << 16) | 4);
        assert_eq!(flag(true), 1);
        assert_eq!(disc(&Some(1u8)), disc(&Some(2u8)));
        assert_ne!(disc(&Some(1u8)), disc(&None::<u8>));
    }

    #[test]
    fn test_byzantine_mode_parsing() {
        assert_eq!(Byzantine::parse(None), Byzantine::Skip);
        assert_eq!(Byzantine::parse(Some("skip")), Byzantine::Skip);
        assert_eq!(Byzantine::parse(Some("check")), Byzantine::Check);
        assert_eq!(Byzantine::parse(Some("panic")), Byzantine::Panic);
    }

    #[test]
    #[should_panic(expected = "STATELENS_BYZANTINE must be skip, check or panic")]
    fn test_byzantine_mode_rejects_unknown_values() {
        let _ = Byzantine::parse(Some("0"));
    }

    #[test]
    fn test_guard_skips_compromised() {
        set_compromised([1]);
        assert!(is_byzantine(Some(Participant::new(1))));
        assert!(!is_byzantine(Some(Participant::new(0))));
        assert!(!is_byzantine(None));
        assert!(!should_check(Some(Participant::new(1))));
        crate::simplex::statelens::sl_assert!(
            Some(Participant::new(1)),
            "INV-TEST",
            false,
            "skipped"
        );
        crate::simplex::statelens::sl_implies!(
            Some(Participant::new(1)),
            "INV-TEST",
            true,
            false,
            "skipped"
        );
        clear_compromised();
        assert!(!is_byzantine(Some(Participant::new(1))));
    }

    #[test]
    #[should_panic(expected = "[statelens][INV-TEST] replica=0 fires 7")]
    fn test_assert_fires_for_honest() {
        clear_compromised();
        crate::simplex::statelens::sl_assert!(
            Some(Participant::new(0)),
            "INV-TEST",
            false,
            "fires {}",
            7
        );
    }

    #[test]
    fn test_implies_evaluates_post_lazily() {
        crate::simplex::statelens::sl_implies!(None, "INV-TEST", false, evaluated(), "never");
        crate::simplex::statelens::sl_implies!(None, "INV-TEST", true, true, "holds");
    }

    #[test]
    #[should_panic(expected = "[statelens][INV-TEST] replica=none broken")]
    fn test_implies_fires() {
        crate::simplex::statelens::sl_implies!(None, "INV-TEST", true, false, "broken");
    }

    #[test]
    fn test_probe_sets_cell() {
        crate::simplex::statelens::sl_probe!(None, "unit", true, 3u8);
        let site = site_hash("unit-direct");
        record(site, 3, 4);
        // SAFETY: `cell` returns an index below `COUNTERS`; the load is atomic.
        let value =
            unsafe { AtomicU8::from_ptr(table().add(cell(site, 3, 4))) }.load(Ordering::Relaxed);
        assert_eq!(value, 1);
    }

    #[test]
    fn test_ghost_state_skips_guarded_replicas() {
        set_compromised([3]);
        assert_eq!(with_ghost(None, |_| ()), None);
        assert_eq!(with_ghost(Some(Participant::new(2)), |_| 5), Some(5));
        assert_eq!(with_ghost(Some(Participant::new(3)), |_| 5), None);
        assert_eq!(with_global(None, |_| 6), Some(6));
        assert_eq!(with_global(Some(Participant::new(3)), |_| 6), None);
        clear_compromised();
    }

    #[test]
    fn test_fresh_runtime_forgets_ghost_state() {
        clear_compromised();
        assert_eq!(with_ghost(Some(Participant::new(4)), |_| ()), Some(()));
        assert!(GHOSTS.with(|ghosts| ghosts.borrow().contains_key(&4)));
        let _runner = commonware_runtime::deterministic::Runner::seeded(0);
        assert!(GHOSTS.with(|ghosts| ghosts.borrow().is_empty()));
    }
}
