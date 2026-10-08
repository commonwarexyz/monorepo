//! StateLens runtime support for an instrumented campaign.
//!
//! This file is a template kept in `statelens/runtime/`. A campaign copies it into
//! the checkout it instruments as the `statelens` module of the subsystem it
//! instruments, and declares it with `pub mod statelens;`: as
//! `consensus/src/simplex/statelens.rs` for the simplex and marshal profiles, and as
//! `storage/src/qmdb/statelens.rs` for the qmdb profile, where its paths name `qmdb`
//! and the consensus-only tests at the end of the file are left out. It is never
//! compiled on a committed branch.
//!
//! It provides:
//! - the Byzantine guard: [set_compromised], [clear_compromised], [is_byzantine]
//!   and [should_check], and [provider_me] for a component that has a scheme
//!   provider but no scheme;
//! - a SanitizerCoverage counter table fed by state probes: [record] and [reset];
//! - the instrumentation macros `sl_probe!`, `sl_assert!` and `sl_implies!`,
//!   invoked as `crate::simplex::statelens::sl_probe!(...)`;
//! - ghost state: per replica ([Ghost], [with_ghost]) and shared by all honest
//!   replicas ([Global], [with_global]). It lives for one run: [reset] and every
//!   fresh deterministic runtime clear it, while a runtime resumed from a
//!   checkpoint (a crash-restart) keeps it;
//! - discretization helpers: [bucket], [delta], [flag], [pack] and [disc];
//! - the read side, for the target-state scaffolds only: while a scaffold
//!   [watch]es, an ordered trace of the probe observations of one input ([Seen],
//!   [seen], [sites], [observations], [truncated]), and one event sequence per
//!   input that orders those observations and the scaffold helper's events
//!   ([tick], [mark]). Instrumentation never calls it.
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

use commonware_cryptography::certificate::{ConstantProvider, Provider, Scheme as _};
pub use commonware_utils::Participant;
use std::{
    any::TypeId,
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
    static TRACE: RefCell<Trace> = const { RefCell::new(Trace::new()) };
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

/// Returns the replica index a component that holds a scheme provider can use as
/// `me`, without a lookup anyone can observe.
///
/// A provider lookup is not a read: an application may count lookups against the
/// scope it serves and retire it, so an extra one can turn a later lookup of the
/// implementation's into `None`. The only provider whose lookups are known to
/// change nothing is [ConstantProvider], which clones its scheme, and it is the one
/// every fuzz harness uses. For it, this returns `Some` of the scheme's index
/// (`Some(None)` for a scheme that is not a participant). For any other provider it
/// makes no lookup and returns `None`, and so it does when the provider has no
/// signing scheme for `scope`: the index is unknown, and the caller must leave its
/// sites uninstrumented rather than pass `None` as `me`, which would turn the
/// Byzantine guard off. `scope` is not used for a [ConstantProvider], so any one in
/// hand will do.
pub fn provider_me<P: Provider>(provider: &P, scope: P::Scope) -> Option<Option<Participant>> {
    if TypeId::of::<P>() != TypeId::of::<ConstantProvider<P::Scheme, P::Scope>>() {
        return None;
    }
    provider.scheme(scope).map(|scheme| scheme.me())
}

/// Raw pointer to the counter bytes.
fn table() -> *mut u8 {
    // `Counters<N>` is `#[repr(transparent)]` over `UnsafeCell<[u8; N]>`.
    (&TABLE as *const sancov::Counters<COUNTERS>)
        .cast::<u8>()
        .cast_mut()
}

/// Prepares a fuzz input: zeroes the counter table, forgets the compromised set,
/// clears the ghost state, and drops the probe trace, so the event sequence and
/// the run counter start again at 0. In a fuzzing build it also registers the
/// table with libFuzzer on first use, unless `STATELENS_FEEDBACK=0`.
///
/// Called by the StateLens fuzz target before every input.
pub fn reset() {
    #[cfg(fuzzing)]
    {
        static REGISTERED: OnceLock<()> = OnceLock::new();
        REGISTERED.get_or_init(|| {
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
    clear_trace();
}

/// Forgets all ghost state.
fn forget_ghosts() {
    GHOSTS.with(|ghosts| ghosts.borrow_mut().clear());
    GLOBAL.with(|global| *global.borrow_mut() = Global::default());
}

/// Starts an independent run: forgets all ghost state, then counts the runtime
/// instance of the input.
///
/// Registered as the deterministic runtime's fresh-run hook, so history from an
/// earlier, independent run on this thread (for example another seed of the same
/// test) does not leak into the next run. A runtime resumed from a checkpoint (a
/// crash-restart) keeps the history and the run number.
fn fresh_run() {
    forget_ghosts();
    TRACE.with(|trace| {
        let mut trace = trace.borrow_mut();
        trace.run = trace.run.saturating_add(1);
    });
}

/// Registers [fresh_run] with the deterministic runtime; only the first call of the
/// process sets it.
fn register_fresh_run_hook() {
    let _ = commonware_runtime::deterministic::STATELENS_FRESH_RUN.set(fresh_run);
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

/// Most observations the trace of one input keeps.
pub const TRACE_CAP: usize = 1 << 20;

/// One probe observation of a watched input. Its fields are private, so only the
/// runtime makes or changes one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Seen {
    label: &'static str,
    site: &'static str,
    me: Option<u32>,
    a: u32,
    b: u32,
    seq: u64,
    run: u32,
}

impl Seen {
    /// The `sl_probe!` label, or the invariant ID of an `sl_implies!` site.
    pub const fn label(self) -> &'static str {
        self.label
    }

    /// The call site, `concat!(file!(), ":", line!(), ":", column!())`.
    pub const fn site(self) -> &'static str {
        self.site
    }

    /// The participant index of the observing replica.
    pub const fn me(self) -> Option<u32> {
        self.me
    }

    /// The first recorded value; `pre` at an `sl_implies!` site.
    pub const fn a(self) -> u32 {
        self.a
    }

    /// The second recorded value; `pre && post` at an `sl_implies!` site.
    pub const fn b(self) -> u32 {
        self.b
    }

    /// The position of the observation in the event sequence of the input, from 1.
    pub const fn seq(self) -> u64 {
        self.seq
    }

    /// The runtime instance of the input that made it, from 1.
    pub const fn run(self) -> u32 {
        self.run
    }
}

/// The read side's state on this thread: the trace of one input, its event
/// sequence and its run counter.
struct Trace {
    /// Whether a scaffold watches, so observations are kept and the sequence advances.
    watching: bool,
    /// The position of the first observation dropped because the trace held
    /// [TRACE_CAP], if any.
    truncated: Option<u64>,
    /// The last position issued in the input.
    seq: u64,
    /// The runtime instance current on this thread, counted by [fresh_run].
    run: u32,
    /// The observations, in order of their positions.
    seen: Vec<Seen>,
}

impl Trace {
    const fn new() -> Self {
        Self {
            watching: false,
            truncated: None,
            seq: 0,
            run: 0,
            seen: Vec::new(),
        }
    }
}

/// Drops the trace, sets the run counter and the event sequence to 0, and
/// registers the fresh-run hook, so the first runtime of the input has run 1.
///
/// [reset] calls it. Self-tests call it instead of [reset], because it touches
/// only the thread-local trace, run counter and sequence.
fn clear_trace() {
    register_fresh_run_hook();
    TRACE.with(|trace| *trace.borrow_mut() = Trace::new());
}

/// Starts an empty trace for this input. The event sequence goes on from its
/// current value.
pub fn watch() {
    TRACE.with(|trace| {
        let mut trace = trace.borrow_mut();
        trace.watching = true;
        trace.truncated = None;
        trace.seen = Vec::new();
    });
}

/// Stops keeping observations and drops the trace.
pub fn unwatch() {
    TRACE.with(|trace| {
        let mut trace = trace.borrow_mut();
        trace.watching = false;
        trace.truncated = None;
        trace.seen = Vec::new();
    });
}

/// Advances the event sequence and returns its new value, which is greater than
/// every position issued earlier in the input. While not watching it returns 0
/// and advances nothing.
///
/// Only the scaffold helper calls it.
pub fn tick() -> u64 {
    TRACE.with(|trace| {
        let mut trace = trace.borrow_mut();
        if !trace.watching {
            return 0;
        }
        trace.seq = trace.seq.saturating_add(1);
        trace.seq
    })
}

/// The last position issued in the input, to an observation or by a [tick],
/// without advancing the sequence; 0 before the first.
pub fn mark() -> u64 {
    TRACE.with(|trace| trace.borrow().seq)
}

/// The runtime instance current on this thread, from 1; 0 before the first
/// runtime of the input.
pub fn current_run() -> u32 {
    TRACE.with(|trace| trace.borrow().run)
}

/// The position of the first observation the trace dropped because it held
/// [TRACE_CAP], or `None` while it has dropped none. A dropped observation still
/// advances the sequence, so what the trace holds from that position on is
/// incomplete.
pub fn truncated() -> Option<u64> {
    TRACE.with(|trace| trace.borrow().truncated)
}

/// The earliest observation at or after position `since`, of the run current at
/// the call, with `label`, at `site` when one is given, that `f` accepts. `None`
/// while not watching.
///
/// Find a site with [sites], never as a literal: edits move lines.
pub fn seen(
    label: &str,
    site: Option<&str>,
    since: u64,
    mut f: impl FnMut(&Seen) -> bool,
) -> Option<Seen> {
    let (mut index, run) = TRACE.with(|trace| {
        let trace = trace.borrow();
        trace.watching.then(|| {
            (
                trace.seen.partition_point(|seen| seen.seq < since),
                trace.run,
            )
        })
    })?;
    loop {
        // `f` runs outside the borrow, so it may read the trace itself.
        let candidate = TRACE.with(|trace| {
            let trace = trace.borrow();
            let rest = trace.seen.get(index..)?;
            let offset = rest.iter().position(|seen| {
                seen.run == run && seen.label == label && site.is_none_or(|site| site == seen.site)
            })?;
            Some((rest[offset], index + offset + 1))
        });
        let (candidate, next) = candidate?;
        if f(&candidate) {
            return Some(candidate);
        }
        index = next;
    }
}

/// The sites at which the trace holds `label`, in order of their first observation.
pub fn sites(label: &str) -> Vec<&'static str> {
    TRACE.with(|trace| {
        let mut sites = Vec::new();
        for seen in trace
            .borrow()
            .seen
            .iter()
            .filter(|seen| seen.label == label)
        {
            if !sites.contains(&seen.site) {
                sites.push(seen.site);
            }
        }
        sites
    })
}

/// Every observation at or after position `since`, of every run, oldest first.
pub fn observations(since: u64) -> Vec<Seen> {
    TRACE.with(|trace| {
        let trace = trace.borrow();
        let start = trace.seen.partition_point(|seen| seen.seq < since);
        trace.seen[start..].to_vec()
    })
}

/// While watching, advances the event sequence and appends an observation with
/// the new value as its position, unless the trace holds [TRACE_CAP]
/// observations, in which case [truncated] keeps the position of the first one it
/// dropped. Only the macros call it, inside the guard, after [record].
#[doc(hidden)]
pub fn note(me: Option<Participant>, label: &'static str, site: &'static str, a: u32, b: u32) {
    TRACE.with(|trace| {
        let mut trace = trace.borrow_mut();
        if !trace.watching {
            return;
        }
        trace.seq = trace.seq.saturating_add(1);
        if trace.seen.len() >= TRACE_CAP {
            if trace.truncated.is_none() {
                trace.truncated = Some(trace.seq);
            }
            return;
        }
        let seen = Seen {
            label,
            site,
            me: me.map(|me| me.get()),
            a,
            b,
            seq: trace.seq,
            run: trace.run,
        };
        trace.seen.push(seen);
    });
}

/// Records a state probe for replica `me`: `sl_probe!(me, "label", a, b)`.
///
/// `a` and `b` must convert into `u32` with `Into` (`bool`, `u8`, `u16`, `u32`),
/// so raw `u64` views or counts must go through [bucket] or [delta] first. The
/// site is `label` plus the call location, so every call site is distinct. While
/// a scaffold watches, the observation is also appended to the trace.
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
            $crate::simplex::statelens::note(
                me,
                $label,
                ::core::concat!(
                    ::core::file!(),
                    ":",
                    ::core::line!(),
                    ":",
                    ::core::column!()
                ),
                a,
                b,
            );
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
/// `post` is evaluated only when `pre` holds. While a scaffold watches, the
/// observation is also appended to the trace, before a violation panics.
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
            $crate::simplex::statelens::note(
                me,
                $id,
                ::core::concat!(
                    ::core::file!(),
                    ":",
                    ::core::line!(),
                    ":",
                    ::core::column!()
                ),
                u32::from(pre),
                u32::from(post),
            );
            if pre && !post {
                $crate::simplex::statelens::violation(me, $id, ::core::format_args!($($arg)+));
            }
        }
    }};
}

// The subsystem module is declared inside a macro (`stability_scope!`), so
// `#[macro_export]` macros could not be called by path from this crate. Instrumented
// code calls `crate::simplex::statelens::sl_probe!(...)` through these re-exports instead.
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
            "skipped by the guard"
        );
        crate::simplex::statelens::sl_implies!(
            Some(Participant::new(1)),
            "INV-TEST",
            true,
            false,
            "skipped by the guard"
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

    // The read-side tests call `clear_trace`, never `reset`, which zeroes the
    // counter table the other tests share under plain `cargo test`.

    #[test]
    fn test_read_side_is_off_unless_watched() {
        clear_trace();
        crate::simplex::statelens::sl_probe!(None, "unwatched", true, 1u8);
        assert_eq!(tick(), 0, "no position while not watching");
        assert_eq!(mark(), 0);
        assert!(observations(0).is_empty());
        assert_eq!(seen("unwatched", None, 0, |_| true), None);
        watch();
        crate::simplex::statelens::sl_probe!(None, "watched", true, 2u8);
        let trace = observations(0);
        assert_eq!(trace.len(), 1);
        let only = trace[0];
        assert_eq!(
            (only.label(), only.me(), only.a(), only.b()),
            ("watched", None, 1, 2)
        );
        assert_eq!((only.seq(), only.run()), (1, 0));
        let site: Vec<&str> = only.site().rsplitn(3, ':').collect();
        assert_eq!(site.len(), 3, "the site is file:line:column");
        assert_eq!(site[2], file!());
        assert!(site[0].parse::<u32>().is_ok() && site[1].parse::<u32>().is_ok());
        unwatch();
        assert!(observations(0).is_empty());
        assert_eq!(tick(), 0);
        crate::simplex::statelens::sl_probe!(None, "watched", true, 2u8);
        assert_eq!(mark(), 1, "unwatch keeps the sequence");
        watch();
        assert!(observations(0).is_empty(), "watch starts an empty trace");
        assert_eq!(tick(), 2, "the sequence goes on from its current value");
        clear_trace();
    }

    #[test]
    fn test_ticks_and_observations_share_one_sequence() {
        clear_trace();
        watch();
        let first = tick();
        let second = tick();
        assert_eq!(
            (first, second),
            (1, 2),
            "two ticks get distinct, ordered positions"
        );
        crate::simplex::statelens::sl_probe!(Some(Participant::new(0)), "shared", true, 0u8);
        let third = tick();
        crate::simplex::statelens::sl_probe!(None, "shared", false, 0u8);
        let positions: Vec<u64> = observations(0).iter().map(|seen| seen.seq()).collect();
        assert_eq!(positions, vec![3, 5]);
        assert_eq!(third, 4);
        assert_eq!(mark(), 5, "mark is the last position");
        assert_eq!(mark(), 5, "mark does not advance");
        assert_eq!(observations(5).len(), 1);
        assert_eq!(tick(), 6);
        clear_trace();
        assert_eq!(mark(), 0, "clear_trace starts the sequence again");
        assert_eq!(tick(), 0, "and stops watching");
        watch();
        assert_eq!(tick(), 1, "positions are unique within one input only");
        clear_trace();
    }

    #[test]
    fn test_seen_finds_the_earliest_match() {
        clear_trace();
        clear_compromised();
        watch();
        for value in 0u8..3 {
            crate::simplex::statelens::sl_probe!(Some(Participant::new(1)), "earliest", value, 0u8);
        }
        crate::simplex::statelens::sl_probe!(Some(Participant::new(2)), "earliest", 1u8, 0u8);
        crate::simplex::statelens::sl_probe!(None, "other", 1u8, 0u8);
        let found = sites("earliest");
        assert_eq!(found.len(), 2, "one site per call");
        assert_eq!(sites("other").len(), 1);
        assert!(sites("absent").is_empty());
        let first = seen("earliest", None, 0, |_| true).expect("first");
        assert_eq!((first.seq(), first.a(), first.site()), (1, 0, found[0]));
        let later = seen("earliest", None, 2, |_| true).expect("at or after");
        assert_eq!((later.seq(), later.a()), (2, 1));
        let accepted = seen("earliest", None, 0, |seen| seen.a() == 1).expect("accepted");
        assert_eq!(accepted.seq(), 2);
        let at_site = seen("earliest", Some(found[1]), 0, |seen| seen.a() == 1).expect("site");
        assert_eq!((at_site.seq(), at_site.me()), (4, Some(2)));
        assert_eq!(seen("earliest", Some(found[0]), 4, |_| true), None);
        assert_eq!(seen("earliest", None, 0, |seen| seen.a() == 7), None);
        assert_eq!(seen("absent", None, 0, |_| true), None);
        clear_trace();
    }

    #[test]
    fn test_guarded_replicas_are_not_observed() {
        clear_trace();
        set_compromised([1]);
        watch();
        crate::simplex::statelens::sl_probe!(Some(Participant::new(1)), "guarded", true, 0u8);
        crate::simplex::statelens::sl_implies!(
            Some(Participant::new(1)),
            "INV-TEST",
            true,
            false,
            "skipped by the guard"
        );
        crate::simplex::statelens::sl_probe!(Some(Participant::new(0)), "guarded", true, 0u8);
        let trace = observations(0);
        assert_eq!(trace.len(), 1);
        assert_eq!(
            (trace[0].me(), trace[0].seq()),
            (Some(0), 1),
            "a skipped hit takes no position"
        );
        clear_compromised();
        clear_trace();
    }

    #[test]
    fn test_implies_notes_its_pair() {
        clear_trace();
        watch();
        crate::simplex::statelens::sl_implies!(None, "INV-PAIR", false, evaluated(), "never");
        crate::simplex::statelens::sl_implies!(None, "INV-PAIR", true, true, "holds");
        let violated = std::panic::catch_unwind(|| {
            crate::simplex::statelens::sl_implies!(None, "INV-PAIR", true, false, "broken");
        });
        assert!(violated.is_err());
        let pairs: Vec<(u32, u32)> = observations(0)
            .iter()
            .filter(|seen| seen.label() == "INV-PAIR")
            .map(|seen| (seen.a(), seen.b()))
            .collect();
        assert_eq!(
            pairs,
            vec![(0, 0), (1, 1), (1, 0)],
            "the violation is in the trace"
        );
        clear_trace();
    }

    #[test]
    fn test_trace_cap() {
        clear_trace();
        watch();
        for _ in 0..TRACE_CAP {
            note(None, "cap", "cap.rs:1:1", 0, 0);
        }
        assert_eq!(truncated(), None);
        note(None, "cap", "cap.rs:1:1", 1, 0);
        let first = TRACE_CAP as u64 + 1;
        assert_eq!(
            truncated(),
            Some(first),
            "an observation past the cap is dropped, and its position kept"
        );
        assert_eq!(TRACE.with(|trace| trace.borrow().seen.len()), TRACE_CAP);
        assert_eq!(mark(), first, "a dropped observation takes a position");
        assert_eq!(tick(), first + 1);
        note(None, "cap", "cap.rs:1:1", 2, 0);
        assert_eq!(truncated(), Some(first), "the first dropped position stays");
        assert_eq!(mark(), first + 2);
        assert_eq!(seen("cap", None, 0, |seen| seen.a() != 0), None);
        unwatch();
        assert_eq!(truncated(), None, "unwatch forgets the cut");
        watch();
        assert_eq!(truncated(), None, "watch starts an uncut trace");
        clear_trace();
        assert_eq!(truncated(), None);
    }

    #[test]
    fn test_fresh_runtime_counts_runs() {
        clear_trace();
        clear_compromised();
        assert_eq!(current_run(), 0);
        watch();
        crate::simplex::statelens::sl_probe!(None, "runs", true, 0u8);
        let _first = commonware_runtime::deterministic::Runner::seeded(0);
        assert_eq!(current_run(), 1, "the first runtime of an input has run 1");
        crate::simplex::statelens::sl_probe!(None, "runs", true, 1u8);
        let _second = commonware_runtime::deterministic::Runner::seeded(1);
        crate::simplex::statelens::sl_probe!(None, "runs", true, 2u8);
        let runs: Vec<(u32, u32)> = observations(0)
            .iter()
            .map(|seen| (seen.run(), seen.b()))
            .collect();
        assert_eq!(runs, vec![(0, 0), (1, 1), (2, 2)], "the trace spans runs");
        let current = seen("runs", None, 0, |_| true).expect("current run");
        assert_eq!(
            (current.run(), current.b()),
            (2, 2),
            "seen reads the current run"
        );
        clear_trace();
        assert_eq!(current_run(), 0);
        let _third = commonware_runtime::deterministic::Runner::seeded(2);
        assert_eq!(current_run(), 1);
        clear_trace();
    }
}

// [statelens] consensus only: these tests build Simplex signing schemes, so a campaign
// that puts this module in another crate leaves out everything from this line on.
#[cfg(test)]
mod provider_tests {
    use super::*;

    /// A provider that counts its lookups, as an application that retires a scope
    /// after a number of them would.
    #[derive(Clone)]
    struct CountingProvider {
        scheme: std::sync::Arc<crate::simplex::scheme::ed25519::Scheme>,
        lookups: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Provider for CountingProvider {
        type Scope = ();
        type Scheme = crate::simplex::scheme::ed25519::Scheme;

        fn scoped(
            &self,
            _: (),
        ) -> Option<commonware_cryptography::certificate::Scoped<Self::Scheme>> {
            self.lookups.fetch_add(1, Ordering::Relaxed);
            Some(commonware_cryptography::certificate::Scoped::scheme(
                self.scheme.clone(),
            ))
        }
    }

    #[test]
    fn test_provider_me_reads_a_constant_provider() {
        let commonware_cryptography::certificate::mocks::Fixture {
            schemes, verifier, ..
        } = crate::simplex::scheme::ed25519::fixture(
            &mut commonware_utils::test_rng(),
            b"statelens",
            4,
        );
        let expected = schemes[2].me();
        assert!(expected.is_some());
        let provider = ConstantProvider::<_, ()>::new(schemes[2].clone());
        assert_eq!(provider_me(&provider, ()), Some(expected));
        // A scheme that is not a participant is known to be one: `Some(None)`.
        let provider = ConstantProvider::<_, ()>::new(verifier);
        assert_eq!(provider_me(&provider, ()), Some(None));
    }

    #[test]
    fn test_provider_me_leaves_any_other_provider_alone() {
        let commonware_cryptography::certificate::mocks::Fixture { schemes, .. } =
            crate::simplex::scheme::ed25519::fixture(
                &mut commonware_utils::test_rng(),
                b"statelens",
                4,
            );
        let provider = CountingProvider {
            scheme: std::sync::Arc::new(schemes[0].clone()),
            lookups: Default::default(),
        };
        assert_eq!(provider_me(&provider, ()), None, "the index is unknown");
        assert_eq!(
            provider.lookups.load(Ordering::Relaxed),
            0,
            "an unknown provider must not be looked up"
        );
    }
}
