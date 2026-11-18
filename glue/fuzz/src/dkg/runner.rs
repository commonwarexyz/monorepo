//! What the drivers share around a run: the entry point a fuzz target calls,
//! the runtime the run executes on, the watch a Twins driver keeps over its
//! correct engines, and what every driver reads of the network afterwards.
//!
//! The network itself, the panic record, and the report line come from
//! [`crate::stateful::runner`]. The aggregate a fuzz process writes over its
//! runs comes from [`super::report`].

use super::{
    PublicKey, invariants,
    report::{Emitter, Entry, Report, Stderr},
};
use crate::stateful::runner::{self, Panic, Reportable};
use commonware_macros::select;
use commonware_p2p::simulated::Oracle;
use commonware_runtime::{Clock as _, Handle, Runner as _, deterministic};
use commonware_utils::{
    FuzzRng,
    sync::{Mutex, Once},
};
use futures::future::{join_all, select_all};
use std::{ffi::c_int, fmt, future::Future, time::Duration};

/// Why a run stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Every correct engine reached the end of what the driver observes.
    Completed,
    /// The run's bounded timeout expired.
    Timeout,
    /// A correct engine stopped.
    Stopped,
    /// The twins generator produced no case, so nothing ran.
    NoCase,
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Completed => f.write_str("completed"),
            Self::Timeout => f.write_str("timeout"),
            Self::Stopped => f.write_str("stopped"),
            Self::NoCase => f.write_str("no-case"),
        }
    }
}

/// A report that is printed only on request. No target requires a run to
/// measure anything: a run in which no ceremony completed, no artifact was
/// emitted, or no joiner synced is healthy, and so is a run that left an
/// invariant unmeasured.
struct OnRequest<R>(R);

impl<R: Report> fmt::Display for OnRequest<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<R: Report> Reportable for OnRequest<R> {
    fn measured(&self) -> bool {
        self.0.judged().entries().iter().any(Entry::measured)
    }

    fn unexpected(&self) -> bool {
        false
    }
}

/// The aggregate of every target this process has run, each written to
/// standard error. A fuzz process runs one target.
static EMITTERS: Mutex<Vec<Emitter<Stderr>>> = Mutex::new(Vec::new());

unsafe extern "C" {
    /// The C library's `atexit`: call `callback` when the process exits by
    /// returning from `main` or by calling `exit`.
    fn atexit(callback: extern "C" fn()) -> c_int;
}

/// Write the aggregate over every run the process completed. Registered to
/// run when the process ends by itself, as when libFuzzer reaches its limit
/// of runs or of time. A process that is killed or that aborts does not get
/// here.
extern "C" fn finish() {
    for emitter in EMITTERS.lock().iter_mut() {
        emitter.finish();
    }
}

/// Ask the C library to call `callback` when the process ends by itself.
fn at_exit(callback: extern "C" fn()) {
    // SAFETY: `atexit` is the C library's, which every process links. It
    // keeps the pointer it is given until the process ends, and a function
    // lives that long.
    //
    // Miri cannot call `atexit`. By the user's decision of 2026-11-18 this
    // one call is exempt from the Miri test that unsafe code otherwise gets.
    let registered = unsafe { atexit(callback) };
    assert_eq!(registered, 0, "the exit handler must register");
}

/// Fold the report of a completed run into the aggregate of its target, and
/// write the aggregate when its interval of runs is over.
fn emit<R: Report>(report: &R) {
    static AT_EXIT: Once = Once::new();
    AT_EXIT.call_once(|| at_exit(finish));
    let target = report.judged().target();
    let mut emitters = EMITTERS.lock();
    let position = emitters
        .iter()
        .position(|emitter| emitter.aggregate().target() == target)
        .unwrap_or_else(|| {
            emitters.push(Emitter::new(target, Stderr));
            emitters.len() - 1
        });
    emitters[position].completed(report);
}

/// Run `input`, whose tape is `raw_bytes`, the way a fuzz target does: a
/// failure prints the input's controls and its tape, the report of the run
/// is folded into the aggregate the process writes, and the report itself is
/// printed if reports were asked for.
pub(super) fn fuzz<I: fmt::Debug, R: Report>(
    raw_bytes: Vec<u8>,
    input: I,
    run: impl FnOnce(I) -> R,
) {
    let controls = format!("{input:?}");
    runner::report_input(&controls, &raw_bytes, || {
        let report = run(input);
        emit(&report);
        OnRequest(report)
    });
}

/// Run `root` as the root task of a deterministic runtime seeded with
/// `entropy`. Returns what the root task returned and every panic the run
/// raised, each with the engine it is attributed to.
///
/// The runtime catches the panics of its tasks, so a panic stops the task it
/// occurs in instead of the run, and the caller judges the record once the
/// runtime has stopped, where a violation is never caught. The root task is
/// the harness itself, and a panic that leaves it is a violation of I8.
pub(super) fn execute<T, Fut>(
    entropy: Vec<u8>,
    root: impl FnOnce(deterministic::Context) -> Fut,
) -> (T, Vec<Panic>)
where
    Fut: Future<Output = T>,
{
    let config = deterministic::Config::new()
        .with_rng(FuzzRng::new(entropy))
        .with_catch_panics(true);
    let (observed, panics) = runner::tolerating(|| deterministic::Runner::new(config).start(root));
    (invariants::check_root_task(observed, &panics), panics)
}

/// Wait until every one of `waiters` has completed, one of the correct
/// `engines` stops, or `timeout` of simulated time has passed. Returns why
/// the wait ended and the correct engines that stopped.
///
/// A correct engine never stops on its own, so one that does has failed.
pub(super) async fn watch(
    context: &deterministic::Context,
    engines: Vec<(usize, Handle<()>)>,
    waiters: Vec<Handle<()>>,
    timeout: Duration,
) -> (Outcome, Vec<usize>) {
    let (indices, handles): (Vec<usize>, Vec<Handle<()>>) = engines.into_iter().unzip();
    let mut stopped = Vec::new();
    let outcome = select! {
        (_, index, _) = select_all(handles) => {
            stopped.push(indices[index]);
            Outcome::Stopped
        },
        _ = join_all(waiters) => Outcome::Completed,
        _ = context.sleep(timeout) => Outcome::Timeout,
    };
    (outcome, stopped)
}

/// Every `(blocker, blocked)` pair the network of `oracle` recorded.
pub(super) async fn blocked(
    oracle: &Oracle<PublicKey, deterministic::Context>,
) -> Vec<(PublicKey, PublicKey)> {
    oracle
        .blocked()
        .await
        .expect("the network must report its blocks")
}

#[cfg(test)]
mod tests {
    use super::*;

    extern "C" fn noted() {}

    /// Miri cannot call `atexit`, so this test is outside the `miri` group.
    #[test]
    fn exit_handler_registers() {
        at_exit(noted);
    }
}
