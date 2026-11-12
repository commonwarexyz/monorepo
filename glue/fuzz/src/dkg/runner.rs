//! What the drivers share around a run: the entry point a fuzz target calls,
//! the runtime the run executes on, the watch a Twins driver keeps over its
//! correct engines, and what every driver reads of the network afterwards.
//!
//! The network itself, the panic record, and the report line come from
//! [`crate::stateful::runner`].

use super::{PublicKey, invariants};
use crate::stateful::runner::{self, Panic, Reportable};
use commonware_macros::select;
use commonware_p2p::simulated::Oracle;
use commonware_runtime::{Clock as _, Handle, Runner as _, deterministic};
use commonware_utils::FuzzRng;
use futures::future::{join_all, select_all};
use std::{fmt, future::Future, time::Duration};

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

/// What one run of a driver observed, as its report line prints it.
pub(super) trait Report: fmt::Display {
    /// Whether the run's checks compared something.
    fn measured(&self) -> bool;
}

/// A report that is printed only on request. No target requires a run to
/// measure anything: a run in which no ceremony completed, no artifact was
/// emitted, or no joiner synced is healthy.
struct OnRequest<R>(R);

impl<R: Report> fmt::Display for OnRequest<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<R: Report> Reportable for OnRequest<R> {
    fn measured(&self) -> bool {
        self.0.measured()
    }

    fn unexpected(&self) -> bool {
        false
    }
}

/// Run `input`, whose tape is `raw_bytes`, the way a fuzz target does: a
/// failure prints the input's controls and its tape, and the report of the
/// run is printed if reports were asked for.
pub(super) fn fuzz<I: fmt::Debug, R: Report>(
    raw_bytes: Vec<u8>,
    input: I,
    run: impl FnOnce(I) -> R,
) {
    let controls = format!("{input:?}");
    runner::report_input(&controls, &raw_bytes, || OnRequest(run(input)));
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
