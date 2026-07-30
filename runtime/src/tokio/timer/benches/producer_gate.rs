//! Cancelable coordination for dedicated benchmark producers.

use commonware_utils::sync::{Condvar, Mutex};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

/// Coordinator state for cancellation producers.
pub(crate) struct ProducerGate {
    /// Protected arrival count and release decision.
    state: Mutex<State>,
    /// Wakes the coordinator or every waiting producer.
    changed: Condvar,
}

/// State protected by [`ProducerGate`].
struct State {
    /// Producers that completed registration.
    ready: usize,
    /// Whether producers should wait, cancel, or start measurement.
    release: ProducerRelease,
}

/// Coordinator decision observed by every cancellation producer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProducerRelease {
    /// A producer failure requires waiting producers to discard their timers.
    Cancel,
    /// Every producer may begin cancellation.
    Start,
    /// Registration is still in progress.
    Waiting,
}

impl ProducerGate {
    /// Creates a gate with no registered producer.
    pub(crate) const fn new() -> Self {
        Self {
            state: Mutex::new(State {
                ready: 0,
                release: ProducerRelease::Waiting,
            }),
            changed: Condvar::new(),
        }
    }

    /// Registers one arrival and waits for the coordinator's decision.
    pub(crate) fn arrive_and_wait(&self) -> ProducerRelease {
        let mut state = self.state.lock();
        state.ready += 1;
        self.changed.notify_all();
        while state.release == ProducerRelease::Waiting {
            self.changed.wait(&mut state);
        }
        state.release
    }

    /// Waits until every producer arrives or setup is canceled.
    pub(crate) fn wait_until_ready(&self, producers: usize) -> bool {
        let mut state = self.state.lock();
        while state.ready < producers && state.release == ProducerRelease::Waiting {
            self.changed.wait(&mut state);
        }
        state.ready == producers && state.release != ProducerRelease::Cancel
    }

    /// Releases producers unless setup was already canceled.
    pub(crate) fn start(&self) {
        self.release(ProducerRelease::Start);
    }

    /// Dominates any prior decision and releases producers without measurement.
    ///
    /// Replacing `Start` records that an already-released producer panicked.
    /// Producers that left the gate continue and expose the panic through join.
    pub(crate) fn cancel(&self) {
        self.release(ProducerRelease::Cancel);
    }

    /// Cancels waiting producers before resuming a producer panic.
    pub(crate) fn cancel_on_unwind<T>(&self, work: impl FnOnce() -> T) -> T {
        match catch_unwind(AssertUnwindSafe(work)) {
            Ok(output) => output,
            Err(payload) => {
                self.cancel();
                resume_unwind(payload);
            }
        }
    }

    /// Publishes one decision while preserving cancellation dominance.
    fn release(&self, release: ProducerRelease) {
        let mut state = self.state.lock();
        if release == ProducerRelease::Cancel || state.release == ProducerRelease::Waiting {
            state.release = release;
        }
        self.changed.notify_all();
    }
}

#[cfg(test)]
#[path = "producer_gate_tests.rs"]
mod tests;
