//! Exit conditions for simulation completion.

use super::{processed::ProcessedHeight, tracker::ProgressTracker};
use commonware_cryptography::PublicKey;
use std::{future::Future, pin::Pin};

/// Simulation termination condition.
///
/// The simulator evaluates this condition against the current tracker and
/// active validator states. Returning `Ok(true)` ends the simulation.
pub trait ExitCondition<P: PublicKey, S>: Send + Sync {
    /// Human-readable name for logging and errors.
    fn name(&self) -> &str;

    /// Whether this condition should also be checked on periodic polls.
    ///
    /// Conditions driven entirely by finalization updates can return `false`.
    /// Conditions based on state that may advance between updates can return
    /// `true`.
    fn requires_polling(&self) -> bool {
        false
    }

    /// Check whether the condition has been satisfied.
    ///
    /// `target_count` is the number of validators that must satisfy the
    /// condition in the current run state (for example, before delayed
    /// validators start this is the count of currently active validators).
    fn reached<'a>(
        &'a self,
        tracker: &'a ProgressTracker<P>,
        states: &'a [&'a S],
        target_count: usize,
    ) -> Pin<Box<dyn Future<Output = Result<bool, String>> + Send + 'a>>;
}

/// Exit once at least `target_count` validators have finalized `required`
/// views.
#[derive(Clone)]
pub struct MinimumFinalizations {
    required: u64,
}

impl MinimumFinalizations {
    pub const fn new(required: u64) -> Self {
        Self { required }
    }
}

impl<P: PublicKey, S> ExitCondition<P, S> for MinimumFinalizations {
    fn name(&self) -> &str {
        "minimum_finalizations"
    }

    fn reached<'a>(
        &'a self,
        tracker: &'a ProgressTracker<P>,
        _states: &'a [&'a S],
        target_count: usize,
    ) -> Pin<Box<dyn Future<Output = Result<bool, String>> + Send + 'a>> {
        Box::pin(async move { Ok(tracker.all_reached(target_count, self.required)) })
    }
}

/// Exit once at least `target_count` validators have processed up to
/// `required` application height.
#[derive(Clone)]
pub struct ProcessedHeightAtLeast {
    required: u64,
}

impl ProcessedHeightAtLeast {
    pub const fn new(required: u64) -> Self {
        Self { required }
    }
}

impl<P: PublicKey, S: ProcessedHeight> ExitCondition<P, S> for ProcessedHeightAtLeast {
    fn name(&self) -> &str {
        "processed_height_at_least"
    }

    fn requires_polling(&self) -> bool {
        true
    }

    fn reached<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<P>,
        states: &'a [&'a S],
        target_count: usize,
    ) -> Pin<Box<dyn Future<Output = Result<bool, String>> + Send + 'a>> {
        Box::pin(async move {
            let mut reached = 0usize;
            for state in states {
                if state.processed_height().await >= self.required {
                    reached += 1;
                }
            }
            Ok(reached >= target_count)
        })
    }
}
