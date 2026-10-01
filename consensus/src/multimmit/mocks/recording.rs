//! Relay and reporter doubles that record every call for later assertions.

use crate::{Relay, Reporter, multimmit::types::Activity};
use commonware_actor::Feedback;
use commonware_cryptography::{Digest, PublicKey, bls12381::primitives::variant::Variant};
use commonware_utils::sync::Mutex;
use std::{collections::VecDeque, marker::PhantomData, sync::Arc};

struct RelayState<D: Digest> {
    scripted: VecDeque<Feedback>,
    fallback: Feedback,
    broadcasts: Vec<(D, Feedback)>,
}

/// Configurable block relay that records every canonical digest and returned response.
pub struct RecordingRelay<D: Digest, P: PublicKey> {
    state: Arc<Mutex<RelayState<D>>>,
    _marker: PhantomData<fn() -> P>,
}

impl<D: Digest, P: PublicKey> Clone for RecordingRelay<D, P> {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
            _marker: PhantomData,
        }
    }
}

impl<D: Digest, P: PublicKey> RecordingRelay<D, P> {
    /// Creates a relay that always returns `feedback`.
    pub fn with_feedback(feedback: Feedback) -> Self {
        Self::scripted([], feedback)
    }

    /// Creates a relay that returns `scripted` responses, then `fallback`.
    pub fn scripted(scripted: impl IntoIterator<Item = Feedback>, fallback: Feedback) -> Self {
        Self {
            state: Arc::new(Mutex::new(RelayState {
                scripted: scripted.into_iter().collect(),
                fallback,
                broadcasts: Vec::new(),
            })),
            _marker: PhantomData,
        }
    }

    /// Returns the canonical digests and responses observed so far, in call order.
    pub fn broadcasts(&self) -> Vec<(D, Feedback)> {
        self.state.lock().broadcasts.clone()
    }
}

impl<D: Digest, P: PublicKey> Default for RecordingRelay<D, P> {
    fn default() -> Self {
        Self::with_feedback(Feedback::Ok)
    }
}

impl<D: Digest, P: PublicKey> Relay for RecordingRelay<D, P> {
    type Digest = D;
    type PublicKey = P;
    type Plan = ();

    fn broadcast(&mut self, payload: Self::Digest, (): Self::Plan) -> Feedback {
        // Span tests locate the relay call by this event.
        tracing::debug!("test relay received payload");
        let mut state = self.state.lock();
        let feedback = state.scripted.pop_front().unwrap_or(state.fallback);
        state.broadcasts.push((payload, feedback));
        feedback
    }
}

struct ReporterState<V: Variant, D: Digest> {
    feedback: Feedback,
    activities: Vec<Activity<V, D>>,
}

/// Configurable reporter that records every submitted activity.
pub struct RecordingReporter<V: Variant, D: Digest> {
    state: Arc<Mutex<ReporterState<V, D>>>,
}

impl<V: Variant, D: Digest> Clone for RecordingReporter<V, D> {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
        }
    }
}

impl<V: Variant, D: Digest> RecordingReporter<V, D> {
    /// Creates a reporter that returns `feedback` for every submitted activity.
    pub fn with_feedback(feedback: Feedback) -> Self {
        Self {
            state: Arc::new(Mutex::new(ReporterState {
                feedback,
                activities: Vec::new(),
            })),
        }
    }

    /// Returns the activities observed so far, in call order.
    pub fn activities(&self) -> Vec<Activity<V, D>> {
        self.state.lock().activities.clone()
    }

    /// Returns the activities observed after the first `offset`, in call order.
    ///
    /// # Panics
    ///
    /// Panics if fewer than `offset` activities were observed.
    pub fn since(&self, offset: usize) -> Vec<Activity<V, D>> {
        self.state
            .lock()
            .activities
            .get(offset..)
            .expect("activity offset is within the observed activities")
            .to_vec()
    }

    /// Returns how many activities were observed.
    pub fn len(&self) -> usize {
        self.state.lock().activities.len()
    }

    /// Returns whether no activity was observed.
    pub fn is_empty(&self) -> bool {
        self.state.lock().activities.is_empty()
    }
}

impl<V: Variant, D: Digest> Default for RecordingReporter<V, D> {
    fn default() -> Self {
        Self::with_feedback(Feedback::Ok)
    }
}

impl<V: Variant, D: Digest> Reporter for RecordingReporter<V, D> {
    type Activity = Activity<V, D>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        // Span tests locate the reporter call by this event.
        tracing::debug!("test reporter received activity");
        let mut state = self.state.lock();
        state.activities.push(activity);
        state.feedback
    }
}
