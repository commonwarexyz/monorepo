//! Reporter wrapper that forwards finalization events to the
//! simulation harness.
//!
//! Custom [`EngineDefinition`](super::engine::EngineDefinition)
//! implementations should include a [`MonitorReporter`] in their
//! reporter chain so the harness can track finalization progress.

use super::tracker::FinalizationUpdate;
use commonware_actor::Feedback;
use commonware_consensus::{marshal::Update, Block, Reporter};
use commonware_cryptography::{Digest, Digestible, PublicKey};
use commonware_utils::channel::mpsc;

/// Wraps another [`Reporter`] and forwards marshal [`Update`]
/// finalization events to the simulation harness via a monitor channel.
///
/// Place this in the marshal reporter chain so it intercepts
/// [`Update::Tip`] events before delegation.
#[derive(Clone)]
pub struct MonitorReporter<P: PublicKey, R> {
    inner: R,
    monitor: mpsc::Sender<FinalizationUpdate<P>>,
    pk: P,
}

impl<P: PublicKey, R> MonitorReporter<P, R> {
    /// Create a new monitor reporter.
    ///
    /// - `pk`: the public key of the validator this reporter belongs to.
    /// - `monitor`: channel for sending finalization updates to the harness.
    /// - `inner`: the wrapped reporter to delegate to after interception.
    pub const fn new(pk: P, monitor: mpsc::Sender<FinalizationUpdate<P>>, inner: R) -> Self {
        Self { inner, monitor, pk }
    }
}

impl<P, B, R> Reporter for MonitorReporter<P, R>
where
    P: PublicKey,
    B: Block + Digestible,
    <B as Digestible>::Digest: Digest,
    R: Reporter<Activity = Update<B>>,
{
    type Activity = Update<B>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        if let Update::Tip(round, _, ref digest) = activity {
            let _ = self.monitor.try_send(FinalizationUpdate {
                pk: self.pk.clone(),
                view: round.view(),
                block_digest: digest.as_ref().to_vec(),
            });
        }
        self.inner.report(activity)
    }
}
