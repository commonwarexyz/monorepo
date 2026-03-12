//! Reporter wrapper that forwards simplex finalization events to the
//! simulation harness.
//!
//! Custom [`EngineDefinition`](super::engine::EngineDefinition)
//! implementations should include a [`MonitorReporter`] in their
//! reporter chain so the harness can track finalization progress.

use super::tracker::FinalizationUpdate;
use commonware_consensus::{simplex::types::Activity, Reporter, Viewable as _};
use commonware_cryptography::{certificate::Scheme, Digest, PublicKey};
use commonware_utils::channel::mpsc;

/// Wraps another [`Reporter`] and forwards simplex finalization events
/// to the simulation harness via a monitor channel.
///
/// Place this as the outermost reporter in the chain so it intercepts
/// all activity before delegation.
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

impl<P, S, D, R> Reporter for MonitorReporter<P, R>
where
    P: PublicKey,
    S: Scheme<PublicKey = P>,
    D: Digest,
    R: Reporter<Activity = Activity<S, D>>,
{
    type Activity = Activity<S, D>;

    async fn report(&mut self, activity: Self::Activity) {
        if let Activity::Finalization(ref f) = activity {
            let _ = self
                .monitor
                .send(FinalizationUpdate {
                    pk: self.pk.clone(),
                    view: f.view(),
                    block_digest: f.proposal.payload.as_ref().to_vec(),
                })
                .await;
        }
        self.inner.report(activity).await;
    }
}
