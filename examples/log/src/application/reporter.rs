use super::Scheme;
use commonware_consensus::{simplex::types::Activity, Viewable};
use commonware_cryptography::Digest;
use commonware_utils::channel::actor::Enqueue;
use std::marker::PhantomData;
use tracing::info;

/// Implementation of `commonware-consensus::Reporter`.
#[derive(Clone)]
pub struct Reporter<D: Digest> {
    _phantom: PhantomData<D>,
}

impl<D: Digest> Reporter<D> {
    pub const fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<D: Digest> commonware_consensus::Reporter for Reporter<D> {
    type Activity = Activity<Scheme, D>;

    fn report(&mut self, activity: Self::Activity) -> Enqueue {
        let view = activity.view();
        match activity {
            Activity::Notarization(notarization) => {
                info!(%view, payload = ?notarization.proposal.payload, "notarized");
            }
            Activity::Finalization(finalization) => {
                info!(%view, payload = ?finalization.proposal.payload, "finalized");
            }
            Activity::Nullification(_) => {
                info!(%view, "nullified");
            }
            _ => {}
        }
        Enqueue::Queued
    }
}
