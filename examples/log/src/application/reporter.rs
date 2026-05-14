use super::{
    ingress::{Mailbox, Message},
    Scheme,
};
use commonware_actor::{mailbox::Sender, Feedback};
use commonware_consensus::{simplex::types::Activity, Viewable};
use commonware_cryptography::Digest;
use tracing::info;

/// Implementation of `commonware-consensus::Reporter`.
#[derive(Clone)]
pub struct Reporter<D: Digest> {
    sender: Sender<Message<D>>,
}

impl<D: Digest> Reporter<D> {
    pub(super) fn new(mailbox: &Mailbox<D>) -> Self {
        Self {
            sender: mailbox.sender.clone(),
        }
    }
}

impl<D: Digest> commonware_consensus::Reporter for Reporter<D> {
    type Activity = Activity<Scheme, D>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        self.sender.enqueue(Message::Report { activity })
    }
}

pub(super) fn log<D: Digest>(activity: Activity<Scheme, D>) {
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
}
