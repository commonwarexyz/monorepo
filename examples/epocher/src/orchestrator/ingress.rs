use crate::GENESIS_BLOCK;
use commonware_consensus::{threshold_simplex::types::Finalization, types::Epoch, Reporter};
use commonware_cryptography::{
    bls12381::primitives::variant::{MinSig, Variant},
    sha256::Digest as Sha256Digest,
    Committable,
};
use futures::{channel::mpsc, SinkExt};

/// Certificate of an epoch transition.
///
/// Contains the two most recent finalizations of the last block in the previous two epochs.
/// Corner case: if the epoch is 1, there is only one finalization from epoch 0.
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum EpochCert {
    Single(Finalization<MinSig, Sha256Digest>),
    Double(
        Finalization<MinSig, Sha256Digest>,
        Finalization<MinSig, Sha256Digest>,
    ),
}

impl EpochCert {
    /// Verifies the epoch certificate.
    pub fn verify(&self, namespace: &[u8], identity: &<MinSig as Variant>::Public) -> bool {
        match self {
            EpochCert::Single(f0) => f0.round().epoch() == 0 && f0.verify(namespace, identity),
            EpochCert::Double(f1, f2) => {
                f1.round()
                    .epoch()
                    .checked_add(1)
                    .is_some_and(|epoch| epoch == f2.round().epoch())
                    && f1.verify(namespace, identity)
                    && f2.verify(namespace, identity)
            }
        }
    }

    /// Returns the epoch to enter.
    pub fn epoch(&self) -> Epoch {
        match self {
            EpochCert::Single(_) => 1,
            EpochCert::Double(_, f2) => f2.round().epoch().checked_add(1).unwrap(),
        }
    }

    /// Returns the seed used.
    pub fn seed(&self) -> Sha256Digest {
        match self {
            EpochCert::Single(_) => GENESIS_BLOCK.commitment(),
            EpochCert::Double(f1, _) => f1.proposal.payload,
        }
    }
}

pub enum Message {
    EpochTransition(EpochCert),
}

/// Mailbox for the orchestrator.
#[derive(Clone)]
pub struct Mailbox {
    sender: mpsc::Sender<Message>,
}

impl Mailbox {
    pub fn new(sender: mpsc::Sender<Message>) -> Self {
        Self { sender }
    }
}

impl Reporter for Mailbox {
    type Activity = EpochCert;

    async fn report(&mut self, activity: Self::Activity) {
        self.sender
            .send(Message::EpochTransition(activity))
            .await
            .expect("Failed to send epoch transition");
    }
}
