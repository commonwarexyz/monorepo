mod actor;
mod ingress;
mod state;

use crate::types::Epoch;
pub use actor::Actor;
use commonware_cryptography::certificate::Scheme;
use commonware_p2p::Blocker;
use commonware_parallel::Strategy;
pub use ingress::Mailbox;
#[cfg(test)]
pub use ingress::MailboxMessage;
use std::{num::NonZeroUsize, time::Duration};

pub struct Config<S: Scheme, B: Blocker, T: Strategy> {
    pub scheme: S,

    pub blocker: B,

    /// Strategy for parallel operations.
    pub strategy: T,

    pub epoch: Epoch,
    pub mailbox_size: NonZeroUsize,
    pub fetch_concurrent: NonZeroUsize,
    pub fetch_timeout: Duration,
}

/// Certificate builders shared by the resolver test modules.
#[cfg(test)]
mod test_helpers {
    use crate::{
        simplex::{
            scheme::ed25519,
            types::{
                Finalization, Finalize, Notarization, Notarize, Nullification, Nullify, Proposal,
            },
        },
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::sha256::Digest as Sha256Digest;
    use commonware_parallel::Sequential;

    type TestScheme = ed25519::Scheme;

    pub(super) fn build_nullification(
        schemes: &[TestScheme],
        verifier: &TestScheme,
        epoch: Epoch,
        view: View,
    ) -> Nullification<TestScheme> {
        let round = Round::new(epoch, view);
        let votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Nullify::sign::<Sha256Digest>(scheme, round).unwrap())
            .collect();
        Nullification::from_nullifies(verifier, &votes, &Sequential).expect("nullification quorum")
    }

    pub(super) fn build_notarization(
        schemes: &[TestScheme],
        verifier: &TestScheme,
        epoch: Epoch,
        view: View,
    ) -> Notarization<TestScheme, Sha256Digest> {
        let proposal = Proposal::new(
            Round::new(epoch, view),
            view.previous().unwrap_or(View::zero()),
            Sha256Digest::from([view.get() as u8; 32]),
        );
        let votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        Notarization::from_notarizes(verifier, &votes, &Sequential).expect("notarization quorum")
    }

    pub(super) fn build_finalization(
        schemes: &[TestScheme],
        verifier: &TestScheme,
        epoch: Epoch,
        view: View,
    ) -> Finalization<TestScheme, Sha256Digest> {
        let proposal = Proposal::new(
            Round::new(epoch, view),
            view.previous().unwrap_or(View::zero()),
            Sha256Digest::from([view.get() as u8; 32]),
        );
        let votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        Finalization::from_finalizes(verifier, &votes, &Sequential).expect("finalization quorum")
    }
}
