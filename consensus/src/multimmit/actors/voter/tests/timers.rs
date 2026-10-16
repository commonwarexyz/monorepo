//! View timers: without a proposal, the grace period ends the view's wait for its leader.

use super::harness::{Attachments, Network, tuning};
use crate::{
    multimmit::{mocks::cluster::CONSENSUS_CHANNEL, wire::ConsensusMessage},
    types::View,
};
use commonware_cryptography::{bls12381::primitives::variant::MinPk, sha256::Digest};
use commonware_macros::test_traced;
use commonware_runtime::{Clock as _, Runner as _, deterministic::Runner};
use std::time::Duration;

#[test_traced]
fn a_view_without_a_proposal_ends_in_a_leaderless_final_after_the_grace_period() {
    Runner::timed(Duration::from_secs(30)).start(|context| async move {
        let network = Network::new(&context, 51).await;
        let (_, mut consensus) = network.peer(1, CONSENSUS_CHANNEL).await;
        let attachments = Attachments::paused();
        let _node = network.start(&context, "node", &attachments).await;
        let started = context.current();

        let final_update = network
            .receive(
                &context,
                &mut consensus,
                Duration::from_secs(5),
                |message: ConsensusMessage<MinPk, Digest>| match message {
                    ConsensusMessage::Update(update) if update.is_final() => Some(update),
                    ConsensusMessage::Update(update) => {
                        assert!(update.leader().is_none(), "no leader block exists");
                        None
                    }
                    ConsensusMessage::Proposal { .. } => panic!("the node is not view 1's leader"),
                },
            )
            .await;
        let waited = context.current().duration_since(started).unwrap();
        assert_eq!(final_update.round().view(), View::new(1));
        assert!(final_update.leader().is_none());
        // With no proposal, the final waits out the base grace period, two and a half initial
        // delay estimates, and then declares every chain.
        let grace = tuning().delta_initial * 5 / 2;
        assert!(waited >= grace, "the final was sent after {waited:?}");
        assert_eq!(
            final_update.declared().len(),
            network.committee.codec().chains()
        );
    });
}
