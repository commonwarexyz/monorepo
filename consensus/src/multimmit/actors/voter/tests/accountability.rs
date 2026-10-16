//! Accountability: an equivocation the machine proves blocks the faulty participant's peer.

use super::harness::{Attachments, Network};
use crate::{
    Epochable as _,
    multimmit::{
        machine::testing::fixtures::block,
        mocks::cluster::DATA_CHANNEL,
        types::ChainId,
        wire::{DataMessage, Envelope},
    },
};
use commonware_codec::Encode as _;
use commonware_cryptography::{bls12381::primitives::variant::MinPk, sha256::Digest};
use commonware_macros::test_traced;
use commonware_p2p::{Recipients, Sender as _};
use commonware_runtime::{Clock as _, Metrics as _, Runner as _, deterministic::Runner};
use std::time::Duration;

#[test_traced]
fn two_headers_at_one_height_block_their_producer() {
    Runner::timed(Duration::from_secs(30)).start(|context| async move {
        let network = Network::new(&context, 51).await;
        let committee = &network.committee;
        let (mut data, _) = network.peer(1, DATA_CHANNEL).await;
        let attachments = Attachments::paused();
        let _node = network.start(&context, "node", &attachments).await;

        let chain = ChainId::new(1);
        let producer = committee
            .config
            .producer(chain)
            .expect("chain 1 has a producer");
        let genesis = committee.genesis().tips()[chain.index()];
        for label in [b"first".as_slice(), b"second".as_slice()] {
            let header = block(committee, &genesis, label);
            let frame = Envelope::new(
                committee.config.epoch(),
                DataMessage::<MinPk, Digest>::Block(header),
            )
            .encode();
            data.send(
                Recipients::One(committee.identities[0].clone()),
                frame,
                false,
            );
        }

        let faulty = committee.identities[usize::from(producer)].clone();
        let deadline = context.current() + Duration::from_secs(5);
        while !attachments.blocker.blocked().contains(&faulty) {
            assert!(
                context.current() < deadline,
                "the producer was never blocked"
            );
            context.sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(attachments.blocker.blocked(), vec![faulty]);
        assert!(
            context
                .encode()
                .lines()
                .any(|line| line.ends_with("_blocked_total 1")),
            "the equivocation counter records the block"
        );
    });
}
