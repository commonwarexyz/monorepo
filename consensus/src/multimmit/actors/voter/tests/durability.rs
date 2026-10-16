//! Durability before exposure: the voter signs and publishes nothing its journal has not
//! acknowledged, and a restarted voter resumes its durable publications without re-signing.

use super::harness::{Attachments, Hooks, Network};
use crate::multimmit::{actors::voter::persistence::TestGates, mocks::cluster::DATA_CHANNEL};
use commonware_cryptography::Sha256;
use commonware_macros::test_traced;
use commonware_runtime::{Runner as _, deterministic::Runner};
use std::time::Duration;

#[test_traced]
fn a_staged_header_is_withheld_until_its_barrier_is_durable() {
    Runner::timed(Duration::from_secs(30)).start(|context| async move {
        let network = Network::new(&context, 21).await;
        let (_, mut data) = network.peer(1, DATA_CHANNEL).await;
        let gates = TestGates::default();
        let attachments = Attachments {
            hooks: Hooks::default().with_gates(gates.clone()),
            ..Attachments::paused()
        };
        let node = network.start(&context, "node", &attachments).await;

        // Hold the journal after its next sync: no barrier staged from here on is acknowledged.
        let mut held = gates.arm_next_after_sync();
        attachments.application.permit_builds(1);
        held.wait_entered().await;
        node.wait_until(&context, Duration::from_secs(5), |inspection| {
            inspection
                .producer()
                .is_some_and(|producer| producer.produced().get() == 1)
        })
        .await;
        Network::silent(&context, &mut data, Duration::from_secs(1)).await;
        assert!(attachments.relay.broadcasts().is_empty());
        assert!(
            attachments.hooks.events().is_empty(),
            "a publication was installed"
        );

        held.release();
        let block = network.next_block(&context, &mut data).await;
        assert_eq!(block.header().height().get(), 1);
    });
}

#[test_traced]
fn a_restarted_voter_resumes_its_header_publication_without_resigning_the_height() {
    Runner::timed(Duration::from_secs(60)).start(|context| async move {
        let network = Network::new(&context, 22).await;
        let (_, mut data) = network.peer(1, DATA_CHANNEL).await;
        let attachments = Attachments::paused();
        let node = network.start(&context, "first", &attachments).await;
        attachments.application.permit_builds(1);
        let first = network.next_block(&context, &mut data).await;
        node.crash(&context).await;

        // The peer never endorsed the header, so its publication is still owed after restart:
        // the recovered voter sends the identical signed header again and builds the next
        // height above it.
        attachments.application.permit_builds(1);
        let node = network.start(&context, "second", &attachments).await;
        assert_eq!(network.next_block(&context, &mut data).await, first);
        let second = loop {
            let block = network.next_block(&context, &mut data).await;
            if block.header().height().get() == 2 {
                break block;
            }
            assert_eq!(block, first, "a recovered voter re-signed a durable height");
        };
        assert_eq!(second.header().parent(), first.header().digest::<Sha256>());
        assert_eq!(attachments.application.log().lock().built, 2);
        let producer = node
            .inspect()
            .await
            .producer()
            .expect("a validator produces");
        assert_eq!(producer.produced().get(), 2);
    });
}
