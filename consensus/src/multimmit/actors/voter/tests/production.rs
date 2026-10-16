//! Local production: the application builds a payload, custodies it, and only then does the
//! voter sign, relay, and broadcast the header.

use super::harness::{Attachments, Network};
use crate::multimmit::{
    mocks::cluster::DATA_CHANNEL,
    types::{Activity, ChainId, TransactionBlockHeader},
};
use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinPk, sha256::Digest};
use commonware_macros::test_traced;
use commonware_runtime::{Clock as _, Runner as _, deterministic::Runner};
use std::time::Duration;

#[test_traced]
fn a_header_is_signed_only_after_its_payload_is_custodied() {
    Runner::timed(Duration::from_secs(30)).start(|context| async move {
        let network = Network::new(&context, 11).await;
        let (_, mut data) = network.peer(1, DATA_CHANNEL).await;
        let attachments = Attachments::paused();
        let node = network.start(&context, "node", &attachments).await;
        let mut custody = attachments.application.gate_verification();
        attachments.application.permit_builds(1);

        // The build completed and its custody check is pending: nothing is signed or sent.
        custody.wait_started().await;
        Network::silent(&context, &mut data, Duration::from_millis(500)).await;
        assert!(attachments.relay.broadcasts().is_empty());
        let producer = node
            .inspect()
            .await
            .producer()
            .expect("a validator produces");
        assert!(producer.custody_pending());
        assert_eq!(producer.produced().get(), 0);

        custody.release();
        let block = network.next_block(&context, &mut data).await;
        let header = block.header().clone();
        let (built, payload) = attachments.application.log().lock().builds[0];
        assert_eq!(header, TransactionBlockHeader::from_context(built, payload));
        assert_eq!(header.chain(), ChainId::new(0));
        assert_eq!(header.height().get(), 1);
        assert_eq!(header.parent_ref(), network.committee.genesis().tips()[0]);
        assert_eq!(block, network.committee.sign_header(header.clone()));

        let digest = header.digest::<Sha256>();
        assert_eq!(
            attachments
                .relay
                .broadcasts()
                .into_iter()
                .map(|(relayed, _)| relayed)
                .collect::<Vec<Digest>>(),
            vec![digest]
        );
        assert!(
            attachments
                .reporter
                .activities()
                .iter()
                .any(|activity| matches!(
                    activity,
                    Activity::<MinPk, Digest>::TransactionProposed { block, .. }
                        if *block == header.block_ref::<Sha256>()
                ))
        );
        let producer = node
            .inspect()
            .await
            .producer()
            .expect("a validator produces");
        assert_eq!(producer.produced().get(), 1);
        assert!(!producer.custody_pending());
    });
}

#[test_traced]
fn production_runs_ahead_to_the_flow_bound_and_stops() {
    Runner::timed(Duration::from_secs(30)).start(|context| async move {
        let network = Network::new(&context, 12).await;
        let (_, mut data) = network.peer(1, DATA_CHANNEL).await;
        let attachments = Attachments::default();
        let node = network.start(&context, "node", &attachments).await;

        // Alone, the node endorses and finalizes nothing, so it produces exactly the flow bound
        // above genesis and stops. Unendorsed headers are retransmitted, so only first arrivals
        // count.
        let flow = u64::from(network.committee.config.window().flow());
        let mut arrived = 0;
        while arrived < flow {
            let block = network.next_block(&context, &mut data).await;
            let height = block.header().height().get();
            if height > arrived {
                assert_eq!(height, arrived + 1, "heights are produced in order");
                arrived = height;
            }
        }
        context.sleep(Duration::from_secs(1)).await;
        let producer = node
            .inspect()
            .await
            .producer()
            .expect("a validator produces");
        assert_eq!(producer.produced().get(), flow);
        assert_eq!(attachments.application.log().lock().built, flow);
    });
}
