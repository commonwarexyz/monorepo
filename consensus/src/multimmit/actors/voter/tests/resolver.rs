//! Resolver serving: the voter hands its durable artifacts to the resolver, which serves them
//! to peers by retrieval key.

use super::harness::{Attachments, Network};
use crate::multimmit::{machine::RetrievalKey, mocks::cluster::DATA_CHANNEL, types::Artifact};
use commonware_cryptography::{Hasher as _, Sha256};
use commonware_macros::test_traced;
use commonware_runtime::{Runner as _, deterministic::Runner};
use std::time::Duration;

#[test_traced]
fn the_resolver_serves_a_published_own_header_by_digest() {
    Runner::timed(Duration::from_secs(30)).start(|context| async move {
        let network = Network::new(&context, 41).await;
        let (_, mut data) = network.peer(1, DATA_CHANNEL).await;
        let attachments = Attachments::paused();
        let node = network.start(&context, "node", &attachments).await;
        attachments.application.permit_builds(1);
        let block = network.next_block(&context, &mut data).await;
        let header = block.header();

        let served = node
            .artifacts
            .serve(RetrievalKey::Header {
                chain: header.chain(),
                digest: header.digest::<Sha256>(),
            })
            .await
            .expect("the resolver answers");
        assert!(matches!(
            served.as_deref(),
            Some(Artifact::TransactionBlock(served)) if *served == block
        ));
        let unknown = node
            .artifacts
            .serve(RetrievalKey::Header {
                chain: header.chain(),
                digest: Sha256::hash(&[b"unknown".as_slice()]),
            })
            .await
            .expect("the resolver answers");
        assert!(unknown.is_none());
    });
}
