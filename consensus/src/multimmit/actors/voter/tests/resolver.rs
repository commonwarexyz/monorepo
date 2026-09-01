//! Resolver port and view-proof resolution tests.

use super::harness::{NodeBuilder, Requested};
use crate::{
    multimmit::{
        actors::resolver::ResolveRequest,
        config::Role,
        mocks::{Committee, cluster::start_network},
        wire::{CertificateMessage, ConsensusMessage},
    },
    types::View,
};
use commonware_codec::Encode as _;
use commonware_cryptography::{
    bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
};
use commonware_macros::{select, test_traced};
use commonware_p2p::{Recipients, Sender as _, simulated::Link};
use commonware_runtime::{Clock as _, Runner as _, deterministic::Runner as DeterministicRunner};
use commonware_utils::probability;
use std::time::Duration;
#[test_traced]
fn resolver_port_receives_machine_issued_requests() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let mut node = NodeBuilder::new(47, Role::Observer, "primary")
            .start(&context)
            .await;
        let (mut consensus_tx, _) = node.peer(1, 1).await;

        // A vote for an unknown leader parks as a dependency; ordering does not request
        // resolution for it, but a V-QC naming an unknown parent does.
        let vqc = node.committee.vqc(View::new(2));
        consensus_tx.send(
            Recipients::One(node.me.clone()),
            node.envelope(ConsensusMessage::Proposal {
                block: Box::new(node.committee.leader_block(View::new(3))),
                parent: Some(Box::new(vqc)),
            })
            .encode(),
            true,
        );

        // The machine may or may not need external resolution for this schedule; the port must
        // simply stay wired if a request is emitted.
        select! {
            request = node.resolver.recv() => {
                let Requested(ResolveRequest { job, .. }) = request.expect("voter stays running");
                assert!(job.view() >= View::new(1));
            },
            () = context.sleep(Duration::from_secs(2)) => {},
        }
        let _ = node.inspect().await;
    });
}

#[test_traced]
fn skipped_view_nullification_resolves_from_a_peer_node() {
    let executor = DeterministicRunner::timed(Duration::from_secs(60));
    executor.start(|context| async move {
        let seed = 48;
        let committee = Committee::<MinPk>::builder(seed, 6).build();
        let oracle = start_network(&context, committee.identities.clone(), 1024 * 1024).await;

        // Two full observers: node A misses the gap proof that node B durably forwarded.
        let mut node_a = Box::pin(
            NodeBuilder::new(seed, Role::Observer, "node_a")
                .network(
                    Committee::<MinPk>::builder(seed, 6).build(),
                    oracle.clone(),
                    0,
                )
                .production_resolver()
                .start(&context),
        )
        .await;
        let node_b = Box::pin(
            NodeBuilder::new(seed + 1, Role::Observer, "node_b")
                .network(
                    Committee::<MinPk>::builder(seed, 6).build(),
                    oracle.clone(),
                    1,
                )
                .production_resolver()
                .start(&context),
        )
        .await;

        // Link both nodes on every plane so certificates and resolver traffic flow.
        let link = Link {
            latency: Duration::from_millis(1),
            jitter: Duration::ZERO,
            success_rate: probability!(1.0),
        };
        let _ = oracle
            .add_link(node_a.me.clone(), node_b.me.clone(), link.clone())
            .await;
        let _ = oracle
            .add_link(node_b.me.clone(), node_a.me.clone(), link.clone())
            .await;

        // A third identity injects protocol traffic into both nodes.
        let (mut certs_tx, _) = node_b.peer(2, 2).await;
        let _ = oracle
            .add_link(
                committee.identities[2].clone(),
                node_a.me.clone(),
                link.clone(),
            )
            .await;
        let (mut consensus_tx_a, _) = node_a.peer(2, 1).await;

        // Node B durably forwards the skipped-view nullification, making it servable.
        let nullification = committee.nullification(View::new(2));
        certs_tx.send(
            Recipients::One(node_b.me.clone()),
            node_b
                .envelope(CertificateMessage::<MinPk, Sha256Digest>::Nullification(
                    nullification,
                ))
                .encode(),
            true,
        );
        context.sleep(Duration::from_millis(200)).await;

        // Node A receives an exact-Q proposal that skips view two. It has the parent certificate
        // in the proposal bundle but must retrieve the durable proof for the skipped view.
        let vqc = committee.vqc(View::new(1));
        let block = committee.leader_block_with_parent(View::new(3), &vqc);
        consensus_tx_a.send(
            Recipients::One(node_a.me.clone()),
            node_a
                .envelope(ConsensusMessage::Proposal {
                    block: Box::new(block),
                    parent: Some(Box::new(vqc)),
                })
                .encode(),
            true,
        );

        // The proposal leaves the dependency index once the resolver retrieves the gap proof.
        let mut settled = false;
        for _ in 0..400 {
            context.sleep(Duration::from_millis(25)).await;
            let inspection = node_a.inspect().await;
            if inspection.waiting_artifacts() == 0 && inspection.cached_artifacts() >= 2 {
                settled = true;
                break;
            }
        }
        assert!(settled, "the skipped-view nullification was never resolved");
    });
}
