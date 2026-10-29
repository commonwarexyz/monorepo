//! Forwarding of unplaced certified-only chain certificates over the simulated network.

use super::harness::{Node, NodeBuilder, da_certificate};
use crate::{
    Epochable as _,
    multimmit::{
        config::Role,
        mocks::{Committee, cluster::start_network},
        types::{ChainId, PathLimits, TransactionBlockHeader},
        wire::{CertificateMessage, DataMessage, Envelope},
    },
    types::{Height, Participant, View},
};
use commonware_codec::{Decode as _, Encode as _};
use commonware_cryptography::{
    Hasher as _, Sha256, bls12381::primitives::variant::MinPk, ed25519::PublicKey,
    sha256::Digest as Sha256Digest,
};
use commonware_macros::{select, test_traced};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{
    Clock as _, Metrics as _, Runner as _,
    deterministic::{Context as DeterministicContext, Runner as DeterministicRunner},
    telemetry::metrics::metric_sum,
};
use std::time::Duration;

/// Sends the nullification of `view` to `node` and waits until it enters the next view.
async fn exit_view(
    context: &DeterministicContext,
    node: &mut Node,
    certificates: &mut impl Sender<PublicKey = PublicKey>,
    view: u64,
) {
    certificates.send(
        Recipients::One(node.me.clone()),
        node.envelope(CertificateMessage::<MinPk, Sha256Digest>::Nullification(
            node.committee.nullification(View::new(view)),
        ))
        .encode(),
        true,
    );
    while node.inspect().await.view() <= View::new(view) {
        context.sleep(Duration::from_millis(1)).await;
    }
}

/// Returns how many data-plane messages `receiver` takes from `sender` within `window` that
/// carry a DA certificate for `header`.
async fn certificates_received(
    context: &DeterministicContext,
    node: &Node,
    receiver: &mut impl Receiver<PublicKey = PublicKey>,
    header: &TransactionBlockHeader<Sha256Digest>,
    window: Duration,
) -> usize {
    let deadline = context.current() + window;
    let mut received = 0;
    loop {
        select! {
            result = receiver.recv() => {
                let (sender, bytes) = result.expect("network stays up");
                let envelope = Envelope::<DataMessage<MinPk, Sha256Digest>>::decode_cfg(
                    bytes,
                    &node.envelope_cfg(node.committee.codec()),
                )
                .expect("canonical data envelope");
                if let DataMessage::DaCertificate(certificate) = envelope.into_payload()
                    && certificate.header() == header
                {
                    assert_eq!(sender, node.me);
                    received += 1;
                }
            },
            () = context.sleep_until(deadline) => return received,
        }
    }
}

#[test_traced]
fn view_entry_forwards_an_unplaced_certificate_to_the_next_leader_on_the_wire() {
    DeterministicRunner::timed(Duration::from_secs(60)).start(|context| async move {
        // Chain 1 is certified-only. Validator 0 neither produces it nor leads views 1 to 4.
        let chain = ChainId::new(1);
        let mut limits = vec![PathLimits::new(2, 1); 6];
        limits[chain.get() as usize] = PathLimits::new(0, 0);
        let committee = Committee::<MinPk>::builder(96, 6)
            .chain_limits(limits)
            .build();
        let oracle = start_network(&context, committee.identities.clone(), 1024 * 1024).await;
        let mut node = NodeBuilder::new(96, Role::Validator(Participant::new(0)), "forwarder")
            .network(committee, oracle, 0)
            .start(&context)
            .await;
        let config = node.committee.config.clone();
        let leader = config.leader(View::new(4));
        assert_ne!(leader, Participant::new(0));
        let (mut data, _) = node.peer(1, 0).await;
        let (mut certificates, _) = node.peer(1, 2).await;
        let (_, mut leader_data) = node.peer(leader.get() as usize, 0).await;

        // Hand the node a certificate it did not produce, and wait until it holds it.
        let genesis = config.genesis().tips()[chain.get() as usize];
        let header = TransactionBlockHeader::new(
            config.epoch(),
            chain,
            Height::new(1),
            genesis.digest(),
            Sha256::hash(&[b"forwarded"]),
        )
        .unwrap();
        data.send(
            Recipients::One(node.me.clone()),
            node.envelope(DataMessage::<MinPk, Sha256Digest>::DaCertificate(
                da_certificate(&node.committee, &header),
            ))
            .encode(),
            false,
        );
        while node.inspect().await.chain_progress()[chain.get() as usize].certified()
            < Height::new(1)
        {
            context.sleep(Duration::from_millis(1)).await;
        }

        // Entering view 2 records the unplaced certificate; entering view 3, where validator 0
        // is among the rotating forwarders, sends it once, point to point, to the leader of
        // view 4.
        let forwarded = |context: &DeterministicContext| {
            metric_sum(
                &context.encode(),
                "forwarder_voter_forwarded_da_certificates_total",
                &[],
            )
        };
        exit_view(&context, &mut node, &mut certificates, 1).await;
        exit_view(&context, &mut node, &mut certificates, 2).await;
        assert_eq!(
            certificates_received(
                &context,
                &node,
                &mut leader_data,
                &header,
                Duration::from_secs(2)
            )
            .await,
            1
        );
        assert_eq!(forwarded(&context), 1.0);

        // Validator 0 next forwards on entering view 8, to the leader of view 9, and then on
        // entering view 11, whose next leader is itself, so it sends nothing.
        for view in 3..=10 {
            exit_view(&context, &mut node, &mut certificates, view).await;
        }
        assert_eq!(config.leader(View::new(12)), Participant::new(0));
        context.sleep(Duration::from_millis(100)).await;
        assert_eq!(forwarded(&context), 2.0);
    });
}
