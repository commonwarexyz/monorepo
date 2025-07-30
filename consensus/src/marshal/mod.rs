pub mod actor;
pub mod config;
pub mod finalizer;
pub mod ingress;
pub mod mocks;

#[cfg(test)]
mod tests {
    use super::{
        actor,
        config::Config,
        mocks::{application::Application, block::Block},
    };
    use crate::{
        threshold_simplex::types::{Finalization, Proposal},
        Reporter,
    };
    use commonware_broadcast::buffered;
    use commonware_codec::Encode;
    use commonware_cryptography::{
        bls12381::{
            dkg::ops::generate_shares,
            primitives::{
                group::Share,
                ops, poly,
                variant::{MinPk, Variant},
            },
        },
        ed25519::{PrivateKey, PublicKey},
        sha256::{self, Digest as Sha256Digest},
        Digestible, PrivateKeyExt as _, Signer as _,
    };
    use commonware_p2p::simulated::{self, Network, Oracle};
    use commonware_resolver::p2p::{
        self as resolver,
        mocks::{Consumer, Producer},
    };
    use commonware_runtime::{deterministic, Clock, Metrics, Runner};
    use futures::channel::mpsc;
    use governor::Quota;
    use std::{collections::BTreeMap, num::NonZeroU32, time::Duration};

    type D = Sha256Digest;
    type B = Block<D>;
    type P = PublicKey;
    type V = MinPk;
    type S = <MinPk as Variant>::Signature;
    type Sh = Share;
    type E = PrivateKey;

    #[test]
    fn basic_finalization() {
        const NUM_VALIDATORS: u32 = 4;
        const QUORUM: u32 = 3;
        const NUM_BLOCKS: u64 = 10;

        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(move |context| async move {
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                simulated::Config {
                    max_size: 1024 * 1024,
                },
            );
            network.start();
            let (poly, shares) =
                generate_shares::<_, V>(&mut context, None, NUM_VALIDATORS, QUORUM);

            let mut pks = Vec::new();
            let mut secrets = Vec::new();
            for i in 0..NUM_VALIDATORS {
                let secret = PrivateKey::from_seed(i as u64);
                pks.push(secret.public_key());
                secrets.push(secret);
            }

            let mut applications = BTreeMap::new();
            let mut actors = Vec::new();
            let coordinator = resolver::mocks::Coordinator::new(pks.clone());

            for i in 0..NUM_VALIDATORS as usize {
                let (application, actor) = setup_validator(
                    context.with_label(&format!("validator-{}", i)),
                    &mut oracle,
                    coordinator.clone(),
                    secrets[i].clone(),
                    poly.clone(),
                    shares[i].clone(),
                )
                .await;
                applications.insert(pks[i].clone(), application);
                actors.push(actor);
            }

            let mut blocks = Vec::new();
            let mut parent = sha256::hash(b"");
            for i in 0..NUM_BLOCKS {
                let block = B::new::<sha256::Digest>(parent, i, i);
                parent = block.digest();
                blocks.push(block);
            }

            for (i, block) in blocks.iter().enumerate() {
                let proposal = Proposal {
                    view: i as u64,
                    parent: sha256::hash(b""),
                    payload: block.digest(),
                };
                let finalization = make_finalization(proposal, &poly, &shares, QUORUM);
                let mut actor = actors[i % NUM_VALIDATORS as usize].clone();
                actor
                    .report(crate::threshold_simplex::types::Activity::Finalization(
                        finalization,
                    ))
                    .await;
                context.sleep(Duration::from_millis(100)).await;
            }

            context.sleep(Duration::from_secs(5)).await;

            for (_, app) in applications {
                assert_eq!(app.blocks().len(), NUM_BLOCKS as usize);
            }
        });
    }

    async fn setup_validator(
        context: deterministic::Context,
        oracle: &mut Oracle<P>,
        coordinator: resolver::mocks::Coordinator<P>,
        secret: E,
        poly: poly::Public<V>,
        share: Sh,
    ) -> (
        Application<B>,
        crate::marshal::ingress::mailbox::Mailbox<V, B>,
    ) {
        let (backfill_by_digest_tx, backfill_by_digest_rx) = mpsc::channel(100);
        let (backfill_by_height_tx, backfill_by_height_rx) = mpsc::channel(100);
        let (backfill_by_view_tx, backfill_by_view_rx) = mpsc::channel(100);

        let (resolver_engine, resolver) = resolver::Engine::new(
            context.clone(),
            resolver::Config {
                coordinator,
                consumer: Consumer::new().0,
                producer: Producer::default(),
                mailbox_size: 100,
                requester_config: commonware_p2p::utils::requester::Config {
                    public_key: secret.public_key(),
                    rate_limit: Quota::per_second(NonZeroU32::new(10).unwrap()),
                    initial: Duration::from_millis(100),
                    timeout: Duration::from_millis(400),
                },
                fetch_retry_timeout: Duration::from_millis(100),
                priority_requests: false,
                priority_responses: false,
            },
        );
        let network = oracle.register(secret.public_key(), 0).await.unwrap();
        resolver_engine.start(network);

        let config = Config {
            public_key: secret.public_key(),
            identity: share.public::<V>(),
            coordinator,
            mailbox_size: 100,
            backfill_quota: Quota::per_second(NonZeroU32::new(1).unwrap()),
            namespace: b"test".to_vec(),
            view_retention_timeout: 10,
            max_repair: 10,
            codec_config: (),
            partition_prefix: format!("validator-{}", secret.public_key()),
            prunable_items_per_section: 10u64,
            replay_buffer: 1024,
            write_buffer: 1024,
            finalized_freezer_table_initial_size: 10,
            freezer_table_resize_frequency: 10,
            freezer_table_resize_chunk_size: 10,
            freezer_journal_target_size: 1024,
            freezer_journal_compression: None,
            blocks_freezer_table_initial_size: 10,
            immutable_items_per_section: 10u64,
        };

        let (actor, mailbox) = actor::Actor::init(context.clone(), config).await;
        let application = Application::<B>::default();

        // Create a buffered broadcast engine and get its mailbox
        let broadcast_config = buffered::Config {
            public_key: secret.public_key(),
            mailbox_size: 100,
            deque_size: 10,
            priority: false,
            codec_config: (),
        };
        let (broadcast_engine, buffer) = buffered::Engine::new(context.clone(), broadcast_config);
        let network = oracle.register(secret.public_key(), 1).await.unwrap();
        broadcast_engine.start(network);
        actor.start(
            application.clone(),
            buffer,
            (backfill_by_digest_tx, backfill_by_digest_rx),
            (backfill_by_height_tx, backfill_by_height_rx),
            (backfill_by_view_tx, backfill_by_view_rx),
        );

        (application, mailbox)
    }

    fn make_finalization(
        proposal: Proposal<D>,
        poly: &poly::Public<V>,
        shares: &[Sh],
        quorum: u32,
    ) -> Finalization<V, D> {
        let msg = proposal.encode();
        let sig_evals: Vec<_> = shares
            .iter()
            .take(quorum as usize)
            .map(|share| {
                let sig_share = ops::partial_sign_message(share, Some(b"test"), &msg);
                poly::Eval {
                    index: share.index,
                    value: sig_share,
                }
            })
            .collect();
        let signature = S::recover(quorum, &sig_evals).unwrap();
        Finalization {
            proposal,
            proposal_signature: signature,
            seed_signature: signature,
        }
    }
}
