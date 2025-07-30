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
        threshold_simplex::types::{
            finalize_namespace, notarize_namespace, Activity, Finalization, Notarization, Proposal,
        },
        Block as _, Reporter,
    };
    use commonware_broadcast::buffered;
    use commonware_codec::Encode;
    use commonware_cryptography::{
        bls12381::{
            dkg::ops::generate_shares,
            primitives::{
                group::Share,
                ops::{partial_sign_message, threshold_signature_recover},
                poly,
                variant::{MinPk, Variant},
            },
        },
        ed25519::{PrivateKey, PublicKey},
        sha256::{self, Digest as Sha256Digest},
        Digestible, PrivateKeyExt as _, Signer as _,
    };
    use commonware_p2p::simulated::{self, Link, Network, Oracle};
    use commonware_resolver::p2p as resolver;
    use commonware_runtime::{deterministic, Clock, Metrics, Runner};
    use governor::Quota;
    use std::{collections::BTreeMap, num::NonZeroU32, time::Duration};

    type D = Sha256Digest;
    type B = Block<D>;
    type P = PublicKey;
    type V = MinPk;
    type Sh = Share;
    type E = PrivateKey;

    const NAMESPACE: &[u8] = b"test";
    const NETWORK_SPEED: Duration = Duration::from_millis(100);
    const SUCCESS_RATE: f64 = 1.0;
    const JITTER: f64 = NETWORK_SPEED.as_millis() as f64 / 2.0;
    const NUM_VALIDATORS: u32 = 4;
    const QUORUM: u32 = 3;
    const NUM_BLOCKS: u64 = 100;

    #[test]
    fn basic_finalization() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            // Initialize network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                simulated::Config {
                    max_size: 1024 * 1024,
                },
            );
            network.start();

            // Generate private keys and sort them by public key.
            let mut schemes = (0..NUM_VALIDATORS)
                .map(|i| PrivateKey::from_seed(i as u64))
                .collect::<Vec<_>>();
            schemes.sort_by_key(|s| s.public_key());
            let peers: Vec<PublicKey> = schemes.iter().map(|s| s.public_key()).collect();

            // Generate shares
            let (identity, shares) =
                generate_shares::<_, V>(&mut context, None, NUM_VALIDATORS, QUORUM);
            let identity = *poly::public::<V>(&identity);

            // Initialize validators
            let mut pks = Vec::new();
            let mut secrets = Vec::new();
            for scheme in schemes.iter() {
                pks.push(scheme.public_key());
                secrets.push(scheme);
            }

            // Initialize applications and actors
            let mut applications = BTreeMap::new();
            let mut actors = Vec::new();
            let coordinator = resolver::mocks::Coordinator::new(pks.clone());

            for i in 0..NUM_VALIDATORS as usize {
                let (application, actor) = setup_validator(
                    context.with_label(&format!("validator-{i}")),
                    &mut oracle,
                    coordinator.clone(),
                    secrets[i].clone(),
                    identity,
                )
                .await;
                applications.insert(pks[i].clone(), application);
                actors.push(actor);
            }

            // Add links between all peers
            let link = Link {
                latency: NETWORK_SPEED.as_millis() as f64,
                jitter: JITTER,
                success_rate: SUCCESS_RATE,
            };
            for p1 in peers.iter() {
                for p2 in peers.iter() {
                    if p2 == p1 {
                        continue;
                    }
                    oracle
                        .add_link(p1.clone(), p2.clone(), link.clone())
                        .await
                        .unwrap();
                }
            }

            // Generate blocks, skipping the genesis block.
            let mut blocks = Vec::<B>::new();
            let mut parent = sha256::hash(b"");
            for i in 1..=NUM_BLOCKS {
                let block = B::new::<sha256::Sha256>(parent, i, i);
                parent = block.digest();
                blocks.push(block);
            }

            // Broadcast and finalize blocks // TODO: make the order random
            for block in blocks.iter() {
                // Skip genesis block
                let height = block.height();
                assert!(height > 0, "genesis block should not have been generated");

                // Broadcast block by one validator
                let actor_index: usize = (height % (NUM_VALIDATORS as u64)) as usize;
                let mut actor = actors[actor_index].clone();
                actor.broadcast(block.clone()).await;
                actor.verified(height, block.clone()).await;

                // Wait for the block to be broadcast, but due to jitter, we may or may not receive
                // the block before continuing.
                context.sleep(NETWORK_SPEED).await;

                // Notarize block by the validator that broadcasted it
                let proposal = Proposal {
                    view: height,
                    parent: height.checked_sub(1).unwrap(),
                    payload: block.digest(),
                };
                let notarization = make_notarization(proposal.clone(), &shares, QUORUM);
                actor
                    .report(Activity::Notarization(notarization.clone()))
                    .await;

                // Finalize block by all validators
                let fin = make_finalization(proposal, &shares, QUORUM);
                for actor in actors.iter_mut() {
                    actor.report(Activity::Finalization(fin.clone())).await;
                }
            }

            // Wait for things to complete
            context.sleep(Duration::from_secs(5)).await;

            // Check that all applications received all blocks.
            assert_eq!(applications.len(), NUM_VALIDATORS as usize);
            for (i, app) in applications {
                assert!(
                    app.blocks().len() == NUM_BLOCKS as usize,
                    "validator {i} has {:?} blocks",
                    app.blocks().keys().collect::<Vec<_>>(),
                );
            }
        });
    }

    async fn setup_validator(
        context: deterministic::Context,
        oracle: &mut Oracle<P>,
        coordinator: resolver::mocks::Coordinator<P>,
        secret: E,
        identity: <V as Variant>::Public,
    ) -> (
        Application<B>,
        crate::marshal::ingress::mailbox::Mailbox<V, B>,
    ) {
        let config = Config {
            public_key: secret.public_key(),
            identity,
            coordinator,
            mailbox_size: 100,
            backfill_quota: Quota::per_second(NonZeroU32::new(1).unwrap()),
            namespace: NAMESPACE.to_vec(),
            view_retention_timeout: 10,
            max_repair: 10,
            codec_config: (),
            partition_prefix: format!("validator-{}", secret.public_key()),
            prunable_items_per_section: 10u64,
            replay_buffer: 1024,
            write_buffer: 1024,
            freezer_table_initial_size: 64,
            freezer_table_resize_frequency: 10,
            freezer_table_resize_chunk_size: 10,
            freezer_journal_target_size: 1024,
            freezer_journal_compression: None,
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

        // Start the actor
        let backfill_by_digest = oracle.register(secret.public_key(), 2).await.unwrap();
        let backfill_by_height = oracle.register(secret.public_key(), 3).await.unwrap();
        let backfill_by_view = oracle.register(secret.public_key(), 4).await.unwrap();
        actor.start(
            application.clone(),
            buffer,
            backfill_by_digest,
            backfill_by_height,
            backfill_by_view,
        );

        (application, mailbox)
    }

    fn make_finalization(proposal: Proposal<D>, shares: &[Sh], quorum: u32) -> Finalization<V, D> {
        let proposal_msg = proposal.encode();
        let partials: Vec<_> = shares
            .iter()
            .take(quorum as usize)
            .map(|s| {
                partial_sign_message::<V>(s, Some(&finalize_namespace(NAMESPACE)), &proposal_msg)
            })
            .collect();
        let signature = threshold_signature_recover::<V, _>(quorum, &partials).unwrap();
        Finalization {
            proposal,
            proposal_signature: signature,
            seed_signature: signature,
        }
    }

    fn make_notarization(proposal: Proposal<D>, shares: &[Sh], quorum: u32) -> Notarization<V, D> {
        let proposal_msg = proposal.encode();
        let partials: Vec<_> = shares
            .iter()
            .take(quorum as usize)
            .map(|s| {
                partial_sign_message::<V>(s, Some(&notarize_namespace(NAMESPACE)), &proposal_msg)
            })
            .collect();
        let signature = threshold_signature_recover::<V, _>(quorum, &partials).unwrap();
        Notarization {
            proposal,
            proposal_signature: signature,
            seed_signature: signature,
        }
    }
}
