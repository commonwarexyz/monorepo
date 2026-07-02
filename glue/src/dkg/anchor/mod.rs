//! Discover the public epoch material a joining node needs before consensus starts.
//!
//! A node that is starting fresh cannot construct epoch-scoped state until it learns the current
//! epoch's participant set. That set lives in the [`EpochInfo`] of
//! a finalized boundary block. The [`Actor`] discovers that block, publishes the resulting
//! [`Artifact`], and then serves the same boundary block to other joining peers.
//!
//! At startup the node knows only a configured peer set, a constant certificate verifier valid
//! across all epochs, and the epoch length.
//!
//! # Weak Subjectivity
//!
//! The actor has a deliberately weak subjectivity boundary. Before it has read a boundary block it
//! does not know the epoch participant set, so it cannot run the `f + 1` peer-sample protocol used
//! by a stronger scheme such as [`stateful::probe`](crate::stateful::probe). Instead it accepts a
//! finalization it can verify with the all-epoch verifier, then asks peers for the boundary block
//! that finalization implies. A verified finalization remains provisional until the corresponding
//! boundary block is returned; while waiting, a strictly newer verified finalization may replace the
//! pending candidate. While the resulting [`Artifact`] is guaranteed to be a _valid_ finalized
//! block, it is not guaranteed that it is _recent_.
//!
//! Operators treat the configured peers and constant verifier as the weakly subjective checkpoint
//! for startup.
//!
//! # Protocol
//!
//! The actor is a two-state machine: it discovers an [`Artifact`], then serves boundary blocks.
//!
//! ## Discovery
//!
//! Once a subscriber appears, [`Actor`] listens on the simplex certificate channel and accepts a
//! finalization it can verify with the all-epoch verifier:
//!
//! ```text
//!   peer --Finalization--> Actor --verify (all-epoch)--> accepted
//! ```
//!
//! The accepted finalization names a finalized block, but not its contents. The actor asks peers
//! for the boundary block that holds the epoch's [`EpochInfo`]:
//!
//! ```text
//!                +-- Request(epoch) --> peer 1
//!                |
//!   Actor -------+-- Request(epoch) --> peer 2 <-- Response(block + finalization)
//!                |
//!                +-- Request(epoch) --> peer 3
//! ```
//!
//! If the boundary request remains unanswered and the actor verifies a newer finalization, that
//! finalization supersedes the pending candidate. The actor then requests the boundary implied by
//! the newer finalization: the final block of the previous epoch, which carries the newer epoch's
//! [`EpochInfo`]. Older or equal finalizations are ignored while a request is pending, and late
//! responses for superseded candidates are ignored without blocking the peer.
//!
//! ```text
//!   peer --Finalization(epoch = E + 1)--> Actor --verify (all-epoch)--> supersede
//!   Actor --Request(E + 1)--> peers
//! ```
//!
//! The block's [`EpochInfo`] is packaged into an [`Artifact`] and
//! published to subscribers:
//!
//! ```text
//!   finalization + boundary block --> Artifact { epoch, finalization, info }
//! ```
//!
//! ## Serving
//!
//! After a source of finalized blocks is attached, the actor enters service and answers peers'
//! boundary requests for the rest of the process lifetime:
//!
//! ```text
//!   peer --Request(epoch)--> Actor --lookup--> Response(block + finalization) --> peer
//! ```
//!
//! An epoch with no known boundary block is answered with nothing.

use crate::dkg::{types::EpochInfo, ReshareBlock};
use commonware_consensus::{
    marshal::core::Variant as MarshalVariant,
    simplex::{scheme::Scheme, types::Finalization},
    types::Epoch,
};
use commonware_cryptography::{bls12381::primitives::variant::Variant as BlsVariant, Digest};

mod actor;
pub use actor::{Actor, Config};

mod mailbox;
pub use mailbox::Mailbox;

mod wire;

/// Concrete anchor artifact for a marshal variant.
pub(crate) type ActorArtifact<S, V> = Artifact<
    S,
    <V as MarshalVariant>::Commitment,
    <<V as MarshalVariant>::ApplicationBlock as ReshareBlock>::Variant,
>;

/// Public epoch material discovered during bootstrap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Artifact<S, D, V>
where
    S: Scheme<D>,
    D: Digest,
    V: BlsVariant,
{
    /// Epoch described by the boundary block's [`EpochInfo`].
    pub epoch: Epoch,
    /// Finalization of the boundary block that carried the epoch info.
    ///
    /// Epoch zero is anchored by genesis and has no boundary finalization.
    pub finalization: Option<Finalization<S, D>>,
    /// Public epoch information from the finalized boundary block.
    pub info: EpochInfo<V, S::PublicKey>,
}

#[cfg(test)]
mod tests {
    use super::{wire, Actor, Config};
    use crate::dkg::{
        anchor::Artifact,
        tests::mocks,
        types::{EpochInfo, EpochOutcome, Payload},
    };
    use commonware_actor::Feedback;
    use commonware_codec::Encode as _;
    use commonware_consensus::{
        marshal::{self, resolver::p2p as marshal_resolver, Start},
        simplex::types::{Activity, Certificate, Finalization, Finalize, Proposal},
        types::{Epoch, Epocher as _, FixedEpocher, Height, Round, View, ViewDelta},
        Epochable as _, Heightable as _, Reporter as _,
    };
    use commonware_cryptography::{
        bls12381::{
            dkg::feldman_desmedt::deal,
            primitives::sharing::{Mode, Sharing},
        },
        certificate::Verifier as _,
        sha256::Sha256,
        Digest as _, Digestible as _, Hasher as _,
    };
    use commonware_macros::select;
    use commonware_p2p::{
        simulated::{
            Config as NetworkConfig, Link, Network, Oracle, Receiver as SimReceiver,
            Sender as SimSender,
        },
        Receiver as _, Recipients, Sender as _,
    };
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        buffer::paged::CacheRef, deterministic, Clock as _, Handle, Quota, Runner as _,
        Spawner as _, Supervisor as _,
    };
    use commonware_storage::archive::immutable;
    use commonware_utils::{
        channel::{fallible::AsyncFallibleExt as _, mpsc, oneshot},
        ordered::Set,
        test_rng_seeded, N3f1, NZDuration, NZUsize, NZU16, NZU32, NZU64,
    };
    use std::{num::NonZeroU64, time::Duration};

    const BACKFILL_CHANNEL: u64 = 0;
    const CERTIFICATE_CHANNEL: u64 = 1;
    const BOUNDARY_CHANNEL: u64 = 2;
    const TEST_QUOTA: Quota = Quota::per_second(NZU32!(1_000_000));
    const BLOCKS_PER_EPOCH: NonZeroU64 = NZU64!(2);
    const LINK: Link = Link {
        latency: Duration::from_millis(1),
        jitter: Duration::ZERO,
        success_rate: 1.0,
    };

    struct Harness {
        participants: Vec<mocks::TestPublicKey>,
        schemes: Vec<mocks::TestScheme>,
        source_certificate_sender: SimSender<mocks::TestPublicKey, deterministic::Context>,
        source_boundary_sender: SimSender<mocks::TestPublicKey, deterministic::Context>,
        client_boundary_sender: SimSender<mocks::TestPublicKey, deterministic::Context>,
        client_boundary_receiver: SimReceiver<mocks::TestPublicKey>,
        oracle: Oracle<mocks::TestPublicKey, deterministic::Context>,
        joiner: super::Mailbox<mocks::TestScheme, mocks::TestMarshalVariant>,
        boundary: mocks::TestBlock,
        boundary_finalization: Finalization<mocks::TestScheme, mocks::TestDigest>,
        boundary_sharing: Sharing<mocks::TestBlsVariant>,
        _handles: Vec<Handle<()>>,
        _network: Handle<()>,
    }

    impl Harness {
        async fn start(context: &mut deterministic::Context) -> Self {
            Self::start_with(context, true).await
        }

        async fn start_with(context: &mut deterministic::Context, source_serves: bool) -> Self {
            let boundaries = if source_serves {
                vec![Epoch::new(1)]
            } else {
                Vec::new()
            };
            Self::start_with_boundaries(context, boundaries).await
        }

        async fn start_with_boundaries(
            context: &mut deterministic::Context,
            source_boundaries: Vec<Epoch>,
        ) -> Self {
            let fixture = mocks::scheme_fixture_n(context, 4);
            let participants = fixture.participants.clone();
            let peers = Set::from_iter_dedup(participants.iter().cloned());

            let (network, oracle) = Network::new_with_peers(
                context.child("network"),
                NetworkConfig {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
                participants.clone(),
            )
            .await;
            let network = network.start();
            for from in &participants {
                for to in &participants {
                    if from != to {
                        oracle
                            .add_link(from.clone(), to.clone(), LINK)
                            .await
                            .expect("failed to add link");
                    }
                }
            }

            let (boundary, boundary_sharing) =
                boundary_block(Epoch::new(1), participants[0].clone(), &participants);
            let genesis = genesis_info(&participants);
            let first_boundary_finalization =
                boundary_finalization(Epoch::new(1), boundary.digest(), &fixture.schemes);
            let source_boundaries = source_boundaries
                .into_iter()
                .map(|epoch| {
                    let (block, _) = boundary_block(epoch, participants[0].clone(), &participants);
                    let finalization =
                        boundary_finalization(epoch, block.digest(), &fixture.schemes);
                    (block, finalization)
                })
                .collect::<Vec<_>>();

            let (source_marshal, marshal_handle) = start_marshal(
                context.child("source_marshal"),
                &oracle,
                &fixture,
                0,
                source_boundaries,
            )
            .await;

            let source_control = oracle.control(participants[0].clone());
            let (source_certificate_sender, _source_certificate_receiver) = source_control
                .register(CERTIFICATE_CHANNEL, TEST_QUOTA)
                .await
                .expect("failed to register source certificates");
            let (_source_certificate_backup_sender, source_certificate_backup) = mpsc::channel(16);
            let source_boundaries = source_control
                .register(BOUNDARY_CHANNEL, TEST_QUOTA)
                .await
                .expect("failed to register source boundaries");
            let source_boundary_sender = source_boundaries.0.clone();
            let (source_actor, source_mailbox) = Actor::new(Config {
                context: context.child("source_anchor"),
                manager: oracle.manager(),
                peers: peers.clone(),
                verifier: fixture.schemes[0].clone(),
                genesis: genesis.clone(),
                strategy: Sequential,
                blocker: oracle.control(participants[0].clone()),
                blocks_per_epoch: BLOCKS_PER_EPOCH,
                retry_timeout: NZDuration!(Duration::from_millis(500)),
                mailbox_size: NZUsize!(16),
                block_codec_config: (),
            });
            source_mailbox.attach(source_marshal.clone());
            let source_handle = source_actor.start(source_certificate_backup, source_boundaries);

            let joiner_control = oracle.control(participants[1].clone());
            let (_joiner_certificate_sender, mut joiner_certificate_receiver) = joiner_control
                .register(CERTIFICATE_CHANNEL, TEST_QUOTA)
                .await
                .expect("failed to register joiner certificates");
            let (joiner_certificate_backup_sender, joiner_certificate_backup_receiver) =
                mpsc::channel(16);
            let joiner_certificate_backup_handle = context
                .child("joiner_certificate_backup")
                .spawn(move |_| async move {
                    loop {
                        let Ok(message) = joiner_certificate_receiver.recv().await else {
                            return;
                        };
                        if !joiner_certificate_backup_sender
                            .send_lossy((CERTIFICATE_CHANNEL, message))
                            .await
                        {
                            return;
                        }
                    }
                });
            let joiner_boundaries = joiner_control
                .register(BOUNDARY_CHANNEL, TEST_QUOTA)
                .await
                .expect("failed to register joiner boundaries");
            let (joiner_actor, joiner) = Actor::new(Config {
                context: context.child("joiner_anchor"),
                manager: oracle.manager(),
                peers,
                verifier: fixture.schemes[1].clone(),
                genesis,
                strategy: Sequential,
                blocker: oracle.control(participants[1].clone()),
                blocks_per_epoch: BLOCKS_PER_EPOCH,
                retry_timeout: NZDuration!(Duration::from_millis(500)),
                mailbox_size: NZUsize!(16),
                block_codec_config: (),
            });
            let joiner_handle =
                joiner_actor.start(joiner_certificate_backup_receiver, joiner_boundaries);
            let client_boundaries = oracle
                .control(participants[2].clone())
                .register(BOUNDARY_CHANNEL, TEST_QUOTA)
                .await
                .expect("failed to register client boundaries");

            Self {
                participants,
                schemes: fixture.schemes,
                source_certificate_sender,
                source_boundary_sender,
                client_boundary_sender: client_boundaries.0,
                client_boundary_receiver: client_boundaries.1,
                oracle,
                joiner,
                boundary,
                boundary_finalization: first_boundary_finalization,
                boundary_sharing,
                _handles: vec![
                    marshal_handle,
                    source_handle,
                    joiner_certificate_backup_handle,
                    joiner_handle,
                ],
                _network: network,
            }
        }

        fn send_target_finalization(
            &mut self,
        ) -> Finalization<mocks::TestScheme, mocks::TestDigest> {
            self.send_target_finalization_for(Epoch::new(1), self.boundary.digest())
        }

        fn send_target_finalization_for(
            &mut self,
            epoch: Epoch,
            digest: mocks::TestDigest,
        ) -> Finalization<mocks::TestScheme, mocks::TestDigest> {
            let target = finalization(
                Proposal::new(Round::new(epoch, View::new(2)), View::new(1), digest),
                &self.schemes,
            );
            self.source_certificate_sender.send(
                Recipients::One(self.participants[1].clone()),
                Certificate::Finalization(target.clone()).encode().to_vec(),
                false,
            );
            target
        }

        /// Awaits the next boundary request the joiner broadcasts, as observed by
        /// a peer, and returns the requested epoch.
        async fn next_client_request(&mut self) -> Epoch {
            let (_, message) = self
                .client_boundary_receiver
                .recv()
                .await
                .expect("boundary request");
            wire::read_request(message)
                .expect("decode boundary request")
                .expect("boundary request tag")
        }
    }

    async fn start_marshal(
        context: deterministic::Context,
        oracle: &Oracle<mocks::TestPublicKey, deterministic::Context>,
        fixture: &mocks::SchemeFixture,
        index: usize,
        boundaries: Vec<(
            mocks::TestBlock,
            Finalization<mocks::TestScheme, mocks::TestDigest>,
        )>,
    ) -> (mocks::TestMarshalMailbox, Handle<()>) {
        let public_key = fixture.participants[index].clone();
        let partition_prefix = format!("anchor-node-{index}");
        let page_cache = CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(16));
        let control = oracle.control(public_key.clone());
        let backfill = control
            .register(BACKFILL_CHANNEL, TEST_QUOTA)
            .await
            .expect("failed to register marshal backfill");
        let resolver = marshal_resolver::init(
            context.child("marshal_resolver"),
            marshal_resolver::Config {
                public_key: public_key.clone(),
                peer_provider: oracle.manager(),
                blocker: oracle.control(public_key.clone()),
                mailbox_size: NZUsize!(16),
                initial: Duration::from_secs(1),
                timeout: Duration::from_secs(2),
                fetch_retry_timeout: Duration::from_millis(100),
                priority_requests: false,
                priority_responses: false,
            },
            backfill,
        );
        let finalizations_by_height =
            immutable::Archive::init(context.child("finalizations_by_height"), {
                let _: () = mocks::TestScheme::certificate_codec_config_unbounded();
                archive_config(
                    &partition_prefix,
                    "finalizations_by_height",
                    page_cache.clone(),
                    (),
                )
            })
            .await
            .expect("failed to initialize finalizations archive");
        let finalized_blocks = immutable::Archive::init(
            context.child("finalized_blocks"),
            archive_config(
                &partition_prefix,
                "finalized_blocks",
                page_cache.clone(),
                (),
            ),
        )
        .await
        .expect("failed to initialize finalized blocks archive");

        let (marshal_actor, mut marshal, _) = marshal::core::Actor::init(
            context.child("marshal"),
            finalizations_by_height,
            finalized_blocks,
            marshal::Config {
                provider: mocks::TestProvider::new(fixture.schemes[index].clone()),
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                start: Start::Genesis(mocks::genesis_block(public_key)),
                partition_prefix,
                mailbox_size: NZUsize!(16),
                view_retention_timeout: ViewDelta::new(8),
                prunable_items_per_section: NZU64!(10),
                page_cache,
                replay_buffer: NZUsize!(1024),
                key_write_buffer: NZUsize!(1024),
                value_write_buffer: NZUsize!(1024),
                block_codec_config: (),
                max_repair: NZUsize!(4),
                max_pending_acks: NZUsize!(4),
                strategy: Sequential,
            },
        )
        .await;
        let handle = marshal_actor.start_unbuffered(mocks::MarshalApplication::default(), resolver);

        for (block, finalization) in boundaries {
            assert!(marshal.certified(block.context().round, block).await);
            assert_eq!(
                marshal.report(Activity::Finalization(finalization)),
                Feedback::Ok
            );
        }

        (marshal, handle)
    }

    fn archive_config<C>(
        prefix: &str,
        name: &str,
        page_cache: CacheRef,
        codec_config: C,
    ) -> immutable::Config<C> {
        immutable::Config {
            metadata_partition: format!("{prefix}-{name}-metadata"),
            freezer_table_partition: format!("{prefix}-{name}-freezer-table"),
            freezer_table_initial_size: 64,
            freezer_table_resize_frequency: 10,
            freezer_table_resize_chunk_size: 10,
            freezer_key_partition: format!("{prefix}-{name}-freezer-key"),
            freezer_key_page_cache: page_cache,
            freezer_value_partition: format!("{prefix}-{name}-freezer-value"),
            freezer_value_target_size: 1024,
            freezer_value_compression: None,
            ordinal_partition: format!("{prefix}-{name}-ordinal"),
            items_per_section: NZU64!(10),
            codec_config,
            replay_buffer: NZUsize!(1024),
            freezer_key_write_buffer: NZUsize!(1024),
            freezer_value_write_buffer: NZUsize!(1024),
            ordinal_write_buffer: NZUsize!(1024),
        }
    }

    fn boundary_block(
        epoch: Epoch,
        leader: mocks::TestPublicKey,
        participants: &[mocks::TestPublicKey],
    ) -> (mocks::TestBlock, Sharing<mocks::TestBlsVariant>) {
        let height = FixedEpocher::new(BLOCKS_PER_EPOCH)
            .last(epoch.previous().expect("boundary epoch must be non-zero"))
            .expect("test epoch must be supported");
        let parent = if height == Height::zero() {
            mocks::TestDigest::EMPTY
        } else {
            Sha256::hash(
                &height
                    .previous()
                    .expect("non-genesis height")
                    .get()
                    .to_be_bytes(),
            )
        };
        let context = mocks::TestContext {
            round: Round::new(
                epoch.previous().expect("boundary epoch must be non-zero"),
                View::new(1),
            ),
            leader,
            parent: (View::zero(), parent),
        };
        let participants = Set::from_iter_dedup(participants.iter().cloned());
        let (output, _) = deal::<mocks::TestBlsVariant, _, N3f1>(
            test_rng_seeded(epoch.get()),
            Mode::NonZeroCounter,
            participants.clone(),
        )
        .expect("failed to create test DKG output");
        let sharing = output.public().clone();
        let block = mocks::TestBlock::new::<Sha256>(context, parent, height, epoch.get())
            .with_payload::<Sha256, mocks::TestBlsVariant, mocks::TestSigner>(
            NZU32!(16),
            Payload::EpochInfo(EpochInfo {
                outcome: EpochOutcome::Success,
                epoch,
                output,
                players: participants.clone(),
                next_players: participants,
            }),
        );
        (block, sharing)
    }

    fn boundary_finalization(
        epoch: Epoch,
        digest: mocks::TestDigest,
        schemes: &[mocks::TestScheme],
    ) -> Finalization<mocks::TestScheme, mocks::TestDigest> {
        finalization(
            Proposal::new(
                Round::new(
                    epoch.previous().expect("boundary epoch must be non-zero"),
                    View::new(1),
                ),
                View::zero(),
                digest,
            ),
            schemes,
        )
    }

    fn genesis_info(
        participants: &[mocks::TestPublicKey],
    ) -> EpochInfo<mocks::TestBlsVariant, mocks::TestPublicKey> {
        let participants = Set::from_iter_dedup(participants.iter().cloned());
        let (output, _) = deal::<mocks::TestBlsVariant, _, N3f1>(
            test_rng_seeded(0),
            Mode::NonZeroCounter,
            participants.clone(),
        )
        .expect("failed to create test DKG output");
        EpochInfo {
            outcome: EpochOutcome::Success,
            epoch: Epoch::zero(),
            output,
            players: participants.clone(),
            next_players: participants,
        }
    }

    fn finalization(
        proposal: Proposal<mocks::TestDigest>,
        schemes: &[mocks::TestScheme],
    ) -> Finalization<mocks::TestScheme, mocks::TestDigest> {
        let finalizes = schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect::<Vec<_>>();
        Finalization::from_finalizes(&schemes[0], &finalizes, &Sequential)
            .expect("finalization quorum")
    }

    fn assert_artifact(
        artifact: Artifact<mocks::TestScheme, mocks::TestDigest, mocks::TestBlsVariant>,
        expected_finalization: &Finalization<mocks::TestScheme, mocks::TestDigest>,
        expected_sharing: &Sharing<mocks::TestBlsVariant>,
        participants: &[mocks::TestPublicKey],
    ) {
        let expected_epoch = expected_finalization.epoch().next();
        let participants = Set::from_iter_dedup(participants.iter().cloned());
        assert_eq!(artifact.epoch, expected_epoch);
        assert_eq!(artifact.finalization.as_ref(), Some(expected_finalization));
        assert_eq!(artifact.info.epoch, expected_epoch);
        assert_eq!(artifact.info.output.public(), expected_sharing);
        assert_eq!(artifact.info.output.players(), &participants);
        assert_eq!(artifact.info.players, participants);
    }

    #[test]
    fn discovers_artifact_from_first_finalization() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut harness = Harness::start(&mut context).await;
            let mut subscription = harness.joiner.subscribe();
            harness.send_target_finalization();

            context.sleep(Duration::from_millis(100)).await;
            let artifact = subscription.try_recv().expect("artifact resolved");
            assert_artifact(
                artifact,
                &harness.boundary_finalization,
                &harness.boundary_sharing,
                &harness.participants,
            );
        });
    }

    #[test]
    fn rebroadcasts_boundary_request_when_unanswered() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            // The source has no boundary block, so the joiner's request goes
            // unanswered and it must re-request rather than wedging.
            let mut harness = Harness::start_with(&mut context, false).await;
            let mut subscription = harness.joiner.subscribe();
            harness.send_target_finalization();

            // First broadcast: a peer observes the request, but nobody answers.
            assert_eq!(harness.next_client_request().await, Epoch::new(1));
            assert!(matches!(
                subscription.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));

            // After the retry timeout the joiner re-broadcasts the same request.
            assert_eq!(harness.next_client_request().await, Epoch::new(1));
            assert!(matches!(
                subscription.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
        });
    }

    #[test]
    fn newer_finalization_supersedes_unanswered_boundary() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            // The source can serve the newer boundary but not the first one.
            let mut harness =
                Harness::start_with_boundaries(&mut context, vec![Epoch::new(2)]).await;
            let mut subscription = harness.joiner.subscribe();

            harness.send_target_finalization();
            assert_eq!(harness.next_client_request().await, Epoch::new(1));
            assert!(matches!(
                subscription.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));

            let (newer_boundary, newer_sharing) = boundary_block(
                Epoch::new(2),
                harness.participants[0].clone(),
                &harness.participants,
            );
            let newer_finalization =
                harness.send_target_finalization_for(Epoch::new(2), newer_boundary.digest());

            assert_eq!(harness.next_client_request().await, Epoch::new(2));
            context.sleep(Duration::from_millis(100)).await;

            let artifact = subscription.try_recv().expect("artifact resolved");
            assert_artifact(
                artifact,
                &boundary_finalization(Epoch::new(2), newer_boundary.digest(), &harness.schemes),
                &newer_sharing,
                &harness.participants,
            );
            assert_eq!(newer_finalization.epoch(), Epoch::new(2));
        });
    }

    #[test]
    fn genesis_resolves_after_retry_grace() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut harness = Harness::start(&mut context).await;
            let mut subscription = harness.joiner.subscribe();

            // A lone epoch-zero finalization is only provisional: it must not
            // resolve until the retry grace elapses, so a newer finalization has
            // a window to supersede it.
            harness.send_target_finalization_for(Epoch::zero(), mocks::TestDigest::EMPTY);
            context.sleep(Duration::from_millis(100)).await;
            assert!(matches!(
                subscription.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));

            // With nothing newer arriving, the grace elapses and genesis resolves
            // from the locally known artifact.
            context.sleep(Duration::from_secs(1)).await;
            let artifact = subscription.try_recv().expect("genesis resolved");
            assert_eq!(artifact.epoch, Epoch::zero());
            assert!(artifact.finalization.is_none());
            assert_eq!(artifact.info, genesis_info(&harness.participants));
        });
    }

    #[test]
    fn newer_finalization_supersedes_genesis() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            // The source can serve the epoch-one boundary.
            let mut harness = Harness::start(&mut context).await;
            let mut subscription = harness.joiner.subscribe();

            // A replayed epoch-zero finalization arrives first, but must not
            // permanently pin the joiner to genesis.
            harness.send_target_finalization_for(Epoch::zero(), mocks::TestDigest::EMPTY);
            context.sleep(Duration::from_millis(100)).await;
            assert!(matches!(
                subscription.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));

            // A strictly-newer epoch-one finalization supersedes the genesis
            // candidate and resolves to the epoch-one boundary artifact.
            harness.send_target_finalization();
            context.sleep(Duration::from_millis(100)).await;
            let artifact = subscription.try_recv().expect("newer finalization resolved");
            assert_artifact(
                artifact,
                &harness.boundary_finalization,
                &harness.boundary_sharing,
                &harness.participants,
            );
        });
    }

    #[test]
    fn late_response_for_superseded_boundary_does_not_block_peer() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut harness = Harness::start_with_boundaries(&mut context, Vec::new()).await;
            let mut subscription = harness.joiner.subscribe();

            harness.send_target_finalization();
            assert_eq!(harness.next_client_request().await, Epoch::new(1));

            let (newer_boundary, _) = boundary_block(
                Epoch::new(2),
                harness.participants[0].clone(),
                &harness.participants,
            );
            harness.send_target_finalization_for(Epoch::new(2), newer_boundary.digest());
            assert_eq!(harness.next_client_request().await, Epoch::new(2));

            harness.source_boundary_sender.send(
                Recipients::One(harness.participants[1].clone()),
                wire::Message::<mocks::TestScheme, mocks::TestMarshalVariant>::Response(
                    wire::Response {
                        finalization: harness.boundary_finalization.clone(),
                        block: harness.boundary.clone(),
                    },
                )
                .encode()
                .to_vec(),
                false,
            );
            context.sleep(Duration::from_millis(100)).await;

            let blocked = harness.oracle.blocked().await.unwrap();
            assert!(
                !blocked.contains(&(
                    harness.participants[1].clone(),
                    harness.participants[0].clone()
                )),
                "late response for superseded boundary should not block source peer"
            );
            assert!(matches!(
                subscription.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
        });
    }

    #[test]
    fn ignores_certificates_until_subscribed() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut harness = Harness::start(&mut context).await;
            harness.send_target_finalization();
            context.sleep(Duration::from_millis(100)).await;

            let mut subscription = harness.joiner.subscribe();
            context.sleep(Duration::from_millis(100)).await;
            assert!(matches!(
                subscription.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));

            harness.send_target_finalization();
            context.sleep(Duration::from_millis(100)).await;
            let artifact = subscription.try_recv().expect("artifact resolved");
            assert_artifact(
                artifact,
                &harness.boundary_finalization,
                &harness.boundary_sharing,
                &harness.participants,
            );
        });
    }

    #[test]
    fn late_subscriber_receives_cached_artifact() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut harness = Harness::start(&mut context).await;
            let mut first = harness.joiner.subscribe();
            harness.send_target_finalization();

            context.sleep(Duration::from_millis(100)).await;
            let artifact = first.try_recv().expect("artifact resolved");
            assert_artifact(
                artifact,
                &harness.boundary_finalization,
                &harness.boundary_sharing,
                &harness.participants,
            );

            let mut second = harness.joiner.subscribe();
            context.sleep(Duration::from_millis(10)).await;
            let artifact = second.try_recv().expect("cached artifact resolved");
            assert_artifact(
                artifact,
                &harness.boundary_finalization,
                &harness.boundary_sharing,
                &harness.participants,
            );
        });
    }

    #[test]
    fn serving_answers_boundary_requests_from_marshal() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut harness = Harness::start(&mut context).await;
            harness.client_boundary_sender.send(
                Recipients::One(harness.participants[0].clone()),
                wire::Message::<mocks::TestScheme, mocks::TestMarshalVariant>::Request(Epoch::new(
                    1,
                ))
                .encode()
                .to_vec(),
                false,
            );

            let (_peer, message) = harness
                .client_boundary_receiver
                .recv()
                .await
                .expect("boundary response delivered");
            let response = wire::read_response::<mocks::TestScheme, mocks::TestMarshalVariant>(
                message,
                &harness.schemes[2].certificate_codec_config(),
                &(),
            )
            .expect("boundary response decoded")
            .expect("boundary response");

            assert_eq!(response.block.digest(), harness.boundary.digest());
            assert_eq!(response.block.height(), Height::new(1));
            assert_eq!(response.finalization, harness.boundary_finalization);
        });
    }

    #[test]
    fn serving_ignores_epoch_without_boundary() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut harness = Harness::start(&mut context).await;
            harness.client_boundary_sender.send(
                Recipients::One(harness.participants[0].clone()),
                wire::Message::<mocks::TestScheme, mocks::TestMarshalVariant>::Request(
                    Epoch::zero(),
                )
                .encode()
                .to_vec(),
                false,
            );

            select! {
                _ = harness.client_boundary_receiver.recv() => {
                    panic!("boundary response delivered");
                },
                _ = context.sleep(Duration::from_millis(100)) => {},
            };
        });
    }
}
