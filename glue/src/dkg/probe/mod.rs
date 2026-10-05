//! Discovery of the public epoch material a joining node needs before consensus starts.
//!
//! A node that is starting fresh cannot construct epoch-scoped state until it learns the current
//! epoch's participant set. That set lives in the [`EpochInfo`] of a finalized boundary block.
//! The [`Actor`] discovers that block, publishes the resulting [`Artifact`] (which also carries
//! the sampled state-sync floor), and then serves the same boundary material to other joining peers.
//!
//! This protocol extends [`stateful::probe`](crate::stateful::probe): it begins with the same
//! solicit-and-sample floor discovery and adds requests for the floor epoch's boundary
//! finalization and block, which carry the epoch's public [`EpochInfo`].
//!
//! At startup the node knows a [`Bootstrap`] checkpoint (the complete participant snapshot of a
//! configured bootstrap epoch and its transport [`Directory`]), a constant certificate verifier
//! valid across all epochs, and the epoch length. Solicitation, membership checks, and the fault
//! budgets below apply to the snapshot's dealers, which are the epoch's share holders and
//! certificate signers.
//!
//! The actor activates the snapshot only when its first subscriber appears. If activation fails,
//! the actor shuts down before sending a request and drops all pending subscribers. The
//! discovered [`Artifact`] carries the target epoch's own directory in its [`EpochInfo`].
//!
//! # Trust Model
//!
//! The configured peers and constant verifier are the weakly subjective checkpoint for startup.
//! For `n` configured members, `f` is the maximum fault count under the `3f + 1` model and the
//! discovery sample threshold is `f + 1`.
//!
//! A rotated-out member remains current if it follows the chain at its configured identity.
//! At discovery time:
//!
//! - At most `f` members may be Byzantine or stale, where _stale_ means honest but no longer
//!   following the chain. A frozen node replies honestly with an old finalization, which is
//!   indistinguishable from an adversarial replay, so it spends the same budget.
//! - At most `f` members may be unreachable (shut down, address changed, identity retired).
//!   These cost liveness only and cannot inject anything.
//! - The remaining `f + 1` honest, current, reachable members guarantee both liveness (the
//!   sample completes) and recency (every `f + 1` sample contains at least one of them).
//!
//! Both budgets may be fully spent simultaneously. Refresh the checkpoint when fewer than
//! `f + 1` members remain live and current. Configure the complete snapshot: a subset gives the
//! wrong fault threshold and cannot be detected at startup.
//!
//! The budgets bound recency, not validity. Every accepted reply verifies under the constant
//! group key, so it names a block the network finalized provided no adversary holds a threshold
//! of shares from any committee. The group key is reshare-invariant, so this assumption covers
//! every past committee as well as the current one: a threshold of shares from an earlier epoch
//! can sign for any round. Under that assumption, the sample supplies recency. See
//! [`stateful::probe`](crate::stateful::probe) for the `f + 1` recency argument this actor
//! inherits.
//!
//! # Protocol
//!
//! The actor is a two-state machine: it discovers an [`Artifact`], then serves boundary material.
//!
//! ## Discovery: solicit and sample
//!
//! Once a subscriber appears, the [`Actor`] asks every dealer in the snapshot for its latest
//! finalization:
//!
//! ```text
//!                +-- LatestRequest --> dealer 1
//!                |
//!   Actor -------+-- LatestRequest --> dealer 2
//!                |
//!                +-- LatestRequest --> dealer 3
//!                |
//!                +-- LatestRequest --> dealer 4
//! ```
//!
//! Replies are verified with the all-epoch verifier. At most one reply is counted per peer, a
//! reply from a peer that is not a dealer is blocked, and replies below the bootstrap epoch or
//! below the epoch of a persisted [`Config::floor`] are ignored without blocking (the chain
//! reached both epochs, so an older reply is stale rather than proof of misbehavior). Once
//! `f + 1` distinct dealers have replied, the highest finalization becomes the sampled floor and
//! names the target epoch.
//!
//! With four dealers (`f = 1`), two verified `(epoch, view)` replies suffice:
//!
//! ```text
//!   dealer 1 --LatestResponse(5, 10)-->\
//!                                      +-> Actor --> floor = (6, 1)
//!   dealer 2 --LatestResponse(6, 1)--->/
//! ```
//!
//! If too few peers reply before `retry_timeout`, collected replies are cleared and the
//! solicitation is re-issued.
//!
//! ## Discovery: boundary fetch
//!
//! The actor requests the floor epoch's boundary finalization from every peer, verifies replies,
//! then requests the committed block from one verified responder. Other verified responders
//! remain available if that fetch fails.
//!
//! ```text
//!                +-- BoundaryRequest(epoch) --> peer 1
//!                |
//!   Actor -------+-- BoundaryRequest(epoch) --> peer 2
//!                |
//!                +-- BoundaryRequest(epoch) --> peer 3
//!
//!   peer 2 --BoundaryResponse(finalization)--> Actor
//!                                               |
//!                                      verify finalization
//!                                               |
//!                                               v
//!   peer 2 <---------BlockRequest(epoch)------ Actor
//!   peer 2 --BlockResponse(epoch, block)-----> Actor
//! ```
//!
//! The block's [`EpochInfo`] is packaged into an [`Artifact`] together with the sampled floor and
//! published to subscribers. [`Artifact::info`] always describes the epoch of [`Artifact::floor`].
//!
//! A floor in epoch zero resolves from the locally known genesis info without a boundary fetch.
//!
//! ## Serving
//!
//! Once marshal is attached and no subscriber is pending, the actor enters service and answers
//! peers' latest-finalization, boundary finalization, and boundary block requests for the rest of
//! the process lifetime.
//!
//! An epoch with no known boundary block is answered with nothing, as is a latest-finalization
//! request when marshal has no finalization yet.
//!
//! During consensus catch-up, the orchestrator asks for the boundary certificate of the active
//! epoch, naming a peer that has advanced past it. The service requests the certificate from that
//! peer and, after each `retry_timeout`, from every peer, until marshal stores or has processed
//! the boundary. It verifies at most one response from each peer asked in the latest request,
//! using the all-epoch verifier, and ignores other responses. Verified certificates are reported
//! to marshal for commitment-based block acquisition. Serving continues throughout.

use crate::dkg::{
    ReshareBlock,
    network::Directory,
    types::{EpochInfo, Participants},
};
use commonware_consensus::{
    marshal::core::Variant as MarshalVariant,
    simplex::{scheme::Scheme, types::Finalization},
    types::Epoch,
};
use commonware_cryptography::{
    Digest, PublicKey, bls12381::primitives::variant::Variant as BlsVariant,
};
use commonware_utils::sequence::Unit;

mod actor;
pub use actor::{Actor, Config};

mod mailbox;
pub use mailbox::Mailbox;

pub(crate) mod wire;

/// The weakly subjective checkpoint a joining node bootstraps from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bootstrap<P: PublicKey, D: Directory<P> = Unit> {
    /// Epoch whose participant snapshot is [`Bootstrap::participants`].
    ///
    /// Latest-finalization replies below this epoch are ignored, so the
    /// discovered floor is never older than the configured trust point.
    pub epoch: Epoch,
    /// The complete participant snapshot of [`Bootstrap::epoch`].
    ///
    /// Discovery samples `f + 1` of the snapshot's dealers, so the dealers
    /// must be the epoch's complete committee (a subset mis-derives `f`). The
    /// snapshot must equal the epoch's canonical [`Participants`] because it is
    /// activated at that epoch's peer-set ID. See the
    /// [trust model](crate::dkg::probe#trust-model) for the fault budgets.
    pub participants: Participants<P>,
    /// Transport directory for [`Bootstrap::participants`].
    pub directory: D,
}

/// Concrete probe artifact for a marshal variant.
pub(crate) type ActorArtifact<S, V> = Artifact<
    S,
    <V as MarshalVariant>::Commitment,
    <<V as MarshalVariant>::ApplicationBlock as ReshareBlock>::Variant,
    <<V as MarshalVariant>::ApplicationBlock as ReshareBlock>::Directory,
>;

/// Public epoch material discovered during bootstrap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Artifact<S, D, V, Dir = Unit>
where
    S: Scheme<D>,
    D: Digest,
    V: BlsVariant,
    Dir: Directory<S::PublicKey>,
{
    /// Finalization of the boundary block that carried the epoch info.
    ///
    /// Epoch zero is anchored by genesis and has no boundary finalization.
    pub finalization: Option<Finalization<S, D>>,
    /// Public epoch information for the epoch of [`Artifact::floor`] (the genesis
    /// information for epoch zero).
    pub info: EpochInfo<V, S::PublicKey, Dir>,
    /// Highest finalization from the `f + 1` peer sample.
    ///
    /// This is the sampled state-sync floor, at least as recent as the freshest
    /// honest reply in the sample.
    pub floor: Finalization<S, D>,
}

#[cfg(test)]
mod tests {
    use super::{Actor, Bootstrap, Config, wire};
    use crate::{
        dkg::{
            probe::Artifact,
            state_sync::{Config as StateSyncConfig, Plan as StateSyncPlan, StateSync},
            tests::{max_supported_mode, mocks},
            types::{EpochInfo, EpochOutcome, Payload},
        },
        stateful::SyncPlan,
    };
    use commonware_actor::Feedback;
    use commonware_codec::Encode as _;
    use commonware_consensus::{
        Epochable as _, Heightable as _, Reporter as _,
        marshal::{self, Start, resolver::p2p as marshal_resolver},
        simplex::types::{Activity, Finalization, Finalize, Proposal},
        types::{Epoch, Epocher as _, FixedEpocher, Height, Round, View, ViewDelta},
    };
    use commonware_cryptography::{
        Digest as _, Digestible as _, Hasher as _,
        bls12381::{
            dkg::feldman_desmedt::deal,
            primitives::sharing::{Mode, Sharing},
        },
        certificate::Verifier as _,
        sha256::Sha256,
    };
    use commonware_macros::select;
    use commonware_p2p::{
        Provider as _, Receiver as _, Recipients, Sender as _,
        simulated::{
            Config as NetworkConfig, Link, Network, Oracle, Receiver as SimReceiver,
            Sender as SimSender,
        },
    };
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        Clock as _, Handle, Quota, Runner as _, Supervisor as _, buffer::paged::CacheRef,
        deterministic,
    };
    use commonware_storage::{archive::prunable, translator::TwoCap};
    use commonware_utils::{
        N3f1, NZDuration, NZU16, NZU32, NZU64, NZUsize, TestRng, channel::oneshot, non_empty,
        ordered::Set, probability, sequence::Unit,
    };
    use std::{num::NonZeroU64, time::Duration};

    const BACKFILL_CHANNEL: u64 = 0;
    const BOUNDARY_CHANNEL: u64 = 1;
    const TEST_QUOTA: Quota = Quota::per_second(NZU32!(1_000_000));
    const BLOCKS_PER_EPOCH: NonZeroU64 = NZU64!(2);
    const LINK: Link = Link {
        latency: Duration::from_millis(1),
        jitter: Duration::ZERO,
        success_rate: probability!(1.0),
    };

    struct Harness {
        participants: Vec<mocks::TestPublicKey>,
        schemes: Vec<mocks::TestScheme>,
        source_boundary_sender: SimSender<mocks::TestPublicKey, deterministic::Context>,
        client_boundary_sender: SimSender<mocks::TestPublicKey, deterministic::Context>,
        client_boundary_receiver: SimReceiver<mocks::TestPublicKey>,
        backup_boundary_sender: SimSender<mocks::TestPublicKey, deterministic::Context>,
        backup_boundary_receiver: SimReceiver<mocks::TestPublicKey>,
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
            Self::start_full(
                context,
                fixture,
                source_boundaries,
                Epoch::zero(),
                None,
                Duration::from_millis(500),
            )
            .await
        }

        async fn start_full(
            context: &mut deterministic::Context,
            fixture: mocks::SchemeFixture,
            source_boundaries: Vec<Epoch>,
            bootstrap_epoch: Epoch,
            floor: Option<Finalization<mocks::TestScheme, mocks::TestDigest>>,
            retry_timeout: Duration,
        ) -> Self {
            let participants = fixture.participants.clone();

            let (network, oracle) = Network::new_with_peers(
                context.child("network"),
                NetworkConfig {
                    max_size: 1024 * 1024,
                    max_peers_per_set: NZUsize!(participants.len()),
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
                &fixture.participants,
                &fixture.schemes,
                0,
                source_boundaries,
            )
            .await;

            let source_control = oracle.control(participants[0].clone());
            let source_boundaries = source_control
                .register(BOUNDARY_CHANNEL, TEST_QUOTA)
                .await
                .expect("failed to register source boundaries");
            let source_boundary_sender = source_boundaries.0.clone();
            let (source_actor, source_mailbox) = Actor::new(Config {
                context: context.child("source_probe"),
                manager: oracle.manager(),
                bootstrap: Bootstrap {
                    epoch: bootstrap_epoch,
                    participants: genesis.participants(),
                    directory: Unit,
                },
                floor: None,
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
            let source_handle = source_actor.start(source_boundaries);

            let joiner_control = oracle.control(participants[1].clone());
            let joiner_boundaries = joiner_control
                .register(BOUNDARY_CHANNEL, TEST_QUOTA)
                .await
                .expect("failed to register joiner boundaries");
            let (joiner_actor, joiner) = Actor::new(Config {
                context: context.child("joiner_probe"),
                manager: oracle.manager(),
                bootstrap: Bootstrap {
                    epoch: bootstrap_epoch,
                    participants: genesis.participants(),
                    directory: Unit,
                },
                floor,
                verifier: fixture.schemes[1].clone(),
                genesis,
                strategy: Sequential,
                blocker: oracle.control(participants[1].clone()),
                blocks_per_epoch: BLOCKS_PER_EPOCH,
                retry_timeout: NZDuration!(retry_timeout),
                mailbox_size: NZUsize!(16),
                block_codec_config: (),
            });
            let joiner_handle = joiner_actor.start(joiner_boundaries);
            let client_boundaries = oracle
                .control(participants[2].clone())
                .register(BOUNDARY_CHANNEL, TEST_QUOTA)
                .await
                .expect("failed to register client boundaries");
            let backup_boundaries = oracle
                .control(participants[3].clone())
                .register(BOUNDARY_CHANNEL, TEST_QUOTA)
                .await
                .expect("failed to register backup boundaries");

            Self {
                participants,
                schemes: fixture.schemes,
                source_boundary_sender,
                client_boundary_sender: client_boundaries.0,
                client_boundary_receiver: client_boundaries.1,
                backup_boundary_sender: backup_boundaries.0,
                backup_boundary_receiver: backup_boundaries.1,
                oracle,
                joiner,
                boundary,
                boundary_finalization: first_boundary_finalization,
                boundary_sharing,
                _handles: vec![marshal_handle, source_handle, joiner_handle],
                _network: network,
            }
        }

        /// Builds a latest finalization for `epoch` committing to `digest`.
        fn latest_finalization(
            &self,
            epoch: Epoch,
            digest: mocks::TestDigest,
        ) -> Finalization<mocks::TestScheme, mocks::TestDigest> {
            finalization(
                Proposal::new(Round::new(epoch, View::new(2)), View::new(1), digest),
                &self.schemes,
            )
        }

        /// The default latest reply: a finalization within epoch 1 committing
        /// to the epoch-1 boundary digest.
        fn target_finalization(&self) -> Finalization<mocks::TestScheme, mocks::TestDigest> {
            self.latest_finalization(Epoch::new(1), self.boundary.digest())
        }

        fn latest_response(
            finalization: Finalization<mocks::TestScheme, mocks::TestDigest>,
        ) -> Vec<u8> {
            wire::Message::<mocks::TestScheme, mocks::TestMarshalVariant>::LatestResponse(
                finalization,
            )
            .encode()
            .to_vec()
        }

        fn reply_latest_from_client(
            &mut self,
            finalization: Finalization<mocks::TestScheme, mocks::TestDigest>,
        ) {
            self.client_boundary_sender.send(
                Recipients::One(self.participants[1].clone()),
                Self::latest_response(finalization),
                false,
            );
        }

        fn reply_latest_from_backup(
            &mut self,
            finalization: Finalization<mocks::TestScheme, mocks::TestDigest>,
        ) {
            self.backup_boundary_sender.send(
                Recipients::One(self.participants[1].clone()),
                Self::latest_response(finalization),
                false,
            );
        }

        /// Completes a sample for the target finalization from the client and
        /// backup peers.
        fn complete_target_sample(&mut self) -> Finalization<mocks::TestScheme, mocks::TestDigest> {
            let target = self.target_finalization();
            self.reply_latest_from_client(target.clone());
            self.reply_latest_from_backup(target.clone());
            target
        }

        async fn next_request(receiver: &mut SimReceiver<mocks::TestPublicKey>) -> wire::Request {
            let (_, message) = receiver.recv().await.expect("boundary request");
            wire::read_request(message)
                .expect("decode boundary request")
                .expect("boundary request tag")
        }

        async fn expect_latest_request(receiver: &mut SimReceiver<mocks::TestPublicKey>) {
            match Self::next_request(receiver).await {
                wire::Request::Latest => {}
                wire::Request::Boundary(_) | wire::Request::Block(_) => {
                    panic!("expected latest request")
                }
            }
        }

        async fn next_boundary_request(receiver: &mut SimReceiver<mocks::TestPublicKey>) -> Epoch {
            match Self::next_request(receiver).await {
                wire::Request::Boundary(epoch) => epoch,
                wire::Request::Block(_) | wire::Request::Latest => {
                    panic!("expected finalization request")
                }
            }
        }

        async fn next_block_request(receiver: &mut SimReceiver<mocks::TestPublicKey>) -> Epoch {
            match Self::next_request(receiver).await {
                wire::Request::Block(epoch) => epoch,
                wire::Request::Boundary(_) | wire::Request::Latest => {
                    panic!("expected block request")
                }
            }
        }

        async fn next_client_boundary_request(&mut self) -> Epoch {
            Self::next_boundary_request(&mut self.client_boundary_receiver).await
        }

        async fn attach_joiner(
            &mut self,
            context: &deterministic::Context,
        ) -> mocks::TestMarshalMailbox {
            let (marshal, handle) = start_marshal(
                context.child("joiner_marshal"),
                &self.oracle,
                &self.participants,
                &self.schemes,
                1,
                Vec::new(),
            )
            .await;
            self._handles.push(handle);
            self.joiner.attach(marshal.clone());
            marshal
        }
    }

    async fn start_marshal(
        context: deterministic::Context,
        oracle: &Oracle<mocks::TestPublicKey, deterministic::Context>,
        participants: &[mocks::TestPublicKey],
        schemes: &[mocks::TestScheme],
        index: usize,
        boundaries: Vec<(
            mocks::TestBlock,
            Finalization<mocks::TestScheme, mocks::TestDigest>,
        )>,
    ) -> (mocks::TestMarshalMailbox, Handle<()>) {
        let public_key = participants[index].clone();
        let partition_prefix = format!("probe-node-{index}");
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
                timeout: Duration::from_secs(2),
                fetch_retry_timeout: Duration::from_millis(100),
                priority_requests: false,
                priority_responses: false,
            },
            backfill,
        );
        let finalizations_by_height =
            prunable::Archive::init(context.child("finalizations_by_height"), {
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
        let finalized_blocks = prunable::Archive::init(
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
                provider: mocks::TestProvider::new(schemes[index].clone()),
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                start: Start::Genesis(mocks::genesis_block(public_key).into()),
                partition_prefix,
                mailbox_size: NZUsize!(16),
                view_retention: ViewDelta::new(8),
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
    ) -> prunable::Config<TwoCap, C> {
        prunable::Config {
            translator: TwoCap,
            metadata_partition: format!("{prefix}-{name}-metadata"),
            key_partition: format!("{prefix}-{name}-key"),
            key_page_cache: page_cache,
            value_partition: format!("{prefix}-{name}-value"),
            compression: None,
            items_per_section: NZU64!(10),
            codec_config,
            replay_buffer: NZUsize!(1024),
            key_write_buffer: NZUsize!(1024),
            value_write_buffer: NZUsize!(1024),
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
            Sha256::hash(&[&height
                .previous()
                .expect("non-genesis height")
                .get()
                .to_be_bytes()])
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
            TestRng::new(epoch.get()),
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
                directory: Unit,
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
            TestRng::new(0),
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
            directory: Unit,
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
        Finalization::from_finalizes(&schemes[0], non_empty![@finalizes.iter()], &Sequential)
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
        assert_eq!(artifact.finalization.as_ref(), Some(expected_finalization));
        assert_eq!(artifact.info.epoch, expected_epoch);
        assert_eq!(artifact.info.output.public(), expected_sharing);
        assert_eq!(artifact.info.output.players(), &participants);
        assert_eq!(artifact.info.players, participants);
        assert_eq!(artifact.floor.epoch(), expected_epoch);
    }

    #[test]
    fn discovers_artifact_from_sample() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut harness = Harness::start(&mut context).await;
            let mut subscription = harness.joiner.subscribe();
            let target = harness.complete_target_sample();

            context.sleep(Duration::from_millis(100)).await;
            let artifact = subscription.try_recv().expect("artifact resolved");
            assert_eq!(artifact.floor, target);
            assert_artifact(
                artifact,
                &harness.boundary_finalization,
                &harness.boundary_sharing,
                &harness.participants,
            );
        });
    }

    #[test]
    fn waits_for_full_sample() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut harness = Harness::start_with(&mut context, false).await;
            let mut subscription = harness.joiner.subscribe();

            // One reply is below the sample threshold (f + 1 = 2 of 4).
            let target = harness.target_finalization();
            harness.reply_latest_from_client(target);

            context.sleep(Duration::from_millis(100)).await;
            assert!(
                matches!(
                    subscription.try_recv(),
                    Err(oneshot::error::TryRecvError::Empty)
                ),
                "a single reply must not complete the sample"
            );
        });
    }

    #[test]
    fn duplicate_latest_reply_is_ignored() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut harness = Harness::start_with(&mut context, false).await;
            let mut subscription = harness.joiner.subscribe();

            // Two different valid replies from the same peer must count once.
            let first = harness.latest_finalization(Epoch::new(1), Sha256::hash(&[b"first"]));
            let second = harness.latest_finalization(Epoch::new(2), Sha256::hash(&[b"second"]));
            harness.reply_latest_from_client(first);
            harness.reply_latest_from_client(second);

            context.sleep(Duration::from_millis(100)).await;
            assert!(
                matches!(
                    subscription.try_recv(),
                    Err(oneshot::error::TryRecvError::Empty)
                ),
                "duplicate replies must not inflate the sample"
            );
            let blocked = harness.oracle.blocked().await.unwrap();
            assert!(
                blocked.is_empty(),
                "a duplicate reply must be ignored, not treated as a fault"
            );
        });
    }

    #[test]
    fn sample_selects_highest_reply() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            // The source can serve the epoch-2 boundary.
            let mut harness =
                Harness::start_with_boundaries(&mut context, vec![Epoch::new(2)]).await;
            let mut subscription = harness.joiner.subscribe();

            let (newer_boundary, newer_sharing) = boundary_block(
                Epoch::new(2),
                harness.participants[0].clone(),
                &harness.participants,
            );
            let stale = harness.latest_finalization(Epoch::new(1), Sha256::hash(&[b"stale"]));
            let newest = harness.latest_finalization(Epoch::new(2), newer_boundary.digest());
            harness.reply_latest_from_client(stale);
            harness.reply_latest_from_backup(newest.clone());

            context.sleep(Duration::from_millis(100)).await;
            let artifact = subscription.try_recv().expect("artifact resolved");
            assert_eq!(artifact.floor, newest);
            assert_artifact(
                artifact,
                &boundary_finalization(Epoch::new(2), newer_boundary.digest(), &harness.schemes),
                &newer_sharing,
                &harness.participants,
            );
        });
    }

    #[test]
    fn genesis_floor_resolves_locally() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut harness = Harness::start_with(&mut context, false).await;
            let mut subscription = harness.joiner.subscribe();

            // The whole sample reports epoch-zero finalizations: the artifact
            // resolves from the locally known genesis info without any
            // boundary fetch.
            let floor =
                harness.latest_finalization(Epoch::zero(), Sha256::hash(&[b"genesis floor"]));
            harness.reply_latest_from_client(floor.clone());
            harness.reply_latest_from_backup(floor.clone());

            context.sleep(Duration::from_millis(100)).await;
            let artifact = subscription.try_recv().expect("genesis resolved");
            assert_eq!(artifact.info.epoch, Epoch::zero());
            assert!(artifact.finalization.is_none());
            assert_eq!(artifact.info, genesis_info(&harness.participants));
            assert_eq!(artifact.floor, floor);
        });
    }

    #[test]
    fn resolicits_when_sample_incomplete() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut harness = Harness::start_with(&mut context, false).await;
            let _subscription = harness.joiner.subscribe();

            // The first solicitation reaches the client, goes unanswered, and
            // is re-issued after the retry timeout.
            Harness::expect_latest_request(&mut harness.client_boundary_receiver).await;
            Harness::expect_latest_request(&mut harness.client_boundary_receiver).await;
        });
    }

    /// Latest replies below the bootstrap epoch are ignored without blocking
    /// peers, including when a persisted floor from an earlier epoch is set.
    #[rstest::rstest]
    #[case::none(false)]
    #[case::older(true)]
    fn ignores_latest_reply_below_bootstrap_epoch(#[case] older: bool) {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            // In the `older` case, a persisted epoch-zero floor must not lower
            // the minimum epoch below the bootstrap epoch.
            let fixture = mocks::scheme_fixture_n(&mut context, 4);
            let floor = older.then(|| {
                finalization(
                    Proposal::new(
                        Round::new(Epoch::zero(), View::new(1)),
                        View::zero(),
                        Sha256::hash(&[b"floor"]),
                    ),
                    &fixture.schemes,
                )
            });
            let mut harness = Harness::start_full(
                &mut context,
                fixture,
                vec![Epoch::new(1)],
                Epoch::new(1),
                floor,
                Duration::from_millis(500),
            )
            .await;
            let mut subscription = harness.joiner.subscribe();

            // Valid replies below the bootstrap epoch are stale by definition
            // and must be ignored without blocking.
            let stale = harness.latest_finalization(Epoch::zero(), Sha256::hash(&[b"stale"]));
            harness.reply_latest_from_client(stale.clone());
            harness.reply_latest_from_backup(stale);
            context.sleep(Duration::from_millis(100)).await;
            assert!(
                matches!(
                    subscription.try_recv(),
                    Err(oneshot::error::TryRecvError::Empty)
                ),
                "below-bootstrap replies must not complete the sample"
            );
            let blocked = harness.oracle.blocked().await.unwrap();
            assert!(blocked.is_empty(), "stale replies must not block peers");

            // The same peers may still contribute accepted replies.
            let target = harness.complete_target_sample();
            context.sleep(Duration::from_millis(100)).await;
            let artifact = subscription.try_recv().expect("artifact resolved");
            assert_eq!(artifact.floor, target);
        });
    }

    /// A node resuming an interrupted state sync ignores latest replies below
    /// its persisted floor's epoch, so the discovered info describes the floor
    /// it resumes from. The bootstrap committee is tracked at the bootstrap
    /// epoch's peer-set ID, not the floor's.
    #[test]
    fn ignores_latest_reply_below_floor_epoch() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            // Select an in-progress floor in epoch 2, which persists it, then
            // reload it as a restarted node.
            let fixture = mocks::scheme_fixture_n(&mut context, 4);
            let persisted = finalization(
                Proposal::new(
                    Round::new(Epoch::new(2), View::new(3)),
                    View::new(2),
                    Sha256::hash(&[b"persisted"]),
                ),
                &fixture.schemes,
            );
            let plan = SyncPlan::<_, mocks::TestScheme, mocks::TestMarshalVariant>::init(
                context.child("plan"),
                "floor",
            )
            .await
            .set_floor(persisted.clone())
            .await;
            drop(plan);
            let plan = SyncPlan::<_, mocks::TestScheme, mocks::TestMarshalVariant>::init(
                context.child("restart"),
                "floor",
            )
            .await;
            assert_eq!(plan.floor(), Some(&persisted));

            // Valid replies at the bootstrap epoch are below the floor's
            // epoch: they must neither complete the sample nor block peers,
            // even though the source can serve that epoch's boundary.
            let mut harness = Harness::start_full(
                &mut context,
                fixture,
                vec![Epoch::new(1), Epoch::new(2)],
                Epoch::new(1),
                plan.floor().cloned(),
                Duration::from_millis(500),
            )
            .await;
            let mut subscription = harness.joiner.subscribe();
            let stale = harness.target_finalization();
            harness.reply_latest_from_client(stale.clone());
            harness.reply_latest_from_backup(stale);
            context.sleep(Duration::from_millis(100)).await;
            assert!(
                matches!(
                    subscription.try_recv(),
                    Err(oneshot::error::TryRecvError::Empty)
                ),
                "below-floor replies must not complete the sample"
            );
            let blocked = harness.oracle.blocked().await.unwrap();
            assert!(blocked.is_empty(), "stale replies must not block peers");

            // Replies in the floor's epoch resolve that epoch's info. The
            // network starts with only set 0, so set 1 proves the committee is
            // tracked at the bootstrap epoch's ID rather than the floor's.
            let sampled = harness.latest_finalization(Epoch::new(2), Sha256::hash(&[b"sampled"]));
            harness.reply_latest_from_client(sampled.clone());
            harness.reply_latest_from_backup(sampled.clone());
            context.sleep(Duration::from_millis(100)).await;
            let artifact = subscription.try_recv().expect("artifact resolved");
            assert_eq!(artifact.floor, sampled);
            assert_eq!(artifact.info.epoch, Epoch::new(2));
            let mut manager = harness.oracle.manager();
            assert!(manager.peer_set(1).await.is_some());
            assert!(manager.peer_set(2).await.is_none());

            // The plan keeps the later persisted floor, and the DKG startup
            // material pairs the plan's floor with the discovered info.
            let plan = plan.set_floor(artifact.floor.clone()).await;
            assert_eq!(plan.floor(), Some(&persisted));
            StateSyncPlan::init(
                context.child("dkg"),
                StateSyncConfig {
                    partition_prefix: "floor".into(),
                    max_participants: NZU32!(16),
                    max_supported_mode: max_supported_mode(),
                },
                Some(StateSync {
                    info: artifact.info,
                    floor: plan.floor().cloned().expect("resumed floor"),
                }),
            )
            .await;
        });
    }

    #[test]
    fn invalid_latest_reply_blocks_peer() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut harness = Harness::start_with(&mut context, false).await;
            let _subscription = harness.joiner.subscribe();

            // A finalization signed by a foreign key set decodes cleanly but
            // fails verification against the all-epoch verifier.
            let foreign = mocks::scheme_fixture_n(&mut context, 4);
            let invalid = finalization(
                Proposal::new(
                    Round::new(Epoch::new(1), View::new(2)),
                    View::new(1),
                    Sha256::hash(&[b"foreign"]),
                ),
                &foreign.schemes,
            );
            harness.reply_latest_from_client(invalid);

            context.sleep(Duration::from_millis(100)).await;
            let blocked = harness.oracle.blocked().await.unwrap();
            assert!(
                blocked.contains(&(
                    harness.participants[1].clone(),
                    harness.participants[2].clone(),
                )),
                "joiner should block the sender of an invalid reply"
            );
        });
    }

    #[test]
    fn fetches_boundary_block_from_one_responder() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut harness = Harness::start_with(&mut context, false).await;
            let mut subscription = harness.joiner.subscribe();

            Harness::expect_latest_request(&mut harness.client_boundary_receiver).await;
            Harness::expect_latest_request(&mut harness.backup_boundary_receiver).await;
            harness.complete_target_sample();

            assert_eq!(harness.next_client_boundary_request().await, Epoch::new(1));
            assert_eq!(
                Harness::next_boundary_request(&mut harness.backup_boundary_receiver).await,
                Epoch::new(1)
            );

            harness.client_boundary_sender.send(
                Recipients::One(harness.participants[1].clone()),
                wire::Message::<mocks::TestScheme, mocks::TestMarshalVariant>::BoundaryResponse(
                    harness.boundary_finalization.clone(),
                )
                .encode()
                .to_vec(),
                false,
            );
            assert_eq!(
                Harness::next_block_request(&mut harness.client_boundary_receiver).await,
                Epoch::new(1)
            );

            select! {
                _ = harness.backup_boundary_receiver.recv() => {
                    panic!("block request sent to an unselected responder");
                },
                _ = context.sleep(Duration::from_millis(100)) => {},
            }

            harness.client_boundary_sender.send(
                Recipients::One(harness.participants[1].clone()),
                wire::Message::<mocks::TestScheme, mocks::TestMarshalVariant>::BlockResponse {
                    epoch: Epoch::new(1),
                    block: harness.boundary.clone().into(),
                }
                .encode()
                .to_vec(),
                false,
            );
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
    fn retries_boundary_block_with_another_responder() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut harness = Harness::start_with(&mut context, false).await;
            let mut subscription = harness.joiner.subscribe();

            Harness::expect_latest_request(&mut harness.client_boundary_receiver).await;
            Harness::expect_latest_request(&mut harness.backup_boundary_receiver).await;
            harness.complete_target_sample();

            assert_eq!(harness.next_client_boundary_request().await, Epoch::new(1));
            assert_eq!(
                Harness::next_boundary_request(&mut harness.backup_boundary_receiver).await,
                Epoch::new(1)
            );

            harness.client_boundary_sender.send(
                Recipients::One(harness.participants[1].clone()),
                wire::Message::<mocks::TestScheme, mocks::TestMarshalVariant>::BoundaryResponse(
                    harness.boundary_finalization.clone(),
                )
                .encode()
                .to_vec(),
                false,
            );
            assert_eq!(
                Harness::next_block_request(&mut harness.client_boundary_receiver).await,
                Epoch::new(1)
            );

            harness.backup_boundary_sender.send(
                Recipients::One(harness.participants[1].clone()),
                wire::Message::<mocks::TestScheme, mocks::TestMarshalVariant>::BoundaryResponse(
                    harness.boundary_finalization.clone(),
                )
                .encode()
                .to_vec(),
                false,
            );
            assert_eq!(
                Harness::next_block_request(&mut harness.backup_boundary_receiver).await,
                Epoch::new(1)
            );

            harness.backup_boundary_sender.send(
                Recipients::One(harness.participants[1].clone()),
                wire::Message::<mocks::TestScheme, mocks::TestMarshalVariant>::BlockResponse {
                    epoch: Epoch::new(1),
                    block: harness.boundary.clone().into(),
                }
                .encode()
                .to_vec(),
                false,
            );
            context.sleep(Duration::from_millis(100)).await;

            let artifact = subscription.try_recv().expect("artifact resolved");
            assert_artifact(
                artifact,
                &harness.boundary_finalization,
                &harness.boundary_sharing,
                &harness.participants,
            );
            let blocked = harness.oracle.blocked().await.unwrap();
            assert!(blocked.is_empty(), "silent responders must not be blocked");
        });
    }

    #[test]
    fn invalid_boundary_block_tries_another_responder_immediately() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut harness = Harness::start_with(&mut context, false).await;
            let mut subscription = harness.joiner.subscribe();

            Harness::expect_latest_request(&mut harness.client_boundary_receiver).await;
            Harness::expect_latest_request(&mut harness.backup_boundary_receiver).await;
            harness.complete_target_sample();

            assert_eq!(harness.next_client_boundary_request().await, Epoch::new(1));
            assert_eq!(
                Harness::next_boundary_request(&mut harness.backup_boundary_receiver).await,
                Epoch::new(1)
            );

            harness.client_boundary_sender.send(
                Recipients::One(harness.participants[1].clone()),
                wire::Message::<mocks::TestScheme, mocks::TestMarshalVariant>::BoundaryResponse(
                    harness.boundary_finalization.clone(),
                )
                .encode()
                .to_vec(),
                false,
            );
            assert_eq!(
                Harness::next_block_request(&mut harness.client_boundary_receiver).await,
                Epoch::new(1)
            );

            harness.backup_boundary_sender.send(
                Recipients::One(harness.participants[1].clone()),
                wire::Message::<mocks::TestScheme, mocks::TestMarshalVariant>::BoundaryResponse(
                    harness.boundary_finalization.clone(),
                )
                .encode()
                .to_vec(),
                false,
            );
            context.sleep(Duration::from_millis(100)).await;

            let (wrong_block, _) = boundary_block(
                Epoch::new(2),
                harness.participants[0].clone(),
                &harness.participants,
            );
            harness.client_boundary_sender.send(
                Recipients::One(harness.participants[1].clone()),
                wire::Message::<mocks::TestScheme, mocks::TestMarshalVariant>::BlockResponse {
                    epoch: Epoch::new(1),
                    block: wrong_block.into(),
                }
                .encode()
                .to_vec(),
                false,
            );

            select! {
                epoch = Harness::next_block_request(&mut harness.backup_boundary_receiver) => {
                    assert_eq!(epoch, Epoch::new(1));
                },
                _ = context.sleep(Duration::from_millis(100)) => {
                    panic!("invalid block did not trigger immediate failover");
                },
            }

            harness.backup_boundary_sender.send(
                Recipients::One(harness.participants[1].clone()),
                wire::Message::<mocks::TestScheme, mocks::TestMarshalVariant>::BlockResponse {
                    epoch: Epoch::new(1),
                    block: harness.boundary.clone().into(),
                }
                .encode()
                .to_vec(),
                false,
            );
            context.sleep(Duration::from_millis(100)).await;

            let artifact = subscription.try_recv().expect("artifact resolved");
            assert_artifact(
                artifact,
                &harness.boundary_finalization,
                &harness.boundary_sharing,
                &harness.participants,
            );
            let blocked = harness.oracle.blocked().await.unwrap();
            assert!(blocked.contains(&(
                harness.participants[1].clone(),
                harness.participants[2].clone()
            )));
        });
    }

    #[test]
    fn rebroadcasts_finalization_request_when_unanswered() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            // The source has no boundary block, so the joiner's request goes
            // unanswered and it must re-request rather than wedging.
            let mut harness = Harness::start_with(&mut context, false).await;
            let mut subscription = harness.joiner.subscribe();

            Harness::expect_latest_request(&mut harness.client_boundary_receiver).await;
            harness.complete_target_sample();

            // First broadcast: a peer observes the request, but nobody answers.
            assert_eq!(harness.next_client_boundary_request().await, Epoch::new(1));
            assert!(matches!(
                subscription.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));

            // After the retry timeout the joiner re-broadcasts the same request.
            assert_eq!(harness.next_client_boundary_request().await, Epoch::new(1));
            assert!(matches!(
                subscription.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
        });
    }

    #[test]
    fn terminal_epoch_boundary_response_does_not_panic() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut harness = Harness::start_with_boundaries(&mut context, Vec::new()).await;
            let mut subscription = harness.joiner.subscribe();

            Harness::expect_latest_request(&mut harness.client_boundary_receiver).await;
            harness.complete_target_sample();
            assert_eq!(harness.next_client_boundary_request().await, Epoch::new(1));

            let terminal_finalization = finalization(
                Proposal::new(
                    Round::new(Epoch::new(u64::MAX), View::new(1)),
                    View::zero(),
                    harness.boundary.digest(),
                ),
                &harness.schemes,
            );
            let message =
                wire::Message::<mocks::TestScheme, mocks::TestMarshalVariant>::BoundaryResponse(
                    terminal_finalization,
                )
                .encode();
            let decoded = wire::read_response::<mocks::TestScheme, mocks::TestMarshalVariant, _>(
                message.clone(),
                &harness.schemes[2].certificate_codec_config(),
            )
            .expect("terminal response decoded")
            .expect("terminal response tag");
            let wire::Response::Boundary(decoded) = decoded else {
                panic!("expected finalization response");
            };
            assert_eq!(decoded.epoch(), Epoch::new(u64::MAX));

            harness.source_boundary_sender.send(
                Recipients::One(harness.participants[1].clone()),
                message,
                false,
            );
            context.sleep(Duration::from_millis(100)).await;

            let blocked = harness.oracle.blocked().await.unwrap();
            assert!(
                blocked.contains(&(
                    harness.participants[1].clone(),
                    harness.participants[0].clone()
                )),
                "terminal-epoch response should block source peer"
            );
            assert!(matches!(
                subscription.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
        });
    }

    #[test]
    fn does_not_solicit_without_subscriber() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut harness = Harness::start(&mut context).await;
            select! {
                _ = harness.client_boundary_receiver.recv() => {
                    panic!("solicitation sent before any subscriber");
                },
                _ = context.sleep(Duration::from_millis(700)) => {},
            }
        });
    }

    #[test]
    fn late_subscriber_receives_cached_artifact() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut harness = Harness::start(&mut context).await;
            let mut first = harness.joiner.subscribe();
            harness.complete_target_sample();

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
    fn serving_answers_latest_request_from_marshal() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut harness = Harness::start(&mut context).await;
            harness.client_boundary_sender.send(
                Recipients::One(harness.participants[0].clone()),
                wire::Message::<mocks::TestScheme, mocks::TestMarshalVariant>::LatestRequest
                    .encode()
                    .to_vec(),
                false,
            );

            let (_peer, message) = harness
                .client_boundary_receiver
                .recv()
                .await
                .expect("latest response delivered");
            let response = wire::read_response::<mocks::TestScheme, mocks::TestMarshalVariant, _>(
                message,
                &harness.schemes[2].certificate_codec_config(),
            )
            .expect("latest response decoded")
            .expect("latest response");
            let wire::Response::Latest(finalization) = response else {
                panic!("expected latest response");
            };
            assert_eq!(finalization, harness.boundary_finalization);
        });
    }

    #[test]
    fn catch_up_retries_silent_peer_and_acquires_boundary() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut harness = Harness::start(&mut context).await;
            // Catchup can arrive before marshal attaches to the probe.
            harness
                .joiner
                .catch_up(Epoch::zero(), harness.participants[2].clone());
            let marshal = harness.attach_joiner(&context).await;
            assert_eq!(harness.next_client_boundary_request().await, Epoch::new(1));
            assert!(marshal.get_finalization(Height::new(1)).await.is_none());

            assert_eq!(
                Harness::next_boundary_request(&mut harness.backup_boundary_receiver).await,
                Epoch::new(1),
            );
            let block = loop {
                if let Some(block) = marshal.get_block(Height::new(1)).await {
                    break block;
                }
                context.sleep(Duration::from_millis(10)).await;
            };
            assert_eq!(block.digest(), harness.boundary.digest());
            assert_eq!(
                marshal.get_finalization(Height::new(1)).await,
                Some(harness.boundary_finalization),
            );
        });
    }

    #[test]
    fn catch_up_stops_after_processed_boundary_is_pruned() {
        let runner = deterministic::Runner::timed(Duration::from_secs(120));
        runner.start(|mut context| async move {
            let retry_timeout = Duration::from_secs(30);
            let fixture = mocks::scheme_fixture_n(&mut context, 4);
            let mut harness = Harness::start_full(
                &mut context,
                fixture,
                Vec::new(),
                Epoch::zero(),
                None,
                retry_timeout,
            )
            .await;
            let mut marshal = harness.attach_joiner(&context).await;
            let started = context.current();
            harness
                .joiner
                .catch_up(Epoch::zero(), harness.participants[2].clone());
            assert_eq!(harness.next_client_boundary_request().await, Epoch::new(1));

            let leader = harness.participants[1].clone();
            let mut parent = mocks::genesis_block(leader.clone());
            for height in 1..=15 {
                let epoch = Epoch::new(height / BLOCKS_PER_EPOCH.get());
                let parent_view = if epoch == parent.context().round.epoch() {
                    parent.context().round.view()
                } else {
                    View::zero()
                };
                let block_context = mocks::TestContext {
                    round: Round::new(epoch, View::new(height)),
                    leader: leader.clone(),
                    parent: (parent_view, parent.digest()),
                };
                let block = mocks::TestBlock::new::<Sha256>(
                    block_context.clone(),
                    parent.digest(),
                    Height::new(height),
                    height,
                );
                let certificate = finalization(
                    Proposal::new(block_context.round, parent_view, block.digest()),
                    &harness.schemes,
                );
                assert!(marshal.certified(block_context.round, block.clone()).await);
                if height == 1 {
                    harness.client_boundary_sender.send(
                        Recipients::One(harness.participants[1].clone()),
                        wire::Message::<mocks::TestScheme, mocks::TestMarshalVariant>::BoundaryResponse(
                            certificate,
                        )
                        .encode(),
                        false,
                    );
                } else {
                    assert_eq!(marshal.report(Activity::Finalization(certificate)), Feedback::Ok);
                }
                while marshal.get_processed().await.map(|processed| processed.height())
                    < Some(Height::new(height))
                {
                    context.sleep(Duration::from_millis(1)).await;
                }
                assert!(marshal.get_finalization(Height::new(height)).await.is_some());
                parent = block;
            }

            // Keep a full epoch and the current boundary after removing an old section.
            marshal.prune(Height::new(10));
            assert!(marshal.get_finalization(Height::new(1)).await.is_none());
            assert!(marshal.get_block(Height::new(1)).await.is_none());
            let retained = marshal.get_finalization(Height::new(15)).await.unwrap();
            assert!(context.current() < started + retry_timeout);

            select! {
                epoch = harness.next_client_boundary_request() => {
                    assert_eq!(epoch, Epoch::new(1));
                    panic!("processed catchup restarted after its boundary was pruned");
                },
                _ = context.sleep(retry_timeout * 2 + Duration::from_millis(10)) => {},
            }

            harness.client_boundary_sender.send(
                Recipients::One(harness.participants[1].clone()),
                wire::Message::<mocks::TestScheme, mocks::TestMarshalVariant>::BoundaryRequest(
                    Epoch::new(8),
                )
                .encode(),
                false,
            );
            let (_, response) = harness.client_boundary_receiver.recv().await.unwrap();
            let Some(wire::Response::Boundary(certificate)) =
                wire::read_response::<mocks::TestScheme, mocks::TestMarshalVariant, _>(
                    response,
                    &harness.schemes[1].certificate_codec_config(),
                )
                .unwrap()
            else {
                panic!("expected the retained boundary response");
            };
            assert_eq!(certificate, retained);
        });
    }

    #[test]
    fn catch_up_rejects_invalid_certificate_and_keeps_retrying() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut harness = Harness::start(&mut context).await;
            let marshal = harness.attach_joiner(&context).await;
            harness
                .joiner
                .catch_up(Epoch::zero(), harness.participants[2].clone());
            assert_eq!(harness.next_client_boundary_request().await, Epoch::new(1));

            let mut invalid = harness.boundary_finalization.clone();
            invalid.proposal.payload = mocks::TestDigest::EMPTY;
            harness.client_boundary_sender.send(
                Recipients::One(harness.participants[1].clone()),
                wire::Message::<mocks::TestScheme, mocks::TestMarshalVariant>::BoundaryResponse(
                    invalid,
                )
                .encode(),
                false,
            );
            context.sleep(Duration::from_millis(10)).await;
            assert!(marshal.get_finalization(Height::new(1)).await.is_none());
            assert!(harness.oracle.blocked().await.unwrap().contains(&(
                harness.participants[1].clone(),
                harness.participants[2].clone(),
            )));

            assert_eq!(
                Harness::next_boundary_request(&mut harness.backup_boundary_receiver).await,
                Epoch::new(1),
            );
            loop {
                if let Some(block) = marshal.get_block(Height::new(1)).await {
                    assert_eq!(block.digest(), harness.boundary.digest());
                    break;
                }
                context.sleep(Duration::from_millis(10)).await;
            }
        });
    }

    /// Each peer asked in a catch-up request round has at most one boundary
    /// response verified, and responses from peers outside the round are
    /// ignored. Invalid certificates expose verification by blocking the peer.
    #[test]
    fn catch_up_verifies_one_response_per_asked_peer_per_round() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut harness = Harness::start(&mut context).await;
            let _marshal = harness.attach_joiner(&context).await;
            let joiner = harness.participants[1].clone();
            let client = harness.participants[2].clone();
            harness.joiner.catch_up(Epoch::zero(), client.clone());
            assert_eq!(harness.next_client_boundary_request().await, Epoch::new(1));

            let response = |finalization| {
                wire::Message::<mocks::TestScheme, mocks::TestMarshalVariant>::BoundaryResponse(
                    finalization,
                )
                .encode()
            };
            let mut invalid = harness.boundary_finalization.clone();
            invalid.proposal.payload = mocks::TestDigest::EMPTY;
            let invalid = response(invalid);

            // The first round asks only the client, so the backup's response
            // is ignored.
            harness.backup_boundary_sender.send(
                Recipients::One(joiner.clone()),
                invalid.clone(),
                false,
            );

            // The client's first response is valid but names a block no peer
            // serves, so catch-up stays pending. Its later responses in the
            // same round are not verified.
            let unserved = harness.latest_finalization(Epoch::zero(), Sha256::hash(&[b"unserved"]));
            harness.client_boundary_sender.send(
                Recipients::One(joiner.clone()),
                response(unserved),
                false,
            );
            harness.client_boundary_sender.send(
                Recipients::One(joiner.clone()),
                invalid.clone(),
                false,
            );
            context.sleep(Duration::from_millis(100)).await;
            assert!(harness.oracle.blocked().await.unwrap().is_empty());

            // The retry round asks every peer again, so the client's next
            // response is verified.
            assert_eq!(harness.next_client_boundary_request().await, Epoch::new(1));
            harness
                .client_boundary_sender
                .send(Recipients::One(joiner.clone()), invalid, false);
            context.sleep(Duration::from_millis(100)).await;
            assert!(
                harness
                    .oracle
                    .blocked()
                    .await
                    .unwrap()
                    .contains(&(joiner, client))
            );
        });
    }

    #[test]
    fn serving_answers_finalization_and_block_requests_from_marshal() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut harness = Harness::start(&mut context).await;
            harness.client_boundary_sender.send(
                Recipients::One(harness.participants[0].clone()),
                wire::Message::<mocks::TestScheme, mocks::TestMarshalVariant>::BoundaryRequest(
                    Epoch::new(1),
                )
                .encode()
                .to_vec(),
                false,
            );

            let (_peer, message) = harness
                .client_boundary_receiver
                .recv()
                .await
                .expect("boundary response delivered");
            let response = wire::read_response::<mocks::TestScheme, mocks::TestMarshalVariant, _>(
                message,
                &harness.schemes[2].certificate_codec_config(),
            )
            .expect("boundary response decoded")
            .expect("boundary response");
            let wire::Response::Boundary(finalization) = response else {
                panic!("expected finalization response");
            };
            let commitment = finalization.proposal.payload;
            assert_eq!(finalization, harness.boundary_finalization);

            harness.client_boundary_sender.send(
                Recipients::One(harness.participants[0].clone()),
                wire::Message::<mocks::TestScheme, mocks::TestMarshalVariant>::BlockRequest(
                    Epoch::new(1),
                )
                .encode()
                .to_vec(),
                false,
            );
            let (_peer, message) = harness
                .client_boundary_receiver
                .recv()
                .await
                .expect("block response delivered");
            let response = wire::read_response::<mocks::TestScheme, mocks::TestMarshalVariant, _>(
                message,
                &harness.schemes[2].certificate_codec_config(),
            )
            .expect("block response decoded")
            .expect("block response");
            let wire::Response::Block { epoch, body } = response else {
                panic!("expected block response");
            };
            assert_eq!(epoch, Epoch::new(1));
            let block = wire::read_block::<mocks::TestMarshalVariant>(body, commitment, &())
                .expect("boundary block decoded");

            assert_eq!(block.digest(), harness.boundary.digest());
            assert_eq!(block.height(), Height::new(1));
        });
    }

    #[test]
    fn serving_ignores_epoch_without_boundary() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut harness = Harness::start(&mut context).await;
            harness.client_boundary_sender.send(
                Recipients::One(harness.participants[0].clone()),
                wire::Message::<mocks::TestScheme, mocks::TestMarshalVariant>::BoundaryRequest(
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

    #[test]
    fn address_failure_stops_probe_and_drops_subscriber() {
        let runner = deterministic::Runner::timed(Duration::from_secs(5));
        runner.start(|mut context| async move {
            let fixture = mocks::scheme_fixture_n(&mut context, 1);
            let participants = fixture.participants.clone();
            let (network, oracle) = Network::new_with_peers(
                context.child("network"),
                NetworkConfig {
                    max_size: 1024 * 1024,
                    max_peers_per_set: NZUsize!(participants.len()),
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
                participants.clone(),
            )
            .await;
            let network = network.start();
            let control = oracle.control(participants[0].clone());
            let boundaries = control
                .register(BOUNDARY_CHANNEL, TEST_QUOTA)
                .await
                .expect("failed to register boundaries");
            let genesis = genesis_info(&participants);
            let (actor, mailbox): (
                _,
                super::Mailbox<mocks::TestScheme, mocks::TestMarshalVariant>,
            ) = Actor::new(Config {
                context: context.child("probe"),
                manager: mocks::FailingManager(oracle.manager()),
                bootstrap: Bootstrap {
                    epoch: Epoch::zero(),
                    participants: genesis.participants(),
                    directory: Unit,
                },
                floor: None,
                verifier: fixture.schemes[0].clone(),
                genesis,
                strategy: Sequential,
                blocker: control,
                blocks_per_epoch: BLOCKS_PER_EPOCH,
                retry_timeout: NZDuration!(Duration::from_millis(500)),
                mailbox_size: NZUsize!(16),
                block_codec_config: (),
            });
            let handle = actor.start(boundaries);

            assert!(mailbox.subscribe().await.is_err());
            handle.await.expect("probe should stop cleanly");
            network.abort();
        });
    }
}
