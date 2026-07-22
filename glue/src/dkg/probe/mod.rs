//! Discover the public epoch material a joining node needs before consensus starts.
//!
//! A node that is starting fresh cannot construct epoch-scoped state until it learns the current
//! epoch's participant set. That set lives in the [`EpochInfo`] of a finalized boundary block.
//! The [`Actor`] discovers that block, publishes the resulting [`Artifact`] (which also carries
//! the state-sync floor), and then serves the same boundary material to other joining peers.
//!
//! This protocol is an extension of [`stateful::probe`](crate::stateful::probe): it begins with
//! the same solicit-and-sample floor discovery (built on the same shared sample core) and adds
//! requests for the floor epoch's boundary finalization and block, which carry the epoch's
//! public [`EpochInfo`].
//!
//! At startup the node knows a canonical participant snapshot (the complete dealer, player, and
//! next-player sets of a configured bootstrap epoch), a constant certificate verifier valid
//! across all epochs, and the epoch length. When discovery begins, the actor tracks the
//! snapshot's canonical peer set at the bootstrap epoch's own peer-set ID; the orchestrator
//! tracks identical contents if it later enters that epoch, so the registrations never
//! conflict. Solicitation, membership, and the fault budgets below all apply to the snapshot's
//! dealers: the epoch's active committee of share holders and certificate signers.
//!
//! # Trust Model
//!
//! The configured peers and constant verifier are the weakly subjective checkpoint for startup.
//! For `n` configured members, `f` is the maximum fault count under the `3f + 1` model and the
//! discovery sample threshold is `f + 1`.
//!
//! Rotation out of the active committee is not what the budgets bound: a rotated-out member that
//! keeps running an honest, chain-following node at its configured identity costs nothing. What
//! matters is what members do after rotating. At bootstrap time:
//!
//! - At most `f` members may be Byzantine or stale, where "stale" means honest but no longer
//!   following the chain. A frozen node replies honestly with an old finalization, which is
//!   indistinguishable from an adversarial replay, so it spends the same budget.
//! - At most `f` members may be unreachable (shut down, address changed, identity retired).
//!   These cost liveness only; they cannot inject anything.
//! - The remaining `f + 1` honest, current, reachable members guarantee both liveness (the
//!   sample completes) and recency (every `f + 1` sample contains at least one of them).
//!
//! Both budgets may be fully spent simultaneously. Operators should refresh the configured set
//! once they can no longer vouch that `f + 1` members remain live and current, exactly as one
//! refreshes a weak-subjectivity checkpoint. Passing a subset of the committee mis-derives `f`
//! and cannot be detected at startup; it is the same trust class as a wrong genesis.
//!
//! Certificate forgery is impossible regardless of these budgets: the threshold group key is
//! reshare-invariant and finalizations are self-certifying, so an old committee can never sign
//! for a round it did not finalize. Recency is the only weak-subjectivity dimension, and the
//! sample supplies exactly that. See [`stateful::probe`](crate::stateful::probe) for the
//! extended `f + 1` recency argument this actor inherits.
//!
//! # Protocol
//!
//! The actor is a two-state machine: it discovers an [`Artifact`], then serves boundary material.
//!
//! ## Discovery: solicit and sample
//!
//! Once a subscriber appears, [`Actor`] solicits every configured peer's latest finalization:
//!
//! ```text
//!                +-- LatestRequest --> peer 1
//!                |
//!   Actor -------+-- LatestRequest --> peer 2
//!                |
//!                +-- LatestRequest --> peer 3
//!
//!   peer 2 --LatestResponse(finalization)--> Actor
//! ```
//!
//! Replies are verified with the all-epoch verifier. At most one reply is counted per peer, only
//! configured members may reply, and replies below the bootstrap epoch are ignored (the chain
//! reached that epoch by definition, so any current member holds a finalization at or above its
//! boundary). Once `f + 1` distinct peers have replied, the highest finalization becomes the
//! state-sync floor and names the target epoch:
//!
//! ```text
//!   peer 1 --LatestResponse(round 10)-->\               replies
//!   peer 2 --LatestResponse(round 12)--> +-> Actor {10, 12, 13}
//!   peer 3 --LatestResponse(round 13)-->/                     |
//!                                                             v
//!                          sample reached, highest reply becomes the floor: 13
//! ```
//!
//! If too few peers reply before `retry_timeout`, collected replies are cleared and the
//! solicitation is re-issued. Retry is a liveness mechanism only.
//!
//! ## Discovery: boundary fetch
//!
//! The floor's epoch identifies the target epoch, but not its boundary block. The actor asks
//! every peer for the boundary finalization. These responses are small, so peers can answer in
//! parallel without duplicating the boundary block:
//!
//! ```text
//!                +-- BoundaryRequest(epoch) --> peer 1
//!                |
//!   Actor -------+-- BoundaryRequest(epoch) --> peer 2
//!                |
//!                +-- BoundaryRequest(epoch) --> peer 3
//!
//!   peer 2 --BoundaryResponse(finalization)--> Actor
//! ```
//!
//! After verifying a boundary finalization, the actor requests its committed block only from that
//! responder. Other verified responders are retained as failover candidates:
//!
//! ```text
//!   Actor --BlockRequest(epoch)-------> peer 2
//!   peer 2 --BlockResponse(epoch, block)--> Actor
//! ```
//!
//! The block's [`EpochInfo`] is packaged into an [`Artifact`] together with the sampled floor and
//! published to subscribers. The floor and the epoch info are fixed atomically, so the artifact's
//! epoch always equals the floor's epoch:
//!
//! ```text
//!   floor + boundary finalization + boundary block
//!       --> Artifact { epoch, finalization, info, floor }
//! ```
//!
//! A floor in epoch zero resolves from the locally known genesis info without a boundary fetch.
//!
//! ## Serving
//!
//! After a source of finalized blocks is attached, the actor enters service and answers peers'
//! latest-finalization, boundary finalization, and boundary block requests for the rest of the
//! process lifetime:
//!
//! ```text
//!   peer --LatestRequest---------------> Actor --lookup--> LatestResponse -------> peer
//!   peer --BoundaryRequest(epoch)-----> Actor --lookup--> BoundaryResponse -----> peer
//!   peer --BlockRequest(epoch)---------> Actor --lookup--> BlockResponse --------> peer
//! ```
//!
//! An epoch with no known boundary block is answered with nothing, as is a latest-finalization
//! request when marshal has no finalization yet.

use crate::dkg::{
    ReshareBlock,
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

mod actor;
pub use actor::{Actor, Config};

mod mailbox;
pub use mailbox::Mailbox;

mod wire;

/// The weakly subjective checkpoint a joining node bootstraps from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bootstrap<P: PublicKey> {
    /// Epoch whose participant snapshot is [`Bootstrap::participants`].
    ///
    /// Latest-finalization replies below this epoch are ignored, so the
    /// discovered floor is never older than the configured trust point.
    pub epoch: Epoch,
    /// The complete participant snapshot of [`Bootstrap::epoch`].
    ///
    /// Discovery solicits and samples `f + 1` of the snapshot's dealers,
    /// which are the epoch's active committee (its share holders and
    /// certificate signers), so the dealers must be that complete committee:
    /// a subset mis-derives `f`. See the module docs for the trust model and
    /// the budgets on faulty, stale, and unreachable members.
    ///
    /// The snapshot must match the epoch's canonical [`Participants`]: when
    /// discovery begins, the actor tracks the snapshot's
    /// [`tracked_peers`](Participants::tracked_peers) at the epoch's own
    /// peer-set ID, and all peers must track the same set contents at the
    /// same ID. The orchestrator tracks the identical contents if it later
    /// enters the bootstrap epoch, so the duplicate registration is benign.
    pub participants: Participants<P>,
}

/// Concrete probe artifact for a marshal variant.
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
    /// Finalization of the boundary block that carried the epoch info.
    ///
    /// Epoch zero is anchored by genesis and has no boundary finalization.
    pub finalization: Option<Finalization<S, D>>,
    /// Public epoch information from the finalized boundary block.
    pub info: EpochInfo<V, S::PublicKey>,
    /// Highest finalization from the `f + 1` peer sample.
    ///
    /// This is the state-sync floor: it is at least as recent as the freshest
    /// honest reply in the sample.
    pub floor: Finalization<S, D>,
}

#[cfg(test)]
mod tests {
    use super::{Actor, Bootstrap, Config, wire};
    use crate::dkg::{
        probe::Artifact,
        tests::mocks,
        types::{EpochInfo, EpochOutcome, Payload},
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
        Receiver as _, Recipients, Sender as _,
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
    use commonware_storage::archive::immutable;
    use commonware_utils::{
        N3f1, NZDuration, NZU16, NZU32, NZU64, NZUsize, TestRng, channel::oneshot, ordered::Set,
    };
    use std::{num::NonZeroU64, time::Duration};

    const BACKFILL_CHANNEL: u64 = 0;
    const BOUNDARY_CHANNEL: u64 = 1;
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
            Self::start_full(context, source_boundaries, Epoch::zero()).await
        }

        async fn start_full(
            context: &mut deterministic::Context,
            source_boundaries: Vec<Epoch>,
            bootstrap_epoch: Epoch,
        ) -> Self {
            let fixture = mocks::scheme_fixture_n(context, 4);
            let participants = fixture.participants.clone();

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
                },
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
                },
                verifier: fixture.schemes[1].clone(),
                genesis,
                strategy: Sequential,
                blocker: oracle.control(participants[1].clone()),
                blocks_per_epoch: BLOCKS_PER_EPOCH,
                retry_timeout: NZDuration!(Duration::from_millis(500)),
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
                provider: mocks::TestProvider::new(schemes[index].clone()),
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                start: Start::Genesis(mocks::genesis_block(public_key)),
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

    #[test]
    fn ignores_latest_reply_below_bootstrap_epoch() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut harness =
                Harness::start_full(&mut context, vec![Epoch::new(1)], Epoch::new(1)).await;
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
                    block: harness.boundary.clone(),
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
                    block: harness.boundary.clone(),
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
                    block: wrong_block,
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
                    block: harness.boundary.clone(),
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
                .encode()
                .to_vec();
            let decoded = wire::read_response::<mocks::TestScheme, mocks::TestMarshalVariant, _>(
                message.as_slice(),
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
}
