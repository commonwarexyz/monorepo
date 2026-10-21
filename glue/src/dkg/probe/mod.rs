//! Discovery of the public epoch material a joining node needs before consensus starts.
//!
//! A node that is starting fresh cannot construct epoch-scoped state until it learns the current
//! epoch's participant set. That set lives in the [`EpochInfo`] of a finalized boundary block.
//! The [`Actor`] discovers that block and the dealer logs the state-sync floor skipped, publishes
//! the resulting [`Artifact`] (which also carries the floor), and then serves the same material to
//! other joining peers.
//!
//! This protocol extends [`stateful::probe`](crate::stateful::probe): it begins with the same
//! solicit-and-sample floor discovery and adds requests for the floor epoch's boundary
//! finalization and block, which carry the epoch's public [`EpochInfo`], and for the finalized
//! blocks between the epoch's midpoint and the floor.
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
//! solicitation is re-issued. A persisted [`Config::floor`] at a later round than the sampled
//! floor replaces it, so a resumed sync describes the floor marshal starts from.
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
//! A floor in epoch zero takes the locally known genesis info without a boundary fetch.
//!
//! ## Discovery: inclusion window
//!
//! Marshal neither stores nor repairs finalized blocks below the floor, so the dealer logs of
//! the blocks between the floor epoch's midpoint and the floor would otherwise never reach the
//! reshare actor. The actor fetches the floor block by its commitment from the responder that
//! served the boundary block, with the other verified responders (the snapshot's dealers for
//! epoch zero) as fallbacks, and reads the floor's height from the authenticated block. For a
//! floor in the late phase of its epoch it then walks parent links down to the midpoint,
//! requesting each parent by the commitment its child carries, so every block is bound to the
//! floor's finalization. A block that does not match its commitment blocks its sender and the
//! walk continues with the next responder; a silent responder is replaced after
//! `retry_timeout`.
//!
//! ```text
//!   peer 2 <---AncestorRequest(floor commitment)--- Actor
//!   peer 2 ---AncestorResponse(commitment, block)-> Actor
//!                                                   |
//!                                  floor late in its epoch: walk parents
//!                                                   |
//!   peer 2 <---AncestorRequest(parent commitment)-- Actor     (repeat down to the midpoint)
//!   peer 2 ---AncestorResponse(commitment, block)-> Actor
//! ```
//!
//! The window's dealer logs, in ascending height order, are packaged into an [`Artifact`]
//! together with the floor and the epoch info and published to subscribers. [`Artifact::info`]
//! always describes the epoch of [`Artifact::floor`], and [`Artifact::window`] is complete for
//! that floor: a walk that cannot complete keeps retrying rather than publishing a floor
//! without its window.
//!
//! ## Serving
//!
//! Once marshal is attached and no subscriber is pending, the actor enters service and answers
//! peers' latest-finalization, boundary finalization, boundary block, and ancestor requests for
//! the rest of the process lifetime. Ancestor requests are answered from marshal's block storage
//! (see [Marshal Retention](crate::dkg#marshal-retention) for what peers must keep).
//!
//! An epoch with no known boundary block or a commitment with no stored block is answered with
//! nothing, as is a latest-finalization request when marshal has no finalization yet.

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
    Digest, PublicKey, Signer,
    bls12381::{dkg::feldman_desmedt::SignedDealerLog, primitives::variant::Variant as BlsVariant},
    certificate::Verifier,
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
    <<V as MarshalVariant>::ApplicationBlock as ReshareBlock>::Signer,
    <<V as MarshalVariant>::ApplicationBlock as ReshareBlock>::Directory,
>;

/// Epoch info carried by a marshal variant's blocks.
pub(crate) type ActorInfo<S, V> = EpochInfo<
    <<V as MarshalVariant>::ApplicationBlock as ReshareBlock>::Variant,
    <S as Verifier>::PublicKey,
    <<V as MarshalVariant>::ApplicationBlock as ReshareBlock>::Directory,
>;

/// Public epoch material discovered during bootstrap.
#[derive(Clone, Debug, PartialEq)]
pub struct Artifact<S, D, V, C, Dir = Unit>
where
    S: Scheme<D>,
    D: Digest,
    V: BlsVariant,
    C: Signer,
    Dir: Directory<S::PublicKey>,
{
    /// Finalization of the boundary block that carried the epoch info.
    ///
    /// Epoch zero is anchored by genesis and has no boundary finalization.
    pub finalization: Option<Finalization<S, D>>,
    /// Public epoch information for the epoch of [`Artifact::floor`] (the genesis
    /// information for epoch zero).
    pub info: EpochInfo<V, S::PublicKey, Dir>,
    /// The state-sync floor: the highest finalization from the `f + 1` peer
    /// sample, or the persisted [`Config::floor`] when that is at a later round.
    ///
    /// It is at least as recent as the freshest honest reply in the sample.
    pub floor: Finalization<S, D>,
    /// Dealer logs carried by the finalized blocks from the floor epoch's
    /// midpoint up to the floor's parent, in ascending height order.
    ///
    /// Empty unless the floor is in the late phase of its epoch. Signatures are
    /// not checked: the reshare actor applies the same checks it applies to
    /// logs delivered by marshal.
    pub window: Vec<SignedDealerLog<V, C>>,
}

#[cfg(test)]
mod tests {
    use super::{Actor, Bootstrap, Config, wire};
    use crate::{
        dkg::{
            ReshareBlock as _,
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
        Digest as _, Digested, Digestible as _, Hasher as _, Signer as _,
        bls12381::{
            dkg::feldman_desmedt::{Dealer, Info, Reveal, SignedDealerLog, deal},
            primitives::sharing::{Mode, Sharing},
        },
        certificate::Verifier as _,
        ed25519,
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
    use commonware_storage::archive::immutable;
    use commonware_utils::{
        N3f1, NZDuration, NZU16, NZU32, NZU64, NZUsize, TestRng, channel::oneshot, non_empty,
        ordered::Set, probability, sequence::Unit, test_rng,
    };
    use std::{num::NonZeroU64, time::Duration};

    const BACKFILL_CHANNEL: u64 = 0;
    const BOUNDARY_CHANNEL: u64 = 1;
    const TEST_QUOTA: Quota = Quota::per_second(NZU32!(1_000_000));
    /// Long enough for an epoch to have a late phase of several blocks.
    const BLOCKS_PER_EPOCH: NonZeroU64 = NZU64!(8);
    const LOG_NAMESPACE: &[u8] = b"_COMMONWARE_GLUE_DKG_PROBE_TEST";
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
        /// First block of epoch 1, which floors in epoch 1 commit to.
        floor: mocks::TestBlock,
        floor_finalization: Finalization<mocks::TestScheme, mocks::TestDigest>,
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
            Self::start_full(context, fixture, source_boundaries, Epoch::zero(), None).await
        }

        async fn start_full(
            context: &mut deterministic::Context,
            fixture: mocks::SchemeFixture,
            source_boundaries: Vec<Epoch>,
            bootstrap_epoch: Epoch,
            floor: Option<Finalization<mocks::TestScheme, mocks::TestDigest>>,
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
            let first_floor = floor_block(Epoch::new(1), participants[0].clone(), &participants);
            let first_floor_finalization =
                floor_finalization(Epoch::new(1), first_floor.digest(), &fixture.schemes);

            // The source serves each epoch's boundary block and the floor block
            // that floors in that epoch commit to.
            let source_boundaries = source_boundaries
                .into_iter()
                .flat_map(|epoch| {
                    let (block, _) = boundary_block(epoch, participants[0].clone(), &participants);
                    let finalization =
                        boundary_finalization(epoch, block.digest(), &fixture.schemes);
                    let floor = floor_block(epoch, participants[0].clone(), &participants);
                    let floor_finalization =
                        floor_finalization(epoch, floor.digest(), &fixture.schemes);
                    [(block, finalization), (floor, floor_finalization)]
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
                floor: first_floor,
                floor_finalization: first_floor_finalization,
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
        /// to the epoch-1 floor block.
        fn target_finalization(&self) -> Finalization<mocks::TestScheme, mocks::TestDigest> {
            self.latest_finalization(Epoch::new(1), self.floor.digest())
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

        async fn next_request(
            receiver: &mut SimReceiver<mocks::TestPublicKey>,
        ) -> wire::Request<mocks::TestDigest> {
            let (_, message) = receiver.recv().await.expect("boundary request");
            wire::read_request::<mocks::TestDigest>(message)
                .expect("decode boundary request")
                .expect("boundary request tag")
        }

        async fn expect_latest_request(receiver: &mut SimReceiver<mocks::TestPublicKey>) {
            match Self::next_request(receiver).await {
                wire::Request::Latest => {}
                wire::Request::Boundary(_)
                | wire::Request::Block(_)
                | wire::Request::Ancestor(_) => {
                    panic!("expected latest request")
                }
            }
        }

        async fn next_boundary_request(receiver: &mut SimReceiver<mocks::TestPublicKey>) -> Epoch {
            match Self::next_request(receiver).await {
                wire::Request::Boundary(epoch) => epoch,
                wire::Request::Block(_) | wire::Request::Latest | wire::Request::Ancestor(_) => {
                    panic!("expected finalization request")
                }
            }
        }

        async fn next_block_request(receiver: &mut SimReceiver<mocks::TestPublicKey>) -> Epoch {
            match Self::next_request(receiver).await {
                wire::Request::Block(epoch) => epoch,
                wire::Request::Boundary(_) | wire::Request::Latest | wire::Request::Ancestor(_) => {
                    panic!("expected block request")
                }
            }
        }

        async fn next_ancestor_request(
            receiver: &mut SimReceiver<mocks::TestPublicKey>,
        ) -> mocks::TestDigest {
            match Self::next_request(receiver).await {
                wire::Request::Ancestor(commitment) => commitment,
                wire::Request::Boundary(e) => panic!("expected ancestor request, got boundary {e}"),
                wire::Request::Block(e) => panic!("expected ancestor request, got block {e}"),
                wire::Request::Latest => panic!("expected ancestor request, got latest"),
            }
        }

        async fn next_client_boundary_request(&mut self) -> Epoch {
            Self::next_boundary_request(&mut self.client_boundary_receiver).await
        }

        /// Completes the sample with `floor`, then serves the boundary
        /// finalization and block from the client, with the backup also
        /// answering the finalization request so both are verified
        /// responders. Returns once the client has received the first
        /// inclusion-window request.
        async fn serve_boundary_with_floor(
            &mut self,
            context: &deterministic::Context,
            floor: Finalization<mocks::TestScheme, mocks::TestDigest>,
        ) -> mocks::TestDigest {
            Self::expect_latest_request(&mut self.client_boundary_receiver).await;
            Self::expect_latest_request(&mut self.backup_boundary_receiver).await;
            self.reply_latest_from_client(floor.clone());
            self.reply_latest_from_backup(floor);

            assert_eq!(self.next_client_boundary_request().await, Epoch::new(1));
            assert_eq!(
                Self::next_boundary_request(&mut self.backup_boundary_receiver).await,
                Epoch::new(1)
            );
            let boundary_response =
                wire::Message::<mocks::TestScheme, mocks::TestMarshalVariant>::BoundaryResponse(
                    self.boundary_finalization.clone(),
                )
                .encode()
                .to_vec();
            self.client_boundary_sender.send(
                Recipients::One(self.participants[1].clone()),
                boundary_response.clone(),
                false,
            );
            assert_eq!(
                Self::next_block_request(&mut self.client_boundary_receiver).await,
                Epoch::new(1)
            );

            // The backup's finalization lands before the boundary block, so it
            // is a verified responder when the walk begins.
            self.backup_boundary_sender.send(
                Recipients::One(self.participants[1].clone()),
                boundary_response,
                false,
            );
            context.sleep(Duration::from_millis(10)).await;
            self.client_boundary_sender.send(
                Recipients::One(self.participants[1].clone()),
                wire::Message::<mocks::TestScheme, mocks::TestMarshalVariant>::BlockResponse {
                    epoch: Epoch::new(1),
                    block: Digested::precomputed(self.boundary.clone(), self.boundary.digest()),
                }
                .encode()
                .to_vec(),
                false,
            );
            Self::next_ancestor_request(&mut self.client_boundary_receiver).await
        }

        fn ancestor_response(block: &mocks::TestBlock) -> Vec<u8> {
            wire::Message::<mocks::TestScheme, mocks::TestMarshalVariant>::AncestorResponse {
                commitment: block.digest(),
                block: Digested::precomputed(block.clone(), block.digest()),
            }
            .encode()
            .to_vec()
        }

        fn reply_ancestor_from_client(&mut self, block: &mocks::TestBlock) {
            self.client_boundary_sender.send(
                Recipients::One(self.participants[1].clone()),
                Self::ancestor_response(block),
                false,
            );
        }

        fn reply_ancestor_from_backup(&mut self, block: &mocks::TestBlock) {
            self.backup_boundary_sender.send(
                Recipients::One(self.participants[1].clone()),
                Self::ancestor_response(block),
                false,
            );
        }

        /// Answers the client's request for the epoch-1 floor block.
        async fn serve_floor_from_client(&mut self) {
            let requested = Self::next_ancestor_request(&mut self.client_boundary_receiver).await;
            assert_eq!(requested, self.floor.digest());
            let floor = self.floor.clone();
            self.reply_ancestor_from_client(&floor);
        }

        /// Answers the backup's request for the epoch-1 floor block.
        async fn serve_floor_from_backup(&mut self) {
            let requested = Self::next_ancestor_request(&mut self.backup_boundary_receiver).await;
            assert_eq!(requested, self.floor.digest());
            let floor = self.floor.clone();
            self.reply_ancestor_from_backup(&floor);
        }

        /// Serves `blocks`, newest first, from the client, checking that each
        /// request names the block about to be served.
        async fn serve_window_from_client(
            &mut self,
            mut requested: mocks::TestDigest,
            blocks: &[mocks::TestBlock],
        ) {
            for (index, block) in blocks.iter().rev().enumerate() {
                if index > 0 {
                    requested =
                        Self::next_ancestor_request(&mut self.client_boundary_receiver).await;
                }
                assert_eq!(requested, block.digest());
                self.reply_ancestor_from_client(block);
            }
        }
    }

    /// A signed dealer log from the signer at `index`.
    fn dealer_log(index: u64) -> SignedDealerLog<mocks::TestBlsVariant, mocks::TestSigner> {
        let signers = (0..4)
            .map(ed25519::PrivateKey::from_seed)
            .collect::<Vec<_>>();
        let players = Set::from_iter_dedup(signers.iter().map(ed25519::PrivateKey::public_key));
        let info = Info::<mocks::TestBlsVariant, _>::new::<N3f1>(
            LOG_NAMESPACE,
            1,
            None,
            Mode::NonZeroCounter,
            Reveal::V1,
            players.clone(),
            players,
        )
        .expect("valid info");
        let signer = signers[index as usize % signers.len()].clone();
        let (dealer, _, _) =
            Dealer::start::<N3f1>(test_rng(), info, signer, None).expect("dealer should start");
        dealer.finalize::<N3f1>()
    }

    /// Builds the epoch-1 blocks from the midpoint up to `floor`, linked by
    /// parent digest, each carrying the dealer log of its height.
    fn window_chain(leader: mocks::TestPublicKey, floor: Height) -> Vec<mocks::TestBlock> {
        let midpoint = FixedEpocher::new(BLOCKS_PER_EPOCH)
            .midpoint(Epoch::new(1))
            .expect("test epoch must be supported");
        let mut parent = Sha256::hash(&[b"below the window"]);
        let mut blocks = Vec::new();
        for height in midpoint.get()..=floor.get() {
            let context = mocks::TestContext {
                round: Round::new(Epoch::new(1), View::new(height)),
                leader: leader.clone(),
                parent: (View::zero(), parent),
            };
            let block = mocks::TestBlock::new::<Sha256>(context, parent, Height::new(height), 0)
                .with_payload::<Sha256, mocks::TestBlsVariant, mocks::TestSigner>(
                NZU32!(16),
                Payload::DealerLog(dealer_log(height)),
            );
            parent = block.digest();
            blocks.push(block);
        }
        blocks
    }

    /// The dealer logs `blocks` carry, in order.
    fn logs_of(
        blocks: &[mocks::TestBlock],
    ) -> Vec<SignedDealerLog<mocks::TestBlsVariant, mocks::TestSigner>> {
        blocks
            .iter()
            .map(|block| match block.payload() {
                Some(Payload::DealerLog(log)) => log,
                _ => panic!("window block must carry a dealer log"),
            })
            .collect()
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

        let genesis = mocks::genesis_block(public_key);
        let (marshal_actor, mut marshal, _) = marshal::core::Actor::init(
            context.child("marshal"),
            finalizations_by_height,
            finalized_blocks,
            marshal::Config {
                provider: mocks::TestProvider::new(schemes[index].clone()),
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                start: Start::Genesis(Digested::precomputed(genesis.clone(), genesis.digest())),
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
            assert!(
                marshal
                    .certified(
                        block.context().round,
                        Digested::precomputed(block.clone(), block.digest())
                    )
                    .await
            );
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

    /// The first block of `epoch`, extending its boundary block. Its round
    /// differs from the round of the next epoch's boundary block.
    fn floor_block(
        epoch: Epoch,
        leader: mocks::TestPublicKey,
        participants: &[mocks::TestPublicKey],
    ) -> mocks::TestBlock {
        let (boundary, _) = boundary_block(epoch, leader.clone(), participants);
        let height = FixedEpocher::new(BLOCKS_PER_EPOCH)
            .first(epoch)
            .expect("test epoch must be supported");
        let context = mocks::TestContext {
            round: Round::new(epoch, View::new(2)),
            leader,
            parent: (View::zero(), boundary.digest()),
        };
        mocks::TestBlock::new::<Sha256>(context, boundary.digest(), height, epoch.get())
    }

    fn floor_finalization(
        epoch: Epoch,
        digest: mocks::TestDigest,
        schemes: &[mocks::TestScheme],
    ) -> Finalization<mocks::TestScheme, mocks::TestDigest> {
        finalization(
            Proposal::new(Round::new(epoch, View::new(2)), View::new(1), digest),
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
        artifact: Artifact<
            mocks::TestScheme,
            mocks::TestDigest,
            mocks::TestBlsVariant,
            mocks::TestSigner,
        >,
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
            // The source can serve the epoch-2 boundary and floor blocks.
            let mut harness =
                Harness::start_with_boundaries(&mut context, vec![Epoch::new(2)]).await;
            let mut subscription = harness.joiner.subscribe();

            let (newer_boundary, newer_sharing) = boundary_block(
                Epoch::new(2),
                harness.participants[0].clone(),
                &harness.participants,
            );
            let newer_floor = floor_block(
                Epoch::new(2),
                harness.participants[0].clone(),
                &harness.participants,
            );
            let stale = harness.latest_finalization(Epoch::new(1), Sha256::hash(&[b"stale"]));
            let newest = harness.latest_finalization(Epoch::new(2), newer_floor.digest());
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
    fn genesis_floor_resolves_without_boundary_fetch() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut harness = Harness::start_with(&mut context, false).await;
            let mut subscription = harness.joiner.subscribe();
            Harness::expect_latest_request(&mut harness.client_boundary_receiver).await;

            // The whole sample reports epoch-zero finalizations: the artifact
            // resolves from the locally known genesis info once the floor
            // block, which the source serves, is fetched.
            let genesis = mocks::genesis_block(harness.participants[0].clone());
            let floor = harness.latest_finalization(Epoch::zero(), genesis.digest());
            harness.reply_latest_from_client(floor.clone());
            harness.reply_latest_from_backup(floor.clone());

            select! {
                _ = harness.client_boundary_receiver.recv() => {
                    panic!("boundary request sent for an epoch-zero floor");
                },
                _ = context.sleep(Duration::from_millis(100)) => {},
            }
            let artifact = subscription.try_recv().expect("genesis resolved");
            assert_eq!(artifact.info.epoch, Epoch::zero());
            assert!(artifact.finalization.is_none());
            assert_eq!(artifact.info, genesis_info(&harness.participants));
            assert_eq!(artifact.floor, floor);
            assert!(artifact.window.is_empty());
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
    /// it resumes from, and resolves the persisted floor itself when the sample
    /// is not newer. The bootstrap committee is tracked at the bootstrap epoch's
    /// peer-set ID, not the floor's.
    #[test]
    fn ignores_latest_reply_below_floor_epoch() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            // Select an in-progress floor in epoch 2, which persists it, then
            // reload it as a restarted node.
            let fixture = mocks::scheme_fixture_n(&mut context, 4);
            let floor = floor_block(
                Epoch::new(2),
                fixture.participants[0].clone(),
                &fixture.participants,
            );
            let persisted = finalization(
                Proposal::new(
                    Round::new(Epoch::new(2), View::new(3)),
                    View::new(2),
                    floor.digest(),
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

            // Replies in the floor's epoch resolve that epoch's info for the
            // persisted floor, whose round is later than the sampled one. The
            // network starts with only set 0, so set 1 proves the committee is
            // tracked at the bootstrap epoch's ID rather than the floor's.
            let sampled = harness.latest_finalization(Epoch::new(2), floor.digest());
            harness.reply_latest_from_client(sampled.clone());
            harness.reply_latest_from_backup(sampled.clone());
            context.sleep(Duration::from_millis(100)).await;
            let artifact = subscription.try_recv().expect("artifact resolved");
            assert_eq!(artifact.floor, persisted);
            assert_eq!(artifact.info.epoch, Epoch::new(2));
            let mut manager = harness.oracle.manager();
            assert!(manager.peer_set(1).await.is_some());
            assert!(manager.peer_set(2).await.is_none());

            // The plan keeps the persisted floor, and the DKG startup material
            // pairs the plan's floor with the discovered info.
            let plan = plan.set_floor(artifact.floor.clone()).await;
            assert_eq!(plan.floor(), Some(&persisted));
            StateSyncPlan::init(
                context.child("dkg"),
                StateSyncConfig {
                    partition_prefix: "floor".into(),
                    max_participants: NZU32!(16),
                    max_supported_mode: max_supported_mode(),
                    blocks_per_epoch: BLOCKS_PER_EPOCH,
                },
                Some(StateSync {
                    info: artifact.info,
                    floor: plan.floor().cloned().expect("resumed floor"),
                    window: artifact.window,
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
                    block: Digested::precomputed(
                        harness.boundary.clone(),
                        harness.boundary.digest(),
                    ),
                }
                .encode()
                .to_vec(),
                false,
            );
            harness.serve_floor_from_client().await;
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
                    block: Digested::precomputed(
                        harness.boundary.clone(),
                        harness.boundary.digest(),
                    ),
                }
                .encode()
                .to_vec(),
                false,
            );
            harness.serve_floor_from_backup().await;
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
                    block: Digested::precomputed(wrong_block.clone(), wrong_block.digest()),
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
                    block: Digested::precomputed(
                        harness.boundary.clone(),
                        harness.boundary.digest(),
                    ),
                }
                .encode()
                .to_vec(),
                false,
            );
            harness.serve_floor_from_backup().await;
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
            assert_eq!(finalization, harness.floor_finalization);
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
            let block =
                wire::read_block::<mocks::TestMarshalVariant>(body, commitment, &(), &Sequential)
                    .await
                    .expect("boundary block decoded");

            assert_eq!(block.digest(), harness.boundary.digest());
            assert_eq!(block.height(), harness.boundary.height());
        });
    }

    #[test]
    fn serving_answers_ancestor_request_from_marshal() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut harness = Harness::start(&mut context).await;
            let commitment = harness.boundary.digest();
            harness.client_boundary_sender.send(
                Recipients::One(harness.participants[0].clone()),
                wire::Message::<mocks::TestScheme, mocks::TestMarshalVariant>::AncestorRequest(
                    commitment,
                )
                .encode()
                .to_vec(),
                false,
            );

            let (_peer, message) = harness
                .client_boundary_receiver
                .recv()
                .await
                .expect("ancestor response delivered");
            let response = wire::read_response::<mocks::TestScheme, mocks::TestMarshalVariant, _>(
                message,
                &harness.schemes[2].certificate_codec_config(),
            )
            .expect("ancestor response decoded")
            .expect("ancestor response");
            let wire::Response::Ancestor {
                commitment: echoed,
                body,
            } = response
            else {
                panic!("expected ancestor response");
            };
            assert_eq!(echoed, commitment);
            let block =
                wire::read_block::<mocks::TestMarshalVariant>(body, commitment, &(), &Sequential)
                    .await
                    .expect("ancestor block decoded");
            assert_eq!(block.digest(), harness.boundary.digest());

            // A block marshal does not have is answered with nothing.
            harness.client_boundary_sender.send(
                Recipients::One(harness.participants[0].clone()),
                wire::Message::<mocks::TestScheme, mocks::TestMarshalVariant>::AncestorRequest(
                    Sha256::hash(&[b"unknown"]),
                )
                .encode()
                .to_vec(),
                false,
            );
            select! {
                _ = harness.client_boundary_receiver.recv() => {
                    panic!("ancestor response delivered for an unknown block");
                },
                _ = context.sleep(Duration::from_millis(100)) => {},
            };
        });
    }

    /// A floor in the late phase of its epoch resolves with the dealer logs of
    /// the blocks from the midpoint up to the floor's parent, in ascending
    /// height order, and the walk asks for nothing below the midpoint.
    #[test]
    fn late_floor_fetches_inclusion_window() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut harness = Harness::start_with(&mut context, false).await;
            let mut subscription = harness.joiner.subscribe();

            let floor_height = FixedEpocher::new(BLOCKS_PER_EPOCH)
                .last(Epoch::new(1))
                .expect("test epoch must be supported");
            let chain = window_chain(harness.participants[0].clone(), floor_height);
            let floor_block = chain.last().expect("chain must reach the floor");
            let floor = harness.latest_finalization(Epoch::new(1), floor_block.digest());

            let requested = harness
                .serve_boundary_with_floor(&context, floor.clone())
                .await;
            harness.serve_window_from_client(requested, &chain).await;

            select! {
                _ = harness.client_boundary_receiver.recv() => {
                    panic!("walk requested a block below the midpoint");
                },
                _ = context.sleep(Duration::from_millis(100)) => {},
            }
            let artifact = subscription.try_recv().expect("artifact resolved");
            assert_eq!(artifact.floor, floor);
            assert_eq!(artifact.window, logs_of(&chain[..chain.len() - 1]));
            assert_artifact(
                artifact,
                &harness.boundary_finalization,
                &harness.boundary_sharing,
                &harness.participants,
            );
            let blocked = harness.oracle.blocked().await.unwrap();
            assert!(
                blocked.is_empty(),
                "valid window blocks must not block peers"
            );
        });
    }

    /// A floor at or before the midpoint resolves with an empty window once the
    /// floor block is authenticated, without asking for its parent.
    #[rstest::rstest]
    #[case::early(2)]
    #[case::midpoint(4)]
    fn floor_before_late_phase_yields_no_window(#[case] relative: u64) {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut harness = Harness::start_with(&mut context, false).await;
            let mut subscription = harness.joiner.subscribe();

            let first = FixedEpocher::new(BLOCKS_PER_EPOCH)
                .first(Epoch::new(1))
                .expect("test epoch must be supported");
            let floor_height = Height::new(first.get() + relative);
            let context_for = |parent| mocks::TestContext {
                round: Round::new(Epoch::new(1), View::new(relative)),
                leader: harness.participants[0].clone(),
                parent: (View::zero(), parent),
            };
            let parent = Sha256::hash(&[b"floor parent"]);
            let floor_block =
                mocks::TestBlock::new::<Sha256>(context_for(parent), parent, floor_height, 0)
                    .with_payload::<Sha256, mocks::TestBlsVariant, mocks::TestSigner>(
                    NZU32!(16),
                    Payload::DealerLog(dealer_log(relative)),
                );
            let floor = harness.latest_finalization(Epoch::new(1), floor_block.digest());

            let requested = harness
                .serve_boundary_with_floor(&context, floor.clone())
                .await;
            assert_eq!(requested, floor_block.digest());
            harness.reply_ancestor_from_client(&floor_block);

            select! {
                _ = harness.client_boundary_receiver.recv() => {
                    panic!("walk requested the parent of a floor before the late phase");
                },
                _ = context.sleep(Duration::from_millis(100)) => {},
            }
            let artifact = subscription.try_recv().expect("artifact resolved");
            assert_eq!(artifact.floor, floor);
            assert!(artifact.window.is_empty());
        });
    }

    /// A window block that does not match the requested commitment blocks its
    /// sender, and the walk continues with another verified responder.
    #[test]
    fn invalid_window_block_tries_another_responder_immediately() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut harness = Harness::start_with(&mut context, false).await;
            let mut subscription = harness.joiner.subscribe();

            let floor_height = FixedEpocher::new(BLOCKS_PER_EPOCH)
                .last(Epoch::new(1))
                .expect("test epoch must be supported");
            let chain = window_chain(harness.participants[0].clone(), floor_height);
            let floor_block = chain.last().expect("chain must reach the floor");
            let floor = harness.latest_finalization(Epoch::new(1), floor_block.digest());

            // The client serves the floor block, then answers the request for
            // its parent with the block below it.
            let requested = harness.serve_boundary_with_floor(&context, floor.clone()).await;
            assert_eq!(requested, floor_block.digest());
            harness.reply_ancestor_from_client(floor_block);
            let requested = Harness::next_ancestor_request(&mut harness.client_boundary_receiver).await;
            let parent = &chain[chain.len() - 2];
            assert_eq!(requested, parent.digest());
            harness.client_boundary_sender.send(
                Recipients::One(harness.participants[1].clone()),
                wire::Message::<mocks::TestScheme, mocks::TestMarshalVariant>::AncestorResponse {
                    commitment: parent.digest(),
                    block: Digested::precomputed(chain[0].clone(), chain[0].digest()),
                }
                .encode()
                .to_vec(),
                false,
            );

            // The backup is asked for the same block right away and serves the
            // rest of the window.
            select! {
                requested = Harness::next_ancestor_request(&mut harness.backup_boundary_receiver) => {
                    assert_eq!(requested, parent.digest());
                },
                _ = context.sleep(Duration::from_millis(100)) => {
                    panic!("invalid window block did not trigger immediate failover");
                },
            }
            for block in chain[..chain.len() - 1].iter().rev() {
                if block.digest() != parent.digest() {
                    let requested =
                        Harness::next_ancestor_request(&mut harness.backup_boundary_receiver).await;
                    assert_eq!(requested, block.digest());
                }
                harness.reply_ancestor_from_backup(block);
            }
            context.sleep(Duration::from_millis(100)).await;

            let artifact = subscription.try_recv().expect("artifact resolved");
            assert_eq!(artifact.window, logs_of(&chain[..chain.len() - 1]));
            let blocked = harness.oracle.blocked().await.unwrap();
            assert!(blocked.contains(&(
                harness.participants[1].clone(),
                harness.participants[2].clone()
            )));
        });
    }

    /// A boundary responder verified after the walk began joins its rotation,
    /// so a walk whose only responder serves a wrong block continues through
    /// the late responder instead of waiting on the blocked one.
    #[test]
    fn window_walk_recruits_responders_verified_after_it_began() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut harness = Harness::start_with(&mut context, false).await;
            let mut subscription = harness.joiner.subscribe();

            let floor_height = FixedEpocher::new(BLOCKS_PER_EPOCH)
                .last(Epoch::new(1))
                .expect("test epoch must be supported");
            let chain = window_chain(harness.participants[0].clone(), floor_height);
            let floor_block = chain.last().expect("chain must reach the floor");
            let floor = harness.latest_finalization(Epoch::new(1), floor_block.digest());

            // Both peers answer the latest request, but only the client answers
            // the boundary request before the walk begins.
            Harness::expect_latest_request(&mut harness.client_boundary_receiver).await;
            Harness::expect_latest_request(&mut harness.backup_boundary_receiver).await;
            harness.reply_latest_from_client(floor.clone());
            harness.reply_latest_from_backup(floor.clone());
            assert_eq!(harness.next_client_boundary_request().await, Epoch::new(1));
            assert_eq!(
                Harness::next_boundary_request(&mut harness.backup_boundary_receiver).await,
                Epoch::new(1)
            );
            let boundary_response =
                wire::Message::<mocks::TestScheme, mocks::TestMarshalVariant>::BoundaryResponse(
                    harness.boundary_finalization.clone(),
                )
                .encode()
                .to_vec();
            harness.client_boundary_sender.send(
                Recipients::One(harness.participants[1].clone()),
                boundary_response.clone(),
                false,
            );
            assert_eq!(
                Harness::next_block_request(&mut harness.client_boundary_receiver).await,
                Epoch::new(1)
            );
            harness.client_boundary_sender.send(
                Recipients::One(harness.participants[1].clone()),
                wire::Message::<mocks::TestScheme, mocks::TestMarshalVariant>::BlockResponse {
                    epoch: Epoch::new(1),
                    block: Digested::precomputed(
                        harness.boundary.clone(),
                        harness.boundary.digest(),
                    ),
                }
                .encode()
                .to_vec(),
                false,
            );
            let requested =
                Harness::next_ancestor_request(&mut harness.client_boundary_receiver).await;
            assert_eq!(requested, floor_block.digest());
            harness.reply_ancestor_from_client(floor_block);

            // The backup's boundary response arrives while the walk is in
            // progress, then the client answers the request for the floor's
            // parent with the wrong block.
            harness.backup_boundary_sender.send(
                Recipients::One(harness.participants[1].clone()),
                boundary_response,
                false,
            );
            context.sleep(Duration::from_millis(50)).await;
            let requested =
                Harness::next_ancestor_request(&mut harness.client_boundary_receiver).await;
            let parent = &chain[chain.len() - 2];
            assert_eq!(requested, parent.digest());
            harness.client_boundary_sender.send(
                Recipients::One(harness.participants[1].clone()),
                wire::Message::<mocks::TestScheme, mocks::TestMarshalVariant>::AncestorResponse {
                    commitment: parent.digest(),
                    block: Digested::precomputed(chain[0].clone(), chain[0].digest()),
                }
                .encode()
                .to_vec(),
                false,
            );

            // The backup takes over right away and serves the rest of the window.
            select! {
                requested = Harness::next_ancestor_request(&mut harness.backup_boundary_receiver) => {
                    assert_eq!(requested, parent.digest());
                },
                _ = context.sleep(Duration::from_millis(100)) => {
                    panic!("walk did not recruit the responder verified after it began");
                },
            }
            for block in chain[..chain.len() - 1].iter().rev() {
                if block.digest() != parent.digest() {
                    let requested =
                        Harness::next_ancestor_request(&mut harness.backup_boundary_receiver).await;
                    assert_eq!(requested, block.digest());
                }
                harness.reply_ancestor_from_backup(block);
            }
            context.sleep(Duration::from_millis(100)).await;

            let artifact = subscription.try_recv().expect("artifact resolved");
            assert_eq!(artifact.window, logs_of(&chain[..chain.len() - 1]));
        });
    }

    /// A walk whose whole rotation stops answering asks for boundary responders
    /// again, and a peer that answers then serves the rest of the window.
    #[test]
    fn window_walk_recruits_responders_after_its_rotation_falls_silent() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut harness = Harness::start_with(&mut context, false).await;
            let mut subscription = harness.joiner.subscribe();

            let floor_height = FixedEpocher::new(BLOCKS_PER_EPOCH)
                .last(Epoch::new(1))
                .expect("test epoch must be supported");
            let chain = window_chain(harness.participants[0].clone(), floor_height);
            let floor_block = chain.last().expect("chain must reach the floor");
            let floor = harness.latest_finalization(Epoch::new(1), floor_block.digest());

            // Only the client answers the boundary request and serves the
            // boundary block, so it is the walk's only responder.
            Harness::expect_latest_request(&mut harness.client_boundary_receiver).await;
            Harness::expect_latest_request(&mut harness.backup_boundary_receiver).await;
            harness.reply_latest_from_client(floor.clone());
            harness.reply_latest_from_backup(floor);
            assert_eq!(harness.next_client_boundary_request().await, Epoch::new(1));
            assert_eq!(
                Harness::next_boundary_request(&mut harness.backup_boundary_receiver).await,
                Epoch::new(1)
            );
            let boundary_response =
                wire::Message::<mocks::TestScheme, mocks::TestMarshalVariant>::BoundaryResponse(
                    harness.boundary_finalization.clone(),
                )
                .encode()
                .to_vec();
            harness.client_boundary_sender.send(
                Recipients::One(harness.participants[1].clone()),
                boundary_response.clone(),
                false,
            );
            assert_eq!(
                Harness::next_block_request(&mut harness.client_boundary_receiver).await,
                Epoch::new(1)
            );
            harness.client_boundary_sender.send(
                Recipients::One(harness.participants[1].clone()),
                wire::Message::<mocks::TestScheme, mocks::TestMarshalVariant>::BlockResponse {
                    epoch: Epoch::new(1),
                    block: Digested::precomputed(
                        harness.boundary.clone(),
                        harness.boundary.digest(),
                    ),
                }
                .encode()
                .to_vec(),
                false,
            );
            let requested =
                Harness::next_ancestor_request(&mut harness.client_boundary_receiver).await;
            assert_eq!(requested, floor_block.digest());

            // The client never answers. Once the rotation cycles without a
            // block, the walk asks for boundary responders again and the
            // backup joins it.
            assert_eq!(
                Harness::next_boundary_request(&mut harness.backup_boundary_receiver).await,
                Epoch::new(1)
            );
            harness.backup_boundary_sender.send(
                Recipients::One(harness.participants[1].clone()),
                boundary_response,
                false,
            );
            let requested =
                Harness::next_ancestor_request(&mut harness.backup_boundary_receiver).await;
            assert_eq!(requested, floor_block.digest());
            harness.reply_ancestor_from_backup(floor_block);
            for block in chain[..chain.len() - 1].iter().rev() {
                let requested =
                    Harness::next_ancestor_request(&mut harness.backup_boundary_receiver).await;
                assert_eq!(requested, block.digest());
                harness.reply_ancestor_from_backup(block);
            }
            context.sleep(Duration::from_millis(100)).await;

            let artifact = subscription.try_recv().expect("artifact resolved");
            assert_eq!(artifact.window, logs_of(&chain[..chain.len() - 1]));
            let blocked = harness.oracle.blocked().await.unwrap();
            assert!(blocked.is_empty());
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

    // ---- seat-1 falsification tests (review-only, not part of the PR) ----

    /// Builds linked blocks for an epoch from its midpoint up to the floor,
    /// each carrying the dealer log chosen by the index function.
    fn window_chain_in(
        epoch: Epoch,
        leader: mocks::TestPublicKey,
        floor: Height,
        log_index: impl Fn(u64) -> u64,
    ) -> Vec<mocks::TestBlock> {
        let midpoint = FixedEpocher::new(BLOCKS_PER_EPOCH)
            .midpoint(epoch)
            .expect("test epoch must be supported");
        let mut parent = Sha256::hash(&[b"below the window"]);
        let mut blocks = Vec::new();
        for height in midpoint.get()..=floor.get() {
            let context = mocks::TestContext {
                round: Round::new(epoch, View::new(height)),
                leader: leader.clone(),
                parent: (View::zero(), parent),
            };
            let block = mocks::TestBlock::new::<Sha256>(context, parent, Height::new(height), 0)
                .with_payload::<Sha256, mocks::TestBlsVariant, mocks::TestSigner>(
                NZU32!(16),
                Payload::DealerLog(dealer_log(log_index(height))),
            );
            parent = block.digest();
            blocks.push(block);
        }
        blocks
    }

    /// A responder that stops answering mid-walk is replaced after the retry
    /// timeout by the next verified responder, its late reply is ignored, and
    /// it is not blocked.
    #[test]
    fn stalled_window_responder_is_replaced_after_retry_timeout() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut harness = Harness::start_with(&mut context, false).await;
            let mut subscription = harness.joiner.subscribe();

            let floor_height = FixedEpocher::new(BLOCKS_PER_EPOCH)
                .last(Epoch::new(1))
                .expect("test epoch must be supported");
            let chain = window_chain(harness.participants[0].clone(), floor_height);
            let floor_block = chain.last().expect("chain must reach the floor");
            let floor = harness.latest_finalization(Epoch::new(1), floor_block.digest());

            let requested = harness.serve_boundary_with_floor(&context, floor.clone()).await;
            assert_eq!(requested, floor_block.digest());
            harness.reply_ancestor_from_client(floor_block);
            let parent = &chain[chain.len() - 2];
            let requested =
                Harness::next_ancestor_request(&mut harness.client_boundary_receiver).await;
            assert_eq!(requested, parent.digest());

            // The client stays silent. Nothing is asked of the backup before
            // the retry timeout (500ms) elapses.
            select! {
                _ = harness.backup_boundary_receiver.recv() => {
                    panic!("backup asked before the retry timeout");
                },
                _ = context.sleep(Duration::from_millis(400)) => {},
            }
            select! {
                requested = Harness::next_ancestor_request(&mut harness.backup_boundary_receiver) => {
                    assert_eq!(requested, parent.digest());
                },
                _ = context.sleep(Duration::from_millis(300)) => {
                    panic!("silent responder was not replaced after the retry timeout");
                },
            }

            // The client's late reply must be ignored: the backup is now the
            // in-flight responder and keeps serving the rest of the window.
            harness.reply_ancestor_from_client(parent);
            context.sleep(Duration::from_millis(10)).await;
            for block in chain[..chain.len() - 1].iter().rev() {
                if block.digest() != parent.digest() {
                    let requested =
                        Harness::next_ancestor_request(&mut harness.backup_boundary_receiver).await;
                    assert_eq!(requested, block.digest());
                }
                harness.reply_ancestor_from_backup(block);
            }
            context.sleep(Duration::from_millis(100)).await;

            let artifact = subscription.try_recv().expect("artifact resolved");
            assert_eq!(artifact.floor, floor);
            assert_eq!(artifact.window, logs_of(&chain[..chain.len() - 1]));
            let blocked = harness.oracle.blocked().await.unwrap();
            assert!(blocked.is_empty(), "a silent responder must not be blocked");
        });
    }

    /// A persisted floor at a later round than the sampled one is resolved as
    /// the artifact's floor, and the walk fetches that floor's block and
    /// window rather than the sampled floor's.
    #[test]
    fn persisted_late_floor_wins_and_its_window_is_fetched() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let fixture = mocks::scheme_fixture_n(&mut context, 4);
            let floor_height = FixedEpocher::new(BLOCKS_PER_EPOCH)
                .last(Epoch::new(1))
                .expect("test epoch must be supported");
            let chain = window_chain(fixture.participants[0].clone(), floor_height);
            let floor_block = chain.last().expect("chain must reach the floor");
            let persisted = finalization(
                Proposal::new(
                    Round::new(Epoch::new(1), View::new(9)),
                    View::new(8),
                    floor_block.digest(),
                ),
                &fixture.schemes,
            );
            let mut harness = Harness::start_full(
                &mut context,
                fixture,
                Vec::new(),
                Epoch::zero(),
                Some(persisted.clone()),
            )
            .await;
            let mut subscription = harness.joiner.subscribe();

            // The sample lands on the epoch-1 floor block at view 2, below the
            // persisted floor's view 9.
            let sampled = harness.target_finalization();
            let requested = harness
                .serve_boundary_with_floor(&context, sampled.clone())
                .await;
            assert_eq!(
                requested,
                floor_block.digest(),
                "walk must start at the persisted floor"
            );
            harness.serve_window_from_client(requested, &chain).await;

            select! {
                _ = harness.client_boundary_receiver.recv() => {
                    panic!("walk requested a block below the midpoint");
                },
                _ = context.sleep(Duration::from_millis(100)) => {},
            }
            let artifact = subscription.try_recv().expect("artifact resolved");
            assert_eq!(artifact.floor, persisted);
            assert_ne!(artifact.floor, sampled);
            assert_eq!(artifact.info.epoch, Epoch::new(1));
            assert_eq!(artifact.window, logs_of(&chain[..chain.len() - 1]));
        });
    }

    /// A floor block whose height lies outside the floor finalization's epoch
    /// is rejected: the sender is blocked and the next responder is asked at
    /// once. (Unreachable on a correct chain; checks the walk neither accepts
    /// nor panics.)
    #[test]
    fn floor_block_outside_floor_epoch_is_rejected() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut harness = Harness::start_with(&mut context, false).await;
            let _subscription = harness.joiner.subscribe();

            // A block at the first height of epoch 2, finalized "in" epoch 1.
            let height = FixedEpocher::new(BLOCKS_PER_EPOCH)
                .first(Epoch::new(2))
                .expect("test epoch must be supported");
            let parent = Sha256::hash(&[b"foreign parent"]);
            let foreign = mocks::TestBlock::new::<Sha256>(
                mocks::TestContext {
                    round: Round::new(Epoch::new(1), View::new(2)),
                    leader: harness.participants[0].clone(),
                    parent: (View::zero(), parent),
                },
                parent,
                height,
                0,
            );
            let floor = harness.latest_finalization(Epoch::new(1), foreign.digest());
            let requested = harness.serve_boundary_with_floor(&context, floor).await;
            assert_eq!(requested, foreign.digest());
            harness.reply_ancestor_from_client(&foreign);

            select! {
                requested = Harness::next_ancestor_request(&mut harness.backup_boundary_receiver) => {
                    assert_eq!(requested, foreign.digest());
                },
                _ = context.sleep(Duration::from_millis(100)) => {
                    panic!("foreign floor block did not trigger immediate failover");
                },
            }
            let blocked = harness.oracle.blocked().await.unwrap();
            assert!(blocked.contains(&(
                harness.participants[1].clone(),
                harness.participants[2].clone()
            )));
        });
    }

    /// Every window block's log is carried, including repeated logs from one
    /// dealer, and the persisted material accepts a window at the capacity
    /// bound; dedup is the reshare store's job.
    #[test]
    fn duplicate_dealer_logs_fill_window_to_capacity() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut harness = Harness::start_with(&mut context, false).await;
            let mut subscription = harness.joiner.subscribe();

            let floor_height = FixedEpocher::new(BLOCKS_PER_EPOCH)
                .last(Epoch::new(1))
                .expect("test epoch must be supported");
            // Every block carries a log from dealer 0.
            let chain = window_chain_in(
                Epoch::new(1),
                harness.participants[0].clone(),
                floor_height,
                |_| 0,
            );
            let floor_block = chain.last().expect("chain must reach the floor");
            let floor = harness.latest_finalization(Epoch::new(1), floor_block.digest());

            let requested = harness
                .serve_boundary_with_floor(&context, floor.clone())
                .await;
            harness.serve_window_from_client(requested, &chain).await;
            context.sleep(Duration::from_millis(100)).await;

            let artifact = subscription.try_recv().expect("artifact resolved");
            let expected = logs_of(&chain[..chain.len() - 1]);
            assert_eq!(artifact.window, expected);
            assert_eq!(artifact.window.len(), 3, "window spans [midpoint, floor-1]");
            // Capacity for an 8-block epoch is 3, so the material persists.
            StateSyncPlan::init(
                context.child("dkg"),
                StateSyncConfig {
                    partition_prefix: "dup-window".into(),
                    max_participants: NZU32!(16),
                    max_supported_mode: max_supported_mode(),
                    blocks_per_epoch: BLOCKS_PER_EPOCH,
                },
                Some(StateSync {
                    info: artifact.info,
                    floor: artifact.floor,
                    window: artifact.window,
                }),
            )
            .await;
        });
    }

    /// An epoch-zero floor in the late phase walks the window with the
    /// snapshot's dealers as responders. Responders that cannot serve (the
    /// source without the blocks, and the joiner itself) each cost one retry
    /// timeout before the walk reaches a serving dealer.
    #[test]
    fn epoch_zero_late_floor_fetches_window_from_snapshot_dealers() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut harness = Harness::start_with(&mut context, false).await;
            let mut subscription = harness.joiner.subscribe();
            Harness::expect_latest_request(&mut harness.client_boundary_receiver).await;
            Harness::expect_latest_request(&mut harness.backup_boundary_receiver).await;

            let floor_height = FixedEpocher::new(BLOCKS_PER_EPOCH)
                .last(Epoch::zero())
                .expect("epoch zero must be supported");
            let chain = window_chain_in(
                Epoch::zero(),
                harness.participants[0].clone(),
                floor_height,
                |height| height,
            );
            let floor_block = chain.last().expect("chain must reach the floor");
            let floor = harness.latest_finalization(Epoch::zero(), floor_block.digest());
            harness.reply_latest_from_client(floor.clone());
            harness.reply_latest_from_backup(floor.clone());

            // Dealers are asked in snapshot order: source (no such block), the
            // joiner itself, then the client. Two retry timeouts pass first.
            let started = context.current();
            let requested = select! {
                requested = Harness::next_ancestor_request(&mut harness.client_boundary_receiver) => requested,
                _ = context.sleep(Duration::from_secs(5)) => panic!("walk never reached the client"),
            };
            let elapsed = context
                .current()
                .duration_since(started)
                .expect("monotonic");
            assert!(elapsed >= Duration::from_millis(1000), "elapsed {elapsed:?}");
            assert_eq!(requested, floor_block.digest());
            harness.serve_window_from_client(requested, &chain).await;
            context.sleep(Duration::from_millis(100)).await;

            let artifact = subscription.try_recv().expect("artifact resolved");
            assert!(artifact.finalization.is_none());
            assert_eq!(artifact.info, genesis_info(&harness.participants));
            assert_eq!(artifact.floor, floor);
            assert_eq!(artifact.window, logs_of(&chain[..chain.len() - 1]));
            let blocked = harness.oracle.blocked().await.unwrap();
            assert!(
                blocked.is_empty(),
                "non-answering dealers must not be blocked"
            );
        });
    }
}
