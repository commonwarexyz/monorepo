//! The own-chain data-availability recovery plane, run on its own work-stealing task.
//!
//! Stage 1 of the DA-plane sharding lifts the own producer chain's share pools and certificate
//! recovery off the single dedicated voter thread. Central (the serial [`super::CoreState`] owner)
//! still mints the observation identity and order of every share, and it alone owns the durability
//! funnel: this task never touches the durable cursor, reserves no change, and publishes nothing.
//!
//! ```text
//! central                                   own-chain DA task
//! -------                                   ----------------
//! admit share (mint identity/order) --Observe--> pool shares, decide n - 2f recovery
//! advance certified anchor -------AnchorAdvanced--> prune settled pools
//!                                                dispatch recovery crypto (Strategy clone)
//! durable admit + publish <----Recovered---------- assemble certificate
//! block invalid share signers <-BlockSigners------ attribute a failed quorum
//! ```
//!
//! The task holds only volatile, rebuildable state. On restart central replays its durable state,
//! respawns a fresh task, and re-seeds it with the recovered certified anchor; the pools refill
//! from re-observed shares. A saturated command mailbox backpressures central admission for this
//! chain alone and is never fatal.

use super::*;
use crate::{
    multimmit::types::{DaCertificate, DaVote},
    types::Attributable as _,
};
use commonware_actor::mailbox::{Policy, Sender as ChainSender};
use commonware_macros::select_loop;
use commonware_runtime::telemetry::metrics::Counter;
use std::{collections::BTreeSet, panic::AssertUnwindSafe};

/// A command from central to the own-chain data-availability task.
///
/// Central authenticates and orders every command before it crosses the boundary. The reverse
/// direction ([`DaTaskUpdate`]) carries the task's only outputs.
pub(super) enum ChainCommand<V: Variant, D: Digest> {
    /// An authenticated own-chain data-availability share whose observation identity central
    /// already minted.
    Observe(Arc<DaVote<V, D>>),
    /// The own chain's certified anchor advanced to this height; pools at or below it are settled.
    AnchorAdvanced(Height),
    /// A new process generation began; drop volatile pools and stamp later results with it.
    Reconfigure {
        /// The new process generation.
        generation: u64,
        /// The certified anchor of the new generation.
        certified: Height,
    },
}

impl<V: Variant, D: Digest> Policy for ChainCommand<V, D> {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        overflow.push_back(message);
    }
}

/// A result returned by the own-chain data-availability task to central.
///
/// Each result carries the issuing process generation so a completion from a superseded task is
/// dropped rather than admitted, mirroring how central drops stale async completions elsewhere.
pub(super) enum DaTaskUpdate<V: Variant, D: Digest> {
    /// An assembled certificate ready for central to durably admit and publish.
    Recovered {
        /// The process generation that spawned the task.
        generation: u64,
        /// The certified block.
        block: BlockRef<D>,
        /// The recovered certificate.
        certificate: DaCertificate<V, D>,
    },
    /// Signers a failed recovery attributed invalid shares to, for central to block.
    BlockSigners {
        /// The process generation that spawned the task.
        generation: u64,
        /// The attributed signers.
        signers: Vec<Participant>,
    },
}

impl<V: Variant, D: Digest> Policy for DaTaskUpdate<V, D> {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        overflow.push_back(message);
    }
}

/// One producer header's accumulated shares, keyed in the task by the header digest.
struct VotePool<V: Variant, D: Digest> {
    header: TransactionBlockHeader<D>,
    shares: BTreeMap<Participant, Arc<DaVote<V, D>>>,
    /// Signers a failed recovery attributed an invalid share for this header to.
    ///
    /// Shares enter on structural checks alone, so recovery is where an invalid one is discovered.
    /// Remembering the signer keeps a rejected share out of every later selection. Bounded by the
    /// committee.
    rejected: BTreeSet<Participant>,
}

/// One completed recovery crypto dispatch, correlated to its header digest.
struct Recovered<V: Variant, D: Digest> {
    header: D,
    block: BlockRef<D>,
    started_at: SystemTime,
    outcome: RecoveryOutcome<V, D>,
}

/// The outcome of one recovery crypto dispatch.
enum RecoveryOutcome<V: Variant, D: Digest> {
    /// The quorum assembled into a certificate.
    Certificate(DaCertificate<V, D>),
    /// The group check failed and attributed these signers' shares.
    Invalid(Vec<Participant>),
    /// The recovery could not attribute a culprit; the block re-arms and retries.
    Unattributed,
}

/// The task's volatile recovery state, owned for the lifetime of one run.
struct Plane<V: Variant, D: Digest> {
    /// Header digest -> accumulated shares.
    pools: BTreeMap<D, VotePool<V, D>>,
    /// Header digests whose pool reached quorum and awaits a recovery slot.
    ready: BTreeSet<D>,
    /// Header digests with a recovery in flight or already returned to central.
    ///
    /// A returned certificate stays here until central confirms it through `AnchorAdvanced`, so a
    /// later share for the same block never re-arms a redundant recovery. It is retired only by
    /// anchor advance (the certificate landed) or by a failed attempt (which re-arms).
    pending: BTreeSet<D>,
    /// The greatest certified own-chain height central has reported.
    certified_through: Height,
    /// The process generation stamped on results, so central drops superseded completions.
    generation: u64,
}

/// One own-chain data-availability task bound to one process generation.
pub(super) struct DaPlane<E, H, P, V, T>
where
    E: Clock + Spawner + Metrics,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    T: Strategy,
{
    context: E,
    scheme: Arc<Scheme<P, V>>,
    strategy: T,
    updates: ChainSender<DaTaskUpdate<V, H::Digest>>,
    own_chain: ChainId,
    da_quorum: usize,
    /// The most recovery crypto dispatches the task keeps in flight at once.
    ///
    /// At most `d` (pipeline depth) own-chain headers are uncertified above the anchor, so `d`
    /// concurrent recoveries suffice and cannot exceed central's certificate capacity for the one
    /// chain.
    recovery_slots: usize,
    generation: u64,
    certified_through: Height,
    latency: Histogram,
    fallbacks: Counter,
}

impl<E, H, P, V, T> DaPlane<E, H, P, V, T>
where
    E: Clock + Spawner + Metrics,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    T: Strategy,
{
    /// Builds a task bound to one process generation.
    #[allow(clippy::too_many_arguments)]
    pub(super) const fn new(
        context: E,
        scheme: Arc<Scheme<P, V>>,
        strategy: T,
        updates: ChainSender<DaTaskUpdate<V, H::Digest>>,
        own_chain: ChainId,
        da_quorum: usize,
        recovery_slots: usize,
        generation: u64,
        certified_through: Height,
        latency: Histogram,
        fallbacks: Counter,
    ) -> Self {
        Self {
            context,
            scheme,
            strategy,
            updates,
            own_chain,
            da_quorum,
            recovery_slots,
            generation,
            certified_through,
            latency,
            fallbacks,
        }
    }

    /// Drains commands and recovery completions until central closes the channel or the runtime
    /// stops.
    pub(super) async fn run(self, mut commands: mailbox::Receiver<ChainCommand<V, H::Digest>>) {
        let mut plane = Plane {
            pools: BTreeMap::new(),
            ready: BTreeSet::new(),
            pending: BTreeSet::new(),
            certified_through: self.certified_through,
            generation: self.generation,
        };
        let mut recoveries: Pool<Recovered<V, H::Digest>> = Pool::default();
        select_loop! {
            self.context,
            on_stopped => {
                drop(shutdown);
            },
            Some(command) = commands.recv() else break => {
                self.handle_command(&mut plane, &mut recoveries, command);
            },
            done = recoveries.next_completed() => {
                if !self.handle_recovered(&mut plane, done) {
                    break;
                }
                self.drive(&mut plane, &mut recoveries);
            },
        }
    }

    fn handle_command(
        &self,
        plane: &mut Plane<V, H::Digest>,
        recoveries: &mut Pool<Recovered<V, H::Digest>>,
        command: ChainCommand<V, H::Digest>,
    ) {
        match command {
            ChainCommand::Observe(share) => self.observe(plane, recoveries, &share),
            ChainCommand::AnchorAdvanced(height) => self.advance_anchor(plane, recoveries, height),
            ChainCommand::Reconfigure {
                generation,
                certified,
            } => {
                // A new generation invalidates every in-flight recovery: results still returning
                // from the old generation are stamped with it and central drops them. Dropping the
                // pools rebuilds the projection from the new generation's re-observed shares.
                plane.generation = generation;
                plane.certified_through = certified;
                plane.pools.clear();
                plane.ready.clear();
                plane.pending.clear();
            }
        }
    }

    fn observe(
        &self,
        plane: &mut Plane<V, H::Digest>,
        recoveries: &mut Pool<Recovered<V, H::Digest>>,
        share: &Arc<DaVote<V, H::Digest>>,
    ) {
        let header = share.header();
        if header.chain() != self.own_chain || header.height() <= plane.certified_through {
            return;
        }
        let digest = header.digest::<H>();
        let pool = plane.pools.entry(digest).or_insert_with(|| VotePool {
            header: header.clone(),
            shares: BTreeMap::new(),
            rejected: BTreeSet::new(),
        });
        if pool.header != *header {
            return;
        }
        let signer = share.signer();
        if !pool.rejected.contains(&signer) {
            pool.shares
                .entry(signer)
                .or_insert_with(|| Arc::clone(share));
        }
        self.refresh(plane, digest);
        self.drive(plane, recoveries);
    }

    fn advance_anchor(
        &self,
        plane: &mut Plane<V, H::Digest>,
        recoveries: &mut Pool<Recovered<V, H::Digest>>,
        height: Height,
    ) {
        if height <= plane.certified_through {
            return;
        }
        plane.certified_through = height;
        let settled = plane
            .pools
            .iter()
            .filter(|(_, pool)| pool.header.height() <= height)
            .map(|(digest, _)| *digest)
            .collect::<Vec<_>>();
        for digest in settled {
            plane.pools.remove(&digest);
            plane.ready.remove(&digest);
            plane.pending.remove(&digest);
        }
        self.drive(plane, recoveries);
    }

    /// Recomputes one pool's recovery readiness.
    fn refresh(&self, plane: &mut Plane<V, H::Digest>, digest: H::Digest) {
        let ready = plane.pools.get(&digest).is_some_and(|pool| {
            pool.header.height() > plane.certified_through
                && !plane.pending.contains(&digest)
                && pool.shares.len() >= self.da_quorum
        });
        if ready {
            plane.ready.insert(digest);
        } else {
            plane.ready.remove(&digest);
        }
    }

    /// Dispatches ready recoveries up to the in-flight slot bound.
    fn drive(
        &self,
        plane: &mut Plane<V, H::Digest>,
        recoveries: &mut Pool<Recovered<V, H::Digest>>,
    ) {
        while recoveries.len() < self.recovery_slots {
            let Some(digest) = plane.ready.iter().next().copied() else {
                break;
            };
            plane.ready.remove(&digest);
            let Some(pool) = plane.pools.get(&digest) else {
                continue;
            };
            if pool.shares.len() < self.da_quorum {
                continue;
            }
            let block = pool.header.block_ref::<H>();
            let votes = pool
                .shares
                .values()
                .take(self.da_quorum)
                .map(|vote| vote.as_ref().clone())
                .collect::<Vec<_>>();
            plane.pending.insert(digest);
            let scheme = Arc::clone(&self.scheme);
            let strategy = self.strategy.clone();
            let started_at = self.context.current();
            recoveries.push(async move {
                // The group check runs on the shared pool, and a worker panic is reconciled into
                // an unattributed failure rather than escaping the task.
                let outcome = strategy
                    .spawn(move |strategy| {
                        std::panic::catch_unwind(AssertUnwindSafe(move || {
                            scheme.assemble_da_certificate_optimistic(&votes, &strategy)
                        }))
                    })
                    .await;
                let outcome = match outcome {
                    Ok(Ok(certificate)) => RecoveryOutcome::Certificate(certificate),
                    Ok(Err(DaRecoveryError::InvalidShares(invalid))) => {
                        RecoveryOutcome::Invalid(invalid)
                    }
                    Ok(Err(DaRecoveryError::Scheme(_))) | Err(_) => RecoveryOutcome::Unattributed,
                };
                Recovered {
                    header: digest,
                    block,
                    started_at,
                    outcome,
                }
            });
        }
    }

    /// Applies one recovery completion; returns whether the task should keep running.
    fn handle_recovered(
        &self,
        plane: &mut Plane<V, H::Digest>,
        done: Recovered<V, H::Digest>,
    ) -> bool {
        self.latency
            .observe_between(done.started_at, self.context.current());
        match done.outcome {
            RecoveryOutcome::Certificate(certificate) => {
                // The block stays pending until central confirms the anchor, so a later share
                // cannot re-arm a redundant recovery for a block already certified here.
                self.send(DaTaskUpdate::Recovered {
                    generation: plane.generation,
                    block: done.block,
                    certificate,
                })
            }
            RecoveryOutcome::Invalid(invalid) => {
                self.fallbacks.inc();
                if let Some(pool) = plane.pools.get_mut(&done.header) {
                    for signer in &invalid {
                        pool.shares.remove(signer);
                        pool.rejected.insert(*signer);
                    }
                }
                plane.pending.remove(&done.header);
                let running = self.send(DaTaskUpdate::BlockSigners {
                    generation: plane.generation,
                    signers: invalid,
                });
                self.refresh(plane, done.header);
                running
            }
            RecoveryOutcome::Unattributed => {
                self.fallbacks.inc();
                plane.pending.remove(&done.header);
                self.refresh(plane, done.header);
                true
            }
        }
    }

    /// Sends one update to central; returns whether the channel is still open.
    fn send(&self, update: DaTaskUpdate<V, H::Digest>) -> bool {
        self.updates.enqueue(update).accepted()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::{
            config::{Config, Limits},
            scheme::bls12381_threshold::{Roster, Scheme},
            types::{CertificateId, EpochGenesis},
        },
        types::{Epoch, Participant},
    };
    use bytes::BytesMut;
    use commonware_codec::{Read as _, Write as _};
    use commonware_cryptography::{
        Sha256, Signer as _,
        bls12381::primitives::{
            group::{Private, Scalar, Share},
            ops,
            sharing::{Mode, ModeVersion, Sharing},
            variant::MinPk,
        },
        ed25519::PrivateKey as Ed25519PrivateKey,
        sha256::Digest,
    };
    use commonware_math::poly::Poly;
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        Runner as _, Supervisor as _,
        deterministic::Runner,
        telemetry::metrics::{MetricsExt as _, histogram},
    };
    use commonware_utils::{TestRng, ordered::Set};
    use std::num::{NonZeroU32, NonZeroUsize};

    const PARTICIPANTS: u32 = 6;
    const NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MULTIMMIT_DA_TASK_TEST";

    fn digest(label: &[u8]) -> Digest {
        Sha256::hash(&[label])
    }

    fn sharing(rng: &mut TestRng, total: u32, required: u32) -> (Sharing<MinPk>, Vec<Share>) {
        let private = Poly::<Scalar>::new(rng, required - 1);
        let shares = (0..total)
            .map(|index| {
                let point = Scalar::from_u64(u64::from(index) + 1);
                Share::new(Participant::new(index), Private::new(private.eval(&point)))
            })
            .collect();
        let public = Poly::<
            <MinPk as commonware_cryptography::bls12381::primitives::variant::Variant>::Public,
        >::commit(private);
        let mut encoded = BytesMut::new();
        Mode::NonZeroCounter.write(&mut encoded);
        total.write(&mut encoded);
        public.write(&mut encoded);
        let mut encoded = encoded.freeze();
        let total = NonZeroU32::new(total).unwrap();
        let sharing = Sharing::read_cfg(&mut encoded, &(total, ModeVersion::v0())).unwrap();
        (sharing, shares)
    }

    fn config() -> Config<Digest> {
        let epoch = Epoch::new(9);
        let tips = (0..PARTICIPANTS)
            .map(|chain| BlockRef::new(ChainId::new(chain), Height::zero(), digest(b"genesis")))
            .collect();
        let genesis = EpochGenesis::new(
            epoch,
            digest(b"leader genesis"),
            CertificateId::new(digest(b"vqc genesis")),
            CertificateId::new(digest(b"lqc genesis")),
            tips,
        )
        .unwrap();
        Config::new(
            epoch,
            NAMESPACE,
            PARTICIPANTS as usize,
            (0..PARTICIPANTS).map(Participant::new).collect(),
            Limits::new(2, 2).unwrap(),
            genesis,
        )
        .unwrap()
    }

    /// Builds signer schemes and a verifier over one deterministic threshold sharing.
    fn fixture() -> (
        Vec<Scheme<Ed25519PublicKey, MinPk>>,
        Scheme<Ed25519PublicKey, MinPk>,
    ) {
        let protocol = config();
        let codec = protocol.codec_config();
        let identities = Set::try_from(
            (0..PARTICIPANTS)
                .map(|index| Ed25519PrivateKey::from_seed(u64::from(index) + 100).public_key())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let mut rng = TestRng::new(7);
        let mut ordinary = Vec::with_capacity(PARTICIPANTS as usize);
        let participants = identities
            .iter()
            .map(|identity| {
                let (private, public) = ops::keypair::<_, MinPk>(&mut rng);
                let proof = Roster::<Ed25519PublicKey, MinPk>::proof_of_possession(
                    protocol.namespace(),
                    &private,
                );
                ordinary.push(private);
                (identity.clone(), public, proof)
            })
            .collect();
        let roster = Roster::verify(
            protocol.namespace(),
            codec.participants(),
            participants,
            &Sequential,
        )
        .unwrap();
        let (da, da_shares) = sharing(
            &mut rng,
            PARTICIPANTS,
            u32::try_from(codec.da_quorum()).unwrap(),
        );
        let (nullification, nullification_shares) = sharing(
            &mut rng,
            PARTICIPANTS,
            u32::try_from(codec.nullification_quorum()).unwrap(),
        );
        let signers = ordinary
            .into_iter()
            .zip(da_shares)
            .zip(nullification_shares)
            .map(|((ordinary, da_share), nullification_share)| {
                Scheme::signer(
                    &protocol,
                    roster.clone(),
                    ordinary,
                    da.clone(),
                    da_share,
                    nullification.clone(),
                    nullification_share,
                )
                .unwrap()
            })
            .collect();
        let verifier = Scheme::verifier(&protocol, roster, da, nullification).unwrap();
        (signers, verifier)
    }

    type Ed25519PublicKey = commonware_cryptography::ed25519::PublicKey;

    fn own_header() -> TransactionBlockHeader<Digest> {
        TransactionBlockHeader::new(
            Epoch::new(9),
            ChainId::new(0),
            Height::new(1),
            digest(b"genesis"),
            digest(b"own body"),
        )
        .unwrap()
    }

    fn latency<E: commonware_runtime::Metrics>(context: &E) -> Histogram {
        context.histogram("latency", "", histogram::Buckets::CRYPTOGRAPHY)
    }

    /// A quorum of shares crossing the task boundary recovers a verifiable certificate.
    #[test]
    fn own_chain_quorum_crosses_the_boundary_and_recovers() {
        Runner::default().start(|context| async move {
            let (signers, verifier) = fixture();
            let da_quorum = verifier.codec_config().da_quorum();
            let scheme = Arc::new(verifier);
            let header = own_header();
            let (commands, command_rx) =
                mailbox::new(context.child("commands"), NonZeroUsize::new(64).unwrap());
            let (updates, mut update_rx) =
                mailbox::new(context.child("updates"), NonZeroUsize::new(64).unwrap());
            let verify = Arc::clone(&scheme);
            let latency = latency(&context);
            let fallbacks = context.counter("fallbacks", "");
            let _task = context.child("da_task").spawn(move |context| {
                DaPlane::<_, Sha256, _, MinPk, _>::new(
                    context,
                    scheme,
                    Sequential,
                    updates,
                    ChainId::new(0),
                    da_quorum,
                    2,
                    1,
                    Height::zero(),
                    latency,
                    fallbacks,
                )
                .run(command_rx)
            });
            for signer in signers.iter().take(da_quorum) {
                let vote = signer.sign_da_vote(header.clone()).unwrap();
                assert!(
                    commands
                        .enqueue(ChainCommand::Observe(Arc::new(vote)))
                        .accepted()
                );
            }
            match update_rx.recv().await.expect("the task returns a recovery") {
                DaTaskUpdate::Recovered {
                    generation,
                    block,
                    certificate,
                } => {
                    assert_eq!(generation, 1);
                    assert_eq!(block, header.block_ref::<Sha256>());
                    assert!(verify.verify_da_certificate(&certificate));
                }
                DaTaskUpdate::BlockSigners { .. } => panic!("a valid quorum must not be rejected"),
            }
        });
    }

    /// A rejected share re-arms a fresh quorum that excludes its signer.
    #[test]
    fn rejected_share_re_arms_a_quorum_excluding_the_signer() {
        Runner::default().start(|context| async move {
            let (signers, verifier) = fixture();
            let da_quorum = verifier.codec_config().da_quorum();
            let scheme = Arc::new(verifier);
            let header = own_header();
            let (commands, command_rx) =
                mailbox::new(context.child("commands"), NonZeroUsize::new(64).unwrap());
            let (updates, mut update_rx) =
                mailbox::new(context.child("updates"), NonZeroUsize::new(64).unwrap());
            let verify = Arc::clone(&scheme);
            let latency = latency(&context);
            let fallbacks = context.counter("fallbacks", "");
            let _task = context.child("da_task").spawn(move |context| {
                DaPlane::<_, Sha256, _, MinPk, _>::new(
                    context,
                    scheme,
                    Sequential,
                    updates,
                    ChainId::new(0),
                    da_quorum,
                    2,
                    1,
                    Height::zero(),
                    latency,
                    fallbacks,
                )
                .run(command_rx)
            });
            // The culprit's share is structurally valid but signs the wrong subject, so the
            // group check fails and the task attributes exactly its signer. A fresh signer then
            // completes a quorum that excludes the rejected culprit.
            let culprit_index = da_quorum - 1;
            let replacement_index = da_quorum;
            let culprit = Participant::new(u32::try_from(culprit_index).unwrap());
            let wrong = signers[culprit_index]
                .sign_da_vote(
                    TransactionBlockHeader::new(
                        Epoch::new(9),
                        ChainId::new(0),
                        Height::new(2),
                        digest(b"genesis"),
                        digest(b"other body"),
                    )
                    .unwrap(),
                )
                .unwrap();
            let invalid = DaVote::new(header.clone(), wrong.share().clone());
            for signer in signers.iter().take(da_quorum - 1) {
                let vote = signer.sign_da_vote(header.clone()).unwrap();
                assert!(
                    commands
                        .enqueue(ChainCommand::Observe(Arc::new(vote)))
                        .accepted()
                );
            }
            assert!(
                commands
                    .enqueue(ChainCommand::Observe(Arc::new(invalid)))
                    .accepted()
            );
            match update_rx
                .recv()
                .await
                .expect("the task reports the invalid signer")
            {
                DaTaskUpdate::BlockSigners { signers, .. } => {
                    assert_eq!(signers, vec![culprit]);
                }
                DaTaskUpdate::Recovered { .. } => panic!("an invalid share must fail the quorum"),
            }
            // A fresh signer re-arms a quorum that excludes the rejected culprit.
            let replacement = signers[replacement_index]
                .sign_da_vote(header.clone())
                .unwrap();
            assert!(
                commands
                    .enqueue(ChainCommand::Observe(Arc::new(replacement)))
                    .accepted()
            );
            match update_rx
                .recv()
                .await
                .expect("the task recovers after re-arming")
            {
                DaTaskUpdate::Recovered {
                    block, certificate, ..
                } => {
                    assert_eq!(block, header.block_ref::<Sha256>());
                    assert!(verify.verify_da_certificate(&certificate));
                }
                DaTaskUpdate::BlockSigners { .. } => {
                    panic!("the re-armed quorum must recover")
                }
            }
        });
    }
}
