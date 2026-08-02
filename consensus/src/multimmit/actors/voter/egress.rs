//! Durable publication retry without retirement authority.
//!
//! The machine's durable outbox is the single retry authority: an entry installed here is
//! retried with bounded backoff until the voter observes the machine's typed semantic
//! supersession in a persisted journal event. Local sender acceptance is volatile attempt
//! telemetry only. Every retry reuses the exact bytes encoded when the effect was installed.

use super::VoterLimits;
use crate::{
    multimmit::{
        actors::wire::{CertificateMessage, ConsensusMessage, DataMessage, Envelope, Plane},
        machine::{Artifact, EffectId, ProposalPublication},
        types::ProposalParent,
    },
    types::{Epoch, View},
};
use bytes::Bytes;
use commonware_codec::{Encode as _, EncodeSize, Write};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use commonware_utils::SystemTimeExt as _;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::{Duration, SystemTime},
};

/// One exact pre-encoded transmission.
#[derive(Clone, Debug)]
pub(super) struct Transmission<P, D: Digest> {
    /// The physical plane carrying the message.
    pub plane: Plane,
    /// The exact encoded envelope bytes.
    pub bytes: Bytes,
    /// The sole recipient, or `None` to broadcast to all connected eligible peers.
    pub recipient: Option<P>,
    /// The application payload to relay before publishing this transaction header.
    pub relay: Option<D>,
}

/// One due publication: effect id, generation, prior local delivery, and its transmissions.
pub(super) type Due<P, D> = (
    EffectId,
    u64,
    u64,
    bool,
    Arc<[Transmission<P, D>]>,
    PublicationOrigin,
);

/// Scalar context retained across an obligation's unbounded retry lifetime.
#[derive(Clone, Copy)]
pub(super) struct PublicationOrigin {
    pub view: View,
}

struct Entry<P, D: Digest> {
    generation: u64,
    attempts: u64,
    transmissions: Arc<[Transmission<P, D>]>,
    sign_ready_at: Option<SystemTime>,
    next: SystemTime,
    backoff: Duration,
    delivered: bool,
    origin: PublicationOrigin,
}

/// Encode-once retry state for the machine's outstanding publications.
pub(super) struct Egress<P, D: Digest> {
    epoch: Epoch,
    entries: BTreeMap<EffectId, Entry<P, D>>,
    deadlines: BTreeSet<(SystemTime, EffectId)>,
    retry_cursor: Option<(SystemTime, EffectId)>,
    limits: VoterLimits,
}

impl<P: Clone, D: Digest> Egress<P, D> {
    pub(super) const fn new(epoch: Epoch, limits: VoterLimits) -> Self {
        Self {
            epoch,
            entries: BTreeMap::new(),
            deadlines: BTreeSet::new(),
            retry_cursor: None,
            limits,
        }
    }

    /// Frames a leader proposal from the machine's durable parent-transmission choice.
    pub(super) fn frame_proposal<V: Variant>(
        &self,
        publication: &ProposalPublication<V, D>,
    ) -> Transmission<P, D> {
        let message = self.proposal_message(publication);
        Transmission {
            plane: Plane::Consensus,
            bytes: self.envelope(message),
            recipient: None,
            relay: None,
        }
    }

    fn proposal_message<V: Variant>(
        &self,
        publication: &ProposalPublication<V, D>,
    ) -> ConsensusMessage<V, D> {
        let parent = match publication.parent() {
            ProposalParent::Genesis => None,
            ProposalParent::Exact(parent) if publication.attach_parent() => {
                Some(Box::new(parent.as_ref().clone()))
            }
            ProposalParent::Exact(_) => None,
        };
        ConsensusMessage::Proposal {
            block: Box::new(publication.block().as_ref().clone()),
            parent,
        }
    }

    /// Frames one non-proposal artifact for its ordinary plane.
    ///
    /// Leader blocks return `None` because they must travel through the typed proposal path with
    /// their exact parent.
    pub(super) fn frame<V: Variant>(
        &self,
        artifact: &Artifact<V, D>,
        recipient: Option<P>,
    ) -> Option<Transmission<P, D>> {
        let (plane, bytes, relay) = match artifact {
            Artifact::TransactionBlock(block) => (
                Plane::Data,
                self.envelope(DataMessage::Block(block.clone())),
                Some(block.header().commitment()),
            ),
            Artifact::DaVote(vote) => (
                Plane::Data,
                self.envelope(DataMessage::DaVote(vote.clone())),
                None,
            ),
            Artifact::DaCertificate(certificate) => (
                Plane::Data,
                self.envelope(DataMessage::DaCertificate(certificate.clone())),
                None,
            ),
            Artifact::LeaderBlock(_) => return None,
            Artifact::Vote(vote) => (
                Plane::Consensus,
                self.envelope(ConsensusMessage::Vote(vote.clone())),
                None,
            ),
            Artifact::NoVote(vote) => (
                Plane::Consensus,
                self.envelope(ConsensusMessage::<V, D>::NoVote(vote.clone())),
                None,
            ),
            Artifact::Nullify(nullify) => (
                Plane::Consensus,
                self.envelope(ConsensusMessage::<V, D>::Nullify(nullify.clone())),
                None,
            ),
            Artifact::Nullification(nullification) => (
                Plane::Certificate,
                self.envelope(CertificateMessage::<V, D>::Nullification(
                    nullification.clone(),
                )),
                None,
            ),
            Artifact::Vqc(certificate) => (
                Plane::Certificate,
                self.envelope(CertificateMessage::Vqc(certificate.clone())),
                None,
            ),
            Artifact::Lqc(certificate) => (
                Plane::Certificate,
                self.envelope(CertificateMessage::Lqc(certificate.clone())),
                None,
            ),
        };
        Some(Transmission {
            plane,
            bytes,
            recipient,
            relay,
        })
    }

    /// Frames one exact envelope payload.
    pub(super) fn envelope<M: Write + EncodeSize>(&self, payload: M) -> Bytes {
        Envelope::new(self.epoch, payload).encode()
    }

    /// Installs or replaces one outstanding publication and schedules an immediate attempt.
    ///
    /// Exact reinstallation (recovery reissue) resets volatile retry state only.
    pub(super) fn install(
        &mut self,
        id: EffectId,
        generation: u64,
        transmissions: Vec<Transmission<P, D>>,
        sign_ready_at: Option<SystemTime>,
        now: SystemTime,
        origin: PublicationOrigin,
    ) {
        let replaced = self.entries.insert(
            id,
            Entry {
                generation,
                attempts: 0,
                transmissions: transmissions.into(),
                sign_ready_at,
                next: now,
                backoff: self.limits.retry_initial,
                delivered: false,
                origin,
            },
        );
        if let Some(replaced) = replaced {
            let removed = self.deadlines.remove(&(replaced.next, id));
            debug_assert!(removed, "every publication has one retry deadline");
        }
        let inserted = self.deadlines.insert((now, id));
        debug_assert!(inserted, "publication retry deadlines are unique by effect");
    }

    /// Returns the number of outstanding publications.
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Removes publications retired by a machine-owned semantic supersession.
    pub(super) fn retire(&mut self, retired: &[EffectId]) {
        for id in retired {
            if let Some(entry) = self.entries.remove(id) {
                let removed = self.deadlines.remove(&(entry.next, *id));
                debug_assert!(removed, "every publication has one retry deadline");
            }
        }
    }

    /// Returns the next scheduled attempt time, if any work is outstanding.
    pub(super) fn next_attempt(&self) -> Option<SystemTime> {
        self.deadlines.first().map(|(deadline, _)| *deadline)
    }

    /// Collects at most `limit` transmissions due at `now` and advances their bounded backoff.
    ///
    /// The caller reports the first accepted attempt for each effect as volatile `Delivered`
    /// telemetry.
    pub(super) fn due(&mut self, now: SystemTime, limit: usize) -> Vec<Due<P, D>> {
        let mut due = Vec::with_capacity(limit.min(self.entries.len()));
        let mut scheduled = Vec::with_capacity(due.capacity());
        let Some(&first) = self
            .deadlines
            .first()
            .filter(|(deadline, _)| *deadline <= now)
        else {
            return due;
        };
        let cursor = self
            .retry_cursor
            .filter(|(deadline, _)| *deadline == first.0);
        if let Some(cursor) = cursor {
            for &key in self.deadlines.range((
                std::ops::Bound::Excluded(cursor),
                std::ops::Bound::Unbounded,
            )) {
                if key.0 != first.0 || scheduled.len() == limit {
                    break;
                }
                scheduled.push(key);
            }
        }
        for &key in &self.deadlines {
            if key.0 > now || scheduled.len() == limit {
                break;
            }
            if cursor.is_some_and(|cursor| key.0 == first.0 && key > cursor) {
                continue;
            }
            scheduled.push(key);
        }
        for key in &scheduled {
            let removed = self.deadlines.remove(key);
            debug_assert!(removed, "selected retry deadlines remain indexed");
        }
        self.retry_cursor = scheduled.last().copied();
        for (_, id) in scheduled {
            let (next, attempt) = {
                let entry = self
                    .entries
                    .get_mut(&id)
                    .expect("retry deadlines reference live publications");
                let attempt = entry.attempts;
                entry.attempts = entry.attempts.saturating_add(1);
                entry.next = now.saturating_add_ext(entry.backoff);
                entry.backoff = entry
                    .backoff
                    .saturating_mul(2)
                    .min(self.limits.retry_ceiling);
                (
                    entry.next,
                    (
                        id,
                        entry.generation,
                        attempt,
                        entry.delivered,
                        Arc::clone(&entry.transmissions),
                        entry.origin,
                    ),
                )
            };
            let inserted = self.deadlines.insert((next, id));
            debug_assert!(inserted, "a serviced publication receives one new deadline");
            due.push(attempt);
        }
        due
    }

    /// Records volatile local acceptance for one publication attempt.
    pub(super) fn accepted(&mut self, id: EffectId) -> (bool, Option<SystemTime>) {
        let Some(entry) = self.entries.get_mut(&id) else {
            return (false, None);
        };
        let first = !entry.delivered;
        entry.delivered = true;
        (first, first.then_some(entry.sign_ready_at).flatten())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::{
            config::Limits,
            machine::{Cursor, ProposalPublication},
            mocks::Committee,
            types::{ProposalParent, ViewMessage},
        },
        types::{Epoch, View},
    };
    use commonware_cryptography::{
        Sha256, bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
    };
    use commonware_parallel::Sequential;
    use std::{
        num::{NonZeroU64, NonZeroUsize},
        sync::atomic::{AtomicBool, Ordering},
    };
    use tracing::{Id, Subscriber};
    use tracing_subscriber::{Layer, layer::Context, prelude::*, registry::LookupSpan};

    #[derive(Clone)]
    struct CloseLayer {
        round_closed: Arc<AtomicBool>,
    }

    impl<S> Layer<S> for CloseLayer
    where
        S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    {
        fn on_close(&self, id: Id, context: Context<'_, S>) {
            let Some(metadata) = context.metadata(&id) else {
                return;
            };
            if metadata.name() == "test.installation_round" {
                self.round_closed.store(true, Ordering::Relaxed);
            }
        }
    }

    fn limits() -> VoterLimits {
        VoterLimits {
            inflight_application: NonZeroUsize::MIN,
            retry_initial: Duration::from_millis(1),
            retry_ceiling: Duration::from_millis(2),
            heartbeat: Duration::from_secs(1),
            checkpoint_interval: NonZeroU64::MIN,
        }
    }

    #[test]
    fn retry_deadline_and_backoff_saturate() {
        let limits = VoterLimits {
            retry_initial: Duration::MAX,
            retry_ceiling: Duration::MAX,
            heartbeat: Duration::MAX,
            ..limits()
        };
        let now = SystemTime::UNIX_EPOCH;
        let id = EffectId::from_cursor(Cursor::zero());
        let mut egress = Egress::<(), Sha256Digest>::new(Epoch::new(70), limits);
        egress.install(
            id,
            0,
            Vec::new(),
            None,
            now,
            PublicationOrigin { view: View::zero() },
        );

        assert_eq!(egress.due(now, usize::MAX).len(), 1);
        let deadline = egress.next_attempt().expect("the retry remains scheduled");
        assert!(deadline >= now);
        assert_eq!(egress.due(deadline, usize::MAX).len(), 1);
    }

    #[test]
    fn rejected_publication_does_not_retain_installation_round_span() {
        let round_closed = Arc::new(AtomicBool::new(false));
        let subscriber = tracing_subscriber::registry().with(CloseLayer {
            round_closed: Arc::clone(&round_closed),
        });

        tracing::subscriber::with_default(subscriber, || {
            let now = SystemTime::UNIX_EPOCH;
            let id = EffectId::from_cursor(Cursor::zero());
            let mut egress = Egress::<(), Sha256Digest>::new(Epoch::new(79), limits());
            let round = tracing::info_span!(parent: None, "test.installation_round");
            round.in_scope(|| {
                egress.install(
                    id,
                    0,
                    Vec::new(),
                    None,
                    now,
                    PublicationOrigin { view: View::zero() },
                );
            });

            let mut due_at = now;
            for _ in 0..3 {
                assert_eq!(egress.due(due_at, usize::MAX).len(), 1);
                due_at = egress.next_attempt().expect("rejected retry remains live");
            }

            drop(round);
            assert!(
                round_closed.load(Ordering::Relaxed),
                "the durable retry must not own its installation round span"
            );
            assert_eq!(egress.len(), 1, "the rejected obligation remains installed");
        });
    }

    #[test]
    fn saturated_deadline_rotates_across_bounded_turns() {
        const LIMIT: usize = 2;

        let limits = VoterLimits {
            retry_initial: Duration::MAX,
            retry_ceiling: Duration::MAX,
            heartbeat: Duration::MAX,
            ..limits()
        };
        let now = SystemTime::UNIX_EPOCH;
        let mut egress = Egress::<(), Sha256Digest>::new(Epoch::new(78), limits);
        for cursor in 0..=LIMIT {
            egress.install(
                EffectId::from_cursor(Cursor::new(cursor as u64)),
                0,
                Vec::new(),
                None,
                now,
                PublicationOrigin { view: View::zero() },
            );
        }
        while egress.next_attempt() == Some(now) {
            egress.due(now, LIMIT);
        }
        let saturated = egress.next_attempt().expect("retries remain scheduled");

        let first = egress.due(saturated, LIMIT);
        let second = egress.due(saturated, LIMIT);
        let serviced = first
            .iter()
            .chain(&second)
            .map(|attempt| attempt.0)
            .collect::<BTreeSet<_>>();

        assert_eq!(serviced.len(), LIMIT + 1);
    }

    #[test]
    fn retry_deadline_cache_tracks_install_retirement_and_due() {
        let now = SystemTime::UNIX_EPOCH;
        let later = now + Duration::from_millis(10);
        let first = EffectId::from_cursor(Cursor::zero());
        let second = EffectId::from_cursor(Cursor::new(1));
        let mut egress = Egress::<(), Sha256Digest>::new(Epoch::new(75), limits());
        let origin = || PublicationOrigin { view: View::zero() };

        egress.install(first, 0, Vec::new(), None, now, origin());
        egress.install(second, 0, Vec::new(), None, later, origin());
        assert_eq!(egress.next_attempt(), Some(now));

        egress.retire(&[first]);
        assert_eq!(egress.next_attempt(), Some(later));
        assert_eq!(egress.due(later, usize::MAX).len(), 1);
        assert_eq!(
            egress.next_attempt(),
            Some(later + Duration::from_millis(1))
        );
    }

    #[test]
    fn exact_reinstallation_moves_one_deadline() {
        let now = SystemTime::UNIX_EPOCH;
        let later = now + Duration::from_millis(10);
        let id = EffectId::from_cursor(Cursor::zero());
        let mut egress = Egress::<(), Sha256Digest>::new(Epoch::new(77), limits());
        let origin = || PublicationOrigin { view: View::zero() };

        egress.install(id, 0, Vec::new(), None, later, origin());
        egress.install(id, 1, Vec::new(), None, now, origin());

        assert_eq!(egress.entries.len(), 1);
        assert_eq!(egress.deadlines.len(), 1);
        assert_eq!(egress.next_attempt(), Some(now));
        let attempts = egress.due(now, usize::MAX);
        let [attempt] = attempts.as_slice() else {
            panic!("exact reinstallation did not produce one attempt");
        };
        assert_eq!(attempt.1, 1);
        assert_eq!(egress.deadlines.len(), 1);
    }

    #[test]
    fn due_attempts_are_bounded_per_turn() {
        let now = SystemTime::UNIX_EPOCH;
        let mut egress = Egress::<(), Sha256Digest>::new(Epoch::new(76), limits());
        for cursor in 0..3 {
            egress.install(
                EffectId::from_cursor(Cursor::new(cursor)),
                0,
                Vec::new(),
                None,
                now,
                PublicationOrigin { view: View::zero() },
            );
        }

        assert_eq!(egress.due(now, 2).len(), 2);
        assert_eq!(egress.next_attempt(), Some(now));
        assert_eq!(egress.due(now, 2).len(), 1);
        assert!(egress.next_attempt().is_some_and(|next| next > now));
    }

    #[test]
    fn previously_broadcast_parent_is_omitted_from_proposal() {
        let committee = Committee::<MinPk>::new(71, 6, Limits::new(2, 1).unwrap());
        let parent = committee.vqc(1);
        let block = committee.leader_block_with_parent(2, &parent);
        let publication = ProposalPublication::new(
            Arc::new(block.clone()),
            ProposalParent::Exact(Arc::new(parent)),
            false,
        );
        let egress = Egress::<(), Sha256Digest>::new(Epoch::new(71), limits());

        let artifacts = egress
            .proposal_message(&publication)
            .into_artifacts()
            .collect::<Vec<_>>();

        assert_eq!(artifacts, vec![Artifact::LeaderBlock(block)]);
    }

    #[test]
    fn unbroadcast_parent_is_attached_to_proposal() {
        let committee = Committee::<MinPk>::new(72, 6, Limits::new(2, 1).unwrap());
        let parent = committee.vqc(1);
        let block = committee.leader_block_with_parent(2, &parent);
        let publication = ProposalPublication::new(
            Arc::new(block.clone()),
            ProposalParent::Exact(Arc::new(parent.clone())),
            true,
        );
        let egress = Egress::<(), Sha256Digest>::new(Epoch::new(72), limits());

        let artifacts = egress
            .proposal_message(&publication)
            .into_artifacts()
            .collect::<Vec<_>>();

        assert_eq!(
            artifacts,
            vec![Artifact::Vqc(parent), Artifact::LeaderBlock(block)]
        );
    }

    #[test]
    fn updated_broadcast_parent_is_attached_to_proposal() {
        let committee = Committee::<MinPk>::new(73, 6, Limits::new(2, 1).unwrap());
        let leader = committee.leader_block(1);
        let first = committee.vqc(1);
        let messages = [0, 1, 2, 3, 5]
            .into_iter()
            .map(|signer| ViewMessage::Vote(committee.vote(signer, &leader)))
            .collect::<Vec<_>>();
        let parent = committee
            .verifier
            .assemble_vqc::<Sha256, _>(leader.block().clone(), &messages, &Sequential)
            .expect("a different quorum for the same view aggregates");
        assert_ne!(parent.id::<Sha256>(), first.id::<Sha256>());
        let block = committee.leader_block_with_parent(3, &parent);
        let publication = ProposalPublication::new(
            Arc::new(block.clone()),
            ProposalParent::Exact(Arc::new(parent.clone())),
            true,
        );
        let egress = Egress::<(), Sha256Digest>::new(Epoch::new(73), limits());

        let artifacts = egress
            .proposal_message(&publication)
            .into_artifacts()
            .collect::<Vec<_>>();

        assert_eq!(
            artifacts,
            vec![Artifact::Vqc(parent), Artifact::LeaderBlock(block)]
        );
    }

    #[test]
    fn recovered_proposal_reuses_the_durable_parent_choice() {
        let committee = Committee::<MinPk>::new(74, 6, Limits::new(2, 1).unwrap());
        let parent = committee.vqc(1);
        let block = committee.leader_block_with_parent(2, &parent);
        let publication = ProposalPublication::new(
            Arc::new(block),
            ProposalParent::Exact(Arc::new(parent)),
            false,
        );
        let before = Egress::<(), Sha256Digest>::new(Epoch::new(74), limits())
            .frame_proposal(&publication)
            .bytes;
        let recovered = Egress::<(), Sha256Digest>::new(Epoch::new(74), limits())
            .frame_proposal(&publication)
            .bytes;

        assert_eq!(before, recovered);
    }
}
