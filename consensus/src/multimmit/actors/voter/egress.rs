//! Durable publication retry without retirement authority.
//!
//! The machine's durable outbox is the single retry authority: an entry installed here is
//! retried with bounded backoff while local submission is incomplete, then at a coarse repair
//! cadence until the voter observes the machine's typed semantic supersession in a persisted
//! journal event. Local sender acceptance is volatile scheduling telemetry and never retirement
//! authority. Header retries reuse the exact encoded bytes captured when the effect was installed.
//! Relay acceptance gates the first header attempt, then refreshes at the heartbeat cadence while
//! the effect remains live.

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
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use commonware_utils::SystemTimeExt as _;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::{Duration, SystemTime},
};

const FIRST_COMPLETE_REPAIR_MULTIPLIER: u32 = 4;

/// One exact pre-encoded transmission.
#[derive(Clone, Debug)]
pub(super) struct Transmission<P, D: Digest> {
    /// The physical plane carrying the message.
    pub plane: Plane,
    /// The exact encoded envelope bytes.
    pub bytes: Bytes,
    /// The sole recipient, or `None` to broadcast to all connected eligible peers.
    pub recipient: Option<P>,
    /// The canonical transaction-block header digest to relay before publishing the block.
    pub relay: Option<D>,
}

/// One due publication attempt.
pub(super) struct Due<P, D: Digest> {
    pub id: EffectId,
    pub generation: u64,
    pub retries: u64,
    pub delivered: bool,
    pub transmit_due: bool,
    pub relay_due: bool,
    pub transmissions: Arc<[Transmission<P, D>]>,
    pub origin: PublicationOrigin,
}

/// Scalar context retained across an obligation's unbounded retry lifetime.
#[derive(Clone, Copy)]
pub(super) struct PublicationOrigin {
    pub view: View,
}

struct Entry<P, D: Digest> {
    generation: u64,
    attempts: u64,
    transmissions: Arc<[Transmission<P, D>]>,
    next: SystemTime,
    backoff: Duration,
    delivered: bool,
    complete: bool,
    next_relay: Option<SystemTime>,
    origin: PublicationOrigin,
}

impl<P, D: Digest> Entry<P, D> {
    fn attempt(&mut self, id: EffectId, now: SystemTime, retry_ceiling: Duration) -> Due<P, D> {
        let retries = self.attempts;
        let transmit_due = self.next <= now;
        if transmit_due {
            self.attempts = self.attempts.saturating_add(1);
            self.next = now.saturating_add_ext(self.backoff);
            self.backoff = self.backoff.saturating_mul(2).min(retry_ceiling);
        }
        Due {
            id,
            generation: self.generation,
            retries,
            delivered: self.delivered,
            transmit_due,
            relay_due: self.next_relay.is_some_and(|next| next <= now),
            transmissions: Arc::clone(&self.transmissions),
            origin: self.origin,
        }
    }
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

    fn deadline(entry: &Entry<P, D>) -> SystemTime {
        entry
            .next_relay
            .map_or(entry.next, |relay| entry.next.min(relay))
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
    pub(super) fn frame<H: Hasher<Digest = D>, V: Variant>(
        &self,
        artifact: &Artifact<V, D>,
        recipient: Option<P>,
    ) -> Option<Transmission<P, D>> {
        let (plane, bytes, relay) = match artifact {
            Artifact::TransactionBlock(block) => (
                Plane::Data,
                self.envelope(DataMessage::Block(block.clone())),
                Some(block.header().digest::<H>()),
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
        now: SystemTime,
        origin: PublicationOrigin,
    ) {
        let next_relay = transmissions
            .iter()
            .any(|transmission| transmission.relay.is_some())
            .then_some(now);
        let replaced = self.entries.insert(
            id,
            Entry {
                generation,
                attempts: 0,
                transmissions: transmissions.into(),
                next: now,
                backoff: self.limits.retry_initial,
                delivered: false,
                complete: false,
                next_relay,
                origin,
            },
        );
        if let Some(replaced) = replaced {
            let removed = self.deadlines.remove(&(Self::deadline(&replaced), id));
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
                let removed = self.deadlines.remove(&(Self::deadline(&entry), *id));
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
                let attempt = entry.attempt(id, now, self.limits.retry_ceiling);
                (Self::deadline(entry), attempt)
            };
            let inserted = self.deadlines.insert((next, id));
            debug_assert!(inserted, "a serviced publication receives one new deadline");
            due.push(attempt);
        }
        due
    }

    /// Claims one immediate attempt for a single publication, advancing its bounded
    /// backoff exactly as [`Self::due`] would.
    ///
    /// Used to transmit a freshly installed publication inline, leaving the scheduled
    /// path to carry retries only. Returns `None` for an unknown effect.
    pub(super) fn claim(&mut self, id: EffectId, now: SystemTime) -> Option<Due<P, D>> {
        let (prior, next, attempt) = {
            let entry = self.entries.get_mut(&id)?;
            let prior = Self::deadline(entry);
            let attempt = entry.attempt(id, now, self.limits.retry_ceiling);
            (prior, Self::deadline(entry), attempt)
        };
        let removed = self.deadlines.remove(&(prior, id));
        debug_assert!(removed, "every publication has one retry deadline");
        let inserted = self.deadlines.insert((next, id));
        debug_assert!(inserted, "a claimed publication receives one new deadline");
        Some(attempt)
    }

    /// Records acceptance of the Relay obligation for one publication attempt.
    pub(super) fn relay_accepted(&mut self, id: EffectId, now: SystemTime) {
        self.schedule_relay(id, now.saturating_add_ext(self.limits.heartbeat));
    }

    /// Defers a closed Relay obligation to the next transmission retry.
    pub(super) fn relay_rejected(&mut self, id: EffectId) {
        let Some(next) = self.entries.get(&id).map(|entry| entry.next) else {
            return;
        };
        self.schedule_relay(id, next);
    }

    fn schedule_relay(&mut self, id: EffectId, next: SystemTime) {
        let Some(entry) = self.entries.get_mut(&id) else {
            return;
        };
        let prior = Self::deadline(entry);
        entry.next_relay = Some(next);
        let next = Self::deadline(entry);
        let removed = self.deadlines.remove(&(prior, id));
        debug_assert!(removed, "every publication has one retry deadline");
        let inserted = self.deadlines.insert((next, id));
        debug_assert!(inserted, "a Relay update preserves one retry deadline");
    }

    /// Records volatile local submission and schedules its next repair opportunity.
    pub(super) fn submitted(
        &mut self,
        id: EffectId,
        now: SystemTime,
        accepted: bool,
        complete: bool,
    ) -> bool {
        let Some(entry) = self.entries.get_mut(&id) else {
            return false;
        };
        let prior = Self::deadline(entry);
        let first = accepted && !entry.delivered;
        entry.delivered |= accepted;
        if complete {
            let repair = if entry.complete {
                self.limits.retry_ceiling
            } else {
                self.limits
                    .retry_initial
                    .saturating_mul(FIRST_COMPLETE_REPAIR_MULTIPLIER)
                    .min(self.limits.retry_ceiling)
            };
            entry.next = now.saturating_add_ext(repair);
            entry.backoff = self.limits.retry_ceiling;
        } else if entry.complete {
            entry.next = now.saturating_add_ext(self.limits.retry_initial);
            entry.backoff = self
                .limits
                .retry_initial
                .saturating_mul(2)
                .min(self.limits.retry_ceiling);
        }
        entry.complete = complete;
        let next = Self::deadline(entry);
        let removed = self.deadlines.remove(&(prior, id));
        debug_assert!(removed, "every publication has one retry deadline");
        let inserted = self.deadlines.insert((next, id));
        debug_assert!(
            inserted,
            "a submitted publication retains one repair deadline"
        );
        first
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
    use rand::{RngExt as _, SeedableRng as _};
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

    fn retry_limits() -> VoterLimits {
        VoterLimits {
            retry_initial: Duration::from_millis(250),
            retry_ceiling: Duration::from_secs(4),
            heartbeat: Duration::from_secs(10),
            ..limits()
        }
    }

    fn installed_egress(
        epoch: u64,
    ) -> (Egress<(), Sha256Digest>, EffectId, SystemTime, VoterLimits) {
        let limits = retry_limits();
        let now = SystemTime::UNIX_EPOCH;
        let id = EffectId::from_cursor(Cursor::zero());
        let mut egress = Egress::new(Epoch::new(epoch), limits);
        egress.install(
            id,
            0,
            Vec::new(),
            now,
            PublicationOrigin { view: View::zero() },
        );
        (egress, id, now, limits)
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
            .map(|attempt| attempt.id)
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

        egress.install(first, 0, Vec::new(), now, origin());
        egress.install(second, 0, Vec::new(), later, origin());
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

        egress.install(id, 0, Vec::new(), later, origin());
        egress.install(id, 1, Vec::new(), now, origin());

        assert_eq!(egress.entries.len(), 1);
        assert_eq!(egress.deadlines.len(), 1);
        assert_eq!(egress.next_attempt(), Some(now));
        let attempts = egress.due(now, usize::MAX);
        let [attempt] = attempts.as_slice() else {
            panic!("exact reinstallation did not produce one attempt");
        };
        assert_eq!(attempt.generation, 1);
        assert_eq!(egress.deadlines.len(), 1);
    }

    #[test]
    fn claim_advances_backoff_like_a_due_attempt() {
        let limits = VoterLimits {
            retry_initial: Duration::from_millis(10),
            retry_ceiling: Duration::from_millis(40),
            heartbeat: Duration::from_secs(1),
            ..limits()
        };
        let now = SystemTime::UNIX_EPOCH;
        let id = EffectId::from_cursor(Cursor::zero());
        let mut egress = Egress::<(), Sha256Digest>::new(Epoch::new(81), limits);
        egress.install(
            id,
            0,
            Vec::new(),
            now,
            PublicationOrigin { view: View::zero() },
        );

        let first = egress.claim(id, now).expect("installed publication claims");
        assert_eq!(first.retries, 0);
        assert!(first.transmit_due);
        assert_eq!(
            egress.next_attempt(),
            Some(now + Duration::from_millis(10)),
            "the claimed attempt consumes the immediate deadline"
        );
        assert!(
            egress.due(now, usize::MAX).is_empty(),
            "no immediate retry remains after the inline claim"
        );

        let retry_at = egress.next_attempt().expect("retry remains scheduled");
        let retry = egress
            .due(retry_at, usize::MAX)
            .pop()
            .expect("retry is due");
        assert_eq!(retry.retries, 1);
        assert!(
            egress
                .claim(EffectId::from_cursor(Cursor::new(9)), now)
                .is_none()
        );
    }

    #[test]
    fn retry_deadlines_survive_random_actor_interleavings() {
        // Emulates the actor's exact call discipline around the egress under randomized
        // interleavings of install, retire, inline claims, scheduled attempts, relay feedback,
        // and submission outcomes. Two properties must hold at every step: the deadline index
        // matches the entry set exactly, and no live publication is ever starved past the
        // repair horizon.
        let limits = retry_limits();
        let horizon = limits.retry_ceiling.max(limits.heartbeat) + Duration::from_secs(1);
        for seed in 0..64u64 {
            let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
            let mut egress: Egress<(), Sha256Digest> = Egress::new(Epoch::new(90), limits);
            let mut now = SystemTime::UNIX_EPOCH;
            let mut live: Vec<EffectId> = Vec::new();

            let check_index = |egress: &Egress<(), Sha256Digest>| {
                assert_eq!(
                    egress.deadlines.len(),
                    egress.entries.len(),
                    "deadline index and entry set diverged"
                );
                for (id, entry) in &egress.entries {
                    assert!(
                        egress.deadlines.contains(&(Egress::deadline(entry), *id)),
                        "entry {id:?} lost its deadline"
                    );
                }
            };

            for op in 0..600u32 {
                let attempt = |egress: &mut Egress<(), Sha256Digest>,
                               rng: &mut rand::rngs::StdRng,
                               now: SystemTime,
                               due: Due<(), Sha256Digest>| {
                    if due.relay_due && rng.random_bool(0.2) {
                        egress.relay_rejected(due.id);
                        return;
                    }
                    if due.relay_due {
                        egress.relay_accepted(due.id, now);
                    }
                    if due.transmit_due {
                        let accepted = rng.random_bool(0.9);
                        let complete = accepted && rng.random_bool(0.8);
                        egress.submitted(due.id, now, accepted, complete);
                    }
                };
                match rng.random_range(0..10u32) {
                    0..=2 => {
                        let id = EffectId::from_cursor(Cursor::new(rng.random_range(0..12u64)));
                        let relay = rng
                            .random_bool(0.5)
                            .then(|| Sha256::hash(&[b"relayed header"]));
                        let transmissions = vec![Transmission {
                            plane: Plane::Consensus,
                            bytes: Bytes::new(),
                            recipient: None,
                            relay,
                        }];
                        egress.install(
                            id,
                            0,
                            transmissions,
                            now,
                            PublicationOrigin { view: View::zero() },
                        );
                        if !live.contains(&id) {
                            live.push(id);
                        }
                        if rng.random_bool(0.7)
                            && let Some(due) = egress.claim(id, now)
                        {
                            attempt(&mut egress, &mut rng, now, due);
                        }
                    }
                    3 => {
                        if let Some(index) =
                            (!live.is_empty()).then(|| rng.random_range(0..live.len()))
                        {
                            let id = live.swap_remove(index);
                            egress.retire(&[id]);
                        }
                    }
                    4..=7 => {
                        let limit = rng.random_range(1..4usize);
                        for due in egress.due(now, limit) {
                            attempt(&mut egress, &mut rng, now, due);
                        }
                    }
                    _ => {
                        now += Duration::from_millis(rng.random_range(0..600u64));
                    }
                }
                check_index(&egress);

                // Liveness sweep: far past every pacing horizon, one unbounded drain must
                // surface every live publication as transmit-due.
                if op % 97 == 96 {
                    now += horizon;
                    let drained = egress.due(now, usize::MAX);
                    let mut ids = drained.iter().map(|due| due.id).collect::<Vec<_>>();
                    ids.sort_unstable();
                    let mut expected = live.clone();
                    expected.sort_unstable();
                    assert_eq!(
                        ids, expected,
                        "seed {seed} op {op}: starved publications survived the horizon"
                    );
                    assert!(
                        drained.iter().all(|due| due.transmit_due),
                        "seed {seed} op {op}: a horizon drain must be transmit-due"
                    );
                    for due in drained {
                        attempt(&mut egress, &mut rng, now, due);
                    }
                    check_index(&egress);
                }
            }
        }
    }

    #[test]
    fn accepted_publication_settles_without_healthy_path_retry() {
        let (mut egress, id, now, _) = installed_egress(82);

        let first = egress.claim(id, now).expect("installed publication claims");
        assert!(first.transmit_due);
        assert!(egress.submitted(id, now, true, true));

        let settled_at = now + Duration::from_millis(340);
        assert!(
            egress.due(settled_at, usize::MAX).is_empty(),
            "a locally accepted publication must not retry during healthy settlement"
        );
        egress.retire(&[id]);
        assert_eq!(egress.next_attempt(), None);
    }

    #[test]
    fn accepted_publication_remains_repairable() {
        let (mut egress, id, now, limits) = installed_egress(83);

        egress.claim(id, now).expect("installed publication claims");
        assert!(egress.submitted(id, now, true, true));

        let repair_at = now
            + limits
                .retry_initial
                .saturating_mul(FIRST_COMPLETE_REPAIR_MULTIPLIER);
        assert!(
            egress
                .due(repair_at - Duration::from_nanos(1), 1)
                .is_empty()
        );
        let repair = egress.due(repair_at, 1).pop().expect("repair is due");
        assert!(repair.transmit_due);
        assert_eq!(repair.retries, 1);
        assert!(repair.delivered);
        assert_eq!(
            egress.next_attempt(),
            Some(repair_at + limits.retry_ceiling)
        );
    }

    #[test]
    fn rejected_publication_keeps_initial_retry() {
        let (mut egress, id, now, limits) = installed_egress(84);

        egress.claim(id, now).expect("installed publication claims");

        assert!(
            egress
                .due(now + limits.retry_initial - Duration::from_nanos(1), 1)
                .is_empty()
        );
        let retry_at = now + limits.retry_initial;
        let retry = egress
            .due(retry_at, 1)
            .pop()
            .expect("rejected publication retries promptly");
        assert_eq!(retry.retries, 1);
        assert!(!retry.delivered);
        assert!(egress.submitted(id, retry_at, true, true));
        assert_eq!(
            egress.next_attempt(),
            Some(
                retry_at
                    + limits
                        .retry_initial
                        .saturating_mul(FIRST_COMPLETE_REPAIR_MULTIPLIER)
            )
        );
    }

    #[test]
    fn incomplete_repair_returns_to_initial_backoff() {
        let (mut egress, id, now, limits) = installed_egress(85);
        egress.claim(id, now).expect("installed publication claims");
        egress.submitted(id, now, true, true);

        let repair_at = now
            + limits
                .retry_initial
                .saturating_mul(FIRST_COMPLETE_REPAIR_MULTIPLIER);
        egress.due(repair_at, 1).pop().expect("repair is due");
        egress.submitted(id, repair_at, false, false);

        assert_eq!(
            egress.next_attempt(),
            Some(repair_at + limits.retry_initial)
        );
        let retry = egress
            .due(repair_at + limits.retry_initial, 1)
            .pop()
            .expect("incomplete repair retries promptly");
        assert_eq!(retry.retries, 2);
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
    fn transaction_block_retries_canonical_header_digest() {
        let committee = Committee::<MinPk>::new(80, 6, Limits::new(2, 1).unwrap());
        let block = committee.signed_block(0, Sha256::hash(&[b"application body"]));
        let header_digest = block.header().digest::<Sha256>();
        assert_ne!(header_digest, block.header().body_digest());
        let limits = VoterLimits {
            retry_initial: Duration::from_millis(70),
            retry_ceiling: Duration::from_millis(70),
            heartbeat: Duration::from_millis(200),
            ..limits()
        };
        let mut egress = Egress::<(), Sha256Digest>::new(Epoch::new(80), limits);

        let transmission = egress
            .frame::<Sha256, _>(&Artifact::TransactionBlock(block), None)
            .expect("a transaction block has an authorized publication frame");
        assert_eq!(transmission.relay, Some(header_digest));

        let now = SystemTime::UNIX_EPOCH;
        let id = EffectId::from_cursor(Cursor::zero());
        egress.install(
            id,
            0,
            vec![transmission],
            now,
            PublicationOrigin { view: View::zero() },
        );
        let first = egress.due(now, 1).pop().expect("initial attempt is due");
        egress.relay_accepted(id, now);
        let first_retry = egress.next_attempt().expect("retry remains scheduled");
        let second = egress.due(first_retry, 1).pop().expect("retry is due");
        let second_retry = egress.next_attempt().expect("retry remains scheduled");
        let third = egress.due(second_retry, 1).pop().expect("retry is due");
        let refresh_at = egress
            .next_attempt()
            .expect("Relay refresh remains scheduled");
        let refresh = egress
            .due(refresh_at, 1)
            .pop()
            .expect("Relay refresh is due");

        assert!(first.transmit_due);
        assert!(first.relay_due);
        assert!(second.transmit_due);
        assert!(!second.relay_due);
        assert!(third.transmit_due);
        assert!(!third.relay_due);
        assert!(!refresh.transmit_due);
        assert!(refresh.relay_due);
        assert_eq!(refresh_at, now + limits.heartbeat);
        assert_eq!(first.transmissions[0].relay, Some(header_digest));
        assert_eq!(second.transmissions[0].relay, Some(header_digest));
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
