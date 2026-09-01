//! Encode-once retry scheduler for publications the machine asked to send.
//!
//! Entries leave only when the machine retires them. An entry is retried with bounded backoff while
//! local submission is incomplete, then at a slower repair interval. Retries reuse the bytes encoded
//! at install. Relay acceptance gates the first header attempt and is refreshed at the heartbeat
//! while the entry is live.

use super::VoterLimits;
use crate::{
    multimmit::{
        machine::{EffectId, Generation, ProposalParent, ProposalPublication},
        types::{Artifact, Vqc},
        wire::{Frame, Plane},
    },
    types::{Epoch, View},
};
use bytes::Bytes;
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use commonware_utils::SystemTimeExt as _;
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Bound,
    sync::Arc,
    time::{Duration, SystemTime},
};

/// Multiple of the initial retry backoff that delays the first repair after a complete submission.
///
/// A complete submission means every recipient accepted the bytes, so an immediate retry would
/// only duplicate them. Four initial backoffs leave time for the machine to retire the publication
/// in a healthy view before the first repair, while still repairing a lost message well before the
/// retry ceiling.
const FIRST_COMPLETE_REPAIR_MULTIPLIER: u32 = 4;

/// Retry pacing for outstanding publications.
#[derive(Clone, Copy, Debug)]
pub(super) struct EgressConfig {
    /// Backoff after the first incomplete attempt.
    pub(crate) retry_initial: Duration,
    /// Largest backoff between attempts.
    pub(crate) retry_ceiling: Duration,
    /// Interval between Relay refreshes of a live publication.
    pub(crate) relay_refresh: Duration,
}

impl From<VoterLimits> for EgressConfig {
    fn from(limits: VoterLimits) -> Self {
        Self {
            retry_initial: limits.retry_initial,
            retry_ceiling: limits.retry_ceiling,
            relay_refresh: limits.heartbeat,
        }
    }
}

/// One pre-encoded transmission.
#[derive(Clone, Debug)]
pub(super) struct Transmission<P, D: Digest> {
    /// The physical plane carrying the message.
    pub(crate) plane: Plane,
    /// The encoded envelope bytes.
    pub(crate) bytes: Bytes,
    /// The sole recipient, or `None` to broadcast to all connected eligible peers.
    pub(crate) recipient: Option<P>,
    /// The canonical transaction-block header digest to relay before publishing the block.
    pub(crate) relay: Option<D>,
}

/// What the network accepted from one publication attempt.
#[derive(Clone, Copy, Debug)]
pub(super) struct Submission {
    /// At least one recipient accepted a transmission.
    pub(crate) accepted: bool,
    /// Every intended recipient accepted every transmission.
    pub(crate) complete: bool,
}

/// One due publication attempt.
pub(super) struct Due<P, D: Digest> {
    /// The publication's effect.
    pub(crate) id: EffectId,
    /// The process generation that installed the publication.
    pub(crate) generation: Generation,
    /// Attempts made before this one.
    pub(crate) retries: u64,
    /// Whether any earlier attempt was accepted by the network.
    pub(crate) delivered: bool,
    /// Whether the transmissions are due in this attempt.
    pub(crate) transmit_due: bool,
    /// Whether the Relay obligation is due in this attempt.
    pub(crate) relay_due: bool,
    /// The encoded transmissions captured at installation.
    pub(crate) transmissions: Arc<[Transmission<P, D>]>,
    /// The view in which the publication was installed.
    pub(crate) view: View,
}

struct Entry<P, D: Digest> {
    generation: Generation,
    attempts: u64,
    transmissions: Arc<[Transmission<P, D>]>,
    next: SystemTime,
    backoff: Duration,
    delivered: bool,
    complete: bool,
    next_relay: Option<SystemTime>,
    view: View,
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
            view: self.view,
        }
    }
}

/// Encode-once retry state for the machine's outstanding publications.
pub(super) struct Egress<P, D: Digest> {
    epoch: Epoch,
    entries: BTreeMap<EffectId, Entry<P, D>>,
    deadlines: BTreeSet<(SystemTime, EffectId)>,
    retry_cursor: Option<(SystemTime, EffectId)>,
    config: EgressConfig,
}

impl<P: Clone, D: Digest> Egress<P, D> {
    pub(super) const fn new(epoch: Epoch, config: EgressConfig) -> Self {
        Self {
            epoch,
            entries: BTreeMap::new(),
            deadlines: BTreeSet::new(),
            retry_cursor: None,
            config,
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
        let Frame {
            plane,
            bytes,
            relay,
        } = Frame::proposal(
            self.epoch,
            publication.block(),
            proposal_parent(publication),
        );
        Transmission {
            plane,
            bytes,
            recipient: None,
            relay,
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
        let Frame {
            plane,
            bytes,
            relay,
        } = Frame::artifact::<H, V>(self.epoch, artifact)?;
        Some(Transmission {
            plane,
            bytes,
            recipient,
            relay,
        })
    }

    /// Installs or replaces one outstanding publication and schedules an immediate attempt.
    ///
    /// Reinstallation (recovery reissue) resets volatile retry state only.
    pub(super) fn install(
        &mut self,
        id: EffectId,
        generation: Generation,
        transmissions: Vec<Transmission<P, D>>,
        now: SystemTime,
        view: View,
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
                backoff: self.config.retry_initial,
                delivered: false,
                complete: false,
                next_relay,
                view,
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
            for &key in self
                .deadlines
                .range((Bound::Excluded(cursor), Bound::Unbounded))
            {
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
                let attempt = entry.attempt(id, now, self.config.retry_ceiling);
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
        let retry_ceiling = self.config.retry_ceiling;
        self.update(id, |entry| entry.attempt(id, now, retry_ceiling))
    }

    /// Records acceptance of the Relay obligation for one publication attempt.
    pub(super) fn relay_accepted(&mut self, id: EffectId, now: SystemTime) {
        self.schedule_relay(id, now.saturating_add_ext(self.config.relay_refresh));
    }

    /// Defers a closed Relay obligation to the next transmission retry.
    pub(super) fn relay_rejected(&mut self, id: EffectId) {
        let Some(next) = self.entries.get(&id).map(|entry| entry.next) else {
            return;
        };
        self.schedule_relay(id, next);
    }

    fn schedule_relay(&mut self, id: EffectId, next: SystemTime) {
        self.update(id, |entry| entry.next_relay = Some(next));
    }

    /// Records volatile local submission and schedules its next repair opportunity.
    ///
    /// Returns whether this attempt is the publication's first accepted one.
    pub(super) fn submitted(
        &mut self,
        id: EffectId,
        now: SystemTime,
        submission: Submission,
    ) -> bool {
        let config = self.config;
        self.update(id, |entry| {
            let first = submission.accepted && !entry.delivered;
            entry.delivered |= submission.accepted;
            if submission.complete {
                let repair = if entry.complete {
                    config.retry_ceiling
                } else {
                    config
                        .retry_initial
                        .saturating_mul(FIRST_COMPLETE_REPAIR_MULTIPLIER)
                        .min(config.retry_ceiling)
                };
                entry.next = now.saturating_add_ext(repair);
                entry.backoff = config.retry_ceiling;
            } else if entry.complete {
                entry.next = now.saturating_add_ext(config.retry_initial);
                entry.backoff = config
                    .retry_initial
                    .saturating_mul(2)
                    .min(config.retry_ceiling);
            }
            entry.complete = submission.complete;
            first
        })
        .unwrap_or(false)
    }

    /// Applies `f` to one live publication and moves its retry deadline once.
    ///
    /// Returns `None` for an unknown effect.
    fn update<R>(&mut self, id: EffectId, f: impl FnOnce(&mut Entry<P, D>) -> R) -> Option<R> {
        let entry = self.entries.get_mut(&id)?;
        let prior = Self::deadline(entry);
        let result = f(entry);
        let next = Self::deadline(entry);
        let removed = self.deadlines.remove(&(prior, id));
        debug_assert!(removed, "every publication has one retry deadline");
        let inserted = self.deadlines.insert((next, id));
        debug_assert!(inserted, "an updated publication keeps one retry deadline");
        Some(result)
    }
}

/// Returns the parent a proposal carries: its exact parent V-QC, unless the machine recorded that
/// the parent was already broadcast or the parent is synthetic genesis.
fn proposal_parent<V: Variant, D: Digest>(
    publication: &ProposalPublication<V, D>,
) -> Option<&Vqc<V, D>> {
    match publication.parent() {
        ProposalParent::Genesis => None,
        ProposalParent::Exact(parent) if publication.attach_parent() => Some(parent.as_ref()),
        ProposalParent::Exact(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::{
            machine::{Cursor, ProposalPublication},
            mocks::Committee,
            types::{ChainId, ViewMessage},
            wire::{ConsensusMessage, Envelope, EnvelopeConfig},
        },
        types::{Epoch, Participant, View},
    };
    use commonware_codec::Decode as _;
    use commonware_cryptography::{
        Sha256, bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
    };
    use commonware_parallel::Sequential;
    use commonware_utils::TestRng;
    use rand::RngExt as _;
    use std::sync::atomic::{AtomicBool, Ordering};
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

    /// Decodes a framed proposal back into the artifacts it carries, in observation order.
    fn proposal_artifacts(
        committee: &Committee<MinPk>,
        egress: &Egress<(), Sha256Digest>,
        publication: &ProposalPublication<MinPk, Sha256Digest>,
    ) -> Vec<Artifact<MinPk, Sha256Digest>> {
        let transmission = egress.frame_proposal(publication);
        let config = EnvelopeConfig {
            max_frame_bytes: usize::MAX,
            epoch: egress.epoch,
            payload: committee.codec(),
        };
        Envelope::<ConsensusMessage<MinPk, Sha256Digest>>::decode_cfg(transmission.bytes, &config)
            .expect("the proposal frame decodes")
            .into_payload()
            .into_artifacts()
            .collect()
    }

    const fn limits() -> EgressConfig {
        EgressConfig {
            retry_initial: Duration::from_millis(1),
            retry_ceiling: Duration::from_millis(2),
            relay_refresh: Duration::from_secs(1),
        }
    }

    const fn retry_limits() -> EgressConfig {
        EgressConfig {
            retry_initial: Duration::from_millis(250),
            retry_ceiling: Duration::from_secs(4),
            relay_refresh: Duration::from_secs(10),
        }
    }

    fn installed_egress(
        epoch: u64,
    ) -> (Egress<(), Sha256Digest>, EffectId, SystemTime, EgressConfig) {
        let limits = retry_limits();
        let now = SystemTime::UNIX_EPOCH;
        let id = EffectId::from_cursor(Cursor::zero());
        let mut egress = Egress::new(Epoch::new(epoch), limits);
        egress.install(id, Generation::new(0), Vec::new(), now, View::zero());
        (egress, id, now, limits)
    }

    #[test]
    fn retry_deadline_and_backoff_saturate() {
        let limits = EgressConfig {
            retry_initial: Duration::MAX,
            retry_ceiling: Duration::MAX,
            relay_refresh: Duration::MAX,
        };
        let now = SystemTime::UNIX_EPOCH;
        let id = EffectId::from_cursor(Cursor::zero());
        let mut egress = Egress::<(), Sha256Digest>::new(Epoch::new(70), limits);
        egress.install(id, Generation::new(0), Vec::new(), now, View::zero());

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
                egress.install(id, Generation::new(0), Vec::new(), now, View::zero());
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

        let limits = EgressConfig {
            retry_initial: Duration::MAX,
            retry_ceiling: Duration::MAX,
            relay_refresh: Duration::MAX,
        };
        let now = SystemTime::UNIX_EPOCH;
        let mut egress = Egress::<(), Sha256Digest>::new(Epoch::new(78), limits);
        for cursor in 0..=LIMIT {
            egress.install(
                EffectId::from_cursor(Cursor::new(cursor as u64)),
                Generation::new(0),
                Vec::new(),
                now,
                View::zero(),
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

        egress.install(first, Generation::new(0), Vec::new(), now, View::zero());
        egress.install(second, Generation::new(0), Vec::new(), later, View::zero());
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

        egress.install(id, Generation::new(0), Vec::new(), later, View::zero());
        egress.install(id, Generation::new(1), Vec::new(), now, View::zero());

        assert_eq!(egress.entries.len(), 1);
        assert_eq!(egress.deadlines.len(), 1);
        assert_eq!(egress.next_attempt(), Some(now));
        let attempts = egress.due(now, usize::MAX);
        let [attempt] = attempts.as_slice() else {
            panic!("exact reinstallation did not produce one attempt");
        };
        assert_eq!(attempt.generation, Generation::new(1));
        assert_eq!(egress.deadlines.len(), 1);
    }

    #[test]
    fn claim_advances_backoff_like_a_due_attempt() {
        let limits = EgressConfig {
            retry_initial: Duration::from_millis(10),
            retry_ceiling: Duration::from_millis(40),
            relay_refresh: Duration::from_secs(1),
        };
        let now = SystemTime::UNIX_EPOCH;
        let id = EffectId::from_cursor(Cursor::zero());
        let mut egress = Egress::<(), Sha256Digest>::new(Epoch::new(81), limits);
        egress.install(id, Generation::new(0), Vec::new(), now, View::zero());

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
        // Emulates the actor's call discipline around the egress under randomized
        // interleavings of install, retire, inline claims, scheduled attempts, relay feedback,
        // and submission outcomes. Two properties must hold at every step: the deadline index
        // matches the entry set exactly, and no live publication is ever starved past the
        // repair horizon.
        let limits = retry_limits();
        let horizon = limits.retry_ceiling.max(limits.relay_refresh) + Duration::from_secs(1);
        for seed in 0..64u64 {
            let mut rng = TestRng::new(seed);
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
                               rng: &mut TestRng,
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
                        egress.submitted(due.id, now, Submission { accepted, complete });
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
                        egress.install(id, Generation::new(0), transmissions, now, View::zero());
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
        assert!(egress.submitted(
            id,
            now,
            Submission {
                accepted: true,
                complete: true
            }
        ));

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
        assert!(egress.submitted(
            id,
            now,
            Submission {
                accepted: true,
                complete: true
            }
        ));

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
        assert!(egress.submitted(
            id,
            retry_at,
            Submission {
                accepted: true,
                complete: true
            }
        ));
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
        egress.submitted(
            id,
            now,
            Submission {
                accepted: true,
                complete: true,
            },
        );

        let repair_at = now
            + limits
                .retry_initial
                .saturating_mul(FIRST_COMPLETE_REPAIR_MULTIPLIER);
        egress.due(repair_at, 1).pop().expect("repair is due");
        egress.submitted(
            id,
            repair_at,
            Submission {
                accepted: false,
                complete: false,
            },
        );

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
                Generation::new(0),
                Vec::new(),
                now,
                View::zero(),
            );
        }

        assert_eq!(egress.due(now, 2).len(), 2);
        assert_eq!(egress.next_attempt(), Some(now));
        assert_eq!(egress.due(now, 2).len(), 1);
        assert!(egress.next_attempt().is_some_and(|next| next > now));
    }

    #[test]
    fn transaction_block_retries_canonical_header_digest() {
        let committee = Committee::<MinPk>::builder(80, 6).build();
        let block = committee.signed_block(ChainId::new(0), Sha256::hash(&[b"application body"]));
        let header_digest = block.header().digest::<Sha256>();
        assert_ne!(header_digest, block.header().body_digest());
        let limits = EgressConfig {
            retry_initial: Duration::from_millis(70),
            retry_ceiling: Duration::from_millis(70),
            relay_refresh: Duration::from_millis(200),
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
            Generation::new(0),
            vec![transmission],
            now,
            View::zero(),
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
        assert_eq!(refresh_at, now + limits.relay_refresh);
        assert_eq!(first.transmissions[0].relay, Some(header_digest));
        assert_eq!(second.transmissions[0].relay, Some(header_digest));
    }

    #[test]
    fn previously_broadcast_parent_is_omitted_from_proposal() {
        let committee = Committee::<MinPk>::builder(71, 6).build();
        let parent = committee.vqc(View::new(1));
        let block = committee.leader_block_with_parent(View::new(2), &parent);
        let publication = ProposalPublication::new(
            Arc::new(block.clone()),
            ProposalParent::Exact(Arc::new(parent)),
            false,
        );
        let egress = Egress::<(), Sha256Digest>::new(Epoch::new(71), limits());

        let artifacts = proposal_artifacts(&committee, &egress, &publication);

        assert_eq!(artifacts, vec![Artifact::LeaderBlock(block)]);
    }

    #[test]
    fn unbroadcast_parent_is_attached_to_proposal() {
        let committee = Committee::<MinPk>::builder(72, 6).build();
        let parent = committee.vqc(View::new(1));
        let block = committee.leader_block_with_parent(View::new(2), &parent);
        let publication = ProposalPublication::new(
            Arc::new(block.clone()),
            ProposalParent::Exact(Arc::new(parent.clone())),
            true,
        );
        let egress = Egress::<(), Sha256Digest>::new(Epoch::new(72), limits());

        let artifacts = proposal_artifacts(&committee, &egress, &publication);

        assert_eq!(
            artifacts,
            vec![Artifact::Vqc(parent), Artifact::LeaderBlock(block)]
        );
    }

    #[test]
    fn updated_broadcast_parent_is_attached_to_proposal() {
        let committee = Committee::<MinPk>::builder(73, 6).build();
        let leader = committee.leader_block(View::new(1));
        let first = committee.vqc(View::new(1));
        let messages = [0, 1, 2, 3, 5]
            .into_iter()
            .map(|signer| {
                ViewMessage::Vote(committee.vote(Participant::from_usize(signer), &leader))
            })
            .collect::<Vec<_>>();
        let parent = committee
            .verifier
            .assemble_vqc::<Sha256, _>(leader.block().clone(), &messages, &Sequential)
            .expect("a different quorum for the same view aggregates");
        assert_ne!(parent.id::<Sha256>(), first.id::<Sha256>());
        let block = committee.leader_block_with_parent(View::new(3), &parent);
        let publication = ProposalPublication::new(
            Arc::new(block.clone()),
            ProposalParent::Exact(Arc::new(parent.clone())),
            true,
        );
        let egress = Egress::<(), Sha256Digest>::new(Epoch::new(73), limits());

        let artifacts = proposal_artifacts(&committee, &egress, &publication);

        assert_eq!(
            artifacts,
            vec![Artifact::Vqc(parent), Artifact::LeaderBlock(block)]
        );
    }

    #[test]
    fn recovered_proposal_reuses_the_durable_parent_choice() {
        let committee = Committee::<MinPk>::builder(74, 6).build();
        let parent = committee.vqc(View::new(1));
        let block = committee.leader_block_with_parent(View::new(2), &parent);
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
