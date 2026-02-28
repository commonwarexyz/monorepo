//! Batcher actor implementation for Minimmit consensus.
//!
//! The batcher handles:
//! - Receiving votes from the network
//! - Batch signature verification
//! - Forwarding verified votes to the voter (state machine handles certificate construction)
//! - Forwarding verified certificates from the network to the voter

use super::{ingress::Message, Config, Mailbox, Round};
use crate::{
    minimmit::{
        actors::voter,
        interesting,
        metrics::{Inbound, Peer},
        scheme::Scheme,
        types::{Activity, Certificate, Vote},
    },
    types::{Epoch, View, ViewDelta},
    Epochable, Reporter, Viewable,
};
use commonware_cryptography::Digest;
use commonware_macros::select_loop;
use commonware_p2p::{utils::codec::WrappedReceiver, Blocker, Receiver};
use commonware_parallel::Strategy;
use commonware_runtime::{
    spawn_cell,
    telemetry::metrics::{
        histogram::{self, Buckets},
        status::GaugeExt,
    },
    Clock, ContextCell, Handle, Metrics, Spawner,
};
use commonware_utils::{
    channel::{fallible::OneshotExt, mpsc},
    ordered::{Quorum, Set},
};
use prometheus_client::metrics::{
    counter::Counter, family::Family, gauge::Gauge, histogram::Histogram,
};
use rand_core::CryptoRngCore;
use std::{collections::BTreeMap, sync::Arc};
use tracing::{debug, trace};

/// Batcher actor for Minimmit consensus.
///
/// Handles message batching, verification, and forwarding to voter.
/// Certificate construction is delegated to the state machine in the voter.
pub struct Actor<E, S, B, D, R, T>
where
    E: Spawner + Metrics + Clock + CryptoRngCore,
    S: Scheme<D>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    R: Reporter<Activity = Activity<S, D>>,
    T: Strategy,
{
    context: ContextCell<E>,

    participants: Set<S::PublicKey>,
    scheme: S,

    blocker: B,
    reporter: R,
    strategy: T,

    activity_timeout: ViewDelta,
    skip_timeout: ViewDelta,
    epoch: Epoch,

    mailbox_receiver: mpsc::Receiver<Message<S, D>>,

    added: Counter,
    verified: Counter,
    inbound_messages: Family<Inbound, Counter>,
    latest_vote: Family<Peer, Gauge>,
    batch_size: Histogram,
    verify_latency: histogram::Timed<E>,
}

impl<E, S, B, D, R, T> Actor<E, S, B, D, R, T>
where
    E: Spawner + Metrics + Clock + CryptoRngCore,
    S: Scheme<D>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    R: Reporter<Activity = Activity<S, D>>,
    T: Strategy,
{
    /// Create a new batcher actor.
    pub fn new(context: E, cfg: Config<S, B, D, R, T>) -> (Self, Mailbox<S, D>) {
        let added = Counter::default();
        let verified = Counter::default();
        let inbound_messages = Family::<Inbound, Counter>::default();
        let batch_size =
            Histogram::new([1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0, 512.0]);
        context.register(
            "added",
            "number of messages added to the verifier",
            added.clone(),
        );
        context.register("verified", "number of messages verified", verified.clone());
        context.register(
            "inbound_messages",
            "number of inbound messages",
            inbound_messages.clone(),
        );
        let latest_vote = Family::<Peer, Gauge>::default();
        context.register(
            "latest_vote",
            "view of latest vote received per peer",
            latest_vote.clone(),
        );
        for participant in cfg.scheme.participants().iter() {
            latest_vote.get_or_create(&Peer::new(participant)).set(0);
        }
        context.register(
            "batch_size",
            "number of messages in a signature verification batch",
            batch_size.clone(),
        );
        let verify_latency = Histogram::new(Buckets::CRYPTOGRAPHY);
        context.register(
            "verify_latency",
            "latency of signature verification",
            verify_latency.clone(),
        );
        // TODO(#1833): Metrics should use the post-start context
        let clock = Arc::new(context.clone());
        let (sender, receiver) = mpsc::channel(cfg.mailbox_size);
        (
            Self {
                context: ContextCell::new(context),

                participants: cfg.scheme.participants().clone(),
                scheme: cfg.scheme,

                blocker: cfg.blocker,
                reporter: cfg.reporter,
                strategy: cfg.strategy,

                activity_timeout: cfg.activity_timeout,
                skip_timeout: cfg.skip_timeout,
                epoch: cfg.epoch,

                mailbox_receiver: receiver,

                added,
                verified,
                inbound_messages,
                latest_vote,
                batch_size,
                verify_latency: histogram::Timed::new(verify_latency, clock),
            },
            Mailbox::new(sender),
        )
    }

    fn new_round(&self) -> Round<S, B, D, R> {
        Round::new(
            self.participants.clone(),
            self.scheme.clone(),
            self.blocker.clone(),
            self.reporter.clone(),
        )
    }

    /// Records that an M-notarization exists for `view`.
    ///
    /// The replay hint can arrive before any votes for the view are observed.
    /// In that case we still need a round so the verifier can batch toward
    /// L-quorum once additional votes arrive.
    fn mark_m_notarization_exists(&self, work: &mut BTreeMap<View, Round<S, B, D, R>>, view: View) {
        work.entry(view)
            .or_insert_with(|| self.new_round())
            .mark_m_quorum_reached();
    }

    /// Start the batcher actor.
    pub fn start(
        mut self,
        voter: voter::Mailbox<S, D>,
        vote_receiver: impl Receiver<PublicKey = S::PublicKey>,
        certificate_receiver: impl Receiver<PublicKey = S::PublicKey>,
    ) -> Handle<()> {
        spawn_cell!(
            self.context,
            self.run(voter, vote_receiver, certificate_receiver).await
        )
    }

    pub async fn run(
        mut self,
        mut voter: voter::Mailbox<S, D>,
        vote_receiver: impl Receiver<PublicKey = S::PublicKey>,
        certificate_receiver: impl Receiver<PublicKey = S::PublicKey>,
    ) {
        // Wrap channels
        let mut vote_receiver: WrappedReceiver<_, Vote<S, D>> =
            WrappedReceiver::new((), vote_receiver);
        let mut certificate_receiver: WrappedReceiver<_, Certificate<S, D>> =
            WrappedReceiver::new(self.scheme.certificate_codec_config(), certificate_receiver);

        // Initialize view data structures
        let mut current = View::zero();
        let mut finalized = View::zero();
        let mut work = BTreeMap::new();
        select_loop! {
            self.context,
            on_start => {
                // Track which view was modified (if any) for verification
                let updated_view;
            },
            on_stopped => {
                debug!("context shutdown, stopping batcher");
            },
            Some(message) = self.mailbox_receiver.recv() else break => {
                match message {
                    Message::Update {
                        current: new_current,
                        leader,
                        finalized: new_finalized,
                        active,
                    } => {
                        current = new_current;
                        finalized = new_finalized;
                        work
                            .entry(current)
                            .or_insert_with(|| self.new_round())
                            .set_leader(leader);

                        // Check if the leader has been active recently
                        let skip_timeout = self.skip_timeout.get() as usize;
                        let is_active =
                            // Ensure we have enough data to judge activity (none of this
                            // data may be in the last skip_timeout views if we jumped ahead
                            // to a new view)
                            work.len() < skip_timeout
                            // Leader active in at least one recent round
                            || work.iter().rev().take(skip_timeout).any(|(_, round)| round.is_active(leader));
                        active.send_lossy(is_active);

                        // Setting leader may enable batch verification
                        updated_view = current;
                    }
                    Message::Constructed(message) => {
                        // If the view isn't interesting, we can skip
                        let view = message.view();
                        if !interesting(
                            self.activity_timeout,
                            finalized,
                            current,
                            view,
                            false,
                        ) {
                            continue;
                        }

                        // Add the message to the verifier
                        work.entry(view)
                            .or_insert_with(|| self.new_round())
                            .add_constructed(message)
                            .await;
                        self.added.inc();
                        updated_view = view;
                    }
                    Message::MNotarizationExists(view) => {
                        // Mark that M-quorum was reached for this view.
                        // This allows batching toward L-quorum even after crash
                        // recovery where the verified vote count is lost.
                        self.mark_m_notarization_exists(&mut work, view);
                        // No verification needed, just continue
                        continue;
                    }
                }
            },
            // Handle certificates from the network
            Ok((sender, message)) = certificate_receiver.recv() else break => {
                // If there is a decoding error, block
                let Ok(message) = message else {
                    commonware_p2p::block!(self.blocker, sender, "malformed certificate received");
                    continue;
                };

                // Update metrics
                let label = match &message {
                    Certificate::MNotarization(_) => Inbound::m_notarization(&sender),
                    Certificate::Nullification(_) => Inbound::nullification(&sender),
                    Certificate::Finalization(_) => Inbound::finalization(&sender),
                };
                self.inbound_messages.get_or_create(&label).inc();

                // If the epoch is not the current epoch, block
                if message.epoch() != self.epoch {
                    commonware_p2p::block!(self.blocker, sender, "epoch mismatch in certificate");
                    continue;
                }

                // Allow future certificates (they advance our view)
                let view = message.view();
                if !interesting(
                    self.activity_timeout,
                    finalized,
                    current,
                    view,
                    true, // allow future
                ) {
                    continue;
                }

                // Check if we already have this certificate type for this view
                let round = work.entry(view).or_insert_with(|| self.new_round());
                let already_have = match &message {
                    Certificate::MNotarization(m) => round.has_m_notarization(&m.proposal),
                    Certificate::Nullification(_) => round.has_nullification(),
                    Certificate::Finalization(_) => round.has_finalization(),
                };
                if already_have {
                    trace!(%view, "skipping duplicate certificate");
                    continue;
                }

                // Verify the certificate signature
                let valid = match &message {
                    Certificate::MNotarization(m) => {
                        m.verify(&mut self.context, &self.scheme, &self.strategy)
                    }
                    Certificate::Nullification(n) => {
                        n.verify::<_, D>(&mut self.context, &self.scheme, &self.strategy)
                    }
                    Certificate::Finalization(f) => {
                        f.verify(&mut self.context, &self.scheme, &self.strategy)
                    }
                };

                if !valid {
                    commonware_p2p::block!(self.blocker, sender, "invalid certificate received");
                    continue;
                }

                // Mark and forward to voter.
                round.mark_certificate(&message);
                voter.verified_certificate(message).await;

                // Certificates are forwarded directly, no need for further processing
                continue;
            },
            // Handle votes from the network
            Ok((sender, message)) = vote_receiver.recv() else break => {
                // If there is a decoding error, block
                let Ok(message) = message else {
                    commonware_p2p::block!(self.blocker, sender, "malformed vote received");
                    continue;
                };

                // Update metrics
                let label = match &message {
                    Vote::Notarize(_) => Inbound::notarize(&sender),
                    Vote::Nullify(_) => Inbound::nullify(&sender),
                };
                self.inbound_messages.get_or_create(&label).inc();

                // If the epoch is not the current epoch, block
                if message.epoch() != self.epoch {
                    commonware_p2p::block!(self.blocker, sender, "epoch mismatch in vote");
                    continue;
                }

                // If the view isn't interesting, we can skip
                let view = message.view();
                if !interesting(
                    self.activity_timeout,
                    finalized,
                    current,
                    view,
                    false,
                ) {
                    continue;
                }

                // Add the vote to the verifier
                let peer = Peer::new(&sender);
                if work
                    .entry(view)
                    .or_insert_with(|| self.new_round())
                    .add_network(sender, message)
                    .await {
                        self.added.inc();

                        // Update per-peer latest vote metric (only if higher than current)
                        let _ = self
                            .latest_vote
                            .get_or_create(&peer)
                            .try_set_max(view.get());
                    }
                updated_view = view;
            },
            on_end => {
                assert!(
                    updated_view != View::zero(),
                    "updated view must be greater than zero"
                );

                // Forward leader's proposal to voter (if we're not the leader and haven't already)
                if let Some(round) = work.get_mut(&current) {
                    if let Some(me) = self.scheme.me() {
                        if let Some(proposal) = round.forward_proposal(me) {
                            voter.proposal(proposal).await;
                        }
                    }
                }

                // Skip verification for views at or below finalized.
                //
                // We still use interesting() for filtering votes because we want to
                // notify the reporter of all votes within the activity timeout (even
                // if we don't need them in the voter).
                if updated_view <= finalized {
                    continue;
                }

                // Process the updated view (if any)
                let Some(round) = work.get_mut(&updated_view) else {
                    continue;
                };

                // Batch verify votes if ready
                let mut timer = self.verify_latency.timer();
                let verified = if round.ready_notarizes() {
                    Some(round.verify_notarizes(&mut self.context, &self.strategy))
                } else if round.ready_nullifies() {
                    Some(round.verify_nullifies(&mut self.context, &self.strategy))
                } else {
                    None
                };

                // Process batch verification results
                if let Some((voters, failed)) = verified {
                    timer.observe();

                    // Process verified votes
                    let batch = voters.len() + failed.len();
                    trace!(view = %updated_view, batch, "batch verified votes");
                    self.verified.inc_by(batch as u64);
                    self.batch_size.observe(batch as f64);

                    // Block invalid signers
                    for invalid in failed {
                        if let Some(signer) = self.participants.key(invalid) {
                            commonware_p2p::block!(self.blocker, signer.clone(), "invalid signature in vote");
                        }
                    }

                    // Forward verified votes to voter (state machine handles certificate construction)
                    for vote in voters {
                        match vote {
                            Vote::Notarize(notarize) => {
                                voter.verified_notarize(notarize).await;
                            }
                            Vote::Nullify(nullify) => {
                                voter.verified_nullify(nullify).await;
                            }
                        }
                    }
                } else {
                    timer.cancel();
                    trace!(
                        %current,
                        %finalized,
                        "no verifier ready"
                    );
                }

                // Drop any rounds that are no longer interesting
                while work.first_key_value().is_some_and(|(&view, _)| {
                    !interesting(self.activity_timeout, finalized, current, view, false)
                }) {
                    work.pop_first();
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        minimmit::{scheme::ed25519, types::Nullify},
        types::{Epoch, Participant, Round as Rnd, View},
    };
    use commonware_cryptography::{
        certificate::{mocks::Fixture, Scheme as _},
        ed25519::PublicKey as Ed25519PublicKey,
        sha256::Digest as Sha256Digest,
    };
    use commonware_p2p::Blocker;
    use commonware_parallel::Sequential;
    use commonware_runtime::{deterministic, Runner};
    use commonware_utils::{channel::mpsc, test_rng};

    const NAMESPACE: &[u8] = b"minimmit-batcher-actor";

    #[derive(Clone, Default)]
    struct NoopBlocker;

    impl Blocker for NoopBlocker {
        type PublicKey = Ed25519PublicKey;

        async fn block(&mut self, _peer: Self::PublicKey) {}
    }

    #[derive(Clone, Default)]
    struct NoopReporter;

    impl Reporter for NoopReporter {
        type Activity = Activity<ed25519::Scheme, Sha256Digest>;

        async fn report(&mut self, _activity: Self::Activity) {}
    }

    fn ed25519_fixture() -> Vec<ed25519::Scheme> {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = ed25519::fixture(&mut rng, NAMESPACE, 6);
        schemes
    }

    #[test]
    fn regression_verified_certificate_not_dropped_under_backpressure() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let schemes = ed25519_fixture();
            let view = View::new(1);
            let mut round = Round::new(
                schemes[0].participants().clone(),
                schemes[0].clone(),
                NoopBlocker,
                NoopReporter,
            );

            let nullifies: Vec<_> = schemes
                .iter()
                .take(3)
                .map(|scheme| {
                    Nullify::sign::<Sha256Digest>(scheme, Rnd::new(Epoch::new(1), view)).unwrap()
                })
                .collect();
            let nullification = crate::minimmit::types::Nullification::from_nullifies(
                &schemes[0],
                nullifies.iter(),
                &Sequential,
            )
            .unwrap();
            let certificate = Certificate::Nullification(nullification);

            let (voter_tx, mut voter_rx) = mpsc::channel(1);
            let mut voter = voter::Mailbox::new(voter_tx);
            let proposal = crate::minimmit::types::Proposal::new(
                Rnd::new(Epoch::new(1), View::new(2)),
                view,
                Sha256Digest::from([1u8; 32]),
                Sha256Digest::from([2u8; 32]),
            );
            voter.proposal(proposal).await;

            let handle = context.with_label("forward").spawn(|_| async move {
                round.mark_certificate(&certificate);
                voter.verified_certificate(certificate).await;
                round
            });

            // Let the forward task block on full mailbox capacity.
            context.sleep(std::time::Duration::from_millis(1)).await;

            // Free capacity and ensure the certificate is eventually delivered.
            assert!(voter_rx.try_recv().is_ok(), "expected pre-filled proposal");
            let round = handle.await.expect("forward task should complete");
            assert!(round.has_nullification(), "certificate should be marked");
            assert!(
                voter_rx.try_recv().is_ok(),
                "verified certificate should eventually be delivered"
            );
        });
    }

    #[test]
    fn regression_m_notarization_dedup_uses_full_proposal() {
        let schemes = ed25519_fixture();
        let view = View::new(3);
        let payload = Sha256Digest::from([0xAAu8; 32]);
        let round_id = Rnd::new(Epoch::new(1), view);

        let proposal_a = crate::minimmit::types::Proposal::new(
            round_id,
            View::new(2),
            Sha256Digest::from([1u8; 32]),
            payload,
        );
        let proposal_b = crate::minimmit::types::Proposal::new(
            round_id,
            View::new(2),
            Sha256Digest::from([2u8; 32]),
            payload,
        );

        let votes_a: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| {
                crate::minimmit::types::Notarize::sign(scheme, proposal_a.clone()).unwrap()
            })
            .collect();
        let votes_b: Vec<_> = schemes
            .iter()
            .skip(1)
            .take(3)
            .map(|scheme| {
                crate::minimmit::types::Notarize::sign(scheme, proposal_b.clone()).unwrap()
            })
            .collect();
        let m_notarization_a = crate::minimmit::types::MNotarization::from_notarizes(
            &schemes[0],
            votes_a.iter(),
            &Sequential,
        )
        .unwrap();
        let m_notarization_b = crate::minimmit::types::MNotarization::from_notarizes(
            &schemes[1],
            votes_b.iter(),
            &Sequential,
        )
        .unwrap();

        let mut round = Round::new(
            schemes[0].participants().clone(),
            schemes[0].clone(),
            NoopBlocker,
            NoopReporter,
        );
        round.mark_certificate(&Certificate::MNotarization(m_notarization_a));
        assert!(
            !round.has_m_notarization(&m_notarization_b.proposal),
            "same payload but distinct parent proposal must not be treated as duplicate"
        );

        round.mark_certificate(&Certificate::MNotarization(m_notarization_b.clone()));
        assert!(
            round.has_m_notarization(&m_notarization_b.proposal),
            "marked M-notarization should dedup by full proposal identity"
        );
    }

    #[test]
    fn regression_replay_m_notarization_hint_survives_before_round_creation() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let schemes = ed25519_fixture();
            let view = View::new(2);
            let leader = Participant::new(0);
            let round_id = Rnd::new(Epoch::new(1), view);
            let parent_payload = Sha256Digest::from([1u8; 32]);
            let proposal = crate::minimmit::types::Proposal::new(
                round_id,
                View::new(1),
                parent_payload,
                Sha256Digest::from([2u8; 32]),
            );

            let cfg = Config {
                scheme: schemes[0].clone(),
                blocker: NoopBlocker,
                reporter: NoopReporter,
                strategy: Sequential,
                epoch: Epoch::new(1),
                mailbox_size: 8,
                activity_timeout: ViewDelta::new(3),
                skip_timeout: ViewDelta::new(1),
            };
            let (actor, _mailbox) = Actor::new(context.with_label("batcher"), cfg);

            let mut work = BTreeMap::new();

            // Simulate replay notifying the batcher before any round state exists.
            actor.mark_m_notarization_exists(&mut work, view);

            let round = work
                .get_mut(&view)
                .expect("round should exist after replay hint");
            round.set_leader(leader);

            // Only two post-restart votes arrive; without the replay hint the verifier
            // would wait forever for M-quorum again and never continue toward L-quorum.
            let leader_vote =
                crate::minimmit::types::Notarize::sign(&schemes[0], proposal.clone()).unwrap();
            let other_vote =
                crate::minimmit::types::Notarize::sign(&schemes[1], proposal.clone()).unwrap();
            let leader_peer = schemes[0]
                .participants()
                .key(leader)
                .expect("leader key")
                .clone();
            let other_peer = schemes[0]
                .participants()
                .key(Participant::new(1))
                .expect("participant key")
                .clone();

            assert!(
                round
                    .add_network(leader_peer, Vote::Notarize(leader_vote))
                    .await
            );
            assert!(
                round
                    .add_network(other_peer, Vote::Notarize(other_vote))
                    .await
            );

            assert!(
                round.ready_notarizes(),
                "replayed M-notarization hint must allow batching toward L-quorum even when no round existed at replay time"
            );
        });
    }
}
