//! Transmission of the machine's durable publications and their retries.

use super::{DigestOf, Fatal, Hooks as _, VoterTypes, live::Live};
use crate::{
    Relay as _,
    multimmit::{
        actors::{
            metrics::Traffic,
            voter::egress::{Due, Submission, Transmission},
        },
        machine::{EffectCompletion, EffectId, Generation, Input, Issued},
        wire::Plane,
    },
};
use commonware_actor::Feedback;
use commonware_p2p::{Recipients, Sender};
use commonware_runtime::{
    Clock as _,
    telemetry::{metrics::GaugeExt as _, traces::TracedExt as _},
};
use tracing::{debug, debug_span};

/// Publication attempts admitted in one voter turn.
const PUBLICATION_BUDGET: usize = 32;

impl<T, S> Live<T, S>
where
    T: VoterTypes,
    S: Sender<PublicKey = T::PublicKey>,
{
    /// Installs one durable publication and transmits its first attempt inline.
    ///
    /// The inline attempt keeps fresh publications off the scheduled retry path, which
    /// services overdue retries first and is bounded per turn. A rejected inline send
    /// leaves the installed entry to that path, so the failure mode is a scheduled retry.
    pub(crate) fn install(
        &mut self,
        id: EffectId,
        generation: Generation,
        transmissions: Vec<Transmission<T::PublicKey, DigestOf<T>>>,
    ) -> Result<(), Fatal> {
        let now = self.context.current();
        let view = self.telemetry.round_view();
        debug!(
            epoch = self.epoch.get().traced(),
            view = view.get().traced(),
            id = id.get().traced(),
            generation = generation.get().traced(),
            "durable publication installed"
        );
        self.egress
            .install(id, generation, transmissions, now, view);
        self.hooks.installed(id, generation);
        let _ = self
            .telemetry
            .metrics
            .publications
            .try_set(self.egress.len());
        let due = self
            .egress
            .claim(id, now)
            .expect("a freshly installed publication is claimable");
        self.attempt_publication(due)
    }

    /// Attempts every publication whose retry is due, up to the per-turn budget.
    pub(crate) fn publish_due(&mut self) -> Result<(), Fatal> {
        let now = self.context.current();
        for due in self.egress.due(now, PUBLICATION_BUDGET) {
            self.attempt_publication(due)?;
        }
        Ok(())
    }

    /// Attempts one claimed publication and reports first local acceptance to the machine.
    fn attempt_publication(&mut self, due: Due<T::PublicKey, DigestOf<T>>) -> Result<(), Fatal> {
        let Due {
            id,
            generation,
            retries,
            delivered,
            transmit_due,
            relay_due,
            transmissions,
            view,
        } = due;
        let attempt_number = retries.saturating_add(1);
        // Tracing needs a literal span name, so the shared fields are written once here.
        macro_rules! attempt_span {
            ($name:literal) => {
                debug_span!(
                    parent: None,
                    $name,
                    epoch = self.epoch.get().traced(),
                    view = view.get().traced(),
                    id = id.get().traced(),
                    generation = generation.get().traced(),
                    attempt = attempt_number.traced(),
                    previously_delivered = delivered,
                    transmit_due,
                    relay_due,
                    relay_ready = tracing::field::Empty,
                    sender_accepted = tracing::field::Empty,
                    sender_complete = tracing::field::Empty,
                    first_accepted = tracing::field::Empty,
                )
            };
        }
        let attempt = if retries == 0 {
            attempt_span!("multimmit.voter.publish")
        } else {
            attempt_span!("multimmit.voter.publish.retry")
        };
        let _guard = attempt.enter();
        // Relay closure withholds only the transmissions that carry a Relay obligation. A
        // publication may bundle consensus-critical artifacts with a transaction block, and a
        // dead relay endpoint must not silence the whole entry: two such senders exhaust the
        // committee's fault budget and freeze every view.
        let mut relay_blocked = false;
        let mut submission = Submission {
            accepted: false,
            complete: transmit_due && !transmissions.is_empty(),
        };
        for transmission in transmissions.iter() {
            if relay_due && let Some(header_digest) = transmission.relay {
                self.telemetry.metrics.relay_attempts.inc();
                if self.relay.broadcast(header_digest, ()) == Feedback::Closed {
                    self.telemetry.metrics.relay_closed.inc();
                    relay_blocked = true;
                    submission.complete = false;
                    continue;
                }
            }
            if transmit_due {
                let sent = self.transmit(transmission, retries > 0);
                submission.accepted |= sent.accepted;
                submission.complete &= sent.complete;
            }
        }
        attempt.record("relay_ready", !relay_blocked);
        if relay_blocked {
            self.egress.relay_rejected(id);
        } else if relay_due {
            let now = self.context.current();
            self.egress.relay_accepted(id, now);
        }
        attempt.record("sender_accepted", submission.accepted);
        attempt.record("sender_complete", submission.complete);
        let first = transmit_due
            && self
                .egress
                .submitted(id, self.context.current(), submission);
        attempt.record("first_accepted", first);
        if first {
            self.track_transition(
                |core| {
                    core.enqueue(Input::EffectCompleted(EffectCompletion::delivered(
                        Issued::new(id, generation),
                    )))
                },
                &attempt,
            )?;
        }
        Ok(())
    }

    /// Sends one pre-encoded transmission and reports local recipient admission.
    ///
    /// Retries count into a separate per-plane byte family, so each plane's traffic splits
    /// into first attempts and retry amplification.
    fn transmit(
        &mut self,
        transmission: &Transmission<T::PublicKey, DigestOf<T>>,
        retry: bool,
    ) -> Submission {
        let recipients = transmission
            .recipient
            .as_ref()
            .map_or(Recipients::All, |peer| Recipients::One(peer.clone()));
        let priority = transmission.plane != Plane::Data;
        let metric = &Traffic::from(transmission.plane);
        let sent = self.planes.sender(transmission.plane).send(
            recipients,
            transmission.bytes.clone(),
            priority,
        );
        let complete = match &transmission.recipient {
            Some(recipient) => sent.iter().any(|peer| peer == recipient),
            None => {
                let participants = self.crypto.scheme().participants();
                let local = self
                    .participant
                    .and_then(|participant| participants.get(participant.into()));
                let accepted = sent
                    .iter()
                    .filter(|peer| local != Some(*peer) && participants.position(peer).is_some())
                    .count();
                accepted
                    == participants
                        .len()
                        .saturating_sub(usize::from(local.is_some()))
            }
        };
        let accepted = !sent.is_empty();
        let recipients = sent.len() as u64;
        let metrics = &self.telemetry.metrics;
        metrics
            .transmissions
            .get_or_create(metric)
            .inc_by(recipients);
        metrics
            .transmitted_bytes
            .get_or_create(metric)
            .inc_by(recipients * transmission.bytes.len() as u64);
        if retry {
            metrics
                .retransmitted_bytes
                .get_or_create(metric)
                .inc_by(recipients * transmission.bytes.len() as u64);
        }
        Submission { accepted, complete }
    }
}
