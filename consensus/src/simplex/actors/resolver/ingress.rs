use crate::{
    Epochable, Viewable,
    simplex::{actors::AncestryRequirement, types::Certificate},
    types::{Round as Rnd, View},
};
use bytes::Bytes;
use commonware_actor::mailbox::{Overflow, Policy, Sender};
use commonware_cryptography::{Digest, certificate::Scheme};
use commonware_resolver::{Consumer, Delivery, p2p::Producer};
use commonware_runtime::telemetry::traces::TracedExt as _;
use commonware_utils::{channel::oneshot, sequence::U64};
use std::collections::VecDeque;
use tracing::{Span, info_span};

/// Purpose attached to a resolver fetch.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum Subscription {
    /// Background repair between the local floor and current view.
    Backfill,
    /// Ancestry requested from a leader whose proposal claimed it.
    Targeted(AncestryRequirement),
}

impl Subscription {
    /// Returns whether this subscriber came from proposal-targeted repair.
    const fn is_targeted(self) -> bool {
        matches!(self, Self::Targeted(_))
    }

    /// Returns whether local resolution of `requirement` retires this
    /// subscriber.
    ///
    /// This does not constrain response validity: any certificate valid for
    /// the peer-visible key completes every subscriber in that delivery.
    pub(super) fn is_retired_by(self, requirement: AncestryRequirement) -> bool {
        match self {
            // Background repair only requests missing nullifications.
            Self::Backfill => matches!(requirement, AncestryRequirement::Nullification),
            Self::Targeted(expected) => expected == requirement,
        }
    }
}

/// Messages sent to the resolver actor from the voter.
pub enum MailboxMessage<S: Scheme, D: Digest> {
    /// A certificate was received or produced.
    Certificate {
        /// The span carried with this message.
        span: Span,
        /// The certificate.
        certificate: Certificate<S, D>,
    },
    /// Certification result for a round.
    Certified {
        /// The span carried with this message.
        span: Span,
        /// The certified round.
        round: Rnd,
        /// Whether certification succeeded.
        success: bool,
    },
    /// Fetch proposal ancestry from the leader that claimed it.
    Resolve {
        /// The span carried with this message.
        span: Span,
        /// Round of the proposal being verified.
        round: Rnd,
        /// View whose certificate is needed.
        view: View,
        /// Evidence needed for the proposal's ancestry.
        requirement: AncestryRequirement,
        /// Proposal leader to query.
        target: S::PublicKey,
    },
}

impl<S: Scheme, D: Digest> MailboxMessage<S, D> {
    /// Returns the message view used for pruning and deduplication.
    pub(crate) fn view(&self) -> View {
        match self {
            Self::Certificate { certificate, .. } => certificate.view(),
            Self::Certified { round, .. } => round.view(),
            // Finalization of the requested ancestry, rather than of the
            // proposal that exposed it, makes this work obsolete.
            Self::Resolve { view, .. } => *view,
        }
    }

    /// Returns the span carried with this message.
    pub(crate) const fn span(&self) -> &Span {
        match self {
            Self::Certificate { span, .. }
            | Self::Certified { span, .. }
            | Self::Resolve { span, .. } => span,
        }
    }

    /// Returns the operation name of this message.
    pub(crate) const fn name(&self) -> &'static str {
        match self {
            Self::Certificate { .. } => "certificate",
            Self::Certified { .. } => "certified",
            Self::Resolve { .. } => "resolve",
        }
    }
}

/// Pending resolver messages retained after the mailbox fills.
pub struct Pending<S: Scheme, D: Digest> {
    finalization: Option<MailboxMessage<S, D>>,
    messages: VecDeque<MailboxMessage<S, D>>,
}

impl<S: Scheme, D: Digest> Default for Pending<S, D> {
    fn default() -> Self {
        Self {
            finalization: None,
            messages: VecDeque::new(),
        }
    }
}

impl<S: Scheme, D: Digest> Overflow<MailboxMessage<S, D>> for Pending<S, D> {
    fn is_empty(&self) -> bool {
        self.finalization.is_none() && self.messages.is_empty()
    }

    fn drain<F>(&mut self, mut push: F)
    where
        F: FnMut(MailboxMessage<S, D>) -> Option<MailboxMessage<S, D>>,
    {
        if let Some(finalization) = self.finalization.take()
            && let Some(finalization) = push(finalization)
        {
            self.finalization = Some(finalization);
            return;
        }

        while let Some(message) = self.messages.pop_front() {
            if let Some(message) = push(message) {
                self.messages.push_front(message);
                break;
            }
        }
    }
}

impl<S: Scheme, D: Digest> Policy for MailboxMessage<S, D> {
    type Overflow = Pending<S, D>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        // Ignore the message if there exists a queued finalization
        // with a view greater than or equal to the new view
        let new_view = message.view();
        if matches!(
            overflow.finalization.as_ref(),
            Some(Self::Certificate { certificate: Certificate::Finalization(old_finalized), .. })
                if old_finalized.view() >= new_view
        ) {
            return;
        }

        // Retain only the highest-view finalization and any messages with a view greater than the new view
        if matches!(
            &message,
            Self::Certificate {
                certificate: Certificate::Finalization(_),
                ..
            }
        ) {
            overflow
                .messages
                .retain(|old_message| old_message.view() > new_view);
            overflow.finalization = Some(message);
            return;
        }

        // Ignore the message if it is a duplicate
        if overflow
            .messages
            .iter()
            .any(|old_message| match (&message, old_message) {
                (
                    Self::Certificate {
                        certificate: new_certificate,
                        ..
                    },
                    Self::Certificate {
                        certificate: old_certificate,
                        ..
                    },
                ) => {
                    new_certificate.view() == old_certificate.view()
                        && matches!(
                            (new_certificate, old_certificate),
                            (Certificate::Notarization(_), Certificate::Notarization(_))
                                | (Certificate::Nullification(_), Certificate::Nullification(_))
                                | (Certificate::Finalization(_), Certificate::Finalization(_))
                        )
                }
                (
                    Self::Certified {
                        round: new_round, ..
                    },
                    Self::Certified {
                        round: old_round, ..
                    },
                ) => new_round.view() == old_round.view(),
                (
                    Self::Resolve {
                        round: new_round,
                        view: new_view,
                        requirement: new_requirement,
                        ..
                    },
                    Self::Resolve {
                        round: old_round,
                        view: old_view,
                        requirement: old_requirement,
                        ..
                    },
                ) => {
                    new_round == old_round
                        && new_view == old_view
                        && new_requirement == old_requirement
                }
                _ => false,
            })
        {
            return;
        }
        overflow.messages.push_back(message);
    }
}

#[derive(Clone)]
pub struct Mailbox<S: Scheme, D: Digest> {
    sender: Sender<MailboxMessage<S, D>>,
}

impl<S: Scheme, D: Digest> Mailbox<S, D> {
    /// Create a new mailbox.
    pub const fn new(sender: Sender<MailboxMessage<S, D>>) -> Self {
        Self { sender }
    }

    /// Send a certificate.
    pub fn updated(&mut self, certificate: Certificate<S, D>) {
        let _ = self.sender.enqueue(MailboxMessage::Certificate {
            span: info_span!(
                "simplex.resolver.mailbox.updated",
                epoch = certificate.epoch().traced(),
                view = certificate.view().traced()
            ),
            certificate,
        });
    }

    /// Notify the resolver of a certification result.
    pub fn certified(&mut self, round: Rnd, success: bool) {
        let _ = self.sender.enqueue(MailboxMessage::Certified {
            span: info_span!(
                "simplex.resolver.mailbox.certified",
                epoch = round.epoch().traced(),
                view = round.view().traced(),
                success
            ),
            round,
            success,
        });
    }

    /// Request proposal ancestry from its leader.
    pub(crate) fn resolve(
        &mut self,
        round: Rnd,
        view: View,
        requirement: AncestryRequirement,
        target: S::PublicKey,
    ) {
        let _ = self.sender.enqueue(MailboxMessage::Resolve {
            span: info_span!(
                "simplex.resolver.mailbox.resolve",
                epoch = round.epoch().traced(),
                proposal_view = round.view().traced(),
                view = view.traced(),
                requirement = requirement.as_str()
            ),
            round,
            view,
            requirement,
            target,
        });
    }
}

#[derive(Debug)]
pub(crate) enum HandlerMessage {
    Deliver {
        span: Span,
        view: View,
        data: Bytes,
        targeted: bool,
        response: oneshot::Sender<bool>,
    },
    Produce {
        view: View,
        response: oneshot::Sender<Bytes>,
    },
}

impl HandlerMessage {
    /// Returns true if the requester stopped waiting for this response.
    pub(crate) fn response_closed(&self) -> bool {
        match self {
            Self::Deliver { response, .. } => response.is_closed(),
            Self::Produce { response, .. } => response.is_closed(),
        }
    }
}

/// Pending resolver handler messages retained after the mailbox fills.
#[derive(Default)]
pub(crate) struct HandlerPending(VecDeque<HandlerMessage>);

impl Overflow<HandlerMessage> for HandlerPending {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn drain<F>(&mut self, mut push: F)
    where
        F: FnMut(HandlerMessage) -> Option<HandlerMessage>,
    {
        while let Some(message) = self.0.pop_front() {
            if message.response_closed() {
                continue;
            }

            if let Some(message) = push(message) {
                self.0.push_front(message);
                break;
            }
        }
    }
}

impl Policy for HandlerMessage {
    type Overflow = HandlerPending;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        if message.response_closed() {
            return;
        }
        overflow.0.push_back(message);
    }
}

#[derive(Clone)]
pub(crate) struct Handler {
    sender: Sender<HandlerMessage>,
}

impl Handler {
    pub(crate) const fn new(sender: Sender<HandlerMessage>) -> Self {
        Self { sender }
    }
}

impl Consumer for Handler {
    type Key = U64;
    type Value = Bytes;
    type Subscriber = Subscription;

    fn deliver(
        &mut self,
        delivery: Delivery<Self::Key, Self::Subscriber>,
        value: Self::Value,
    ) -> oneshot::Receiver<bool> {
        let (response, receiver) = oneshot::channel();
        let (_, span) = delivery.subscribers.first().clone();
        let targeted = delivery
            .subscribers
            .iter()
            .all(|(subscription, _)| subscription.is_targeted());
        let _ = self.sender.enqueue(HandlerMessage::Deliver {
            span,
            view: View::new(delivery.key.into()),
            data: value,
            targeted,
            response,
        });
        receiver
    }
}

impl Producer for Handler {
    type Key = U64;

    fn produce(&mut self, key: Self::Key) -> oneshot::Receiver<Bytes> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(HandlerMessage::Produce {
            view: View::new(key.into()),
            response,
        });
        receiver
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        simplex::{
            scheme::ed25519,
            types::{Certificate, Finalization, Finalize, Nullification, Nullify, Proposal},
        },
        types::{Epoch, Round},
    };
    use commonware_actor::mailbox::Policy;
    use commonware_cryptography::{certificate::mocks::Fixture, sha256::Digest as Sha256Digest};
    use commonware_macros::test_async;
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner, deterministic};
    use commonware_utils::{NZUsize, non_empty_vec, test_rng};
    use std::collections::VecDeque;

    type TestScheme = ed25519::Scheme;
    const EPOCH: Epoch = Epoch::new(1);

    fn fixture() -> (Vec<TestScheme>, TestScheme) {
        let mut rng = test_rng();
        let Fixture {
            schemes, verifier, ..
        } = ed25519::fixture(&mut rng, b"resolver-policy", 5);
        (schemes, verifier)
    }

    fn proposal(view: View) -> Proposal<Sha256Digest> {
        Proposal::new(
            Round::new(EPOCH, view),
            view.previous().unwrap_or(View::zero()),
            Sha256Digest::from([view.get() as u8; 32]),
        )
    }

    fn nullification(view: View) -> Certificate<TestScheme, Sha256Digest> {
        let (schemes, verifier) = fixture();
        let round = Round::new(EPOCH, view);
        let votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Nullify::sign::<Sha256Digest>(scheme, round).expect("nullify"))
            .collect();
        Certificate::Nullification(
            Nullification::from_nullifies(&verifier, &votes, &Sequential).expect("nullification"),
        )
    }

    fn finalization(view: View) -> Certificate<TestScheme, Sha256Digest> {
        let (schemes, verifier) = fixture();
        let proposal = proposal(view);
        let votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).expect("finalize"))
            .collect();
        Certificate::Finalization(
            Finalization::from_finalizes(&verifier, &votes, &Sequential).expect("finalization"),
        )
    }

    fn drain(
        mut overflow: Pending<TestScheme, Sha256Digest>,
    ) -> VecDeque<MailboxMessage<TestScheme, Sha256Digest>> {
        let mut messages = VecDeque::new();
        Overflow::drain(&mut overflow, |message| {
            messages.push_back(message);
            None
        });
        messages
    }

    fn certificate_msg(
        certificate: Certificate<TestScheme, Sha256Digest>,
    ) -> MailboxMessage<TestScheme, Sha256Digest> {
        MailboxMessage::Certificate {
            span: Span::none(),
            certificate,
        }
    }

    #[test_async]
    async fn handler_distinguishes_targeted_only_deliveries() {
        let runtime = deterministic::Runner::default();
        runtime.start(|context| async move {
            let (sender, mut receiver) = commonware_actor::mailbox::new(context, NZUsize!(2));
            let mut handler = Handler::new(sender);

            drop(handler.deliver(
                Delivery {
                    key: U64::from(View::new(3)),
                    subscribers: non_empty_vec![
                        (
                            Subscription::Targeted(AncestryRequirement::Nullification),
                            Span::none()
                        ),
                        (
                            Subscription::Targeted(AncestryRequirement::Parent),
                            Span::none()
                        )
                    ],
                },
                Bytes::new(),
            ));
            assert!(matches!(
                receiver.recv().await,
                Some(HandlerMessage::Deliver { targeted: true, .. })
            ));

            drop(handler.deliver(
                Delivery {
                    key: U64::from(View::new(3)),
                    subscribers: non_empty_vec![
                        (
                            Subscription::Targeted(AncestryRequirement::Parent),
                            Span::none()
                        ),
                        (Subscription::Backfill, Span::none())
                    ],
                },
                Bytes::new(),
            ));
            assert!(matches!(
                receiver.recv().await,
                Some(HandlerMessage::Deliver {
                    targeted: false,
                    ..
                })
            ));
        });
    }

    fn certified_msg(view: View, success: bool) -> MailboxMessage<TestScheme, Sha256Digest> {
        MailboxMessage::Certified {
            span: Span::none(),
            round: Round::new(EPOCH, view),
            success,
        }
    }

    fn resolve_msg(
        proposal_view: View,
        view: View,
        requirement: AncestryRequirement,
    ) -> MailboxMessage<TestScheme, Sha256Digest> {
        let mut rng = test_rng();
        let Fixture { participants, .. } = ed25519::fixture(&mut rng, b"resolver-policy-target", 5);
        MailboxMessage::Resolve {
            span: Span::none(),
            round: Round::new(EPOCH, proposal_view),
            view,
            requirement,
            target: participants[0].clone(),
        }
    }

    #[test]
    fn handler_drain_skips_closed_responses() {
        let mut overflow = HandlerPending::default();

        let (closed_response, closed_receiver) = oneshot::channel();
        HandlerMessage::handle(
            &mut overflow,
            HandlerMessage::Produce {
                view: View::new(1),
                response: closed_response,
            },
        );
        drop(closed_receiver);

        let (open_response, _open_receiver) = oneshot::channel();
        HandlerMessage::handle(
            &mut overflow,
            HandlerMessage::Produce {
                view: View::new(2),
                response: open_response,
            },
        );

        let mut messages = Vec::new();
        Overflow::drain(&mut overflow, |message| {
            messages.push(message);
            None
        });

        assert_eq!(messages.len(), 1);
        assert!(matches!(
            messages.pop(),
            Some(HandlerMessage::Produce { view, .. }) if view == View::new(2)
        ));
    }

    #[test]
    fn finalization_prunes_stale_certificates_and_results() {
        let mut overflow = Pending::default();
        MailboxMessage::handle(&mut overflow, certificate_msg(nullification(View::new(2))));
        MailboxMessage::handle(&mut overflow, certified_msg(View::new(2), false));
        MailboxMessage::handle(&mut overflow, certificate_msg(nullification(View::new(5))));
        MailboxMessage::handle(&mut overflow, certified_msg(View::new(5), false));
        MailboxMessage::handle(&mut overflow, certificate_msg(finalization(View::new(3))));

        let mut overflow = drain(overflow);
        assert_eq!(overflow.len(), 3);
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Certificate { certificate: Certificate::Finalization(f), .. })
                if f.view() == View::new(3)
        ));
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Certificate { certificate: Certificate::Nullification(n), .. })
                if n.view() == View::new(5)
        ));
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Certified {
                round,
                success: false,
                ..
            }) if round.view() == View::new(5)
        ));
    }

    #[test]
    fn finalization_prunes_resolve_by_requested_view() {
        let mut overflow = Pending::default();
        MailboxMessage::handle(
            &mut overflow,
            resolve_msg(
                View::new(10),
                View::new(2),
                AncestryRequirement::Nullification,
            ),
        );
        MailboxMessage::handle(
            &mut overflow,
            resolve_msg(View::new(10), View::new(5), AncestryRequirement::Parent),
        );
        MailboxMessage::handle(&mut overflow, certificate_msg(finalization(View::new(3))));

        let mut overflow = drain(overflow);
        assert_eq!(overflow.len(), 2);
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Certificate { certificate: Certificate::Finalization(f), .. })
                if f.view() == View::new(3)
        ));
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Resolve {
                round,
                view,
                requirement: AncestryRequirement::Parent,
                ..
            }) if round.view() == View::new(10) && view == View::new(5)
        ));
    }

    #[test]
    fn resolve_requirements_deduplicate_independently() {
        let mut overflow = Pending::default();
        for requirement in [
            AncestryRequirement::Nullification,
            AncestryRequirement::Nullification,
            AncestryRequirement::Parent,
        ] {
            MailboxMessage::handle(
                &mut overflow,
                resolve_msg(View::new(10), View::new(3), requirement),
            );
        }

        let overflow = drain(overflow);
        assert_eq!(overflow.len(), 2);
        assert!(matches!(
            &overflow[0],
            MailboxMessage::Resolve {
                requirement: AncestryRequirement::Nullification,
                ..
            }
        ));
        assert!(matches!(
            &overflow[1],
            MailboxMessage::Resolve {
                requirement: AncestryRequirement::Parent,
                ..
            }
        ));
    }

    #[test]
    fn duplicate_certified_result_is_ignored() {
        let mut overflow = Pending::<TestScheme, Sha256Digest>::default();
        MailboxMessage::handle(&mut overflow, certified_msg(View::new(4), false));
        MailboxMessage::handle(&mut overflow, certified_msg(View::new(4), true));

        let mut overflow = drain(overflow);
        assert_eq!(overflow.len(), 1);
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Certified {
                round,
                success: false,
                ..
            }) if round.view() == View::new(4)
        ));
    }

    #[test]
    fn queued_finalization_rejects_covered_messages() {
        let mut overflow = Pending::default();
        MailboxMessage::handle(&mut overflow, certificate_msg(finalization(View::new(3))));

        MailboxMessage::handle(&mut overflow, certificate_msg(nullification(View::new(2))));
        MailboxMessage::handle(&mut overflow, certified_msg(View::new(2), false));
        MailboxMessage::handle(&mut overflow, certificate_msg(finalization(View::new(2))));
        MailboxMessage::handle(
            &mut overflow,
            resolve_msg(
                View::new(10),
                View::new(2),
                AncestryRequirement::Nullification,
            ),
        );
        MailboxMessage::handle(&mut overflow, certificate_msg(nullification(View::new(4))));
        MailboxMessage::handle(
            &mut overflow,
            resolve_msg(View::new(10), View::new(4), AncestryRequirement::Parent),
        );

        let mut overflow = drain(overflow);
        assert_eq!(overflow.len(), 3);
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Certificate { certificate: Certificate::Finalization(f), .. })
                if f.view() == View::new(3)
        ));
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Certificate { certificate: Certificate::Nullification(n), .. })
                if n.view() == View::new(4)
        ));
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Resolve {
                view,
                requirement: AncestryRequirement::Parent,
                ..
            }) if view == View::new(4)
        ));
    }

    #[test]
    fn duplicate_finalization_is_dropped() {
        let mut overflow = Pending::default();
        MailboxMessage::handle(&mut overflow, certificate_msg(finalization(View::new(3))));
        MailboxMessage::handle(&mut overflow, certificate_msg(finalization(View::new(3))));

        let mut overflow = drain(overflow);
        assert_eq!(overflow.len(), 1);
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Certificate { certificate: Certificate::Finalization(f), .. })
                if f.view() == View::new(3)
        ));
    }

    #[test]
    fn newer_finalization_replaces_older_pruning_floor() {
        let mut overflow = Pending::default();
        MailboxMessage::handle(&mut overflow, certificate_msg(finalization(View::new(3))));
        MailboxMessage::handle(&mut overflow, certificate_msg(nullification(View::new(4))));
        MailboxMessage::handle(&mut overflow, certified_msg(View::new(4), false));
        MailboxMessage::handle(&mut overflow, certificate_msg(finalization(View::new(5))));

        let mut overflow = drain(overflow);
        assert_eq!(overflow.len(), 1);
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Certificate { certificate: Certificate::Finalization(f), .. })
                if f.view() == View::new(5)
        ));
    }

    #[test]
    fn duplicate_certificate_is_ignored() {
        let mut overflow = Pending::default();
        MailboxMessage::handle(&mut overflow, certificate_msg(nullification(View::new(4))));
        MailboxMessage::handle(&mut overflow, certified_msg(View::new(4), true));
        MailboxMessage::handle(&mut overflow, certificate_msg(nullification(View::new(4))));

        let mut overflow = drain(overflow);
        assert_eq!(overflow.len(), 2);
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Certificate { certificate: Certificate::Nullification(n), .. })
                if n.view() == View::new(4)
        ));
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Certified {
                round,
                success: true,
                ..
            }) if round.view() == View::new(4)
        ));
    }
}
