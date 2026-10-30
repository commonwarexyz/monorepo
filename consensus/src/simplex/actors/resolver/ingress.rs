use crate::{
    Epochable, Viewable,
    simplex::{
        actors::{Ask, Kind},
        types::{Certificate, Notarization},
    },
    types::View,
};
use bytes::Bytes;
use commonware_actor::mailbox::{Overflow, Policy, Sender};
use commonware_cryptography::{Digest, certificate::Scheme};
use commonware_resolver::{Consumer, Delivery, Outcome, p2p::Producer};
use commonware_runtime::telemetry::traces::TracedExt as _;
use commonware_utils::{channel::oneshot, sequence::U64, vec::NonEmptyVec};
use std::collections::{HashMap, VecDeque};
use tracing::{Span, info_span};

/// Messages sent to the resolver actor from the voter.
pub enum MailboxMessage<S: Scheme, D: Digest> {
    /// A certificate was received or produced.
    Updated {
        /// The span carried with this message.
        span: Span,
        /// The certificate.
        certificate: Certificate<S, D>,
    },
    /// Certification verdict for a notarization.
    Certified {
        /// The span carried with this message.
        span: Span,
        /// The notarization whose proposal was judged.
        notarization: Notarization<S, D>,
        /// Whether certification succeeded.
        success: bool,
    },
    /// Fetch missing proposal ancestry.
    Resolve {
        /// The span carried with this message.
        span: Span,
        /// View of the proposal that exposed the missing ancestry.
        proposal: View,
        /// View whose certificate is needed.
        view: View,
        /// The certificate that is needed.
        kind: Kind,
        /// When set, the resolver queries only this peer.
        target: Option<S::PublicKey>,
    },
    /// The voter finished replaying its journal, so every recovered
    /// certificate precedes this message and background repair may begin.
    Replayed {
        /// The span carried with this message.
        span: Span,
    },
}

impl<S: Scheme, D: Digest> MailboxMessage<S, D> {
    /// Returns the message view used for pruning and deduplication. The
    /// replay marker carries no view and is never pruned or coalesced.
    pub(crate) fn view(&self) -> View {
        match self {
            Self::Updated { certificate, .. } => certificate.view(),
            Self::Certified { notarization, .. } => notarization.view(),
            Self::Resolve { view, .. } => *view,
            Self::Replayed { .. } => View::zero(),
        }
    }

    /// Returns the span carried with this message.
    pub(crate) const fn span(&self) -> &Span {
        match self {
            Self::Updated { span, .. }
            | Self::Certified { span, .. }
            | Self::Resolve { span, .. }
            | Self::Replayed { span } => span,
        }
    }

    /// Returns the operation name of this message.
    pub(crate) const fn name(&self) -> &'static str {
        match self {
            Self::Updated { .. } => "updated",
            Self::Certified { .. } => "certified",
            Self::Resolve { .. } => "resolve",
            Self::Replayed { .. } => "replayed",
        }
    }

    /// Returns the deduplication key, or `None` for the replay marker.
    fn key(&self) -> Option<Key> {
        Some(match self {
            Self::Updated { certificate, .. } => match certificate {
                Certificate::Notarization(n) => Key::Notarization(n.view()),
                Certificate::Nullification(n) => Key::Nullification(n.view()),
                Certificate::Finalization(f) => Key::Finalization(f.view()),
            },
            Self::Certified { notarization, .. } => Key::Certified(notarization.view()),
            Self::Resolve {
                proposal,
                view,
                kind: Kind::Nullification,
                ..
            } => Key::ResolveNullification(*proposal, *view),
            Self::Resolve {
                proposal,
                view,
                kind: Kind::Notarization,
                ..
            } => Key::ResolveNotarization(*proposal, *view),
            Self::Replayed { .. } => return None,
        })
    }
}

/// Identifies queued messages that are duplicate work.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Key {
    Notarization(View),
    Nullification(View),
    Finalization(View),
    Certified(View),
    ResolveNullification(View, View),
    ResolveNotarization(View, View),
}

/// Pending resolver messages retained after the mailbox fills.
///
/// Each keyed message in `messages` has one entry in `index` that maps its
/// key to its logical position. The message at logical position `p` is at
/// `messages[p - head]`. A pop from the front increments `head`, so other
/// positions stay valid. A finalization prune rebuilds the index because it
/// already visits every message.
pub struct Pending<S: Scheme, D: Digest> {
    finalization: Option<MailboxMessage<S, D>>,
    messages: VecDeque<MailboxMessage<S, D>>,
    index: HashMap<Key, u64>,
    head: u64,
}

impl<S: Scheme, D: Digest> Default for Pending<S, D> {
    fn default() -> Self {
        Self {
            finalization: None,
            messages: VecDeque::new(),
            index: HashMap::new(),
            head: 0,
        }
    }
}

impl<S: Scheme, D: Digest> Pending<S, D> {
    /// Returns the queued message at a logical position.
    fn get_mut(&mut self, position: u64) -> Option<&mut MailboxMessage<S, D>> {
        self.messages.get_mut((position - self.head) as usize)
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
            let key = message.key();
            if let Some(key) = &key {
                self.index.remove(key);
            }
            self.head += 1;
            if let Some(message) = push(message) {
                self.head -= 1;
                if let Some(key) = key {
                    self.index.insert(key, self.head);
                }
                self.messages.push_front(message);
                break;
            }
        }
    }
}

impl<S: Scheme, D: Digest> Policy for MailboxMessage<S, D> {
    type Overflow = Pending<S, D>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        // The replay marker must follow every message queued before it and
        // survive every finalization, or background repair never starts.
        let Some(key) = message.key() else {
            overflow.messages.push_back(message);
            return;
        };

        // Ignore the message if there exists a queued finalization
        // with a view greater than or equal to the new view
        let new_view = message.view();
        if matches!(
            overflow.finalization.as_ref(),
            Some(Self::Updated { certificate: Certificate::Finalization(old_finalized), .. })
                if old_finalized.view() >= new_view
        ) {
            return;
        }

        // Retain only the highest-view finalization and any messages with a view greater than the new view
        if matches!(key, Key::Finalization(_)) {
            overflow.messages.retain(|old_message| {
                matches!(old_message, Self::Replayed { .. }) || old_message.view() > new_view
            });
            overflow.head = 0;
            overflow.index.clear();
            for (position, old_message) in overflow.messages.iter().enumerate() {
                if let Some(key) = old_message.key() {
                    overflow.index.insert(key, position as u64);
                }
            }
            overflow.finalization = Some(message);
            return;
        }

        // Ignore duplicate work. Resolve requests with the same proposal,
        // requested view, and kind share one network fetch. An unrestricted
        // duplicate removes the target. Different kinds remain distinct
        // because their certificates are not interchangeable.
        if let Some(&position) = overflow.index.get(&key) {
            if let Self::Resolve { target: None, .. } = message
                && let Some(Self::Resolve { target, .. }) = overflow.get_mut(position)
            {
                *target = None;
            }
            return;
        }
        overflow
            .index
            .insert(key, overflow.head + overflow.messages.len() as u64);
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
    ///
    /// A certificate may be sent more than once, including one the resolver
    /// delivered. Sending it again opens no fetches.
    pub fn updated(&mut self, certificate: Certificate<S, D>) {
        let _ = self.sender.enqueue(MailboxMessage::Updated {
            span: info_span!(
                "simplex.resolver.mailbox.updated",
                epoch = certificate.epoch().traced(),
                view = certificate.view().traced()
            ),
            certificate,
        });
    }

    /// Notify the resolver of a certification verdict.
    pub fn certified(&mut self, notarization: Notarization<S, D>, success: bool) {
        let _ = self.sender.enqueue(MailboxMessage::Certified {
            span: info_span!(
                "simplex.resolver.mailbox.certified",
                view = notarization.view().traced(),
                success
            ),
            notarization,
            success,
        });
    }

    /// Notify the resolver that journal replay is complete. Every recovered
    /// certificate and verdict was sent before this, so the resolver can start
    /// background repair above the recovered floor.
    pub fn replayed(&mut self) {
        let _ = self.sender.enqueue(MailboxMessage::Replayed {
            span: info_span!("simplex.resolver.mailbox.replayed"),
        });
    }

    /// Requests missing proposal ancestry. If `target` is provided, the
    /// resolver queries only that peer.
    pub(crate) fn resolve(
        &mut self,
        proposal: View,
        view: View,
        kind: Kind,
        target: Option<S::PublicKey>,
    ) {
        let _ = self.sender.enqueue(MailboxMessage::Resolve {
            span: info_span!(
                "simplex.resolver.mailbox.resolve",
                proposal = proposal.traced(),
                view = view.traced(),
                kind = kind.as_str()
            ),
            proposal,
            view,
            kind,
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
        asks: NonEmptyVec<Ask>,
        response: oneshot::Sender<Outcome>,
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

/// Deliveries retained while the ready queue is full.
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
        // Drop produce requests so the serve backlog stays bounded by the ready
        // queue. We prefer handling our own responses over serving peers, who can
        // ask a less loaded peer instead.
        if matches!(message, Self::Produce { .. }) {
            return;
        }

        // Retain deliveries that still have a waiting requester.
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
    type Subscriber = Ask;
    type Outcome = Outcome;

    fn deliver(
        &mut self,
        delivery: Delivery<Self::Key, Self::Subscriber>,
        value: Self::Value,
    ) -> oneshot::Receiver<Self::Outcome> {
        let (response, receiver) = oneshot::channel();
        let (_, span) = delivery.subscribers.first().clone();
        let asks = delivery.subscribers.map_into(|(ask, _)| ask);
        let _ = self.sender.enqueue(HandlerMessage::Deliver {
            span,
            view: View::new(delivery.key.into()),
            data: value,
            asks,
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
            types::{
                Certificate, Finalization, Finalize, Notarization, Notarize, Nullification,
                Nullify, Proposal,
            },
        },
        types::{Epoch, Round},
    };
    use commonware_actor::mailbox::Policy;
    use commonware_cryptography::{certificate::mocks::Fixture, sha256::Digest as Sha256Digest};
    use commonware_parallel::Sequential;
    use commonware_utils::{non_empty, test_rng};
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
            Nullification::from_nullifies(&verifier, non_empty![@&votes], &Sequential)
                .expect("nullification"),
        )
    }

    fn notarization(view: View) -> Notarization<TestScheme, Sha256Digest> {
        let (schemes, verifier) = fixture();
        let proposal = proposal(view);
        let votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).expect("notarize"))
            .collect();
        Notarization::from_notarizes(&verifier, non_empty![@&votes], &Sequential)
            .expect("notarization")
    }

    fn finalization(view: View) -> Certificate<TestScheme, Sha256Digest> {
        let (schemes, verifier) = fixture();
        let proposal = proposal(view);
        let votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).expect("finalize"))
            .collect();
        Certificate::Finalization(
            Finalization::from_finalizes(&verifier, non_empty![@&votes], &Sequential)
                .expect("finalization"),
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
        MailboxMessage::Updated {
            span: Span::none(),
            certificate,
        }
    }

    fn certified_msg(view: View, success: bool) -> MailboxMessage<TestScheme, Sha256Digest> {
        MailboxMessage::Certified {
            span: Span::none(),
            notarization: notarization(view),
            success,
        }
    }

    fn resolve_msg(
        proposal: View,
        view: View,
        kind: Kind,
    ) -> MailboxMessage<TestScheme, Sha256Digest> {
        let mut rng = test_rng();
        let Fixture { participants, .. } = ed25519::fixture(&mut rng, b"resolver-policy-target", 5);
        MailboxMessage::Resolve {
            span: Span::none(),
            proposal,
            view,
            kind,
            target: Some(participants[0].clone()),
        }
    }

    fn unrestricted_resolve_msg(
        proposal: View,
        view: View,
        kind: Kind,
    ) -> MailboxMessage<TestScheme, Sha256Digest> {
        MailboxMessage::Resolve {
            span: Span::none(),
            proposal,
            view,
            kind,
            target: None,
        }
    }

    #[test]
    fn handle_retains_open_deliveries_only() {
        let mut overflow = HandlerPending::default();
        let deliver = |view: u64, response| HandlerMessage::Deliver {
            span: Span::none(),
            view: View::new(view),
            data: Bytes::new(),
            asks: NonEmptyVec::new(Ask::backfill()),
            response,
        };

        // An overflowed produce request is dropped and its requester sees the
        // closed response.
        let (response, mut produce) = oneshot::channel();
        HandlerMessage::handle(
            &mut overflow,
            HandlerMessage::Produce {
                view: View::new(1),
                response,
            },
        );
        assert!(matches!(
            produce.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        ));

        // Deliveries are retained, and drain skips one whose requester left.
        let (response, closed) = oneshot::channel();
        HandlerMessage::handle(&mut overflow, deliver(2, response));
        let (response, _open) = oneshot::channel();
        HandlerMessage::handle(&mut overflow, deliver(3, response));
        drop(closed);

        let mut messages = Vec::new();
        Overflow::drain(&mut overflow, |message| {
            messages.push(message);
            None
        });
        assert_eq!(messages.len(), 1);
        assert!(matches!(
            messages.pop(),
            Some(HandlerMessage::Deliver { view, .. }) if view == View::new(3)
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
            Some(MailboxMessage::Updated { certificate: Certificate::Finalization(f), .. })
                if f.view() == View::new(3)
        ));
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Updated { certificate: Certificate::Nullification(n), .. })
                if n.view() == View::new(5)
        ));
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Certified {
                notarization,
                success: false,
                ..
            }) if notarization.view() == View::new(5)
        ));
    }

    #[test]
    fn finalization_prunes_resolve_by_requested_view() {
        let mut overflow = Pending::default();
        MailboxMessage::handle(
            &mut overflow,
            resolve_msg(View::new(10), View::new(2), Kind::Nullification),
        );
        MailboxMessage::handle(
            &mut overflow,
            resolve_msg(View::new(10), View::new(5), Kind::Notarization),
        );
        MailboxMessage::handle(&mut overflow, certificate_msg(finalization(View::new(3))));

        let mut overflow = drain(overflow);
        assert_eq!(overflow.len(), 2);
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Updated { certificate: Certificate::Finalization(f), .. })
                if f.view() == View::new(3)
        ));
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Resolve {
                proposal,
                view,
                kind: Kind::Notarization,
                ..
            }) if proposal == View::new(10) && view == View::new(5)
        ));
    }

    #[test]
    fn resolve_deduplicates_by_proposal_view_and_kind() {
        let mut overflow = Pending::default();
        for kind in [Kind::Nullification, Kind::Nullification, Kind::Notarization] {
            MailboxMessage::handle(
                &mut overflow,
                resolve_msg(View::new(10), View::new(3), kind),
            );
        }

        let overflow = drain(overflow);
        assert_eq!(overflow.len(), 2);
        assert!(matches!(
            &overflow[0],
            MailboxMessage::Resolve {
                kind: Kind::Nullification,
                ..
            }
        ));
        assert!(matches!(
            &overflow[1],
            MailboxMessage::Resolve {
                kind: Kind::Notarization,
                ..
            }
        ));
    }

    /// An unrestricted request must not modify a pending request for another
    /// certificate kind.
    #[test]
    fn resolve_retains_target_across_kinds() {
        let proposal = View::new(10);
        let view = View::new(3);
        let mut overflow = Pending::default();
        MailboxMessage::handle(
            &mut overflow,
            resolve_msg(proposal, view, Kind::Nullification),
        );
        MailboxMessage::handle(
            &mut overflow,
            unrestricted_resolve_msg(proposal, view, Kind::Notarization),
        );

        let mut overflow = drain(overflow);
        assert_eq!(overflow.len(), 2);
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Resolve {
                kind: Kind::Nullification,
                target: Some(_),
                ..
            })
        ));
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Resolve {
                kind: Kind::Notarization,
                target: None,
                ..
            })
        ));
    }

    /// An unrestricted duplicate must widen the pending request regardless of
    /// arrival order.
    #[test]
    fn resolve_widens_duplicate_to_unrestricted() {
        let proposal = View::new(10);
        let view = View::new(3);
        for unrestricted_first in [false, true] {
            let messages = if unrestricted_first {
                [
                    unrestricted_resolve_msg(proposal, view, Kind::Notarization),
                    resolve_msg(proposal, view, Kind::Notarization),
                ]
            } else {
                [
                    resolve_msg(proposal, view, Kind::Notarization),
                    unrestricted_resolve_msg(proposal, view, Kind::Notarization),
                ]
            };
            let mut overflow = Pending::default();
            for message in messages {
                MailboxMessage::handle(&mut overflow, message);
            }

            let mut overflow = drain(overflow);
            assert_eq!(overflow.len(), 1);
            assert!(matches!(
                overflow.pop_front(),
                Some(MailboxMessage::Resolve {
                    proposal: actual_proposal,
                    view: actual_view,
                    kind: Kind::Notarization,
                    target: None,
                    ..
                }) if actual_proposal == proposal && actual_view == view
            ));
        }
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
                notarization,
                success: false,
                ..
            }) if notarization.view() == View::new(4)
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
            resolve_msg(View::new(10), View::new(2), Kind::Nullification),
        );
        MailboxMessage::handle(&mut overflow, certificate_msg(nullification(View::new(4))));
        MailboxMessage::handle(
            &mut overflow,
            resolve_msg(View::new(10), View::new(4), Kind::Notarization),
        );

        let mut overflow = drain(overflow);
        assert_eq!(overflow.len(), 3);
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Updated { certificate: Certificate::Finalization(f), .. })
                if f.view() == View::new(3)
        ));
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Updated { certificate: Certificate::Nullification(n), .. })
                if n.view() == View::new(4)
        ));
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Resolve {
                view,
                kind: Kind::Notarization,
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
            Some(MailboxMessage::Updated { certificate: Certificate::Finalization(f), .. })
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
            Some(MailboxMessage::Updated { certificate: Certificate::Finalization(f), .. })
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
            Some(MailboxMessage::Updated { certificate: Certificate::Nullification(n), .. })
                if n.view() == View::new(4)
        ));
        assert!(matches!(
            overflow.pop_front(),
            Some(MailboxMessage::Certified {
                notarization,
                success: true,
                ..
            }) if notarization.view() == View::new(4)
        ));
    }

    /// A queued finalization prunes lower messages but never the replay marker,
    /// which keeps its place behind the messages it followed.
    #[test]
    fn replay_marker_survives_finalization() {
        for finalization_first in [false, true] {
            let mut overflow = Pending::default();
            MailboxMessage::handle(&mut overflow, certificate_msg(nullification(View::new(2))));
            if finalization_first {
                MailboxMessage::handle(&mut overflow, certificate_msg(finalization(View::new(3))));
            }
            MailboxMessage::handle(
                &mut overflow,
                MailboxMessage::Replayed { span: Span::none() },
            );
            if !finalization_first {
                MailboxMessage::handle(&mut overflow, certificate_msg(finalization(View::new(3))));
            }
            MailboxMessage::handle(&mut overflow, certificate_msg(nullification(View::new(5))));

            let mut overflow = drain(overflow);
            assert_eq!(overflow.len(), 3);
            assert!(matches!(
                overflow.pop_front(),
                Some(MailboxMessage::Updated { certificate: Certificate::Finalization(f), .. })
                    if f.view() == View::new(3)
            ));
            assert!(matches!(
                overflow.pop_front(),
                Some(MailboxMessage::Replayed { .. })
            ));
            assert!(matches!(
                overflow.pop_front(),
                Some(MailboxMessage::Updated { certificate: Certificate::Nullification(n), .. })
                    if n.view() == View::new(5)
            ));
        }
    }

    /// Checks that each keyed message has one index entry at its position.
    fn assert_indexed(overflow: &Pending<TestScheme, Sha256Digest>) {
        let keyed = overflow.messages.iter().filter_map(|m| m.key()).count();
        assert_eq!(overflow.index.len(), keyed);
        for (key, &position) in &overflow.index {
            let message = &overflow.messages[(position - overflow.head) as usize];
            assert!(message.key() == Some(*key));
        }
    }

    /// Drains with a receiver that accepts `accept` messages, then rejects.
    fn drain_some(overflow: &mut Pending<TestScheme, Sha256Digest>, accept: usize) {
        let mut accepted = 0;
        Overflow::drain(overflow, |message| {
            if accepted == accept {
                return Some(message);
            }
            accepted += 1;
            None
        });
        assert_indexed(overflow);
    }

    fn keys(overflow: Pending<TestScheme, Sha256Digest>) -> Vec<Option<Key>> {
        drain(overflow).iter().map(|m| m.key()).collect()
    }

    #[test]
    fn certificate_kinds_deduplicate_separately() {
        let view = View::new(4);
        let mut overflow = Pending::default();
        for _ in 0..2 {
            let notarization = Certificate::Notarization(notarization(view));
            MailboxMessage::handle(&mut overflow, certificate_msg(notarization));
            MailboxMessage::handle(&mut overflow, certificate_msg(nullification(view)));
            MailboxMessage::handle(&mut overflow, certified_msg(view, true));
        }
        assert_indexed(&overflow);
        assert!(
            keys(overflow)
                == [
                    Some(Key::Notarization(view)),
                    Some(Key::Nullification(view)),
                    Some(Key::Certified(view)),
                ]
        );
    }

    /// A failed push requeues the message at the front and keeps its index
    /// entry. A delivered message no longer suppresses a new one.
    #[test]
    fn failed_drain_keeps_message_indexed() {
        let mut overflow = Pending::default();
        MailboxMessage::handle(&mut overflow, certificate_msg(nullification(View::new(2))));
        MailboxMessage::handle(&mut overflow, certificate_msg(nullification(View::new(3))));
        drain_some(&mut overflow, 1);
        drain_some(&mut overflow, 0);
        MailboxMessage::handle(&mut overflow, certificate_msg(nullification(View::new(3))));
        MailboxMessage::handle(&mut overflow, certificate_msg(nullification(View::new(2))));
        assert_indexed(&overflow);
        assert!(
            keys(overflow)
                == [
                    Some(Key::Nullification(View::new(3))),
                    Some(Key::Nullification(View::new(2))),
                ]
        );
    }

    /// An unrestricted duplicate widens the queued request after earlier
    /// messages were drained.
    #[test]
    fn resolve_widens_after_partial_drain() {
        let proposal = View::new(10);
        let mut overflow = Pending::default();
        MailboxMessage::handle(&mut overflow, certificate_msg(nullification(View::new(2))));
        for (view, kind) in [(3, Kind::Nullification), (4, Kind::Notarization)] {
            MailboxMessage::handle(&mut overflow, resolve_msg(proposal, View::new(view), kind));
        }
        drain_some(&mut overflow, 1);
        for view in [4, 3] {
            MailboxMessage::handle(
                &mut overflow,
                unrestricted_resolve_msg(proposal, View::new(view), Kind::Notarization),
            );
        }

        let overflow = drain(overflow);
        let targets: Vec<_> = overflow
            .iter()
            .map(|m| {
                matches!(
                    m,
                    MailboxMessage::Resolve {
                        target: Some(_),
                        ..
                    }
                )
            })
            .collect();
        assert_eq!(targets, [true, false, false]);
        assert_eq!(overflow[1].view(), View::new(4));
        assert_eq!(overflow[2].view(), View::new(3));
    }

    /// A finalization prune rebuilds the index, so retained messages still
    /// deduplicate and pruned keys can be queued again above the floor.
    #[test]
    fn finalization_prune_rebuilds_index() {
        let proposal = View::new(10);
        let mut overflow = Pending::default();
        MailboxMessage::handle(&mut overflow, certificate_msg(nullification(View::new(1))));
        MailboxMessage::handle(&mut overflow, certified_msg(View::new(2), true));
        MailboxMessage::handle(
            &mut overflow,
            resolve_msg(proposal, View::new(5), Kind::Notarization),
        );
        MailboxMessage::handle(&mut overflow, certificate_msg(nullification(View::new(6))));
        drain_some(&mut overflow, 1);

        MailboxMessage::handle(&mut overflow, certificate_msg(finalization(View::new(3))));
        assert_indexed(&overflow);
        MailboxMessage::handle(&mut overflow, certificate_msg(nullification(View::new(6))));
        MailboxMessage::handle(
            &mut overflow,
            unrestricted_resolve_msg(proposal, View::new(5), Kind::Notarization),
        );
        MailboxMessage::handle(&mut overflow, certified_msg(View::new(2), true));
        MailboxMessage::handle(&mut overflow, certified_msg(View::new(7), true));
        assert_indexed(&overflow);

        let overflow = drain(overflow);
        assert!(matches!(
            &overflow[1],
            MailboxMessage::Resolve { target: None, .. }
        ));
        let queued: Vec<_> = overflow.iter().map(|m| m.key()).collect();
        assert!(
            queued
                == [
                    Some(Key::Finalization(View::new(3))),
                    Some(Key::ResolveNotarization(proposal, View::new(5))),
                    Some(Key::Nullification(View::new(6))),
                    Some(Key::Certified(View::new(7))),
                ]
        );
    }

    #[test]
    fn replay_markers_are_never_deduplicated() {
        let mut overflow = Pending::default();
        for _ in 0..3 {
            let replayed = MailboxMessage::Replayed { span: Span::none() };
            MailboxMessage::handle(&mut overflow, replayed);
        }
        MailboxMessage::handle(&mut overflow, certificate_msg(finalization(View::new(3))));
        assert_indexed(&overflow);
        assert!(keys(overflow) == [Some(Key::Finalization(View::new(3))), None, None, None]);
    }
}
