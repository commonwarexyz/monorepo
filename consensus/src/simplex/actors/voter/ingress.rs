use crate::{
    Epochable, Viewable,
    simplex::{
        metrics::TimeoutReason,
        types::{Certificate, Proposal},
    },
    types::{Round as Rnd, View},
};
use commonware_actor::mailbox::{Overflow, Policy, Sender};
use commonware_cryptography::{Digest, certificate::Scheme};
use commonware_runtime::telemetry::traces::TracedExt as _;
use std::collections::VecDeque;
use tracing::{Span, info_span};

/// Sources that delivered a verified certificate to the voter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CertificateSource {
    known_to_resolver: bool,
    rebroadcast: bool,
}

impl CertificateSource {
    const BATCHER: Self = Self {
        known_to_resolver: false,
        rebroadcast: true,
    };
    const BACKGROUND_RESOLVER: Self = Self {
        known_to_resolver: true,
        rebroadcast: true,
    };
    const TARGETED_RESOLVER: Self = Self {
        known_to_resolver: true,
        rebroadcast: false,
    };

    pub(super) const fn is_resolver(self) -> bool {
        self.known_to_resolver
    }

    pub(super) const fn rebroadcast(self) -> bool {
        self.rebroadcast
    }

    /// Combines the independently useful properties of duplicate deliveries.
    const fn merge(self, other: Self) -> Self {
        Self {
            known_to_resolver: self.known_to_resolver || other.known_to_resolver,
            rebroadcast: self.rebroadcast || other.rebroadcast,
        }
    }
}

/// Messages sent to the [super::actor::Actor].
pub enum Message<S: Scheme, D: Digest> {
    /// Leader's proposal from batcher.
    Proposal {
        /// The span carried with this message.
        span: Span,
        /// The leader's proposal.
        proposal: Proposal<D>,
    },
    /// Signal that the current view should timeout (if not already).
    Timeout {
        /// The span carried with this message.
        span: Span,
        /// The round to timeout.
        round: Rnd,
        /// The reason for the timeout.
        reason: TimeoutReason,
    },
    /// Certificate from batcher or resolver.
    Verified {
        /// The span carried with this message.
        span: Span,
        /// The verified certificate.
        certificate: Certificate<S, D>,
        /// How the certificate reached the voter.
        source: CertificateSource,
    },
}

impl<S: Scheme, D: Digest> Message<S, D> {
    /// Returns the message view used for pruning and deduplication.
    pub(crate) fn view(&self) -> View {
        match self {
            Self::Proposal { proposal, .. } => proposal.view(),
            Self::Timeout { round, .. } => round.view(),
            Self::Verified { certificate, .. } => certificate.view(),
        }
    }

    /// Returns the span carried with this message.
    pub(crate) const fn span(&self) -> &Span {
        match self {
            Self::Proposal { span, .. }
            | Self::Timeout { span, .. }
            | Self::Verified { span, .. } => span,
        }
    }

    /// Returns the operation name of this message.
    pub(crate) const fn name(&self) -> &'static str {
        match self {
            Self::Proposal { .. } => "proposal",
            Self::Timeout { .. } => "timeout",
            Self::Verified { .. } => "verified",
        }
    }
}

/// Pending voter messages retained after the mailbox fills.
pub struct Pending<S: Scheme, D: Digest> {
    finalization: Option<Message<S, D>>,
    messages: VecDeque<Message<S, D>>,
}

impl<S: Scheme, D: Digest> Default for Pending<S, D> {
    fn default() -> Self {
        Self {
            finalization: None,
            messages: VecDeque::new(),
        }
    }
}

impl<S: Scheme, D: Digest> Overflow<Message<S, D>> for Pending<S, D> {
    fn is_empty(&self) -> bool {
        self.finalization.is_none() && self.messages.is_empty()
    }

    fn drain<F>(&mut self, mut push: F)
    where
        F: FnMut(Message<S, D>) -> Option<Message<S, D>>,
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

impl<S: Scheme, D: Digest> Policy for Message<S, D> {
    type Overflow = Pending<S, D>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        // Ignore messages covered by a queued finalization, but combine the
        // sources when the message duplicates that finalization.
        let new_view = message.view();
        if let Some(Self::Verified {
            certificate: Certificate::Finalization(old_finalized),
            source: old_source,
            ..
        }) = overflow.finalization.as_mut()
            && old_finalized.view() >= new_view
        {
            if old_finalized.view() == new_view
                && let Self::Verified {
                    certificate: Certificate::Finalization(_),
                    source: new_source,
                    ..
                } = &message
            {
                *old_source = (*old_source).merge(*new_source);
            }
            return;
        }

        // Retain only the highest-view finalization and any messages with a view greater than the new view
        if matches!(
            &message,
            Self::Verified {
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

        // Coalesce duplicates and combine their certificate sources.
        if overflow
            .messages
            .iter_mut()
            .any(|old_message| match (&message, old_message) {
                (
                    Self::Proposal {
                        proposal: new_proposal,
                        ..
                    },
                    Self::Proposal {
                        proposal: old_proposal,
                        ..
                    },
                ) => new_proposal.view() == old_proposal.view(),
                (
                    Self::Timeout {
                        round: new_round, ..
                    },
                    Self::Timeout {
                        round: old_round, ..
                    },
                ) => {
                    new_round.view() == old_round.view() // only retain the first queued timeout reason
                }
                (
                    Self::Verified {
                        certificate: new_certificate,
                        source: new_source,
                        ..
                    },
                    Self::Verified {
                        certificate: old_certificate,
                        source: old_source,
                        ..
                    },
                ) => {
                    let duplicate = new_certificate.view() == old_certificate.view()
                        && matches!(
                            (new_certificate, &*old_certificate),
                            (Certificate::Notarization(_), Certificate::Notarization(_))
                                | (Certificate::Nullification(_), Certificate::Nullification(_))
                                | (Certificate::Finalization(_), Certificate::Finalization(_))
                        );
                    if duplicate {
                        *old_source = (*old_source).merge(*new_source);
                    }
                    duplicate
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
    sender: Sender<Message<S, D>>,
}

impl<S: Scheme, D: Digest> Mailbox<S, D> {
    /// Create a new mailbox.
    pub const fn new(sender: Sender<Message<S, D>>) -> Self {
        Self { sender }
    }

    /// Send a leader's proposal.
    pub fn proposal(&mut self, proposal: Proposal<D>) {
        let _ = self.sender.enqueue(Message::Proposal {
            span: info_span!(
                "simplex.voter.mailbox.proposal",
                epoch = proposal.epoch().traced(),
                view = proposal.view().traced()
            ),
            proposal,
        });
    }

    /// Signal that the given round should timeout (if not already).
    pub fn timeout(&mut self, round: Rnd, reason: TimeoutReason) {
        let _ = self.sender.enqueue(Message::Timeout {
            span: info_span!(
                "simplex.voter.mailbox.timeout",
                epoch = round.epoch().traced(),
                view = round.view().traced(),
                reason = reason.as_str()
            ),
            round,
            reason,
        });
    }

    /// Send a recovered certificate.
    pub fn recovered(&mut self, certificate: Certificate<S, D>) {
        let _ = self.sender.enqueue(Message::Verified {
            span: info_span!(
                "simplex.voter.mailbox.recovered",
                epoch = certificate.epoch().traced(),
                view = certificate.view().traced(),
                certificate = %certificate.kind()
            ),
            certificate,
            source: CertificateSource::BATCHER,
        });
    }

    /// Send a resolved certificate.
    pub fn resolved(&mut self, certificate: Certificate<S, D>) {
        let _ = self.sender.enqueue(Message::Verified {
            span: info_span!(
                "simplex.voter.mailbox.resolved",
                epoch = certificate.epoch().traced(),
                view = certificate.view().traced(),
                certificate = %certificate.kind()
            ),
            certificate,
            source: CertificateSource::BACKGROUND_RESOLVER,
        });
    }

    /// Send a certificate resolved directly from a proposal's leader without
    /// requesting an immediate re-gossip to the other participants.
    pub(crate) fn resolved_targeted(&mut self, certificate: Certificate<S, D>) {
        let _ = self.sender.enqueue(Message::Verified {
            span: info_span!(
                "simplex.voter.mailbox.resolved_targeted",
                epoch = certificate.epoch().traced(),
                view = certificate.view().traced(),
                certificate = %certificate.kind()
            ),
            certificate,
            source: CertificateSource::TARGETED_RESOLVER,
        });
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
    use commonware_actor::mailbox::{self, Policy};
    use commonware_cryptography::{certificate::mocks::Fixture, sha256::Digest as Sha256Digest};
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner, deterministic};
    use commonware_utils::{NZUsize, test_rng};
    use std::collections::VecDeque;

    type TestScheme = ed25519::Scheme;
    const EPOCH: Epoch = Epoch::new(1);

    fn fixture() -> (Vec<TestScheme>, TestScheme) {
        let mut rng = test_rng();
        let Fixture {
            schemes, verifier, ..
        } = ed25519::fixture(&mut rng, b"voter-policy", 5);
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

    fn proposal_msg(view: View) -> Message<TestScheme, Sha256Digest> {
        Message::Proposal {
            span: Span::none(),
            proposal: proposal(view),
        }
    }

    fn timeout_msg(view: View, reason: TimeoutReason) -> Message<TestScheme, Sha256Digest> {
        Message::Timeout {
            span: Span::none(),
            round: Round::new(EPOCH, view),
            reason,
        }
    }

    fn verified_msg(
        certificate: Certificate<TestScheme, Sha256Digest>,
        from_resolver: bool,
    ) -> Message<TestScheme, Sha256Digest> {
        verified_msg_from(
            certificate,
            if from_resolver {
                CertificateSource::BACKGROUND_RESOLVER
            } else {
                CertificateSource::BATCHER
            },
        )
    }

    fn verified_msg_from(
        certificate: Certificate<TestScheme, Sha256Digest>,
        source: CertificateSource,
    ) -> Message<TestScheme, Sha256Digest> {
        Message::Verified {
            span: Span::none(),
            certificate,
            source,
        }
    }

    fn drain(
        mut overflow: Pending<TestScheme, Sha256Digest>,
    ) -> VecDeque<Message<TestScheme, Sha256Digest>> {
        let mut messages = VecDeque::new();
        Overflow::drain(&mut overflow, |message| {
            messages.push_back(message);
            None
        });
        messages
    }

    fn retained_duplicate_source(
        certificate: Certificate<TestScheme, Sha256Digest>,
        first: CertificateSource,
        second: CertificateSource,
    ) -> CertificateSource {
        let mut overflow = Pending::default();
        Message::handle(&mut overflow, verified_msg_from(certificate.clone(), first));
        Message::handle(&mut overflow, verified_msg_from(certificate, second));

        let mut overflow = drain(overflow);
        assert_eq!(overflow.len(), 1);
        let Some(Message::Verified { source, .. }) = overflow.pop_front() else {
            panic!("expected retained certificate");
        };
        source
    }

    #[test]
    fn targeted_resolution_controls_immediate_rebroadcast() {
        let runtime = deterministic::Runner::default();
        runtime.start(|context| async move {
            let (sender, mut receiver) = mailbox::new(context, NZUsize!(1));
            let mut mailbox = Mailbox::new(sender);
            mailbox.resolved_targeted(finalization(View::new(2)));

            let Some(Message::Verified { source, .. }) = receiver.recv().await else {
                panic!("expected targeted resolver certificate");
            };
            assert_eq!(source, CertificateSource::TARGETED_RESOLVER);
            assert!(source.is_resolver());
            assert!(!source.rebroadcast());

            mailbox.resolved(finalization(View::new(3)));
            let Some(Message::Verified { source, .. }) = receiver.recv().await else {
                panic!("expected background resolver certificate");
            };
            assert_eq!(source, CertificateSource::BACKGROUND_RESOLVER);
            assert!(source.is_resolver());
            assert!(source.rebroadcast());
        });
    }

    #[test]
    fn finalization_prunes_stale_overflow() {
        let mut overflow = Pending::default();
        Message::handle(&mut overflow, proposal_msg(View::new(2)));
        Message::handle(
            &mut overflow,
            timeout_msg(View::new(2), TimeoutReason::LeaderTimeout),
        );
        Message::handle(
            &mut overflow,
            verified_msg(nullification(View::new(2)), false),
        );
        Message::handle(&mut overflow, proposal_msg(View::new(4)));
        Message::handle(
            &mut overflow,
            verified_msg(finalization(View::new(3)), false),
        );

        let mut overflow = drain(overflow);
        assert_eq!(overflow.len(), 2);
        assert!(matches!(
            overflow.pop_front(),
            Some(Message::Verified { certificate: Certificate::Finalization(f), source: CertificateSource::BATCHER, .. })
                if f.view() == View::new(3)
        ));
        assert!(matches!(
            overflow.pop_front(),
            Some(Message::Proposal { proposal: p, .. }) if p.view() == View::new(4)
        ));
    }

    #[test]
    fn duplicate_certificate_combines_sources() {
        for (certificate, background) in [
            (
                nullification(View::new(5)),
                CertificateSource::BACKGROUND_RESOLVER,
            ),
            (finalization(View::new(5)), CertificateSource::BATCHER),
        ] {
            let source = retained_duplicate_source(
                certificate,
                CertificateSource::TARGETED_RESOLVER,
                background,
            );
            assert!(source.is_resolver());
            assert!(source.rebroadcast());
        }
    }

    #[test]
    fn queued_finalization_rejects_covered_messages() {
        let mut overflow = Pending::default();
        Message::handle(
            &mut overflow,
            verified_msg(finalization(View::new(3)), false),
        );

        Message::handle(&mut overflow, proposal_msg(View::new(3)));
        Message::handle(
            &mut overflow,
            timeout_msg(View::new(2), TimeoutReason::LeaderTimeout),
        );
        Message::handle(
            &mut overflow,
            verified_msg(nullification(View::new(2)), false),
        );
        Message::handle(
            &mut overflow,
            verified_msg(finalization(View::new(2)), false),
        );
        Message::handle(&mut overflow, proposal_msg(View::new(4)));

        let mut overflow = drain(overflow);
        assert_eq!(overflow.len(), 2);
        assert!(matches!(
            overflow.pop_front(),
            Some(Message::Verified { certificate: Certificate::Finalization(f), source: CertificateSource::BATCHER, .. })
                if f.view() == View::new(3)
        ));
        assert!(matches!(
            overflow.pop_front(),
            Some(Message::Proposal { proposal: p, .. }) if p.view() == View::new(4)
        ));
    }

    #[test]
    fn duplicate_finalization_is_dropped() {
        let mut overflow = Pending::default();
        Message::handle(
            &mut overflow,
            verified_msg(finalization(View::new(3)), false),
        );
        Message::handle(
            &mut overflow,
            verified_msg(finalization(View::new(3)), true),
        );

        let mut overflow = drain(overflow);
        assert_eq!(overflow.len(), 1);
        let Some(Message::Verified {
            certificate: Certificate::Finalization(finalization),
            source,
            ..
        }) = overflow.pop_front()
        else {
            panic!("expected retained finalization");
        };
        assert_eq!(finalization.view(), View::new(3));
        assert!(source.is_resolver());
        assert!(source.rebroadcast());
    }

    #[test]
    fn newer_finalization_replaces_older_pruning_floor() {
        let mut overflow = Pending::default();
        Message::handle(
            &mut overflow,
            verified_msg(finalization(View::new(3)), false),
        );
        Message::handle(&mut overflow, proposal_msg(View::new(4)));
        Message::handle(
            &mut overflow,
            verified_msg(finalization(View::new(5)), false),
        );

        let mut overflow = drain(overflow);
        assert_eq!(overflow.len(), 1);
        assert!(matches!(
            overflow.pop_front(),
            Some(Message::Verified { certificate: Certificate::Finalization(f), source: CertificateSource::BATCHER, .. })
                if f.view() == View::new(5)
        ));
    }

    #[test]
    fn duplicate_proposals_and_timeouts_are_deduplicated() {
        let mut overflow = Pending::<TestScheme, Sha256Digest>::default();
        Message::handle(&mut overflow, proposal_msg(View::new(4)));
        Message::handle(&mut overflow, proposal_msg(View::new(4)));
        Message::handle(
            &mut overflow,
            timeout_msg(View::new(4), TimeoutReason::LeaderTimeout),
        );
        Message::handle(
            &mut overflow,
            timeout_msg(View::new(4), TimeoutReason::Inactivity),
        );

        let overflow = drain(overflow);
        assert_eq!(overflow.len(), 2);
    }
}
