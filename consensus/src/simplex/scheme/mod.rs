//! Signing scheme implementations for `simplex`.
//!
//! # Attributable Schemes and Fault Evidence
//!
//! Signing schemes differ in whether per-validator activities can be used as evidence of either
//! liveness or of committing a fault:
//!
//! - **Attributable Schemes** ([`ed25519`], [`bls12381_multisig`]): Individual signatures can be presented
//!   to some third party as evidence of either liveness or of committing a fault. Certificates contain signer
//!   indices alongside individual signatures, enabling secure per-validator activity tracking and
//!   conflict detection.
//!
//! - **Non-Attributable schemes** ([`bls12381_threshold`]): Individual signatures cannot be presented
//!   to some third party as evidence of either liveness or of committing a fault because they can be forged
//!   by other players (often after some quorum of partial signatures are collected). With [`bls12381_threshold`],
//!   possession of any `t` valid partial signatures can be used to forge a partial signature for any other player.
//!   Because peer connections are authenticated, evidence can be used locally (as it must be sent by said participant)
//!   but can't be used by an external observer.
//!
//! The [`Scheme::is_attributable()`] method signals whether evidence can be safely
//! exposed. For applications only interested in collecting evidence for liveness/faults, use [`reporter::AttributableReporter`]
//! which automatically handles filtering and verification based on scheme (hiding votes/proofs that are not attributable). If
//! full observability is desired, process all messages passed through the [`crate::Reporter`] interface.

pub mod bls12381_multisig;
pub mod bls12381_threshold;
pub mod ed25519;

cfg_if::cfg_if! {
    if #[cfg(not(target_arch = "wasm32"))] {
        pub mod reporter {
            //! Wrapper for scheme-dependent activity filtering and verification.
            //!
            //! # Overview
            //!
            //! The [`AttributableReporter`] provides a composable wrapper around consensus reporters
            //! that automatically filters and verifies activities based on scheme attributability.
            //! This ensures that:
            //!
            //! 1. **Peer activities are cryptographically verified** before being reported
            //! 2. **Non-attributable schemes** suppress per-validator activities from peers to prevent
            //!    signature forgery attacks
            //! 3. **Certificates** are always reported as they contain valid quorum proofs
            //!
            //! # Security Rationale
            //!
            //! With [`super::bls12381_threshold`], any `t` valid partial signatures
            //! can be used to forge a partial signature for any participant. If per-validator activities
            //! were exposed for such schemes, adversaries could fabricate evidence of either liveness or of committing a fault.
            //! This wrapper prevents that attack by suppressing peer activities for non-attributable schemes.

            use crate::{
                simplex::{scheme::SimplexScheme, types::Activity},
                Reporter,
            };
            use commonware_cryptography::{certificate::Scheme, Digest};
            use rand::{CryptoRng, Rng};

            /// Reporter wrapper that filters and verifies activities based on scheme attributability.
            ///
            /// This wrapper provides scheme-aware activity filtering with automatic verification of peer
            /// activities. It prevents signature forgery attacks on non-attributable schemes while ensuring
            /// all activities are cryptographically valid before reporting.
            #[derive(Clone)]
            pub struct AttributableReporter<
                E: Clone + Rng + CryptoRng + Send + 'static,
                S: Scheme,
                D: Digest,
                R: Reporter<Activity = Activity<S, D>>,
            > {
                /// RNG for certificate verification
                rng: E,
                /// Signing scheme for verification
                scheme: S,
                /// Namespace for domain separation in verification
                namespace: Vec<u8>,
                /// Inner reporter that receives filtered activities
                reporter: R,
                /// Whether to always verify peer activities
                verify: bool,
            }

            impl<
                    E: Clone + Rng + CryptoRng + Send + 'static,
                    S: Scheme,
                    D: Digest,
                    R: Reporter<Activity = Activity<S, D>>,
                > AttributableReporter<E, S, D, R>
            {
                /// Creates a new `AttributableReporter` that wraps an inner reporter.
                pub const fn new(rng: E, scheme: S, namespace: Vec<u8>, reporter: R, verify: bool) -> Self {
                    Self {
                        rng,
                        scheme,
                        namespace,
                        reporter,
                        verify,
                    }
                }
            }

            impl<
                    E: Clone + Rng + CryptoRng + Send + 'static,
                    S: SimplexScheme<D>,
                    D: Digest,
                    R: Reporter<Activity = Activity<S, D>>,
                > Reporter for AttributableReporter<E, S, D, R>
            {
                type Activity = Activity<S, D>;

                async fn report(&mut self, activity: Self::Activity) {
                    // Verify peer activities if verification is enabled
                    if self.verify
                        && !activity.verified()
                        && !activity.verify(&mut self.rng, &self.scheme, &self.namespace)
                    {
                        // Drop unverified peer activity
                        return;
                    }

                    // Filter based on scheme attributability
                    if !self.scheme.is_attributable() {
                        match activity {
                            Activity::Notarize(_)
                            | Activity::Nullify(_)
                            | Activity::Finalize(_)
                            | Activity::ConflictingNotarize(_)
                            | Activity::ConflictingFinalize(_)
                            | Activity::NullifyFinalize(_) => {
                                // Drop per-validator peer activity for non-attributable scheme
                                return;
                            }
                            Activity::Notarization(_)
                            | Activity::Nullification(_)
                            | Activity::Finalization(_) => {
                                // Always report certificates
                            }
                        }
                    }

                    self.reporter.report(activity).await;
                }
            }

            #[cfg(test)]
            mod tests {
                use super::*;
                use crate::{
                    simplex::{
                        scheme::{bls12381_threshold, ed25519, Scheme},
                        types::{Notarization, Notarize, Proposal, Subject},
                    },
                    types::{Epoch, Round, View},
                };
                use commonware_cryptography::{
                    bls12381::primitives::variant::MinPk, certificate::mocks::Fixture,
                    sha256::Digest as Sha256Digest, Hasher, Sha256,
                };
                use futures::executor::block_on;
                use rand::{rngs::StdRng, SeedableRng};
                use std::sync::{Arc, Mutex};

                const NAMESPACE: &[u8] = b"test-reporter";

                #[derive(Clone)]
                struct MockReporter<S: Scheme, D: Digest> {
                    activities: Arc<Mutex<Vec<Activity<S, D>>>>,
                }

                impl<S: Scheme, D: Digest> MockReporter<S, D> {
                    fn new() -> Self {
                        Self {
                            activities: Arc::new(Mutex::new(Vec::new())),
                        }
                    }

                    fn reported(&self) -> Vec<Activity<S, D>> {
                        self.activities.lock().unwrap().clone()
                    }

                    fn count(&self) -> usize {
                        self.activities.lock().unwrap().len()
                    }
                }

                impl<S: Scheme, D: Digest> Reporter for MockReporter<S, D> {
                    type Activity = Activity<S, D>;

                    async fn report(&mut self, activity: Self::Activity) {
                        self.activities.lock().unwrap().push(activity);
                    }
                }

                fn create_proposal(epoch: u64, view: u64) -> Proposal<Sha256Digest> {
                    let data = format!("proposal-{epoch}-{view}");
                    let hash = Sha256::hash(data.as_bytes());
                    let epoch = Epoch::new(epoch);
                    let view = View::new(view);
                    Proposal::new(Round::new(epoch, view), view, hash)
                }

                #[test]
                fn test_invalid_peer_activity_dropped() {
                    // Invalid peer activities should be dropped when verification is enabled
                    let mut rng = StdRng::seed_from_u64(42);
                    let Fixture {
                        schemes, verifier, ..
                    } = ed25519::fixture(&mut rng, 4);

                    assert!(verifier.is_attributable(), "Ed25519 must be attributable");

                    let mock = MockReporter::new();
                    let mut reporter =
                        AttributableReporter::new(rng, verifier, NAMESPACE.to_vec(), mock.clone(), true);

                    // Create an invalid activity (wrong namespace)
                    let proposal = create_proposal(0, 1);
                    let signature = schemes[1]
                        .sign::<Sha256Digest>(
                            &[], // Invalid namespace
                            Subject::Notarize {
                                proposal: &proposal,
                            },
                        )
                        .expect("signing failed");
                    let notarize = Notarize {
                        proposal,
                        signature,
                    };

                    // Report it
                    block_on(reporter.report(Activity::Notarize(notarize)));

                    // Should be dropped
                    assert_eq!(mock.count(), 0);
                }

                #[test]
                fn test_skip_verification() {
                    // When verification is disabled, invalid activities pass through
                    let mut rng = StdRng::seed_from_u64(42);
                    let Fixture {
                        schemes, verifier, ..
                    } = ed25519::fixture(&mut rng, 4);

                    assert!(verifier.is_attributable(), "Ed25519 must be attributable");

                    let mock = MockReporter::new();
                    let mut reporter = AttributableReporter::new(
                        rng,
                        verifier,
                        NAMESPACE.to_vec(),
                        mock.clone(),
                        false, // Disable verification
                    );

                    // Create an invalid activity (wrong namespace)
                    let proposal = create_proposal(0, 1);
                    let signature = schemes[1]
                        .sign::<Sha256Digest>(
                            &[], // Invalid namespace
                            Subject::Notarize {
                                proposal: &proposal,
                            },
                        )
                        .expect("signing failed");
                    let notarize = Notarize {
                        proposal,
                        signature,
                    };

                    // Report it
                    block_on(reporter.report(Activity::Notarize(notarize)));

                    // Should be reported even though it's invalid
                    assert_eq!(mock.count(), 1);
                    let reported = mock.reported();
                    assert!(matches!(reported[0], Activity::Notarize(_)));
                }

                #[test]
                fn test_certificates_always_reported() {
                    // Certificates should always be reported, even for non-attributable schemes
                    let mut rng = StdRng::seed_from_u64(42);
                    let Fixture {
                        schemes, verifier, ..
                    } = bls12381_threshold::fixture::<MinPk, _>(&mut rng, 4);

                    assert!(
                        !verifier.is_attributable(),
                        "BLS threshold must be non-attributable"
                    );

                    let mock = MockReporter::new();
                    let mut reporter =
                        AttributableReporter::new(rng, verifier, NAMESPACE.to_vec(), mock.clone(), true);

                    // Create a certificate from multiple validators
                    let proposal = create_proposal(0, 1);
                    let votes: Vec<_> = schemes
                        .iter()
                        .map(|scheme| {
                            scheme
                                .sign::<Sha256Digest>(
                                    NAMESPACE,
                                    Subject::Notarize {
                                        proposal: &proposal,
                                    },
                                )
                                .expect("signing failed")
                        })
                        .collect();

                    let certificate = schemes[0]
                        .assemble_certificate(votes)
                        .expect("failed to assemble certificate");

                    let notarization = Notarization {
                        proposal,
                        certificate,
                    };

                    // Report it
                    block_on(reporter.report(Activity::Notarization(notarization)));

                    // Should be reported even though scheme is non-attributable (certificates are quorum proofs)
                    assert_eq!(mock.count(), 1);
                    let reported = mock.reported();
                    assert!(matches!(reported[0], Activity::Notarization(_)));
                }

                #[test]
                fn test_non_attributable_filters_peer_activities() {
                    // Non-attributable schemes (like BLS threshold) must filter peer per-validator activities
                    let mut rng = StdRng::seed_from_u64(42);
                    let Fixture {
                        schemes, verifier, ..
                    } = bls12381_threshold::fixture::<MinPk, _>(&mut rng, 4);

                    assert!(
                        !verifier.is_attributable(),
                        "BLS threshold must be non-attributable"
                    );

                    let mock = MockReporter::new();
                    let mut reporter =
                        AttributableReporter::new(rng, verifier, NAMESPACE.to_vec(), mock.clone(), true);

                    // Create peer activity (from validator 1)
                    let proposal = create_proposal(0, 1);
                    let signature = schemes[1]
                        .sign::<Sha256Digest>(
                            NAMESPACE,
                            Subject::Notarize {
                                proposal: &proposal,
                            },
                        )
                        .expect("signing failed");

                    let notarize = Notarize {
                        proposal,
                        signature,
                    };

                    // Report peer per-validator activity
                    block_on(reporter.report(Activity::Notarize(notarize)));

                    // Must be filtered
                    assert_eq!(mock.count(), 0);
                }

                #[test]
                fn test_attributable_scheme_reports_peer_activities() {
                    // Ed25519 (attributable) should report peer per-validator activities
                    let mut rng = StdRng::seed_from_u64(42);
                    let Fixture {
                        schemes, verifier, ..
                    } = ed25519::fixture(&mut rng, 4);

                    assert!(verifier.is_attributable(), "Ed25519 must be attributable");

                    let mock = MockReporter::new();
                    let mut reporter =
                        AttributableReporter::new(rng, verifier, NAMESPACE.to_vec(), mock.clone(), true);

                    // Create a peer activity (from validator 1)
                    let proposal = create_proposal(0, 1);
                    let signature = schemes[1]
                        .sign::<Sha256Digest>(
                            NAMESPACE,
                            Subject::Notarize {
                                proposal: &proposal,
                            },
                        )
                        .expect("signing failed");

                    let notarize = Notarize {
                        proposal,
                        signature,
                    };

                    // Report the peer per-validator activity
                    block_on(reporter.report(Activity::Notarize(notarize)));

                    // Should be reported since scheme is attributable
                    assert_eq!(mock.count(), 1);
                    let reported = mock.reported();
                    assert!(matches!(reported[0], Activity::Notarize(_)));
                }
            }
        }
    }
}

use crate::{simplex::types::Subject, types::Round};
use commonware_codec::Encode;
use commonware_cryptography::{
    certificate::{self, Scheme},
    Digest,
};
use commonware_utils::union;

impl<'a, D: Digest> certificate::Subject for Subject<'a, D> {
    fn namespace_and_message(&self, namespace: &[u8]) -> (Vec<u8>, Vec<u8>) {
        vote_namespace_and_message(namespace, self)
    }
}

/// Extension trait for schemes that can derive randomness from certificates.
///
/// Some signing schemes (like [`bls12381_threshold`]) produce certificates that contain
/// embedded randomness which can be extracted and used for leader election or other
/// protocol-level randomness requirements. This trait provides a uniform interface for
/// extracting that randomness when available.
///
/// Schemes that do not support embedded randomness (like [`ed25519`] and [`bls12381_multisig`])
/// implement this trait but return `None` from [`SeededScheme::seed`].
pub trait SeededScheme: Scheme {
    /// Randomness seed derived from a certificate, if the scheme supports it.
    type Seed: Clone + Encode + Send;

    /// Extracts randomness seed, if provided by the scheme, derived from the certificate
    /// for the given round.
    fn seed(&self, round: Round, certificate: &Self::Certificate) -> Option<Self::Seed>;
}

pub trait SimplexScheme<D: Digest>: for<'a> SeededScheme<Subject<'a, D> = Subject<'a, D>> {}

impl<D: Digest, S> SimplexScheme<D> for S where
    S: for<'a> SeededScheme<Subject<'a, D> = Subject<'a, D>>
{
}

// Constants for domain separation in signature verification
// These are used to prevent cross-protocol attacks and message-type confusion
const SEED_SUFFIX: &[u8] = b"_SEED";
const NOTARIZE_SUFFIX: &[u8] = b"_NOTARIZE";
const NULLIFY_SUFFIX: &[u8] = b"_NULLIFY";
const FINALIZE_SUFFIX: &[u8] = b"_FINALIZE";

/// Creates a namespace for seed messages by appending the SEED_SUFFIX
/// The seed is used for leader election and randomness generation
#[inline]
pub(crate) fn seed_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, SEED_SUFFIX)
}

/// Creates a namespace for notarize messages by appending the NOTARIZE_SUFFIX
/// Domain separation prevents cross-protocol attacks
#[inline]
pub(crate) fn notarize_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, NOTARIZE_SUFFIX)
}

/// Creates a namespace for nullify messages by appending the NULLIFY_SUFFIX
/// Domain separation prevents cross-protocol attacks
#[inline]
pub(crate) fn nullify_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, NULLIFY_SUFFIX)
}

/// Creates a namespace for finalize messages by appending the FINALIZE_SUFFIX
/// Domain separation prevents cross-protocol attacks
#[inline]
pub(crate) fn finalize_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, FINALIZE_SUFFIX)
}

/// Produces the vote namespace and message bytes for a given vote context.
///
/// Returns the final namespace (with the context-specific suffix) and the
/// serialized message to sign or verify.
#[inline]
pub(crate) fn vote_namespace_and_message<D: Digest>(
    namespace: &[u8],
    subject: &Subject<'_, D>,
) -> (Vec<u8>, Vec<u8>) {
    match subject {
        Subject::Notarize { proposal } => {
            (notarize_namespace(namespace), proposal.encode().to_vec())
        }
        Subject::Nullify { round } => (nullify_namespace(namespace), round.encode().to_vec()),
        Subject::Finalize { proposal } => {
            (finalize_namespace(namespace), proposal.encode().to_vec())
        }
    }
}

/// Produces the seed namespace and message bytes for a given vote context.
///
/// Returns the final namespace (with the seed suffix) and the serialized
/// message to sign or verify.
#[inline]
pub(crate) fn seed_namespace_and_message<D: Digest>(
    namespace: &[u8],
    subject: &Subject<'_, D>,
) -> (Vec<u8>, Vec<u8>) {
    (
        seed_namespace(namespace),
        match subject {
            Subject::Notarize { proposal } | Subject::Finalize { proposal } => {
                proposal.round.encode().to_vec()
            }
            Subject::Nullify { round } => round.encode().to_vec(),
        },
    )
}
