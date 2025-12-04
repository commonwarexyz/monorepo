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
    simplex::{signing_scheme::Scheme, types::Activity},
    Reporter,
};
use commonware_cryptography::Digest;
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
        S: Scheme,
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
            mocks::fixtures::{bls12381_threshold, ed25519, Fixture},
            signing_scheme::Scheme,
            types::{Notarization, Notarize, Proposal, Subject},
        },
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{
        bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest, Hasher, Sha256,
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
        } = ed25519(&mut rng, 4);

        assert!(verifier.is_attributable(), "Ed25519 must be attributable");

        let mock = MockReporter::new();
        let mut reporter =
            AttributableReporter::new(rng, verifier, NAMESPACE.to_vec(), mock.clone(), true);

        // Create an invalid activity (wrong namespace)
        let proposal = create_proposal(0, 1);
        let signature = schemes[1]
            .sign_vote::<Sha256Digest>(
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
        } = ed25519(&mut rng, 4);

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
            .sign_vote::<Sha256Digest>(
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
        } = bls12381_threshold::<MinPk, _>(&mut rng, 4);

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
                    .sign_vote::<Sha256Digest>(
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
        } = bls12381_threshold::<MinPk, _>(&mut rng, 4);

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
            .sign_vote::<Sha256Digest>(
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
        } = ed25519(&mut rng, 4);

        assert!(verifier.is_attributable(), "Ed25519 must be attributable");

        let mock = MockReporter::new();
        let mut reporter =
            AttributableReporter::new(rng, verifier, NAMESPACE.to_vec(), mock.clone(), true);

        // Create a peer activity (from validator 1)
        let proposal = create_proposal(0, 1);
        let signature = schemes[1]
            .sign_vote::<Sha256Digest>(
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
