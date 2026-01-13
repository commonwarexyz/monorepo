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
    minimmit::{scheme::Scheme, types::Activity},
    Reporter,
};
use commonware_cryptography::{certificate, Digest};
use commonware_parallel::Strategy;
use rand_core::CryptoRngCore;

/// Reporter wrapper that filters and verifies activities based on scheme attributability.
///
/// This wrapper provides scheme-aware activity filtering with automatic verification of peer
/// activities. It prevents signature forgery attacks on non-attributable schemes while ensuring
/// all activities are cryptographically valid before reporting.
#[derive(Clone)]
pub struct AttributableReporter<
    E: Clone + CryptoRngCore + Send + 'static,
    S: certificate::Scheme,
    D: Digest,
    T: Strategy,
    R: Reporter<Activity = Activity<S, D>>,
> {
    /// RNG for certificate verification
    rng: E,
    /// Signing scheme for verification
    scheme: S,
    /// Inner reporter that receives filtered activities
    reporter: R,
    /// Strategy for parallel operations.
    strategy: T,
    /// Whether to always verify peer activities
    verify: bool,
}

impl<
        E: Clone + CryptoRngCore + Send + 'static,
        S: certificate::Scheme,
        D: Digest,
        T: Strategy,
        R: Reporter<Activity = Activity<S, D>>,
    > AttributableReporter<E, S, D, T, R>
{
    /// Creates a new `AttributableReporter` that wraps an inner reporter.
    pub const fn new(rng: E, scheme: S, reporter: R, strategy: T, verify: bool) -> Self {
        Self {
            rng,
            scheme,
            reporter,
            strategy,
            verify,
        }
    }
}

impl<
        E: Clone + CryptoRngCore + Send + 'static,
        S: Scheme<D>,
        D: Digest,
        T: Strategy,
        R: Reporter<Activity = Activity<S, D>>,
    > Reporter for AttributableReporter<E, S, D, T, R>
{
    type Activity = Activity<S, D>;

    async fn report(&mut self, activity: Self::Activity) {
        // Verify peer activities if verification is enabled
        if self.verify
            && !activity.verified()
            && !activity.verify(&mut self.rng, &self.scheme, &self.strategy)
        {
            // Drop unverified peer activity
            return;
        }

        // Filter based on scheme attributability
        if !S::is_attributable() {
            match activity {
                Activity::Notarize(_)
                | Activity::Nullify(_)
                | Activity::ConflictingNotarize(_)
                | Activity::NullifyNotarize(_) => {
                    // Drop per-validator peer activity for non-attributable scheme
                    return;
                }
                Activity::Notarization(_) | Activity::Nullification(_) => {
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
        minimmit::{
            scheme::ed25519,
            types::{Notarization, Notarize, Proposal, Subject},
        },
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{
        certificate::{self, mocks::Fixture, Scheme as _},
        sha256::Digest as Sha256Digest,
        Hasher, Sha256,
    };
    use commonware_parallel::Sequential;
    use futures::executor::block_on;
    use rand::{rngs::StdRng, SeedableRng};
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct MockReporter<S: certificate::Scheme, D: Digest> {
        activities: Arc<Mutex<Vec<Activity<S, D>>>>,
    }

    impl<S: certificate::Scheme, D: Digest> MockReporter<S, D> {
        fn new() -> Self {
            Self {
                activities: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn count(&self) -> usize {
            self.activities.lock().expect("lock poisoned").len()
        }
    }

    impl<S: certificate::Scheme, D: Digest> Reporter for MockReporter<S, D> {
        type Activity = Activity<S, D>;

        async fn report(&mut self, activity: Self::Activity) {
            self.activities
                .lock()
                .expect("lock poisoned")
                .push(activity);
        }
    }

    fn create_proposal(epoch: u64, view: u64) -> Proposal<Sha256Digest> {
        let data = format!("proposal-{epoch}-{view}");
        let hash = Sha256::hash(data.as_bytes());
        let epoch = Epoch::new(epoch);
        let view = View::new(view);
        let round = Round::new(epoch, view);
        Proposal::new(round, view, hash)
    }

    #[test]
    fn test_invalid_peer_activity_dropped() {
        // Invalid peer activities should be dropped when verification is enabled
        let mut rng = StdRng::seed_from_u64(42);
        let namespace = b"minimmit_consensus";
        let Fixture { verifier, .. } = ed25519::fixture(&mut rng, namespace, 4);

        // Create a scheme with wrong namespace to generate invalid signatures
        let wrong_namespace = b"wrong_namespace";
        let Fixture {
            schemes: wrong_schemes,
            ..
        } = ed25519::fixture(&mut rng, wrong_namespace, 4);

        assert!(
            ed25519::Scheme::is_attributable(),
            "Ed25519 must be attributable"
        );

        let mock = MockReporter::new();
        let strategy = Sequential;
        let mut reporter = AttributableReporter::new(rng, verifier, mock.clone(), strategy, true);

        // Create an invalid activity (signed with wrong namespace scheme)
        let proposal = create_proposal(0, 1);
        let attestation = wrong_schemes[1]
            .sign::<Sha256Digest>(Subject::Notarize {
                proposal: &proposal,
            })
            .expect("signing failed");
        let notarize = Notarize {
            proposal,
            attestation,
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
        let namespace = b"minimmit_consensus";
        let Fixture { verifier, .. } = ed25519::fixture(&mut rng, namespace, 4);

        // Create a scheme with wrong namespace to generate invalid signatures
        let wrong_namespace = b"wrong_namespace";
        let Fixture {
            schemes: wrong_schemes,
            ..
        } = ed25519::fixture(&mut rng, wrong_namespace, 4);

        assert!(
            ed25519::Scheme::is_attributable(),
            "Ed25519 must be attributable"
        );

        let mock = MockReporter::new();
        let strategy = Sequential;
        let mut reporter = AttributableReporter::new(
            rng,
            verifier,
            mock.clone(),
            strategy,
            false, // Disable verification
        );

        // Create an invalid activity (signed with wrong namespace scheme)
        let proposal = create_proposal(0, 1);
        let attestation = wrong_schemes[1]
            .sign::<Sha256Digest>(Subject::Notarize {
                proposal: &proposal,
            })
            .expect("signing failed");
        let notarize = Notarize {
            proposal,
            attestation,
        };

        // Report it
        block_on(reporter.report(Activity::Notarize(notarize)));

        // Should be reported even though it's invalid
        assert_eq!(mock.count(), 1);
    }

    #[test]
    fn test_certificates_always_reported_for_attributable() {
        // Certificates should always be reported
        let mut rng = StdRng::seed_from_u64(42);
        let namespace = b"minimmit_consensus";
        let Fixture {
            schemes, verifier, ..
        } = ed25519::fixture(&mut rng, namespace, 4);

        assert!(
            ed25519::Scheme::is_attributable(),
            "Ed25519 must be attributable"
        );

        let mock = MockReporter::new();
        let strategy = Sequential;
        let mut reporter = AttributableReporter::new(rng, verifier, mock.clone(), strategy, true);

        // Create a certificate from multiple validators
        let proposal = create_proposal(0, 1);
        let votes: Vec<_> = schemes
            .iter()
            .map(|scheme| {
                scheme
                    .sign::<Sha256Digest>(Subject::Notarize {
                        proposal: &proposal,
                    })
                    .expect("signing failed")
            })
            .collect();

        let certificate = schemes[0]
            .assemble(votes, &Sequential)
            .expect("failed to assemble certificate");

        let notarization = Notarization {
            proposal,
            certificate,
        };

        // Report it
        block_on(reporter.report(Activity::Notarization(notarization)));

        // Should be reported
        assert_eq!(mock.count(), 1);
    }

    #[test]
    fn test_attributable_scheme_reports_peer_activities() {
        // Ed25519 (attributable) should report peer per-validator activities
        let mut rng = StdRng::seed_from_u64(42);
        let namespace = b"minimmit_consensus";
        let Fixture {
            schemes, verifier, ..
        } = ed25519::fixture(&mut rng, namespace, 4);

        assert!(
            ed25519::Scheme::is_attributable(),
            "Ed25519 must be attributable"
        );

        let mock = MockReporter::new();
        let strategy = Sequential;
        let mut reporter = AttributableReporter::new(rng, verifier, mock.clone(), strategy, true);

        // Create a peer activity (from validator 1)
        let proposal = create_proposal(0, 1);
        let attestation = schemes[1]
            .sign::<Sha256Digest>(Subject::Notarize {
                proposal: &proposal,
            })
            .expect("signing failed");

        let notarize = Notarize {
            proposal,
            attestation,
        };

        // Report the peer per-validator activity
        block_on(reporter.report(Activity::Notarize(notarize)));

        // Should be reported since scheme is attributable
        assert_eq!(mock.count(), 1);
    }

    #[test]
    fn test_verified_returns_correct_values() {
        // Test that verified() returns correct values for different activity types
        let mut rng = StdRng::seed_from_u64(42);
        let namespace = b"minimmit_consensus";
        let Fixture { schemes, .. } = ed25519::fixture(&mut rng, namespace, 4);

        let proposal = create_proposal(0, 1);

        // Individual vote - should not be pre-verified
        let attestation = schemes[0]
            .sign::<Sha256Digest>(Subject::Notarize {
                proposal: &proposal,
            })
            .expect("signing failed");
        let notarize_activity: Activity<ed25519::Scheme, Sha256Digest> =
            Activity::Notarize(Notarize {
                proposal: proposal.clone(),
                attestation,
            });
        assert!(!notarize_activity.verified());

        // Certificate - should be pre-verified
        let votes: Vec<_> = schemes
            .iter()
            .map(|s| {
                s.sign::<Sha256Digest>(Subject::Notarize {
                    proposal: &proposal,
                })
                .expect("signing failed")
            })
            .collect();
        let certificate = schemes[0].assemble(votes, &Sequential).expect("assemble failed");
        let notarization_activity: Activity<ed25519::Scheme, Sha256Digest> =
            Activity::Notarization(Notarization {
                proposal,
                certificate,
            });
        assert!(notarization_activity.verified());
    }
}
