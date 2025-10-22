//! [`Reporter`] wrapper for scheme-dependent activity filtering and verification.
//!
//! # Overview
//!
//! The `AttributableReporter` provides a composable wrapper around consensus reporters
//! that automatically filters and verifies activities based on signing scheme properties.
//! This ensures that:
//!
//! 1. **Peer activities are cryptographically verified** before being reported
//! 2. **Non-attributable schemes** suppress per-validator activities from peers to prevent
//!    signature forgery attacks
//! 3. **Own activities** are always reported regardless of scheme attributability
//! 4. **Certificates** are always reported as they contain valid quorum proofs
//!
//! # Security Rationale
//!
//! With threshold signature schemes (like BLS threshold), any `t` valid partial signatures
//! can be used to forge a partial signature for any participant. If per-validator activities
//! were exposed for such schemes, adversaries could fabricate Byzantine fault evidence.
//! This wrapper prevents that attack by suppressing peer activities for non-attributable schemes.
//!
//! # Observer Support
//!
//! The wrapper supports both validators and observers:
//! - **Validators** (`me = Some(public_key)`): Distinguish own vs peer activities
//! - **Observers** (`me = None`): Treat all activities as peer activities, useful for monitoring

use crate::{
    simplex::{
        signing_scheme::Scheme,
        types::{Activity, Attributable},
    },
    Reporter,
};
use commonware_cryptography::{Digest, PublicKey};
use commonware_utils::set::Set;
use rand::{CryptoRng, Rng};

/// Reporter wrapper that filters and verifies activities based on scheme attributability.
///
/// This wrapper provides scheme-aware activity filtering with automatic verification of peer
/// activities. It prevents signature forgery attacks on non-attributable schemes while ensuring
/// all activities are cryptographically valid before reporting.
#[derive(Clone)]
pub struct AttributableReporter<
    E: Clone + Rng + CryptoRng + Send + 'static,
    P: PublicKey,
    S: Scheme,
    D: Digest,
    R: Reporter<Activity = Activity<S, D>>,
> {
    /// RNG for certificate verification
    rng: E,
    /// Our validator identity (`None` for observers/monitors)
    me: Option<P>,
    /// All participants in the consensus
    participants: Set<P>,
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
        P: PublicKey,
        S: Scheme,
        D: Digest,
        R: Reporter<Activity = Activity<S, D>>,
    > AttributableReporter<E, P, S, D, R>
{
    /// Creates a new `AttributableReporter` that wraps an inner reporter.
    pub fn new(
        rng: E,
        me: Option<P>,
        participants: Set<P>,
        scheme: S,
        namespace: Vec<u8>,
        reporter: R,
        verify: bool,
    ) -> Self {
        Self {
            rng,
            me,
            participants,
            scheme,
            namespace,
            reporter,
            verify,
        }
    }
}

impl<
        E: Clone + Rng + CryptoRng + Send + 'static,
        P: PublicKey,
        S: Scheme,
        D: Digest,
        R: Reporter<Activity = Activity<S, D>>,
    > Reporter for AttributableReporter<E, P, S, D, R>
{
    type Activity = Activity<S, D>;

    async fn report(&mut self, activity: Self::Activity) {
        // Determine if the activity is from our local validator
        let is_local = if let Some(ref me) = self.me {
            // Extract signer from activity
            let signer = match &activity {
                Activity::Notarize(n) => Some(n.signer()),
                Activity::Nullify(n) => Some(n.signer()),
                Activity::Finalize(f) => Some(f.signer()),
                Activity::ConflictingNotarize(c) => Some(c.signer()),
                Activity::ConflictingFinalize(c) => Some(c.signer()),
                Activity::NullifyFinalize(c) => Some(c.signer()),
                // Certificates don't have direct attribution
                Activity::Notarization(_)
                | Activity::Nullification(_)
                | Activity::Finalization(_) => None,
            };

            // Check if the signer is us
            signer
                .and_then(|s| self.participants.get(s as usize))
                .map(|s| s == me)
                .unwrap_or(false)
        } else {
            // Observers have no local identity
            false
        };

        // Verify peer activities if verification is enabled and it's not our local activity
        if self.verify
            && !is_local
            && !(activity.verified()
                || activity.verify(&mut self.rng, &self.scheme, &self.namespace))
        {
            // Drop unverified peer activity
            return;
        }

        // Filter based on scheme attributability
        if !self.scheme.is_attributable() && !is_local {
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
                // Always report certificates
                Activity::Notarization(_)
                | Activity::Nullification(_)
                | Activity::Finalization(_) => {}
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
            mocks::fixtures::{bls_threshold_fixture, ed25519_fixture},
            signing_scheme::{ed25519, Scheme},
            types::{Notarization, Notarize, Proposal, VoteContext},
        },
        types::Round,
    };
    use commonware_cryptography::{
        bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest, Hasher, Sha256,
        Signer,
    };
    use commonware_utils::set::Set;
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
        let data = format!("proposal-{}-{}", epoch, view);
        let hash = Sha256::hash(data.as_bytes());
        Proposal::new(Round::new(epoch, view), view, hash)
    }

    #[test]
    fn test_local_activity_always_reported() {
        // Local activities should always be reported, even for non-attributable schemes
        let mut rng = StdRng::seed_from_u64(42);
        let (keys, public_keys, schemes, _verifier) =
            bls_threshold_fixture::<MinPk, _>(&mut rng, 4);
        let participants = Set::from(public_keys.clone());

        let scheme = schemes[0].clone();
        assert!(
            !scheme.is_attributable(),
            "BLS threshold must be non-attributable"
        );

        let mock = MockReporter::new();
        let rng = StdRng::seed_from_u64(43);

        let mut reporter = AttributableReporter::new(
            rng,
            Some(keys[0].public_key()),
            participants,
            scheme.clone(),
            NAMESPACE.to_vec(),
            mock.clone(),
            true,
        );

        let proposal = create_proposal(0, 1);
        let vote = scheme
            .sign_vote::<Sha256Digest>(
                NAMESPACE,
                VoteContext::Notarize {
                    proposal: &proposal,
                },
            )
            .expect("signing failed");
        let notarize = Notarize { proposal, vote };

        block_on(reporter.report(Activity::Notarize(notarize)));

        // Should be reported even though scheme is non-attributable (it's our own activity)
        assert_eq!(mock.count(), 1);
        let reported = mock.reported();
        assert!(matches!(reported[0], Activity::Notarize(_)));
    }

    #[test]
    fn test_invalid_peer_activity_dropped() {
        // Invalid peer activities should be dropped when verification is enabled
        let mut rng = StdRng::seed_from_u64(42);
        let (keys, public_keys, _schemes, our_scheme) = ed25519_fixture(&mut rng, 4);
        let participants = Set::from(public_keys.clone());

        assert!(our_scheme.is_attributable(), "Ed25519 must be attributable");

        let mock = MockReporter::new();
        let rng = StdRng::seed_from_u64(42);

        let mut reporter = AttributableReporter::new(
            rng,
            Some(keys[0].public_key()),
            participants,
            our_scheme,
            NAMESPACE.to_vec(),
            mock.clone(),
            true,
        );

        // Create an invalid activity (wrong namespace)
        let proposal = create_proposal(0, 1);
        let peer_scheme = ed25519::Scheme::new(public_keys.clone(), keys[1].clone());
        let vote = peer_scheme
            .sign_vote::<Sha256Digest>(
                &[], // Invalid namespace
                VoteContext::Notarize {
                    proposal: &proposal,
                },
            )
            .expect("signing failed");
        let notarize = Notarize { proposal, vote };

        // Report it
        block_on(reporter.report(Activity::Notarize(notarize)));

        // Should be dropped (not reported)
        assert_eq!(mock.count(), 0);
    }

    #[test]
    fn test_skip_verification() {
        // When verification is disabled, invalid activities pass through
        let mut rng = StdRng::seed_from_u64(42);
        let (keys, public_keys, _schemes, our_scheme) = ed25519_fixture(&mut rng, 4);
        let participants = Set::from(public_keys.clone());

        assert!(our_scheme.is_attributable(), "Ed25519 must be attributable");

        let mock = MockReporter::new();
        let rng = StdRng::seed_from_u64(42);

        let mut reporter = AttributableReporter::new(
            rng,
            Some(keys[0].public_key()),
            participants,
            our_scheme,
            NAMESPACE.to_vec(),
            mock.clone(),
            false, // Disable verification
        );

        // Create an invalid activity (wrong namespace)
        let proposal = create_proposal(0, 1);
        let peer_scheme = ed25519::Scheme::new(public_keys.clone(), keys[1].clone());
        let vote = peer_scheme
            .sign_vote::<Sha256Digest>(
                &[], // Invalid namespace
                VoteContext::Notarize {
                    proposal: &proposal,
                },
            )
            .expect("signing failed");
        let notarize = Notarize { proposal, vote };

        // Report it
        block_on(reporter.report(Activity::Notarize(notarize)));

        // Should be reported even though it's invalid (verification disabled)
        assert_eq!(mock.count(), 1);
        let reported = mock.reported();
        assert!(matches!(reported[0], Activity::Notarize(_)));
    }

    #[test]
    fn test_certificates_always_reported() {
        // Certificates should always be reported, even for non-attributable schemes
        let mut rng = StdRng::seed_from_u64(42);
        let (keys, public_keys, schemes, _verifier) =
            bls_threshold_fixture::<MinPk, _>(&mut rng, 4);
        let participants = Set::from(public_keys.clone());

        let scheme = schemes[0].clone();
        assert!(
            !scheme.is_attributable(),
            "BLS threshold must be non-attributable"
        );

        let mock = MockReporter::new();
        let rng = StdRng::seed_from_u64(43);

        let mut reporter = AttributableReporter::new(
            rng,
            Some(keys[0].public_key()),
            participants,
            scheme.clone(),
            NAMESPACE.to_vec(),
            mock.clone(),
            true,
        );

        // Create a certificate from multiple validators
        let proposal = create_proposal(0, 1);
        let votes: Vec<_> = schemes
            .iter()
            .map(|scheme| {
                scheme
                    .sign_vote::<Sha256Digest>(
                        NAMESPACE,
                        VoteContext::Notarize {
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
        // Non-attributable schemes (like BLS threshold) MUST filter peer per-validator activities
        let mut rng = StdRng::seed_from_u64(42);
        let (keys, public_keys, schemes, our_scheme) =
            bls_threshold_fixture::<MinPk, _>(&mut rng, 4);
        let participants = Set::from(public_keys.clone());

        assert!(
            !our_scheme.is_attributable(),
            "BLS threshold must be non-attributable"
        );

        let mock = MockReporter::new();
        let rng = StdRng::seed_from_u64(43);

        let mut reporter = AttributableReporter::new(
            rng,
            Some(keys[0].public_key()),
            participants,
            our_scheme,
            NAMESPACE.to_vec(),
            mock.clone(),
            true,
        );

        // Create peer activity (from validator 1)
        let proposal = create_proposal(0, 1);
        let vote = schemes[1]
            .sign_vote::<Sha256Digest>(
                NAMESPACE,
                VoteContext::Notarize {
                    proposal: &proposal,
                },
            )
            .expect("signing failed");

        let notarize = Notarize { proposal, vote };

        // Report peer per-validator activity
        block_on(reporter.report(Activity::Notarize(notarize)));

        // MUST be filtered (not reported)
        assert_eq!(mock.count(), 0);
    }

    #[test]
    fn test_attributable_scheme_reports_peer_activities() {
        // Ed25519 (attributable) should report peer per-validator activities
        let mut rng = StdRng::seed_from_u64(42);
        let (keys, public_keys, _schemes, our_scheme) = ed25519_fixture(&mut rng, 4);
        let participants = Set::from(public_keys.clone());

        assert!(our_scheme.is_attributable(), "Ed25519 must be attributable");

        let mock = MockReporter::new();
        let rng = StdRng::seed_from_u64(42);

        let mut reporter = AttributableReporter::new(
            rng,
            Some(keys[0].public_key()),
            participants,
            our_scheme,
            NAMESPACE.to_vec(),
            mock.clone(),
            true,
        );

        // Create a peer activity (from validator 1)
        let proposal = create_proposal(0, 1);
        let peer_scheme = ed25519::Scheme::new(public_keys.clone(), keys[1].clone());
        let vote = peer_scheme
            .sign_vote::<Sha256Digest>(
                NAMESPACE,
                VoteContext::Notarize {
                    proposal: &proposal,
                },
            )
            .expect("signing failed");

        let notarize = Notarize { proposal, vote };

        // Report the peer per-validator activity
        block_on(reporter.report(Activity::Notarize(notarize)));

        // Should be REPORTED since scheme is attributable
        assert_eq!(mock.count(), 1);
        let reported = mock.reported();
        assert!(matches!(reported[0], Activity::Notarize(_)));
    }

    #[test]
    fn test_observer_treats_all_as_peer() {
        // Observers (me = None) with non-attributable schemes filter all per-validator activities
        let mut rng = StdRng::seed_from_u64(42);
        let (_keys, public_keys, schemes, verifier) =
            bls_threshold_fixture::<MinPk, _>(&mut rng, 4);
        let participants = Set::from(public_keys.clone());

        assert!(
            !verifier.is_attributable(),
            "BLS threshold must be non-attributable"
        );

        let mock = MockReporter::new();
        let rng = StdRng::seed_from_u64(43);

        let mut reporter = AttributableReporter::new(
            rng,
            None, // Observer has no identity
            participants,
            verifier,
            NAMESPACE.to_vec(),
            mock.clone(),
            true,
        );

        // Create a valid activity from validator 0
        let proposal = create_proposal(0, 1);
        let vote = schemes[0]
            .sign_vote::<Sha256Digest>(
                NAMESPACE,
                VoteContext::Notarize {
                    proposal: &proposal,
                },
            )
            .expect("signing failed");
        let notarize = Notarize { proposal, vote };

        // Report it
        block_on(reporter.report(Activity::Notarize(notarize)));

        // Should be filtered (observer treats all as peer + non-attributable scheme)
        assert_eq!(mock.count(), 0);
    }
}
