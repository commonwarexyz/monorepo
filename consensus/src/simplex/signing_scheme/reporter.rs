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
            && !activity.verify(&mut self.rng, &self.scheme, &self.namespace)
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
