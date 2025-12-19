//! (Simplex)[commonware_consensus::simplex] signing scheme and
//! [commonware_cryptography::certificate::Provider] implementation.

use crate::orchestrator::EpochTransition;
use commonware_consensus::{simplex, types::Epoch};
use commonware_cryptography::{
    bls12381::{
        dkg,
        primitives::variant::{MinSig, Variant},
    },
    certificate::{self, Scheme},
    ed25519, PublicKey, Signer,
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

/// The BLS12-381 threshold signing scheme used in simplex.
pub type ThresholdScheme<V> = simplex::scheme::bls12381_threshold::Scheme<ed25519::PublicKey, V>;

/// The ED25519 signing scheme used in simplex.
pub type EdScheme = simplex::scheme::ed25519::Scheme;

/// Provides signing schemes for different epochs.
#[derive(Clone)]
pub struct Provider<S: Scheme, C: Signer> {
    schemes: Arc<Mutex<HashMap<Epoch, Arc<S>>>>,
    certificate_verifier: Option<Arc<S>>,
    signer: C,
}

impl<S: Scheme, C: Signer> Provider<S, C> {
    pub fn new(signer: C, certificate_verifier: Option<S>) -> Self {
        Self {
            schemes: Arc::new(Mutex::new(HashMap::new())),
            certificate_verifier: certificate_verifier.map(Arc::new),
            signer,
        }
    }
}

impl<S: Scheme, C: Signer> Provider<S, C> {
    /// Registers a new signing scheme for the given epoch.
    ///
    /// Returns `false` if a scheme was already registered for the epoch.
    pub fn register(&self, epoch: Epoch, scheme: S) -> bool {
        let mut schemes = self.schemes.lock().unwrap();
        schemes.insert(epoch, Arc::new(scheme)).is_none()
    }

    /// Unregisters the signing scheme for the given epoch.
    ///
    /// Returns `false` if no scheme was registered for the epoch.
    pub fn unregister(&self, epoch: &Epoch) -> bool {
        let mut schemes = self.schemes.lock().unwrap();
        schemes.remove(epoch).is_some()
    }
}

impl<S: Scheme, C: Signer> certificate::Provider for Provider<S, C> {
    type Scope = Epoch;
    type Scheme = S;

    fn scoped(&self, epoch: Epoch) -> Option<Arc<S>> {
        let schemes = self.schemes.lock().unwrap();
        schemes.get(&epoch).cloned()
    }

    fn all(&self) -> Option<Arc<S>> {
        self.certificate_verifier.clone()
    }
}

pub trait EpochProvider {
    type Variant: Variant;
    type PublicKey: PublicKey;
    type Scheme: Scheme;

    /// Returns a [Scheme] for the given [EpochTransition].
    fn scheme_for_epoch(
        &self,
        transition: &EpochTransition<Self::Variant, Self::PublicKey>,
    ) -> Self::Scheme;

    /// Creates an epoch-independent certificate verifier from the DKG output.
    ///
    /// Returns `None` for schemes that don't support epoch-independent verification
    /// (Ed25519 during the initial DKG requires the full participant list to verify certificates).
    fn certificate_verifier(
        output: &dkg::Output<Self::Variant, Self::PublicKey>,
    ) -> Option<Self::Scheme>;
}

impl<V: Variant> EpochProvider for Provider<ThresholdScheme<V>, ed25519::PrivateKey> {
    type Variant = V;
    type PublicKey = ed25519::PublicKey;
    type Scheme = ThresholdScheme<V>;

    fn scheme_for_epoch(
        &self,
        transition: &EpochTransition<Self::Variant, Self::PublicKey>,
    ) -> Self::Scheme {
        transition.share.as_ref().map_or_else(
            || {
                ThresholdScheme::verifier(
                    transition.dealers.clone(),
                    transition
                        .poly
                        .clone()
                        .expect("group polynomial must exist"),
                )
            },
            |share| {
                ThresholdScheme::signer(
                    transition.dealers.clone(),
                    transition
                        .poly
                        .clone()
                        .expect("group polynomial must exist"),
                    share.clone(),
                )
                .expect("share must be in dealers")
            },
        )
    }

    fn certificate_verifier(
        output: &dkg::Output<Self::Variant, Self::PublicKey>,
    ) -> Option<Self::Scheme> {
        Some(ThresholdScheme::certificate_verifier(
            *output.public().public(),
        ))
    }
}

impl EpochProvider for Provider<EdScheme, ed25519::PrivateKey> {
    type Variant = MinSig;
    type PublicKey = ed25519::PublicKey;
    type Scheme = EdScheme;

    fn scheme_for_epoch(
        &self,
        transition: &EpochTransition<Self::Variant, Self::PublicKey>,
    ) -> Self::Scheme {
        EdScheme::signer(transition.dealers.clone(), self.signer.clone())
            .unwrap_or_else(|| EdScheme::verifier(transition.dealers.clone()))
    }

    fn certificate_verifier(
        _output: &dkg::Output<Self::Variant, Self::PublicKey>,
    ) -> Option<Self::Scheme> {
        // Ed25519 doesn't support epoch-independent certificate verification
        // since certificates require the full participant list which changes per epoch.
        None
    }
}
