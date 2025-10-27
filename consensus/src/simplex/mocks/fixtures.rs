//! Deterministic test fixtures for `simplex` signing scheme.

use crate::simplex::signing_scheme::{bls12381_multisig, bls12381_threshold, ed25519 as ed_scheme};
use commonware_cryptography::{
    bls12381::{
        dkg::ops,
        primitives::{group, variant::Variant},
    },
    ed25519, PrivateKeyExt, Signer,
};
use commonware_utils::{quorum, set::OrderedAssociated};
use rand::{CryptoRng, RngCore};

/// A test fixture consisting of ed25519 keys and signing schemes for each validator, and a single
/// scheme verifier.
pub type Fixture<S> = (Vec<ed25519::PrivateKey>, Vec<ed25519::PublicKey>, Vec<S>, S);

/// Generates ed25519 participants.
fn ed25519_participants<R>(
    rng: &mut R,
    n: u32,
) -> OrderedAssociated<ed25519::PublicKey, ed25519::PrivateKey>
where
    R: RngCore + CryptoRng,
{
    (0..n)
        .map(|_| {
            let private_key = ed25519::PrivateKey::from_rng(rng);
            let public_key = private_key.public_key();
            (public_key, private_key)
        })
        .collect()
}

/// Builds ed25519 identities alongside the ed25519 signing scheme.
///
/// Returns `(ed25519_private_keys, ed25519_public_keys, ed25519_schemes, ed25519_scheme_verifier)`
/// where all vectors share the same ordering.
pub fn ed25519<R>(rng: &mut R, n: u32) -> Fixture<ed_scheme::Scheme>
where
    R: RngCore + CryptoRng,
{
    assert!(n > 0);

    let ed25519_associated = ed25519_participants(rng, n);
    let ed25519_public = ed25519_associated.keys().clone();
    let ed25519_keys: Vec<_> = ed25519_associated.into_iter().map(|(_, sk)| sk).collect();

    let schemes = ed25519_keys
        .iter()
        .cloned()
        .map(|sk| ed_scheme::Scheme::new(ed25519_public.clone(), sk))
        .collect();
    let verifier = ed_scheme::Scheme::verifier(ed25519_public.clone());

    (ed25519_keys, ed25519_public.into(), schemes, verifier)
}

/// Builds ed25519 identities and matching BLS multisig schemes for tests.
///
/// Returns `(ed25519_private_keys, ed25519_public_keys, bls_multisig_schemes, bls_multisig_scheme_verifier)`
/// where all vectors share the same ordering.
pub fn bls12381_multisig<V, R>(
    rng: &mut R,
    n: u32,
) -> Fixture<bls12381_multisig::Scheme<ed25519::PublicKey, V>>
where
    V: Variant,
    R: RngCore + CryptoRng,
{
    assert!(n > 0);

    let ed25519_associated = ed25519_participants(rng, n);
    let ordered_public_keys = ed25519_associated.keys().clone();
    let ed25519_public: Vec<_> = ordered_public_keys.clone().into();
    let ed25519_keys: Vec<_> = ed25519_associated.into_iter().map(|(_, sk)| sk).collect();

    let bls_privates: Vec<_> = (0..n).map(|_| group::Private::from_rand(rng)).collect();
    let bls_public: Vec<_> = bls_privates
        .iter()
        .map(|sk| commonware_cryptography::bls12381::primitives::ops::compute_public::<V>(sk))
        .collect();

    let participants = ordered_public_keys
        .into_iter()
        .zip(bls_public)
        .collect::<OrderedAssociated<_, _>>();

    let schemes: Vec<_> = bls_privates
        .into_iter()
        .map(|sk| bls12381_multisig::Scheme::new(participants.clone(), sk))
        .collect();
    let verifier = bls12381_multisig::Scheme::verifier(participants);

    (ed25519_keys, ed25519_public, schemes, verifier)
}

/// Builds ed25519 identities and matching BLS threshold schemes for tests.
///
/// Returns `(ed25519_private_keys, ed25519_public_keys, bls_threshold_schemes, bls_threshold_scheme_verifier)`
/// where all vectors share the same ordering.
pub fn bls12381_threshold<V, R>(
    rng: &mut R,
    n: u32,
) -> Fixture<bls12381_threshold::Scheme<ed25519::PublicKey, V>>
where
    V: Variant,
    R: RngCore + CryptoRng,
{
    assert!(n > 0);
    let t = quorum(n);

    let ed25519_associated = ed25519_participants(rng, n);
    let participants = ed25519_associated.keys().clone();
    let ed25519_public: Vec<_> = participants.clone().into();
    let ed25519_keys: Vec<_> = ed25519_associated.into_iter().map(|(_, sk)| sk).collect();

    let (polynomial, shares) = ops::generate_shares::<_, V>(rng, None, n, t);

    let schemes = shares
        .into_iter()
        .map(|share| bls12381_threshold::Scheme::new(participants.clone(), &polynomial, share))
        .collect();
    let verifier = bls12381_threshold::Scheme::verifier(participants, &polynomial.clone());

    (ed25519_keys, ed25519_public, schemes, verifier)
}
