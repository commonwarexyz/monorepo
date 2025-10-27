//! Deterministic test fixtures for `simplex` signing scheme.

use crate::simplex::signing_scheme::{bls12381_multisig, bls12381_threshold, ed25519 as ed_scheme};
use commonware_cryptography::{
    bls12381::{
        dkg::ops,
        primitives::{group, variant::Variant},
    },
    ed25519, PrivateKeyExt, Signer,
};
use commonware_utils::{
    quorum,
    set::{Ordered, OrderedWrapped},
};
use rand::{CryptoRng, RngCore};

/// A test fixture consisting of ed25519 keys and signing schemes for each validator, and a single
/// scheme verifier.
pub type Fixture<S> = (Vec<ed25519::PrivateKey>, Vec<ed25519::PublicKey>, Vec<S>, S);

/// Builds ed25519 identities and matching BLS threshold schemes for tests.
///
/// Returns `(ed25519_private_keys, ed25519_public_keys, bls_threshold_schemes, bls_threshold_scheme_verifier)`
/// where all vectors share the same ordering.
pub fn bls_threshold_fixture<V, R>(
    rng: &mut R,
    n: u32,
) -> Fixture<bls12381_threshold::Scheme<ed25519::PublicKey, V>>
where
    V: Variant,
    R: RngCore + CryptoRng,
{
    assert!(n > 0);
    let t = quorum(n);

    let mut ed25519_keys: Vec<_> = (0..n).map(|_| ed25519::PrivateKey::from_rng(rng)).collect();
    ed25519_keys.sort_by_key(|k| k.public_key());

    let ed25519_public = ed25519_keys
        .iter()
        .map(|k| k.public_key())
        .collect::<Vec<_>>();

    let (polynomial, shares) = ops::generate_shares::<_, V>(rng, None, n, t);

    let participants = Ordered::from(ed25519_public.clone());
    let schemes = shares
        .into_iter()
        .map(|share| bls12381_threshold::Scheme::new(participants.clone(), &polynomial, share))
        .collect();
    let verifier = bls12381_threshold::Scheme::verifier(participants, &polynomial.clone());

    (ed25519_keys, ed25519_public, schemes, verifier)
}

/// Builds ed25519 identities and matching BLS multisig schemes for tests.
///
/// Returns `(ed25519_private_keys, ed25519_public_keys, bls_multisig_schemes, bls_multisig_scheme_verifier)`
/// where all vectors share the same ordering.
pub fn bls_multisig_fixture<V, R>(
    rng: &mut R,
    n: u32,
) -> Fixture<bls12381_multisig::Scheme<ed25519::PublicKey, V>>
where
    V: Variant,
    R: RngCore + CryptoRng,
{
    assert!(n > 0);

    let mut ed25519_keys: Vec<_> = (0..n).map(|_| ed25519::PrivateKey::from_rng(rng)).collect();
    ed25519_keys.sort_by_key(|k| k.public_key());

    let ed25519_public: Vec<_> = ed25519_keys.iter().map(|k| k.public_key()).collect();

    let bls_privates: Vec<_> = (0..n).map(|_| group::Private::from_rand(rng)).collect();
    let bls_public: Vec<_> = bls_privates
        .iter()
        .map(|sk| commonware_cryptography::bls12381::primitives::ops::compute_public::<V>(sk))
        .collect();

    let participants = ed25519_public
        .iter()
        .cloned()
        .zip(bls_public)
        .collect::<OrderedWrapped<_, _>>();

    let schemes: Vec<_> = bls_privates
        .into_iter()
        .map(|sk| bls12381_multisig::Scheme::new(participants.clone(), sk))
        .collect();
    let verifier = bls12381_multisig::Scheme::verifier(participants);

    (ed25519_keys, ed25519_public, schemes, verifier)
}

/// Builds ed25519 identities alongside the ed25519 signing scheme.
///
/// Returns `(ed25519_private_keys, ed25519_public_keys, ed25519_schemes, ed25519_scheme_verifier)`
/// where all vectors share the same ordering.
pub fn ed25519_fixture<R>(rng: &mut R, n: u32) -> Fixture<ed_scheme::Scheme>
where
    R: RngCore + CryptoRng,
{
    assert!(n > 0);

    let mut ed25519_keys: Vec<_> = (0..n).map(|_| ed25519::PrivateKey::from_rng(rng)).collect();
    ed25519_keys.sort_by_key(|k| k.public_key());

    let ed25519_public = ed25519_keys
        .iter()
        .map(|k| k.public_key())
        .collect::<Ordered<_>>();

    let schemes = ed25519_keys
        .iter()
        .cloned()
        .map(|sk| ed_scheme::Scheme::new(ed25519_public.clone(), sk))
        .collect();
    let verifier = ed_scheme::Scheme::verifier(ed25519_public.clone());

    (ed25519_keys, ed25519_public.into(), schemes, verifier)
}
