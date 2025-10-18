use crate::threshold_simplex::signing_scheme::{
    bls12381_multisig, bls12381_threshold, ed25519 as ed_scheme, Scheme,
};
use commonware_cryptography::{
    bls12381::{
        dkg::ops,
        primitives::{group, variant::Variant},
    },
    ed25519, PrivateKeyExt, Signer,
};
use commonware_utils::quorum;
use rand::{CryptoRng, RngCore};

/// Builds deterministic ed25519 identities and matching BLS threshold schemes for tests.
///
/// Returns `(ed25519_private_keys, ed25519_public_keys, bls_threshold_schemes)` where
/// all vectors share the same ordering.
pub fn bls_threshold_fixture<V, R>(
    rng: &mut R,
    n: u32,
) -> (
    Vec<ed25519::PrivateKey>,
    Vec<ed25519::PublicKey>,
    Vec<bls12381_threshold::Scheme<V>>,
)
where
    V: Variant,
    R: RngCore + CryptoRng,
{
    assert!(n > 0);
    let t = quorum(n);

    let mut ed25519_keys: Vec<_> = (0..n)
        .map(|i| ed25519::PrivateKey::from_seed(i as u64))
        .collect();
    ed25519_keys.sort_by_key(|k| k.public_key());

    let ed25519_public = ed25519_keys
        .iter()
        .map(|k| k.public_key())
        .collect::<Vec<_>>();

    let (polynomial, shares) = ops::generate_shares::<_, V>(rng, None, n, t);

    let schemes = shares
        .into_iter()
        .map(|share| bls12381_threshold::Scheme::new(&ed25519_public, &polynomial, share))
        .collect();

    (ed25519_keys, ed25519_public, schemes)
}

/// Builds deterministic ed25519 identities alongside BLS multisignature schemes for tests.
///
/// Returns `(ed25519_private_keys, ed25519_public_keys, bls_multisig_schemes)` where
/// all vectors share the same ordering.
pub fn bls_multisig_fixture<V, R>(
    rng: &mut R,
    n: u32,
) -> (
    Vec<ed25519::PrivateKey>,
    Vec<ed25519::PublicKey>,
    Vec<bls12381_multisig::Scheme<V>>,
)
where
    V: Variant,
    R: RngCore + CryptoRng,
{
    assert!(n > 0);

    let mut ed25519_keys: Vec<_> = (0..n)
        .map(|i| ed25519::PrivateKey::from_seed(i as u64))
        .collect();
    ed25519_keys.sort_by_key(|k| k.public_key());

    let ed25519_public: Vec<_> = ed25519_keys.iter().map(|k| k.public_key()).collect();

    let bls_privates: Vec<_> = (0..n).map(|_| group::Private::from_rand(rng)).collect();
    let bls_public: Vec<_> = bls_privates
        .iter()
        .map(|sk| commonware_cryptography::bls12381::primitives::ops::compute_public::<V>(sk))
        .collect();

    let schemes: Vec<_> = bls_privates
        .into_iter()
        .map(|sk| bls12381_multisig::Scheme::new(bls_public.clone(), sk))
        .collect();

    debug_assert!(schemes.iter().all(|scheme| scheme.can_sign()));

    (ed25519_keys, ed25519_public, schemes)
}

/// Builds deterministic ed25519 identities alongside the ed25519 signing scheme.
///
/// Returns `(ed25519_private_keys, ed25519_public_keys, ed25519_schemes)` where
/// all vectors share the same ordering.
pub fn ed25519_fixture<R>(
    _rng: &mut R,
    n: u32,
) -> (
    Vec<ed25519::PrivateKey>,
    Vec<ed25519::PublicKey>,
    Vec<ed_scheme::Scheme>,
)
where
    R: RngCore + CryptoRng,
{
    assert!(n > 0);

    let mut ed25519_keys: Vec<_> = (0..n)
        .map(|i| ed25519::PrivateKey::from_seed(i as u64))
        .collect();
    ed25519_keys.sort_by_key(|k| k.public_key());

    let ed25519_public = ed25519_keys
        .iter()
        .map(|k| k.public_key())
        .collect::<Vec<_>>();

    let schemes = ed25519_keys
        .iter()
        .cloned()
        .map(|sk| ed_scheme::Scheme::new(ed25519_public.clone(), sk))
        .collect();

    (ed25519_keys, ed25519_public, schemes)
}
