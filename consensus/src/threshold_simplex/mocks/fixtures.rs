use crate::threshold_simplex::new_types::BlsThresholdScheme;
use commonware_cryptography::{
    bls12381::{
        dkg::ops,
        primitives::{poly, variant::Variant},
    },
    ed25519, PrivateKeyExt, Signer,
};
use commonware_utils::quorum;
use rand::{CryptoRng, RngCore};

/// Builds deterministic ed25519 identities and matching BLS threshold schemes for tests.
///
/// Returns `(ed25519_private_keys, bls_threshold_schemes)` where both vectors share
/// the same ordering.
pub fn bls_threshold_fixture<V, R>(
    rng: &mut R,
    n: u32,
) -> (
    Vec<ed25519::PrivateKey>,
    Vec<ed25519::PublicKey>,
    Vec<BlsThresholdScheme<V>>,
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

    let ed25519_public = ed25519_keys.iter().map(|k| k.public_key()).collect();

    let (polynomial, shares) = ops::generate_shares::<_, V>(rng, None, n, t);
    let evaluations = ops::evaluate_all::<V>(&polynomial, n);
    let identity = *poly::public::<V>(&polynomial);

    let schemes = shares
        .into_iter()
        .map(|share| BlsThresholdScheme::new(share.index, evaluations.clone(), identity, share, t))
        .collect();

    (ed25519_keys, ed25519_public, schemes)
}
