//! Deterministic test fixtures for `simplex` signing scheme.

use crate::simplex::signing_scheme::{bls12381_multisig, bls12381_threshold, ed25519 as ed_scheme};
use commonware_cryptography::{
    bls12381::{
        dkg::ops,
        primitives::{group, variant::Variant},
    },
    ed25519, PrivateKeyExt, Signer,
};
use commonware_utils::quorum;
use rand::{CryptoRng, RngCore};

/// A test fixture consisting of ed25519 keys and signing schemes for each validator, and a single
/// scheme verifier.
pub type Fixture<S> = (Vec<ed25519::PrivateKey>, Vec<ed25519::PublicKey>, Vec<S>, S);

/// Builds ed25519 identities and matching BLS threshold schemes for tests.
///
/// Returns `(ed25519_private_keys, ed25519_public_keys, bls_threshold_schemes, bls_threshold_scheme_verifier)`
/// where all vectors share the same ordering.
pub fn bls_threshold_fixture<V, R>(rng: &mut R, n: u32) -> Fixture<bls12381_threshold::Scheme<V>>
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
    let verifier = bls12381_threshold::Scheme::verifier(&ed25519_public, &polynomial.clone());

    (ed25519_keys, ed25519_public, schemes, verifier)
}

/// Builds ed25519 identities and matching BLS multisig schemes for tests.
///
/// Returns `(ed25519_private_keys, ed25519_public_keys, bls_multisig_schemes, bls_multisig_scheme_verifier)`
/// where all vectors share the same ordering.
pub fn bls_multisig_fixture<V, R>(rng: &mut R, n: u32) -> Fixture<bls12381_multisig::Scheme<V>>
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
    let verifier = bls12381_multisig::Scheme::verifier(bls_public.clone());

    (ed25519_keys, ed25519_public, schemes, verifier)
}

/// Builds ed25519 identities alongside the ed25519 signing scheme.
///
/// Returns `(ed25519_private_keys, ed25519_public_keys, ed25519_schemes, ed25519_scheme_verifier)`
/// where all vectors share the same ordering.
pub fn ed25519_fixture<R>(_rng: &mut R, n: u32) -> Fixture<ed_scheme::Scheme>
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
    let verifier = ed_scheme::Scheme::verifier(ed25519_public.clone());

    (ed25519_keys, ed25519_public, schemes, verifier)
}

pub fn ed25519_fixture_2<R>(_rng: &mut R, n: u32) -> Fixture<ed_scheme::Scheme>
where
    R: RngCore + CryptoRng,
{
    assert!(n > 0);

    let twin_scheme = ed25519::PrivateKey::from_seed(3_u64); // Same seed as node 3
    // For registration, we need a unique public key for the twin
    // We'll use a different seed just for generating a unique validator ID
    let twin_registration_key = ed25519::PrivateKey::from_seed(3_u64 + 0xffffffffffffffed);
    let twin_validator_id = twin_registration_key.public_key();

    let twin_2 = ed25519::PrivateKey::from_seed(3_u64).public_key();

    println!("twin original {:?}", twin_2);

    let mut ed25519_keys: Vec<_> = (0..n-1)
        .map(|i| ed25519::PrivateKey::from_seed(i as u64))
        .collect();
    ed25519_keys.push(twin_scheme);
    ed25519_keys.sort_by_key(|k| k.public_key());


    let mut ed25519_public = ed25519_keys
        .iter()
        .map(|k| k.public_key())
        .collect::<Vec<_>>();

    let index = ed25519_public.iter().position(|pk| *pk == twin_2).unwrap();
    // replace one of them with the twin_validator_id
    ed25519_public[index] = twin_validator_id;

    let schemes = ed25519_keys
        .iter()
        .cloned()
        .map(|sk| ed_scheme::Scheme::new(ed25519_public.clone(), sk))
        .collect();
    let verifier = ed_scheme::Scheme::verifier(ed25519_public.clone());

    //ed25519_public[index] = twin_validator_id;

    println!("private keys {:?}", ed25519_keys);
    println!("public keys {:?}", ed25519_public);
    println!("schemes {:?}", schemes);

    (ed25519_keys, ed25519_public, schemes, verifier)
}

pub fn ed25519_fixture_twins<R>(_rng: &mut R, n: u32) -> Fixture<ed_scheme::Scheme>
where
    R: RngCore + CryptoRng,
{
    assert_eq!(n, 4, "twins test requires exactly 4 nodes");

    // Register participants with Twins approach
    // Nodes 0,1,2,3 have normal keys, node 4 is a twin of node 3
    let mut schemes = Vec::new();
    let mut validators = Vec::new();
    let mut ed25519_keys = Vec::new();

    // Create nodes 0,1,2,3 normally
    for i in 0..4 {
        let scheme = ed25519::PrivateKey::from_seed(i as u64);
        let pk = scheme.public_key();
        ed25519_keys.push(scheme.clone());
        validators.push(pk);
        println!("node {}: private key {:?} public key {:?}", i, scheme, scheme.public_key());
    }

    // Create node 4 as a twin of node 3
    // It uses the same private key as node 3 but needs a different public key for registration
    let twin_scheme = ed25519::PrivateKey::from_seed(3_u64); // Same seed as node 3
    // For registration, we need a unique public key for the twin
    // We'll use a different seed just for generating a unique validator ID
    let twin_registration_key = ed25519::PrivateKey::from_seed(3_u64 + 0xffffffffffffffed);
    let twin_validator_id = twin_registration_key.public_key();

    println!("private key for seed 3 twin validator id: {:?}", ed25519::PrivateKey::from_seed(3_u64));
    println!("pub key for seed 3 twin validator id: {:?}", ed25519::PrivateKey::from_seed(3_u64).public_key());
    println!("twin validator private key: {:?}", twin_scheme);
    println!("twin validator public key: {:?}", twin_registration_key.public_key());
    println!("---");

    ed25519_keys.push(twin_scheme.clone());
    //validators.sort();
    validators.push(twin_validator_id);

    assert_eq!(ed25519_keys[3], ed25519_keys[4], "twins private keys are the same");

    // The consensus participants should be the 4 original nodes (not including twin ID)
    // Get the original public keys for nodes 0,1,2,3
    let mut ed25519_public = Vec::new();
    for i in 0..3 {
        ed25519_public.push(ed25519::PrivateKey::from_seed(i as u64).public_key());
    }
    ed25519_public.sort();
    ed25519_public.push(ed25519::PrivateKey::from_seed(3_u64).public_key());
    schemes.push(ed_scheme::Scheme::new(
        ed25519_public,
        ed25519::PrivateKey::from_seed(0)
    ));

    let mut ed25519_public = Vec::new();
    for i in 0..3 {
        ed25519_public.push(ed25519::PrivateKey::from_seed(i as u64).public_key());
    }
    ed25519_public.sort();
    ed25519_public.push(ed25519::PrivateKey::from_seed(3_u64 + 0xffffffffffffffed).public_key());
    schemes.push(ed_scheme::Scheme::new(
        ed25519_public,
        ed25519::PrivateKey::from_seed(1)
    ));

    let mut ed25519_public = Vec::new();
    for i in 0..3 {
        ed25519_public.push(ed25519::PrivateKey::from_seed(i as u64).public_key());
    }
    ed25519_public.sort();
    ed25519_public.push(ed25519::PrivateKey::from_seed(3_u64).public_key());
    schemes.push(ed_scheme::Scheme::new(
        ed25519_public,
        ed25519::PrivateKey::from_seed(2)
    ));

    let mut ed25519_public = Vec::new();
    for i in 0..3 {
        ed25519_public.push(ed25519::PrivateKey::from_seed(i as u64).public_key());
    }
    ed25519_public.sort();
    ed25519_public.push(ed25519::PrivateKey::from_seed(3_u64 + 0xffffffffffffffed).public_key());
    schemes.push(ed_scheme::Scheme::new(
        ed25519_public,
        ed25519::PrivateKey::from_seed(3)
    ));

    let mut ed25519_public = Vec::new();
    for i in 0..3 {
        ed25519_public.push(ed25519::PrivateKey::from_seed(i as u64).public_key());
    }
    ed25519_public.sort();
    ed25519_public.push(ed25519::PrivateKey::from_seed(3_u64 + 0xffffffffffffffed).public_key());
    schemes.push(ed_scheme::Scheme::new(
        ed25519_public,
        ed25519::PrivateKey::from_seed(3)
    ));


    //Create schemes for all 5 nodes
    //for i in 0..4 {
    //    schemes.push(ed_scheme::Scheme::new(ed25519_public.clone(), ed25519::PrivateKey::from_seed(i as u64)));
    //}



    
    // Twin uses new_twins constructor to sign as node 3


    println!("schemes {:?}", schemes);

    let mut ed25519_public = Vec::new();
    for i in 0..4 {
        ed25519_public.push(ed25519::PrivateKey::from_seed(i as u64).public_key());
    }

    let verifier = ed_scheme::Scheme::verifier(ed25519_public.clone());

    (ed25519_keys, validators, schemes, verifier)
}
