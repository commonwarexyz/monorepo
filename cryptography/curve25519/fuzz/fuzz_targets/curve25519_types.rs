#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_codec::{Copying, DecodeExt as _, Encode as _, FixedSize};
use commonware_cryptography::{BatchEntry, BatchVerifier, Signer, Verifier};
use commonware_cryptography_curve25519::{
    key_exchange::{PublicKey, SecretKey},
    signing::{Signature, SigningKey, VerifyingKey},
};
use commonware_math::algebra::Random as _;
use commonware_parallel::Sequential;
use commonware_runtime::{Runner, deterministic};
use commonware_utils::{Entropy, FuzzRng};
use libfuzzer_sys::fuzz_target;
use rand_core::Rng as _;
use std::{
    cmp::Ordering,
    collections::{BTreeSet, HashSet},
    fmt::{self, Debug},
    hash::{DefaultHasher, Hash, Hasher},
};

const MIN_SIGNERS: usize = 2;
const MAX_SIGNERS: usize = 4;
/// Namespaces and messages are at most this long.
const MAX_PAYLOAD: usize = 64;
const STREAM_BYTES: usize = 1 << 10;
const SEED_BYTES: usize = 8;
const ENTROPY_BYTES: usize = 32;

/// How a run obtains a signing key.
enum Source {
    /// Drawn from the runtime's RNG.
    Random,
    /// Sampled from the input through the key's `Arbitrary` implementation.
    Sampled(Box<SigningKey>),
}

impl Debug for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Random => f.write_str("Random"),
            Self::Sampled(key) => f
                .debug_tuple("Sampled")
                .field(&key.verifying_key())
                .finish(),
        }
    }
}

#[derive(Debug)]
struct Signing {
    sources: Vec<Source>,
    namespace: Vec<u8>,
    message: Vec<u8>,
    /// A verifying key sampled through its `Arbitrary` implementation, which need not encode a
    /// point.
    stray: VerifyingKey,
    /// A signature sampled through its `Arbitrary` implementation.
    forged: Signature,
}

/// The key the first party exchanges with, relative to the second party's key.
#[derive(Debug)]
enum Other {
    /// The second party's key as transmitted.
    Transmitted,
    /// The second party's key with bit 255 set, which X25519 ignores.
    HighBit,
    /// The first party's own key.
    Reflected,
    /// A low-order coordinate, which X25519 rejects.
    LowOrder([u8; 32]),
    /// A key sampled through its `Arbitrary` implementation.
    Sampled(PublicKey),
}

#[derive(Debug)]
struct FuzzInput {
    signing: Signing,
    other: Other,
    entropy: Entropy,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // libFuzzer starts from inputs of a few bytes and lengthens them slowly, and a run
        // sampled from so few bytes would hold no keys. The input's head therefore seeds a
        // fixed-size stream of [`FuzzRng`] output that the rest of the input overwrites from its
        // start, so every input, even an empty one, samples a whole run, and a byte mutated past
        // the head changes only what is sampled from it.
        let seed = u.bytes(u.len().min(SEED_BYTES))?.to_vec();
        let mut stream = vec![0; STREAM_BYTES.max(u.len())];
        FuzzRng::new(seed).fill_bytes(&mut stream);
        let literal = u.bytes(u.len())?;
        stream[..literal.len()].copy_from_slice(literal);
        let (run, entropy) = stream.split_at(stream.len() - ENTROPY_BYTES);
        let u = &mut Unstructured::new(run);

        Ok(Self {
            signing: signing(u)?,
            other: other(u)?,
            entropy: Unstructured::new(entropy).arbitrary()?,
        })
    }
}

fn payload(u: &mut Unstructured<'_>) -> arbitrary::Result<Vec<u8>> {
    let len = u.int_in_range(0..=MAX_PAYLOAD)?;
    Ok(u.bytes(len)?.to_vec())
}

fn signing(u: &mut Unstructured<'_>) -> arbitrary::Result<Signing> {
    let sources = (0..u.int_in_range(MIN_SIGNERS..=MAX_SIGNERS)?)
        .map(|_| {
            Ok(if u.arbitrary()? {
                Source::Random
            } else {
                Source::Sampled(Box::new(u.arbitrary()?))
            })
        })
        .collect::<arbitrary::Result<_>>()?;
    Ok(Signing {
        sources,
        namespace: payload(u)?,
        message: payload(u)?,
        stray: u.arbitrary()?,
        forged: u.arbitrary()?,
    })
}

/// Samples one of the low-order coordinates that are short to write down: 0 and 1, the
/// non-canonical encodings `p` and `p + 1` of the same two, and `p - 1`.
fn low_order(u: &mut Unstructured<'_>) -> arbitrary::Result<[u8; 32]> {
    let mut bytes = [0; 32];
    match u.int_in_range(0u8..=4)? {
        0 => {}
        1 => bytes[0] = 1,
        offset => {
            bytes = [0xff; 32];
            bytes[31] = 0x7f;
            bytes[0] = 0xec + (offset - 2);
        }
    }
    Ok(bytes)
}

fn other(u: &mut Unstructured<'_>) -> arbitrary::Result<Other> {
    Ok(match u.int_in_range(0u8..=4)? {
        0 => Other::Transmitted,
        1 => Other::HighBit,
        2 => Other::Reflected,
        3 => Other::LowOrder(low_order(u)?),
        _ => Other::Sampled(u.arbitrary()?),
    })
}

/// The canonical encoding of the coordinate X25519 decodes from `bytes`: bit 255 is ignored and
/// the remaining 255-bit value is reduced modulo `p = 2^255 - 19`.
fn coordinate(bytes: &[u8]) -> [u8; 32] {
    let mut coordinate: [u8; 32] = bytes.try_into().expect("a public key is 32 bytes");
    coordinate[31] &= 0x7f;
    // The value is at least `p` exactly when every byte above the first is at its maximum and
    // the first is at least 0xed. It is then below `p + 19`, so only the first byte survives
    // the subtraction.
    if coordinate[31] == 0x7f
        && coordinate[1..31].iter().all(|&byte| byte == 0xff)
        && coordinate[0] >= 0xed
    {
        coordinate = [0; 32];
        coordinate[0] = bytes[0] - 0xed;
    }
    coordinate
}

fn hash(key: &VerifyingKey) -> u64 {
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    hasher.finish()
}

/// Checks that equality, ordering and hashing of verifying keys follow their encodings.
fn check_identity(keys: &[VerifyingKey]) {
    for a in keys {
        for b in keys {
            let order = a.as_ref().cmp(b.as_ref());
            assert_eq!(a.cmp(b), order);
            assert_eq!(a.partial_cmp(b), Some(order));
            assert_eq!(a == b, order == Ordering::Equal);
            if a == b {
                assert_eq!(hash(a), hash(b));
            }
        }
    }
    let encodings: BTreeSet<_> = keys.iter().map(|key| key.encode()).collect();
    assert_eq!(
        keys.iter().cloned().collect::<BTreeSet<_>>().len(),
        encodings.len()
    );
    assert_eq!(
        keys.iter().cloned().collect::<HashSet<_>>().len(),
        encodings.len()
    );
}

fn check_signing(context: &mut deterministic::Context, signing: &Signing) {
    let Signing {
        sources,
        namespace,
        message,
        stray,
        forged,
    } = signing;
    let keys: Vec<_> = sources
        .iter()
        .map(|source| match source {
            Source::Random => SigningKey::random(&mut *context),
            Source::Sampled(key) => (**key).clone(),
        })
        .collect();

    let mut verifying_keys = vec![stray.clone()];
    for key in &keys {
        // The `Signer` trait reaches the inherent methods, and signing is deterministic.
        let verifying_key = key.verifying_key();
        assert_eq!(key.public_key(), verifying_key);
        let signature = key.sign(namespace, message);
        assert_eq!(key.sign(namespace, message), signature);
        assert_eq!(Signer::sign(key, namespace, message), signature);

        // A signing key serializes as its seed, from which the same key is derived.
        let encoded = key.encode();
        assert_eq!(encoded.len(), SigningKey::SIZE);
        let decoded = SigningKey::decode(encoded.clone()).expect("a seed decodes");
        assert_eq!(decoded.encode(), encoded);
        assert_eq!(decoded.verifying_key(), verifying_key);
        assert_eq!(decoded.sign(namespace, message), signature);

        // A verifying key serializes as the bytes it exposes, and a decoded copy, which caches
        // no point, is the same key and verifies the same signatures.
        let encoded = verifying_key.encode();
        assert_eq!(encoded.len(), VerifyingKey::SIZE);
        assert_eq!(encoded.as_ref(), verifying_key.as_ref());
        assert_eq!(&*verifying_key, verifying_key.as_ref());
        let decoded = VerifyingKey::decode(encoded).expect("32 bytes decode");
        assert_eq!(decoded, verifying_key);
        assert_eq!(format!("{decoded}"), format!("{verifying_key:?}"));
        assert!(verifying_key.verify(namespace, message, &signature));
        assert!(decoded.verify(namespace, message, &signature));
        assert!(Verifier::verify(
            &verifying_key,
            namespace,
            message,
            &signature
        ));

        // A signature serializes as the bytes it exposes.
        let encoded = signature.encode();
        assert_eq!(encoded.len(), Signature::SIZE);
        assert_eq!(encoded.as_ref(), signature.as_ref());
        assert_eq!(&*signature, signature.as_ref());
        assert_eq!(
            Signature::decode(encoded).expect("64 bytes decode"),
            signature
        );
        assert_eq!(format!("{signature}"), format!("{signature:?}"));

        // An honest key admits exactly one signature per message, and the signature verifies
        // under exactly one encoding of the key: ZIP215 hashes the encoding as received.
        assert_eq!(
            verifying_key.verify(namespace, message, forged),
            *forged == signature
        );
        assert_eq!(
            stray.verify(namespace, message, &signature),
            *stray == verifying_key
        );

        verifying_keys.push(decoded);
        verifying_keys.push(verifying_key);
    }

    // The batch of every key's signature verifies, is rejected when empty, and fails once a
    // signature is replaced by a forged one.
    let mut batch: Vec<_> = keys
        .iter()
        .map(|key| (key.verifying_key(), key.sign(namespace, message)))
        .collect();
    let mut verify_batch = |batch: &[(VerifyingKey, Signature)]| {
        VerifyingKey::verify_batch(
            &mut *context,
            batch,
            |_, (public_key, signature)| BatchEntry {
                namespace,
                message,
                public_key,
                signature,
            },
            &Sequential,
        )
    };
    assert!(verify_batch(&batch));
    assert!(!verify_batch(&[]));
    let replaced = batch[0].1 != *forged;
    batch[0].1 = forged.clone();
    assert_eq!(verify_batch(&batch), !replaced);

    let encoded = stray.encode();
    assert_eq!(encoded.as_ref(), stray.as_ref());
    verifying_keys.push(VerifyingKey::decode(encoded).expect("32 bytes decode"));
    check_identity(&verifying_keys);
}

fn check_exchange(context: &mut deterministic::Context, kind: &Other) {
    let alice = SecretKey::random(&mut *context);
    let bob = SecretKey::random(&mut *context);
    let (alice_public, bob_public) = (alice.public_key(), bob.public_key());

    // A public key serializes as the bytes it exposes, and a decoded copy is the same key.
    let encoded = bob_public.encode();
    assert_eq!(encoded.len(), PublicKey::SIZE);
    assert_eq!(encoded.as_ref(), bob_public.as_ref());
    let decoded = PublicKey::decode(encoded).expect("32 bytes decode");
    assert_eq!(decoded, bob_public);
    assert_eq!(decoded.as_ref(), bob_public.as_ref());
    assert_eq!(format!("{decoded}"), format!("{bob_public:?}"));

    let other = match kind {
        Other::Transmitted => bob_public.clone(),
        Other::HighBit => {
            let mut bytes = bob_public.as_ref().to_vec();
            bytes[31] |= 0x80;
            PublicKey::decode(Copying(&bytes)).expect("32 bytes decode")
        }
        Other::Reflected => alice_public.clone(),
        Other::LowOrder(bytes) => PublicKey::decode(Copying(bytes)).expect("32 bytes decode"),
        Other::Sampled(key) => key.clone(),
    };

    // Equality compares the coordinates the keys decode to, not the bytes transmitted.
    let same = coordinate(other.as_ref()) == coordinate(bob_public.as_ref());
    assert_eq!(other == bob_public, same);
    assert_eq!(
        other == alice_public,
        coordinate(other.as_ref()) == coordinate(alice_public.as_ref())
    );

    // Honest keys are contributory, every encoding of the same coordinate derives the same
    // secret, and a low-order coordinate derives none.
    let shared = bob
        .exchange(&alice_public)
        .expect("honest key is contributory");
    assert_ne!(shared.as_bytes(), &[0; 32]);
    let alice_shared = alice.exchange(&other);
    if same {
        let alice_shared = alice_shared.expect("honest key is contributory");
        assert_eq!(alice_shared.as_bytes(), shared.as_bytes());
    } else if matches!(kind, Other::LowOrder(_)) {
        assert!(alice_shared.is_none());
    }
}

fn fuzz(input: FuzzInput) {
    let FuzzInput {
        signing,
        other,
        entropy,
    } = input;
    let cfg = deterministic::Config::new().with_rng(FuzzRng::from(entropy));
    let runner = deterministic::Runner::new(cfg);
    runner.start(|mut context| async move {
        check_signing(&mut context, &signing);
        check_exchange(&mut context, &other);
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
