//! Property tests that exercise only the crate's public API.

use crate::signing::{BatchVerifier, Signature, SigningKey, VerifyingKey};
use arbitrary::{Arbitrary, Unstructured};
use commonware_codec::DecodeExt as _;
use commonware_math::algebra::Random as _;
use commonware_parallel::Sequential;
use commonware_utils::TestRng;
use rand_core::Rng as _;

const SCALAR_ORDER: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

const fn identity_encoding(sign: bool) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[0] = 1;
    if sign {
        bytes[31] = 0x80;
    }
    bytes
}

const fn mostly_ff_encoding(first: u8, sign: bool) -> [u8; 32] {
    let mut bytes = [0xff; 32];
    bytes[0] = first;
    if !sign {
        bytes[31] = 0x7f;
    }
    bytes
}

// These are the canonical and non-canonical encodings of the two points with x = 0. They are
// low order, so a signature with low-order A and R and s = 0 satisfies the cofactored ZIP215
// verification equation for every message.
const LOW_ORDER_ENCODINGS: [[u8; 32]; 6] = [
    identity_encoding(false),
    identity_encoding(true),
    mostly_ff_encoding(0xec, false),
    mostly_ff_encoding(0xec, true),
    mostly_ff_encoding(0xee, false),
    mostly_ff_encoding(0xee, true),
];

// Bias payloads around fixed Ed25519 widths, SHA-512 boundaries, and length-prefix transitions.
const INTERESTING_LENGTHS: [usize; 18] = [
    0, 1, 31, 32, 47, 48, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129, 255, 256,
];
// Cover both sides of the four-coefficient and eight-point SIMD blocks, plus larger compositions.
const INTERESTING_BATCH_SIZES: [usize; 17] =
    [0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64];
// Debug verification is expensive. Keep the unit minifuzz bounded while the fuzz target retains
// all of the larger structural boundaries above.
const MAX_BATCH_SIZE: usize = if cfg!(test) { 17 } else { 64 };
const INTERESTING_BATCH_SIZE_COUNT: usize = if cfg!(test) { 12 } else { 17 };

fn signing_key(seed: u64) -> SigningKey {
    SigningKey::random(TestRng::new(seed))
}

fn decode_verifying_key(bytes: [u8; 32]) -> VerifyingKey {
    VerifyingKey::decode(bytes.as_slice()).expect("a fixed-size key encoding must decode")
}

fn decode_signature(bytes: [u8; 64]) -> Signature {
    Signature::decode(bytes.as_slice()).expect("a fixed-size signature encoding must decode")
}

fn signature_bytes(signature: &Signature) -> [u8; 64] {
    signature
        .as_ref()
        .try_into()
        .expect("a signature is always 64 bytes")
}

fn arbitrary_key_seed(u: &mut Unstructured<'_>) -> arbitrary::Result<u64> {
    Ok(match u.int_in_range(0u8..=5)? {
        0 => 0,
        1 => 1,
        2 => u.arbitrary::<u8>()?.into(),
        3 => u.arbitrary::<u16>()?.into(),
        _ => u.arbitrary()?,
    })
}

fn arbitrary_length(u: &mut Unstructured<'_>) -> arbitrary::Result<usize> {
    if u.ratio(3, 4)? {
        Ok(*u.choose(&INTERESTING_LENGTHS)?)
    } else {
        u.int_in_range(0..=256)
    }
}

fn arbitrary_bytes(u: &mut Unstructured<'_>) -> arbitrary::Result<Vec<u8>> {
    let len = arbitrary_length(u)?;
    Ok(match u.int_in_range(0u8..=4)? {
        0 => vec![0; len],
        1 => vec![u.arbitrary()?; len],
        2 => (0..len).map(|i| i as u8).collect(),
        3 => {
            let mut bytes = vec![0; len];
            TestRng::new(u.arbitrary()?).fill_bytes(&mut bytes);
            bytes
        }
        _ => u.bytes(len)?.to_vec(),
    })
}

fn arbitrary_batch_size(u: &mut Unstructured<'_>) -> arbitrary::Result<usize> {
    if u.ratio(3, 4)? {
        Ok(*u.choose(&INTERESTING_BATCH_SIZES[..INTERESTING_BATCH_SIZE_COUNT])?)
    } else {
        u.int_in_range(0..=MAX_BATCH_SIZE)
    }
}

fn arbitrary_item_index(u: &mut Unstructured<'_>, len: usize) -> arbitrary::Result<usize> {
    let last = len - 1;
    let interesting = [
        0,
        last,
        len / 2,
        3.min(last),
        4.min(last),
        7.min(last),
        8.min(last),
    ];
    Ok(*u.choose(&interesting)?)
}

fn mutate_bytes(bytes: &mut Vec<u8>, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
    if bytes.is_empty() || u.ratio(1, 4)? {
        bytes.push(u.arbitrary()?);
    } else {
        let index = u.int_in_range(0..=bytes.len() - 1)?;
        let bit = u.int_in_range(0u8..=7)?;
        bytes[index] ^= 1u8 << bit;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct EncodedPoint([u8; 32]);

impl Arbitrary<'_> for EncodedPoint {
    fn arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        let bytes = match u.int_in_range(0u8..=9)? {
            0..=3 => *u.choose(&LOW_ORDER_ENCODINGS)?,
            4 => {
                let mut bytes = [0; 32];
                bytes[0] = 2;
                bytes
            }
            5 => [0; 32],
            6 => [0xff; 32],
            7 => signing_key(arbitrary_key_seed(u)?)
                .verifying_key()
                .as_ref()
                .try_into()
                .expect("a verifying key is always 32 bytes"),
            _ => u.arbitrary()?,
        };
        Ok(Self(bytes))
    }
}

#[derive(Clone, Copy, Debug)]
struct EncodedScalar([u8; 32]);

impl Arbitrary<'_> for EncodedScalar {
    fn arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        let bytes = match u.int_in_range(0u8..=7)? {
            0 => [0; 32],
            1 => {
                let mut bytes = [0; 32];
                bytes[0] = 1;
                bytes
            }
            2 => {
                let mut bytes = SCALAR_ORDER;
                bytes[0] -= 1;
                bytes
            }
            3 => SCALAR_ORDER,
            4 => {
                let mut bytes = SCALAR_ORDER;
                bytes[0] += 1;
                bytes
            }
            5 => [0xff; 32],
            _ => u.arbitrary()?,
        };
        Ok(Self(bytes))
    }
}

#[derive(Clone, Debug)]
struct Payload {
    namespace: Vec<u8>,
    message: Vec<u8>,
}

impl Arbitrary<'_> for Payload {
    fn arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            namespace: arbitrary_bytes(u)?,
            message: arbitrary_bytes(u)?,
        })
    }
}

#[derive(Clone, Debug)]
struct Item {
    namespace: Vec<u8>,
    message: Vec<u8>,
    verifying_key: VerifyingKey,
    signature: Signature,
}

impl Item {
    fn signed(u: &mut Unstructured<'_>, seed: Option<u64>) -> arbitrary::Result<Self> {
        let Payload { namespace, message } = u.arbitrary()?;
        let signing_key = signing_key(match seed {
            Some(seed) => seed,
            None => arbitrary_key_seed(u)?,
        });
        let verifying_key = signing_key.verifying_key();
        let signature = signing_key.sign(&namespace, &message);
        Ok(Self {
            namespace,
            message,
            verifying_key,
            signature,
        })
    }

    fn low_order(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        let Payload { namespace, message } = u.arbitrary()?;
        let verifying_key = decode_verifying_key(*u.choose(&LOW_ORDER_ENCODINGS)?);
        let mut signature = [0; 64];
        signature[..32].copy_from_slice(u.choose(&LOW_ORDER_ENCODINGS)?);
        Ok(Self {
            namespace,
            message,
            verifying_key,
            signature: decode_signature(signature),
        })
    }

    fn valid(u: &mut Unstructured<'_>, seed: Option<u64>) -> arbitrary::Result<Self> {
        if seed.is_none() && u.ratio(1, 8)? {
            Self::low_order(u)
        } else {
            Self::signed(u, seed)
        }
    }

    fn raw(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        let Payload { namespace, message } = u.arbitrary()?;
        let EncodedPoint(verifying_key) = u.arbitrary()?;
        let EncodedPoint(r) = u.arbitrary()?;
        let EncodedScalar(s) = u.arbitrary()?;
        let mut signature = [0; 64];
        signature[..32].copy_from_slice(&r);
        signature[32..].copy_from_slice(&s);
        Ok(Self {
            namespace,
            message,
            verifying_key: decode_verifying_key(verifying_key),
            signature: decode_signature(signature),
        })
    }

    fn invalidate(mut self, u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        match u.int_in_range(0u8..=5)? {
            0 => mutate_bytes(&mut self.namespace, u)?,
            1 => mutate_bytes(&mut self.message, u)?,
            2 => {
                let EncodedPoint(bytes) = u.arbitrary()?;
                self.verifying_key = decode_verifying_key(bytes);
            }
            3 => {
                let EncodedPoint(r) = u.arbitrary()?;
                let mut signature = signature_bytes(&self.signature);
                signature[..32].copy_from_slice(&r);
                self.signature = decode_signature(signature);
            }
            4 => {
                let EncodedScalar(s) = u.arbitrary()?;
                let mut signature = signature_bytes(&self.signature);
                signature[32..].copy_from_slice(&s);
                self.signature = decode_signature(signature);
            }
            _ => self.make_scalar_noncanonical(),
        }

        // A targeted mutation can occasionally preserve a signature (for example, by selecting
        // its original key). Fall back to the first non-canonical scalar so this path always
        // exercises rejection.
        if self.verify() {
            self.make_scalar_noncanonical();
        }
        Ok(self)
    }

    fn make_scalar_noncanonical(&mut self) {
        let mut signature = signature_bytes(&self.signature);
        signature[32..].copy_from_slice(&SCALAR_ORDER);
        self.signature = decode_signature(signature);
    }

    fn verify(&self) -> bool {
        self.verifying_key
            .verify(&self.namespace, &self.message, &self.signature)
    }
}

impl Arbitrary<'_> for Item {
    fn arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        match u.int_in_range(0u8..=9)? {
            0..=3 => Self::signed(u, None),
            4 => Self::low_order(u),
            5..=7 => Self::signed(u, None)?.invalidate(u),
            _ => Self::raw(u),
        }
    }
}

#[derive(Debug)]
struct Batch {
    rng_seed: u64,
    items: Vec<Item>,
}

impl Arbitrary<'_> for Batch {
    fn arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        let len = arbitrary_batch_size(u)?;
        let rng_seed = u.arbitrary()?;
        let shared_seed = arbitrary_key_seed(u)?;
        let items = match u.int_in_range(0u8..=5)? {
            0 => (0..len)
                .map(|_| Item::valid(u, None))
                .collect::<arbitrary::Result<_>>()?,
            1 => (0..len)
                .map(|_| Item::signed(u, Some(shared_seed)))
                .collect::<arbitrary::Result<_>>()?,
            2 if len != 0 => vec![Item::valid(u, None)?; len],
            2 => Vec::new(),
            3 => {
                let mut items = (0..len)
                    .map(|_| Item::valid(u, None))
                    .collect::<arbitrary::Result<Vec<_>>>()?;
                if len != 0 {
                    let index = arbitrary_item_index(u, len)?;
                    items[index] = items[index].clone().invalidate(u)?;
                }
                items
            }
            4 => {
                let mut items = (0..len)
                    .map(|_| Item::signed(u, Some(shared_seed)))
                    .collect::<arbitrary::Result<Vec<_>>>()?;
                if len != 0 {
                    let index = arbitrary_item_index(u, len)?;
                    items[index] = items[index].clone().invalidate(u)?;
                }
                items
            }
            _ => (0..len)
                .map(|_| u.arbitrary())
                .collect::<arbitrary::Result<_>>()?,
        };
        Ok(Self { rng_seed, items })
    }
}

impl Batch {
    fn run(self) {
        let expected = self.items.iter().all(Item::verify);
        let mut batch = BatchVerifier::new(self.items.len());
        for item in &self.items {
            batch.add(
                &item.namespace,
                &item.message,
                &item.verifying_key,
                &item.signature,
            );
        }
        let actual = batch.verify(&mut TestRng::new(self.rng_seed), &Sequential);
        assert_eq!(actual, expected, "batch: {self:#?}");
    }
}

/// Fuzzing operations for public API invariants.
pub mod fuzz {
    use super::Batch;
    use arbitrary::{Arbitrary, Unstructured};

    /// A public API fuzzing operation.
    #[derive(Debug, Arbitrary)]
    pub enum Plan {
        /// Check that batch verification agrees with verifying every item individually.
        BatchMatchesIndividual,
    }

    impl Plan {
        /// Runs the fuzzing operation using the remaining input.
        pub fn run(self, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
            match self {
                Self::BatchMatchesIndividual => u.arbitrary::<Batch>()?.run(),
            }
            Ok(())
        }
    }

    #[cfg(test)]
    #[test]
    fn test_fuzz() {
        commonware_invariants::minifuzz::Builder::default()
            .with_seed(0)
            .with_search_limit(32)
            .test(|u| u.arbitrary::<Plan>()?.run(u));
    }
}
