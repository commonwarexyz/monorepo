#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_codec::{
    Copying, DecodeExt as _, EncodeFixed as _, Error, FixedSize, ReadExt as _, Write as _,
};
use commonware_cryptography::{CoreKeccak256, Hasher, Keccak256, keccak256::Digest};
use commonware_math::algebra::Random;
use commonware_parallel::Sequential;
use commonware_runtime::{Runner, deterministic};
use commonware_utils::{Array, Entropy, FuzzRng};
use libfuzzer_sys::fuzz_target;
use rand_core::Rng as _;
use sha3::Digest as _;
use std::{
    cmp::Ordering,
    collections::{HashSet, hash_map::DefaultHasher},
    hash::{Hash, Hasher as _},
};
use zeroize::Zeroize as _;

/// Bytes of a Keccak-256 digest.
const DIGEST_LEN: usize = 32;

/// Bytes Keccak-256 absorbs per permutation: the 1600-bit state less twice the output.
const RATE: usize = 136;

/// Most rate blocks a sampled length spans, enough for a message to cross a block boundary in
/// the middle of a chunk and to end exactly on one.
const MAX_BLOCKS: usize = 3;

/// Longest message, one byte past the last multiple of the rate.
const MAX_LEN: usize = MAX_BLOCKS * RATE + 1;

/// Most messages one hasher streams in a row, which also bounds a batch.
const MAX_MESSAGES: usize = 4;

/// Most cuts that split a message into chunks. Cuts may repeat or sit at either end, so some
/// chunks are empty.
const MAX_CUTS: usize = 8;

/// Most operations a plan applies. Operations share only the digests compared at the end.
const MAX_OPS: usize = 8;

/// Most bytes a decode reads past the encoded size.
const MAX_EXTRA: usize = 8;

/// `Digest::arbitrary` reads a length of at most this many bytes, then hashes a message of at
/// most [`MAX_ARBITRARY_MESSAGE`] bytes.
const MAX_ARBITRARY_LEN_BYTES: usize = 2;
const MAX_ARBITRARY_MESSAGE: usize = 256;

/// Bytes of the stream a plan is sampled from, more than the largest plan, of the input's head
/// that seeds the stream, and of the stream's tail that seeds the runtime.
const STREAM_BYTES: usize = 1 << 14;
const SEED_BYTES: usize = 8;
const ENTROPY_BYTES: usize = 32;

/// Keccak-256 digests, with the original Keccak padding Ethereum uses rather than SHA3's, of
/// the empty message, "abc", and 0xa3 repeated one byte short of, exactly, and one byte past
/// the rate, across two blocks, and to exactly two blocks. The 0xa3 digests are OpenSSL's
/// KECCAK-256.
const KNOWN: [(&[u8], &str); 7] = [
    (
        b"",
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
    ),
    (
        b"abc",
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
    ),
    (
        &[0xa3; 135],
        "3d28d08c3dacab77392064a939f3e7f8d03f2e02e2c664ac08a05f63ac652626",
    ),
    (
        &[0xa3; 136],
        "b82d89d96e5575d11a9e1f4cabb2a45e60899e69a19a724cd796bdcf13511018",
    ),
    (
        &[0xa3; 137],
        "ec8008a74e50bc7d6b22c3ad85402bf10e6d4449f3c8618e36c461b8a44eeafb",
    ),
    (
        &[0xa3; 200],
        "3a57666b048777f2c953dc4456f45a2588e1cb6f2da760122d530ac2ce607d4a",
    ),
    (
        &[0xa3; 272],
        "a657381e5615f539cac71f13c74473a5e77eaa2bd8348422dcac221c8f13da94",
    ),
];

const EMPTY: Digest = <Digest as commonware_cryptography::Digest>::EMPTY;

// The public backend alias names the type the differential oracle calls directly.
const _: fn(CoreKeccak256) -> sha3::Keccak256 = core::convert::identity;

/// A message and the sorted cuts that split it into the chunks it is streamed in.
#[derive(Debug)]
struct Message {
    data: Vec<u8>,
    cuts: Vec<usize>,
}

impl<'a> Arbitrary<'a> for Message {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let len = boundary(u, MAX_LEN)?;
        Ok(Self {
            data: u.bytes(len)?.to_vec(),
            cuts: cuts(u, len)?,
        })
    }
}

/// A known-answer vector and the sorted cuts that split its message.
#[derive(Debug)]
struct Known {
    index: usize,
    cuts: Vec<usize>,
}

impl<'a> Arbitrary<'a> for Known {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let index = u.int_in_range(0..=KNOWN.len() - 1)?;
        Ok(Self {
            index,
            cuts: cuts(u, KNOWN[index].0.len())?,
        })
    }
}

/// How many bytes a decode reads relative to the encoded size.
#[derive(Arbitrary, Debug)]
enum Len {
    Short(u8),
    Exact,
    Long(u8),
}

#[derive(Arbitrary, Debug)]
enum Op {
    /// Streams messages through one hasher, finalizing after each.
    Hash(#[arbitrary(with = messages)] Vec<Message>),
    /// Streams a known-answer vector through one hasher twice.
    Known(Known),
    /// Compares a digest with a copy that differs in at most one byte.
    Order {
        bytes: [u8; DIGEST_LEN],
        edit: Option<(u8, u8)>,
    },
    /// Decodes a prefix of `bytes` shorter than, equal to, or longer than a digest.
    Decode {
        bytes: [u8; DIGEST_LEN + MAX_EXTRA],
        len: Len,
    },
    /// Samples a digest from the bytes with its `Arbitrary` implementation.
    Sample(#[arbitrary(with = sample)] Vec<u8>),
    /// Draws a digest from the runtime.
    Random,
}

/// Returns a length up to `max`: empty, next to a multiple of the rate, or anywhere.
fn boundary(u: &mut Unstructured<'_>, max: usize) -> arbitrary::Result<usize> {
    let len = match u.int_in_range(0..=3)? {
        0 => 0,
        1 | 2 => RATE * u.int_in_range(1..=MAX_BLOCKS)? + u.int_in_range(0..=2)? - 1,
        _ => u.int_in_range(0..=max)?,
    };
    Ok(len.min(max))
}

/// Returns sorted cuts into a message of `len` bytes.
fn cuts(u: &mut Unstructured<'_>, len: usize) -> arbitrary::Result<Vec<usize>> {
    let mut cuts = (0..u.int_in_range(0..=MAX_CUTS)?)
        .map(|_| boundary(u, len))
        .collect::<arbitrary::Result<Vec<_>>>()?;
    cuts.sort_unstable();
    Ok(cuts)
}

fn messages(u: &mut Unstructured<'_>) -> arbitrary::Result<Vec<Message>> {
    (0..u.int_in_range(1..=MAX_MESSAGES)?)
        .map(|_| u.arbitrary())
        .collect()
}

/// Returns bytes for `Digest::arbitrary`, which runs out of them only below its longest read.
fn sample(u: &mut Unstructured<'_>) -> arbitrary::Result<Vec<u8>> {
    let len = u.int_in_range(0..=MAX_ARBITRARY_LEN_BYTES + MAX_ARBITRARY_MESSAGE)?;
    Ok(u.bytes(len)?.to_vec())
}

#[derive(Debug)]
struct Plan {
    ops: Vec<Op>,
    entropy: Entropy,
}

impl<'a> Arbitrary<'a> for Plan {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // libFuzzer starts from inputs of a few bytes and lengthens them slowly, and a plan
        // sampled from so few bytes would hash one empty message. The input's head therefore
        // seeds a fixed-size stream of [`FuzzRng`] output that the rest of the input overwrites
        // from its start, so every input, even an empty one, samples a whole plan, and a byte
        // mutated past the head changes only what is sampled from it.
        let seed = u.bytes(u.len().min(SEED_BYTES))?.to_vec();
        let mut stream = vec![0; STREAM_BYTES.max(u.len())];
        FuzzRng::new(seed).fill_bytes(&mut stream);
        let literal = u.bytes(u.len())?;
        stream[..literal.len()].copy_from_slice(literal);
        let (plan, entropy) = stream.split_at(stream.len() - ENTROPY_BYTES);
        let u = &mut Unstructured::new(plan);

        Ok(Self {
            ops: (0..u.int_in_range(1..=MAX_OPS)?)
                .map(|_| u.arbitrary())
                .collect::<arbitrary::Result<_>>()?,
            entropy: Unstructured::new(entropy).arbitrary()?,
        })
    }
}

/// Splits `data` at `cuts`, which are sorted and at most its length.
fn split<'a>(data: &'a [u8], cuts: &[usize]) -> Vec<&'a [u8]> {
    let mut chunks = Vec::with_capacity(cuts.len() + 1);
    let mut start = 0;
    for &cut in cuts {
        chunks.push(&data[start..cut]);
        start = cut;
    }
    chunks.push(&data[start..]);
    chunks
}

/// Streams `chunks` into `hasher` and returns the reset hasher and the digest.
fn stream(mut hasher: Keccak256, chunks: &[&[u8]]) -> (Keccak256, Digest) {
    chunks
        .iter()
        .fold(&mut hasher, |hasher, chunk| hasher.update(chunk));
    hasher.finalize()
}

/// Oracle: the sha3 crate's Keccak-256, the backend the hasher wraps.
fn backend(data: &[u8]) -> Digest {
    Digest(sha3::Keccak256::digest(data).into())
}

/// Oracle: lowercase hex, two digits per byte and no prefix.
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0xf])
        .map(|nibble| char::from(DIGITS[usize::from(nibble)]))
        .collect()
}

/// Oracle: the bytes of a known digest's hex.
fn unhex(text: &str) -> [u8; DIGEST_LEN] {
    core::array::from_fn(|i| {
        u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("known digests are hex")
    })
}

fn hash<T: Hash + ?Sized>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

/// Checks the items an [Array] offers generic code through its bounds: the bytes behind
/// [AsRef] and [Deref](core::ops::Deref), a fixed-size encoding of them that decodes back, and
/// an order in which the array equals its copy.
fn check_array<A: Array>(array: &A, bytes: &[u8]) {
    assert_eq!(array.as_ref(), bytes);
    assert_eq!(&**array, bytes);
    assert_eq!(A::SIZE, bytes.len());
    assert_eq!(array.encode_size(), A::SIZE);
    assert_eq!(array.encode().as_ref(), bytes);
    let decoded = A::decode(Copying(bytes)).expect("an array decodes from its encoding");
    assert_eq!(&decoded, array);
    assert_eq!(array.cmp(&decoded), Ordering::Equal);
    assert_eq!(array.partial_cmp(&decoded), Some(Ordering::Equal));
    assert_eq!(hash(array), hash(&array.clone()));
}

/// Checks every view of a digest against its bytes.
fn check_digest(digest: &Digest) {
    let bytes = digest.0;
    check_array(digest, &bytes);

    // Conversions to and from the byte array keep the bytes.
    assert_eq!(<[u8; DIGEST_LEN]>::from(digest), bytes);
    assert_eq!(<[u8; DIGEST_LEN]>::from(*digest), bytes);
    assert_eq!(digest.encode_fixed::<DIGEST_LEN>(), bytes);
    assert_eq!(Digest::from(bytes), *digest);
    assert_eq!(Digest::from(&bytes), *digest);
    assert!(matches!(Digest::try_from(&bytes[..]), Ok(d) if d == *digest));

    // Writing appends exactly the bytes to what the buffer holds.
    let mut buf = vec![0x5a];
    digest.write(&mut buf);
    assert_eq!(buf[0], 0x5a);
    assert_eq!(buf[1..], bytes);

    // Display and debug both print the lowercase hex of the bytes.
    let text = hex(&bytes);
    assert_eq!(digest.to_string(), text);
    assert_eq!(format!("{digest:?}"), text);

    // A digest hashes as its bytes do.
    assert_eq!(hash(digest), hash(&bytes));

    // Zeroizing a copy leaves the empty digest and the original unchanged.
    let mut zeroized = *digest;
    zeroized.zeroize();
    assert_eq!(zeroized, EMPTY);
    assert_eq!(digest.0, bytes);
}

/// Checks every entrypoint on `messages` against the backend, streaming them through one hasher.
fn check_messages(messages: &[Message], digests: &mut Vec<Digest>) {
    let chunks: Vec<_> = messages
        .iter()
        .map(|message| split(&message.data, &message.cuts))
        .collect();
    let expected: Vec<_> = messages
        .iter()
        .map(|message| backend(&message.data))
        .collect();

    // Each finalize returns the digest of everything streamed since the previous one and a
    // hasher reset for the next message.
    let mut hasher = Keccak256::default();
    for (parts, expected) in chunks.iter().zip(&expected) {
        let (reset, digest) = stream(hasher, parts);
        hasher = reset;
        assert_eq!(digest, *expected);
        assert_eq!(Keccak256::hash(parts), *expected);
        assert_eq!(Keccak256::hash_across(parts, &Sequential), *expected);
        check_digest(&digest);
        digests.push(digest);
    }
    let (_, empty) = hasher.finalize();
    assert_eq!(empty, backend(&[]));

    // Each message pairs with the next, and the last with the first.
    for (i, left) in chunks.iter().enumerate() {
        let j = (i + 1) % chunks.len();
        assert_eq!(
            Keccak256::hash_pair(left, &chunks[j], &Sequential),
            (expected[i], expected[j])
        );
    }

    let data: Vec<_> = messages.iter().map(|m| m.data.as_slice()).collect();
    assert_eq!(Keccak256::hash_many(&data, &Sequential), expected);
}

/// Checks a known-answer vector, streamed twice through one hasher and hashed in one shot.
fn check_known(known: Known, digests: &mut Vec<Digest>) {
    let (message, text) = KNOWN[known.index];
    let chunks = split(message, &known.cuts);
    let (hasher, digest) = stream(Keccak256::default(), &chunks);
    let (_, again) = stream(hasher, &chunks);
    assert_eq!(digest.0, unhex(text));
    assert_eq!(digest.to_string(), text);
    assert_eq!(again, digest);
    assert_eq!(Keccak256::hash(&chunks), digest);
    check_digest(&digest);
    digests.push(digest);
}

/// Checks two digests that differ in at most one byte against the first differing byte.
fn check_order(bytes: [u8; DIGEST_LEN], edit: Option<(u8, u8)>, digests: &mut Vec<Digest>) {
    let mut edited = bytes;
    if let Some((index, value)) = edit {
        edited[usize::from(index) % DIGEST_LEN] = value;
    }
    let expected = bytes
        .iter()
        .zip(&edited)
        .find(|(a, b)| a != b)
        .map_or(Ordering::Equal, |(a, b)| a.cmp(b));
    let (a, b) = (Digest::from(bytes), Digest::from(edited));
    assert_eq!(a.cmp(&b), expected);
    assert_eq!(b.cmp(&a), expected.reverse());
    assert_eq!(a.partial_cmp(&b), Some(expected));
    assert_eq!(a == b, expected == Ordering::Equal);
    for digest in [a, b] {
        check_digest(&digest);
        digests.push(digest);
    }
}

/// Checks that a decode accepts exactly a digest's worth of bytes, refusing fewer as the end of
/// the buffer and more as extra data, and that a read takes the first digest's worth and leaves
/// the rest.
fn check_decode(bytes: [u8; DIGEST_LEN + MAX_EXTRA], len: Len, digests: &mut Vec<Digest>) {
    let len = match len {
        Len::Short(n) => usize::from(n) % Digest::SIZE,
        Len::Exact => Digest::SIZE,
        Len::Long(n) => Digest::SIZE + 1 + usize::from(n) % MAX_EXTRA,
    };
    let input = &bytes[..len];

    let decoded = Digest::decode(Copying(input));
    let converted = Digest::try_from(input);
    match (len.cmp(&Digest::SIZE), decoded, converted) {
        (Ordering::Less, Err(Error::EndOfBuffer), Err(Error::EndOfBuffer)) => {}
        (Ordering::Equal, Ok(decoded), Ok(converted)) => {
            assert_eq!(decoded.0[..], *input);
            assert_eq!(converted, decoded);
            check_digest(&decoded);
            digests.push(decoded);
        }
        (Ordering::Greater, Err(Error::ExtraData(a)), Err(Error::ExtraData(b)))
            if a == len - Digest::SIZE && b == a => {}
        (_, decoded, converted) => {
            panic!("{len} bytes decoded to {decoded:?} and converted to {converted:?}")
        }
    }

    let mut buf = Copying(input);
    match Digest::read(&mut buf) {
        Ok(read) if len >= Digest::SIZE => {
            assert_eq!(read.0, bytes[..Digest::SIZE]);
            assert_eq!(buf.0.len(), len - Digest::SIZE);
        }
        Err(Error::EndOfBuffer) if len < Digest::SIZE => {}
        read => panic!("{len} bytes read to {read:?}"),
    }
}

/// Checks that an arbitrary digest hashes the message after its length, and that only input
/// shorter than the longest read runs out.
fn check_sample(input: &[u8], digests: &mut Vec<Digest>) {
    let mut u = Unstructured::new(input);
    match Digest::arbitrary(&mut u) {
        Ok(digest) => {
            let read = input.len() - u.len();
            assert!(
                (0..=MAX_ARBITRARY_LEN_BYTES.min(read)).any(|skip| {
                    read - skip <= MAX_ARBITRARY_MESSAGE
                        && Keccak256::hash(&[&input[skip..read]]) == digest
                }),
                "{digest} hashes none of the messages ending at byte {read}"
            );
            assert_eq!(
                Digest::arbitrary(&mut Unstructured::new(input)).ok(),
                Some(digest)
            );
            check_digest(&digest);
            digests.push(digest);
        }
        Err(arbitrary::Error::NotEnoughData)
            if input.len() < MAX_ARBITRARY_LEN_BYTES + MAX_ARBITRARY_MESSAGE => {}
        Err(err) => panic!("{} bytes sampled no digest: {err}", input.len()),
    }
}

/// Checks that digests sort, deduplicate, and hash as their bytes do.
fn check_set(digests: &[Digest]) {
    let mut sorted = digests.to_vec();
    sorted.sort_unstable();
    let sorted: Vec<_> = sorted.iter().map(|digest| digest.0).collect();
    let mut bytes: Vec<_> = digests.iter().map(|digest| digest.0).collect();
    bytes.sort_unstable();
    assert_eq!(sorted, bytes);

    let unique: HashSet<_> = digests.iter().copied().collect();
    let unique_bytes: HashSet<_> = bytes.iter().copied().collect();
    assert_eq!(unique.len(), unique_bytes.len());
}

fn run(plan: Plan) {
    let Plan { ops, entropy } = plan;
    let cfg = deterministic::Config::new().with_rng(FuzzRng::from(entropy));
    let runner = deterministic::Runner::new(cfg);
    runner.start(|mut context| async move {
        assert_eq!(Digest::SIZE, DIGEST_LEN);
        assert_eq!(EMPTY.0, [0; DIGEST_LEN]);
        assert!(format!("{:?}", Keccak256::default()).starts_with("Keccak256 { hasher: "));

        let mut digests = Vec::new();
        for op in ops {
            match op {
                Op::Hash(messages) => check_messages(&messages, &mut digests),
                Op::Known(known) => check_known(known, &mut digests),
                Op::Order { bytes, edit } => check_order(bytes, edit, &mut digests),
                Op::Decode { bytes, len } => check_decode(bytes, len, &mut digests),
                Op::Sample(input) => check_sample(&input, &mut digests),
                Op::Random => {
                    let digest = Digest::random(&mut context);
                    check_digest(&digest);
                    digests.push(digest);
                }
            }
        }
        check_set(&digests);
    });
}

fuzz_target!(|plan: Plan| {
    run(plan);
});
