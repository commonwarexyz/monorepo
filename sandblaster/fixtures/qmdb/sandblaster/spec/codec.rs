//! A proof's bytes: Commonware's `OperationProof::write` and `read_cfg(bytes, &122)`
//! (operation.rs:117-127, merkle/proof.rs:101-114, current/proof/mod.rs:588-605,
//! codec/src/varint.rs). `proofs_have_one_encoding` (LAWS.rs) says the two are inverse.

use super::config::N;
use super::db::MAX_LEAVES;
use super::proof::Proof;
use super::sha256::Digest;

/// The most digests a proof may carry: Commonware's `MAX_PROOF_DIGESTS_PER_ELEMENT`
/// (merkle/proof.rs:1016-1021), which no proof exceeds, so the verdict is Commonware's for every
/// caller bound of at least 122.
pub const MAX_DIGESTS: Nat = 122;

/// Whether `n` digests fit in a proof, as `in_range` checks. A function so that its example pins
/// `MAX_DIGESTS` (the mutation gate takes known answers from functions only).
#[example(digests_fit(122) && !digests_fit(123))] // MAX_PROOF_DIGESTS_PER_ELEMENT = 122
pub(crate) fn digests_fit(n: Nat) -> bool { n <= MAX_DIGESTS }

impl Proof {
    /// What the fields may hold: locations and leaf counts up to 2^62 (`Location`), a `u64`
    /// inactive count, at most 122 digests. Opaque in proofs, like the readers.
    #[opaque]
    #[example(Proof { location: 0, chunk: [0u8; N], leaves: 1, inactive: 0, digests: seq![], partial: None, ops_root: [0u8; 32] }.in_range())]
    #[example(!Proof { location: 4611686018427387905, chunk: [0u8; N], leaves: 1, inactive: 0, digests: seq![], partial: None, ops_root: [0u8; 32] }.in_range())]
    pub fn in_range(&self) -> bool {
        self.location <= MAX_LEAVES && self.leaves <= MAX_LEAVES && self.inactive < pow2(64)
            && self.digests.len() <= MAX_DIGESTS
    }
}

/// The fields in order: numbers as minimal LEB128, the digest count before the digests, the partial
/// digest behind a 0/1 tag.
#[example(encode(Proof { location: 0, chunk: [0u8; N], leaves: 1, inactive: 0, digests: seq![], partial: None, ops_root: [0u8; 32] }) == seq![0u8, ..[0u8; N], 1u8, 0u8, 0u8, 0u8, ..[0u8; 32]])]
#[example(encode(Proof { location: 0, chunk: [0u8; N], leaves: 0, inactive: 0, digests: seq![], partial: Some([0u8; 32]), ops_root: [0u8; 32] }) == seq![0u8, ..[0u8; N], 0u8, 0u8, 0u8, 1u8, ..[0u8; 32], ..[0u8; 32]])] // tag 1, then the digest
pub fn encode(p: Proof) -> Seq<u8> {
    let partial = match p.partial { None => seq![0u8], Some(d) => seq![1u8, ..d] };
    seq![..varint(p.location), ..p.chunk, ..varint(p.leaves), ..varint(p.inactive),
         ..varint(p.digests.len()), ..p.digests.flatten(), ..partial, ..p.ops_root]
}

/// Minimal LEB128 (varint.rs:370-390): seven bits per byte, least significant first, `0x80` on
/// every byte but the last.
#[decreases(x)]
#[example(varint(0) == seq![0u8] && varint(300) == seq![0xACu8, 0x02u8])]
#[example(varint(127) == seq![0x7Fu8] && varint(128) == seq![0x80u8, 0x01u8] && varint(254) == seq![0xFEu8, 0x01u8])]
pub fn varint(x: Nat) -> Seq<u8> { if x < 128 { seq![x as u8] } else { seq![(128 + x % 128) as u8, ..varint(x / 128)] } }

/// The fields in order, then the range checks. Returns the proof and the bytes after it. Each
/// field has its own reader below; they are opaque in proofs, which read `decode` field by field
/// (`by_unfolding(uint)` reveals a reader). `decode` itself is opaque in proofs too.
#[opaque]
#[example(decode(seq![]) == None)]
#[example(decode(seq![..encode(Proof { location: 0, chunk: [0u8; N], leaves: 1, inactive: 0, digests: seq![], partial: None, ops_root: [0u8; 32] }), 7u8]) == Some((Proof { location: 0, chunk: [0u8; N], leaves: 1, inactive: 0, digests: seq![], partial: None, ops_root: [0u8; 32] }, seq![7u8])))]
pub fn decode(b: Seq<u8>) -> Option<(Proof, Seq<u8>)> {
    let (location, b) = uint(64, b)?;
    let (chunk, b) = chunk(b)?;
    let (leaves, b) = uint(64, b)?;
    let (inactive, b) = uint(64, b)?;
    let (count, b) = uint(32, b)?; // a `usize` is written as a `UInt<u32>`
    let (digests, b) = field(32 * count, b)?;
    let (partial, b) = partial(b)?;
    let (ops_root, b) = digest(b)?;
    let p = Proof { location, chunk, leaves, inactive, digests: digests.chunks_exact::<32>(), partial, ops_root };
    if p.in_range() { Some((p, b)) } else { None }
}

/// Commonware's `UInt` (varint.rs:118-154): seven-bit groups, least significant first, `0x80`
/// marking more to come. A zero last group is allowed only as the first, so no value has two
/// encodings, and the value must fit in `bits` bits. (Commonware bounds the last byte a type
/// allows; bounding the value rejects the same encodings.)
#[opaque]
#[example(uint(64, seq![5u8]) == Some((5, seq![])))]
#[example(uint(8, seq![0xACu8, 0x02u8]) == None)]
#[example(uint(3, seq![8u8]) == None)] // 8 needs four bits
#[example(uint(64, seq![..[0x80u8; 9], 1u8]) == Some((pow2(63), seq![])))] // 10 bytes, the last 0x01
#[example(uint(64, seq![..[0x80u8; 10], 1u8]) == None)] // an 11th byte
pub fn uint(bits: Nat, b: Seq<u8>) -> Option<(Nat, Seq<u8>)> {
    let (x, rest) = groups(b, true)?;
    if x < pow2(bits) { Some((x, rest)) } else { None }
}

#[example(groups(seq![0xACu8, 0x02u8], true) == Some((300, seq![])))]
#[example(groups(seq![0x80u8, 0u8], true) == None)]
#[example(groups(seq![0x7Fu8], false) == Some((127, seq![])))] // a last group of seven bits
pub(crate) fn groups(b: Seq<u8>, first: bool) -> Option<(Nat, Seq<u8>)> {
    match b {
        [g, rest @ ..] if g >= 128 => more(g, groups(rest, false)),
        [g, rest @ ..] if g != 0 || first => Some((g as Nat, rest)),
        _ => None, // out of input, or a zero last group after the first
    }
}

/// A continuation group `g` in front of what the rest reads, `y`: `g - 128 + 128 y`. A function of
/// its own so that the kernel's evaluator reads the rest once (a `let` of the recursive result
/// costs time exponential in the number of groups).
#[example(more(0xACu8, Some((2, seq![]))) == Some((300, seq![])))]
#[example(more(0x80u8, None) == None && more(1u8, Some((2, seq![]))) == None)]
pub(crate) fn more(g: u8, r: Option<(Nat, Seq<u8>)>) -> Option<(Nat, Seq<u8>)> {
    match r {
        Some((y, s)) => if g >= 128 { Some((g as Nat - 128 + 128 * y, s)) } else { None },
        None => None,
    }
}

/// The first `n` bytes and the rest.
#[opaque]
#[example(field(2, seq![1u8, 2u8, 3u8]) == Some((seq![1u8, 2u8], seq![3u8])))]
#[example(field(4, seq![1u8]) == None)]
#[example(field(0, seq![]) == Some((seq![], seq![])))]
pub(crate) fn field(n: Nat, b: Seq<u8>) -> Option<(Seq<u8>, Seq<u8>)> { if b.len() < n { None } else { Some((b.take(n), b.skip(n))) } }

/// An activity chunk: `N` raw bytes.
#[opaque]
#[example(chunk(seq![]) == None)]
#[example(chunk(seq![..[7u8; N], 9u8]) == Some(([7u8; N], seq![9u8])))]
#[example(chunk(seq![..[0u8; N]]) == Some(([0u8; N], seq![])))] // exactly N bytes
pub(crate) fn chunk(b: Seq<u8>) -> Option<([u8; N], Seq<u8>)> {
    if b.len() < N as Nat { None } else { Some((b.take(N as Nat).to_array::<N>(), b.skip(N as Nat))) }
}

/// A digest: 32 raw bytes.
#[opaque]
#[example(digest(seq![1u8]) == None)]
#[example(digest(seq![..[3u8; 32]]) == Some(([3u8; 32], seq![])))]
pub(crate) fn digest(b: Seq<u8>) -> Option<(Digest, Seq<u8>)> {
    if b.len() < 32 { None } else { Some((b.take(32).to_array::<32>(), b.skip(32))) }
}

/// The partial chunk's digest behind a `bool` tag: `0` for none, `1` and the digest.
#[opaque]
#[example(partial(seq![0u8, 9u8]) == Some((None, seq![9u8])))]
#[example(partial(seq![2u8]) == None)]
pub(crate) fn partial(b: Seq<u8>) -> Option<(Option<Digest>, Seq<u8>)> {
    match b {
        [0, b @ ..] => Some((None, b)),
        [1, b @ ..] => { let (d, b) = digest(b)?; Some((Some(d), b)) }
        _ => None, // a `bool` is one byte, 0 or 1
    }
}
