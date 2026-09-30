//! Current-membership verification of a QMDB operation proof — the sandblaster
//! port of `verifier.bend`.
//!
//! The caller supplies a **trusted** canonical root and the claimed 32-byte
//! key and value; [`verify`] accepts only if the native Commonware
//! `OperationProof<mmr::Family, Sha256Digest, N>` bytes decode exactly
//! (N = `config::CHUNK_BYTES`: 32 in production, 1 in the Bend instance),
//! the queried operation's activity bit is set, and the reconstructed
//! canonical root equals the trusted root (qmdb/reference/README.md;
//! docs/prod-domain-commonware-spec.md). The target is exactly what
//! Commonware's `OperationProof::decode_cfg(bytes, &122)` followed by
//! `verify` accepts at 6e15fe7c, on every input; `qmdb/oracle` checks the
//! agreement against Commonware itself.
//!
//! # Mapping from the Bend source
//!
//! | `verifier.bend` | here | note |
//! | --- | --- | --- |
//! | `Proof` | [`Proof`] | `chunk` and `digests` borrow the input (zero copy); coordinates are `u64` (Commonware's domain, Bend: `u32`) |
//! | `read_digests`, `read_partial`, `parse` | same names, plus [`read_chunk`], [`parse_counts`], [`parse_body`] | `?` instead of `C.bind`; `parse` is staged so each stage is one lemma in PROOF.rs |
//! | `active`, `root_matches` | same names | |
//! | `canonical.checked`, `canonical` | [`canonical_complete`], [`canonical_partial`], [`canonical`] | one fixed-size hash per suffix shape (64 / 104 bytes) |
//! | `reconstruct` | [`reconstruct`], with [`update_operation`] | the operation `0xD2 ‖ key ‖ value` is a `[u8; 65]` |
//! | `verify_decoded`, `verify_parsed`, `verify_inputs`, `verify` | `verify_decoded`, `verify_parsed`, [`verify_fixed`], [`verify`] | `verify` checks the lengths and calls `verify_fixed` (Bend's `verify_inputs`) |
//!
//! `fixed_bytes(32, xs)` and `bytes_valid(4096, xs)` become length checks:
//! the inputs are `u8`, so Bend's per-element `≤ 255` checks hold by type.
//!
//! # Obligations
//!
//! `read_digests` multiplies `count as usize * 32` with `count: u32`, which
//! cannot overflow a `usize`; `active` indexes the chunk at `(location %
//! CHUNK_BITS) / 8 < CHUNK_BYTES` and shifts by `location % 8 < 8`. All are
//! linear. Every public function here is total.

use sandblaster::prelude::*;

use super::codec::{self, be64, byte, digest, exact, uint, uint64};
use super::config::{CHUNK_BITS, CHUNK_BYTES, Chunk, hash_chunk};
use super::merkle;
use super::sha256::{Digest, equal, hash_64, hash_104};

/// Largest accepted proof, in bytes. The largest proof Commonware accepts is
/// `9 + N + 9 + 1 + 1 + 122·32 + 1 + 32 + 32 = 3989 + N` bytes (location
/// and leaves of at most `2^62` take at most 9 varint bytes; the inactive count
/// and the digest count of an accepted proof one each), which fits for
/// N ≤ 107: 4021 bytes for N = 32, 3990 for N = 1.
pub const MAX_PROOF_BYTES: usize = 4096;

/// Largest accepted number of proof digests: Commonware's production decode
/// bound `MAX_PROOF_DIGESTS_PER_ELEMENT` (storage/src/merkle/proof.rs:1016-1021;
/// 61 siblings plus 61 peaks at 62 peaks). A proof needs at most 122, so the
/// verdict equals Commonware's for any caller bound `max_digests ≥ 122`.
pub const MAX_DIGESTS: u32 = 122;

/// Operation tag of a fixed-size unordered `Update` (Commonware encoding).
pub const UPDATE_TAG: u8 = 0xD2;

/// A decoded current::unordered operation proof, for an MMR and N-byte
/// activity chunks. Bend: `Proof`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Proof<'a> {
    /// Leaf location of the queried operation (at most `MAX_LEAVES`).
    pub location: u64,
    /// The activity chunk (`CHUNK_BITS` operations) containing `location`.
    pub chunk: &'a Chunk,
    /// Number of leaves (operations) in the tree (at most `MAX_LEAVES`).
    pub leaves: u64,
    /// Number of leading inactive peaks (any `u64`; more than the number of
    /// peaks is rejected by the reconstruction).
    pub inactive: u64,
    /// Peak and sibling digests, in range-proof order.
    pub digests: &'a [Digest],
    /// Digest of the trailing partial chunk, if `leaves % CHUNK_BITS != 0`.
    pub partial: Option<Digest>,
    /// Root of the operations tree.
    pub ops_root: Digest,
}

/// Read `count` consecutive digests (borrowed from the input).
/// Bend: `read_digests`.
pub(crate) fn read_digests(count: u32, bytes: &[u8]) -> Option<(&[Digest], &[u8])> {
    let (raw, rest) = bytes.split_at_checked(count as usize * 32)?;
    let (digests, _) = raw.as_chunks::<32>();
    Some((digests, rest))
}

/// Read an activity chunk (borrowed from the input). Bend: `read_chunk`.
pub(crate) fn read_chunk(bytes: &[u8]) -> Option<(&Chunk, &[u8])> {
    bytes.split_first_chunk::<CHUNK_BYTES>()
}

/// Read the optional partial-chunk digest after its tag byte (`0` absent,
/// `1` present, anything else invalid). Bend: `read_partial`.
pub(crate) fn read_partial(tag: u8, bytes: &[u8]) -> Option<(Option<Digest>, &[u8])> {
    match tag {
        0 => Some((None, bytes)),
        1 => {
            let (d, rest) = digest(bytes)?;
            Some((Some(d), rest))
        }
        _ => None,
    }
}

/// Decode an operation proof, returning the unconsumed suffix. Bend: `parse`.
///
/// Wire format (Commonware `OperationProof::read_cfg`, operation.rs:117-127,
/// merkle/proof.rs:101-114, current/proof/mod.rs:588-605): `location` (a
/// `Location`: varint ≤ `2^62`), `chunk` (`CHUNK_BYTES` raw bytes), `leaves`
/// (a `Location`), `inactive` (`UInt<u64>`), `count` (`usize` =
/// `UInt<u32>`, at most [`MAX_DIGESTS`]), `count` digests, no pending chunk
/// (MMR), partial tag (1 byte), optional partial digest, `ops_root`.
pub fn parse(bytes: &[u8]) -> Option<(Proof<'_>, &[u8])> {
    let (location, s0) = codec::location(bytes)?;
    let (chunk, s1) = read_chunk(s0)?;
    parse_counts(location, chunk, s1)
}

/// [`parse`] after the chunk: the leaf count, the inactive count and the
/// digest count.
pub(crate) fn parse_counts<'a>(location: u64, chunk: &'a Chunk, s1: &'a [u8]) -> Option<(Proof<'a>, &'a [u8])> {
    let (leaves, s2) = codec::location(s1)?;
    let (inactive, s3) = uint64(s2)?;
    let (count, s4) = uint(s3)?;
    parse_body(location, chunk, leaves, inactive, count, s4)
}

/// The rest of [`parse`] after the digest count: at most [`MAX_DIGESTS`]
/// digests, the partial tag and digest, the operations root.
pub(crate) fn parse_body<'a>(
    location: u64,
    chunk: &'a Chunk,
    leaves: u64,
    inactive: u64,
    count: u32,
    s4: &'a [u8],
) -> Option<(Proof<'a>, &'a [u8])> {
    if count > MAX_DIGESTS {
        return None;
    }
    let (digests, s5) = read_digests(count, s4)?;
    let (tag, s6) = byte(s5)?;
    let (partial, s7) = read_partial(tag, s6)?;
    let (ops_root, end) = digest(s7)?;
    Some((Proof { location, chunk, leaves, inactive, digests, partial, ops_root }, end))
}

/// Whether the queried operation's activity bit is set: bit `location %
/// CHUNK_BITS` of the chunk, i.e. bit `% 8` (least significant first) of
/// byte `/ 8` (Commonware operation.rs:70-74). Bend: `active`.
pub fn active(proof: &Proof<'_>) -> bool {
    let bit = proof.location % CHUNK_BITS;
    (proof.chunk[(bit / 8) as usize] >> (bit % 8)) % 2 == 1
}

/// Whether a reconstructed root exists and equals `expected`.
/// Bend: `root_matches`.
pub fn root_matches(expected: &Digest, candidate: Option<Digest>) -> bool {
    match candidate {
        None => false,
        Some(root) => equal(expected, &root),
    }
}

/// Canonical root without a partial chunk: `H(ops_root ‖ grafted_root)`.
/// Bend: `canonical.checked` with an empty suffix.
pub fn canonical_complete(ops: &Digest, grafted: &Digest) -> Digest {
    let mut msg = [0u8; 64];
    msg[0..32].copy_from_slice(ops);
    msg[32..64].copy_from_slice(grafted);
    hash_64(&msg)
}

/// Canonical root with a partial chunk:
/// `H(ops_root ‖ grafted_root ‖ u64be(next_bit) ‖ partial_digest)`.
/// Bend: `canonical.checked` with suffix `be64(next_bit) ‖ digest`.
pub fn canonical_partial(ops: &Digest, grafted: &Digest, next_bit: u64, partial: &Digest) -> Digest {
    let mut msg = [0u8; 104];
    msg[0..32].copy_from_slice(ops);
    msg[32..64].copy_from_slice(grafted);
    msg[64..72].copy_from_slice(&be64(next_bit));
    msg[72..104].copy_from_slice(partial);
    hash_104(&msg)
}

/// Combine the operations root, the grafted tree root and the optional
/// partial chunk into the canonical Current root. Bend: `canonical`.
///
/// A trailing partial activity chunk (`leaves % CHUNK_BITS != 0`) is
/// committed alongside the two tree roots (Commonware current/db.rs:835-865,
/// proof/mod.rs:441-460); when the queried bit lies in it (`location /
/// CHUNK_BITS == leaves / CHUNK_BITS`), the supplied chunk must hash to the
/// committed partial digest.
#[allow(clippy::manual_is_multiple_of)]
pub fn canonical(
    location: u64,
    leaves: u64,
    chunk: &Chunk,
    partial: Option<Digest>,
    ops: &Digest,
    grafted: Option<Digest>,
) -> Option<Digest> {
    match (partial, grafted) {
        (None, Some(root)) => {
            if leaves % CHUNK_BITS == 0 { Some(canonical_complete(ops, &root)) } else { None }
        }
        (Some(partial_digest), Some(root)) => {
            let next_bit = leaves % CHUNK_BITS;
            let bound = location / CHUNK_BITS != leaves / CHUNK_BITS || equal(&hash_chunk(chunk), &partial_digest);
            if next_bit != 0 && bound {
                Some(canonical_partial(ops, &root, next_bit, &partial_digest))
            } else {
                None
            }
        }
        (_, None) => None,
    }
}

/// The encoded fixed unordered update `0xD2 ‖ key ‖ value` (65 bytes, no
/// length prefix). Bend: the `operation` list built in `reconstruct`.
pub fn update_operation(key: &Digest, value: &Digest) -> [u8; 65] {
    let mut operation = [0u8; 65];
    operation[0] = UPDATE_TAG;
    operation[1..33].copy_from_slice(key);
    operation[33..65].copy_from_slice(value);
    operation
}

/// Reconstruct the canonical root that `proof` claims for `key ↦ value`.
/// Bend: `reconstruct`.
pub fn reconstruct(proof: &Proof<'_>, key: &Digest, value: &Digest) -> Option<Digest> {
    let operation = update_operation(key, value);
    canonical(
        proof.location,
        proof.leaves,
        proof.chunk,
        proof.partial,
        &proof.ops_root,
        merkle::reconstruct(
            proof.location,
            proof.leaves,
            proof.inactive,
            &operation,
            proof.chunk,
            proof.digests,
        ),
    )
}

/// Check a decoded proof: the operation must be active and the
/// reconstructed root must equal the trusted `root`. Bend: `verify_decoded`.
/// Laws: `inactive_decoded_rejected`, `verify_acceptance`.
pub fn verify_decoded(root: &Digest, proof: &Proof<'_>, key: &Digest, value: &Digest) -> bool {
    active(proof) && root_matches(root, reconstruct(proof, key, value))
}

/// Check exactly decoded inputs; any decoding failure rejects.
/// Bend: `verify_parsed`.
pub fn verify_parsed(
    root: Option<Digest>,
    proof: Option<Proof<'_>>,
    key: &Digest,
    value: &Digest,
) -> bool {
    match (root, proof) {
        (Some(trusted), Some(p)) => verify_decoded(&trusted, &p, key, value),
        _ => false,
    }
}

/// The first 32 bytes of `xs` (zeros if there are fewer; [`verify`] calls it
/// on 32-byte inputs only).
pub(crate) fn first_digest(xs: &[u8]) -> Digest {
    match xs.first_chunk::<32>() {
        Some(d) => *d,
        None => [0u8; 32],
    }
}

/// Verify that `key ↦ value` is a current (active) update of the database
/// whose canonical root is the trusted `root`, given the native proof bytes.
/// Bend: `verify`, which checks the lengths and calls `verify_inputs`; here
/// the 32-byte inputs go to [`verify_fixed`] (§11.1).
///
/// Every input is bounded and checked before decoding or hashing: `root`,
/// `key` and `value` must be exactly 32 bytes and `proof` at most
/// [`MAX_PROOF_BYTES`].
#[refines(crate::spec::proof::verify)]
pub fn verify(root: &[u8], key: &[u8], value: &[u8], proof: &[u8]) -> bool {
    if root.len() != 32 || key.len() != 32 || value.len() != 32 {
        return false;
    }
    verify_fixed(&first_digest(root), &first_digest(key), &first_digest(value), proof)
}

/// [`verify`] with fixed-size root, key and value (DESIGN.md §11.1).
#[refines(crate::spec::proof::verify)]
pub fn verify_fixed(root: &Digest, key: &Digest, value: &Digest, proof: &[u8]) -> bool {
    proof.len() <= MAX_PROOF_BYTES && verify_parsed(Some(*root), exact(parse(proof)), key, value)
}
