//! One out-of-line entry per measured function, the same text in every
//! subject: the bench loop calls these (one call per invocation), and
//! `samecode.py --family` compares them across subjects, following calls into
//! each subject's own copies of `codec` and `storage`. Each entry returns
//! plain values (bytes, integers, options), so every subject returns the same
//! types; writers write into a fixed stack buffer (no allocation timed).
//!
//! What is measured: the verified functions of sandblaster's three modules,
//! through their public API — codec's varint (`UInt`/`SInt` of the verified
//! instances `u16`, `u32`, `u64`, `i16`, `i32`, `i64`: write, read, encoded
//! size; `Decoder::feed`), storage's MMR position and peak arithmetic (the
//! `mmr::Family` methods, `PeakIterator`, the `Position`/`Location`
//! conversions) and the first set of its Merkle proof verifier (the
//! `Standard<Sha256>` hasher's leaf and node digests, and
//! `Proof::verify_element_inclusion`, whose core is the verified
//! `Subtree::reconstruct_digest`).

use codec::varint::{Decoder, SInt, UInt};
use codec::{Copying, EncodeSize, Read, Write};
use commonware_cryptography::{Hasher as _, Sha256};
use storage::merkle::Family as _;
use storage::merkle::hasher::Hasher as _;

type F = storage::mmr::Family;
type Pos = storage::merkle::Position<F>;
type Loc = storage::merkle::Location<F>;

// ---- codec: varint

macro_rules! unsigned {
    ($t:ty, $w:ident, $r:ident, $s:ident) => {
        #[inline(never)]
        pub fn $w(x: $t) -> ([u8; 24], usize) {
            let mut a = [0u8; 24];
            let n = {
                let mut s: &mut [u8] = &mut a;
                UInt(x).write(&mut s);
                24 - s.len()
            };
            (a, n)
        }
        #[inline(never)]
        pub fn $r(b: &[u8]) -> Option<($t, usize)> {
            // a borrowed slice is read through codec's `Copying` adapter
            let mut s = Copying(b);
            UInt::<$t>::read_cfg(&mut s, &()).ok().map(|v| (v.0, s.0.len()))
        }
        #[inline(never)]
        pub fn $s(x: $t) -> usize {
            UInt(x).encode_size()
        }
    };
}

macro_rules! signed {
    ($t:ty, $w:ident, $r:ident, $s:ident) => {
        #[inline(never)]
        pub fn $w(x: $t) -> ([u8; 24], usize) {
            let mut a = [0u8; 24];
            let n = {
                let mut s: &mut [u8] = &mut a;
                SInt(x).write(&mut s);
                24 - s.len()
            };
            (a, n)
        }
        #[inline(never)]
        pub fn $r(b: &[u8]) -> Option<($t, usize)> {
            // a borrowed slice is read through codec's `Copying` adapter
            let mut s = Copying(b);
            SInt::<$t>::read_cfg(&mut s, &()).ok().map(|v| (v.0, s.0.len()))
        }
        #[inline(never)]
        pub fn $s(x: $t) -> usize {
            SInt(x).encode_size()
        }
    };
}

unsigned!(u16, varint_u16_write, varint_u16_read, varint_u16_size);
unsigned!(u32, varint_u32_write, varint_u32_read, varint_u32_size);
unsigned!(u64, varint_u64_write, varint_u64_read, varint_u64_size);
signed!(i16, varint_i16_write, varint_i16_read, varint_i16_size);
signed!(i32, varint_i32_write, varint_i32_read, varint_i32_size);
signed!(i64, varint_i64_write, varint_i64_read, varint_i64_size);

/// `Decoder::<u64>::feed` over the bytes: the value and the bytes it took,
/// or how far it got before an error (`None`) or the end.
#[inline(never)]
pub fn varint_u64_decoder(b: &[u8]) -> (Option<Option<u64>>, usize) {
    let mut d = Decoder::<u64>::new();
    for (i, &x) in b.iter().enumerate() {
        match d.feed(x) {
            Ok(Some(v)) => return (Some(Some(v)), i + 1),
            Ok(None) => {}
            Err(_) => return (Some(None), i + 1),
        }
    }
    (None, b.len())
}

/// `Decoder::<u32>::feed`, likewise.
#[inline(never)]
pub fn varint_u32_decoder(b: &[u8]) -> (Option<Option<u32>>, usize) {
    let mut d = Decoder::<u32>::new();
    for (i, &x) in b.iter().enumerate() {
        match d.feed(x) {
            Ok(Some(v)) => return (Some(Some(v)), i + 1),
            Ok(None) => {}
            Err(_) => return (Some(None), i + 1),
        }
    }
    (None, b.len())
}

// ---- storage: the MMR's position and peak arithmetic

#[inline(never)]
pub fn mmr_is_valid_size(size: u64) -> bool {
    F::is_valid_size(Pos::new(size))
}

/// `size` at most `MAX_NODES`.
#[inline(never)]
pub fn mmr_to_nearest_size(size: u64) -> u64 {
    F::to_nearest_size(Pos::new(size)).as_u64()
}

/// `loc` at most `MAX_LEAVES`.
#[inline(never)]
pub fn mmr_location_to_position(loc: u64) -> u64 {
    F::location_to_position(Loc::new(loc)).as_u64()
}

/// `pos` at most `MAX_NODES`.
#[inline(never)]
pub fn mmr_position_to_location(pos: u64) -> Option<u64> {
    F::position_to_location(Pos::new(pos)).map(|l| l.as_u64())
}

/// A valid size: the peaks folded (count, sum of positions, sum of heights).
#[inline(never)]
pub fn mmr_peaks(size: u64) -> (u32, u64, u32) {
    let (mut n, mut p, mut h) = (0u32, 0u64, 0u32);
    for (pos, height) in F::peaks(Pos::new(size)) {
        n += 1;
        p = p.wrapping_add(pos.as_u64());
        h += height;
    }
    (n, p, h)
}

/// A valid size: `PeakIterator` stepped to its end, likewise.
#[inline(never)]
pub fn mmr_peak_iterator(size: u64) -> (u32, u64, u32) {
    let (mut n, mut p, mut h) = (0u32, 0u64, 0u32);
    for (pos, height) in storage::mmr::iterator::PeakIterator::new(Pos::new(size)) {
        n += 1;
        p = p.wrapping_add(pos.as_u64());
        h += height;
    }
    (n, p, h)
}

/// A node of height `height >= 1` at `pos`: its children.
#[inline(never)]
pub fn mmr_children(pos: u64, height: u32) -> (u64, u64) {
    let (l, r) = F::children(Pos::new(pos), height);
    (l.as_u64(), r.as_u64())
}

/// The heights of the parents a leaf at `leaves` creates (count, sum).
#[inline(never)]
pub fn mmr_parent_heights(leaves: u64) -> (u32, u32) {
    let (mut n, mut s) = (0u32, 0u32);
    for h in F::parent_heights(Loc::new(leaves)) {
        n += 1;
        s += h;
    }
    (n, s)
}

#[inline(never)]
pub fn mmr_location_from_position(pos: u64) -> Option<u64> {
    Loc::try_from(Pos::new(pos)).ok().map(|l| l.as_u64())
}

#[inline(never)]
pub fn mmr_position_from_location(loc: u64) -> Option<u64> {
    Pos::try_from(Loc::new(loc)).ok().map(|p| p.as_u64())
}

// ---- storage: the Merkle proof verifier (first set)

fn bytes32(d: &<Sha256 as commonware_cryptography::Hasher>::Digest) -> [u8; 32] {
    let mut a = [0u8; 32];
    a.copy_from_slice(d.as_ref());
    a
}

fn hasher() -> storage::mmr::StandardHasher<Sha256> {
    storage::mmr::StandardHasher::<Sha256>::new(storage::merkle::Bagging::ForwardFold)
}

#[inline(never)]
pub fn hasher_leaf_digest(pos: u64, element: &[u8]) -> [u8; 32] {
    bytes32(&<_ as storage::merkle::hasher::Hasher<F>>::leaf_digest(&hasher(), Pos::new(pos), element))
}

#[inline(never)]
pub fn hasher_node_digest(pos: u64, left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let (l, r) = (<Sha256 as commonware_cryptography::Hasher>::Digest::from(left), <Sha256 as commonware_cryptography::Hasher>::Digest::from(right));
    bytes32(&<_ as storage::merkle::hasher::Hasher<F>>::node_digest(&hasher(), Pos::new(pos), &l, &r))
}

/// An MMR of `n` leaves (element `i`: the SHA-256 of `i`'s bytes) with its
/// root and every leaf's inclusion proof: built once per subject, untimed.
pub struct Verifier {
    elements: Vec<<Sha256 as commonware_cryptography::Hasher>::Digest>,
    proofs: Vec<storage::mmr::Proof<<Sha256 as commonware_cryptography::Hasher>::Digest>>,
    root: <Sha256 as commonware_cryptography::Hasher>::Digest,
}

impl Verifier {
    pub fn new(n: u64) -> Verifier {
        let h = hasher();
        let mut mmr = storage::mmr::mem::Mmr::new();
        let elements: Vec<_> = (0..n).map(|i| Sha256::hash(&[&i.to_be_bytes()[..]])).collect();
        let batch = {
            let mut batch = mmr.new_batch();
            for e in &elements {
                batch = batch.add(&h, e);
            }
            batch.merkleize(&mmr, &h)
        };
        mmr.apply_batch(&batch).expect("apply");
        let root = mmr.root(&h, 0).expect("root");
        let proofs = (0..n).map(|i| mmr.proof(&h, Loc::new(i), 0).expect("proof")).collect();
        Verifier { elements, proofs, root }
    }

    pub fn len(&self) -> usize {
        self.elements.len()
    }
}

/// `Proof::verify_element_inclusion` of leaf `i`'s proof in `v` (with element
/// `i`, or with a flipped byte when `tamper`), against the root.
#[inline(never)]
pub fn proof_verify_element_inclusion(v: &Verifier, i: usize, tamper: bool) -> bool {
    let mut e = bytes32(&v.elements[i]);
    if tamper {
        e[0] ^= 1;
    }
    v.proofs[i].verify_element_inclusion(&hasher(), &e, Loc::new(i as u64), &v.root)
}
