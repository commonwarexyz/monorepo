//! Fixtures shared by the field benchmarks.

use commonware_cryptography_bls12381::core::field::fp::{
    BYTES, rns::Rns, unsat28::Unsat28, unsat49::Unsat49,
};
use commonware_simd::Simd;

/// The base field operations that benchmarks compare across representations.
pub trait Field<S: Simd>: Copy {
    /// Number of elements in a value.
    const LANES: usize;

    fn load(simd: S, elements: &[[u8; BYTES]], fill: &[u8; BYTES]) -> Self;
    fn store(self, simd: S, elements: &mut [[u8; BYTES]]);
    fn add(self, simd: S, rhs: Self) -> Self;
    fn mul(self, simd: S, rhs: Self) -> Self;
}

/// A base field representation, selecting its element type on every backend.
pub trait Representation {
    /// The representation's name in benchmark labels.
    const NAME: &'static str;

    /// Elements in this representation on backend `S`.
    type Field<S: Simd>: Field<S>;
}

macro_rules! representations {
    ($($marker:ident => $field:ident($lanes:expr): $name:literal),*) => {$(
        #[doc = concat!("Selects [`", stringify!($field), "`].")]
        pub struct $marker;

        impl Representation for $marker {
            const NAME: &'static str = $name;
            type Field<S: Simd> = $field<S>;
        }

        impl<S: Simd> Field<S> for $field<S> {
            const LANES: usize = $lanes;

            #[inline(always)]
            fn load(simd: S, elements: &[[u8; BYTES]], fill: &[u8; BYTES]) -> Self {
                Self::load(simd, elements, fill)
            }

            #[inline(always)]
            fn store(self, simd: S, elements: &mut [[u8; BYTES]]) {
                self.store(simd, elements)
            }

            #[inline(always)]
            fn add(self, simd: S, rhs: Self) -> Self {
                self.add(simd, rhs)
            }

            #[inline(always)]
            fn mul(self, simd: S, rhs: Self) -> Self {
                self.mul(simd, rhs)
            }
        }
    )*};
}

representations!(
    Radix28 => Unsat28(S::U32_LANES): "unsat28",
    Radix49 => Unsat49(S::U64_LANES): "unsat49",
    Residues => Rns(1): "rns"
);

/// One as a big-endian integer.
pub const ONE: [u8; BYTES] = {
    let mut bytes = [0; BYTES];
    bytes[BYTES - 1] = 1;
    bytes
};

/// Fills `bytes` deterministically from `seed`.
fn fill(seed: u64, bytes: &mut [u8]) {
    let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15).wrapping_add(1);
    for byte in bytes {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = state as u8;
    }
}

/// Returns `count` deterministic big-endian integers below `2^380 < p`.
pub fn elements(count: usize) -> Vec<[u8; BYTES]> {
    (0..count)
        .map(|i| {
            let mut bytes = [0; BYTES];
            fill(i as u64, &mut bytes);
            bytes[0] &= 0x0f;
            bytes
        })
        .collect()
}
