use super::LANES;

pub(crate) type Halves = [[u64; LANES]; 2];

pub(crate) struct LaneParameters {
    pub(crate) moduli: [u64; LANES],
    pub(crate) complement: [u64; LANES],
    pub(crate) inverse: [u64; LANES],
}

pub(crate) struct Conversion {
    pub(crate) matrix: [[u64; LANES]; LANES],
    pub(crate) fraction: [u64; LANES],
    pub(crate) correction: [u64; LANES],
    pub(crate) correction_shift: [u64; LANES],
}

/// Generated constants for a sealed modulus and residue geometry.
#[doc(hidden)]
pub struct Parameters {
    pub(crate) bits: usize,
    pub(crate) modulus: [u64; 6],
    pub(crate) no_k: bool,
    pub(crate) max_expand: i64,
    pub(crate) m: LaneParameters,
    pub(crate) n: LaneParameters,
    pub(crate) reduce: Conversion,
    pub(crate) expand: Conversion,
    pub(crate) to_rns: Conversion,
    pub(crate) to_canonical: [[u64; 6]; LANES],
    pub(crate) canonical_correction: [u64; 6],
    pub(crate) canonical_n0: u64,
    pub(crate) canonical_rr: [u64; 6],
    pub(crate) encoded_p: Halves,
    pub(crate) wide_encoded_p2: Halves,
    pub(crate) one: Halves,
    pub(crate) radix_256: Halves,
    pub(crate) root: Halves,
    pub(crate) sqrt_exponent: [u64; 6],
    pub(crate) odd_exponent: [u64; 6],
    pub(crate) half_plus_one: [u64; 6],
    pub(crate) two_adicity: u32,
}
