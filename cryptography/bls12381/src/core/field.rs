//! Field arithmetic on several elements at once, one per vector lane.

pub mod arithmetic;
pub mod fp;
pub mod fp12;
pub mod fp2;
pub mod fp6;

/// Largest number of elements in a value, the widest representation's lane count.
pub const MAX_LANES: usize = 16;
