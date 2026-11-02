//! Low-level arithmetic on several elements at once, one per vector lane: base field
//! representations, the extension fields, curve formulas, and the pairing.
//!
//! Every operation documents the bounds its inputs must satisfy. Callers establish them, and
//! debug builds check them.

#![cfg_attr(
    not(feature = "core"),
    allow(
        dead_code,
        reason = "The benchmarks use operations that the group API does not."
    )
)]

pub mod curve;
mod debug_counter;
pub mod field;
pub mod pairing;
