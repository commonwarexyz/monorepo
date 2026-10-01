//! A host crate whose `src/a.rs` a test of `sandblaster/front/tests` lifts in place.
#![allow(dead_code, unused_imports)]
/// The open trait (a host module the lift does not read).
pub trait Fam {
    const MAX: u64;
    fn cap(x: u64) -> u64;
}
mod a;
