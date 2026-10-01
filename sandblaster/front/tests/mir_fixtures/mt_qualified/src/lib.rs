//! A host crate whose `src/a.rs` a test of `sandblaster/front/tests` lifts in place.
#![allow(dead_code, unused_imports)]
/// The host function `a.rs` imports.
pub fn helper(x: u64) -> u64 {
    x
}
mod a;
