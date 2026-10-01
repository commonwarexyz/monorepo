//! A host crate whose `src/a.rs` a test of `sandblaster/front/tests` lifts in place.
#![allow(dead_code, unused_imports)]
/// The byte-string iterator `first_len` is extracted at (`E: Iterator<Item:
/// AsRef<[u8]>>`; storage's verifier uses the same instance).
pub type Elements = core::iter::Copied<core::slice::Iter<'static, &'static [u8]>>;
mod a;
