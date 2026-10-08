//! Differential test of Target-State Synthesis prefixes against the marshal
//! scenario prefixes.
//!
//! For several of the six scenario source tests, one test runs two prefixes on
//! an identical cluster setup and input bytes: side A, the existing scenario's
//! `drive`, and side B, a hand-written prefix built from the StateLens helper
//! primitives (`Stages`, `Witness`, `stamp`) and the same harness verbs, as the
//! synthesize prompt and SPEC 18.7 prescribe for a scaffold. Both take a
//! canonical state digest after `finish`; the test asserts the digests are
//! equal, and `statelens/scripts/differential.sh` runs the real reach-check
//! validator over side B's captured `[statelens-reach]` lines.
//!
//! Nothing here instruments the system under test or starts an engine.

pub mod cards;
pub mod digest;
pub mod record;
pub mod setup;
#[cfg(test)]
mod tests;
