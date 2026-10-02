//! The standard proof library: domain-independent mathematics a proof references by name, each
//! lemma checked by the kernel like every proof. Nothing here names a crate's own items or any
//! application domain (`tools/stdlib_boundary.sh` checks it). A crate mounts it as a ghost
//! module (`#[cfg(sandblaster)] #[path = ".../stdlib/mod.rs"] mod stdlib;`).
//!
//! | Module | Theory |
//! | --- | --- |
//! | `bits` | halving arithmetic, `pow2`, `popcount`, `log2`, multiples of `2^e` (`aligned`), a word's trailing zeros and trailing ones at every width, big-endian `u64` bytes |
//! | `folds` | `fold_left`, `fold_right`, `fold_right1`, `map`, `all`, `any`, `all2`, `zip`, `scan` over any function (ghost function values `fn(A, T) -> A`): their laws over `++`, `take`, `skip`, fusion, induction, relations and injectivity |
//! | `seqs` | lengths, elements and splits of `take` / `skip` / `++` |
//! | `bridges` | the code's words, slices and options against `Nat` and `Seq` (rules of the prover) |
//!
//! `sha256.rs` (FIPS 180-4 SHA-256, `concat`, `sha256_parts`, `collision` and the
//! `collision_resistance` assumption) is an optional part: not declared here, a crate that hashes
//! mounts it on its own (`#[cfg(sandblaster)] #[path = ".../stdlib/sha256.rs"] mod sha256;`), so
//! crates that do not hash never evaluate its examples.

pub mod bits;
pub mod folds;
/// Every lemma of `bridges` is also a rule of the prover (`#[bridges]`).
#[bridges]
pub mod bridges;
pub mod seqs;
