//! Cost and selection (optimizer design §10; plan O6 and O8).
//!
//! * [`profile`]: the crate's checked-in `PROFILE.json` (plan O6);
//! * [`tables`]: latency/throughput tables per variant set and
//!   microarchitecture (M5 measured; x86 v1, v3-scalar and v4 for Sapphire
//!   Rapids, Zen 4 and Zen 5, Zen 5 measured, the others hypotheses);
//! * [`tuning`]: the committed tuning evidence that overrides table entries,
//!   and its hash (part of the determinism key);
//! * [`model`]: the critical-path-weighted cost of a residual per variant
//!   set, the 3% selection gate and the top-3 ranking.
//!
//! Everything here is untrusted and changes choices only: every candidate
//! it ranks is kernel-checked before it is emitted.

pub mod model;
pub mod profile;
pub mod tables;
pub mod tuning;
