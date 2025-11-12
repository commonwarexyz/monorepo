//! Authenticated databases (ADBs) that provides succinct proofs of _any_ value ever associated with
//! a key. The submodules provide two classes of variants, one specialized for fixed-size values and
//! the other allowing variable-size values.

pub mod fixed;
pub mod variable;
