//! Deterministic support for driving the production machine in tests.
//!
//! A [`Driver`] owns one machine, an in-memory symbolic journal, and a manual clock. Executors
//! complete the capabilities the machine issues without I/O: [`SymbolicPersistence`] appends and
//! acknowledges journal barriers, [`SymbolicVerifier`](executors::SymbolicVerifier) returns
//! scripted verdicts, [`SymbolicSigner`](executors::SymbolicSigner) signs released requests with
//! a committee member's keys,
//! [`SymbolicApplication`](executors::SymbolicApplication) builds, custodies, and validates
//! blocks, [`SymbolicCrypto`](executors::SymbolicCrypto) aggregates certificates, and
//! [`ManualClock`](executors::ManualClock) holds armed deadlines until the test advances time.

mod driver;
pub(crate) mod executors;
mod extensions;
pub(crate) mod fixtures;
pub(crate) mod world;

pub(crate) use super::view::proposal::HeldVqc;
#[cfg(test)]
pub(crate) use driver::DriverError;
pub(crate) use driver::{Drive, Driver, Until, cohort};
pub(crate) use executors::SymbolicPersistence;
#[cfg(test)]
pub(crate) use executors::{Execution, Executor, SymbolicSigner, SymbolicVerifier};
#[cfg(test)]
pub(crate) use extensions::MachineExt;
pub(crate) use extensions::{CapabilitiesExt, StepExt};
