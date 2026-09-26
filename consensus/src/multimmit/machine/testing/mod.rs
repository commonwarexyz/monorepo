//! Deterministic support for driving the production machine in tests and fuzz targets.

mod driver;
#[cfg(test)]
mod executors;
#[cfg(test)]
mod extensions;
pub(crate) mod fixtures;
pub(crate) mod world;

#[cfg(test)]
pub(super) use driver::SymbolicVerifier;
pub(crate) use driver::VerifyJobExt;
#[cfg(test)]
pub(super) use driver::{CapabilityExt, Drive, Driver, Until, cohort, start};
#[cfg(test)]
pub(super) use executors::{PersistSink, SymbolicPersistence};
#[cfg(test)]
pub(crate) use extensions::{CapabilitiesExt, EffectExt, MachineExt, StepExt};
