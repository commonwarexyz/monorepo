//! Type-state encoding for operations with fixed or variable size.

mod sealed {
    /// Type state representing whether an operation has fixed or variable size.
    pub trait Encoding: Clone {}
}

pub use sealed::Encoding;

/// Type state representing a fixed size operation.
#[derive(Clone, Debug, PartialEq)]
pub struct Fixed;
impl sealed::Encoding for Fixed {}

/// Type state representing a variable size operation.
#[derive(Clone, Debug, PartialEq)]
pub struct Variable;
impl sealed::Encoding for Variable {}
