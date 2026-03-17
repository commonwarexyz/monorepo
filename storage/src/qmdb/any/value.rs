//! Type-state for operations with fixed or variable size.

use commonware_codec::{CodecFixedShared, CodecShared};
use std::marker::PhantomData;

mod sealed {
    /// Prevents external implementations of [`ValueEncoding`](super::ValueEncoding).
    pub trait Sealed {}
}

use commonware_codec::CodecShared as ValueCodecShared;

/// A wrapper around a value to indicate whether it is fixed or variable size.
/// Having separate wrappers for fixed and variable size values allows us to
/// use the same operation type for both, while still being able to
/// parameterize the operation encoding by the value type.
///
/// This trait is sealed -- it cannot be implemented outside this crate.
pub trait ValueEncoding: sealed::Sealed + Clone + Send + Sync {
    /// The wrapped value type.
    type Value: ValueCodecShared + Clone;
}

/// A fixed-size, clonable value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixedEncoding<V: FixedValue>(PhantomData<V>);

impl<V: FixedValue> sealed::Sealed for FixedEncoding<V> {}

impl<V: FixedValue> ValueEncoding for FixedEncoding<V> {
    type Value = V;
}

/// A variable-size, clonable value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VariableEncoding<V: VariableValue>(PhantomData<V>);

impl<V: VariableValue> sealed::Sealed for VariableEncoding<V> {}

impl<V: VariableValue> ValueEncoding for VariableEncoding<V> {
    type Value = V;
}

/// A fixed-size, clonable value.
pub trait FixedValue: CodecFixedShared + Clone {}
impl<T: CodecFixedShared + Clone> FixedValue for T {}

/// A variable-size, clonable value.
pub trait VariableValue: CodecShared + Clone {}
impl<T: CodecShared + Clone> VariableValue for T {}
