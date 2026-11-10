//! Type-state for operations with fixed or variable size.

use commonware_codec::{CodecFixedShared, CodecShared};
use std::marker::PhantomData;

/// A wrapper around a value to indicate whether it is fixed or variable size.
/// Having separate wrappers for fixed and variable size values allows us to use the same
/// operation type for both fixed and variable size values, while still being able to
/// parameterize the operation encoding by the value type.
pub trait ValueEncoding: Clone + Send + Sync + 'static {
    /// The wrapped value type.
    type Value: CodecShared + Clone + 'static;
}

/// Selects the fixed-size encoding of `V`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixedEncoding<V: FixedValue>(PhantomData<V>);

impl<V: FixedValue> ValueEncoding for FixedEncoding<V> {
    type Value = V;
}

/// Selects the variable-size encoding of `V`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VariableEncoding<V: VariableValue>(PhantomData<V>);

impl<V: VariableValue> ValueEncoding for VariableEncoding<V> {
    type Value = V;
}

/// A fixed-size, clonable value.
pub trait FixedValue: CodecFixedShared + Clone + 'static {}
impl<T: CodecFixedShared + Clone + 'static> FixedValue for T {}

/// A variable-size, clonable value.
pub trait VariableValue: CodecShared + Clone + 'static {}
impl<T: CodecShared + Clone + 'static> VariableValue for T {}
