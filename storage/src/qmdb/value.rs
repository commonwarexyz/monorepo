//! Type-state for operations with fixed or variable size.

use commonware_codec::{CodecFixedShared, CodecShared};
use std::marker::PhantomData;

mod sealed {
    pub trait Sealed {}
}

/// Selects how an operation encodes its value: at a fixed size or at a variable size.
///
/// The implementors are markers, so one operation type serves both encodings and this parameter
/// picks its codec. The trait is sealed because the databases can store only the encodings
/// defined here.
pub trait ValueEncoding: sealed::Sealed + Clone + Send + Sync + 'static {
    /// The type of the encoded value.
    type Value: CodecShared + Clone + 'static;
}

/// Selects the fixed-size encoding of `V`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixedEncoding<V: FixedValue>(PhantomData<V>);

impl<V: FixedValue> sealed::Sealed for FixedEncoding<V> {}

impl<V: FixedValue> ValueEncoding for FixedEncoding<V> {
    type Value = V;
}

/// Selects the variable-size encoding of `V`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VariableEncoding<V: VariableValue>(PhantomData<V>);

impl<V: VariableValue> sealed::Sealed for VariableEncoding<V> {}

impl<V: VariableValue> ValueEncoding for VariableEncoding<V> {
    type Value = V;
}

/// A fixed-size, clonable value.
pub trait FixedValue: CodecFixedShared + Clone + 'static {}
impl<T: CodecFixedShared + Clone + 'static> FixedValue for T {}

/// A variable-size, clonable value.
pub trait VariableValue: CodecShared + Clone + 'static {}
impl<T: CodecShared + Clone + 'static> VariableValue for T {}
