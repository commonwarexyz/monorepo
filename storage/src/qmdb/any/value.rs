//! Type-state for operations with fixed or variable size.

use commonware_codec::{Codec, CodecFixed};
use std::marker::PhantomData;

mod sealed {
    use commonware_codec::Codec;

    /// A wrapper around a value to indicate whether it is fixed or variable size.
    /// Having separate wrappers for fixed and variable size values allows us to use the same
    /// operation type for both fixed and variable size values, while still being able to
    /// parameterize the operation encoding by the value type.
    pub trait ValueEncoding: Clone + Send + Sync {
        /// The wrapped value type.
        type Value: Codec + Clone + Send + Sync;
    }
}

pub(crate) use sealed::ValueEncoding;

/// A fixed-size, clonable value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixedEncoding<V: FixedValue>(PhantomData<V>);

impl<V: FixedValue> sealed::ValueEncoding for FixedEncoding<V> {
    type Value = V;
}

/// A variable-size, clonable value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VariableEncoding<V: VariableValue>(PhantomData<V>);

impl<V: VariableValue> sealed::ValueEncoding for VariableEncoding<V> {
    type Value = V;
}

/// A fixed-size, clonable value.
pub trait FixedValue: CodecFixed<Cfg = ()> + Clone + Send + Sync {}
impl<T: CodecFixed<Cfg = ()> + Clone + Send + Sync> FixedValue for T {}

/// A variable-size, clonable value.
pub trait VariableValue: Codec + Clone + Send + Sync {}
impl<T: Codec + Clone + Send + Sync> VariableValue for T {}
