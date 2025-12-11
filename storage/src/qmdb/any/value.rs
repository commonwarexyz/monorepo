//! Type-state for operations with fixed or variable size.

use commonware_codec::{Codec, CodecFixed};
use std::marker::PhantomData;

mod sealed {
    use commonware_codec::Codec;

    /// A fixed size or variable size value.
    pub trait ValueEncoding: Clone {
        /// The wrapped value type.
        type Value: Codec + Clone;
    }
}

pub(crate) use sealed::ValueEncoding;

/// A fixed size value.
#[derive(Clone, Debug, PartialEq)]
pub struct FixedEncoding<V: FixedValue>(PhantomData<V>);

impl<V: FixedValue> sealed::ValueEncoding for FixedEncoding<V> {
    type Value = V;
}

/// A variable size value.
#[derive(Clone, Debug, PartialEq)]
pub struct VariableEncoding<V: VariableValue>(PhantomData<V>);

impl<V: VariableValue> sealed::ValueEncoding for VariableEncoding<V> {
    type Value = V;
}

/// A fixed-size, clonable value.
pub trait FixedValue: CodecFixed<Cfg = ()> + Clone {}
impl<T: CodecFixed<Cfg = ()> + Clone> FixedValue for T {}

/// A variable-size, clonable value.
pub trait VariableValue: Codec + Clone {}
impl<T: Codec + Clone> VariableValue for T {}
