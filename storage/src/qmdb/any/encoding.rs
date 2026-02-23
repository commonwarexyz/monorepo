//! Encoding type-state that captures both key and value encoding strategy.

use crate::qmdb::operation::Key;
use commonware_codec::{CodecFixedShared, CodecShared};
use commonware_utils::Array;
use std::marker::PhantomData;

mod sealed {
    use crate::qmdb::operation::Key;
    use commonware_codec::CodecShared;

    /// An encoding that captures both the key and value type, along with the encoding strategy.
    pub trait Encoding: Clone + Send + Sync {
        /// The key type.
        type Key: Key;
        /// The value type.
        type Value: CodecShared + Clone;
    }
}

pub(crate) use sealed::Encoding;

/// A fixed-size, clonable value. Shorthand for `CodecFixedShared + Clone`.
pub trait FixedVal: CodecFixedShared + Clone {}
impl<T: CodecFixedShared + Clone> FixedVal for T {}

/// A variable-size, clonable value. Shorthand for `CodecShared + Clone`.
pub trait VariableVal: CodecShared + Clone {}
impl<T: CodecShared + Clone> VariableVal for T {}

/// Fixed-size keys with fixed-size values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fixed<K: Array, V: FixedVal>(PhantomData<(K, V)>);

impl<K: Array, V: FixedVal> sealed::Encoding for Fixed<K, V> {
    type Key = K;
    type Value = V;
}

/// Fixed-size keys with variable-size values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VariableValue<K: Array, V: VariableVal>(PhantomData<(K, V)>);

impl<K: Array, V: VariableVal> sealed::Encoding for VariableValue<K, V> {
    type Key = K;
    type Value = V;
}

/// Variable-size keys with variable-size values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VariableBoth<K: Key, V: VariableVal>(PhantomData<(K, V)>);

impl<K: Key, V: VariableVal> sealed::Encoding for VariableBoth<K, V> {
    type Key = K;
    type Value = V;
}

/// Variable-size keys with fixed-size values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VariableKey<K: Key, V: FixedVal>(PhantomData<(K, V)>);

impl<K: Key, V: FixedVal> sealed::Encoding for VariableKey<K, V> {
    type Key = K;
    type Value = V;
}

/// Marker for encoding types that produce variable-size operations (as opposed to [Fixed]
/// which pads all operations to a uniform size). Used to share `EncodeSize` and `Write`
/// implementations across encoding variants.
pub(crate) trait VariableEncoding: Encoding {}
impl<K: Array, V: VariableVal> VariableEncoding for VariableValue<K, V> {}
impl<K: Key, V: VariableVal> VariableEncoding for VariableBoth<K, V> {}
impl<K: Key, V: FixedVal> VariableEncoding for VariableKey<K, V> {}
