use crate::qmdb::any::value::{FixedEncoding, VariableEncoding};

pub use crate::qmdb::any::operation::{Unordered as Operation, UnorderedUpdate as Update};

pub type FixedOperation<K, V> = Operation<K, FixedEncoding<V>>;
pub type VariableOperation<K, V> = Operation<K, VariableEncoding<V>>;
