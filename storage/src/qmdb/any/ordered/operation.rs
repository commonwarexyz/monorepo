pub use crate::qmdb::any::operation::{update::Ordered as OrderedUpdate, Ordered as Operation};
use crate::qmdb::any::value::{FixedEncoding, VariableEncoding};

pub type FixedOperation<K, V> = Operation<K, FixedEncoding<V>>;
pub type VariableOperation<K, V> = Operation<K, VariableEncoding<V>>;
