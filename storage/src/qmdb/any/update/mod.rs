use crate::qmdb::any::value::ValueEncoding;
use commonware_utils::Array;
use std::fmt;

mod ordered;
pub use ordered::OrderedUpdate;

mod unordered;
pub use unordered::UnorderedUpdate;

/// An operation that updates a key-value pair.
pub trait Update<K: Array, V: ValueEncoding>: Clone {
    /// The updated key.
    fn key(&self) -> &K;

    /// Format the update for display.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result;
}

#[cfg(test)]
mod tests {
    use crate::qmdb::any::{
        ordered::KeyData,
        value::{FixedEncoding, VariableEncoding},
        OrderedUpdate, UnorderedUpdate,
    };
    use commonware_codec::{Codec, RangeCfg, Read};
    use commonware_utils::sequence::FixedBytes;
    use std::fmt;

    fn roundtrip<T>(value: &T, cfg: &<T as Read>::Cfg)
    where
        T: Codec + PartialEq + fmt::Debug,
    {
        let encoded = value.encode().freeze();
        let decoded = T::decode_cfg(encoded.clone(), cfg).expect("decode");
        assert_eq!(decoded, *value);
        let encoded2 = decoded.encode();
        assert_eq!(encoded, encoded2.freeze());
    }

    #[test]
    fn ordered_update_fixed_roundtrip() {
        type K = FixedBytes<4>;
        type V = u64;

        let upd = OrderedUpdate::<K, FixedEncoding<V>>(KeyData {
            key: FixedBytes::from([1, 2, 3, 4]),
            value: 0xdead_beef_u64,
            next_key: FixedBytes::from([4, 3, 2, 1]),
        });

        roundtrip(&upd, &());
    }

    #[test]
    fn ordered_update_variable_roundtrip() {
        type K = FixedBytes<4>;
        type V = Vec<u8>;

        let upd = OrderedUpdate::<K, VariableEncoding<V>>(KeyData {
            key: FixedBytes::from([1, 2, 3, 4]),
            value: vec![1, 2, 3, 4, 5],
            next_key: FixedBytes::from([4, 3, 2, 1]),
        });

        roundtrip(&upd, &(RangeCfg::from(..), ()));
    }

    #[test]
    fn unordered_update_fixed_roundtrip() {
        type K = FixedBytes<4>;
        type V = u64;

        let upd = UnorderedUpdate::<K, FixedEncoding<V>>(FixedBytes::from([7, 7, 7, 7]), 42u64);

        roundtrip(&upd, &());
    }

    #[test]
    fn unordered_update_variable_roundtrip() {
        type K = FixedBytes<4>;
        type V = Vec<u8>;

        let upd = UnorderedUpdate::<K, VariableEncoding<V>>(
            FixedBytes::from([0, 1, 2, 3]),
            vec![10, 11, 12, 13],
        );

        roundtrip(&upd, &(RangeCfg::from(..), ()));
    }
}
