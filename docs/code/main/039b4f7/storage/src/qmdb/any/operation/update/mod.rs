use crate::qmdb::any::value::ValueEncoding;
use commonware_utils::Array;
use std::fmt;

mod sealed {
    pub trait Sealed {}
}

mod ordered;
pub use ordered::Update as Ordered;

mod unordered;
pub use unordered::Update as Unordered;

/// An operation that updates a key-value pair.
pub trait Update<K: Array, V: ValueEncoding>: sealed::Sealed + Clone {
    /// The updated key.
    fn key(&self) -> &K;

    /// Format the update for display.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result;
}

#[cfg(test)]
mod tests {
    use super::ordered::Update as OrderedUpdate;
    use crate::qmdb::any::{
        unordered::Update as UnorderedUpdate,
        value::{FixedEncoding, VariableEncoding},
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

        let upd = OrderedUpdate::<K, FixedEncoding<V>> {
            key: FixedBytes::from([1, 2, 3, 4]),
            value: 0xdead_beef_u64,
            next_key: FixedBytes::from([4, 3, 2, 1]),
        };

        roundtrip(&upd, &());
    }

    #[test]
    fn ordered_update_variable_roundtrip() {
        type K = FixedBytes<4>;
        type V = Vec<u8>;

        let upd = OrderedUpdate::<K, VariableEncoding<V>> {
            key: FixedBytes::from([1, 2, 3, 4]),
            value: vec![1, 2, 3, 4, 5],
            next_key: FixedBytes::from([4, 3, 2, 1]),
        };

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

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;
        use commonware_utils::sequence::U64;

        commonware_conformance::conformance_tests! {
            CodecConformance<OrderedUpdate<U64, FixedEncoding<U64>>>,
            CodecConformance<OrderedUpdate<U64, VariableEncoding<Vec<u8>>>>,
            CodecConformance<UnorderedUpdate<U64, FixedEncoding<U64>>>,
            CodecConformance<UnorderedUpdate<U64, VariableEncoding<Vec<u8>>>>,
        }
    }
}
