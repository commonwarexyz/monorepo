//! Index implementations that partition the key space across multiple sub-indices based on a
//! fixed-size prefix of the key to reduce the average number of bytes required per key/value
//! stored.
//!
//! # Example
//!
//! A 2-byte key prefix results in 2^16 = 64K partitions, each independently indexed using the
//! remaining bytes of the key. This reduces the average number of bytes required per key/value
//! stored by the size of the prefix, or 2 bytes in this example.
//!
//! Partitioning introduces an up-front fixed RAM cost to pre-allocate the sub-indices corresponding
//! to each partition. This makes a 2-byte prefix efficient only when indexing a large number (>>
//! 2^16) of values, whereas a 1-byte prefix (involving pre-allocation of only 256 sub-indices)
//! could be useful for smaller datasets. Larger prefix lengths are unlikely to be practical, and
//! values larger than 3 will fail to compile.

pub mod ordered;
pub mod unordered;

// Because the prefix length has a max of 3, we can safely use a 4-byte int for the index type
// used by prefix conversion.
const INDEX_INT_SIZE: usize = 4;

/// Get the partition index for the given key, along with the prefix-stripped key for probing
/// the referenced partition. The returned index value is in the range `[0, 2^(P*8) - 1]`.
fn partition_index_and_sub_key<const P: usize>(key: &[u8]) -> (usize, &[u8]) {
    // TODO: Re-evaluate assertion placement after `generic_const_exprs` is stable.
    const {
        assert!(P > 0, "P must be greater than 0");
        assert!(P <= 3, "P must be 3 or less");
    }
    let copy_len = P.min(key.len());

    let mut bytes = [0u8; INDEX_INT_SIZE];
    bytes[INDEX_INT_SIZE - copy_len..].copy_from_slice(&key[..copy_len]);

    (u32::from_be_bytes(bytes) as usize, &key[copy_len..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_partitioned_prefix_length_1() {
        const PREFIX_LENGTH: usize = 1;

        let key = [];
        let (index, sub_key) = partition_index_and_sub_key::<PREFIX_LENGTH>(&key);
        assert_eq!(index, 0);
        assert_eq!(sub_key, b"");

        let key = [0x01];
        let (index, sub_key) = partition_index_and_sub_key::<PREFIX_LENGTH>(&key);
        assert_eq!(index, 1);
        assert_eq!(sub_key, b"");

        let key = [0x00, 0x01];
        let (index, sub_key) = partition_index_and_sub_key::<PREFIX_LENGTH>(&key);
        assert_eq!(index, 0);
        assert_eq!(sub_key, &[0x01]);

        let key = [0x00, 0x00, 0x01];
        let (index, sub_key) = partition_index_and_sub_key::<PREFIX_LENGTH>(&key);
        assert_eq!(index, 0);
        assert_eq!(sub_key, &[0x00, 0x01]);
    }

    #[test]
    fn test_partitioned_prefix_length_2() {
        const PREFIX_LENGTH: usize = 2;

        let key = [];
        let (index, sub_key) = partition_index_and_sub_key::<PREFIX_LENGTH>(&key);
        assert_eq!(index, 0);
        assert_eq!(sub_key, b"");

        let key = [0x01]; // Key shorter than the prefix should act as 0 padded.
        let (index, sub_key) = partition_index_and_sub_key::<PREFIX_LENGTH>(&key);
        assert_eq!(index, 1);
        assert_eq!(sub_key, b"");

        let key = [0x00, 0x01];
        let (index, sub_key) = partition_index_and_sub_key::<PREFIX_LENGTH>(&key);
        assert_eq!(index, 1);
        assert_eq!(sub_key, b"");

        let key = [0x00, 0xFF, 0x01];
        let (index, sub_key) = partition_index_and_sub_key::<PREFIX_LENGTH>(&key);
        assert_eq!(index, 0xFF);
        assert_eq!(sub_key, &[0x01]);

        let key = [0x01, 0xFF, 0x02]; // Bytes after the prefix should be ignored.
        let (index, sub_key) = partition_index_and_sub_key::<PREFIX_LENGTH>(&key);
        assert_eq!(index, (0x01 << 8) | (0xFF));
        assert_eq!(sub_key, &[0x02]);
    }

    #[test]
    fn test_partitioned_prefix_length_3() {
        const PREFIX_LENGTH: usize = 3;

        let key = [];
        let (index, sub_key) = partition_index_and_sub_key::<PREFIX_LENGTH>(&key);
        assert_eq!(index, 0);
        assert_eq!(sub_key, b"");

        let key = [0x01]; // Key shorter than the prefix should act as 0 padded.
        let (index, sub_key) = partition_index_and_sub_key::<PREFIX_LENGTH>(&key);
        assert_eq!(index, 1);
        assert_eq!(sub_key, b"");

        let key = [0x00, 0x01];
        let (index, sub_key) = partition_index_and_sub_key::<PREFIX_LENGTH>(&key);
        assert_eq!(index, 1);
        assert_eq!(sub_key, b"");

        let key = [0x00, 0x01, 0x02];
        let (index, sub_key) = partition_index_and_sub_key::<PREFIX_LENGTH>(&key);
        assert_eq!(index, (0x01 << 8) | 0x02);
        assert_eq!(sub_key, b"");

        let key = [0x00, 0x01, 0x02, 0x03];
        let (index, sub_key) = partition_index_and_sub_key::<PREFIX_LENGTH>(&key);
        assert_eq!(index, (0x01 << 8) | 0x02);
        assert_eq!(sub_key, &[0x03]);

        let key = [0x01, 0xFF, 0xAB, 0xCD, 0xEF];
        let (index, sub_key) = partition_index_and_sub_key::<PREFIX_LENGTH>(&key);
        assert_eq!(index, (0x01 << 16) | (0xFF << 8) | 0xAB);
        assert_eq!(sub_key, &[0xCD, 0xEF]);
    }
}
