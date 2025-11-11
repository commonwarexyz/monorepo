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

pub mod unordered;
