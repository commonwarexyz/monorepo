//! An index for mapping translated keys to values.
//!
//! # Multiple Values for a Key
//!
//! Keys are translated into a compressed, fixed-size representation using a [Translator]. Depending
//! on the size of the representation, this can lead to a non-negligible number of collisions (even
//! if the original keys are collision-free). To workaround this issue, `get` returns all values
//! that map to the same translated key. If the same key is inserted multiple times (and old values
//! are not `removed`), all values will be returned.
//!
//! # Warning
//!
//! If the [Translator] maps many keys to the same translated key, the performance of an index will
//! degrade substantially (each conflicting key may contain the desired value).

pub mod journaled;
pub mod mem;
pub mod translator;

use std::hash::{BuildHasher, Hash};

/// Translate keys into an internal representation used by `Index`.
///
/// # Warning
///
/// The output of `transform` is used as the key in a hash table. If the output is not uniformly
/// distributed, the performance of [Index] will degrade substantially.
pub trait Translator: Clone + BuildHasher {
    /// The type of the internal representation of keys.
    ///
    /// Although `Translator` is a [BuildHasher], the `Key` type must still implement [Hash] for compatibility
    /// with the [std::collections::HashMap] used internally by [Index].
    type Key: Eq + Hash + Copy;

    /// Transform a key into its internal representation.
    fn transform(&self, key: &[u8]) -> Self::Key;
}
