//! Codec implementations for common types

use crate::{Error, Read};
use ::bytes::Buf;
use core::cmp::Ordering;

pub mod btree_map;
pub mod btree_set;
pub mod bytes;
#[cfg(feature = "std")]
pub mod hash_map;
#[cfg(feature = "std")]
pub mod hash_set;
pub mod lazy;
#[cfg(feature = "std")]
pub mod net;
pub mod primitives;
pub mod tuple;
pub mod vec;

/// Read keyed items from [Buf] in ascending order.
fn read_ordered_map<K, V, F>(
    buf: &mut impl Buf,
    len: usize,
    k_cfg: &K::Cfg,
    v_cfg: &V::Cfg,
    mut insert: F,
    map_type: &'static str,
) -> Result<(), Error>
where
    K: Read + Ord,
    V: Read,
    F: FnMut(K, V) -> Option<V>,
{
    let mut last: Option<(K, V)> = None;
    for _ in 0..len {
        // Read key
        let key = K::read_cfg(buf, k_cfg)?;

        // Check if keys are in ascending order relative to the previous key
        if let Some((ref last_key, _)) = last {
            match key.cmp(last_key) {
                Ordering::Equal => return Err(Error::Invalid(map_type, "Duplicate key")),
                Ordering::Less => return Err(Error::Invalid(map_type, "Keys must ascend")),
                _ => {}
            }
        }

        // Read value
        let value = V::read_cfg(buf, v_cfg)?;

        // Add previous item, if exists
        if let Some((last_key, last_value)) = last.take() {
            insert(last_key, last_value);
        }
        last = Some((key, value));
    }

    // Add last item, if exists
    if let Some((last_key, last_value)) = last {
        insert(last_key, last_value);
    }

    Ok(())
}

/// Read items from [Buf] in ascending order.
fn read_ordered_set<K, F>(
    buf: &mut impl Buf,
    len: usize,
    cfg: &K::Cfg,
    mut insert: F,
    set_type: &'static str,
) -> Result<(), Error>
where
    K: Read + Ord,
    F: FnMut(K) -> bool,
{
    let mut last: Option<K> = None;
    for _ in 0..len {
        // Read item
        let item = K::read_cfg(buf, cfg)?;

        // Check if items are in ascending order
        if let Some(ref last) = last {
            match item.cmp(last) {
                Ordering::Equal => return Err(Error::Invalid(set_type, "Duplicate item")),
                Ordering::Less => return Err(Error::Invalid(set_type, "Items must ascend")),
                _ => {}
            }
        }

        // Add previous item, if exists
        if let Some(last) = last.take() {
            insert(last);
        }
        last = Some(item);
    }

    // Add last item, if exists
    if let Some(last) = last {
        insert(last);
    }

    Ok(())
}
