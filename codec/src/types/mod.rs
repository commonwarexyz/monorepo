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
