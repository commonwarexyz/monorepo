//! Utilities for storage tests and fuzz targets.

use commonware_utils::bitmap::BitMap;
use std::{collections::BTreeMap, num::NonZeroU64};
#[cfg(test)]
use {
    commonware_codec::{Error as CodecError, FixedSize, Read, Write},
    commonware_parallel::{Rayon, Strategy as _},
    commonware_runtime::{Buf, BufMut},
    commonware_utils::sync::Mutex,
    std::{
        sync::{Arc, mpsc},
        thread,
        time::Duration,
    },
};

/// Occupy `workers` Rayon workers until the returned sender is dropped.
#[cfg(test)]
pub(crate) fn block_rayon(strategy: &Rayon, workers: usize) -> mpsc::Sender<()> {
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let release_rx = Arc::new(Mutex::new(release_rx));
    for _ in 0..workers {
        let started_tx = started_tx.clone();
        let release_rx = Arc::clone(&release_rx);
        drop(strategy.spawn(move |_| {
            started_tx.send(()).unwrap();
            let _ = release_rx.lock().recv();
        }));
    }
    drop(started_tx);
    for _ in 0..workers {
        started_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("strategy worker did not start");
    }
    release_tx
}

/// An item that preserves `T`'s encoding and reports whether its tracked instance unwound.
#[cfg(test)]
pub(crate) struct DropMonitor<T> {
    inner: T,
    clean_drop: Option<mpsc::Sender<bool>>,
}

#[cfg(test)]
impl<T> DropMonitor<T> {
    /// Create an item that does not report when it is dropped.
    pub(crate) const fn untracked(inner: T) -> Self {
        Self {
            inner,
            clean_drop: None,
        }
    }

    /// Create an item and a receiver that reports whether it was dropped outside an unwind.
    pub(crate) fn tracked(inner: T) -> (Self, mpsc::Receiver<bool>) {
        let (clean_drop, receiver) = mpsc::channel();
        (
            Self {
                inner,
                clean_drop: Some(clean_drop),
            },
            receiver,
        )
    }
}

#[cfg(test)]
impl<T: FixedSize> FixedSize for DropMonitor<T> {
    const SIZE: usize = T::SIZE;
}

#[cfg(test)]
impl<T: Write> Write for DropMonitor<T> {
    fn write(&self, buf: &mut impl BufMut) {
        self.inner.write(buf);
    }
}

#[cfg(test)]
impl<T: Read> Read for DropMonitor<T> {
    type Cfg = T::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        T::read_cfg(buf, cfg).map(Self::untracked)
    }
}

#[cfg(test)]
impl<T> Drop for DropMonitor<T> {
    fn drop(&mut self) {
        if let Some(clean_drop) = self.clean_drop.take() {
            let _ = clean_drop.send(!thread::panicking());
        }
    }
}

/// Build ordinal recovery bitmaps from absolute item indices.
///
/// Each index maps to blob `index / items_per_blob` and sets bit
/// `index % items_per_blob` in that blob's bitmap of `items_per_blob` bits.
pub fn bits_for_indices<const N: usize>(
    items_per_blob: NonZeroU64,
    indices: impl IntoIterator<Item = u64>,
) -> BTreeMap<u64, Option<BitMap<N>>> {
    let items_per_blob = items_per_blob.get();
    let mut bits = BTreeMap::new();
    for index in indices {
        let blob = index / items_per_blob;
        let offset = index % items_per_blob;
        bits.entry(blob)
            .or_insert_with(|| Some(BitMap::zeroes(items_per_blob)))
            .as_mut()
            .unwrap()
            .set(offset, true);
    }
    bits
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::NZU64;

    #[test]
    fn test_bits_for_indices() {
        let empty = bits_for_indices::<1>(NZU64!(10), core::iter::empty());
        assert!(empty.is_empty());

        let bits = bits_for_indices::<1>(NZU64!(10), [0, 1, 9, 10, 25]);
        assert_eq!(bits.len(), 3);

        let blob_0 = bits.get(&0).unwrap().as_ref().unwrap();
        assert_eq!(blob_0.len(), 10);
        assert_eq!(blob_0.count_ones(), 3);
        assert!(blob_0.get(0));
        assert!(blob_0.get(1));
        assert!(blob_0.get(9));

        let blob_1 = bits.get(&1).unwrap().as_ref().unwrap();
        assert_eq!(blob_1.len(), 10);
        assert_eq!(blob_1.count_ones(), 1);
        assert!(blob_1.get(0));

        let blob_2 = bits.get(&2).unwrap().as_ref().unwrap();
        assert_eq!(blob_2.len(), 10);
        assert_eq!(blob_2.count_ones(), 1);
        assert!(blob_2.get(5));
    }
}
