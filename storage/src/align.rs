//! Offset alignment utilities for storage.
//!
//! These utilities allow storing byte offsets as `u32` values by dividing by an alignment
//! factor. This trades some wasted space (padding) for reduced memory usage when tracking
//! many offsets.
//!
//! # Example
//!
//! With 16-byte alignment:
//! - Max addressable size: `u32::MAX * 16 = ~64GB`
//! - Padding waste: up to 15 bytes per entry

use crate::journal::Error;

/// Alignment for offset storage (16 bytes).
///
/// With 16-byte alignment, u32 offsets can address ~64GB per section.
/// This matches typical CPU cache line alignment and keeps padding minimal.
pub const ALIGNMENT: u64 = 16;

/// Convert a byte offset to an aligned u32 offset.
///
/// The byte offset must be aligned (divisible by `ALIGNMENT`).
/// Panics in debug mode if the offset is not aligned.
#[inline]
pub fn to_aligned(byte_offset: u64) -> Result<u32, Error> {
    debug_assert_eq!(
        byte_offset % ALIGNMENT,
        0,
        "byte_offset must be aligned to {}",
        ALIGNMENT
    );
    let aligned = byte_offset / ALIGNMENT;
    aligned.try_into().map_err(|_| Error::OffsetOverflow)
}

/// Convert an aligned u32 offset back to a byte offset.
#[inline]
pub const fn from_aligned(aligned: u32) -> u64 {
    aligned as u64 * ALIGNMENT
}

/// Calculate padding needed to align a size to the next alignment boundary.
///
/// Returns 0 if the size is already aligned.
#[inline]
pub const fn padding_for(size: u64) -> u64 {
    let remainder = size % ALIGNMENT;
    if remainder == 0 {
        0
    } else {
        ALIGNMENT - remainder
    }
}

/// Round up a size to the next alignment boundary.
#[inline]
pub const fn align_up(size: u64) -> u64 {
    size + padding_for(size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_aligned() {
        assert_eq!(to_aligned(0).unwrap(), 0);
        assert_eq!(to_aligned(16).unwrap(), 1);
        assert_eq!(to_aligned(32).unwrap(), 2);
        assert_eq!(to_aligned(4096).unwrap(), 256);
    }

    #[test]
    fn test_from_aligned() {
        assert_eq!(from_aligned(0), 0);
        assert_eq!(from_aligned(1), 16);
        assert_eq!(from_aligned(2), 32);
        assert_eq!(from_aligned(256), 4096);
    }

    #[test]
    fn test_roundtrip() {
        for i in 0..1000u64 {
            let byte_offset = i * ALIGNMENT;
            let aligned = to_aligned(byte_offset).unwrap();
            assert_eq!(from_aligned(aligned), byte_offset);
        }
    }

    #[test]
    fn test_padding_for() {
        assert_eq!(padding_for(0), 0);
        assert_eq!(padding_for(1), 15);
        assert_eq!(padding_for(15), 1);
        assert_eq!(padding_for(16), 0);
        assert_eq!(padding_for(17), 15);
        assert_eq!(padding_for(32), 0);
    }

    #[test]
    fn test_align_up() {
        assert_eq!(align_up(0), 0);
        assert_eq!(align_up(1), 16);
        assert_eq!(align_up(15), 16);
        assert_eq!(align_up(16), 16);
        assert_eq!(align_up(17), 32);
        assert_eq!(align_up(32), 32);
    }

    #[test]
    fn test_max_addressable() {
        let max_bytes = u32::MAX as u64 * ALIGNMENT;
        // u32::MAX * 16 = ~64GB (minus 16 bytes)
        assert!(max_bytes > 63 * 1024 * 1024 * 1024);
    }
}
