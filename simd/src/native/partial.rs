//! Scalar helpers that touch exactly the bytes of a short slice in partial vector loads and
//! stores.

/// Loads `input` into the low bytes of a little-endian word and zero-fills the rest.
///
/// The bits of the length select at most one 4-byte, one 2-byte, and one 1-byte read, so each
/// byte is read exactly once and no byte outside `input` is touched.
///
/// # Panics
///
/// Panics if `input.len() >= 8`.
#[inline(always)]
pub(super) fn load_below_8(input: &[u8]) -> u64 {
    let len = input.len();
    assert!(len < 8);
    let ptr = input.as_ptr();
    let mut word = 0u64;
    let mut offset = 0;
    if len & 4 != 0 {
        // SAFETY: Bit 2 of len is set, so len >= 4 and the first four bytes are readable.
        word = u32::from_le(unsafe { ptr.cast::<u32>().read_unaligned() }) as u64;
        offset = 4;
    }
    if len & 2 != 0 {
        // SAFETY: The bytes consumed so far plus this piece total at most len, so the two
        // bytes at offset are readable.
        let piece = u16::from_le(unsafe { ptr.add(offset).cast::<u16>().read_unaligned() });
        word |= (piece as u64) << (8 * offset);
        offset += 2;
    }
    if len & 1 != 0 {
        // SAFETY: Offset equals len with bit 0 cleared, so the byte at offset is the last
        // readable byte.
        word |= (unsafe { ptr.add(offset).read() } as u64) << (8 * offset);
    }
    word
}

/// Stores the low `output.len()` bytes of a little-endian word into `output`.
///
/// The bits of the length select at most one 4-byte, one 2-byte, and one 1-byte write, so
/// each output byte is written exactly once and no byte outside `output` is touched.
///
/// # Panics
///
/// Panics if `output.len() >= 8`.
#[inline(always)]
pub(super) fn store_below_8(word: u64, output: &mut [u8]) {
    let len = output.len();
    assert!(len < 8);
    let ptr = output.as_mut_ptr();
    let mut offset = 0;
    if len & 4 != 0 {
        // SAFETY: Bit 2 of len is set, so len >= 4 and the first four bytes are writable.
        unsafe { ptr.cast::<u32>().write_unaligned((word as u32).to_le()) };
        offset = 4;
    }
    if len & 2 != 0 {
        // SAFETY: The bytes written so far plus this piece total at most len, so the two
        // bytes at offset are writable.
        unsafe {
            ptr.add(offset)
                .cast::<u16>()
                .write_unaligned(((word >> (8 * offset)) as u16).to_le());
        }
        offset += 2;
    }
    if len & 1 != 0 {
        // SAFETY: Offset equals len with bit 0 cleared, so the byte at offset is the last
        // writable byte.
        unsafe { ptr.add(offset).write((word >> (8 * offset)) as u8) };
    }
}
