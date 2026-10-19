//! Synchronous decoding of one fixed-size journal item whose bytes are already in memory.

use commonware_codec::{CodecFixedShared, Copying, DecodeExt as _};
use commonware_utils::Cached;

// Reusable scratch for items larger than [`STACK_SIZE`], grown to the largest item served on
// the thread.
commonware_utils::thread_local_cache!(static SCRATCH: Vec<u8>);

/// Largest item [`decode_sync`] reads into a stack buffer instead of a thread-local scratch.
pub(super) const STACK_SIZE: usize = 128;

/// Decode an `A` from the `A::SIZE` bytes `read_into` copies into the buffer it is given,
/// returning `None` if `read_into` reports the bytes are not in memory or they fail to decode.
pub(super) fn decode_sync<A: CodecFixedShared>(
    read_into: impl FnOnce(&mut [u8]) -> bool,
) -> Option<A> {
    let decode = |buf: &mut [u8]| {
        if read_into(buf) {
            A::decode(Copying(buf)).ok()
        } else {
            None
        }
    };
    // Small items fit on the stack, skipping the thread-local scratch handoff.
    if const { A::SIZE <= STACK_SIZE } {
        decode(&mut [0u8; STACK_SIZE][..A::SIZE])
    } else {
        let mut scratch = Cached::take(&SCRATCH, || Ok::<_, ()>(Vec::new()), |_| Ok(())).unwrap();
        if scratch.len() < A::SIZE {
            scratch.resize(A::SIZE, 0);
        }
        decode(&mut scratch[..A::SIZE])
    }
}
