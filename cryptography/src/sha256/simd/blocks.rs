use crate::sha256::BLOCK_LENGTH;
use core::slice::Iter;

/// Reads a message, given as parts, one block at a time.
pub(super) struct Blocks<'a> {
    /// Parts not yet started.
    parts: Iter<'a, &'a [u8]>,
    /// The unread rest of the current part.
    part: &'a [u8],
    /// Scratch for a block that spans parts.
    block: [u8; BLOCK_LENGTH],
}

impl<'a> Blocks<'a> {
    /// Start reading the message `parts`.
    pub(super) fn new(parts: &'a [&'a [u8]]) -> Self {
        Self {
            parts: parts.iter(),
            part: &[],
            block: [0; BLOCK_LENGTH],
        }
    }

    /// Return the next full block, borrowed in place when the current part
    /// holds all of it.
    ///
    /// # Panics
    ///
    /// Panics if fewer than [`BLOCK_LENGTH`] bytes remain.
    #[inline(always)]
    pub(super) fn next(&mut self) -> &[u8; BLOCK_LENGTH] {
        // Start the next part, so a block at its start is borrowed in place.
        if self.part.is_empty() {
            self.part = self.parts.next().copied().unwrap_or_default();
        }
        let part = self.part;
        if let Some((block, rest)) = part.split_first_chunk() {
            self.part = rest;
            return block;
        }
        let Self { parts, part, block } = self;
        fill(parts, part, block);
        block
    }

    /// Pad the final `len % BLOCK_LENGTH` bytes of a `len`-byte message,
    /// returning the padding blocks and how many of them are used.
    ///
    /// # Panics
    ///
    /// Panics if fewer than `len % BLOCK_LENGTH` bytes remain.
    #[inline(always)]
    pub(super) fn finish(mut self, len: usize) -> ([u8; 2 * BLOCK_LENGTH], usize) {
        let remainder = len % BLOCK_LENGTH;
        let mut padding = [0u8; 2 * BLOCK_LENGTH];
        fill(&mut self.parts, &mut self.part, &mut padding[..remainder]);
        padding[remainder] = 0x80;
        let end = if remainder < BLOCK_LENGTH - 8 {
            BLOCK_LENGTH
        } else {
            2 * BLOCK_LENGTH
        };
        padding[end - 8..end].copy_from_slice(&(len as u64).wrapping_mul(8).to_be_bytes());
        (padding, end / BLOCK_LENGTH)
    }
}

/// Copy the next `out.len()` bytes of a message into `out`, starting with the
/// rest of `part` and continuing through `parts`.
///
/// # Panics
///
/// Panics if fewer than `out.len()` bytes remain.
#[inline(always)]
fn fill<'a>(parts: &mut Iter<'a, &'a [u8]>, part: &mut &'a [u8], out: &mut [u8]) {
    let mut filled = 0;
    while filled < out.len() {
        if part.is_empty() {
            *part = *parts.next().expect("message shorter than its length");
        }
        let (head, rest) = part.split_at(part.len().min(out.len() - filled));
        out[filled..filled + head.len()].copy_from_slice(head);
        filled += head.len();
        *part = rest;
    }
}
