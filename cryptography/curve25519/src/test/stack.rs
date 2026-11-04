//! Probes of the dead stack below a caller, for checking what the secret operations leave behind.
//!
//! A probe paints a span of stack below its own frame, runs an operation there, and reads the span
//! back. It assumes a downward-growing stack and reads memory outside every live frame, so it
//! cannot run under Miri, and it only describes release builds: at opt-level 0, frames are many
//! times larger than in optimized code.

use core::{hint::black_box, mem::MaybeUninit};

/// Bytes of dead stack read back below the probe's frame.
const SPAN: usize = 1 << 16;

/// The byte the dead stack is painted with before the operation runs.
const PAINT: u8 = 0xA5;

/// Bytes of frame that [`run`] keeps between the probe's frame and the operation's frames, so that
/// reading the span back cannot overwrite what the operation left at the top of it.
const SPACER: usize = 256;

/// Writes [`PAINT`] over the dead stack below the caller's frame, past the span that [`read`]
/// copies out, so that every byte of that span starts out painted.
#[inline(never)]
fn paint() {
    let mut buffer = MaybeUninit::<[u8; SPAN + 1024]>::uninit();
    let start = buffer.as_mut_ptr().cast::<u8>();
    for i in 0..SPAN + 1024 {
        // SAFETY: `start` points at the `SPAN + 1024` bytes of `buffer`, in this frame.
        unsafe { start.add(i).write_volatile(PAINT) };
    }
    black_box(&buffer);
}

/// Runs `op` below a frame of at least [`SPACER`] bytes.
#[inline(never)]
fn run<T>(op: impl FnOnce() -> T) -> T {
    let spacer = MaybeUninit::<[u8; SPACER]>::uninit();
    black_box(&spacer);
    op()
}

/// Copies the [`SPAN`] bytes of dead stack below the caller's frame into `span`, deepest first.
///
/// The copy makes no calls of its own, so the only disturbance to the span is this frame's few
/// locals, and those lie within the spacer [`run`] left.
#[inline(never)]
fn read(span: &mut [u8]) {
    let marker = 0u8;
    let top = black_box(&marker) as *const u8 as usize;
    for (i, byte) in span.iter_mut().enumerate() {
        // SAFETY: the address lies within the thread's stack, between the caller's frame and the
        // span [`paint`] wrote, so it is mapped and readable, if outside every live frame.
        *byte = unsafe { ((top - SPAN + i) as *const u8).read_volatile() };
    }
}

/// Runs `op` below a painted span of stack and returns its result with the span as the operation
/// left it, deepest byte first.
#[inline(never)]
pub(crate) fn probe<T>(op: impl FnOnce() -> T) -> (T, Vec<u8>) {
    let mut span = vec![0u8; SPAN];
    paint();
    let result = run(op);
    read(&mut span);
    (result, span)
}

/// Returns how deep below its caller's frame the operation reached, within a few dozen bytes:
/// the distance from the top of the span to its deepest byte that lost the paint, less the
/// spacer frame the operation ran beneath.
pub(crate) fn depth(span: &[u8]) -> usize {
    span.iter()
        .position(|&byte| byte != PAINT)
        .map_or(0, |deepest| (span.len() - deepest).saturating_sub(SPACER))
}

/// Returns whether the operation cleared `budget` bytes of stack below its caller's frame: every
/// byte from 1 KiB below that frame down to 64 bytes short of the budget is zero. The margins
/// leave room for the scrub frame's own linkage and for anything the operation runs after the
/// scrub, such as returning through a few more frames.
pub(crate) fn scrubbed(span: &[u8], budget: usize) -> bool {
    let top = span.len() - SPACER;
    span[top - budget + 64..top - 1024]
        .iter()
        .all(|&byte| byte == 0)
}

/// Returns whether `pattern` appears anywhere in the span.
pub(crate) fn contains(span: &[u8], pattern: &[u8]) -> bool {
    span.windows(pattern.len()).any(|window| window == pattern)
}

/// Returns `bytes` with each 8-byte word reversed, the layout of a SHA-512 input block or state
/// word held in memory.
pub(crate) fn words_swapped(bytes: &[u8]) -> Vec<u8> {
    bytes
        .chunks(8)
        .flat_map(|word| word.iter().rev().copied())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{contains, depth, probe, scrubbed};
    use crate::STACK_SCRUB_BYTES;
    use core::hint::black_box;
    use zeroize::zeroize_stack;

    /// Copies `secret` into a local and leaves it there.
    #[inline(never)]
    fn leak(secret: &[u8; 32]) {
        let copy = *secret;
        black_box(&copy);
    }

    /// The probe reads back what an operation left, measures how deep it reached, and tells a
    /// scrubbed span from an unscrubbed one.
    #[test]
    fn probe_reads_back_what_an_operation_leaves() {
        let secret: [u8; 32] = core::array::from_fn(|i| 7 * i as u8 + 1);
        let (_, span) = probe(|| leak(&secret));
        assert!(contains(&span, &secret));
        assert!(!scrubbed(&span, STACK_SCRUB_BYTES));
        let reached = depth(&span);
        assert!(
            (32..1024).contains(&reached),
            "leak reached {reached} bytes"
        );

        let (_, span) = probe(|| ());
        assert!(!contains(&span, &secret));
        assert!(!scrubbed(&span, STACK_SCRUB_BYTES));
        let reached = depth(&span);
        assert!(reached < 256, "an empty operation reached {reached} bytes");

        let (_, span) = probe(|| {
            leak(&secret);
            zeroize_stack::<STACK_SCRUB_BYTES>();
        });
        assert!(!contains(&span, &secret));
        assert!(scrubbed(&span, STACK_SCRUB_BYTES));
    }
}
