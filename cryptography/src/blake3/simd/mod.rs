//! BLAKE3 kernels for merkle node pairs, independent message batches.

use super::{Digest, gather};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use blake3::{BLOCK_LEN, CHUNK_LEN, OUT_LEN};

#[cfg(target_arch = "x86_64")]
mod x86_64;

/// The BLAKE3 initial chaining value (the SHA-256 initial hash values).
const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// The message word order of each of the 7 rounds.
const SCHEDULE: [[usize; 16]; 7] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
    [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
    [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
    [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
    [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
];

/// Domain flag for the first block of a chunk.
const CHUNK_START: u32 = 1 << 0;

/// Domain flag for the last block of a chunk.
const CHUNK_END: u32 = 1 << 1;

/// Domain flag for a parent node.
const PARENT: u32 = 1 << 2;

/// Domain flag for the root node.
const ROOT: u32 = 1 << 3;

/// Vector holding one 32-bit word for each of `LANES` messages.
///
/// All methods are unsafe because implementations may use instructions
/// from target features that the caller must establish.
trait Words<const LANES: usize>: Copy {
    /// Broadcast `word` to every lane.
    unsafe fn splat(word: u32) -> Self;

    /// Add lanewise, wrapping on overflow.
    unsafe fn add(self, other: Self) -> Self;

    /// Exclusive-or lanewise.
    unsafe fn xor(self, other: Self) -> Self;

    /// Exclusive-or lanewise, then rotate each lane right by 16 bits.
    unsafe fn xor_rotate16(self, other: Self) -> Self;

    /// Exclusive-or lanewise, then rotate each lane right by 12 bits.
    unsafe fn xor_rotate12(self, other: Self) -> Self;

    /// Exclusive-or lanewise, then rotate each lane right by 8 bits.
    unsafe fn xor_rotate8(self, other: Self) -> Self;

    /// Exclusive-or lanewise, then rotate each lane right by 7 bits.
    unsafe fn xor_rotate7(self, other: Self) -> Self;

    /// Load one block per lane as 16 little-endian message words.
    unsafe fn load(blocks: [&[u8; BLOCK_LEN]; LANES]) -> [Self; 16];

    /// Load bytes `start..start + len` of each lane's input, fewer than
    /// [`BLOCK_LEN`], zero-padded to one block, as 16 little-endian message
    /// words.
    unsafe fn load_partial(inputs: [&[u8]; LANES], start: usize, len: usize) -> [Self; 16];

    /// Store 8 chaining value words as one little-endian output per lane.
    unsafe fn store(words: [Self; 8]) -> [[u8; OUT_LEN]; LANES];
}

/// Load bytes `start..start + len` of each lane's input, zero-padded to one
/// block, by copying them into a zeroed block.
///
/// # Safety
///
/// The caller must establish the target features `V` requires.
///
/// # Panics
///
/// Panics if `len` exceeds [`BLOCK_LEN`] or an input is shorter than
/// `start + len` bytes.
#[inline(always)]
unsafe fn pad<V: Words<L>, const L: usize>(
    inputs: [&[u8]; L],
    start: usize,
    len: usize,
) -> [V; 16] {
    let mut padded = [[0u8; BLOCK_LEN]; L];
    for (padded, input) in padded.iter_mut().zip(inputs) {
        padded[..len].copy_from_slice(&input[start..start + len]);
    }

    // SAFETY: The caller establishes the target features `V` requires.
    unsafe { V::load(padded.each_ref()) }
}

/// Mix one column or diagonal of the state with two message words.
///
/// # Safety
///
/// The caller must establish the target features `V` requires.
#[inline(always)]
unsafe fn g<V: Words<L>, const L: usize>(
    state: &mut [V; 16],
    [a, b, c, d]: [usize; 4],
    x: V,
    y: V,
) {
    // SAFETY: The caller establishes the target features `V` requires.
    unsafe {
        // The value being replaced is the receiver of each fused xor-rotate,
        // so kernels whose instruction overwrites its first operand need no
        // extra copy.
        state[a] = state[a].add(state[b]).add(x);
        state[d] = state[d].xor_rotate16(state[a]);
        state[c] = state[c].add(state[d]);
        state[b] = state[b].xor_rotate12(state[c]);
        state[a] = state[a].add(state[b]).add(y);
        state[d] = state[d].xor_rotate8(state[a]);
        state[c] = state[c].add(state[d]);
        state[b] = state[b].xor_rotate7(state[c]);
    }
}

/// Mix the columns, then the diagonals, with message words in `order`.
///
/// # Safety
///
/// The caller must establish the target features `V` requires.
#[inline(always)]
unsafe fn round<V: Words<L>, const L: usize>(
    state: &mut [V; 16],
    message: &[V; 16],
    order: &[usize; 16],
) {
    // SAFETY: The caller establishes the target features `V` requires.
    unsafe {
        g(state, [0, 4, 8, 12], message[order[0]], message[order[1]]);
        g(state, [1, 5, 9, 13], message[order[2]], message[order[3]]);
        g(state, [2, 6, 10, 14], message[order[4]], message[order[5]]);
        g(state, [3, 7, 11, 15], message[order[6]], message[order[7]]);
        g(state, [0, 5, 10, 15], message[order[8]], message[order[9]]);
        g(
            state,
            [1, 6, 11, 12],
            message[order[10]],
            message[order[11]],
        );
        g(state, [2, 7, 8, 13], message[order[12]], message[order[13]]);
        g(state, [3, 4, 9, 14], message[order[14]], message[order[15]]);
    }
}

/// Compress one block per lane into the lanes' chaining values, with the
/// same counter in every lane.
///
/// # Safety
///
/// The caller must establish the target features `V` requires.
#[inline(always)]
unsafe fn compress<V: Words<L>, const L: usize>(
    cv: &mut [V; 8],
    message: &[V; 16],
    counter: u64,
    len: usize,
    flags: u32,
) {
    // SAFETY: The caller establishes the target features `V` requires.
    unsafe {
        let counter = [V::splat(counter as u32), V::splat((counter >> 32) as u32)];
        compress_lanes(cv, message, counter, len, flags);
    }
}

/// Compress one block per lane into the lanes' chaining values, with each
/// lane's counter split into its low and high words.
///
/// # Safety
///
/// The caller must establish the target features `V` requires.
#[inline(always)]
unsafe fn compress_lanes<V: Words<L>, const L: usize>(
    cv: &mut [V; 8],
    message: &[V; 16],
    [counter_low, counter_high]: [V; 2],
    len: usize,
    flags: u32,
) {
    // SAFETY: The caller establishes the target features `V` requires.
    unsafe {
        let mut state = [
            cv[0],
            cv[1],
            cv[2],
            cv[3],
            cv[4],
            cv[5],
            cv[6],
            cv[7],
            V::splat(IV[0]),
            V::splat(IV[1]),
            V::splat(IV[2]),
            V::splat(IV[3]),
            counter_low,
            counter_high,
            V::splat(len as u32),
            V::splat(flags),
        ];
        round(&mut state, message, &SCHEDULE[0]);
        round(&mut state, message, &SCHEDULE[1]);
        round(&mut state, message, &SCHEDULE[2]);
        round(&mut state, message, &SCHEDULE[3]);
        round(&mut state, message, &SCHEDULE[4]);
        round(&mut state, message, &SCHEDULE[5]);
        round(&mut state, message, &SCHEDULE[6]);
        for (i, word) in cv.iter_mut().enumerate() {
            *word = state[i].xor(state[i + 8]);
        }
    }
}

/// Broadcast the initial chaining value to every lane.
///
/// # Safety
///
/// The caller must establish the target features `V` requires.
#[inline(always)]
unsafe fn iv<V: Words<L>, const L: usize>() -> [V; 8] {
    // SAFETY: The caller establishes the target features `V` requires.
    unsafe {
        [
            V::splat(IV[0]),
            V::splat(IV[1]),
            V::splat(IV[2]),
            V::splat(IV[3]),
            V::splat(IV[4]),
            V::splat(IV[5]),
            V::splat(IV[6]),
            V::splat(IV[7]),
        ]
    }
}

/// Borrow bytes `start..start + BLOCK_LEN` of every lane's input.
///
/// # Panics
///
/// Panics if an input is shorter than `start + BLOCK_LEN` bytes.
#[inline(always)]
fn blocks<const L: usize>(inputs: [&[u8]; L], start: usize) -> [&[u8; BLOCK_LEN]; L] {
    let mut blocks = [&[0u8; BLOCK_LEN]; L];
    for (block, input) in blocks.iter_mut().zip(inputs) {
        *block = input[start..start + BLOCK_LEN]
            .try_into()
            .expect("block is BLOCK_LEN bytes");
    }
    blocks
}

/// Compute the chaining value of chunk `index` (`len` bytes) of every lane.
///
/// `root` is [`ROOT`] when the chunk is the whole message, and zero otherwise.
///
/// # Safety
///
/// The caller must establish the target features `V` requires.
#[inline(always)]
unsafe fn chunk<V: Words<L>, const L: usize>(
    inputs: [&[u8]; L],
    index: usize,
    len: usize,
    root: u32,
) -> [V; 8] {
    let offset = index * CHUNK_LEN;
    let count = len.div_ceil(BLOCK_LEN).max(1);

    // SAFETY: The caller establishes the target features `V` requires.
    unsafe {
        let mut cv = iv::<V, L>();
        for block in 0..count {
            let start = offset + block * BLOCK_LEN;
            let block_len = (len - block * BLOCK_LEN).min(BLOCK_LEN);
            let mut flags = if block == 0 { CHUNK_START } else { 0 };
            if block + 1 == count {
                flags |= CHUNK_END | root;
            }
            let message = if block_len == BLOCK_LEN {
                V::load(blocks(inputs, start))
            } else {
                // The final block of the message is zero-padded.
                V::load_partial(inputs, start, block_len)
            };
            compress(&mut cv, &message, index as u64, block_len, flags);
        }
        cv
    }
}

/// Merge the chaining values of two sibling subtrees of every lane.
///
/// # Safety
///
/// The caller must establish the target features `V` requires.
#[inline(always)]
unsafe fn parent<V: Words<L>, const L: usize>(left: [V; 8], right: [V; 8], root: u32) -> [V; 8] {
    let message = [
        left[0], left[1], left[2], left[3], left[4], left[5], left[6], left[7], right[0], right[1],
        right[2], right[3], right[4], right[5], right[6], right[7],
    ];

    // SAFETY: The caller establishes the target features `V` requires.
    unsafe {
        let mut cv = iv::<V, L>();
        compress(&mut cv, &message, 0, BLOCK_LEN, PARENT | root);
        cv
    }
}

/// Hash `L` equal-length messages, one per lane.
///
/// Equal lengths give every lane the same tree, so each chunk and parent
/// compression advances all lanes at once.
///
/// # Safety
///
/// The caller must establish the target features `V` requires.
#[inline(always)]
unsafe fn hash<V: Words<L>, const L: usize>(inputs: [&[u8]; L]) -> [[u8; OUT_LEN]; L] {
    let len = inputs[0].len();
    assert!(
        inputs[1..].iter().all(|input| input.len() == len),
        "BLAKE3 lane inputs must have equal lengths"
    );
    let chunks = len.div_ceil(CHUNK_LEN).max(1);

    // SAFETY: The caller establishes the target features `V` requires.
    unsafe {
        // Stack of left subtrees awaiting their right siblings, merged as soon
        // as a subtree completes (one merge per trailing zero of the number of
        // chunks hashed so far). The final chunk may be partial and is merged
        // after the loop.
        let mut stack: Vec<[V; 8]> = Vec::new();
        for index in 0..chunks - 1 {
            let mut cv = chunk(inputs, index, CHUNK_LEN, 0);
            for _ in 0..(index + 1).trailing_zeros() {
                let left = stack.pop().expect("completed subtree has a left sibling");
                cv = parent(left, cv, 0);
            }
            stack.push(cv);
        }
        let offset = (chunks - 1) * CHUNK_LEN;
        let root = if stack.is_empty() { ROOT } else { 0 };
        let mut cv = chunk(inputs, chunks - 1, len - offset, root);
        while let Some(left) = stack.pop() {
            let root = if stack.is_empty() { ROOT } else { 0 };
            cv = parent(left, cv, root);
        }
        V::store(cv)
    }
}

/// Hash two messages, each given as parts, with the pair kernel for the
/// current CPU.
///
/// Returns `None` when no kernel is available, the messages differ in length,
/// or either exceeds [`PAIR_LEN`](super::PAIR_LEN) bytes.
#[inline]
pub(super) fn hash_pair(left: &[&[u8]], right: &[&[u8]]) -> Option<(Digest, Digest)> {
    cfg_if::cfg_if! {
        if #[cfg(target_arch = "x86_64")] {
            let [left, right] = x86_64::hash_pair(left, right)?;
            Some((Digest(left), Digest(right)))
        } else {
            let _ = (left, right);
            None
        }
    }
}

/// Hash independent messages with the widest batch kernel for the current CPU.
///
/// Returns `None` exactly when no kernel is available.
pub(super) fn hash_many<M: AsRef<[u8]>>(messages: &[M]) -> Option<Vec<Digest>> {
    cfg_if::cfg_if! {
        if #[cfg(target_arch = "x86_64")] {
            x86_64::hash_many(messages)
        } else {
            let _ = messages;
            None
        }
    }
}

/// Hash `messages` in batches of `L` equal-length messages with `kernel`,
/// hashing the rest individually with the [blake3] crate. The
/// kernel receives each batch with its number of active lanes, and may hash a
/// partial batch with a narrower kernel.
///
/// A batch of messages of fewer than 4 chunks uses the kernel when it has at
/// least two messages. A batch of longer messages uses the kernel when it has
/// more messages than chunks or fills all `L` lanes.
///
fn batch<const L: usize, M: AsRef<[u8]>>(
    messages: &[M],
    kernel: impl Fn([&[u8]; L], usize) -> [[u8; OUT_LEN]; L],
) -> Vec<Digest> {
    let mut digests = Vec::with_capacity(messages.len());
    for run in messages.chunk_by(|left, right| left.as_ref().len() == right.as_ref().len()) {
        let len = run[0].as_ref().len();
        let chunks = len.div_ceil(CHUNK_LEN).max(1);
        let fill = if chunks >= 4 { chunks.min(L) } else { 1 };
        let minimum = (fill + 1).min(L);
        for batch in run.chunks(L) {
            let individual = batch.len() < minimum;

            if individual {
                digests.extend(
                    batch
                        .iter()
                        .map(|message| Digest::from(blake3::hash(message.as_ref()))),
                );
                continue;
            }

            // Spare lanes borrow the first input. Only active lanes contribute output.
            let mut inputs = [batch[0].as_ref(); L];
            for (input, message) in inputs[1..].iter_mut().zip(&batch[1..]) {
                *input = message.as_ref();
            }
            let outputs = kernel(inputs, batch.len());
            digests.extend(outputs[..batch.len()].iter().copied().map(Digest));
        }
    }
    digests
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::TestRng;
    use rand::Rng as _;

    // Scalar words provide the reference implementation for the kernel tests.
    impl<const L: usize> Words<L> for [u32; L] {
        #[inline(always)]
        unsafe fn splat(word: u32) -> Self {
            [word; L]
        }

        #[inline(always)]
        unsafe fn add(self, other: Self) -> Self {
            core::array::from_fn(|lane| self[lane].wrapping_add(other[lane]))
        }

        #[inline(always)]
        unsafe fn xor(self, other: Self) -> Self {
            core::array::from_fn(|lane| self[lane] ^ other[lane])
        }

        #[inline(always)]
        unsafe fn xor_rotate16(self, other: Self) -> Self {
            core::array::from_fn(|lane| (self[lane] ^ other[lane]).rotate_right(16))
        }

        #[inline(always)]
        unsafe fn xor_rotate12(self, other: Self) -> Self {
            core::array::from_fn(|lane| (self[lane] ^ other[lane]).rotate_right(12))
        }

        #[inline(always)]
        unsafe fn xor_rotate8(self, other: Self) -> Self {
            core::array::from_fn(|lane| (self[lane] ^ other[lane]).rotate_right(8))
        }

        #[inline(always)]
        unsafe fn xor_rotate7(self, other: Self) -> Self {
            core::array::from_fn(|lane| (self[lane] ^ other[lane]).rotate_right(7))
        }

        #[inline(always)]
        unsafe fn load(blocks: [&[u8; BLOCK_LEN]; L]) -> [Self; 16] {
            let mut words = [[0u32; L]; 16];
            for (lane, block) in blocks.iter().enumerate() {
                for (word, bytes) in words.iter_mut().zip(block.as_chunks::<4>().0) {
                    word[lane] = u32::from_le_bytes(*bytes);
                }
            }
            words
        }

        #[inline(always)]
        unsafe fn load_partial(inputs: [&[u8]; L], start: usize, len: usize) -> [Self; 16] {
            // SAFETY: The portable words require no target features.
            unsafe { super::pad(inputs, start, len) }
        }

        #[inline(always)]
        unsafe fn store(words: [Self; 8]) -> [[u8; OUT_LEN]; L] {
            core::array::from_fn(|lane| {
                let mut output = [0u8; OUT_LEN];
                for (chunk, word) in output.as_chunks_mut::<4>().0.iter_mut().zip(words) {
                    *chunk = word[lane].to_le_bytes();
                }
                output
            })
        }
    }

    /// Message lengths around block, chunk, and tree-shape boundaries.
    pub(super) fn lengths() -> impl Iterator<Item = usize> {
        (0..=129).chain([
            191,
            192,
            193,
            1023,
            1024,
            1025,
            2047,
            2048,
            2049,
            3 * CHUNK_LEN,
            3 * CHUNK_LEN + 1,
            4 * CHUNK_LEN,
            4 * CHUNK_LEN + 1,
            5 * CHUNK_LEN - 1,
            6 * CHUNK_LEN + 1,
            7 * CHUNK_LEN,
            7 * CHUNK_LEN + 65,
            8 * CHUNK_LEN,
            8 * CHUNK_LEN + 1,
            9 * CHUNK_LEN,
            16 * CHUNK_LEN,
            16 * CHUNK_LEN + 1,
            17 * CHUNK_LEN,
        ])
    }

    /// Return lane `lane`'s `len`-byte test message. Random bytes do not
    /// repeat within or across chunks, so a kernel reading the wrong chunk,
    /// block, or lane produces a different digest.
    fn message(lane: usize, len: usize) -> Vec<u8> {
        let mut message = vec![0; len];
        TestRng::new(lane as u64).fill_bytes(&mut message);
        message
    }

    /// Check a lane hasher against the reference for every length in [`lengths`].
    pub(super) fn check_lanes<const L: usize>(hash: impl Fn([&[u8]; L]) -> [[u8; OUT_LEN]; L]) {
        for len in lengths() {
            let messages: [Vec<u8>; L] = core::array::from_fn(|lane| message(lane, len));
            let outputs = hash(messages.each_ref().map(Vec::as_slice));
            for (message, output) in messages.iter().zip(outputs) {
                assert_eq!(output, *blake3::hash(message).as_bytes(), "len {len}");
            }
        }
    }

    #[test]
    fn test_portable_lanes_match_reference() {
        // SAFETY: The portable words require no target features.
        check_lanes::<1>(|inputs| unsafe { hash::<[u32; 1], 1>(inputs) });

        // SAFETY: The portable words require no target features.
        check_lanes::<2>(|inputs| unsafe { hash::<[u32; 2], 2>(inputs) });

        // SAFETY: The portable words require no target features.
        check_lanes::<5>(|inputs| unsafe { hash::<[u32; 5], 5>(inputs) });
    }

    #[test]
    #[should_panic(expected = "equal lengths")]
    fn test_unequal_lanes_panic() {
        let (short, long) = ([0u8; 1], [0u8; 2]);

        // SAFETY: The portable words require no target features.
        unsafe { hash::<[u32; 2], 2>([&short, &long]) };
    }
}
