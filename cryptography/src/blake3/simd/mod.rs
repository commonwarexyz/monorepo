//! BLAKE3 kernels for merkle node pairs and independent message batches.
//!
//! The batch kernels hash one message per SIMD lane: each vector holds the
//! same state word of every message, so a single instruction advances every
//! message at once. Messages of equal length share the same chunk and parent
//! structure, so the whole tree (chunk compressions and parent merges) runs in
//! lockstep across lanes. This fills vectors even when each message is too
//! short for BLAKE3's chunk-level parallelism within a single message.
//!
//! AVX-512 hashes 16 messages per batch, AVX2 8, and NEON 4. Node pairs use
//! a two-message kernel: on x86_64, AVX2 holds one message's state rows in
//! each 128-bit half of a vector, and on aarch64 two interleaved scalar lanes
//! give the core independent work to overlap.
//!
//! Kernel code keeps intrinsics out of closures: a closure does not inherit
//! its caller's target features, so intrinsics inside it compile to
//! out-of-line calls.

use super::{Digest, gather};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use blake3::{BLOCK_LEN, CHUNK_LEN, OUT_LEN};

// The NEON words load and store little-endian lanes.
#[cfg(all(
    target_arch = "aarch64",
    target_endian = "little",
    any(target_feature = "neon", feature = "std"),
))]
mod aarch64;
#[cfg(any(test, target_arch = "aarch64"))]
mod portable;
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

    /// Rotate each lane right by 16 bits.
    unsafe fn rotate16(self) -> Self;

    /// Rotate each lane right by 12 bits.
    unsafe fn rotate12(self) -> Self;

    /// Rotate each lane right by 8 bits.
    unsafe fn rotate8(self) -> Self;

    /// Rotate each lane right by 7 bits.
    unsafe fn rotate7(self) -> Self;

    /// Load one block per lane as 16 little-endian message words.
    unsafe fn load(blocks: [&[u8; BLOCK_LEN]; LANES]) -> [Self; 16];

    /// Store 8 chaining value words as one little-endian output per lane.
    unsafe fn store(words: [Self; 8]) -> [[u8; OUT_LEN]; LANES];
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
        state[a] = state[a].add(state[b]).add(x);
        state[d] = state[d].xor(state[a]).rotate16();
        state[c] = state[c].add(state[d]);
        state[b] = state[b].xor(state[c]).rotate12();
        state[a] = state[a].add(state[b]).add(y);
        state[d] = state[d].xor(state[a]).rotate8();
        state[c] = state[c].add(state[d]);
        state[b] = state[b].xor(state[c]).rotate7();
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

/// Compress one block per lane into the lanes' chaining values.
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
            V::splat(counter as u32),
            V::splat((counter >> 32) as u32),
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
    let blocks = len.div_ceil(BLOCK_LEN).max(1);

    // SAFETY: The caller establishes the target features `V` requires.
    unsafe {
        let mut cv = iv::<V, L>();
        for block in 0..blocks {
            let start = offset + block * BLOCK_LEN;
            let block_len = (len - block * BLOCK_LEN).min(BLOCK_LEN);
            let mut flags = if block == 0 { CHUNK_START } else { 0 };
            if block + 1 == blocks {
                flags |= CHUNK_END | root;
            }
            let message = if block_len == BLOCK_LEN {
                let mut blocks = [&[0u8; BLOCK_LEN]; L];
                for (block, input) in blocks.iter_mut().zip(inputs) {
                    *block = input[start..start + BLOCK_LEN]
                        .try_into()
                        .expect("block is BLOCK_LEN bytes");
                }
                V::load(blocks)
            } else {
                // The final block of the message is zero-padded.
                let mut padded = [[0u8; BLOCK_LEN]; L];
                for (padded, input) in padded.iter_mut().zip(inputs) {
                    padded[..block_len].copy_from_slice(&input[start..start + block_len]);
                }
                V::load(padded.each_ref())
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
    let (left, len) = gather(left)?;
    let (right, right_len) = gather(right)?;
    if len != right_len {
        return None;
    }

    cfg_if::cfg_if! {
        if #[cfg(target_arch = "aarch64")] {
            // Two interleaved scalar lanes outrun a half-empty NEON batch.
            // SAFETY: The portable words require no target features.
            let [left, right] = unsafe { hash::<[u32; 2], 2>([&left[..len], &right[..len]]) };
        } else if #[cfg(target_arch = "x86_64")] {
            let [left, right] = x86_64::hash_pair(&left, &right, len)?;
        }
    }
    Some((Digest(left), Digest(right)))
}

/// Hash independent messages with the widest batch kernel for the current CPU.
///
/// Returns `None` when no kernel is available.
pub(super) fn hash_many<M: AsRef<[u8]>>(messages: &[M]) -> Option<Vec<Digest>> {
    cfg_if::cfg_if! {
        if #[cfg(all(
            target_arch = "aarch64",
            target_endian = "little",
            any(target_feature = "neon", feature = "std"),
        ))] {
            aarch64::hash_many(messages)
        } else if #[cfg(target_arch = "x86_64")] {
            x86_64::hash_many(messages)
        } else {
            let _ = messages;
            None
        }
    }
}

/// Hash messages of `P` parts each with the widest batch kernel for the
/// current CPU, first concatenating every message into one shared buffer.
///
/// Returns `None` when no kernel is available or there are fewer than two
/// messages.
pub(super) fn hash_many_parts<const P: usize>(messages: &[[&[u8]; P]]) -> Option<Vec<Digest>> {
    // Every batch kernel needs at least two messages.
    if messages.len() < 2 {
        return None;
    }
    let len = messages.iter().flatten().map(|part| part.len()).sum();
    let mut buffer = Vec::with_capacity(len);
    let mut ends = Vec::with_capacity(messages.len());
    for parts in messages {
        for part in parts {
            buffer.extend_from_slice(part);
        }
        ends.push(buffer.len());
    }
    let mut start = 0;
    let slices: Vec<&[u8]> = ends
        .into_iter()
        .map(|end| {
            let slice = &buffer[start..end];
            start = end;
            slice
        })
        .collect();
    hash_many(&slices)
}

/// Hash `messages` in batches of `L` equal-length messages with `kernel`,
/// hashing the rest individually.
///
/// A batch uses the kernel when it has at least `minimum` messages and more
/// active lanes than hashing each message individually would fill. The
/// [blake3] crate hashes a message's chunks in SIMD lanes once it has at least
/// 4 of them, filling `min(chunks, L)` lanes, and hashes shorter messages one
/// block at a time.
fn batch<const L: usize, M: AsRef<[u8]>>(
    messages: &[M],
    minimum: usize,
    kernel: impl Fn([&[u8]; L]) -> [[u8; OUT_LEN]; L],
) -> Vec<Digest> {
    let mut digests = Vec::with_capacity(messages.len());
    for run in messages.chunk_by(|left, right| left.as_ref().len() == right.as_ref().len()) {
        let chunks = run[0].as_ref().len().div_ceil(CHUNK_LEN).max(1);
        let fill = if chunks >= 4 { chunks.min(L) } else { 1 };
        let minimum = minimum.max((fill + 1).min(L));
        for batch in run.chunks(L) {
            if batch.len() < minimum {
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
            let outputs = kernel(inputs);
            digests.extend(outputs[..batch.len()].iter().copied().map(Digest));
        }
    }
    digests
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// Byte `i` of lane `lane`'s test message. The sequence does not repeat
    /// within a chunk or across chunks, so a kernel reading the wrong chunk,
    /// block, or lane produces a different digest.
    pub(super) fn byte(lane: usize, i: usize) -> u8 {
        ((i as u32).wrapping_mul(0x9E37_79B1) >> 24) as u8 ^ (i >> 10) as u8 ^ lane as u8
    }

    /// Check a lane hasher against the reference for every length in [`lengths`].
    pub(super) fn check_lanes<const L: usize>(hash: impl Fn([&[u8]; L]) -> [[u8; OUT_LEN]; L]) {
        for len in lengths() {
            let messages: [Vec<u8>; L] =
                core::array::from_fn(|lane| (0..len).map(|i| byte(lane, i)).collect());
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
    fn test_kernels_dispatch() {
        cfg_if::cfg_if! {
            if #[cfg(target_arch = "aarch64")] {
                let (pair, many) = (true, std::arch::is_aarch64_feature_detected!("neon"));
            } else {
                let avx2 = std::arch::is_x86_feature_detected!("avx2");
                let (pair, many) = (avx2, avx2);
            }
        }
        for len in [0, 64, 72, 128] {
            let (left, right) = (vec![1u8; len], vec![2u8; len]);
            assert_eq!(hash_pair(&[&left], &[&right]).is_some(), pair, "len {len}");
        }
        assert!(hash_pair(&[&[0u8; 64]], &[&[0u8; 65]]).is_none());
        assert!(hash_pair(&[&[0u8; 129]], &[&[0u8; 129]]).is_none());
        assert_eq!(hash_many(&[[0u8; 64]; 16]).is_some(), many);
    }

    #[test]
    #[should_panic(expected = "equal lengths")]
    fn test_unequal_lanes_panic() {
        let (short, long) = ([0u8; 1], [0u8; 2]);

        // SAFETY: The portable words require no target features.
        unsafe { hash::<[u32; 2], 2>([&short, &long]) };
    }

    #[test]
    fn test_batch_minimum() {
        let calls = core::cell::Cell::new(0);
        let kernel = |inputs: [&[u8]; 4]| {
            calls.set(calls.get() + 1);
            inputs.map(|input| *blake3::hash(input).as_bytes())
        };
        let check = |messages: &[Vec<u8>], minimum, expected_calls| {
            calls.set(0);
            let expected: Vec<Digest> = messages
                .iter()
                .map(|message| blake3::hash(message).into())
                .collect();
            assert_eq!(batch(messages, minimum, kernel), expected);
            assert_eq!(calls.get(), expected_calls);
        };

        // Runs shorter than 4 chunks batch once they reach the minimum and fill
        // more than one lane.
        let short: Vec<Vec<u8>> = (0..6).map(|i| vec![i; 100]).collect();
        check(&short, 2, 2);
        check(&short, 3, 1);
        check(&short[..1], 1, 0);
        let three: Vec<Vec<u8>> = (0..6).map(|i| vec![i; 3 * CHUNK_LEN]).collect();
        check(&three, 1, 2);
        check(&three[..1], 1, 0);

        // Runs of 4 or more chunks already fill lanes individually, so they
        // need full batches.
        let long: Vec<Vec<u8>> = (0..7).map(|i| vec![i; 4 * CHUNK_LEN]).collect();
        check(&long, 1, 1);
        check(&long[..3], 1, 0);

        // Runs split at length changes.
        let mixed = vec![vec![0; 10], vec![1; 10], vec![2; 11], vec![3; 11]];
        check(&mixed, 2, 2);
    }
}
