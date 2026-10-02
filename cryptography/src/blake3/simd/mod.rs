//! BLAKE3 kernels for merkle node pairs, independent message batches.

use super::Digest;
#[cfg(target_arch = "x86_64")]
use super::gather;
#[cfg(all(not(feature = "std"), any(target_arch = "x86_64", test, doc)))]
use alloc::vec;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(any(target_arch = "x86_64", test, doc))]
use blake3::hazmat::HasherExt as _;
use blake3::{BLOCK_LEN, CHUNK_LEN, OUT_LEN};

#[cfg(all(target_arch = "aarch64", any(target_feature = "neon", feature = "std")))]
mod aarch64;
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

/// Non-root chaining values of one full chunk per lane, where lane `i` hashes
/// `inputs[i]` as chunk `counters[i]` of its message.
///
/// # Safety
///
/// The caller must establish the target features `V` requires.
///
/// # Panics
///
/// Panics if an input is shorter than [`CHUNK_LEN`].
#[cfg(any(target_arch = "x86_64", test, doc))]
#[inline(always)]
unsafe fn leaves<V: Words<L>, const L: usize>(
    inputs: [&[u8]; L],
    counters: [u64; L],
) -> [[u8; OUT_LEN]; L] {
    // SAFETY: The caller establishes the target features `V` requires.
    unsafe {
        // Load each lane's counter as the first two words of a block, which
        // places the low and high words of every lane in two vectors.
        let mut words = [[0u8; BLOCK_LEN]; L];
        for (block, counter) in words.iter_mut().zip(counters) {
            block[..8].copy_from_slice(&counter.to_le_bytes());
        }
        let words = V::load(words.each_ref());
        let counter = [words[0], words[1]];

        let mut cv = iv::<V, L>();
        let count = CHUNK_LEN / BLOCK_LEN;
        for block in 0..count {
            let flags = match block {
                0 => CHUNK_START,
                _ if block + 1 == count => CHUNK_END,
                _ => 0,
            };
            let message = V::load(blocks(inputs, block * BLOCK_LEN));
            compress_lanes(&mut cv, &message, counter, BLOCK_LEN, flags);
        }
        V::store(cv)
    }
}

/// Non-root chaining values of the last chunk of every lane's message, where
/// the messages have equal lengths and span more than one chunk.
///
/// # Safety
///
/// The caller must establish the target features `V` requires.
#[cfg(any(target_arch = "x86_64", test, doc))]
#[inline(always)]
unsafe fn tails<V: Words<L>, const L: usize>(inputs: [&[u8]; L]) -> [[u8; OUT_LEN]; L] {
    let len = inputs[0].len();
    let index = (len - 1) / CHUNK_LEN;

    // SAFETY: The caller establishes the target features `V` requires.
    unsafe { V::store(chunk(inputs, index, len - index * CHUNK_LEN, 0)) }
}

/// Parent chaining values, where lane `i` merges the two child chaining
/// values concatenated in `children[i]`.
///
/// `root` is [`ROOT`] when the parents are roots, and zero otherwise.
///
/// # Safety
///
/// The caller must establish the target features `V` requires.
#[cfg(any(target_arch = "x86_64", test, doc))]
#[inline(always)]
unsafe fn parents<V: Words<L>, const L: usize>(
    children: [&[u8; BLOCK_LEN]; L],
    root: u32,
) -> [[u8; OUT_LEN]; L] {
    // SAFETY: The caller establishes the target features `V` requires.
    unsafe {
        let mut cv = iv::<V, L>();
        compress(&mut cv, &V::load(children), 0, BLOCK_LEN, PARENT | root);
        V::store(cv)
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
#[cfg(target_arch = "x86_64")]
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
/// Returns `None` when no available kernel supports the messages.
pub(super) fn hash_many<M: AsRef<[u8]>>(messages: &[M]) -> Option<Vec<Digest>> {
    cfg_if::cfg_if! {
        if #[cfg(all(target_arch = "aarch64", any(target_feature = "neon", feature = "std")))] {
            aarch64::hash_many(messages)
        } else if #[cfg(target_arch = "x86_64")] {
            x86_64::hash_many(messages)
        } else {
            let _ = messages;
            None
        }
    }
}

/// Return whether [`hash_many`] has a general batch kernel.
#[inline]
// Feature detection is const only without std.
#[allow(clippy::missing_const_for_fn)]
fn batched() -> bool {
    cfg_if::cfg_if! {
        if #[cfg(target_arch = "x86_64")] {
            x86_64::supports_avx2()
        } else {
            false
        }
    }
}

/// Hash messages of `P` parts each, using short-message kernels where available
/// and otherwise concatenating them for the batch kernel.
///
/// Returns `None` when no kernel is available, there are fewer than two
/// messages, or their total length overflows `usize`.
pub(super) fn hash_many_parts<const P: usize>(messages: &[[&[u8]; P]]) -> Option<Vec<Digest>> {
    // Every batch kernel needs at least two messages.
    if messages.len() < 2 {
        return None;
    }
    #[cfg(target_arch = "x86_64")]
    if let [left, right] = messages
        && let Some((left, right)) = hash_pair(left, right)
    {
        return Some(vec![left, right]);
    }
    #[cfg(target_arch = "x86_64")]
    if matches!(messages.len(), 3 | 4)
        && let Some(digests) = x86_64::hash_many_parts(messages)
    {
        return Some(digests);
    }

    if !batched() {
        return None;
    }
    let len = messages
        .as_flattened()
        .iter()
        .try_fold(0usize, |len, part| len.checked_add(part.len()))?;
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

/// Lane kernels for one instruction set that hash one tree node per lane, so
/// lanes may hold nodes of different messages.
///
/// A value exists only once the instruction set is available, so the methods
/// are safe to call. Each call fills `L` lanes, of which the first `active`
/// contribute output. Spare lanes hold valid inputs, and their outputs are
/// ignored.
#[cfg(any(target_arch = "x86_64", test, doc))]
trait Nodes<const L: usize> {
    /// Non-root chaining values of one full chunk per lane, where lane `i`
    /// hashes `inputs[i]` as chunk `counters[i]` of its message.
    fn leaves(&self, inputs: [&[u8]; L], counters: [u64; L], active: usize) -> [[u8; OUT_LEN]; L];

    /// Non-root chaining values of the last chunk of every lane's message,
    /// where the messages have equal lengths and span more than one chunk.
    fn tails(&self, inputs: [&[u8]; L], active: usize) -> [[u8; OUT_LEN]; L];

    /// Parent chaining values, where lane `i` merges the two child chaining
    /// values concatenated in `children[i]`, with `root` ([`ROOT`] or zero).
    fn parents(
        &self,
        children: [&[u8; BLOCK_LEN]; L],
        root: u32,
        active: usize,
    ) -> [[u8; OUT_LEN]; L];
}

/// Split `nodes` into groups of at most `L`, each with its number of nodes.
/// Spare lanes of a group repeat its first node.
#[cfg(any(target_arch = "x86_64", test, doc))]
fn groups<T: Copy, const L: usize>(
    mut nodes: impl Iterator<Item = T>,
) -> impl Iterator<Item = ([T; L], usize)> {
    core::iter::from_fn(move || {
        let first = nodes.next()?;
        let mut group = [first; L];
        let mut active = 1;
        for (lane, node) in group[1..].iter_mut().zip(&mut nodes) {
            *lane = node;
            active += 1;
        }
        Some((group, active))
    })
}

/// Hash equal-length `messages`, each longer than one chunk, with the nodes of
/// every message's tree packed into lanes, appending the digests to
/// `digests`.
///
/// Nodes at the same tree level are independent within and across messages,
/// so each level fills lanes with the nodes of every message: first the full
/// chunks, each with its own counter, then the partial final chunks, which
/// share a counter and length. Each parent level merges adjacent pairs and
/// moves an odd last value up unchanged, which builds BLAKE3's left-balanced
/// tree, and the last level yields the roots. A lone full chunk in a group
/// uses the `blake3` crate's single-block compression, which is faster than a
/// kernel pass of spare lanes.
///
/// # Panics
///
/// Panics if the messages differ in length or span at most one chunk.
#[cfg(any(target_arch = "x86_64", test, doc))]
fn pack<K: Nodes<L>, const L: usize>(kernels: &K, messages: &[&[u8]], digests: &mut Vec<Digest>) {
    let count = messages.len();
    let len = messages[0].len();
    assert!(len > CHUNK_LEN, "packed messages span more than one chunk");
    assert!(
        messages.iter().all(|message| message.len() == len),
        "BLAKE3 lane inputs must have equal lengths"
    );
    let full = len / CHUNK_LEN;

    // Each level holds `width` chaining values per message, with node `j` of
    // message `m` at `m * width + j`, and merges into the other region of one
    // allocation.
    let mut width = len.div_ceil(CHUNK_LEN);
    let mut buffer = vec![[0u8; OUT_LEN]; count * (width + width.div_ceil(2))];
    let (mut cvs, mut next) = buffer.split_at_mut(count * width);
    let chunk = |(m, j): (usize, usize)| &messages[m][j * CHUNK_LEN..][..CHUNK_LEN];
    let nodes = (0..count).flat_map(|m| (0..full).map(move |j| (m, j)));
    for (group, active) in groups::<_, L>(nodes) {
        if active == 1 {
            let (m, j) = group[0];
            let mut hasher = blake3::Hasher::new();
            hasher.set_input_offset((j * CHUNK_LEN) as u64);
            hasher.update(chunk((m, j)));
            cvs[m * width + j] = hasher.finalize_non_root();
            continue;
        }
        let counters = group.map(|(_, j)| j as u64);
        let outputs = kernels.leaves(group.map(chunk), counters, active);
        for ((m, j), output) in group.into_iter().zip(outputs).take(active) {
            cvs[m * width + j] = output;
        }
    }
    if full < width {
        for (group, active) in groups::<_, L>(0..count) {
            let outputs = kernels.tails(group.map(|m| messages[m]), active);
            for (m, output) in group.into_iter().zip(outputs).take(active) {
                cvs[m * width + full] = output;
            }
        }
    }
    while width > 1 {
        let (pairs, merged) = (width / 2, width.div_ceil(2));
        let root = if merged == 1 { ROOT } else { 0 };
        let nodes = (0..count).flat_map(|m| (0..pairs).map(move |p| (m, p)));
        let children = |(m, p): (usize, usize)| -> &[u8; BLOCK_LEN] {
            cvs[m * width + 2 * p..][..2]
                .as_flattened()
                .try_into()
                .expect("two chaining values")
        };
        for (group, active) in groups::<_, L>(nodes) {
            let outputs = kernels.parents(group.map(children), root, active);
            for ((m, p), output) in group.into_iter().zip(outputs).take(active) {
                next[m * merged + p] = output;
            }
        }
        if width % 2 == 1 {
            for m in 0..count {
                next[m * merged + pairs] = cvs[m * width + 2 * pairs];
            }
        }
        core::mem::swap(&mut cvs, &mut next);
        width = merged;
    }
    digests.extend(cvs[..count].iter().copied().map(Digest));
}

/// Hash `messages` in batches of `L` equal-length messages with `kernel`,
/// hashing the rest individually with the [blake3] crate or with `pack`. The
/// kernel receives each batch with its number of active lanes, and may hash a
/// partial batch with a narrower kernel.
///
/// A batch of messages of fewer than 4 chunks uses the kernel when it has at
/// least two messages. A batch of longer messages uses the kernel when it has
/// more messages than chunks or fills all `L` lanes.
///
/// A batch of multi-chunk messages with fewer full chunks than lanes is
/// instead [packed](pack) when that takes strictly fewer passes over the full
/// chunks, where a pass hashes one full chunk in each lane. For `count`
/// messages of `full` full chunks, packing takes `ceil(count * full / L)`
/// passes, the kernel takes `full`, and hashing individually counts one pass
/// per message.
#[cfg(any(target_arch = "x86_64", test, doc))]
fn batch<const L: usize, M: AsRef<[u8]>>(
    messages: &[M],
    pack: impl Fn(&[&[u8]], &mut Vec<Digest>),
    kernel: impl Fn([&[u8]; L], usize) -> [[u8; OUT_LEN]; L],
) -> Vec<Digest> {
    let mut digests = Vec::with_capacity(messages.len());
    for run in messages.chunk_by(|left, right| left.as_ref().len() == right.as_ref().len()) {
        let len = run[0].as_ref().len();
        let chunks = len.div_ceil(CHUNK_LEN).max(1);
        let fill = if chunks >= 4 { chunks.min(L) } else { 1 };
        let minimum = (fill + 1).min(L);
        let full = len / CHUNK_LEN;
        for batch in run.chunks(L) {
            let individual = batch.len() < minimum;

            // Packing hashes every chunk as a non-root node, so a message of
            // one chunk never packs. A batch hashed individually counts one
            // pass per message.
            let passes = if individual { batch.len() } else { full };
            if len > CHUNK_LEN && full < L && (batch.len() * full).div_ceil(L) < passes {
                let mut inputs = [&[][..]; L];
                for (input, message) in inputs.iter_mut().zip(batch) {
                    *input = message.as_ref();
                }
                pack(&inputs[..batch.len()], &mut digests);
                continue;
            }
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
    use core::cell::RefCell;
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

    /// Portable kernels over `L` lanes that record the active lanes of each
    /// call.
    #[derive(Default)]
    struct Recorder<const L: usize> {
        hashes: RefCell<Vec<usize>>,
        leaves: RefCell<Vec<usize>>,
        tails: RefCell<Vec<usize>>,
        parents: RefCell<Vec<usize>>,
    }

    impl<const L: usize> Recorder<L> {
        /// Hash `L` equal-length messages, one per lane.
        fn hash(&self, inputs: [&[u8]; L], active: usize) -> [[u8; OUT_LEN]; L] {
            self.hashes.borrow_mut().push(active);

            // SAFETY: The portable words require no target features.
            unsafe { hash::<[u32; L], L>(inputs) }
        }

        /// Hash `messages` with [`batch`] and these kernels.
        fn batch(&self, messages: &[Vec<u8>]) -> Vec<Digest> {
            batch(
                messages,
                |messages, digests| pack(self, messages, digests),
                |inputs, active| self.hash(inputs, active),
            )
        }
    }

    impl<const L: usize> Nodes<L> for Recorder<L> {
        fn leaves(
            &self,
            inputs: [&[u8]; L],
            counters: [u64; L],
            active: usize,
        ) -> [[u8; OUT_LEN]; L] {
            self.leaves.borrow_mut().push(active);

            // SAFETY: The portable words require no target features.
            unsafe { leaves::<[u32; L], L>(inputs, counters) }
        }

        fn tails(&self, inputs: [&[u8]; L], active: usize) -> [[u8; OUT_LEN]; L] {
            self.tails.borrow_mut().push(active);

            // SAFETY: The portable words require no target features.
            unsafe { tails::<[u32; L], L>(inputs) }
        }

        fn parents(
            &self,
            children: [&[u8; BLOCK_LEN]; L],
            root: u32,
            active: usize,
        ) -> [[u8; OUT_LEN]; L] {
            self.parents.borrow_mut().push(active);

            // SAFETY: The portable words require no target features.
            unsafe { parents::<[u32; L], L>(children, root) }
        }
    }

    /// Check `hash_many` against the reference for every count up to 33 at
    /// lengths that fit the two-message kernel, pack, fall back, or end in a
    /// partial chunk.
    pub(super) fn check_batch(hash_many: impl Fn(&[Vec<u8>]) -> Vec<Digest>) {
        for len in [
            0,
            1,
            64,
            65,
            72,
            128,
            129,
            1025,
            2048,
            3072,
            4096,
            5000,
            6 * CHUNK_LEN + 1,
            16384,
            65536,
        ] {
            let messages: Vec<Vec<u8>> = (0..33).map(|lane| message(lane, len)).collect();
            let expected: Vec<Digest> = messages
                .iter()
                .map(|message| blake3::hash(message).into())
                .collect();
            for count in 1..=messages.len() {
                assert_eq!(
                    hash_many(&messages[..count]),
                    expected[..count],
                    "len={len} count={count}"
                );
            }
        }
    }

    #[test]
    fn test_portable_batch_matches_reference() {
        let kernels = Recorder::<5>::default();
        check_batch(|messages| kernels.batch(messages));
    }

    /// Check which kernels each batch uses, by the active lanes of each call
    /// to the lockstep kernel, [`Nodes::leaves`], [`Nodes::tails`], and
    /// [`Nodes::parents`].
    #[test]
    fn test_batch_packing() {
        fn check<const L: usize>(messages: &[Vec<u8>], expected: [&[usize]; 4]) {
            let kernels = Recorder::<L>::default();
            let digests: Vec<Digest> = messages
                .iter()
                .map(|message| blake3::hash(message).into())
                .collect();
            assert_eq!(kernels.batch(messages), digests);
            let calls = [
                kernels.hashes,
                kernels.leaves,
                kernels.tails,
                kernels.parents,
            ]
            .map(RefCell::into_inner);
            assert_eq!(calls, expected.map(<[usize]>::to_vec));
        }
        let run = |count: u8, len| -> Vec<Vec<u8>> { (0..count).map(|i| vec![i; len]).collect() };

        // Runs shorter than 4 chunks use the lockstep kernel for batches of
        // at least two messages, and the kernel learns how many lanes of each
        // batch are active. A single message is hashed individually.
        check::<4>(&run(6, 100), [&[4, 2], &[], &[], &[]]);
        check::<4>(&run(1, 100), [&[], &[], &[], &[]]);

        // One full chunk per message takes one pass either way.
        check::<4>(&run(3, CHUNK_LEN + 1), [&[3], &[], &[], &[]]);

        // Two messages of 3 chunks pack their 6 chunks into 2 passes instead
        // of 3, then merge one pair each, then their roots. Four messages
        // take 3 passes either way.
        check::<4>(&run(6, 3 * CHUNK_LEN), [&[4], &[4, 2], &[], &[2, 2]]);
        check::<4>(&run(3, 3 * CHUNK_LEN), [&[3], &[], &[], &[]]);

        // Partial final chunks share one pass, one message per lane.
        check::<4>(&run(2, 2 * CHUNK_LEN + 1), [&[], &[4], &[2], &[2, 2]]);

        // A lone chunk uses the `blake3` crate's compression.
        check::<5>(&run(2, 3 * CHUNK_LEN), [&[], &[5], &[], &[2, 2]]);

        // Messages of one chunk hash that chunk as the root, and messages of
        // at least one pass of full chunks save at most one pass each, so
        // neither packs.
        check::<4>(&run(2, CHUNK_LEN), [&[2], &[], &[], &[]]);
        check::<4>(&run(2, 5 * CHUNK_LEN), [&[], &[], &[], &[]]);

        // Runs of 4 or more chunks use the kernel for batches of more
        // messages than chunks or of `L` messages, and hash other batches
        // individually, unless packing takes fewer passes.
        check::<4>(&run(5, 4 * CHUNK_LEN), [&[4], &[], &[], &[]]);
        check::<4>(&run(3, 4 * CHUNK_LEN), [&[], &[], &[], &[]]);
        check::<8>(&run(2, 4 * CHUNK_LEN), [&[], &[8], &[], &[4, 2]]);
        check::<8>(&run(6, 4 * CHUNK_LEN), [&[], &[8, 8, 8], &[], &[8, 4, 6]]);
        check::<8>(&run(7, 4 * CHUNK_LEN), [&[7], &[], &[], &[]]);

        // Runs split at length changes.
        let mixed = vec![vec![0; 10], vec![1; 10], vec![2; 11], vec![3; 11]];
        check::<4>(&mixed, [&[2, 2], &[], &[], &[]]);
    }
}
