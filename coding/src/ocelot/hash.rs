//! Recursive shard hashing with an original-length commitment.

use commonware_codec::{
    EncodeSize, FixedSize, Write,
    varint::{MAX_U64_VARINT_SIZE, UInt},
};
use commonware_cryptography::Hasher;
use commonware_parallel::{Manual, Strategy};

/// Maximum number of input bytes hashed at each reduction node.
const CHUNK_SIZE: usize = 1024;

/// Minimum input per scheduling tile, independent of the committed chunk size.
const TILE_BYTES: usize = 64 * 1024;

/// Hash equally sized shards, partitioning work across rows and within each row.
pub fn shards<H: Hasher>(
    data: &[impl AsRef<[u8]> + Sync],
    strategy: &impl Strategy,
) -> Vec<H::Digest> {
    const {
        assert!(H::Digest::SIZE > 0 && H::Digest::SIZE <= CHUNK_SIZE / 2);
    }
    let Some(first) = data.first() else {
        return Vec::new();
    };
    let len = first.as_ref().len();
    assert!(data.iter().all(|shard| shard.as_ref().len() == len));
    strategy.run(
        len.saturating_mul(data.len()),
        || {
            data.iter()
                .map(|shard| serial::<H>(shard.as_ref()))
                .collect()
        },
        || {
            let strategy = strategy.manual();
            if data.len() >= strategy.parallelism() || len <= TILE_BYTES {
                return strategy.map_collect_vec(data, |shard| serial::<H>(shard.as_ref()));
            }

            let inputs: Vec<_> = data.iter().map(AsRef::as_ref).collect();
            let mut level = reduce::<H>(&inputs, &strategy);
            let mut width = level.len() / data.len();
            while width > TILE_BYTES {
                let inputs: Vec<_> = level.chunks_exact(width).collect();
                level = reduce::<H>(&inputs, &strategy);
                width = level.len() / data.len();
            }
            strategy.map_collect_vec(level.chunks_exact_mut(width), |row| finish::<H>(len, row))
        },
    )
}

/// Hash a single shard using the same tiling as a batch with one row.
pub fn shard<H: Hasher>(data: &[u8], strategy: &impl Strategy) -> H::Digest {
    if data.len() <= TILE_BYTES {
        return serial::<H>(data);
    }
    shards::<H>(&[data], strategy).pop().unwrap()
}

/// Give each task a contiguous interval of the row-major chunk space. Task
/// starts are evenly spaced across shards or within a shard, while each task
/// streams through its input and writes a disjoint range of digest slots.
fn reduce<H: Hasher>(data: &[&[u8]], strategy: &Manual<impl Strategy>) -> Vec<u8> {
    let width = data[0].len();
    let chunks = width.div_ceil(CHUNK_SIZE);
    let total = chunks
        .checked_mul(data.len())
        .expect("too many hash chunks");
    let jobs = strategy
        .parallelism()
        .min((total / (TILE_BYTES / CHUNK_SIZE)).max(1));
    let mut output = vec![
        0;
        total
            .checked_mul(H::Digest::SIZE)
            .expect("hash buffer overflow")
    ];
    let mut remaining = output.as_mut_slice();
    let mut start = 0;
    let mut tiles = Vec::with_capacity(jobs);
    for job in 0..jobs {
        let slots = total / jobs + usize::from(job < total % jobs);
        let (tile, rest) = remaining.split_at_mut(slots * H::Digest::SIZE);
        tiles.push((start, tile));
        start += slots;
        remaining = rest;
    }
    strategy.map_collect_vec(tiles, |(start_chunk, output)| {
        // Generic digest widths cannot be used as array lengths.
        #[allow(unknown_lints, clippy::chunks_exact_to_as_chunks)]
        for (offset, digest) in output.chunks_exact_mut(H::Digest::SIZE).enumerate() {
            let chunk = start_chunk + offset;
            let row = chunk / chunks;
            let start = (chunk % chunks) * CHUNK_SIZE;
            let end = start + CHUNK_SIZE.min(width - start);
            digest.copy_from_slice(H::hash(&[&data[row][start..end]]).as_ref());
        }
    });
    output
}

/// Reduce consecutive chunks to digests until at most one chunk remains, then
/// hash the original byte length as a `UInt<u64>` followed by the remaining bytes.
/// The original length fixes every reduction's shape and separates raw input
/// from buffers of child digests. Final chunks are not padded.
fn serial<H: Hasher>(data: &[u8]) -> H::Digest {
    const {
        assert!(H::Digest::SIZE > 0 && H::Digest::SIZE <= CHUNK_SIZE / 2);
    }

    if data.len() <= CHUNK_SIZE {
        return root::<H>(data.len(), data);
    }

    let mut level = Vec::with_capacity(data.len().div_ceil(CHUNK_SIZE) * H::Digest::SIZE);
    for chunk in data.chunks(CHUNK_SIZE) {
        level.extend_from_slice(H::hash(&[chunk]).as_ref());
    }

    finish::<H>(data.len(), &mut level)
}

fn finish<H: Hasher>(original_len: usize, level: &mut [u8]) -> H::Digest {
    let mut len = level.len();
    while len > CHUNK_SIZE {
        for (index, start) in (0..len).step_by(CHUNK_SIZE).enumerate() {
            let end = (start + CHUNK_SIZE).min(len);
            let digest = H::hash(&[&level[start..end]]);
            // Digest writes stay behind the next unread chunk.
            let output = index * H::Digest::SIZE;
            level[output..output + H::Digest::SIZE].copy_from_slice(digest.as_ref());
        }
        len = len.div_ceil(CHUNK_SIZE) * H::Digest::SIZE;
    }
    root::<H>(original_len, &level[..len])
}

fn root<H: Hasher>(original_len: usize, data: &[u8]) -> H::Digest {
    let length = UInt(original_len as u64);
    let mut prefix = [0; MAX_U64_VARINT_SIZE];
    length.write(&mut &mut prefix[..]);
    H::hash(&[&prefix[..length.encode_size()], data])
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{Sha256, blake3::Blake3};
    use commonware_parallel::{Rayon, Sequential};
    use commonware_utils::NZUsize;

    fn check_parallel<H: Hasher>() {
        let pools = [NZUsize!(1), NZUsize!(3), NZUsize!(4)]
            .map(|workers| Rayon::new(workers).unwrap().manual());
        for rows in [1, 2, 3, 7] {
            for len in [
                0,
                1024,
                1025,
                TILE_BYTES - 1,
                TILE_BYTES,
                TILE_BYTES + 1,
                2 * 1024 * 1024 + 1,
            ] {
                let data: Vec<Vec<u8>> = (0..rows)
                    .map(|row| (0..len).map(|i| ((i + row) % 251) as u8).collect())
                    .collect();
                let expected = shards::<H>(&data, &Sequential);
                for strategy in &pools {
                    assert_eq!(
                        shards::<H>(&data, strategy),
                        expected,
                        "rows={rows} len={len}"
                    );
                    assert_eq!(shard::<H>(&data[0], strategy), expected[0], "len={len}");
                }
            }
        }
        assert!(shards::<H>(&[] as &[&[u8]], &pools[0]).is_empty());
    }

    #[test]
    fn parallel_matches_sequential() {
        check_parallel::<Sha256>();
        check_parallel::<Blake3>();
    }

    #[test]
    fn sha256_vectors() {
        // Independently generated with SHA-256 and unsigned LEB128 framing.
        for (len, expected) in [
            (
                0,
                "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
            ),
            (
                1,
                "47dc540c94ceb704a23875c11273e16bb0b8a87aed84de911f2133568115f254",
            ),
            (
                127,
                "cf91fd5bb06aa5fad3b283fbce9fb8e4cfd8381a294664ae01bb9439c0a70958",
            ),
            (
                128,
                "08f4ebdcdd7e7c86d97a0bde419940dfcc276b8ce6fe9f272fc005bfbf0df142",
            ),
            (
                1023,
                "d7c698107dda6879c660d1f6b1b8e7111a3e8e9178c8f64cfee187b712bddd22",
            ),
            (
                1024,
                "661d526d9acba1ea39be47f93d2a497c5b42fab350c0f02e76a7665eb7b6a712",
            ),
            (
                1025,
                "c4c483e607967ffe82d01bad48570c0c2138b8e751ca51e828e0566e47e307e2",
            ),
            (
                32768,
                "e18a36b24b52b383561b19646c52625cb81512b255b85b2df345ccb07a9fddd9",
            ),
            (
                32769,
                "ef762e3e99ea8839e64d54f5519dcb40e94495fe89182e7705f9cbeaa11d76df",
            ),
            (
                1048576,
                "3f7530aecf32b4327a6232a3938be43f055d5f9366ded1aed7e1d9adbd1762df",
            ),
            (
                1048577,
                "2f39abd76a15a4e24493d35f6260401742eef41a4b1317e1c0fc5d02b3e98df2",
            ),
        ] {
            let data: Vec<_> = (0..len).map(|i| (i % 251) as u8).collect();
            assert_eq!(
                shard::<Sha256>(&data, &Sequential).to_string(),
                expected,
                "len={len}"
            );
        }
    }

    fn check_length_binding<H: Hasher>() {
        for len in [1025, 32769, 1048577] {
            let mut data: Vec<_> = (0..len).map(|i| (i % 251) as u8).collect();
            let root = shard::<H>(&data, &Sequential);
            while data.len() > CHUNK_SIZE {
                data = data
                    .chunks(CHUNK_SIZE)
                    .flat_map(|chunk| H::hash(&[chunk]).as_ref().to_vec())
                    .collect();
                assert_ne!(root, shard::<H>(&data, &Sequential), "len={len}");
            }
        }
    }

    #[test]
    fn binds_original_length() {
        check_length_binding::<Sha256>();
        check_length_binding::<Blake3>();
    }
}
