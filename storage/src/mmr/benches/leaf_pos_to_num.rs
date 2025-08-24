use commonware_storage::mmr::iterator::{leaf_num_to_pos, leaf_pos_to_num};
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, Rng, SeedableRng};

const ITERATIONS: usize = 1_000_000;

fn bench_leaf_pos_to_num(c: &mut Criterion) {
    for n in [1_000_000, 1_000_000_000, 1_000_000_000_000] {
        // Generate random elements
        let mut rng = StdRng::seed_from_u64(0);
        for version in [1, 2, 3, 4] {
            c.bench_function(
                &format!("{}/n={}/algo={}", module_path!(), n, version),
                |b| {
                    b.iter(|| {
                        for _ in 0..ITERATIONS {
                            let pos = rng.gen_range(0..n);
                            match version {
                                1 => leaf_pos_to_num(pos),
                                2 => leaf_pos_to_num_3_refinements(pos),
                                3 => leaf_pos_to_num_binary_search(pos),
                                4 => leaf_pos_to_num_tree_traversal(pos),
                                _ => unreachable!(),
                            };
                        }
                    });
                },
            );
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_leaf_pos_to_num
}

// Apply the refinement function three times in the straightforward way (constant time).
#[inline]
pub(crate) const fn leaf_pos_to_num_3_refinements(leaf_pos: u64) -> Option<u64> {
    let leaf_num = leaf_pos / 2;
    let leaf_num = (leaf_pos + leaf_num.count_ones() as u64) / 2;
    let leaf_num = (leaf_pos + leaf_num.count_ones() as u64) / 2;
    let leaf_num = (leaf_pos + leaf_num.count_ones() as u64) / 2;
    if leaf_num_to_pos(leaf_num) == leaf_pos {
        Some(leaf_num)
    } else if leaf_num_to_pos(leaf_num + 1) == leaf_pos {
        Some(leaf_num + 1)
    } else {
        None
    }
}

// Naive tree traversal algorithm (log2(n) time).
#[inline]
pub(crate) const fn leaf_pos_to_num_tree_traversal(leaf_pos: u64) -> Option<u64> {
    if leaf_pos == 0 {
        return Some(0);
    }

    let start = u64::MAX >> (leaf_pos + 1).leading_zeros();
    let height = start.trailing_ones();
    let mut two_h = 1 << (height - 1);
    let mut cur_node = start - 1;
    let mut leaf_num_floor = 0u64;

    while two_h > 1 {
        if cur_node == leaf_pos {
            return None;
        }
        let left_pos = cur_node - two_h;
        two_h >>= 1;
        if leaf_pos > left_pos {
            // The leaf is in the right subtree, so we must account for the leaves in the left
            // subtree all of which precede it.
            leaf_num_floor += two_h;
            cur_node -= 1; // move to the right child
        } else {
            // The node is in the left subtree
            cur_node = left_pos;
        }
    }

    Some(leaf_num_floor)
}

// Binary search for the n that solves 2*n - n.count_ones() == leaf_pos (log2(n) time).
#[inline]
pub(crate) const fn leaf_pos_to_num_binary_search(leaf_pos: u64) -> Option<u64> {
    let mut lo = 0u64;
    let mut hi = leaf_pos;

    while lo <= hi {
        let mid = (lo + hi) / 2;
        let pos = 2 * mid - (mid.count_ones() as u64);
        if pos == leaf_pos {
            return Some(mid);
        } else if pos < leaf_pos {
            lo = mid + 1;
        } else {
            if mid == 0 {
                break;
            }
            hi = mid - 1;
        }
    }
    None
}
