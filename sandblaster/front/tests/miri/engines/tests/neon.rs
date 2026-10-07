//! Commonware's NEON Reed–Solomon engine, as shipped, against its naive
//! engine on small inputs: under Miri, with Stacked and Tree Borrows
//! (`../run.sh --engines`), every raw-pointer load and store of `mul_neon`,
//! `fftb_128` and `ifftb_128` is checked in bounds and alias-free.
#![cfg(target_arch = "aarch64")]

use commonware_cryptography::reed_solomon::engine::{Engine, Naive, Neon, ShardsRefMut, SHARD_CHUNK_BYTES};

fn bytes(seed: &mut u64) -> u8 {
    *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    (*seed >> 56) as u8
}

fn chunks(n: usize, seed: &mut u64) -> Vec<[u8; SHARD_CHUNK_BYTES]> {
    (0..n).map(|_| std::array::from_fn(|_| bytes(seed))).collect()
}

#[test]
fn neon_mul_is_the_naive_engines() {
    let (neon, naive) = (Neon::new(), Naive::new());
    let mut seed = 1;
    for (n, log_m) in [(1usize, 0u16), (2, 1), (3, 12345), (2, 65535)] {
        let x = chunks(n, &mut seed);
        let (mut a, mut b) = (x.clone(), x);
        neon.mul(&mut a, log_m);
        naive.mul(&mut b, log_m);
        assert_eq!(a, b, "mul: {n} chunks, log_m {log_m}");
    }
}

#[test]
fn neon_fft_and_ifft_are_the_naive_engines() {
    let (neon, naive) = (Neon::new(), Naive::new());
    let mut seed = 2;
    // 4 shards of one chunk each, then 2 of two: the butterflies of both
    // layers and the partial ones
    for (shards, per) in [(4usize, 1usize), (2, 2)] {
        for inverse in [false, true] {
            let x = chunks(shards * per, &mut seed);
            let (mut a, mut b) = (x.clone(), x);
            {
                let (mut sa, mut sb) = (ShardsRefMut::new(shards, per, &mut a), ShardsRefMut::new(shards, per, &mut b));
                if inverse {
                    neon.ifft(&mut sa, 0, shards, shards, 7);
                    naive.ifft(&mut sb, 0, shards, shards, 7);
                } else {
                    neon.fft(&mut sa, 0, shards, shards, 7);
                    naive.fft(&mut sb, 0, shards, shards, 7);
                }
            }
            assert_eq!(a, b, "{} over {shards} shards of {per} chunk(s)", if inverse { "ifft" } else { "fft" });
        }
    }
}
