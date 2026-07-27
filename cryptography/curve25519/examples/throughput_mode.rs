//! Throughput-mode comparison harness (temporary, not for merge): `threads` independent
//! single-threaded batch verifications looping concurrently -- the execution model
//! narya-ed25519's `RunParallel` benchmark measures (no coordination between workers) -- as
//! opposed to the criterion bench's latency mode, where every thread cooperates on one batch.

use commonware_cryptography_curve25519::signing::{Signature, verify_batch_bytes};
use commonware_parallel::Sequential;
use commonware_utils::{TestRng, test_rng};
use ed25519_consensus::SigningKey as RefSigningKey;
use rand_core::Rng;
use std::{
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::{Duration, Instant},
};

fn generate(n: usize, message_size: usize) -> Vec<([u8; 32], Signature, Vec<u8>)> {
    let mut rng = test_rng();
    (0..n)
        .map(|i| {
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);
            let signing_key = RefSigningKey::from(seed);
            let pubkey_bytes = signing_key.verification_key().to_bytes();
            let mut message = vec![0u8; message_size];
            message[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let signature = Signature::from_bytes(signing_key.sign(&message).to_bytes());
            (pubkey_bytes, signature, message)
        })
        .collect()
}

fn main() {
    const N: usize = 16_384;
    const MESSAGE_SIZE: usize = 1232;
    let batch = generate(N, MESSAGE_SIZE);

    for threads in [1usize, 8, 32] {
        let done = AtomicBool::new(false);
        let total = AtomicU64::new(0);
        let start = Instant::now();
        std::thread::scope(|s| {
            for _ in 0..threads {
                s.spawn(|| {
                    let mut rng = TestRng::new(1);
                    while !done.load(Ordering::Relaxed) {
                        let items = batch.iter().map(|(pk, sig, msg)| (pk, sig, msg.as_slice()));
                        assert!(verify_batch_bytes(&mut rng, items, &Sequential));
                        total.fetch_add(N as u64, Ordering::Relaxed);
                    }
                });
            }
            std::thread::sleep(Duration::from_secs(12));
            done.store(true, Ordering::Relaxed);
        });
        let elapsed = start.elapsed().as_secs_f64();
        let sigs = total.load(Ordering::Relaxed) as f64;
        println!(
            "threads={threads} msg={MESSAGE_SIZE} batch={N} throughput={:.0} sigs/s ({:.2} us/sig/core)",
            sigs / elapsed,
            elapsed * 1e6 * threads as f64 / sigs,
        );
    }
}
