//! Quick measurement harness for private-payment proof sizes and
//! verification times on the native BLS12-381 Pari backend.
//!
//! Run with:
//! `cargo run --release -p commonware-privacy --features zkpari,codec --example payments_bench`

use commonware_codec::Encode;
use commonware_privacy::{payments::Backend, zkpari::payments::ZkPariBackend};
use rand_core::SeedableRng;
use std::time::{Duration, Instant};

fn best_of<R>(iters: usize, mut f: impl FnMut() -> R) -> (Duration, R) {
    let mut best = Duration::MAX;
    let mut out = None;
    for _ in 0..iters {
        let start = Instant::now();
        let r = f();
        let elapsed = start.elapsed();
        best = best.min(elapsed);
        out = Some(r);
    }
    (best, out.unwrap())
}

fn main() {
    let mut rng = rand_chacha::ChaCha8Rng::from_seed([7u8; 32]);
    let params = ZkPariBackend::setup(&[7u8; 32]).expect("setup is infallible");

    let (sender, sender_opening, _) = ZkPariBackend::fund(&params, u64::MAX / 2, &mut rng);

    let (amount, _, transfer_proof) =
        ZkPariBackend::transfer(&params, &sender, &sender_opening, 1234, &mut rng);
    let burn_proof = ZkPariBackend::burn(&params, &sender, &sender_opening, 99, &mut rng);
    println!(
        "transfer proof:     {} bytes",
        transfer_proof.encode().len()
    );
    println!("burn proof:         {} bytes", burn_proof.encode().len());
    println!("amount commitment:  {} bytes", amount.encode().len());

    let (proving, _) = best_of(5, || {
        ZkPariBackend::transfer(&params, &sender, &sender_opening, 1234, &mut rng)
    });
    println!("transfer proving time (best of 5): {proving:?}");

    for n in [1usize, 10, 100] {
        let transfers: Vec<_> = (0..n)
            .map(|i| {
                let (amount, _, proof) = ZkPariBackend::transfer(
                    &params,
                    &sender,
                    &sender_opening,
                    1 + i as u64,
                    &mut rng,
                );
                (sender, amount, proof)
            })
            .collect();
        let (elapsed, ok) = best_of(5, || {
            ZkPariBackend::batch_verify(&params, &[], &transfers, &[], &mut rng)
        });
        assert!(ok, "verification must succeed");
        println!(
            "batch_verify {n:>3} transfers (best of 5): {elapsed:?} ({:?}/transfer)",
            elapsed / n as u32
        );
    }
}
