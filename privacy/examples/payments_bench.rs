//! Quick measurement harness for private-payment proof sizes and
//! verification times. Not a criterion bench; used to compare the
//! two-range-proof construction against the batched construction.
//!
//! Run with:
//! `cargo run --release -p commonware-privacy --features zkpari,codec --example payments_bench`

use ark_bn254::Bn254;
use commonware_codec::Encode;
use commonware_privacy::{
    payments::Backend,
    zkpari::payments::{codec::Compressed, ZkPariBackend},
};
use rand_core::SeedableRng;
use std::time::{Duration, Instant};

type Payments = ZkPariBackend<Bn254>;

fn best_of<R>(iters: usize, mut f: impl FnMut() -> R) -> (Duration, R) {
    let mut best = Duration::MAX;
    let mut out = None;
    for _ in 0..iters {
        let start = Instant::now();
        let r = f();
        let elapsed = start.elapsed();
        if elapsed < best {
            best = elapsed;
        }
        out = Some(r);
    }
    (best, out.unwrap())
}

fn main() {
    let mut rng = rand_chacha::ChaCha8Rng::from_seed([7u8; 32]);
    let params = Payments::setup(&[7u8; 32]).expect("setup is infallible");

    let (sender_commitment, sender_opening, _) = Payments::fund(&params, u64::MAX / 2, &mut rng);

    // Proof sizes (compressed wire encoding).
    let (amount_commitment, _amount_opening, transfer_proof) =
        Payments::transfer(&params, &sender_commitment, &sender_opening, 1234, &mut rng);
    let burn_proof = Payments::burn(&params, &sender_commitment, &sender_opening, 99, &mut rng);
    println!(
        "transfer proof size (compressed): {} bytes",
        Compressed(&transfer_proof).encode().len()
    );
    println!(
        "burn proof size (compressed):     {} bytes",
        Compressed(&burn_proof).encode().len()
    );
    println!(
        "amount commitment (compressed):   {} bytes",
        Compressed(&amount_commitment).encode().len()
    );

    // Proving time.
    let (proving, _) = best_of(5, || {
        Payments::transfer(&params, &sender_commitment, &sender_opening, 1234, &mut rng)
    });
    println!("transfer proving time (best of 5): {proving:?}");

    // Verification time for batches of transfers.
    for n in [1usize, 10, 100] {
        let transfers: Vec<_> = (0..n)
            .map(|i| {
                let (amount, _opening, proof) = Payments::transfer(
                    &params,
                    &sender_commitment,
                    &sender_opening,
                    1 + i as u64,
                    &mut rng,
                );
                (sender_commitment.clone(), amount, proof)
            })
            .collect();
        let (elapsed, ok) = best_of(5, || {
            Payments::batch_verify(&params, &[], &transfers, &[], &mut rng)
        });
        assert!(ok, "verification must succeed");
        println!(
            "batch_verify {n:>3} transfers (best of 5): {elapsed:?} ({:?}/transfer)",
            elapsed / n as u32
        );
    }

    // Burns.
    let burns: Vec<_> = (0..100)
        .map(|i| {
            let value = 1 + i as u64;
            let proof = Payments::burn(
                &params,
                &sender_commitment,
                &sender_opening,
                value,
                &mut rng,
            );
            (sender_commitment.clone(), value, proof)
        })
        .collect();
    let (elapsed, ok) = best_of(5, || {
        Payments::batch_verify(&params, &[], &[], &burns, &mut rng)
    });
    assert!(ok, "burn verification must succeed");
    println!("batch_verify 100 burns (best of 5): {elapsed:?}");
}
