//! Quick measurement harness for private-payment proof sizes and
//! verification times on the native BLS12-381 Pari backend.
//!
//! Two verification paths are reported per batch size:
//!  - `verify`: batch-verify proofs already resident in memory.
//!  - `wire`:   the validator path, where each transaction is received in its
//!    compressed wire form and decoded first. Decoding a point decompresses it
//!    and checks it lies in the group, which the in-memory path skips.
//!
//! Run with:
//! `cargo run --release -p commonware-privacy --features zkpari,codec --example payments_bench`

use commonware_codec::{DecodeExt, Encode};
use commonware_privacy::{
    payments::Backend,
    zkpari::payments::{PaymentCommitment, RangeProof, ZkPariBackend},
};
use rand_core::SeedableRng;
use std::time::{Duration, Instant};

/// The transaction-carried parts of one transfer in compressed wire form: the
/// amount commitment and the range proof. The sender's current commitment
/// comes from validator state, not the wire.
struct Wire {
    amount: Vec<u8>,
    proof: Vec<u8>,
}

/// Run `f` `iters` times and return the median elapsed time (and the last
/// result). The median is more representative of typical performance than the
/// best case.
fn median_of<R>(iters: usize, mut f: impl FnMut() -> R) -> (Duration, R) {
    let mut times = Vec::with_capacity(iters);
    let mut out = None;
    for _ in 0..iters {
        let start = Instant::now();
        let r = f();
        times.push(start.elapsed());
        out = Some(r);
    }
    times.sort_unstable();
    (times[times.len() / 2], out.unwrap())
}

fn per(elapsed: Duration, n: usize) -> Duration {
    elapsed / n as u32
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

    let (proving, _) = median_of(5, || {
        ZkPariBackend::transfer(&params, &sender, &sender_opening, 1234, &mut rng)
    });
    println!("transfer proving time (median of 5): {proving:?}");

    // Build a pool of distinct real transfers once, then cycle it to fill each
    // batch, keeping setup fast while exercising the full verification cost.
    const POOL: usize = 100;
    let pool: Vec<(PaymentCommitment, RangeProof)> = (0..POOL)
        .map(|i| {
            let (amount, _, proof) =
                ZkPariBackend::transfer(&params, &sender, &sender_opening, 1 + i as u64, &mut rng);
            (amount, proof)
        })
        .collect();

    println!();
    for n in [1usize, 100, 1_000, 6_000] {
        let transfers: Vec<_> = (0..n)
            .map(|i| {
                let (amount, proof) = &pool[i % POOL];
                (sender, *amount, proof.clone())
            })
            .collect();

        // In-memory verification (proofs already decompressed).
        let (verify, ok) = median_of(5, || {
            ZkPariBackend::batch_verify(&params, &[], &transfers, &[], &mut rng)
        });
        assert!(ok, "verification must succeed");

        // Encode to the compressed wire form (the leader compresses each point,
        // which normalizes it to affine).
        let (encode, wire) = median_of(5, || {
            transfers
                .iter()
                .map(|(_, amount, proof)| Wire {
                    amount: amount.encode().into(),
                    proof: proof.encode().into(),
                })
                .collect::<Vec<_>>()
        });

        // Decode from the wire (decompress each point and check group membership).
        let (decode, _) = median_of(5, || {
            wire.iter()
                .map(|w| {
                    (
                        PaymentCommitment::decode(&w.amount[..]).expect("commitment decodes"),
                        RangeProof::decode(&w.proof[..]).expect("proof decodes"),
                    )
                })
                .collect::<Vec<_>>()
        });

        // The follower path: decode from the wire, then verify.
        let (wire_verify, ok) = median_of(5, || {
            let decoded: Vec<_> = wire
                .iter()
                .map(|w| {
                    let amount =
                        PaymentCommitment::decode(&w.amount[..]).expect("commitment decodes");
                    let proof = RangeProof::decode(&w.proof[..]).expect("proof decodes");
                    (sender, amount, proof)
                })
                .collect();
            ZkPariBackend::batch_verify(&params, &[], &decoded, &[], &mut rng)
        });
        assert!(ok, "wire verification must succeed");

        println!(
            "n={n:>4}  encode {:>8?}/tx  decode {:>8?}/tx  verify {:>8?}/tx  wire(decode+verify) {:>8?}/tx",
            per(encode, n),
            per(decode, n),
            per(verify, n),
            per(wire_verify, n),
        );
    }
}
