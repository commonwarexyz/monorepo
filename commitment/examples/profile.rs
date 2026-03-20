//! Stage-by-stage profiling of the Ligerito proving pipeline.
//!
//! Breaks the prover into stages and times each one independently.
//! Run with: RUSTFLAGS="-C target-cpu=native" cargo run --release -p commonware-commitment --example profile

use commonware_commitment::{
    field::{BinaryElem128, BinaryElem32, BinaryFieldElement},
    prover_config_20,
    transcript::Sha256Transcript,
};
use rand::Rng;
use std::time::Instant;

fn main() {
    let mut rng = rand::thread_rng();
    let poly: Vec<BinaryElem32> = (0..1 << 20)
        .map(|_| BinaryElem32::from(rng.gen::<u32>()))
        .collect();

    let config = prover_config_20::<BinaryElem32, BinaryElem128>();

    // --- Stage 1: Initial ligero_commit (matrix + RS encode + Merkle) ---
    let t0 = Instant::now();
    for _ in 0..5 {
        let mat = build_matrix(&poly, config.initial_dims.0, config.initial_dims.1);
        std::hint::black_box(&mat);
    }
    let matrix_time = t0.elapsed() / 5;
    eprintln!("Matrix build (transpose): {:.2}ms", matrix_time.as_micros() as f64 / 1000.0);

    let mat = build_matrix(&poly, config.initial_dims.0, config.initial_dims.1);

    let t0 = Instant::now();
    for _ in 0..5 {
        let mut mat_copy = mat.clone();
        rs_encode_columns(&mut mat_copy, &config.initial_reed_solomon);
        std::hint::black_box(&mat_copy);
    }
    let rs_time = t0.elapsed() / 5;
    eprintln!("RS encode columns: {:.2}ms", rs_time.as_micros() as f64 / 1000.0);

    let mut encoded = mat.clone();
    rs_encode_columns(&mut encoded, &config.initial_reed_solomon);

    let t0 = Instant::now();
    for _ in 0..5 {
        let hashes = hash_rows(&encoded);
        std::hint::black_box(&hashes);
    }
    let hash_time = t0.elapsed() / 5;
    eprintln!("Row hashing (BLAKE3): {:.2}ms", hash_time.as_micros() as f64 / 1000.0);

    let hashes = hash_rows(&encoded);

    let t0 = Instant::now();
    for _ in 0..5 {
        let tree = commonware_commitment::merkle::build_merkle_tree_from_hashes(&hashes);
        std::hint::black_box(&tree);
    }
    let merkle_time = t0.elapsed() / 5;
    eprintln!("Merkle tree build: {:.2}ms", merkle_time.as_micros() as f64 / 1000.0);

    // --- Stage 2: Full prove for reference ---
    // Warmup
    for _ in 0..3 {
        let mut t = Sha256Transcript::new(0);
        let _ = commonware_commitment::prove(&config, &poly, &mut t).unwrap();
    }

    let mut times = Vec::new();
    for _ in 0..10 {
        let mut t = Sha256Transcript::new(0);
        let start = Instant::now();
        let p = commonware_commitment::prove(&config, &poly, &mut t).unwrap();
        times.push(start.elapsed());
        std::hint::black_box(p);
    }
    times.sort();
    let median = times[times.len() / 2];
    let min = times[0];

    eprintln!("\n=== Summary ===");
    eprintln!("Matrix build:    {:.2}ms", matrix_time.as_micros() as f64 / 1000.0);
    eprintln!("RS encode:       {:.2}ms", rs_time.as_micros() as f64 / 1000.0);
    eprintln!("Row hash:        {:.2}ms", hash_time.as_micros() as f64 / 1000.0);
    eprintln!("Merkle build:    {:.2}ms", merkle_time.as_micros() as f64 / 1000.0);
    eprintln!("Total prove:     median={:.2}ms min={:.2}ms",
        median.as_micros() as f64 / 1000.0,
        min.as_micros() as f64 / 1000.0);
    eprintln!("Stage1 subtotal: {:.2}ms (of initial commit only)",
        (matrix_time + rs_time + hash_time + merkle_time).as_micros() as f64 / 1000.0);
}

// Isolated stage functions that mirror what ligero_commit does internally

fn build_matrix(poly: &[BinaryElem32], m: usize, n: usize) -> Vec<Vec<BinaryElem32>> {
    let inv_rate = 4;
    let m_target = m * inv_rate;
    let mut mat = vec![vec![BinaryElem32::zero(); n]; m_target];
    for (i, row) in mat.iter_mut().enumerate() {
        for j in 0..n {
            let idx = j * m + i;
            if idx < poly.len() {
                row[j] = poly[idx];
            }
        }
    }
    mat
}

fn rs_encode_columns(
    mat: &mut Vec<Vec<BinaryElem32>>,
    rs: &commonware_commitment::reed_solomon::ReedSolomon<BinaryElem32>,
) {
    let n = mat[0].len();
    let cols: Vec<Vec<BinaryElem32>> = (0..n)
        .map(|j| {
            let mut col: Vec<BinaryElem32> = mat.iter().map(|row| row[j]).collect();
            commonware_commitment::reed_solomon::encode_in_place(rs, &mut col);
            col
        })
        .collect();

    for (i, row) in mat.iter_mut().enumerate() {
        for (j, col) in cols.iter().enumerate() {
            row[j] = col[i];
        }
    }
}

fn hash_rows(mat: &[Vec<BinaryElem32>]) -> Vec<[u8; 32]> {
    mat.iter()
        .map(|row| {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&(row.len() as u32).to_le_bytes());
            // SAFETY: BinaryElem32 is repr(transparent) over a u32 wrapper.
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    row.as_ptr() as *const u8,
                    core::mem::size_of_val(row.as_slice()),
                )
            };
            hasher.update(bytes);
            *hasher.finalize().as_bytes()
        })
        .collect()
}
