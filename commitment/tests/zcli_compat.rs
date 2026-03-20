//! Cross-verification: prove here, verify here, with zcli-compatible
//! settings (SHA-256 row hashing, transcript seed 1234).

use commonware_commitment::{
    field::{BinaryElem32, BinaryElem128},
    prover_config_for_log_size, verifier_config_for_log_size,
    transcript::Sha256Transcript,
};

#[test]
fn test_roundtrip_sha256_seed_1234() {
    let prover_cfg = prover_config_for_log_size::<BinaryElem32, BinaryElem128>(20);
    let verifier_cfg = verifier_config_for_log_size(20);

    let poly = vec![BinaryElem32::from(42u32); 1 << 20];

    let mut pt = Sha256Transcript::new(1234);
    let proof = commonware_commitment::prove(&prover_cfg, &poly, &mut pt)
        .expect("prove failed");

    let mut vt = Sha256Transcript::new(1234);
    let valid = commonware_commitment::verify(&verifier_cfg, &proof, &mut vt)
        .expect("verify failed");

    assert!(valid);
    eprintln!("proof size: {} bytes", proof.size_of());
}

#[test]
fn test_hash_row_matches_zcli_sha256() {
    // zcli's hash_row: SHA-256(row_len_as_le_u32 || raw_element_bytes)
    use sha2::{Digest, Sha256};

    let row: Vec<BinaryElem32> = (0..16).map(|i| BinaryElem32::from(i as u32)).collect();

    // What zcli produces
    let mut hasher = Sha256::new();
    hasher.update((row.len() as u32).to_le_bytes());
    // SAFETY: BinaryElem32 is repr(transparent) over u32.
    let row_bytes = unsafe {
        core::slice::from_raw_parts(
            row.as_ptr() as *const u8,
            core::mem::size_of_val(row.as_slice()),
        )
    };
    hasher.update(row_bytes);
    let zcli_hash: [u8; 32] = hasher.finalize().into();

    // What we produce
    let our_hash = commonware_commitment::utils::hash_row(&row);

    assert_eq!(
        zcli_hash, our_hash,
        "hash_row must match zcli SHA-256 output"
    );
}

#[test]
fn test_deterministic_proofs() {
    // Same input + same seed = same proof (both runs)
    let cfg = prover_config_for_log_size::<BinaryElem32, BinaryElem128>(20);
    let poly = vec![BinaryElem32::from(7u32); 1 << 20];

    let mut t1 = Sha256Transcript::new(1234);
    let proof1 = commonware_commitment::prove(&cfg, &poly, &mut t1).unwrap();

    let mut t2 = Sha256Transcript::new(1234);
    let proof2 = commonware_commitment::prove(&cfg, &poly, &mut t2).unwrap();

    // Merkle roots must match
    assert_eq!(
        proof1.initial_commitment.root.root,
        proof2.initial_commitment.root.root,
        "deterministic proofs must have same root"
    );

    // Proof sizes must match
    assert_eq!(proof1.size_of(), proof2.size_of());
}

#[test]
fn test_wrong_seed_fails() {
    let prover_cfg = prover_config_for_log_size::<BinaryElem32, BinaryElem128>(20);
    let verifier_cfg = verifier_config_for_log_size(20);

    let poly = vec![BinaryElem32::from(42u32); 1 << 20];

    // Prove with seed 1234
    let mut pt = Sha256Transcript::new(1234);
    let proof = commonware_commitment::prove(&prover_cfg, &poly, &mut pt).unwrap();

    // Verify with different seed — must fail
    let mut vt = Sha256Transcript::new(9999);
    let valid = commonware_commitment::verify(&verifier_cfg, &proof, &mut vt).unwrap();

    assert!(!valid, "wrong transcript seed must fail verification");
}
