use super::utils::{MIN_PK_DST, MIN_SIG_DST};
use commonware_codec::DecodeExt as _;
use commonware_cryptography::bls12381::primitives::{
    group::{G1 as LegacyG1, G2 as LegacyG2},
    ops::{self as legacy_ops, batch as legacy_batch},
    variant::{MinPk as LegacyMinPk, MinSig as LegacyMinSig, Variant as _},
};
use commonware_cryptography_bls::bls12381::signing::{
    SigningKey, min_pk as native_min_pk, min_sig as native_min_sig,
};
use commonware_parallel::Sequential;
use commonware_utils::{TestRng, non_empty, union_unique};
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

const GENERAL_COUNTS: [usize; 8] = [1, 2, 8, 15, 16, 17, 32, 64];
const SPECIALIZED_COUNTS: [usize; 5] = [1, 10, 100, 1000, 10000];
const NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_BLS_BATCH_VERIFY_BENCH";

fn keys(count: usize) -> Vec<SigningKey> {
    (0..count)
        .map(|i| {
            let mut ikm = [0; 32];
            ikm[24..].copy_from_slice(&(i as u64 + 1).to_be_bytes());
            SigningKey::key_gen(&ikm, b"batch benchmark").unwrap()
        })
        .collect()
}

fn messages(count: usize) -> Vec<[u8; 8]> {
    (0..count).map(|i| (i as u64).to_be_bytes()).collect()
}

macro_rules! bench_scheme {
    ($c:ident, $scheme:literal, $native:ident, $legacy:ty, $legacy_public:ty, $legacy_signature:ty, $dst:expr) => {{
        for count in GENERAL_COUNTS {
            $c.bench_function(
                &format!("{}/backend=native scheme={} shape=general count={count}", module_path!(), $scheme),
                |b| {
                    let keys = keys(count);
                    let messages = messages(count);
                    let message_refs: Vec<_> = messages.iter().map(|m| m.as_slice()).collect();
                    let public_keys: Vec<_> = keys.iter().map($native::public_key).collect();
                    let signatures: Vec<_> = keys.iter().zip(&message_refs)
                        .map(|(key, message)| $native::sign(key, message, $dst)).collect();
                    let mut rng = TestRng::new(1);
                    b.iter(|| black_box($native::batch_verify(
                        &mut rng, black_box(&public_keys), black_box(&message_refs), $dst,
                        black_box(&signatures),
                    ).unwrap()));
                },
            );
            $c.bench_function(
                &format!("{}/backend=legacy scheme={} shape=general count={count}", module_path!(), $scheme),
                |b| {
                    let keys = keys(count);
                    let messages = messages(count);
                    let public_keys: Vec<$legacy_public> = keys.iter().map($native::public_key)
                        .map(|point| <$legacy_public>::decode(point.to_bytes().to_vec()).unwrap()).collect();
                    let signatures: Vec<$legacy_signature> = keys.iter().zip(&messages)
                        .map(|(key, message)| $native::sign(key, message, $dst))
                        .map(|point| <$legacy_signature>::decode(point.to_bytes().to_vec()).unwrap()).collect();
                    let mut rng = TestRng::new(1);
                    b.iter(|| {
                        let hashes: Vec<_> = messages.iter()
                            .map(|message| legacy_ops::hash::<$legacy>($dst, message)).collect();
                        black_box(<$legacy>::batch_verify(
                            &mut rng, black_box(&public_keys), black_box(&hashes),
                            black_box(&signatures), &Sequential,
                        ).unwrap());
                    });
                },
            );
        }

        for count in SPECIALIZED_COUNTS {
            $c.bench_function(
                &format!("{}/backend=native scheme={} shape=same_message count={count}", module_path!(), $scheme),
                |b| {
                    let keys = keys(count);
                    let message = b"shared batch message";
                    let encoded = union_unique(NAMESPACE, message);
                    let public_keys: Vec<_> = keys.iter().map($native::public_key).collect();
                    let signatures: Vec<_> = keys.iter()
                        .map(|key| $native::sign(key, &encoded, $dst)).collect();
                    let mut rng = TestRng::new(1);
                    b.iter(|| {
                        let encoded = union_unique(NAMESPACE, message);
                        black_box($native::batch_verify_same_message(
                            &mut rng, black_box(&public_keys), black_box(&encoded), $dst,
                            black_box(&signatures),
                        ).unwrap());
                    });
                },
            );
            $c.bench_function(
                &format!("{}/backend=legacy scheme={} shape=same_message count={count}", module_path!(), $scheme),
                |b| {
                    let keys = keys(count);
                    let message = b"shared batch message";
                    let encoded = union_unique(NAMESPACE, message);
                    let public_keys: Vec<$legacy_public> = keys.iter().map($native::public_key)
                        .map(|point| <$legacy_public>::decode(point.to_bytes().to_vec()).unwrap()).collect();
                    let signatures: Vec<$legacy_signature> = keys.iter()
                        .map(|key| $native::sign(key, &encoded, $dst))
                        .map(|point| <$legacy_signature>::decode(point.to_bytes().to_vec()).unwrap()).collect();
                    let entries: Vec<_> = public_keys.iter().copied()
                        .zip(signatures.iter().copied()).collect();
                    let mut rng = TestRng::new(1);
                    b.iter(|| assert!(legacy_batch::verify_same_message::<_, $legacy, _>(
                        &mut rng, NAMESPACE, message, non_empty![@entries.iter().copied()],
                        &Sequential,
                    ).is_empty()));
                },
            );

            $c.bench_function(
                &format!("{}/backend=native scheme={} shape=same_signer count={count}", module_path!(), $scheme),
                |b| {
                    let key = &keys(1)[0];
                    let public_key = $native::public_key(key);
                    let messages = messages(count);
                    let encoded: Vec<_> = messages.iter()
                        .map(|message| union_unique(NAMESPACE, message)).collect();
                    let signatures: Vec<_> = encoded.iter()
                        .map(|message| $native::sign(key, message, $dst)).collect();
                    let mut rng = TestRng::new(1);
                    b.iter(|| {
                        let encoded: Vec<_> = messages.iter()
                            .map(|message| union_unique(NAMESPACE, message)).collect();
                        let message_refs: Vec<_> = encoded.iter()
                            .map(|message| message.as_slice()).collect();
                        black_box($native::batch_verify_same_signer(
                            &mut rng, black_box(&public_key), black_box(&message_refs), $dst,
                            black_box(&signatures),
                        ).unwrap());
                    });
                },
            );
            $c.bench_function(
                &format!("{}/backend=legacy scheme={} shape=same_signer count={count}", module_path!(), $scheme),
                |b| {
                    let key = &keys(1)[0];
                    let public_key: $legacy_public =
                        <$legacy_public>::decode($native::public_key(key).to_bytes().to_vec())
                            .unwrap();
                    let messages = messages(count);
                    let encoded: Vec<_> = messages.iter()
                        .map(|message| union_unique(NAMESPACE, message)).collect();
                    let signatures: Vec<$legacy_signature> = encoded.iter()
                        .map(|message| $native::sign(key, message, $dst))
                        .map(|point| <$legacy_signature>::decode(point.to_bytes().to_vec()).unwrap()).collect();
                    let mut rng = TestRng::new(1);
                    b.iter(|| legacy_batch::verify_same_signer::<_, $legacy, _>(
                        &mut rng, black_box(&public_key),
                        non_empty![@messages.iter().zip(&signatures).map(|(message, signature)| {
                            (NAMESPACE, message.as_slice(), *signature)
                        })],
                        &Sequential,
                    ).unwrap());
                },
            );
        }
    }};
}

fn bench(c: &mut Criterion) {
    bench_scheme!(
        c,
        "min_pk",
        native_min_pk,
        LegacyMinPk,
        LegacyG1,
        LegacyG2,
        MIN_PK_DST
    );
    bench_scheme!(
        c,
        "min_sig",
        native_min_sig,
        LegacyMinSig,
        LegacyG2,
        LegacyG1,
        MIN_SIG_DST
    );
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench,
}
