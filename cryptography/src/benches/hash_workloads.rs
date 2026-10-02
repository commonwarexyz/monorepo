use commonware_cryptography::Hasher;
use commonware_utils::test_rng;
use criterion::Criterion;
use rand::Rng;
use std::hint::black_box;

pub(crate) fn bench_hash_many_parts<H: Hasher>(c: &mut Criterion, prefix: &str) {
    const COUNTS: [usize; 5] = [2, 3, 4, 16, 256];
    let mut sampler = test_rng();
    let mut messages = vec![[0u8; 72]; 256];
    for message in &mut messages {
        sampler.fill_bytes(message);
    }

    let leaf: Vec<_> = messages
        .iter()
        .map(|message| [&message[..8], &message[8..40]])
        .collect();
    let bmt: Vec<_> = messages
        .iter()
        .map(|message| [&message[..32], &message[32..64]])
        .collect();
    let bmt_leaf: Vec<_> = messages
        .iter()
        .map(|message| [&message[..4], &message[4..36]])
        .collect();
    for (shape, parts) in [("leaf", leaf), ("bmt", bmt), ("bmt_leaf", bmt_leaf)] {
        for count in COUNTS {
            c.bench_function(&format!("{prefix}/shape={shape} count={count}"), |b| {
                b.iter(|| black_box(H::hash_many_parts(black_box(&parts[..count]))));
            });
        }
    }

    let mmr: Vec<_> = messages
        .iter()
        .map(|message| [&message[..8], &message[8..40], &message[40..72]])
        .collect();
    for count in COUNTS {
        c.bench_function(&format!("{prefix}/shape=mmr count={count}"), |b| {
            b.iter(|| black_box(H::hash_many_parts(black_box(&mmr[..count]))));
        });
    }

    let mut long = [vec![0u8; 2048], vec![0u8; 2048]];
    for message in &mut long {
        sampler.fill_bytes(message);
    }
    for len in [1024, 2048] {
        let parts = long
            .each_ref()
            .map(|message| [&message[..32], &message[32..len]]);
        c.bench_function(&format!("{prefix}/shape=long count=2 len={len}"), |b| {
            b.iter(|| black_box(H::hash_many_parts(black_box(&parts))));
        });
    }
}

pub(crate) fn bench_hash_pair<H: Hasher>(c: &mut Criterion, prefix: &str) {
    let mut sampler = test_rng();
    let mut messages = [[0u8; 72]; 2];
    for message in &mut messages {
        sampler.fill_bytes(message);
    }
    for (shape, parts) in [
        (
            "bmt_leaf",
            messages
                .each_ref()
                .map(|message| vec![&message[..4], &message[4..36]]),
        ),
        (
            "bmt",
            messages
                .each_ref()
                .map(|message| vec![&message[..32], &message[32..64]]),
        ),
        (
            "mmr",
            messages
                .each_ref()
                .map(|message| vec![&message[..8], &message[8..40], &message[40..]]),
        ),
        (
            "leaf",
            messages
                .each_ref()
                .map(|message| vec![&message[..8], &message[8..40]]),
        ),
    ] {
        c.bench_function(&format!("{prefix}/shape={shape}"), |b| {
            b.iter(|| H::hash_pair(black_box(&parts[0]), black_box(&parts[1])));
        });
    }
}

pub(crate) fn bench_dependent_hash_pair<H: Hasher>(c: &mut Criterion, prefix: &str) {
    let mut sampler = test_rng();
    let mut messages = [[0u8; 72]; 2];
    for message in &mut messages {
        sampler.fill_bytes(message);
    }

    for shape in ["leaf", "bmt", "bmt_leaf", "mmr"] {
        let start = match shape {
            "bmt" => 0,
            "bmt_leaf" => 4,
            _ => 8,
        };
        let mut state = [[0u8; 32]; 2];
        for (digest, message) in state.iter_mut().zip(&messages) {
            digest.copy_from_slice(&message[start..start + 32]);
        }
        c.bench_function(&format!("{prefix}::dependent/shape={shape}"), |b| {
            b.iter(|| {
                let (left, right) = match shape {
                    "leaf" => H::hash_pair(
                        black_box(&[&messages[0][..8], &state[0][..]]),
                        black_box(&[&messages[1][..8], &state[1][..]]),
                    ),
                    "bmt" => H::hash_pair(
                        black_box(&[&state[0][..], &messages[0][32..64]]),
                        black_box(&[&state[1][..], &messages[1][32..64]]),
                    ),
                    "bmt_leaf" => H::hash_pair(
                        black_box(&[&messages[0][..4], &state[0][..]]),
                        black_box(&[&messages[1][..4], &state[1][..]]),
                    ),
                    "mmr" => H::hash_pair(
                        black_box(&[&messages[0][..8], &state[0][..], &messages[0][40..72]]),
                        black_box(&[&messages[1][..8], &state[1][..], &messages[1][40..72]]),
                    ),
                    _ => unreachable!(),
                };
                state[0].copy_from_slice(black_box(left).as_ref());
                state[1].copy_from_slice(black_box(right).as_ref());
            });
        });
    }

    let mut long = [vec![0u8; 2048], vec![0u8; 2048]];
    for message in &mut long {
        sampler.fill_bytes(message);
    }
    for len in [1024, 2048] {
        let parts = long
            .each_ref()
            .map(|message| [&message[..32], &message[32..len]]);
        c.bench_function(&format!("{prefix}::control/shape=long len={len}"), |b| {
            b.iter(|| black_box(H::hash_pair(black_box(&parts[0]), black_box(&parts[1]))));
        });
    }
}
