use crate::tx::{MemoTx, Tx};
use bytes::Bytes;
use commonware_codec::{Copying, DecodeExt as _, Encode, FixedSize, Read, types::lazy::Lazy};
use criterion::{BatchSize, Criterion, criterion_group};
use rand::{Rng, SeedableRng, rngs::StdRng};
use std::{hint::black_box, thread};

const TXS: usize = 100_000;

/// `Tx` contains only fixed-width integers and byte arrays, so every buffer of `Tx::SIZE` bytes
/// is a valid encoding.
fn encoded_transactions(mut rng: impl Rng) -> impl Iterator<Item = Bytes> {
    (0..TXS).map(move |_| {
        let mut bytes = vec![0; Tx::SIZE];
        rng.fill_bytes(&mut bytes);
        Bytes::from(bytes)
    })
}

/// Decodes every value, splitting `items` into `conc` contiguous chunks, one per thread.
fn run<T: Sync>(items: &[T], conc: usize, f: impl Fn(&T) + Sync) {
    if conc == 1 {
        items.iter().for_each(&f);
        return;
    }
    let chunk = items.len().div_ceil(conc);
    thread::scope(|s| {
        for part in items.chunks(chunk) {
            let f = &f;
            s.spawn(move || part.iter().for_each(f));
        }
    });
}

/// Slices each encoded value out of one shared buffer, as when a block is decoded.
fn slices_of_one_buffer(encoded: &[Bytes]) -> Vec<Bytes> {
    let mut block = Vec::new();
    for value in encoded {
        block.extend_from_slice(value);
    }
    let block = Bytes::from(block);
    let mut offset = 0;
    encoded
        .iter()
        .map(|value| {
            let slice = block.slice(offset..offset + value.len());
            offset += value.len();
            slice
        })
        .collect()
}

/// `get` on `Lazy<T>` values sliced from one shared buffer.
fn bench_shared<T: Read<Cfg = ()> + Encode + Sync + Send>(
    c: &mut Criterion,
    value: &str,
    values: impl Iterator<Item = T>,
) {
    let encoded: Vec<Bytes> = values.map(|v| v.encode()).collect();
    let shared = slices_of_one_buffer(&encoded);
    for conc in [1, 8] {
        c.bench_function(
            &format!(
                "{}/value={value} source=shared txs={TXS} conc={conc}",
                module_path!()
            ),
            |b| {
                b.iter_batched(
                    || {
                        shared
                            .iter()
                            .map(|bytes| Lazy::<T>::deferred(&mut bytes.clone(), ()))
                            .collect::<Vec<_>>()
                    },
                    |lazies| {
                        run(&lazies, conc, |l| {
                            black_box(l.get().unwrap());
                        });
                        lazies
                    },
                    BatchSize::LargeInput,
                );
            },
        );
    }
}

fn bench_lazy_get(c: &mut Criterion) {
    let encoded: Vec<Bytes> = encoded_transactions(StdRng::seed_from_u64(0)).collect();
    let shared = slices_of_one_buffer(&encoded);

    // Clone each private value once so every arm starts with a shared (non-promotable) handle.
    let private: Vec<Bytes> = encoded
        .iter()
        .map(|tx| Bytes::from(tx.to_vec()))
        .inspect(|b| drop(b.clone()))
        .collect();

    for conc in [1, 8] {
        for (source, items) in [("shared", &shared), ("private", &private)] {
            c.bench_function(
                &format!("{}/source={source} txs={TXS} conc={conc}", module_path!()),
                |b| {
                    b.iter_batched(
                        || {
                            items
                                .iter()
                                .map(|bytes| Lazy::<Tx>::deferred(&mut bytes.clone(), ()))
                                .collect::<Vec<_>>()
                        },
                        |lazies| {
                            run(&lazies, conc, |l| {
                                black_box(l.get().unwrap());
                            });
                            lazies
                        },
                        BatchSize::LargeInput,
                    );
                },
            );
        }
        c.bench_function(
            &format!("{}/source=borrowed txs={TXS} conc={conc}", module_path!()),
            |b| {
                b.iter(|| {
                    run(&shared, conc, |bytes| {
                        black_box(Tx::decode(Copying(bytes)).unwrap());
                    });
                });
            },
        );
    }
}

fn bench_lazy_get_values(c: &mut Criterion) {
    // A value that keeps a `Bytes` field, which `get` slices out of the shared buffer.
    bench_shared(
        c,
        "memo_tx",
        encoded_transactions(StdRng::seed_from_u64(0))
            .enumerate()
            .map(|(i, bytes)| MemoTx {
                tx: Tx::decode(bytes).unwrap(),
                memo: Bytes::from(vec![i as u8; 16]),
            }),
    );

    // A small fixed-size value, like a public key.
    let mut rng = StdRng::seed_from_u64(0);
    bench_shared(
        c,
        "key33",
        (0..TXS).map(|_| {
            let mut key = [0u8; 33];
            rng.fill_bytes(&mut key);
            key
        }),
    );
}

criterion_group!(benches, bench_lazy_get, bench_lazy_get_values);
