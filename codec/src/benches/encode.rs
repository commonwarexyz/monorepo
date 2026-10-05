use crate::tx::{MemoTx, Tx};
use bytes::Bytes;
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

const VALUES: u64 = 1_000;

fn bench<T: commonware_codec::Encode>(c: &mut Criterion, name: &str, values: &[T]) {
    c.bench_function(
        &format!("{}/value={name} values={}", module_path!(), values.len()),
        |b| {
            b.iter(|| {
                for v in values {
                    black_box(v.encode());
                }
            });
        },
    );
}

fn bench_encode(c: &mut Criterion) {
    let u64s: Vec<u64> = (0..VALUES).collect();
    let digests: Vec<[u8; 32]> = (0..VALUES).map(|i| [i as u8; 32]).collect();
    let txs: Vec<Tx> = (0..VALUES).map(Tx::sample).collect();
    let memo_txs: Vec<MemoTx> = (0..VALUES)
        .map(|i| MemoTx {
            tx: Tx::sample(i),
            memo: Bytes::from(vec![i as u8; 16]),
        })
        .collect();
    let blobs = |len: usize| -> Vec<Bytes> {
        (0..VALUES)
            .map(|i| Bytes::from(vec![i as u8; len]))
            .collect()
    };
    bench(c, "u64", &u64s);
    bench(c, "digest", &digests);
    bench(c, "tx", &txs);
    bench(c, "memo_tx", &memo_txs);
    bench(c, "bytes_64", &blobs(64));
    bench(c, "bytes_1k", &blobs(1024));
    bench(c, "bytes_16k", &blobs(16 * 1024));
}

criterion_group!(benches, bench_encode);
