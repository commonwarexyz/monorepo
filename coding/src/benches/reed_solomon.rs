use crate::{bench_decode_generic, bench_encode_generic, shard_selection::ShardSelection};
use commonware_coding::ReedSolomon;
use commonware_cryptography::{Hasher as _, Sha256};
use commonware_storage::bmt::Builder;
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{RngCore, SeedableRng as _};
use rand_chacha::ChaCha8Rng;
use reed_solomon_simd::{
    engine::DefaultEngine,
    rate::{HighRateDecoder, HighRateEncoder, LowRateDecoder, LowRateEncoder, RateDecoder, RateEncoder},
    ReedSolomonDecoder, ReedSolomonEncoder,
};
use std::hint::black_box;

const TARGET_MSG_LEN: usize = 1 << 20;
const TARGET_CHUNKS: u16 = 100;
const TARGET_MIN: u16 = TARGET_CHUNKS / 3;

struct PreparedData {
    shard_len: usize,
    originals: Vec<Vec<u8>>,
    recoveries: Vec<Vec<u8>>,
    digests: Vec<commonware_cryptography::sha256::Digest>,
}

type IndexedShardRefs<'a> = Vec<(usize, &'a [u8])>;

fn prepare_data(data: &[u8], k: usize) -> (Vec<u8>, usize) {
    let data_len = data.len();
    let prefixed_len = u32::BITS as usize / 8 + data_len;
    let mut shard_len = prefixed_len.div_ceil(k);
    if !shard_len.is_multiple_of(2) {
        shard_len += 1;
    }

    let mut padded = vec![0u8; k * shard_len];
    padded[..u32::BITS as usize / 8].copy_from_slice(&(data_len as u32).to_be_bytes());
    padded[u32::BITS as usize / 8..u32::BITS as usize / 8 + data_len].copy_from_slice(data);
    (padded, shard_len)
}

fn extract_data(shards: &[&[u8]], k: usize) -> Vec<u8> {
    let shards = &shards[..k];
    let mut prefix = [0u8; u32::BITS as usize / 8];
    let mut prefix_len = 0usize;
    for shard in shards {
        if prefix_len == prefix.len() {
            break;
        }
        let read = (prefix.len() - prefix_len).min(shard.len());
        prefix[prefix_len..prefix_len + read].copy_from_slice(&shard[..read]);
        prefix_len += read;
    }

    let data_len = u32::from_be_bytes(prefix) as usize;
    let mut data = Vec::with_capacity(data_len);
    let mut prefix_bytes_left = prefix.len();
    let mut data_bytes_left = data_len;
    for shard in shards {
        let skip = prefix_bytes_left.min(shard.len());
        prefix_bytes_left -= skip;
        if skip == shard.len() {
            continue;
        }

        let payload = &shard[skip..];
        let take = data_bytes_left.min(payload.len());
        data.extend_from_slice(&payload[..take]);
        data_bytes_left -= take;
    }
    data
}

fn prepare_target_case() -> PreparedData {
    let k = TARGET_MIN as usize;
    let m = TARGET_CHUNKS as usize - k;
    let mut data = vec![0u8; TARGET_MSG_LEN];
    ChaCha8Rng::seed_from_u64(0).fill_bytes(&mut data);

    let (padded, shard_len) = prepare_data(&data, k);
    let originals: Vec<Vec<u8>> = padded.chunks(shard_len).map(<[u8]>::to_vec).collect();

    let mut encoder = ReedSolomonEncoder::new(k, m, shard_len).unwrap();
    for shard in &originals {
        encoder.add_original_shard(shard).unwrap();
    }
    let encoding = encoder.encode().unwrap();
    let recoveries: Vec<Vec<u8>> = encoding.recovery_iter().map(<[u8]>::to_vec).collect();

    let digests = originals
        .iter()
        .chain(recoveries.iter())
        .map(|shard| Sha256::hash(shard))
        .collect();

    PreparedData {
        shard_len,
        originals,
        recoveries,
        digests,
    }
}

fn selected_shards(
    prepared: &PreparedData,
    selection: ShardSelection,
) -> (IndexedShardRefs<'_>, IndexedShardRefs<'_>) {
    let k = TARGET_MIN as usize;
    let mut provided_originals = Vec::new();
    let mut provided_recoveries = Vec::new();
    for index in selection.indices(TARGET_MIN) {
        let index = index as usize;
        if index < k {
            provided_originals.push((index, prepared.originals[index].as_slice()));
        } else {
            provided_recoveries.push((index - k, prepared.recoveries[index - k].as_slice()));
        }
    }
    (provided_originals, provided_recoveries)
}

fn bench_decode_breakdown(c: &mut Criterion) {
    let prepared = prepare_target_case();
    let k = TARGET_MIN as usize;
    let m = TARGET_CHUNKS as usize - k;

    for selection in [ShardSelection::Best, ShardSelection::Worst] {
        let label = selection.label();
        let (provided_originals, provided_recoveries) = selected_shards(&prepared, selection);

        c.bench_function(
            &format!(
                "reed_solomon::decode_substeps/reconstruction msg_len={TARGET_MSG_LEN} chunks={TARGET_CHUNKS} shard_selection={label}"
            ),
            |b| {
                b.iter(|| {
                    let mut decoder = ReedSolomonDecoder::new(k, m, prepared.shard_len).unwrap();
                    for (idx, shard) in &provided_originals {
                        decoder.add_original_shard(*idx, shard).unwrap();
                    }
                    for (idx, shard) in &provided_recoveries {
                        decoder.add_recovery_shard(*idx, shard).unwrap();
                    }

                    let decoding = decoder.decode().unwrap();
                    let restored: Vec<_> = decoding.restored_original_iter().collect();
                    black_box(restored);
                });
            },
        );
    }

    c.bench_function(
        &format!(
            "reed_solomon::decode_substeps/reencode msg_len={TARGET_MSG_LEN} chunks={TARGET_CHUNKS}"
        ),
        |b| {
            b.iter(|| {
                let mut encoder = ReedSolomonEncoder::new(k, m, prepared.shard_len).unwrap();
                for shard in &prepared.originals {
                    encoder.add_original_shard(shard).unwrap();
                }
                let encoding = encoder.encode().unwrap();
                let recoveries: Vec<_> = encoding.recovery_iter().collect();
                black_box(recoveries);
            });
        },
    );

    let (worst_originals, worst_recoveries) = selected_shards(&prepared, ShardSelection::Worst);
    c.bench_function(
        &format!(
            "reed_solomon::decode_substeps/high_rate_reconstruction msg_len={TARGET_MSG_LEN} chunks={TARGET_CHUNKS}"
        ),
        |b| {
            b.iter_batched(
                DefaultEngine::new,
                |engine| {
                    let mut decoder =
                        HighRateDecoder::new(k, m, prepared.shard_len, engine, None).unwrap();
                    for (idx, shard) in &worst_originals {
                        decoder.add_original_shard(*idx, shard).unwrap();
                    }
                    for (idx, shard) in &worst_recoveries {
                        decoder.add_recovery_shard(*idx, shard).unwrap();
                    }
                    let decoding = decoder.decode().unwrap();
                    let restored: Vec<_> = decoding.restored_original_iter().collect();
                    black_box(restored);
                },
                BatchSize::SmallInput,
            );
        },
    );

    c.bench_function(
        &format!(
            "reed_solomon::decode_substeps/low_rate_reconstruction msg_len={TARGET_MSG_LEN} chunks={TARGET_CHUNKS}"
        ),
        |b| {
            b.iter_batched(
                DefaultEngine::new,
                |engine| {
                    let mut decoder =
                        LowRateDecoder::new(k, m, prepared.shard_len, engine, None).unwrap();
                    for (idx, shard) in &worst_originals {
                        decoder.add_original_shard(*idx, shard).unwrap();
                    }
                    for (idx, shard) in &worst_recoveries {
                        decoder.add_recovery_shard(*idx, shard).unwrap();
                    }
                    let decoding = decoder.decode().unwrap();
                    let restored: Vec<_> = decoding.restored_original_iter().collect();
                    black_box(restored);
                },
                BatchSize::SmallInput,
            );
        },
    );

    c.bench_function(
        &format!(
            "reed_solomon::decode_substeps/bmt_root_check msg_len={TARGET_MSG_LEN} chunks={TARGET_CHUNKS}"
        ),
        |b| {
            b.iter_batched(
                || prepared.digests.clone(),
                |digests| {
                    let mut builder = Builder::<Sha256>::new(digests.len());
                    for digest in &digests {
                        builder.add(digest);
                    }
                    let root = builder.build().root();
                    black_box(root);
                },
                BatchSize::SmallInput,
            );
        },
    );

    c.bench_function(
        &format!(
            "reed_solomon::decode_substeps/payload_extraction msg_len={TARGET_MSG_LEN} chunks={TARGET_CHUNKS}"
        ),
        |b| {
            b.iter(|| {
                let shard_refs: Vec<_> = prepared.originals.iter().map(Vec::as_slice).collect();
                let data = extract_data(&shard_refs, k);
                black_box(data);
            });
        },
    );
}

fn bench_encode_breakdown(c: &mut Criterion) {
    let prepared = prepare_target_case();
    let k = TARGET_MIN as usize;
    let recovery_refs: Vec<_> = prepared.recoveries.iter().map(Vec::as_slice).collect();
    let m = prepared.recoveries.len();

    c.bench_function(
        &format!(
            "reed_solomon::encode_substeps/recovery_copy msg_len={TARGET_MSG_LEN} chunks={TARGET_CHUNKS}"
        ),
        |b| {
            b.iter(|| {
                let mut buf = Vec::with_capacity(m * prepared.shard_len);
                for shard in &recovery_refs {
                    buf.extend_from_slice(shard);
                }
                black_box(buf);
            });
        },
    );

    c.bench_function(
        &format!(
            "reed_solomon::encode_substeps/high_rate msg_len={TARGET_MSG_LEN} chunks={TARGET_CHUNKS}"
        ),
        |b| {
            b.iter_batched(
                DefaultEngine::new,
                |engine| {
                    let mut encoder =
                        HighRateEncoder::new(k, m, prepared.shard_len, engine, None).unwrap();
                    for shard in &prepared.originals {
                        encoder.add_original_shard(shard).unwrap();
                    }
                    let encoding = encoder.encode().unwrap();
                    let recoveries: Vec<_> = encoding.recovery_iter().collect();
                    black_box(recoveries);
                },
                BatchSize::SmallInput,
            );
        },
    );

    c.bench_function(
        &format!(
            "reed_solomon::encode_substeps/low_rate msg_len={TARGET_MSG_LEN} chunks={TARGET_CHUNKS}"
        ),
        |b| {
            b.iter_batched(
                DefaultEngine::new,
                |engine| {
                    let mut encoder =
                        LowRateEncoder::new(k, m, prepared.shard_len, engine, None).unwrap();
                    for shard in &prepared.originals {
                        encoder.add_original_shard(shard).unwrap();
                    }
                    let encoding = encoder.encode().unwrap();
                    let recoveries: Vec<_> = encoding.recovery_iter().collect();
                    black_box(recoveries);
                },
                BatchSize::SmallInput,
            );
        },
    );
}

fn bench_encode(c: &mut Criterion) {
    bench_encode_generic::<ReedSolomon<Sha256>>("reed_solomon::encode", c);
    bench_encode_breakdown(c);
}

fn bench_decode(c: &mut Criterion) {
    bench_decode_generic::<ReedSolomon<Sha256>>("reed_solomon::decode", c);
    bench_decode_breakdown(c);
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_encode, bench_decode
}
