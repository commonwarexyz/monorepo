use bytes::{BufMut, Bytes};
use commonware_codec::{Encode, EncodeSize, Write};
use commonware_coding::{Config, PhasedAsScheme, ReedSolomon, Scheme, Zoda};
use commonware_cryptography::Sha256;
use commonware_parallel::{Rayon, Sequential, Strategy};
use commonware_utils::{NZU16, NZUsize};
use criterion::{Criterion, Throughput, criterion_group};
use std::hint::black_box;

/// A length-prefixed transaction with several independently serialized fields.
struct Transaction {
    sender: [u8; 34],
    recipient: [u8; 32],
    amount: u64,
    nonce: u64,
    signature: [u8; 65],
}

impl EncodeSize for Transaction {
    fn encode_size(&self) -> usize {
        147usize.encode_size() + 147
    }
}

impl Write for Transaction {
    fn write(&self, out: &mut impl BufMut) {
        147usize.write(out);
        out.put_slice(&self.sender);
        out.put_slice(&self.recipient);
        self.amount.write(out);
        self.nonce.write(out);
        out.put_slice(&self.signature);
    }
}

fn compare<S: Scheme>(
    c: &mut Criterion,
    name: &str,
    value: &(impl Write + EncodeSize),
    config: &Config,
    strategy: &impl Strategy,
) {
    let buffered = || {
        let mut encoded = Vec::with_capacity(value.encode_size() + config.encode_size());
        value.write(&mut encoded);
        config.write(&mut encoded);
        S::encode(config, encoded.as_slice(), strategy).unwrap()
    };
    let direct = || {
        S::encode_with(
            config,
            value.encode_size() + config.encode_size(),
            |out| {
                value.write(out);
                config.write(out);
            },
            strategy,
        )
        .unwrap()
    };
    assert_eq!(buffered(), direct());

    let mut group = c.benchmark_group(module_path!());
    group.throughput(Throughput::Bytes(
        (value.encode_size() + config.encode_size()) as u64,
    ));
    group.bench_function(format!("{name} path=buffered"), |b| {
        b.iter(|| black_box(buffered()));
    });
    group.bench_function(format!("{name} path=direct"), |b| {
        b.iter(|| black_box(direct()));
    });
    group.finish();
}

fn bench_scheme<S: Scheme>(
    c: &mut Criterion,
    scheme: &str,
    counts: &[usize],
    shard_counts: &[u16],
) {
    for &txs in counts {
        let fields: Vec<_> = (0..txs)
            .map(|i| Transaction {
                sender: [i as u8; 34],
                recipient: [(i >> 8) as u8; 32],
                amount: i as u64,
                nonce: !(i as u64),
                signature: [(i >> 16) as u8; 65],
            })
            .collect();
        // Retained encoded transactions exercise the same wire format with fewer writes.
        let retained: Vec<Bytes> = fields.iter().map(|tx| tx.encode().slice(2..)).collect();
        let fields = ([0u8; 128], fields);
        let retained = ([0u8; 128], retained);
        assert_eq!(fields.encode(), retained.encode());

        for &shards in shard_counts {
            let minimum = (shards - 1) / 3 + 1;
            let config = Config {
                minimum_shards: NZU16!(minimum),
                extra_shards: NZU16!(shards - minimum),
            };
            for conc in [1, 8] {
                let name = format!("scheme={scheme} txs={txs} shards={shards} conc={conc}");
                if conc == 1 {
                    compare::<S>(
                        c,
                        &format!("{name} repr=fields"),
                        &fields,
                        &config,
                        &Sequential,
                    );
                    compare::<S>(
                        c,
                        &format!("{name} repr=bytes"),
                        &retained,
                        &config,
                        &Sequential,
                    );
                } else {
                    let strategy = Rayon::new(NZUsize!(conc)).unwrap();
                    compare::<S>(
                        c,
                        &format!("{name} repr=fields"),
                        &fields,
                        &config,
                        &strategy,
                    );
                    compare::<S>(
                        c,
                        &format!("{name} repr=bytes"),
                        &retained,
                        &config,
                        &strategy,
                    );
                }
            }
        }
    }
}

fn bench_encode_with(c: &mut Criterion) {
    bench_scheme::<ReedSolomon<Sha256>>(c, "rs", &[1, 1000, 10000, 50000, 250000], &[4, 25, 100]);
    bench_scheme::<PhasedAsScheme<Zoda<Sha256>>>(c, "zoda", &[1000, 10000], &[4, 25]);
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20);
    targets = bench_encode_with,
}
