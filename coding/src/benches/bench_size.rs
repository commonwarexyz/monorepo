use commonware_codec::EncodeSize as _;
use commonware_coding::{Config, NoCoding, Raptor, ReedSolomon, Scheme, Zoda};
use commonware_cryptography::Sha256;
use commonware_parallel::Sequential;
use commonware_utils::NZU16;
use rand::{RngCore as _, SeedableRng as _};
use rand_chacha::ChaCha8Rng;

const STRATEGY: Sequential = Sequential;

fn bench_size<S: Scheme>(name: &str) {
    let mut rng = ChaCha8Rng::seed_from_u64(0);
    let cases = [8, 12, 16, 19, 20, 24].map(|i| 2usize.pow(i));

    for data_length in cases.into_iter() {
        for chunks in [10u16, 25, 50, 100, 250] {
            let min = chunks / 3;
            let config = Config {
                minimum_shards: NZU16!(min),
                extra_shards: NZU16!(chunks - min),
            };

            let data = {
                let mut data = vec![0u8; data_length];
                rng.fill_bytes(&mut data);
                data
            };

            let (commitment, mut shards) = S::encode(&config, data.as_slice(), &STRATEGY).unwrap();
            let shard = shards.pop().unwrap();
            println!(
                "{} (shard)/msg_len={} chunks={}: {} B",
                name,
                data_length,
                chunks,
                shard.encode_size()
            );

            let (_, _, weak_shard) = S::weaken(
                &config,
                &commitment,
                config.minimum_shards.get() + config.extra_shards.get() - 1,
                shard,
            )
            .unwrap();
            println!(
                "{} (weak_shard)/msg_len={} chunks={}: {} B",
                name,
                data_length,
                chunks,
                weak_shard.encode_size()
            );
            println!();
        }
    }
}

/// Like [bench_size] but only runs configs valid for Raptor (k >= 4).
fn bench_size_raptor<S: Scheme>(name: &str) {
    let mut rng = ChaCha8Rng::seed_from_u64(0);
    let cases = [8, 12, 16, 19, 20, 24].map(|i| 2usize.pow(i));

    for data_length in cases {
        for chunks in [10u16, 25, 50, 100, 250] {
            let min = chunks / 3;
            if min < 4 {
                continue; // Raptor requires k >= 4
            }
            let config = Config {
                minimum_shards: NZU16!(min),
                extra_shards: NZU16!(chunks - min),
            };

            let data = {
                let mut data = vec![0u8; data_length];
                rng.fill_bytes(&mut data);
                data
            };

            let (commitment, mut shards) = S::encode(&config, data.as_slice(), &STRATEGY).unwrap();
            let shard = shards.pop().unwrap();
            println!(
                "{} (shard)/msg_len={} chunks={}: {} B",
                name,
                data_length,
                chunks,
                shard.encode_size()
            );

            let (_, _, weak_shard) = S::weaken(
                &config,
                &commitment,
                config.minimum_shards.get() + config.extra_shards.get() - 1,
                shard,
            )
            .unwrap();
            println!(
                "{} (weak_shard)/msg_len={} chunks={}: {} B",
                name,
                data_length,
                chunks,
                weak_shard.encode_size()
            );
            println!();
        }
    }
}

fn main() {
    bench_size::<ReedSolomon<Sha256>>("reed_solomon size");
    bench_size::<NoCoding<Sha256>>("no_coding size");
    bench_size_raptor::<Raptor<Sha256>>("raptor size");
    bench_size::<Zoda<Sha256>>("zoda size");
}
