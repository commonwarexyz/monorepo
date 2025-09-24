use commonware_codec::EncodeSize as _;
use commonware_coding::{Config, NoCoding, ReedSolomon, Scheme};
use commonware_cryptography::Sha256;
use rand::{RngCore as _, SeedableRng as _};
use rand_chacha::ChaCha8Rng;

fn benchmark_size<S: Scheme>(name: &str) {
    let mut rng = ChaCha8Rng::seed_from_u64(0);
    let cases = [8, 12, 16, 19, 20, 24].map(|i| 2usize.pow(i));

    for data_length in cases.into_iter() {
        for chunks in [10, 25, 50, 100, 250] {
            let min = chunks / 3;
            let config = Config {
                minimum_shards: min as u16,
                extra_shards: (chunks - min) as u16,
            };

            let data = {
                let mut data = vec![0u8; data_length];
                rng.fill_bytes(&mut data);
                data
            };

            let (commitment, shard_proofs) = S::encode(&config, data.as_slice()).unwrap();
            let (shard, proof) = shard_proofs.first().unwrap();
            let reshard = S::check(&commitment, proof, shard).unwrap();

            println!(
                "{} (shard)/msg_len={} chunks={}: {} B",
                name,
                data_length,
                chunks,
                shard.encode_size()
            );
            println!(
                "{} (proof)/msg_len={} chunks={}: {} B",
                name,
                data_length,
                chunks,
                proof.encode_size()
            );
            println!(
                "{} (reshard)/msg_len={} chunks={}: {} B",
                name,
                data_length,
                chunks,
                reshard.encode_size()
            );
            println!();
        }
    }
}

fn main() {
    benchmark_size::<ReedSolomon<Sha256>>("reed_solomon size");
    benchmark_size::<NoCoding<Sha256>>("no_coding size");
}
