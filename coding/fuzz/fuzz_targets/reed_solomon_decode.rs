#![no_main]

use arbitrary::Arbitrary;
use bytes::Buf;
use commonware_codec::{Read, Write};
use commonware_coding::{CodecConfig, Config, ReedSolomon, Scheme};
use commonware_cryptography::{Hasher, Sha256};
use commonware_parallel::Sequential;
use commonware_storage::bmt::Builder;
use commonware_utils::NZU16;
use libfuzzer_sys::fuzz_target;

const STRATEGY: Sequential = Sequential;

type RS = ReedSolomon<Sha256>;
type RSShard = <RS as Scheme>::Shard;

#[derive(Clone, Copy, Debug, Arbitrary)]
enum DecodeCase {
    Empty,
    CommitmentMismatch,
    Duplicate,
    Insufficient,
    Oversized,
    ShortPrefix,
    BadLength,
    BadPadding,
    NonCanonical,
    BadRecovery,
    BadRoot,
}

struct OversizedBuf;

impl Buf for OversizedBuf {
    fn remaining(&self) -> usize {
        usize::try_from(u64::from(u32::MAX) + 1).unwrap_or(usize::MAX)
    }

    fn chunk(&self) -> &[u8] {
        &[]
    }

    fn advance(&mut self, _: usize) {
        unreachable!("oversized input should be rejected before reading")
    }
}

fn config(minimum_shards: u16, extra_shards: u16) -> Config {
    Config {
        minimum_shards: NZU16!(minimum_shards),
        extra_shards: NZU16!(extra_shards),
    }
}

fn decode_codeword(config: &Config, codeword: &[Vec<u8>], indexes: &[u16]) {
    let mut builder = Builder::<Sha256>::new(codeword.len());
    let digests = codeword
        .iter()
        .map(|shard| {
            let mut hasher = Sha256::new();
            hasher.update(shard);
            hasher.finalize()
        })
        .collect::<Vec<_>>();
    for digest in &digests {
        builder.add(digest);
    }
    let tree = builder.build();
    let root = tree.root();

    let checked = indexes
        .iter()
        .map(|index| {
            let shard = &codeword[*index as usize];
            let proof = tree.proof(u32::from(*index)).unwrap();
            let mut encoded = Vec::new();
            shard.write(&mut encoded);
            index.write(&mut encoded);
            proof.write(&mut encoded);

            let mut buf = encoded.as_slice();
            let shard = RSShard::read_cfg(
                &mut buf,
                &CodecConfig {
                    maximum_shard_size: shard.len(),
                },
            )
            .unwrap();
            RS::check(config, &root, *index, &shard).unwrap()
        })
        .collect::<Vec<_>>();

    let _ = RS::decode(config, &root, checked.iter(), &STRATEGY);
}

fn decode_checked(case: DecodeCase) {
    match case {
        DecodeCase::Empty => {
            let (root, _) = RS::encode(&config(1, 1), [].as_slice(), &STRATEGY).unwrap();
            let _ = RS::decode(
                &config(1, 1),
                &root,
                std::iter::empty::<&<RS as Scheme>::CheckedShard>(),
                &STRATEGY,
            );
        }
        DecodeCase::CommitmentMismatch => {
            let cfg = config(1, 1);
            let (root, shards) = RS::encode(&cfg, [].as_slice(), &STRATEGY).unwrap();
            let checked = RS::check(&cfg, &root, 0, &shards[0]).unwrap();
            let (other_root, _) = RS::encode(&cfg, [1].as_slice(), &STRATEGY).unwrap();
            assert!(RS::decode(&cfg, &other_root, [&checked].into_iter(), &STRATEGY).is_err());
        }
        DecodeCase::Duplicate => {
            let cfg = config(1, 1);
            let (root, shards) = RS::encode(&cfg, [].as_slice(), &STRATEGY).unwrap();
            let checked = RS::check(&cfg, &root, 0, &shards[0]).unwrap();
            let _ = RS::decode(&cfg, &root, [&checked, &checked].into_iter(), &STRATEGY);
        }
        DecodeCase::Insufficient => {
            let cfg = config(2, 1);
            let (root, shards) = RS::encode(&cfg, [].as_slice(), &STRATEGY).unwrap();
            let checked = RS::check(&cfg, &root, 0, &shards[0]).unwrap();
            let _ = RS::decode(&cfg, &root, [&checked].into_iter(), &STRATEGY);
        }
        _ => {}
    }
}

fn fuzz(case: DecodeCase) {
    decode_checked(case);
    match case {
        DecodeCase::Empty
        | DecodeCase::CommitmentMismatch
        | DecodeCase::Duplicate
        | DecodeCase::Insufficient => {}
        DecodeCase::Oversized => {
            if usize::BITS > u32::BITS {
                let _ = RS::encode(&config(1, 1), OversizedBuf, &STRATEGY);
            }
        }
        DecodeCase::ShortPrefix => {
            decode_codeword(&config(1, 1), &[vec![0, 0], vec![0, 0]], &[0]);
        }
        DecodeCase::BadLength => {
            decode_codeword(&config(1, 1), &[vec![0, 0, 0, 1], vec![0; 4]], &[0]);
        }
        DecodeCase::BadPadding => {
            decode_codeword(
                &config(2, 1),
                &[vec![0, 0, 0, 0], vec![1, 0, 0, 0], vec![0; 4]],
                &[0, 1],
            );
        }
        DecodeCase::NonCanonical => {
            decode_codeword(
                &config(2, 1),
                &[vec![0; 4], vec![0; 4], vec![0; 4]],
                &[0, 1],
            );
        }
        DecodeCase::BadRecovery => {
            decode_codeword(&config(1, 1), &[vec![0; 4], vec![1, 0, 0, 0]], &[0, 1]);
        }
        DecodeCase::BadRoot => {
            decode_codeword(&config(1, 1), &[vec![0; 4], vec![1, 0, 0, 0]], &[0]);
        }
    }
}

fuzz_target!(|case: DecodeCase| {
    fuzz(case);
});
