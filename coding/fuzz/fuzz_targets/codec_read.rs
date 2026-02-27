#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::Read;
use commonware_coding::{NoCoding, ReedSolomon, Scheme, Zoda};
use commonware_cryptography::Sha256;
use libfuzzer_sys::fuzz_target;

type ZodaShard = <Zoda<Sha256> as Scheme>::Shard;
type ReedSolomonShard = <ReedSolomon<Sha256> as Scheme>::Shard;
type NoCodingShard = <NoCoding<Sha256> as Scheme>::Shard;

const MAX_DATA_BYTES: usize = 1 << 20;
const MAX_INPUT_LEN: usize = 1 << 20;

#[derive(Arbitrary, Debug)]
enum SchemeSelector {
    Zoda,
    ReedSolomon,
    NoCoding,
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    scheme: SchemeSelector,
    max_data_bytes: u32,
    shard_bytes: Vec<u8>,
}

fn fuzz(input: FuzzInput) {
    let max_data_bytes = (input.max_data_bytes as usize).clamp(1, MAX_DATA_BYTES);
    let mut shard_bytes = input.shard_bytes;
    if shard_bytes.len() > MAX_INPUT_LEN {
        shard_bytes.truncate(MAX_INPUT_LEN);
    }

    let codec_config = commonware_coding::CodecConfig {
        maximum_shard_size: max_data_bytes,
    };

    let mut buf = shard_bytes.as_slice();
    match input.scheme {
        SchemeSelector::Zoda => {
            let _ = ZodaShard::read_cfg(&mut buf, &codec_config);
        }
        SchemeSelector::ReedSolomon => {
            let _ = ReedSolomonShard::read_cfg(&mut buf, &codec_config);
        }
        SchemeSelector::NoCoding => {
            let _ = NoCodingShard::read_cfg(&mut buf, &codec_config);
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
