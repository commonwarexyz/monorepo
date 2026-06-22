use crate::reed_solomon::{
    engine::Engine,
    rate::{Rate, RateDecoder, RateEncoder},
};
use core::ops::Range;
use fixedbitset::FixedBitSet;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

// ======================================================================
// IntOrRange - CRATE

pub(crate) trait IntOrRange {
    // incluside
    fn min(&self) -> usize;
    // exclusive
    fn max(&self) -> usize;
}

impl IntOrRange for usize {
    fn min(&self) -> usize {
        *self
    }

    fn max(&self) -> usize {
        self + 1
    }
}

impl IntOrRange for Range<usize> {
    fn min(&self) -> usize {
        self.start
    }

    fn max(&self) -> usize {
        self.end
    }
}

// ======================================================================
// FUNCTIONS - CRATE

pub(crate) fn assert_hash<T>(shards: T, expected: &str)
where
    T: IntoIterator,
    T::Item: AsRef<[u8]>,
{
    let mut sha = Sha256::new();
    for shard in shards {
        sha.update(shard);
    }
    let got = sha.finalize();

    if got.as_slice() != commonware_formatting::from_hex(expected).unwrap() {
        #[cfg(feature = "std")]
        {
            print!("GOT     : ");
            for x in got {
                print!("{:02x}", x);
            }
            println!();
            println!("EXPECTED: {}", expected);
        }
        panic!("recovery shards hash doesn't match");
    }
}

pub(crate) fn generate_original(
    original_count: usize,
    shard_bytes: usize,
    seed: u8,
) -> Vec<Vec<u8>> {
    let mut rng = ChaCha8Rng::from_seed([seed; 32]);
    let mut original = vec![vec![0u8; shard_bytes]; original_count];
    for original in &mut original {
        rng.fill_bytes(original);
    }
    original
}

// ======================================================================
// RATE ENCODER/DECODER - TEST SINGLE-ROUND ROUNDTRIP

pub(crate) fn roundtrip<R: Rate<E>, E: Engine, T: IntOrRange>(
    encoder: &mut R::RateEncoder,
    decoder: &mut R::RateDecoder,
    original_count: usize,
    shard_bytes: usize,
    recovery_hash: &str,
    decoder_original: &[T],
    decoder_recovery: &[T],
    seed: u8,
) {
    let original = generate_original(original_count, shard_bytes, seed);

    for original in &original {
        encoder.add_original_shard(original).unwrap();
    }

    let result = encoder.encode().unwrap();
    let recovery: Vec<_> = result.recovery_iter().collect();

    assert_hash(&recovery, recovery_hash);

    let mut original_received = FixedBitSet::with_capacity(original_count);

    for x in decoder_original {
        for i in x.min()..x.max() {
            decoder.add_original_shard(i, &original[i]).unwrap();
            original_received.set(i, true);
        }
    }

    for x in decoder_recovery {
        for i in x.min()..x.max() {
            decoder.add_recovery_shard(i, recovery[i]).unwrap();
        }
    }

    let result = decoder.decode().unwrap();
    let restored: BTreeMap<_, _> = result.restored_original_iter().collect();

    for i in 0..original_count {
        if !original_received[i] {
            assert_eq!(restored[&i], original[i]);
        }
    }
}

pub(crate) fn roundtrip_single<R: Rate<E>, E: Engine, T: IntOrRange>(
    new_engine: fn() -> E,
    original_count: usize,
    recovery_count: usize,
    shard_bytes: usize,
    recovery_hash: &str,
    decoder_original: &[T],
    decoder_recovery: &[T],
    seed: u8,
) {
    let mut encoder = R::encoder(
        original_count,
        recovery_count,
        shard_bytes,
        new_engine(),
        None,
    )
    .unwrap();

    let mut decoder = R::decoder(
        original_count,
        recovery_count,
        shard_bytes,
        new_engine(),
        None,
    )
    .unwrap();

    roundtrip::<R, E, T>(
        &mut encoder,
        &mut decoder,
        original_count,
        shard_bytes,
        recovery_hash,
        decoder_original,
        decoder_recovery,
        seed,
    );
}

macro_rules! roundtrip_single {
    ($Rate: ident,
     $original_count: expr,
     $recovery_count: expr,
     $shard_bytes: expr,
     $recovery_hash: expr,
     $decoder_original: expr,
     $decoder_recovery: expr,
     $seed: expr $(,)?
    ) => {
        crate::reed_solomon::test_util::roundtrip_single::<$Rate<_>, _, _>(
            crate::reed_solomon::engine::Naive::new,
            $original_count,
            $recovery_count,
            $shard_bytes,
            $recovery_hash,
            $decoder_original,
            $decoder_recovery,
            $seed,
        );

        crate::reed_solomon::test_util::roundtrip_single::<$Rate<_>, _, _>(
            crate::reed_solomon::engine::NoSimd::new,
            $original_count,
            $recovery_count,
            $shard_bytes,
            $recovery_hash,
            $decoder_original,
            $decoder_recovery,
            $seed,
        );
    };
}

// ======================================================================
// RATE ENCODER/DECODER - TEST TWO-ROUND ROUNDTRIP

macro_rules! roundtrip_two_rounds {
    (
        $Rate: ident,
        $explicit_reset: expr,
        (
            $original_count_a: expr,
            $recovery_count_a: expr,
            $shard_bytes_a: expr,
            $recovery_hash_a: expr,
            $decoder_original_a: expr,
            $decoder_recovery_a: expr,
            $seed_a: expr $(,)?
        ),
        (
            $original_count_b: expr,
            $recovery_count_b: expr,
            $shard_bytes_b: expr,
            $recovery_hash_b: expr,
            $decoder_original_b: expr,
            $decoder_recovery_b: expr,
            $seed_b: expr $(,)?
        ) $(,)?
    ) => {
        use crate::reed_solomon::engine::{Naive, NoSimd};

        roundtrip_two_rounds_inner!(
            $Rate,
            Naive,
            $explicit_reset,
            (
                $original_count_a,
                $recovery_count_a,
                $shard_bytes_a,
                $recovery_hash_a,
                $decoder_original_a,
                $decoder_recovery_a,
                $seed_a,
            ),
            (
                $original_count_b,
                $recovery_count_b,
                $shard_bytes_b,
                $recovery_hash_b,
                $decoder_original_b,
                $decoder_recovery_b,
                $seed_b,
            ),
        );

        roundtrip_two_rounds_inner!(
            $Rate,
            NoSimd,
            $explicit_reset,
            (
                $original_count_a,
                $recovery_count_a,
                $shard_bytes_a,
                $recovery_hash_a,
                $decoder_original_a,
                $decoder_recovery_a,
                $seed_a,
            ),
            (
                $original_count_b,
                $recovery_count_b,
                $shard_bytes_b,
                $recovery_hash_b,
                $decoder_original_b,
                $decoder_recovery_b,
                $seed_b,
            ),
        );
    };
}

macro_rules! roundtrip_two_rounds_inner {
    (
        $Rate: ident,
        $Engine: ident,
        $explicit_reset: expr,
        (
            $original_count_a: expr,
            $recovery_count_a: expr,
            $shard_bytes_a: expr,
            $recovery_hash_a: expr,
            $decoder_original_a: expr,
            $decoder_recovery_a: expr,
            $seed_a: expr $(,)?
        ),
        (
            $original_count_b: expr,
            $recovery_count_b: expr,
            $shard_bytes_b: expr,
            $recovery_hash_b: expr,
            $decoder_original_b: expr,
            $decoder_recovery_b: expr,
            $seed_b: expr $(,)?
        ) $(,)?
    ) => {
        let mut encoder = $Rate::encoder(
            $original_count_a,
            $recovery_count_a,
            $shard_bytes_a,
            $Engine::new(),
            None,
        )
        .unwrap();

        let mut decoder = $Rate::decoder(
            $original_count_a,
            $recovery_count_a,
            $shard_bytes_a,
            $Engine::new(),
            None,
        )
        .unwrap();

        test_util::roundtrip::<$Rate<_>, _, _>(
            &mut encoder,
            &mut decoder,
            $original_count_a,
            $shard_bytes_a,
            $recovery_hash_a,
            $decoder_original_a,
            $decoder_recovery_a,
            $seed_a,
        );

        if $explicit_reset {
            encoder
                .reset($original_count_b, $recovery_count_b, $shard_bytes_b)
                .unwrap();

            decoder
                .reset($original_count_b, $recovery_count_b, $shard_bytes_b)
                .unwrap();
        }

        test_util::roundtrip::<$Rate<_>, _, _>(
            &mut encoder,
            &mut decoder,
            $original_count_b,
            $shard_bytes_b,
            $recovery_hash_b,
            $decoder_original_b,
            $decoder_recovery_b,
            $seed_b,
        );
    };
}

// ======================================================================
// RATE ENCODER - TEST ERRORS

macro_rules! test_rate_encoder_errors {
    ($Encoder:ident) => {
        #[test]
        fn different_shard_size_in_add_original_shard() {
            let mut encoder = $Encoder::new(1, 1, 64, NoSimd::new(), None).unwrap();
            assert_eq!(
                encoder.add_original_shard([0; 128]),
                Err(Error::DifferentShardSize {
                    shard_bytes: 64,
                    got: 128
                }),
            );
        }

        #[test]
        fn invalid_shard_size_in_new() {
            assert_eq!(
                $Encoder::new(1, 1, 123, NoSimd::new(), None).err(),
                Some(Error::InvalidShardSize { shard_bytes: 123 }),
            );
        }

        #[test]
        fn invalid_shard_size_in_reset() {
            let mut encoder = $Encoder::new(1, 1, 64, NoSimd::new(), None).unwrap();
            assert_eq!(
                encoder.reset(1, 1, 123),
                Err(Error::InvalidShardSize { shard_bytes: 123 }),
            );
        }

        #[test]
        fn too_few_original_shards() {
            let mut encoder = $Encoder::new(1, 1, 64, NoSimd::new(), None).unwrap();
            assert_eq!(
                encoder.encode().err(),
                Some(Error::TooFewOriginalShards {
                    original_count: 1,
                    original_received_count: 0
                }),
            );
        }

        #[test]
        fn too_many_original_shards() {
            let mut encoder = $Encoder::new(1, 1, 64, NoSimd::new(), None).unwrap();
            encoder.add_original_shard([0; 64]).unwrap();
            assert_eq!(
                encoder.add_original_shard([0; 64]),
                Err(Error::TooManyOriginalShards { original_count: 1 }),
            );
        }

        #[test]
        fn unsupported_shard_count_in_new() {
            assert_eq!(
                $Encoder::new(0, 1, 64, NoSimd::new(), None).err(),
                Some(Error::UnsupportedShardCount {
                    original_count: 0,
                    recovery_count: 1,
                }),
            );
        }

        #[test]
        fn unsupported_shard_count_in_reset() {
            let mut encoder = $Encoder::new(1, 1, 64, NoSimd::new(), None).unwrap();
            assert_eq!(
                encoder.reset(0, 1, 64),
                Err(Error::UnsupportedShardCount {
                    original_count: 0,
                    recovery_count: 1,
                }),
            );
        }
    };
}

// ======================================================================
// RATE DECODER - TEST ERRORS

macro_rules! test_rate_decoder_errors {
    ($Decoder:ident) => {
        #[test]
        fn different_shard_size_in_add_original_shard() {
            let mut decoder = $Decoder::new(1, 1, 64, NoSimd::new(), None).unwrap();
            assert_eq!(
                decoder.add_original_shard(0, [0; 128]),
                Err(Error::DifferentShardSize {
                    shard_bytes: 64,
                    got: 128
                }),
            );
        }

        #[test]
        fn different_shard_size_in_add_recovery_shard() {
            let mut decoder = $Decoder::new(1, 1, 64, NoSimd::new(), None).unwrap();
            assert_eq!(
                decoder.add_recovery_shard(0, [0; 128]),
                Err(Error::DifferentShardSize {
                    shard_bytes: 64,
                    got: 128
                }),
            );
        }

        #[test]
        fn duplicate_shard_index_in_add_original_shard() {
            let mut decoder = $Decoder::new(1, 1, 64, NoSimd::new(), None).unwrap();
            decoder.add_original_shard(0, [0; 64]).unwrap();
            assert_eq!(
                decoder.add_original_shard(0, [0; 64]),
                Err(Error::DuplicateOriginalShardIndex { index: 0 }),
            );
        }

        #[test]
        fn duplicate_shard_index_in_add_recovert_shard() {
            let mut decoder = $Decoder::new(1, 1, 64, NoSimd::new(), None).unwrap();
            decoder.add_recovery_shard(0, [0; 64]).unwrap();
            assert_eq!(
                decoder.add_recovery_shard(0, [0; 64]),
                Err(Error::DuplicateRecoveryShardIndex { index: 0 }),
            );
        }

        #[test]
        fn invalid_original_shard_index() {
            let mut decoder = $Decoder::new(1, 1, 64, NoSimd::new(), None).unwrap();
            assert_eq!(
                decoder.add_original_shard(1, [0; 64]),
                Err(Error::InvalidOriginalShardIndex {
                    original_count: 1,
                    index: 1,
                }),
            );
        }

        #[test]
        fn invalid_recovery_shard_index() {
            let mut decoder = $Decoder::new(1, 1, 64, NoSimd::new(), None).unwrap();
            assert_eq!(
                decoder.add_recovery_shard(1, [0; 64]),
                Err(Error::InvalidRecoveryShardIndex {
                    recovery_count: 1,
                    index: 1,
                }),
            );
        }

        #[test]
        fn invalid_shard_size_in_new() {
            assert_eq!(
                $Decoder::new(1, 1, 123, NoSimd::new(), None).err(),
                Some(Error::InvalidShardSize { shard_bytes: 123 }),
            );
        }

        #[test]
        fn invalid_shard_size_in_reset() {
            let mut decoder = $Decoder::new(1, 1, 64, NoSimd::new(), None).unwrap();
            assert_eq!(
                decoder.reset(1, 1, 123),
                Err(Error::InvalidShardSize { shard_bytes: 123 }),
            );
        }

        #[test]
        fn not_enough_shards() {
            let mut decoder = $Decoder::new(1, 1, 64, NoSimd::new(), None).unwrap();
            assert_eq!(
                decoder.decode().err(),
                Some(Error::NotEnoughShards {
                    original_count: 1,
                    original_received_count: 0,
                    recovery_received_count: 0,
                }),
            );
        }

        #[test]
        fn unsupported_shard_count_in_new() {
            assert_eq!(
                $Decoder::new(0, 1, 64, NoSimd::new(), None).err(),
                Some(Error::UnsupportedShardCount {
                    original_count: 0,
                    recovery_count: 1,
                }),
            );
        }

        #[test]
        fn unsupported_shard_count_in_reset() {
            let mut decoder = $Decoder::new(1, 1, 64, NoSimd::new(), None).unwrap();
            assert_eq!(
                decoder.reset(0, 1, 64),
                Err(Error::UnsupportedShardCount {
                    original_count: 0,
                    recovery_count: 1,
                }),
            );
        }
    };
}

// ============================================================
// RECOVERY HASHES

// SHA256 hashes of some recovery shards.
// - shard_bytes = 1024 (or 64 if mentioned explicitly)
// - Original shards are from `generate_original`.

// ==================================================
// TINY

// (original_count, recovery_count, seed, hash)

#[rustfmt::skip]
pub(crate) const DEFAULT_TINY: &[(usize, usize, u8, &str)] = &[
    // single original/recovery
    (1, 1, 111, "17e3108283196d04f027f01c23577076a1db3c4caeed6269995733ffef6d3398"), // EITHER
    (1, 2, 112, "cabef22cfe49d9167b4cd40a6a6437b52496af28ff1dcfb6e207c9c337d5affa"), // LOW
    (1, 3, 113, "fda3b35bb91a71b0ba7b6ea437fbf74648ea6e94a4ce2be885b0cd14f0d8005b"), // LOW
    (2, 1, 121, "7fc8ed9211851121e4a80cf995b113f498c20646e18dc312db7d27efd6cd60d2"), // HIGH
    (3, 1, 131, "1f118cce8f4c528a4f68c9215d6996e982bce81ba7c0132193a65961f777943a"), // HIGH

    // 2 .. 8
    (2, 2, 122, "7d53725125394f5913300b40f09055bb75e6335a936305070da3707c9211dd26"), // EITHER
    (2, 3, 123, LOW_2_3),                                                            // LOW
    (2, 4, 124, "3ce3eab3625dae68e164daee1e2bd3304ac7cdcf1ffdd8f81560c2def733e567"), // LOW
    (2, 5, 125, LOW_2_5),                                                            // LOW
    (2, 6, 126, "f7d65a6334421428930e8223962f5e280a6ed75a252cb82b9ae6a27314708013"), // LOW
    (2, 7, 127, "cd75f744cf44cf7036758b3bc096192317b962cf2f32039bd67a535ae8b5d251"), // LOW
    (2, 8, 128, "07964065a913b631645d6e251908650fc4eba4a8b5844cdaab43d76d5f4f3a79"), // LOW
    (3, 2, 132, HIGH_3_2),                                                           // HIGH
    (3, 3, 133, EITHER_3_3),                                                         // EITHER
    (3, 4, 134, EITHER_3_4),                                                         // EITHER
    (3, 5, 135, LOW_3_5),                                                            // LOW
    (3, 6, 136, "531b4db2b2148c609fe1b3d6ab4e6a012193f28647c0eb1ed13344a94057c6fe"), // LOW
    (3, 7, 137, "053434cf04886f7f3bef43743700046f57d2e38cb5682ceaeaccf893c5120c78"), // LOW
    (3, 8, 138, "848b7bc12174a1a74a30aaeccf875fe2be82d4cc8f9b992f04e45607839cd4ff"), // LOW
    (4, 2, 142, "e0c05cb0f4e699694907ce9a5c16034e5b1d8b4eee51942ba87854149036d8f1"), // HIGH
    (4, 3, 143, EITHER_4_3),                                                         // EITHER
    (4, 4, 144, "df2c520f15464bfe3448ebbbfbb6bfc2f64237a7a20cfa65bc6f1046e97470d2"), // EITHER
    (4, 5, 145, "e7709cc3f00e377e15e624df78a7a0a76b49ed5e4c0bc9035dda9e846935746a"), // LOW
    (4, 6, 146, "8852c9526508d934315a3e07dd90f9389f5a6639ed7f3aaee74b066cccbcf033"), // LOW
    (4, 7, 147, "4475531153c9ea65743a64e4f661746dc5cd4c7a70bdc06812f1b73d00d65f36"), // LOW
    (4, 8, 148, "b682387ee7e5e6a42ff5c8b8050c301225f84f98961ba5aee739f3f20d3cae02"), // LOW
    (5, 2, 152, HIGH_5_2),                                                           // HIGH
    (5, 3, 153, HIGH_5_3),                                                           // HIGH
    (5, 4, 154, "3eb67a0993903f688d767928d2d35d5762f25fdb196a5f6a0e49b36f9a5a229b"), // HIGH
    (5, 5, 155, "41b83349a18ec3c20fb19879e0e513512c60078e57b4ff98f57cae0d93effc7c"), // EITHER
    (5, 6, 156, "67766507a7cedaa663f798354f274829703143cd068f68075f6380976a65c99a"), // EITHER
    (5, 7, 157, "a47d23ed58eec1c809799b1c63bcfe75e527489985cf91c0f42f7ae10c9e8abe"), // EITHER
    (5, 8, 158, "ff33eb1539f0573faaf0993c63507ed61d809527505fd26e8e2aa2511e3622c5"), // EITHER
    (6, 2, 162, "6e45e014adf6201172f45c23e2918e2b628c55bc60d9e88c359337758ca63e27"), // HIGH
    (6, 3, 163, "b2295f7f0f055476f9385cdfbba27512d3fef0aee872b9794193a457132af7d4"), // HIGH
    (6, 4, 164, "0242981363ddab69e3f3f7bac4e0aeb8d64ed040eb1925d0d63fbba864a7aebc"), // HIGH
    (6, 5, 165, "0619cf8025f6c6f25b2c4c3609f71224de518108b4d6f577762c5160f2753733"), // EITHER
    (6, 6, 166, "27472dea67ef5470579f8f2fcab5f9370334a91af49382780a6ccf0df6027a98"), // EITHER
    (6, 7, 167, "afffabb84e4987e15af741ac0f919fa73af954fe44c0da223cb67bdcfd3415c2"), // EITHER
    (6, 8, 168, "129b44878eef071c0b2e92b17cdb15139d2d0744f8f5306fa6a4c100396a1e3c"), // EITHER
    (7, 2, 172, "b07a9064742825258206c4c4ab041305ad6d3646380740bb54b938962630df6c"), // HIGH
    (7, 3, 173, "64061b0af048381c22e8b08c19a1148de6859a7bcc26ddee348bdf6006554578"), // HIGH
    (7, 4, 174, "4cdab47a556582096b8195a5bf30f63d3effbb1f9ad9e25a48b41ba260739247"), // HIGH
    (7, 5, 175, "feb342a8e0b9c33d120983c3f4df95ca19fded3e0ed3484a0d02f5ec27961d4b"), // EITHER
    (7, 6, 176, "7f127b5c827854f721c7592faecb11a239894c653ac6efb95cfcf54e1348c326"), // EITHER
    (7, 7, 177, "b03e8b01d887050f762c40cce37042a8b5a8afb601a2476eb138f65b9234efe7"), // EITHER
    (7, 8, 178, "eacf451d3112d43be2619b01bbc40915a109d387e21f7b3c083f00fa7abcdf68"), // EITHER
    (8, 2, 182, "dcf2306c7f9aab2dd0590708864d68ba1a6484632c3a7a4b1c1c56a3d6b0bb50"), // HIGH
    (8, 3, 183, "83c2cdcc981c627f778f061c7eadc6be49e7665c4ed591a0884cfa4adc3a20cf"), // HIGH
    (8, 4, 184, "356d75c370e3ed29c7d458a9d5f5b48798119d0d32dc8e742a423f94647eb085"), // HIGH
    (8, 5, 185, "4b0a3bd10e64f8db57abeddb028ce7c93b89d84b59c2e4805eecf1ef43aef858"), // EITHER
    (8, 6, 186, "44ffaeac7c1585d8b8c3afd813ea388b3dcceeebe3ef46bab4219df554ef057f"), // EITHER
    (8, 7, 187, "2627846d37793df3ddeb1922892c2723a5fefe36b6d244506fa810c11fb70df7"), // EITHER
    (8, 8, 188, "b8da62e75f305a59128b2257162605e541fd252aca8f74ceb2a91fb2a3276d6e"), // EITHER
];

#[rustfmt::skip]
pub(crate) const HIGH_TINY: &[(usize, usize, u8, &str)] = &[
    // single original/recovery
    (1, 1, 111, "17e3108283196d04f027f01c23577076a1db3c4caeed6269995733ffef6d3398"), // EITHER
    (1, 2, 112, "a5bdc2eb1cd88327a675d2fa1df587ea3e7fa42e74975fd8577c5c248ab51824"),
    (1, 3, 113, "ea7c19a1de8308599d84334059c6ca6c1e574ea3cfbe680f749754af986a0b18"),
    (2, 1, 121, "7fc8ed9211851121e4a80cf995b113f498c20646e18dc312db7d27efd6cd60d2"),
    (3, 1, 131, "1f118cce8f4c528a4f68c9215d6996e982bce81ba7c0132193a65961f777943a"),

    // 2 .. 8
    (2, 2, 122, "7d53725125394f5913300b40f09055bb75e6335a936305070da3707c9211dd26"), // EITHER
    (2, 3, 123, "19fb5ce2d7a3db95f819017cf49050eb8cd4b3c626cedf5ca13f6d2ab4eb43c4"),
    (2, 4, 124, "ed0d8db29d770cbafc4fa2ebe5ab991b3a0ee2dd8089f82cbb35de4670ccee50"),
    (2, 5, 125, "9b2818b4442619aed74f277ea7a97aa9d0a92f1c1413fea97091fcd2e696f03a"),
    (2, 6, 126, "cac3955636c60dfa82d0a8383949bbdf0a7c5bbb89422fa764cccea0a927d5d7"),
    (2, 7, 127, "42f34812f503a419fc6ddaee8f3947afc1fc533e9c8b29eae746addceebc1748"),
    (2, 8, 128, "1212dc3e1f8e8743996c303a05a0401d03c72b67dfefc1aaaa2cc07c31f47710"),
    (3, 2, 132, HIGH_3_2),
    (3, 3, 133, EITHER_3_3),
    (3, 4, 134, EITHER_3_4),
    (3, 5, 135, "eb5dc236bdd7aa7d8a927524118161f2dd8e51526653cd31194ee8ff007a8062"),
    (3, 6, 136, "2338d6073e4e5103483f748312f5872141f51dc2fa510695837ea99e3508892c"),
    (3, 7, 137, "6559a2478ce0f362e08934dbec840f3be6a42e3fa9591824548b15811717cf49"),
    (3, 8, 138, "afe6ecd8baf01b3514787a593c73276f1e24d29b4bd909ee0a26d16ea3d07844"),
    (4, 2, 142, "e0c05cb0f4e699694907ce9a5c16034e5b1d8b4eee51942ba87854149036d8f1"),
    (4, 3, 143, EITHER_4_3),
    (4, 4, 144, "df2c520f15464bfe3448ebbbfbb6bfc2f64237a7a20cfa65bc6f1046e97470d2"), // EITHER
    (4, 5, 145, "57e72af02f975404d6d3905394782da034581c137c08c5ebe73acb2d071b38bb"),
    (4, 6, 146, "d07ad54dc275f3c16d68a86fb4893c4e7a2dda9edd4dcf5c90d09ee5c647993a"),
    (4, 7, 147, "32266a50e6f97a901f8eae8d633fcf98d27a2c9e71c8369fbe17acc290d5f817"),
    (4, 8, 148, "0f157da98d800fe60dbb381f3473e122e15549d418bc2cb5f3e57e32fad033b8"),
    (5, 2, 152, HIGH_5_2),
    (5, 3, 153, HIGH_5_3),
    (5, 4, 154, "3eb67a0993903f688d767928d2d35d5762f25fdb196a5f6a0e49b36f9a5a229b"),
    (5, 5, 155, "41b83349a18ec3c20fb19879e0e513512c60078e57b4ff98f57cae0d93effc7c"), // EITHER
    (5, 6, 156, "67766507a7cedaa663f798354f274829703143cd068f68075f6380976a65c99a"), // EITHER
    (5, 7, 157, "a47d23ed58eec1c809799b1c63bcfe75e527489985cf91c0f42f7ae10c9e8abe"), // EITHER
    (5, 8, 158, "ff33eb1539f0573faaf0993c63507ed61d809527505fd26e8e2aa2511e3622c5"), // EITHER
    (6, 2, 162, "6e45e014adf6201172f45c23e2918e2b628c55bc60d9e88c359337758ca63e27"),
    (6, 3, 163, "b2295f7f0f055476f9385cdfbba27512d3fef0aee872b9794193a457132af7d4"),
    (6, 4, 164, "0242981363ddab69e3f3f7bac4e0aeb8d64ed040eb1925d0d63fbba864a7aebc"),
    (6, 5, 165, "0619cf8025f6c6f25b2c4c3609f71224de518108b4d6f577762c5160f2753733"), // EITHER
    (6, 6, 166, "27472dea67ef5470579f8f2fcab5f9370334a91af49382780a6ccf0df6027a98"), // EITHER
    (6, 7, 167, "afffabb84e4987e15af741ac0f919fa73af954fe44c0da223cb67bdcfd3415c2"), // EITHER
    (6, 8, 168, "129b44878eef071c0b2e92b17cdb15139d2d0744f8f5306fa6a4c100396a1e3c"), // EITHER
    (7, 2, 172, "b07a9064742825258206c4c4ab041305ad6d3646380740bb54b938962630df6c"),
    (7, 3, 173, "64061b0af048381c22e8b08c19a1148de6859a7bcc26ddee348bdf6006554578"),
    (7, 4, 174, "4cdab47a556582096b8195a5bf30f63d3effbb1f9ad9e25a48b41ba260739247"),
    (7, 5, 175, "feb342a8e0b9c33d120983c3f4df95ca19fded3e0ed3484a0d02f5ec27961d4b"), // EITHER
    (7, 6, 176, "7f127b5c827854f721c7592faecb11a239894c653ac6efb95cfcf54e1348c326"), // EITHER
    (7, 7, 177, "b03e8b01d887050f762c40cce37042a8b5a8afb601a2476eb138f65b9234efe7"), // EITHER
    (7, 8, 178, "eacf451d3112d43be2619b01bbc40915a109d387e21f7b3c083f00fa7abcdf68"), // EITHER
    (8, 2, 182, "dcf2306c7f9aab2dd0590708864d68ba1a6484632c3a7a4b1c1c56a3d6b0bb50"),
    (8, 3, 183, "83c2cdcc981c627f778f061c7eadc6be49e7665c4ed591a0884cfa4adc3a20cf"),
    (8, 4, 184, "356d75c370e3ed29c7d458a9d5f5b48798119d0d32dc8e742a423f94647eb085"),
    (8, 5, 185, "4b0a3bd10e64f8db57abeddb028ce7c93b89d84b59c2e4805eecf1ef43aef858"), // EITHER
    (8, 6, 186, "44ffaeac7c1585d8b8c3afd813ea388b3dcceeebe3ef46bab4219df554ef057f"), // EITHER
    (8, 7, 187, "2627846d37793df3ddeb1922892c2723a5fefe36b6d244506fa810c11fb70df7"), // EITHER
    (8, 8, 188, "b8da62e75f305a59128b2257162605e541fd252aca8f74ceb2a91fb2a3276d6e"), // EITHER
];

#[rustfmt::skip]
pub(crate) const LOW_TINY: &[(usize, usize, u8, &str)] = &[
    // single original/recovery
    (1, 1, 111, "17e3108283196d04f027f01c23577076a1db3c4caeed6269995733ffef6d3398"), // EITHER
    (1, 2, 112, "cabef22cfe49d9167b4cd40a6a6437b52496af28ff1dcfb6e207c9c337d5affa"),
    (1, 3, 113, "fda3b35bb91a71b0ba7b6ea437fbf74648ea6e94a4ce2be885b0cd14f0d8005b"),
    (2, 1, 121, "446657e70765196f11c9df04fcacc74ef915cdb634633e0d5755c1ca6e46e323"),
    (3, 1, 131, "b93350bf3318af823674c954d274f51ed1bef1a49a5240338d31440aebbf8af5"),

    // 2 .. 8
    (2, 2, 122, "7d53725125394f5913300b40f09055bb75e6335a936305070da3707c9211dd26"), // EITHER
    (2, 3, 123, LOW_2_3),
    (2, 4, 124, "3ce3eab3625dae68e164daee1e2bd3304ac7cdcf1ffdd8f81560c2def733e567"),
    (2, 5, 125, LOW_2_5),
    (2, 6, 126, "f7d65a6334421428930e8223962f5e280a6ed75a252cb82b9ae6a27314708013"),
    (2, 7, 127, "cd75f744cf44cf7036758b3bc096192317b962cf2f32039bd67a535ae8b5d251"),
    (2, 8, 128, "07964065a913b631645d6e251908650fc4eba4a8b5844cdaab43d76d5f4f3a79"),
    (3, 2, 132, "1e4d449a4d59f974258ff2fb8dfde7ea6554bd1b5a7d524d801cc9e0503c0f0a"),
    (3, 3, 133, EITHER_3_3),
    (3, 4, 134, EITHER_3_4),
    (3, 5, 135, LOW_3_5),
    (3, 6, 136, "531b4db2b2148c609fe1b3d6ab4e6a012193f28647c0eb1ed13344a94057c6fe"),
    (3, 7, 137, "053434cf04886f7f3bef43743700046f57d2e38cb5682ceaeaccf893c5120c78"),
    (3, 8, 138, "848b7bc12174a1a74a30aaeccf875fe2be82d4cc8f9b992f04e45607839cd4ff"),
    (4, 2, 142, "35a5d572f75bbf8b2a850d503bf988a10dc2f30f15ff5cde611f73ea6cc44d55"),
    (4, 3, 143, EITHER_4_3),
    (4, 4, 144, "df2c520f15464bfe3448ebbbfbb6bfc2f64237a7a20cfa65bc6f1046e97470d2"), // EITHER
    (4, 5, 145, "e7709cc3f00e377e15e624df78a7a0a76b49ed5e4c0bc9035dda9e846935746a"),
    (4, 6, 146, "8852c9526508d934315a3e07dd90f9389f5a6639ed7f3aaee74b066cccbcf033"),
    (4, 7, 147, "4475531153c9ea65743a64e4f661746dc5cd4c7a70bdc06812f1b73d00d65f36"),
    (4, 8, 148, "b682387ee7e5e6a42ff5c8b8050c301225f84f98961ba5aee739f3f20d3cae02"),
    (5, 2, 152, "6728e606f2f9dd9559b0370b495685444519c04ffdcfa5120398a0516858a83f"),
    (5, 3, 153, "b458c5b07fbacfebb9a836251548505b43d5cbca872eecfad098f2bdda111824"),
    (5, 4, 154, "e82d6583b78c42479c98311daa5aa620b64979259bf49ff13c75daf889d3bf22"),
    (5, 5, 155, "41b83349a18ec3c20fb19879e0e513512c60078e57b4ff98f57cae0d93effc7c"), // EITHER
    (5, 6, 156, "67766507a7cedaa663f798354f274829703143cd068f68075f6380976a65c99a"), // EITHER
    (5, 7, 157, "a47d23ed58eec1c809799b1c63bcfe75e527489985cf91c0f42f7ae10c9e8abe"), // EITHER
    (5, 8, 158, "ff33eb1539f0573faaf0993c63507ed61d809527505fd26e8e2aa2511e3622c5"), // EITHER
    (6, 2, 162, "218e25db4678002119fe557c7fc7c6d80fd43c1a9cfc779623ce35455dc8ff75"),
    (6, 3, 163, "ac7d0eeb90253d1e846b2e741557320b80bcf2ae0a8901a18c2d137230e8994b"),
    (6, 4, 164, "c42c4deb89c2c3f19856628e887cc7db72165e5d836e584ac4fdbfac0a356b56"),
    (6, 5, 165, "0619cf8025f6c6f25b2c4c3609f71224de518108b4d6f577762c5160f2753733"), // EITHER
    (6, 6, 166, "27472dea67ef5470579f8f2fcab5f9370334a91af49382780a6ccf0df6027a98"), // EITHER
    (6, 7, 167, "afffabb84e4987e15af741ac0f919fa73af954fe44c0da223cb67bdcfd3415c2"), // EITHER
    (6, 8, 168, "129b44878eef071c0b2e92b17cdb15139d2d0744f8f5306fa6a4c100396a1e3c"), // EITHER
    (7, 2, 172, "1a435f1723561eead67bf9a37bda196814afe2c7b77cd82c3c438600ef616e61"),
    (7, 3, 173, "86ab51f58f9a0f24deeb1ab83cff451983cf679ab9df81ef1a4daf9c3405495a"),
    (7, 4, 174, "192979d61b5dbe112839bc0c4051945568a9ac7c4dc4c1d8e7cc6c4c27213bb9"),
    (7, 5, 175, "feb342a8e0b9c33d120983c3f4df95ca19fded3e0ed3484a0d02f5ec27961d4b"), // EITHER
    (7, 6, 176, "7f127b5c827854f721c7592faecb11a239894c653ac6efb95cfcf54e1348c326"), // EITHER
    (7, 7, 177, "b03e8b01d887050f762c40cce37042a8b5a8afb601a2476eb138f65b9234efe7"), // EITHER
    (7, 8, 178, "eacf451d3112d43be2619b01bbc40915a109d387e21f7b3c083f00fa7abcdf68"), // EITHER
    (8, 2, 182, "ed7c5de1bd38abf2aeda70670ecc61caac6a133d742fe56e52c69e464ba2e9f5"),
    (8, 3, 183, "98e3bbaf60b13e1b11d7a1ed3cc11686e10177ecfab8c7bfecf83c3f011ab353"),
    (8, 4, 184, "dee6491a8007d007db853485dc55b013d2243b7ed9f3a62cd2d3fc77f0fd0899"),
    (8, 5, 185, "4b0a3bd10e64f8db57abeddb028ce7c93b89d84b59c2e4805eecf1ef43aef858"), // EITHER
    (8, 6, 186, "44ffaeac7c1585d8b8c3afd813ea388b3dcceeebe3ef46bab4219df554ef057f"), // EITHER
    (8, 7, 187, "2627846d37793df3ddeb1922892c2723a5fefe36b6d244506fa810c11fb70df7"), // EITHER
    (8, 8, 188, "b8da62e75f305a59128b2257162605e541fd252aca8f74ceb2a91fb2a3276d6e"), // EITHER
];

// ==================================================
// EITHER RATE

// 3 original ; 3 recovery ; 133 seed
pub(crate) const EITHER_3_3: &str =
    "9502b325f6f50a25e6816144603f1b0cda09e00b4949965babbaf8266ff81e84";

// 3 original ; 4 recovery ; 134 seed
pub(crate) const EITHER_3_4: &str =
    "e534a7260f1e8aca3c2983503138f158d8977b82f1d3c09b2cedb66d01c01e0b";

// 4 original ; 3 recovery ; 143 seed
pub(crate) const EITHER_4_3: &str =
    "e43d0903b619f4b17c5389ce869317ce549e3f6d2fe3aa2805ef4d4fb7adce74";

// 32768 original ; 32768 recovery ; 11 seed ; shard_bytes = 64
pub(crate) const EITHER_32768_32768_11: &str =
    "432025ead0e3f432f74e30500076a8c2b5554f5dfb7767b62fc3a8126eef7389";

// ==================================================
// HIGH RATE

// 3 original ; 2 recovery ; 132 seed
pub(crate) const HIGH_3_2: &str =
    "afd47751b63fb0a62671e0e4a124a8ba51eb6d4b55f79c3dd54a60c28583634f";

// 3 original ; 2 recovery ; 232 seed
pub(crate) const HIGH_3_2_232: &str =
    "2ee88d495ae1fff216f2865dbbdda2e1a051c5d98c7117a2a0b2ebcdfb57cd33";

// 5 original ; 2 recovery ; 152 seed
pub(crate) const HIGH_5_2: &str =
    "5387208d6756e3e79558a9b9ddebe0439eb3b08eec2393d4acafce6fc5332683";

// 5 original ; 3 recovery ; 153 seed
pub(crate) const HIGH_5_3: &str =
    "6f53d5175900d70b4821d1d0c947d0c47a802add0d620bfa72d57dd983dfc156";

// 3000 original ; 30000 recovery ; 14 seed ; shard_bytes = 64
// NOTE: Chunk size is 4096, with partial chunk at end.
pub(crate) const HIGH_3000_30000_14: &str =
    "2d7d97fd92be0721b4fcfac8814fe0dd9ad07959eb40558c6ed9af09943fed4e";

// 60000 original ; 3000 recovery ; 12 seed ; shard_bytes = 64
// NOTE: Chunk size is 4096, with partial chunk at end.
pub(crate) const HIGH_60000_3000_12: &str =
    "88e68e1d86a0fc168a549e195845d20b49ff85734db20d560c36ff2e14f78676";

// 34000 original ; 2000 recovery ; 123 seed ; shard_bytes = 8
pub(crate) const HIGH_34000_2000_123_8: &str =
    "8bd33dbe0189b5bffcb843fd93fd8c85daada2533cc7df0c352773e846b701f5";

// ==================================================
// LOW RATE

// 2 original ; 3 recovery ; 123 seed
pub(crate) const LOW_2_3: &str = "f682a6c87c2bcd3e0feddbeff5c34f9d14026b78c44e5fdb5cf3cf71ec15e1f4";

// 2 original ; 3 recovery ; 223 seed
pub(crate) const LOW_2_3_223: &str =
    "2dc25a5dc42b2d1f94a80489e9f357a48f011f931cdac3ed7c85e2abb07063a2";

// 2 original ; 5 recovery ; 125 seed
pub(crate) const LOW_2_5: &str = "24449ae058f54a33b3b7ee568761e68e36bd7171ee2a3271a0fbd2f07ac65a7c";

// 3 original ; 5 recovery ; 135 seed
pub(crate) const LOW_3_5: &str = "c23920347f00328dceca9cb6012d797d97f366617cf27aae5c45b4f0b8491552";

// 3000 original ; 60000 recovery ; 13 seed ; shard_bytes = 64
// NOTE: Chunk size is 4096, with partial chunk at end.
pub(crate) const LOW_3000_60000_13: &str =
    "d44f9c9ed9158f8aad140794e64a730577327f195753af21b810090966b4b4df";

// 30000 original ; 3000 recovery ; 15 seed ; shard_bytes = 64
// NOTE: Chunk size is 4096, with partial chunk at end.
pub(crate) const LOW_30000_3000_15: &str =
    "202f99a2ade121d2404e967d5c04ff390f7a147070a2dcbe71dcf3baeafdf93a";

// 2000 original ; 34000 recovery ; 123 seed ; shard_bytes = 8
pub(crate) const LOW_2000_34000_123_8: &str =
    "9bd2da4d03580d3e2471c60a49595b209a6f9a5f1d504d0c4bd017b953efdd99";
