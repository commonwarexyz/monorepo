//! Codec round-trip and conformance tests for the protocol types.
//!
//! Values come from the [`Arbitrary`] implementations and decode under their fixed codec profile.

use super::{arbitrary::codec_config, *};
use crate::multimmit::mocks::MockBody;
use ::arbitrary::Arbitrary;
use commonware_codec::{
    Decode, Encode, Read,
    conformance::{CodecConformance, generate_value},
};
use commonware_cryptography::{
    Sha256,
    bls12381::primitives::variant::{MinPk, MinSig},
    sha256::Digest as Sha256Digest,
};
use core::fmt::Debug;

fn assert_round_trip<T>(cfg: T::Cfg, n_cases: u64)
where
    T: Read + Encode + Eq + Debug + for<'a> Arbitrary<'a>,
{
    for seed in 0..n_cases {
        let value = generate_value::<T>(seed);
        let encoded = value.encode();
        let decoded = T::decode_cfg(encoded.clone(), &cfg)
            .expect("generated value should decode under its codec config");
        assert_eq!(decoded, value);
        assert!(T::decode_cfg(encoded.slice(..encoded.len() - 1), &cfg).is_err());
    }
}

/// Registers one round-trip test and one conformance test per listed type.
///
/// `$config` names the codec profile inside the decode configuration expressions.
macro_rules! codec_cases {
    ($config:ident => { $($ty:ty => ($cfg:expr, $n_cases:expr)),* $(,)? }) => {
        #[test]
        fn generated_values_round_trip() {
            let $config = codec_config();
            $(assert_round_trip::<$ty>($cfg, $n_cases);)*
        }

        commonware_conformance::conformance_tests! {
            $(CodecConformance<$ty> => $n_cases,)*
        }
    };
}

codec_cases!(config => {
    ChainId => ((), 1024),
    Position => ((), 1024),
    PositionDeviation => ((), 1024),
    ExtensionDeviation => (128, 128),
    CertificateId<Sha256Digest> => ((), 1024),
    BlockRef<Sha256Digest> => ((), 1024),
    TipRecord<Sha256Digest> => (config, 128),
    EpochGenesis<Sha256Digest> => (config, 128),
    TransactionBlockHeader<Sha256Digest> => ((), 128),
    TransactionBlock<Sha256, MockBody> => ((), 128),
    Attestation<MinSig> => ((), 128),
    ThresholdShare<MinSig> => ((), 128),
    SignedTransactionBlock<MinSig, Sha256Digest> => ((), 128),
    DaVote<MinSig, Sha256Digest> => ((), 128),
    DaCertificate<MinSig, Sha256Digest> => ((), 128),
    Anchor<MinSig, Sha256Digest> => ((), 128),
    ChainProposal<MinSig, Sha256Digest> => ((ChainId::new(0), config), 128),
    LeaderBlock<MinSig, Sha256Digest> => (config, 128),
    SignedLeaderBlock<MinSig, Sha256Digest> => (config, 128),
    Extension<Sha256Digest> => (config.extension_bound(), 128),
    Ballot<Sha256Digest> => (config, 128),
    VoteBody<Sha256Digest> => (config, 128),
    Vote<MinSig, Sha256Digest> => (config, 128),
    NoVote<MinSig> => ((), 128),
    Nullify<MinSig> => ((), 128),
    ViewMessage<MinSig, Sha256Digest> => (config, 128),
    ConflictingVote<Sha256Digest> => (config, 128),
    Nullification<MinSig> => ((), 128),
    Vqc<MinSig, Sha256Digest> => (config, 128),
    Lqc<MinSig, Sha256Digest> => (config, 128),
    Attestation<MinPk> => ((), 128),
    ThresholdShare<MinPk> => ((), 128),
    SignedTransactionBlock<MinPk, Sha256Digest> => ((), 128),
    DaVote<MinPk, Sha256Digest> => ((), 128),
    DaCertificate<MinPk, Sha256Digest> => ((), 128),
    Anchor<MinPk, Sha256Digest> => ((), 128),
    ChainProposal<MinPk, Sha256Digest> => ((ChainId::new(0), config), 128),
    LeaderBlock<MinPk, Sha256Digest> => (config, 128),
    SignedLeaderBlock<MinPk, Sha256Digest> => (config, 128),
    Vote<MinPk, Sha256Digest> => (config, 128),
    NoVote<MinPk> => ((), 128),
    Nullify<MinPk> => ((), 128),
    ViewMessage<MinPk, Sha256Digest> => (config, 128),
    Nullification<MinPk> => ((), 128),
    Vqc<MinPk, Sha256Digest> => (config, 128),
    Lqc<MinPk, Sha256Digest> => (config, 128),
});
