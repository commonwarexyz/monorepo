//! Codec round-trip and conformance tests for the protocol types.
//!
//! Values come from the [`Arbitrary`] implementations and decode under their fixed codec profile.

use super::{arbitrary::codec_config, *};
use crate::multimmit::mocks::{Bls, Ed25519, MockBody};
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
    Attestation<Bls<MinSig>> => ((), 128),
    DaAttestation<Bls<MinSig>> => ((), 128),
    NullifyAttestation<Bls<MinSig>> => ((), 128),
    SignedTransactionBlock<Bls<MinSig>, Sha256Digest> => ((), 128),
    DaVote<Bls<MinSig>, Sha256Digest> => ((), 128),
    DaCertificate<Bls<MinSig>, Sha256Digest> => (config, 128),
    Anchor<Bls<MinSig>, Sha256Digest> => (config, 128),
    ChainProposal<Bls<MinSig>, Sha256Digest> => ((ChainId::new(0), config), 128),
    LeaderBlock<Bls<MinSig>, Sha256Digest> => (config, 128),
    SignedLeaderBlock<Bls<MinSig>, Sha256Digest> => (config, 128),
    Extension<Sha256Digest> => (config.extension_bound(), 128),
    Ballot<Sha256Digest> => (config, 128),
    VoteBody<Sha256Digest> => (config, 128),
    Vote<Bls<MinSig>, Sha256Digest> => (config, 128),
    NoVote<Bls<MinSig>> => ((), 128),
    Nullify<Bls<MinSig>> => ((), 128),
    ViewMessage<Bls<MinSig>, Sha256Digest> => (config, 128),
    ConflictingVote<Sha256Digest> => (config, 128),
    Nullification<Bls<MinSig>> => (config, 128),
    Vqc<Bls<MinSig>, Sha256Digest> => (config, 128),
    Lqc<Bls<MinSig>, Sha256Digest> => (config, 128),
    Attestation<Bls<MinPk>> => ((), 128),
    DaAttestation<Bls<MinPk>> => ((), 128),
    NullifyAttestation<Bls<MinPk>> => ((), 128),
    SignedTransactionBlock<Bls<MinPk>, Sha256Digest> => ((), 128),
    DaVote<Bls<MinPk>, Sha256Digest> => ((), 128),
    DaCertificate<Bls<MinPk>, Sha256Digest> => (config, 128),
    Anchor<Bls<MinPk>, Sha256Digest> => (config, 128),
    ChainProposal<Bls<MinPk>, Sha256Digest> => ((ChainId::new(0), config), 128),
    LeaderBlock<Bls<MinPk>, Sha256Digest> => (config, 128),
    SignedLeaderBlock<Bls<MinPk>, Sha256Digest> => (config, 128),
    Vote<Bls<MinPk>, Sha256Digest> => (config, 128),
    NoVote<Bls<MinPk>> => ((), 128),
    Nullify<Bls<MinPk>> => ((), 128),
    ViewMessage<Bls<MinPk>, Sha256Digest> => (config, 128),
    Nullification<Bls<MinPk>> => (config, 128),
    Vqc<Bls<MinPk>, Sha256Digest> => (config, 128),
    Lqc<Bls<MinPk>, Sha256Digest> => (config, 128),
    Attestation<Ed25519> => ((), 128),
    DaAttestation<Ed25519> => ((), 128),
    NullifyAttestation<Ed25519> => ((), 128),
    SignedTransactionBlock<Ed25519, Sha256Digest> => ((), 128),
    DaVote<Ed25519, Sha256Digest> => ((), 128),
    DaCertificate<Ed25519, Sha256Digest> => (config, 128),
    Anchor<Ed25519, Sha256Digest> => (config, 128),
    LeaderBlock<Ed25519, Sha256Digest> => (config, 128),
    SignedLeaderBlock<Ed25519, Sha256Digest> => (config, 128),
    Vote<Ed25519, Sha256Digest> => (config, 128),
    NoVote<Ed25519> => ((), 128),
    Nullify<Ed25519> => ((), 128),
    Nullification<Ed25519> => (config, 128),
    Vqc<Ed25519, Sha256Digest> => (config, 128),
    Lqc<Ed25519, Sha256Digest> => (config, 128),
});
