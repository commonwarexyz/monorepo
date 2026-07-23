#![no_main]

use arbitrary::Arbitrary;
use commonware_consensus::{
    simplex::{
        elector::{self, Elector, Random, RoundRobin},
        scheme::{bls12381_threshold::vrf as bls12381_threshold_vrf, ed25519},
    },
    types::{Round, TermLength, View},
};
use commonware_cryptography::{
    Sha256, Signer,
    bls12381::primitives::variant::{MinPk, MinSig},
    certificate::Scheme,
    ed25519::{PrivateKey, PublicKey},
};
use commonware_math::algebra::Random as _;
use commonware_utils::{TestRng, TryCollect, ordered::Set};
use libfuzzer_sys::fuzz_target;
use std::time::Duration;

#[allow(clippy::large_enum_variant)]
#[derive(Arbitrary, Debug)]
enum FuzzElector {
    RoundRobin(TermLength),
    RoundRobinShuffled([u8; 32], TermLength),
    RandomMinPk(bls12381_threshold_vrf::Certificate<MinPk>),
    RandomMinSig(bls12381_threshold_vrf::Certificate<MinSig>),
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    participants_count: u8,
    round: Round,
    elector: FuzzElector,
}

fn fuzz<S, L>(input: &FuzzInput, elector_config: L, certificate: Option<&S::Certificate>)
where
    S: Scheme<PublicKey = PublicKey>,
    L: elector::Config<S>,
{
    let Ok(participants) = (1..=input.participants_count)
        .map(|i| {
            let mut rng = TestRng::new(i as u64);
            let private_key = PrivateKey::random(&mut rng);
            private_key.public_key()
        })
        .try_collect::<Set<_>>()
    else {
        return;
    };

    if participants.is_empty() {
        return;
    }

    let elector = elector_config.build(&participants);

    // For view 1 certificate should be None, for other views use provided certificate
    if input.round.view() == View::new(1) {
        let leader = elector.elect(input.round, None);
        assert!(leader.get() < participants.len() as u32);
    } else {
        let leader = elector.elect(input.round, certificate);
        assert!(leader.get() < participants.len() as u32);
    }
}

fuzz_target!(|input: FuzzInput| {
    match &input.elector {
        FuzzElector::RoundRobin(term_length) => {
            let elector = match term_length.get() {
                1 => RoundRobin::<Sha256>::default(),
                _ => {
                    RoundRobin::<Sha256>::default().with_term(*term_length, Duration::from_secs(12))
                }
            };
            fuzz::<ed25519::Scheme, _>(&input, elector, None);
        }
        FuzzElector::RoundRobinShuffled(seed, term_length) => {
            let elector = match term_length.get() {
                1 => RoundRobin::<Sha256>::shuffled(seed),
                _ => RoundRobin::<Sha256>::shuffled(seed)
                    .with_term(*term_length, Duration::from_secs(12)),
            };
            fuzz::<ed25519::Scheme, _>(&input, elector, None);
        }
        FuzzElector::RandomMinPk(certificate) => {
            fuzz::<bls12381_threshold_vrf::Scheme<_, MinPk>, _>(&input, Random, Some(certificate));
        }
        FuzzElector::RandomMinSig(certificate) => {
            fuzz::<bls12381_threshold_vrf::Scheme<_, MinSig>, _>(&input, Random, Some(certificate));
        }
    }
});
