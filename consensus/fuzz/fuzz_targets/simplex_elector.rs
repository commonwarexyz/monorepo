#![no_main]

use arbitrary::Arbitrary;
use commonware_consensus::{
    simplex::{
        elector::{Elector, Random, RoundRobin},
        scheme::{bls12381_threshold, ed25519},
    },
    types::{Round, View},
};
use commonware_cryptography::{
    bls12381::primitives::variant::{MinPk, MinSig},
    certificate::Scheme,
    ed25519::{PrivateKey, PublicKey},
    Signer,
};
use commonware_math::algebra::Random as _;
use commonware_utils::{ordered::Set, TryCollect};
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, SeedableRng};

#[allow(clippy::large_enum_variant)]
#[derive(Arbitrary, Debug)]
enum FuzzElector {
    RoundRobin,
    RoundRobinShuffled([u8; 32]),
    RandomMinPk(bls12381_threshold::Signature<MinPk>),
    RandomMinSig(bls12381_threshold::Signature<MinSig>),
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    participants_count: u8,
    round: Round,
    elector: FuzzElector,
}

fn fuzz<S, E>(input: &FuzzInput, mut elector: E, certificate: Option<&S::Certificate>)
where
    S: Scheme<PublicKey = PublicKey>,
    E: Elector<S>,
{
    let Ok(participants) = (1..=input.participants_count)
        .map(|i| {
            let mut rng = StdRng::seed_from_u64(i as u64);
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

    elector.initialize(&participants);

    // For view 1 certificate should be None, for other views use provided certificate
    if input.round.view() == View::new(1) {
        let leader = elector.elect(input.round, None);
        assert!(leader < participants.len() as u32);
    } else {
        let leader = elector.elect(input.round, certificate);
        assert!(leader < participants.len() as u32);
    }
}

fuzz_target!(|input: FuzzInput| {
    match &input.elector {
        FuzzElector::RoundRobin => {
            fuzz::<ed25519::Scheme, _>(&input, <RoundRobin>::default(), None);
        }
        FuzzElector::RoundRobinShuffled(seed) => {
            fuzz::<ed25519::Scheme, _>(&input, <RoundRobin>::shuffled(seed), None);
        }
        FuzzElector::RandomMinPk(certificate) => {
            fuzz::<bls12381_threshold::Scheme<_, MinPk>, _>(
                &input,
                Random::default(),
                Some(certificate),
            );
        }
        FuzzElector::RandomMinSig(certificate) => {
            fuzz::<bls12381_threshold::Scheme<_, MinSig>, _>(
                &input,
                Random::default(),
                Some(certificate),
            );
        }
    }
});
