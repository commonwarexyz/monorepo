#![no_main]

use arbitrary::Arbitrary;
use commonware_consensus::{
    simplex::{
        elector::{Config as ElectorConfig, Elector, Random, RoundRobin},
        scheme::{bls12381_threshold::vrf as bls12381_threshold_vrf, ed25519},
    },
    types::{Round, View},
};
use commonware_cryptography::{
    bls12381::primitives::variant::{MinPk, MinSig},
    ed25519::{PrivateKey, PublicKey},
    Hasher, Sha256, Signer,
};
use commonware_math::algebra::Random as _;
use commonware_utils::{ordered::Set, TryCollect};
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, SeedableRng};
use std::sync::OnceLock;

#[allow(clippy::large_enum_variant)]
#[derive(Arbitrary, Debug)]
enum FuzzElector {
    RoundRobin,
    RoundRobinShuffled([u8; 32]),
    RandomMinPk(bls12381_threshold_vrf::Certificate<MinPk>),
    RandomMinSig(bls12381_threshold_vrf::Certificate<MinSig>),
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    participants_count: u8,
    round: Round,
    elector: FuzzElector,
}

fn participant_pool() -> &'static [PublicKey] {
    static PARTICIPANTS: OnceLock<Vec<PublicKey>> = OnceLock::new();
    PARTICIPANTS.get_or_init(|| {
        (1..=u8::MAX)
            .map(|i| {
                let mut rng = StdRng::seed_from_u64(i as u64);
                let private_key = PrivateKey::random(&mut rng);
                private_key.public_key()
            })
            .collect()
    })
}

fn participants(participants_count: u8) -> Option<Set<PublicKey>> {
    if participants_count == 0 {
        return None;
    }
    participant_pool()
        .iter()
        .take(participants_count as usize)
        .cloned()
        .try_collect::<Set<_>>()
        .ok()
}

fn expected_round_robin(round: Round, participants: usize) -> u32 {
    ((round.epoch().get().wrapping_add(round.view().get())) as usize % participants) as u32
}

fn expected_shuffled(seed: &[u8], round: Round, participants: usize) -> u32 {
    let mut permutation: Vec<_> = (0..participants as u32).collect();
    permutation.sort_by_key(|index| {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(&index.to_be_bytes());
        hasher.finalize()
    });
    let idx = (round.epoch().get().wrapping_add(round.view().get())) as usize % participants;
    permutation[idx]
}

fn assert_round_robin(input: &FuzzInput) {
    let Some(participants) = participants(input.participants_count) else {
        return;
    };
    let elector = <RoundRobin<Sha256> as ElectorConfig<ed25519::Scheme>>::build(
        RoundRobin::<Sha256>::default(),
        &participants,
    );
    let leader = elector.elect(input.round, None);
    assert_eq!(
        leader.get(),
        expected_round_robin(input.round, participants.len())
    );
}

fn assert_round_robin_shuffled(input: &FuzzInput, seed: &[u8; 32]) {
    let Some(participants) = participants(input.participants_count) else {
        return;
    };
    let elector = <RoundRobin<Sha256> as ElectorConfig<ed25519::Scheme>>::build(
        RoundRobin::<Sha256>::shuffled(seed),
        &participants,
    );
    let leader = elector.elect(input.round, None);
    assert_eq!(
        leader.get(),
        expected_shuffled(seed, input.round, participants.len())
    );
}

fn assert_random_minpk(
    input: &FuzzInput,
    certificate: &bls12381_threshold_vrf::Certificate<MinPk>,
) {
    let Some(participants) = participants(input.participants_count) else {
        return;
    };
    let elector = Random.build(&participants);
    let seed = if input.round.view() == View::new(1) {
        None
    } else {
        let Some(certificate) = certificate.get() else {
            return;
        };
        Some(certificate.seed_signature)
    };
    // RandomElector is a thin wrapper around Random::select_leader. This pins
    // the wrapper's certificate-seed extraction and view-1 fallback behavior.
    let leader = elector.elect(input.round, seed.as_ref().map(|_| certificate));
    assert_eq!(
        leader,
        Random::select_leader::<MinPk>(input.round, participants.len() as u32, seed)
    );
}

fn assert_random_minsig(
    input: &FuzzInput,
    certificate: &bls12381_threshold_vrf::Certificate<MinSig>,
) {
    let Some(participants) = participants(input.participants_count) else {
        return;
    };
    let elector = Random.build(&participants);
    let seed = if input.round.view() == View::new(1) {
        None
    } else {
        let Some(certificate) = certificate.get() else {
            return;
        };
        Some(certificate.seed_signature)
    };
    // RandomElector is a thin wrapper around Random::select_leader. This pins
    // the wrapper's certificate-seed extraction and view-1 fallback behavior.
    let leader = elector.elect(input.round, seed.as_ref().map(|_| certificate));
    assert_eq!(
        leader,
        Random::select_leader::<MinSig>(input.round, participants.len() as u32, seed)
    );
}

fuzz_target!(|input: FuzzInput| {
    match &input.elector {
        FuzzElector::RoundRobin => assert_round_robin(&input),
        FuzzElector::RoundRobinShuffled(seed) => assert_round_robin_shuffled(&input, seed),
        FuzzElector::RandomMinPk(certificate) => assert_random_minpk(&input, certificate),
        FuzzElector::RandomMinSig(certificate) => assert_random_minsig(&input, certificate),
    }
});
