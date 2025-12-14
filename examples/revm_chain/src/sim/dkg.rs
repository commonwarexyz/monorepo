use super::ThresholdScheme;
use commonware_consensus::simplex;
use commonware_cryptography::{
    bls12381::{
        dkg,
        primitives::{sharing::Mode, variant::MinSig},
    },
    ed25519, Signer as _,
};
use commonware_utils::{ordered::Set, TryCollect as _};
use rand::{rngs::StdRng, SeedableRng as _};

pub(super) fn participants_set(
    participants: &[ed25519::PublicKey],
) -> anyhow::Result<Set<ed25519::PublicKey>> {
    participants
        .iter()
        .cloned()
        .try_collect()
        .map_err(|_| anyhow::anyhow!("participant public keys are not unique"))
}

pub(super) fn threshold_schemes(
    seed: u64,
    n: usize,
) -> anyhow::Result<(Vec<ed25519::PublicKey>, Vec<ThresholdScheme>)> {
    let participants: Set<ed25519::PublicKey> = (0..n)
        .map(|i| ed25519::PrivateKey::from_seed(seed.wrapping_add(i as u64)).public_key())
        .try_collect()
        .expect("participant public keys are unique");

    let mut rng = StdRng::seed_from_u64(seed);
    let (output, shares) = dkg::deal::<MinSig, _>(&mut rng, Mode::default(), participants.clone())
        .map_err(|e| anyhow::anyhow!("dkg deal failed: {e:?}"))?;

    let mut schemes = Vec::with_capacity(n);
    for pk in participants.iter() {
        let share = shares.get_value(pk).expect("share exists").clone();
        let scheme = simplex::signing_scheme::bls12381_threshold::Scheme::signer(
            participants.clone(),
            output.public().clone(),
            share,
        )
        .expect("signer should exist");
        schemes.push(scheme);
    }

    Ok((participants.into(), schemes))
}
