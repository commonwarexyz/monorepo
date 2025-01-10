use super::{wire, View};
use crate::{
    simplex::encoder::{nullify_message, proposal_message, seed_message},
    ThresholdSupervisor,
};
use commonware_cryptography::bls12381::primitives::{
    self,
    group::{self, Element},
    poly,
};
use tracing::debug;

pub fn verify_seed<S: ThresholdSupervisor<Index = View, Identity = poly::Public>>(
    supervisor: &S,
    namespace: &[u8],
    seed: &wire::Seed,
) -> bool {
    // Get public key
    let Some((polynomial, _)) = supervisor.identity(seed.view) else {
        debug!(
            view = seed.view,
            reason = "unable to get identity for view",
            "dropping seed"
        );
        return false;
    };
    let public_key = poly::public(polynomial);

    // Parse signature
    let Some(signature) = group::Signature::deserialize(&seed.signature) else {
        debug!(reason = "invalid signature", "dropping seed");
        return false;
    };

    // Verify threshold seed
    let message = seed_message(seed.view);
    if primitives::ops::verify_message(&public_key, Some(namespace), &message, &signature).is_err()
    {
        debug!(reason = "invalid signature", "dropping seed");
        return false;
    }
    debug!(view = seed.view, "seed verified");
    true
}

pub fn verify_notarization<S: ThresholdSupervisor<Index = View, Identity = poly::Public>>(
    supervisor: &S,
    namespace: &[u8],
    notarization: &wire::Notarization,
) -> bool {
    // Extract proposal
    let proposal = match &notarization.proposal {
        Some(proposal) => proposal,
        None => {
            debug!(reason = "missing proposal", "dropping notarization");
            return false;
        }
    };

    // Get public key
    let Some((polynomial, _)) = supervisor.identity(proposal.view) else {
        debug!(
            view = proposal.view,
            reason = "unable to get identity for view",
            "dropping notarization"
        );
        return false;
    };
    let public_key = poly::public(polynomial);

    // Parse signature
    let Some(signature) = group::Signature::deserialize(&notarization.signature) else {
        debug!(reason = "invalid signature", "dropping notarization");
        return false;
    };

    // Verify threshold notarization
    let message = proposal_message(proposal.view, proposal.parent, &proposal.payload);
    if primitives::ops::verify_message(&public_key, Some(namespace), &message, &signature).is_err()
    {
        debug!(reason = "invalid signature", "dropping notarization");
        return false;
    }
    debug!(view = proposal.view, "notarization verified");
    true
}

pub fn verify_nullification<S: ThresholdSupervisor<Index = View, Identity = poly::Public>>(
    supervisor: &S,
    namespace: &[u8],
    nullification: &wire::Nullification,
) -> bool {
    // Get public key
    let Some((polynomial, _)) = supervisor.identity(nullification.view) else {
        debug!(
            view = nullification.view,
            reason = "unable to get identity for view",
            "dropping nullification"
        );
        return false;
    };
    let public_key = poly::public(polynomial);

    // Parse signature
    let Some(signature) = group::Signature::deserialize(&nullification.signature) else {
        debug!(reason = "invalid signature", "dropping nullification");
        return false;
    };

    // Verify threshold nullification
    let message = nullify_message(nullification.view);
    if primitives::ops::verify_message(&public_key, Some(namespace), &message, &signature).is_err()
    {
        debug!(reason = "invalid signature", "dropping nullification");
        return false;
    }
    debug!(view = nullification.view, "nullification verified");
    true
}

pub fn verify_finalization<S: ThresholdSupervisor<Index = View, Identity = poly::Public>>(
    supervisor: &S,
    namespace: &[u8],
    finalization: &wire::Finalization,
) -> bool {
    // Extract proposal
    let proposal = match &finalization.proposal {
        Some(proposal) => proposal,
        None => {
            debug!(reason = "missing proposal", "dropping notarization");
            return false;
        }
    };

    // Get public key
    let Some((polynomial, _)) = supervisor.identity(proposal.view) else {
        debug!(
            view = proposal.view,
            reason = "unable to get identity for view",
            "dropping finalization"
        );
        return false;
    };
    let public_key = poly::public(polynomial);

    // Parse signature
    let Some(signature) = group::Signature::deserialize(&finalization.signature) else {
        debug!(reason = "invalid signature", "dropping nullification");
        return false;
    };

    // Verify threshold finalization
    let message = proposal_message(proposal.view, proposal.parent, &proposal.payload);
    if primitives::ops::verify_message(&public_key, Some(namespace), &message, &signature).is_err()
    {
        debug!(reason = "invalid signature", "dropping finalization");
        return false;
    }
    debug!(view = proposal.view, "finalization verified");
    true
}
