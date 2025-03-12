use super::{
    encoder::{nullify_message, proposal_message, seed_message},
    wire, View,
};
use crate::ThresholdSupervisor;
use commonware_codec::Codec;
use commonware_cryptography::bls12381::primitives::{
    self,
    group::{self},
    poly,
};
use commonware_utils::Array;
use tracing::debug;

pub fn verify_notarization<
    D: Array,
    S: ThresholdSupervisor<Index = View, Identity = poly::Public>,
>(
    supervisor: &S,
    notarization_namespace: &[u8],
    seed_namespace: &[u8],
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

    // Ensure payload is well-formed
    let Ok(payload) = D::try_from(&proposal.payload) else {
        debug!(reason = "invalid payload", "dropping notarization");
        return false;
    };

    // Get public key
    let Some(polynomial) = supervisor.identity(proposal.view) else {
        debug!(
            view = proposal.view,
            reason = "unable to get identity for view",
            "dropping notarization"
        );
        return false;
    };
    let public_key = poly::public(polynomial);

    // Parse signature
    let signature = match group::Signature::decode(notarization.proposal_signature) {
        Ok(signature) => signature,
        Err(err) => {
            debug!(reason = "invalid signature", ?err, "dropping notarization");
            return false;
        }
    };

    // Verify threshold notarization
    let message = proposal_message(proposal.view, proposal.parent, &payload);
    if primitives::ops::verify_message(
        &public_key,
        Some(notarization_namespace),
        &message,
        &signature,
    )
    .is_err()
    {
        debug!(reason = "invalid signature", "dropping notarization");
        return false;
    }
    debug!(view = proposal.view, "notarization verified");

    // Verify seed
    let seed = seed_message(proposal.view);
    let signature = match group::Signature::decode(notarization.seed_signature) {
        Ok(signature) => signature,
        Err(err) => {
            debug!(
                reason = "invalid seed signature",
                ?err,
                "dropping notarization"
            );
            return false;
        }
    };
    if primitives::ops::verify_message(&public_key, Some(seed_namespace), &seed, &signature)
        .is_err()
    {
        debug!(reason = "invalid seed signature", "dropping notarization");
        return false;
    }
    debug!(view = proposal.view, "seed verified");
    true
}

pub fn verify_nullification<S: ThresholdSupervisor<Index = View, Identity = poly::Public>>(
    supervisor: &S,
    nullification_namespace: &[u8],
    seed_namespace: &[u8],
    nullification: &wire::Nullification,
) -> bool {
    // Get public key
    let Some(polynomial) = supervisor.identity(nullification.view) else {
        debug!(
            view = nullification.view,
            reason = "unable to get identity for view",
            "dropping nullification"
        );
        return false;
    };
    let public_key = poly::public(polynomial);

    // Parse signature
    let Ok(signature) = group::Signature::decode(nullification.view_signature) else {
        debug!(reason = "invalid signature", "dropping nullification");
        return false;
    };

    // Verify threshold nullification
    let message = nullify_message(nullification.view);
    if primitives::ops::verify_message(
        &public_key,
        Some(nullification_namespace),
        &message,
        &signature,
    )
    .is_err()
    {
        debug!(reason = "invalid signature", "dropping nullification");
        return false;
    }
    debug!(view = nullification.view, "nullification verified");

    // Verify seed
    let seed = seed_message(nullification.view);
    let Ok(signature) = group::Signature::decode(nullification.seed_signature) else {
        debug!(reason = "invalid seed signature", "dropping nullification");
        return false;
    };
    if primitives::ops::verify_message(&public_key, Some(seed_namespace), &seed, &signature)
        .is_err()
    {
        debug!(reason = "invalid seed signature", "dropping nullification");
        return false;
    }
    debug!(view = nullification.view, "seed verified");
    true
}

pub fn verify_finalization<
    D: Array,
    S: ThresholdSupervisor<Index = View, Identity = poly::Public>,
>(
    supervisor: &S,
    finalization_namespace: &[u8],
    seed_namespace: &[u8],
    finalization: &wire::Finalization,
) -> bool {
    // Extract proposal
    let proposal = match &finalization.proposal {
        Some(proposal) => proposal,
        None => {
            debug!(reason = "missing proposal", "dropping finalization");
            return false;
        }
    };

    // Ensure payload is well-formed
    let Ok(payload) = D::try_from(&proposal.payload) else {
        debug!(reason = "invalid payload", "dropping finalization");
        return false;
    };

    // Get public key
    let Some(polynomial) = supervisor.identity(proposal.view) else {
        debug!(
            view = proposal.view,
            reason = "unable to get identity for view",
            "dropping finalization"
        );
        return false;
    };
    let public_key = poly::public(polynomial);

    // Parse signature
    let Ok(signature) = group::Signature::decode(finalization.proposal_signature) else {
        debug!(reason = "invalid signature", "dropping finalization");
        return false;
    };

    // Verify threshold finalization
    let message = proposal_message(proposal.view, proposal.parent, &payload);
    if primitives::ops::verify_message(
        &public_key,
        Some(finalization_namespace),
        &message,
        &signature,
    )
    .is_err()
    {
        debug!(reason = "invalid signature", "dropping finalization");
        return false;
    }
    debug!(view = proposal.view, "finalization verified");

    // Verify seed
    let seed = seed_message(proposal.view);
    let Ok(signature) = group::Signature::decode(&finalization.seed_signature) else {
        debug!(reason = "invalid seed signature", "dropping finalization");
        return false;
    };
    if primitives::ops::verify_message(&public_key, Some(seed_namespace), &seed, &signature)
        .is_err()
    {
        debug!(reason = "invalid seed signature", "dropping finalization");
        return false;
    }
    debug!(view = proposal.view, "seed verified");
    true
}
