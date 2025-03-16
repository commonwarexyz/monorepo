use super::{
    encoder::{nullify_message, proposal_message, seed_message},
    wire, View,
};
use crate::ThresholdSupervisor;
use commonware_cryptography::bls12381::primitives::{
    group::{self, Element},
    ops::{aggregate_signatures, aggregate_verify_multiple_messages},
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

    // Parse signatures
    let Some(notarization_signature) =
        group::Signature::deserialize(&notarization.proposal_signature)
    else {
        debug!(reason = "invalid signature", "dropping notarization");
        return false;
    };
    let Some(seed_signature) = group::Signature::deserialize(&notarization.seed_signature) else {
        debug!(reason = "invalid seed signature", "dropping notarization");
        return false;
    };

    // Verify aggregate signature
    let signature = aggregate_signatures(&[notarization_signature, seed_signature]);
    let notarization_message = proposal_message(proposal.view, proposal.parent, &payload);
    let notarization_message = (Some(notarization_namespace), notarization_message.as_ref());
    let seed_message = seed_message(proposal.view);
    let seed_message = (Some(seed_namespace), seed_message.as_ref());
    let messages = [notarization_message, seed_message];
    if aggregate_verify_multiple_messages(public_key, &messages, &signature, 1).is_err() {
        debug!(reason = "invalid signature", "dropping notarization");
        return false;
    }
    debug!(view = proposal.view, "notarization verified");
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
    let Some(nullification_signature) =
        group::Signature::deserialize(&nullification.view_signature)
    else {
        debug!(reason = "invalid signature", "dropping nullification");
        return false;
    };
    let Some(seed_signature) = group::Signature::deserialize(&nullification.seed_signature) else {
        debug!(reason = "invalid seed signature", "dropping nullification");
        return false;
    };

    // Verify aggregate signature
    let signature = aggregate_signatures(&[nullification_signature, seed_signature]);
    let nullification_message = nullify_message(nullification.view);
    let nullification_message = (
        Some(nullification_namespace),
        nullification_message.as_ref(),
    );
    let seed_message = seed_message(nullification.view);
    let seed_message = (Some(seed_namespace), seed_message.as_ref());
    let messages = [nullification_message, seed_message];
    if aggregate_verify_multiple_messages(public_key, &messages, &signature, 1).is_err() {
        debug!(reason = "invalid signature", "dropping nullification");
        return false;
    }
    debug!(view = nullification.view, "nullification verified");
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

    // Parse signatures
    let Some(finalization_signature) =
        group::Signature::deserialize(&finalization.proposal_signature)
    else {
        debug!(reason = "invalid signature", "dropping finalization");
        return false;
    };
    let Some(seed_signature) = group::Signature::deserialize(&finalization.seed_signature) else {
        debug!(reason = "invalid seed signature", "dropping finalization");
        return false;
    };

    // Verify aggregate signature
    let signature = aggregate_signatures(&[finalization_signature, seed_signature]);
    let finalization_message = proposal_message(proposal.view, proposal.parent, &payload);
    let finalization_message = (Some(finalization_namespace), finalization_message.as_ref());
    let seed_message = seed_message(proposal.view);
    let seed_message = (Some(seed_namespace), seed_message.as_ref());
    let messages = [finalization_message, seed_message];
    if aggregate_verify_multiple_messages(public_key, &messages, &signature, 1).is_err() {
        debug!(reason = "invalid signature", "dropping finalization");
        return false;
    }
    debug!(view = proposal.view, "finalization verified");
    true
}
