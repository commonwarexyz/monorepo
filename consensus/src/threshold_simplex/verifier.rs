use super::{
    types::{view_message, Finalization, Notarization, Nullification},
    View,
};
use crate::ThresholdSupervisor;
use commonware_codec::Codec;
use commonware_cryptography::{
    bls12381::primitives::{
        ops::{aggregate_signatures, aggregate_verify_multiple_messages},
        poly,
    },
    Digest,
};
use tracing::debug;

pub fn verify_notarization<
    D: Digest,
    S: ThresholdSupervisor<Index = View, Identity = poly::Public>,
>(
    supervisor: &S,
    notarization_namespace: &[u8],
    seed_namespace: &[u8],
    notarization: &Notarization<D>,
) -> bool {
    // Get public key
    let proposal = &notarization.proposal;
    let Some(polynomial) = supervisor.identity(proposal.view) else {
        debug!(
            view = proposal.view,
            reason = "unable to get identity for view",
            "dropping notarization"
        );
        return false;
    };
    let public_key = poly::public(polynomial);

    // Verify aggregate signature
    let signature =
        aggregate_signatures(&[notarization.proposal_signature, notarization.seed_signature]);
    let notarization_message = proposal.encode();
    let notarization_message = (Some(notarization_namespace), notarization_message.as_ref());
    let seed_message = view_message(proposal.view);
    let seed_message = (Some(seed_namespace), seed_message.as_ref());
    if aggregate_verify_multiple_messages(
        public_key,
        &[notarization_message, seed_message],
        &signature,
        1,
    )
    .is_err()
    {
        debug!(
            reason = "signature verification failed",
            "dropping notarization"
        );
        return false;
    }
    debug!(view = proposal.view, "notarization verified");
    true
}

pub fn verify_nullification<S: ThresholdSupervisor<Index = View, Identity = poly::Public>>(
    supervisor: &S,
    nullification_namespace: &[u8],
    seed_namespace: &[u8],
    nullification: &Nullification,
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

    // Verify aggregate signature
    let signature =
        aggregate_signatures(&[nullification.view_signature, nullification.seed_signature]);
    let nullification_message = view_message(nullification.view);
    let nullification_message = (
        Some(nullification_namespace),
        nullification_message.as_ref(),
    );
    let seed_message = view_message(nullification.view);
    let seed_message = (Some(seed_namespace), seed_message.as_ref());
    if aggregate_verify_multiple_messages(
        public_key,
        &[nullification_message, seed_message],
        &signature,
        1,
    )
    .is_err()
    {
        debug!(
            reason = "signature verification failed",
            "dropping nullification"
        );
        return false;
    }
    debug!(view = nullification.view, "nullification verified");
    true
}

pub fn verify_finalization<
    D: Digest,
    S: ThresholdSupervisor<Index = View, Identity = poly::Public>,
>(
    supervisor: &S,
    finalization_namespace: &[u8],
    seed_namespace: &[u8],
    finalization: &Finalization<D>,
) -> bool {
    // Get public key
    let proposal = &finalization.proposal;
    let Some(polynomial) = supervisor.identity(proposal.view) else {
        debug!(
            view = proposal.view,
            reason = "unable to get identity for view",
            "dropping finalization"
        );
        return false;
    };
    let public_key = poly::public(polynomial);

    // Verify aggregate signature
    let signature =
        aggregate_signatures(&[finalization.proposal_signature, finalization.seed_signature]);
    let finalization_message = proposal.encode();
    let finalization_message = (Some(finalization_namespace), finalization_message.as_ref());
    let seed_message = view_message(proposal.view);
    let seed_message = (Some(seed_namespace), seed_message.as_ref());
    if aggregate_verify_multiple_messages(
        public_key,
        &[finalization_message, seed_message],
        &signature,
        1,
    )
    .is_err()
    {
        debug!(
            reason = "signature verification failed",
            "dropping finalization"
        );
        return false;
    }
    debug!(view = proposal.view, "finalization verified");
    true
}
