use std::collections::HashSet;

use commonware_codec::ReadExt;
use commonware_cryptography::Scheme;
use commonware_utils::{quorum, Array};
use tracing::debug;

use super::{wire, View};
use crate::{
    simplex::encoder::{nullify_message, proposal_message},
    Supervisor,
};

pub fn threshold<P: Array>(validators: &[P]) -> Option<(u32, u32)> {
    let len = validators.len() as u32;
    let threshold = quorum(len);
    Some((threshold, len))
}

pub fn verify_notarization<
    S: Supervisor<Index = View, PublicKey = C::PublicKey>,
    C: Scheme,
    D: Array,
>(
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

    // Ensure payload is well-formed
    let Ok(payload) = D::read(&mut proposal.payload.as_ref()) else {
        debug!(reason = "invalid payload", "dropping notarization");
        return false;
    };

    // Ensure finalization has valid number of signatures
    let validators = match supervisor.participants(proposal.view) {
        Some(validators) => validators,
        None => {
            debug!(
                view = proposal.view,
                reason = "unable to compute participants for view",
                "dropping notarization"
            );
            return false;
        }
    };
    let (threshold, count) = match threshold(validators) {
        Some(participation) => participation,
        None => {
            debug!(
                view = proposal.view,
                reason = "unable to compute participants for view",
                "dropping notarization"
            );
            return false;
        }
    };
    if notarization.signatures.len() < threshold as usize {
        debug!(
            threshold,
            signatures = notarization.signatures.len(),
            reason = "insufficient signatures",
            "dropping notarization"
        );
        return false;
    }
    if notarization.signatures.len() > count as usize {
        debug!(
            threshold,
            signatures = notarization.signatures.len(),
            reason = "too many signatures",
            "dropping notarization"
        );
        return false;
    }

    // Verify threshold notarization
    let message = proposal_message(proposal.view, proposal.parent, &payload);
    let mut seen = HashSet::new();
    for signature in notarization.signatures.iter() {
        // Get public key
        let public_key = match validators.get(signature.public_key as usize) {
            Some(public_key) => public_key,
            None => {
                debug!(
                    view = proposal.view,
                    signer = signature.public_key,
                    reason = "invalid validator",
                    "dropping notarization"
                );
                return false;
            }
        };

        // Ensure we haven't seen this signature before
        if seen.contains(&signature.public_key) {
            debug!(
                signer = ?public_key,
                reason = "duplicate signature",
                "dropping notarization"
            );
            return false;
        }
        seen.insert(signature.public_key);

        // Verify signature
        let Ok(signature) = C::Signature::read(&mut signature.signature.as_ref()) else {
            return false;
        };
        if !C::verify(Some(namespace), &message, public_key, &signature) {
            debug!(reason = "invalid signature", "dropping notarization");
            return false;
        }
    }
    debug!(view = proposal.view, "notarization verified");
    true
}

pub fn verify_nullification<S: Supervisor<Index = View, PublicKey = C::PublicKey>, C: Scheme>(
    supervisor: &S,
    namespace: &[u8],
    nullification: &wire::Nullification,
) -> bool {
    // Ensure finalization has valid number of signatures
    let validators = match supervisor.participants(nullification.view) {
        Some(validators) => validators,
        None => {
            debug!(
                view = nullification.view,
                reason = "unable to compute participants for view",
                "dropping nullification"
            );
            return false;
        }
    };
    let (threshold, count) = match threshold(validators) {
        Some(participation) => participation,
        None => {
            debug!(
                view = nullification.view,
                reason = "unable to compute participants for view",
                "dropping nullification"
            );
            return false;
        }
    };
    if nullification.signatures.len() < threshold as usize {
        debug!(
            threshold,
            signatures = nullification.signatures.len(),
            reason = "insufficient signatures",
            "dropping nullification"
        );
        return false;
    }
    if nullification.signatures.len() > count as usize {
        debug!(
            threshold,
            signatures = nullification.signatures.len(),
            reason = "too many signatures",
            "dropping nullification"
        );
        return false;
    }

    // Verify threshold nullification
    let message = nullify_message(nullification.view);
    let mut seen = HashSet::new();
    for signature in nullification.signatures.iter() {
        // Get public key
        let public_key = match validators.get(signature.public_key as usize) {
            Some(public_key) => public_key,
            None => {
                debug!(
                    view = nullification.view,
                    signer = signature.public_key,
                    reason = "invalid validator",
                    "dropping nullification"
                );
                return false;
            }
        };

        // Ensure we haven't seen this signature before
        if seen.contains(&signature.public_key) {
            debug!(
                signer = ?public_key,
                reason = "duplicate signature",
                "dropping nullification"
            );
            return false;
        }
        seen.insert(signature.public_key);

        // Verify signature
        let Ok(signature) = C::Signature::read(&mut signature.signature.as_ref()) else {
            return false;
        };
        if !C::verify(Some(namespace), &message, public_key, &signature) {
            debug!(reason = "invalid signature", "dropping nullification");
            return false;
        }
    }
    debug!(view = nullification.view, "nullification verified");
    true
}

pub fn verify_finalization<
    S: Supervisor<Index = View, PublicKey = C::PublicKey>,
    C: Scheme,
    D: Array,
>(
    supervisor: &S,
    namespace: &[u8],
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
    let Ok(payload) = D::read(&mut proposal.payload.as_ref()) else {
        debug!(reason = "invalid payload", "dropping finalization");
        return false;
    };

    // Ensure finalization has valid number of signatures
    let validators = match supervisor.participants(proposal.view) {
        Some(validators) => validators,
        None => {
            debug!(
                view = proposal.view,
                reason = "unable to compute participants for view",
                "dropping finalization"
            );
            return false;
        }
    };
    let (threshold, count) = match threshold(validators) {
        Some(participation) => participation,
        None => {
            debug!(
                view = proposal.view,
                reason = "unable to compute participants for view",
                "dropping finalization"
            );
            return false;
        }
    };
    if finalization.signatures.len() < threshold as usize {
        debug!(
            threshold,
            signatures = finalization.signatures.len(),
            reason = "insufficient signatures",
            "dropping finalization"
        );
        return false;
    }
    if finalization.signatures.len() > count as usize {
        debug!(
            threshold,
            signatures = finalization.signatures.len(),
            reason = "too many signatures",
            "dropping finalization"
        );
        return false;
    }

    // Verify threshold finalization
    let message = proposal_message(proposal.view, proposal.parent, &payload);
    let mut seen = HashSet::new();
    for signature in finalization.signatures.iter() {
        // Get public key
        let public_key = match validators.get(signature.public_key as usize) {
            Some(public_key) => public_key,
            None => {
                debug!(
                    view = proposal.view,
                    signer = signature.public_key,
                    reason = "invalid validator",
                    "dropping finalization"
                );
                return false;
            }
        };

        // Ensure we haven't seen this signature before
        if seen.contains(&signature.public_key) {
            debug!(
                signer = ?public_key,
                reason = "duplicate signature",
                "dropping finalization"
            );
            return false;
        }
        seen.insert(signature.public_key);

        // Verify signature
        let Ok(signature) = C::Signature::read(&mut signature.signature.as_ref()) else {
            return false;
        };
        if !C::verify(Some(namespace), &message, public_key, &signature) {
            debug!(reason = "invalid signature", "dropping finalization");
            return false;
        }
    }
    debug!(view = proposal.view, "finalization verified");
    true
}
