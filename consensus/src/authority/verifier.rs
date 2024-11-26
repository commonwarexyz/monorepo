use super::{wire, View};
use crate::{
    authority::encoder::{nullify_message, proposal_message},
    Supervisor,
};
use commonware_cryptography::Scheme;
use commonware_utils::{hex, quorum};
use std::collections::HashSet;
use tracing::debug;

pub fn threshold<S: Supervisor<Index = View>>(supervisor: &S, view: View) -> Option<(u32, u32)> {
    let validators = match supervisor.participants(view) {
        Some(validators) => validators,
        None => return None,
    };
    let len = validators.len() as u32;
    let threshold = quorum(len).expect("not enough validators for a quorum");
    Some((threshold, len))
}

pub fn verify_notarization<C: Scheme>(
    threshold: u32,
    count: u32,
    namespace: &[u8],
    notarization: &wire::Notarization,
) -> bool {
    let proposal = match &notarization.proposal {
        Some(proposal) => proposal,
        None => {
            debug!(reason = "missing proposal", "dropping notarization");
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
    let message = proposal_message(proposal.view, proposal.parent, &proposal.payload);
    let mut seen = HashSet::new();
    for signature in notarization.signatures.iter() {
        // Verify signature
        if !C::validate(&signature.public_key) {
            debug!(
                signer = hex(&signature.public_key),
                reason = "invalid validator",
                "dropping notarization"
            );
            return false;
        }

        // Ensure we haven't seen this signature before
        if seen.contains(&signature.public_key) {
            debug!(
                signer = hex(&signature.public_key),
                reason = "duplicate signature",
                "dropping notarization"
            );
            return false;
        }
        seen.insert(signature.public_key.clone());

        // Verify signature
        if !C::verify(
            namespace,
            &message,
            &signature.public_key,
            &signature.signature,
        ) {
            debug!(reason = "invalid signature", "dropping notarization");
            return false;
        }
    }
    debug!(view = proposal.view, "notarization verified");
    true
}

pub fn verify_nullification<C: Scheme>(
    threshold: u32,
    count: u32,
    namespace: &[u8],
    nullification: &wire::Nullification,
) -> bool {
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

    // Verify threshold notarization
    let message = nullify_message(nullification.view);
    let mut seen = HashSet::new();
    for signature in nullification.signatures.iter() {
        // Verify signature
        if !C::validate(&signature.public_key) {
            debug!(
                signer = hex(&signature.public_key),
                reason = "invalid validator",
                "dropping notarization"
            );
            return false;
        }

        // Ensure we haven't seen this signature before
        if seen.contains(&signature.public_key) {
            debug!(
                signer = hex(&signature.public_key),
                reason = "duplicate signature",
                "dropping notarization"
            );
            return false;
        }
        seen.insert(signature.public_key.clone());

        // Verify signature
        if !C::verify(
            namespace,
            &message,
            &signature.public_key,
            &signature.signature,
        ) {
            debug!(reason = "invalid signature", "dropping notarization");
            return false;
        }
    }
    debug!(view = nullification.view, "nullification verified");
    true
}
