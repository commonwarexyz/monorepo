//! Distributed Key Generation (DKG), Resharing, Signatures, and Threshold Signatures over the BLS12-381 curve.
//!
//! # Features
//!
//! This crate has the following features:
//!
//! - `portable`: Enables `portable` feature on `blst` (<https://github.com/supranational/blst?tab=readme-ov-file#platform-and-language-compatibility>).

pub mod dkg;
pub mod primitives;
mod scheme;
pub use scheme::Bls12381;

#[cfg(test)]
mod tests {
    use super::*;
    use dkg::ops::generate_shares;
    use primitives::group::Private;
    use primitives::ops::{
        partial_sign_message, partial_verify_message, threshold_signature_recover, verify_message,
    };
    use primitives::poly::public;
    use primitives::Error;

    #[test]
    fn test_partial_aggregate_signature() {
        let (n, t) = (5, 4);

        // Create the private key polynomial and evaluate it at `n`
        // points to generate the shares.
        //
        // If receiving a share from an untrusted party, the recipient
        // should verify the share is on the public polynomial.
        let (group, shares) = generate_shares(None, n, t);

        // Generate the partial signatures
        let namespace = Some(&b"test"[..]);
        let msg = b"hello";
        let partials = shares
            .iter()
            .map(|s| partial_sign_message(s, namespace, msg))
            .collect::<Vec<_>>();

        // Each partial sig can be partially verified against the public polynomial
        partials.iter().for_each(|partial| {
            partial_verify_message(&group, namespace, msg, partial).unwrap();
        });

        // Generate and verify the threshold sig
        let threshold_sig = threshold_signature_recover(t, partials).unwrap();
        let threshold_pub = public(&group);
        verify_message(&threshold_pub, namespace, msg, &threshold_sig).unwrap();
    }

    #[test]
    fn test_partial_aggregate_signature_bad_namespace() {
        let (n, t) = (5, 4);

        // Create the private key polynomial and evaluate it at `n`
        // points to generate the shares.
        //
        // If receiving a share from an untrusted party, the recipient
        // should verify the share is on the public polynomial.
        let (group, shares) = generate_shares(None, n, t);

        // Generate the partial signatures
        let namespace = Some(&b"test"[..]);
        let msg = b"hello";
        let partials = shares
            .iter()
            .map(|s| partial_sign_message(s, namespace, msg))
            .collect::<Vec<_>>();

        // Each partial sig can be partially verified against the public polynomial
        let namespace = Some(&b"bad"[..]);
        partials.iter().for_each(|partial| {
            assert!(matches!(
                partial_verify_message(&group, namespace, msg, partial).unwrap_err(),
                Error::InvalidSignature
            ));
        });

        // Generate and verify the threshold sig
        let threshold_sig = threshold_signature_recover(t, partials).unwrap();
        let threshold_pub = public(&group);
        assert!(matches!(
            verify_message(&threshold_pub, namespace, msg, &threshold_sig).unwrap_err(),
            Error::InvalidSignature
        ));
    }

    #[test]
    fn test_partial_aggregate_signature_insufficient() {
        let (n, t) = (5, 4);

        // Create the private key polynomial and evaluate it at `n`
        // points to generate the shares
        let (group, shares) = generate_shares(None, n, t);

        // Only take t-1 shares
        let shares = shares.into_iter().take(t as usize - 1).collect::<Vec<_>>();

        // Generate the partial signatures
        let namespace = Some(&b"test"[..]);
        let msg = b"hello";
        let partials = shares
            .iter()
            .map(|s| partial_sign_message(s, namespace, msg))
            .collect::<Vec<_>>();

        // Each partial sig can be partially verified against the public polynomial
        partials.iter().for_each(|partial| {
            partial_verify_message(&group, namespace, msg, partial).unwrap();
        });

        // Generate the threshold sig
        assert!(matches!(
            threshold_signature_recover(t, partials).unwrap_err(),
            Error::NotEnoughPartialSignatures(4, 3)
        ));
    }

    #[test]
    fn test_partial_aggregate_signature_insufficient_duplicates() {
        let (n, t) = (5, 4);

        // Create the private key polynomial and evaluate it at `n`
        // points to generate the shares
        let (group, shares) = generate_shares(None, n, t);

        // Only take t-1 shares
        let mut shares = shares.into_iter().take(t as usize - 1).collect::<Vec<_>>();
        shares.push(shares[0]);

        // Generate the partial signatures
        let namespace = Some(&b"test"[..]);
        let msg = b"hello";
        let partials = shares
            .iter()
            .map(|s| partial_sign_message(s, namespace, msg))
            .collect::<Vec<_>>();

        // Each partial sig can be partially verified against the public polynomial
        partials.iter().for_each(|partial| {
            partial_verify_message(&group, namespace, msg, partial).unwrap();
        });

        // Generate the threshold sig
        assert!(matches!(
            threshold_signature_recover(t, partials).unwrap_err(),
            Error::DuplicateEval,
        ));
    }

    #[test]
    #[should_panic(expected = "InvalidSignature")]
    fn test_partial_aggregate_signature_bad_share() {
        let (n, t) = (5, 4);

        // Create the private key polynomial and evaluate it at `n`
        // points to generate the shares
        let (group, mut shares) = generate_shares(None, n, t);

        // Corrupt a share
        let share = shares.get_mut(3).unwrap();
        share.private = Private::rand(&mut rand::thread_rng());

        // Generate the partial signatures
        let namespace = Some(&b"test"[..]);
        let msg = b"hello";
        let partials = shares
            .iter()
            .map(|s| partial_sign_message(s, namespace, msg))
            .collect::<Vec<_>>();

        // Each partial sig can be partially verified against the public polynomial
        partials.iter().for_each(|partial| {
            partial_verify_message(&group, namespace, msg, partial).unwrap();
        });

        // Generate and verify the threshold sig
        let threshold_sig = threshold_signature_recover(t, partials).unwrap();
        let threshold_pub = public(&group);
        verify_message(&threshold_pub, namespace, msg, &threshold_sig).unwrap();
    }
}
