//! Native payer-signature verification for bounded payment submissions.

use super::rpc::AcceptSendsRequest;
use anyhow::{Context, Result, anyhow, bail};
use commonware_clearing::bajillion::payment::VECTOR_SEND_SIGNATURE_NAMESPACE;
use commonware_codec::Encode as _;
use commonware_cryptography_curve25519::signing::BatchVerifier;
use commonware_parallel::{Rayon, Strategy as _};
use rand_core::CryptoRng;

/// Maximum independently owned payer submissions in one aggregate verification.
pub(crate) const MAX_VERIFICATION_BATCHES: usize = 8;

/// Exact request inputs whose payer signatures have been verified.
pub(crate) struct VerifiedSends {
    request: AcceptSendsRequest,
}

impl VerifiedSends {
    /// Returns the exact verified request without granting mutation access.
    pub(crate) const fn request(&self) -> &AcceptSendsRequest {
        &self.request
    }

    /// Consumes the marker and returns the exact verified request.
    pub(crate) fn into_request(self) -> AcceptSendsRequest {
        self.request
    }
}

fn add_request(verifier: &mut BatchVerifier, request: &AcceptSendsRequest) {
    for send in &request.sends {
        let body = send.authorization.body();
        verifier.add(
            VECTOR_SEND_SIGNATURE_NAMESPACE,
            &body.encode(),
            body.payer().as_zip215(),
            send.authorization.payer_signature(),
        );
    }
}

fn verify_request(request: AcceptSendsRequest) -> Result<VerifiedSends> {
    for (position, send) in request.sends.iter().enumerate() {
        let body = send.authorization.body();
        if !body.payer().verify(
            VECTOR_SEND_SIGNATURE_NAMESPACE,
            &body.encode(),
            send.authorization.payer_signature(),
        ) {
            bail!("payment send at position {position} has an invalid payer signature");
        }
    }
    Ok(VerifiedSends { request })
}

/// Verifies payer signatures across a group, isolating any failed payer submission.
///
/// A successful aggregate verifies all structurally bounded requests without repeating
/// individual signature checks. If it fails, each bounded payer submission is checked once so
/// one invalid member rejects its whole submission without rejecting unrelated payers.
pub(crate) fn verify_sends(
    requests: Vec<AcceptSendsRequest>,
    rng: &mut impl CryptoRng,
    strategy: &Rayon,
) -> Vec<Result<VerifiedSends>> {
    if requests.len() > MAX_VERIFICATION_BATCHES {
        return requests
            .into_iter()
            .map(|_| {
                Err(anyhow!(
                    "payment verification group exceeds the batch bound"
                ))
            })
            .collect();
    }
    let requests = requests
        .into_iter()
        .map(|request| {
            request
                .validate()
                .context("validate payment submission")
                .map(|()| request)
        })
        .collect::<Vec<_>>();
    let signatures = requests.iter().try_fold(0_usize, |total, request| {
        total.checked_add(request.as_ref().map_or(0, |request| request.sends.len()))
    });
    let Some(signatures) = signatures else {
        return requests
            .into_iter()
            .map(|_| Err(anyhow!("payment signature count overflow")))
            .collect();
    };
    if signatures == 0 {
        return requests
            .into_iter()
            .map(|request| request.map(|request| VerifiedSends { request }))
            .collect();
    }

    let mut verifier = BatchVerifier::new(signatures);
    for request in requests.iter().filter_map(|request| request.as_ref().ok()) {
        add_request(&mut verifier, request);
    }
    if verifier.verify(rng, strategy) {
        return requests
            .into_iter()
            .map(|request| request.map(|request| VerifiedSends { request }))
            .collect();
    }

    strategy.map_collect_vec(requests, |request| {
        request.and_then(|request| verify_request(request).context("verify payer authorization"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        operator::rpc::AcceptSendRequest,
        protocol::{Entry, Key, Wallet},
    };
    use bytes::Bytes;
    use commonware_clearing::bajillion::{
        commitment::VectorRoot,
        payment::{PaymentContext, SendAuthorization, VectorSendBody},
    };
    use commonware_codec::DecodeExt as _;
    use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest};
    use commonware_utils::test_rng;
    use std::num::NonZeroUsize;

    fn request(
        payer: &Wallet,
        recipient: &Key,
        context: &PaymentContext<Key, Digest>,
        first_sequence: u64,
        count: usize,
    ) -> AcceptSendsRequest {
        let sends = (0..count)
            .map(|offset| {
                let sequence = first_sequence + u64::try_from(offset).unwrap();
                let body = VectorSendBody::new(
                    context,
                    payer.public_key(),
                    sequence,
                    sequence,
                    VectorRoot {
                        digest: Sha256::hash(&[&sequence.to_be_bytes()]),
                    },
                );
                AcceptSendRequest {
                    authorization: SendAuthorization::sign(body, payer.signer()),
                    entries: vec![Entry {
                        recipient: recipient.clone(),
                        amount: 1,
                    }],
                }
            })
            .collect();
        AcceptSendsRequest { sends }
    }

    fn corrupt_signature(request: &mut AcceptSendsRequest, position: usize) {
        let mut encoded = request.sends[position].authorization.encode().to_vec();
        *encoded.last_mut().unwrap() ^= 1;
        request.sends[position].authorization =
            SendAuthorization::decode(Bytes::from(encoded)).unwrap();
    }

    #[test]
    fn aggregate_verification_preserves_exact_requests() {
        let payer_a = Wallet::from_seed("payer-a", 1);
        let payer_b = Wallet::from_seed("payer-b", 2);
        let recipient = Wallet::from_seed("recipient", 3).public_key();
        let context = PaymentContext::new(
            Sha256::hash(&[b"verification-anchor"]),
            7,
            Wallet::from_seed("operator", 4).public_key(),
        );
        let requests = vec![
            request(&payer_a, &recipient, &context, 1, 2),
            request(&payer_b, &recipient, &context, 8, 3),
        ];
        let expected = requests.clone();
        let strategy = Rayon::new(NonZeroUsize::new(2).unwrap()).unwrap();

        let verified = verify_sends(requests, &mut test_rng(), &strategy);

        assert_eq!(verified.len(), expected.len());
        for (verified, expected) in verified.into_iter().zip(expected) {
            let verified = verified.unwrap();
            assert_eq!(verified.request(), &expected);
            assert_eq!(verified.into_request(), expected);
        }
    }

    #[test]
    fn failed_aggregate_rejects_whole_bad_submission_only() {
        let payer_a = Wallet::from_seed("payer-a", 11);
        let payer_b = Wallet::from_seed("payer-b", 12);
        let payer_c = Wallet::from_seed("payer-c", 13);
        let recipient = Wallet::from_seed("recipient", 14).public_key();
        let context = PaymentContext::new(
            Sha256::hash(&[b"isolation-anchor"]),
            9,
            Wallet::from_seed("operator", 15).public_key(),
        );
        let good_a = request(&payer_a, &recipient, &context, 1, 2);
        let mut bad = request(&payer_b, &recipient, &context, 1, 3);
        corrupt_signature(&mut bad, 1);
        let good_c = request(&payer_c, &recipient, &context, 1, 2);
        let expected_a = good_a.clone();
        let expected_c = good_c.clone();
        let strategy = Rayon::new(NonZeroUsize::new(2).unwrap()).unwrap();

        let mut verified = verify_sends(vec![good_a, bad, good_c], &mut test_rng(), &strategy);

        assert_eq!(verified.remove(0).unwrap().into_request(), expected_a);
        let Err(error) = verified.remove(0) else {
            panic!("invalid payer batch was marked verified");
        };
        assert!(format!("{error:#}").contains("verify payer authorization"));
        assert_eq!(verified.remove(0).unwrap().into_request(), expected_c);
    }

    #[test]
    fn signatures_bind_the_namespace_and_exact_context_body() {
        let payer = Wallet::from_seed("payer", 31);
        let recipient = Wallet::from_seed("recipient", 32).public_key();
        let operator = Wallet::from_seed("operator", 33).public_key();
        let context = PaymentContext::new(Sha256::hash(&[b"bound-anchor"]), 13, operator.clone());
        let mut wrong_namespace = request(&payer, &recipient, &context, 1, 1);
        let body = wrong_namespace.sends[0].authorization.body().clone();
        let signature = payer
            .signer()
            .sign(b"_COMMONWARE_TERMINAL_WRONG", &body.encode());
        wrong_namespace.sends[0].authorization =
            SendAuthorization::from_raw_unchecked(body, signature);

        let mut wrong_body = request(&payer, &recipient, &context, 1, 1);
        let original = &wrong_body.sends[0].authorization;
        let original_body = original.body();
        let signature = original.payer_signature().clone();
        let other_context = PaymentContext::new(Sha256::hash(&[b"other-anchor"]), 13, operator);
        let altered_body = VectorSendBody::new(
            &other_context,
            original_body.payer().clone(),
            original_body.seq(),
            original_body.cumulative_debit(),
            original_body.send_root(),
        );
        wrong_body.sends[0].authorization =
            SendAuthorization::from_raw_unchecked(altered_body, signature);
        let strategy = Rayon::new(NonZeroUsize::new(2).unwrap()).unwrap();

        let verified = verify_sends(
            vec![wrong_namespace, wrong_body],
            &mut test_rng(),
            &strategy,
        );

        assert!(verified.into_iter().all(|result| result.is_err()));
    }

    #[test]
    fn shape_is_checked_before_signature_verification() {
        let payer = Wallet::from_seed("payer", 21);
        let recipient = Wallet::from_seed("recipient", 22).public_key();
        let context = PaymentContext::new(
            Sha256::hash(&[b"shape-anchor"]),
            11,
            Wallet::from_seed("operator", 23).public_key(),
        );
        let mut invalid = request(&payer, &recipient, &context, 1, 2);
        let replacement = request(&payer, &recipient, &context, 4, 1);
        invalid.sends[1] = replacement.sends.into_iter().next().unwrap();
        let strategy = Rayon::new(NonZeroUsize::new(2).unwrap()).unwrap();

        let verified = verify_sends(vec![invalid], &mut test_rng(), &strategy);

        assert_eq!(verified.len(), 1);
        assert!(verified.into_iter().next().unwrap().is_err());
    }

    #[test]
    fn verification_group_is_bounded_before_crypto_work() {
        let payer = Wallet::from_seed("payer", 41);
        let recipient = Wallet::from_seed("recipient", 42).public_key();
        let context = PaymentContext::new(
            Sha256::hash(&[b"group-bound-anchor"]),
            15,
            Wallet::from_seed("operator", 43).public_key(),
        );
        let request = request(&payer, &recipient, &context, 1, 1);
        let requests = vec![request; MAX_VERIFICATION_BATCHES + 1];
        let strategy = Rayon::new(NonZeroUsize::new(2).unwrap()).unwrap();

        let verified = verify_sends(requests, &mut test_rng(), &strategy);

        assert_eq!(verified.len(), MAX_VERIFICATION_BATCHES + 1);
        assert!(verified.into_iter().all(|result| result.is_err()));
    }
}
