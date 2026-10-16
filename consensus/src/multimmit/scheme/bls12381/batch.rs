//! Batch verification of individually attributed items and certificates.

use super::{Contents, Scheme, claims::Claim};
use crate::multimmit::types::{
    Attestation, Lqc, SignedLeaderBlock, SignedTransactionBlock, VoteContent, Vqc,
};
use commonware_cryptography::{
    Digest, Hasher, PublicKey,
    bls12381::primitives::{ops::batch, variant::Variant},
};
use commonware_parallel::Strategy;
use rand_core::CryptoRng;

/// One signed item awaiting verification.
#[derive(Debug)]
pub enum Signed<'a, V: Variant, D: Digest> {
    /// A producer-signed transaction-block header.
    TransactionBlock(&'a SignedTransactionBlock<V, D>),
    /// A scheduled leader's signed leader block.
    LeaderBlock(&'a SignedLeaderBlock<V, D>),
    /// A vote content with its signer's attestation, such as the rebuilt content of a vote update.
    Vote {
        /// The signed content.
        content: &'a VoteContent<D>,
        /// The signer's attestation over `content`.
        attestation: &'a Attestation<V>,
    },
    /// A view quorum certificate.
    Vqc(&'a Vqc<V, D>),
    /// A leader quorum certificate.
    Lqc(&'a Lqc<V, D>),
}

impl<V: Variant, D: Digest> Clone for Signed<'_, V, D> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<V: Variant, D: Digest> Copy for Signed<'_, V, D> {}

/// The verdict on one batched item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict<D: Digest> {
    /// The item failed a structural check or its signature is invalid.
    Invalid,
    /// The individually attributed item is authentic.
    Valid,
    /// The certificate is authentic; these are the vote contents it records, in signer order.
    Certificate(Contents<D>),
}

impl<D: Digest> Verdict<D> {
    /// Returns whether the item is authentic.
    pub const fn is_valid(&self) -> bool {
        !matches!(self, Self::Invalid)
    }
}

impl<P: PublicKey, V: Variant> Scheme<P, V> {
    /// Verifies a batch of signed items and returns one verdict per item, in input order.
    ///
    /// Items are independent: an invalid item cannot fail a valid neighbor. Every item decomposes
    /// into one pairing claim, and the batch is checked as one randomly scaled pairing product
    /// costing one pairing per distinct message rather than one per signature. When the product
    /// fails, bisection isolates the invalid items. An invalid signature is attributable
    /// misbehavior, so the single product is the common case.
    pub fn verify_batch<R: CryptoRng, H: Hasher<Digest = D>, D: Digest>(
        &self,
        rng: &mut R,
        items: &[Signed<'_, V, D>],
        strategy: &impl Strategy,
    ) -> Vec<Verdict<D>> {
        // Structural checks, message encoding, and tally expansion dominate claim extraction, so
        // they run in parallel.
        let claims = strategy.map_collect_vec(items, |item| self.claim::<H, D>(item));
        let mut owners = Vec::with_capacity(claims.len());
        let mut batched = Vec::with_capacity(claims.len());
        for (index, claim) in claims.iter().enumerate() {
            if let Some((claim, _)) = claim {
                owners.push(index);
                batched.push(claim.as_batch());
            }
        }
        let invalid = batch::verify_claims(rng, &batched, strategy);
        let mut verdicts: Vec<_> = claims
            .into_iter()
            .map(|claim| match claim {
                None => Verdict::Invalid,
                Some((_, None)) => Verdict::Valid,
                Some((_, Some(contents))) => Verdict::Certificate(contents),
            })
            .collect();
        for offset in invalid {
            verdicts[owners[offset]] = Verdict::Invalid;
        }
        verdicts
    }

    /// Decomposes one item into its pairing claim and, for a certificate, its vote contents.
    fn claim<H: Hasher<Digest = D>, D: Digest>(
        &self,
        item: &Signed<'_, V, D>,
    ) -> Option<(Claim<'_, V>, Option<Contents<D>>)> {
        match *item {
            Signed::TransactionBlock(block) => Some((self.transaction_block_claim(block)?, None)),
            Signed::LeaderBlock(block) => Some((self.leader_block_claim(block)?, None)),
            Signed::Vote {
                content,
                attestation,
            } => Some((self.vote_claim(content, attestation)?, None)),
            Signed::Vqc(certificate) => self
                .vqc_claim(certificate)
                .map(|(claim, contents)| (claim, Some(contents))),
            Signed::Lqc(certificate) => self
                .lqc_claim::<H, D>(certificate)
                .map(|(claim, contents)| (claim, Some(contents))),
        }
    }
}
