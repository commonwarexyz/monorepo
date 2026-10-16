//! Signing with the local participant's ordinary key.

use super::{Error, Scheme};
use crate::{
    Epochable, Viewable as _,
    multimmit::{
        scheme::Subject,
        types::{
            Attestation, LeaderBlock, SignedLeaderBlock, SignedTransactionBlock,
            TransactionBlockHeader, VoteContent,
        },
    },
};
use commonware_cryptography::{
    Digest, PublicKey,
    bls12381::primitives::{ops, variant::Variant},
    certificate::Subject as _,
};
use commonware_utils::Participant;

impl<P: PublicKey, V: Variant> Scheme<P, V> {
    mocks_pub! {
        /// Signs a transaction-block header for the local participant's producer chain.
        fn sign_transaction_block<D: Digest>(
            &self,
            header: TransactionBlockHeader<D>,
        ) -> Result<SignedTransactionBlock<V, D>, Error> {
            let expected = self.producer(header.chain())?;
            let attestation = self.sign_expected(Subject::transaction_block(&header), expected)?;
            Ok(SignedTransactionBlock::new(header, attestation))
        }
    }

    mocks_pub! {
        /// Signs a leader block as its view's scheduled leader.
        fn sign_leader_block<D: Digest>(
            &self,
            block: LeaderBlock<D>,
        ) -> Result<SignedLeaderBlock<V, D>, Error> {
            let expected = self.parameters.leader(block.view());
            let attestation = self.sign_expected(Subject::leader_block(&block), expected)?;
            Ok(SignedLeaderBlock::new(block, attestation))
        }
    }

    mocks_pub! {
        /// Signs one vote content with the local ordinary key.
        ///
        /// The returned attestation travels in a [`VoteUpdate`](crate::multimmit::types::VoteUpdate)
        /// whose rebuilt content is `content`.
        fn sign_vote<D: Digest>(&self, content: &VoteContent<D>) -> Result<Attestation<V>, Error> {
            if content.tips().len() != self.codec_config().chains() {
                return Err(Error::Chain);
            }
            self.sign(Subject::vote(content))
        }
    }

    fn sign(&self, subject: Subject) -> Result<Attestation<V>, Error> {
        self.ensure_epoch(subject.epoch())?;
        let signer = self.signer.as_ref().ok_or(Error::VerifierOnly)?;
        let signature = ops::sign_message::<V>(
            &signer.private,
            subject.namespace(&self.namespace),
            &subject.message(),
        );
        Ok(Attestation::new(signer.participant, signature.into()))
    }

    fn sign_expected(
        &self,
        subject: Subject,
        expected: Participant,
    ) -> Result<Attestation<V>, Error> {
        match self.me() {
            None => Err(Error::VerifierOnly),
            Some(me) if me != expected => Err(Error::Signer),
            Some(_) => self.sign(subject),
        }
    }
}
