//! Signing with the local participant's ordinary key and threshold shares.

use super::{Error, Scheme};
use crate::{
    Epochable, Viewable,
    multimmit::{
        scheme::Subject,
        types::{
            Attestation, DaVote, LeaderBlock, NoVote, Nullify, SignedLeaderBlock,
            SignedTransactionBlock, ThresholdShare, TransactionBlockHeader, Vote, VoteBody,
        },
    },
    types::{Attributable as _, Round},
};
use commonware_cryptography::{
    Digest, PublicKey,
    bls12381::primitives::{
        group::Share,
        ops::{self, threshold},
        variant::Variant,
    },
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
        /// Signs a data-availability threshold share over one complete header.
        fn sign_da_vote<D: Digest>(
            &self,
            header: TransactionBlockHeader<D>,
        ) -> Result<DaVote<V, D>, Error> {
            self.ensure_chain(header.chain())?;
            let share = self.sign_share(&self.signer_keys()?.da, Subject::da_vote(&header))?;
            Ok(DaVote::new(header, share))
        }
    }

    mocks_pub! {
        /// Signs a complete leader block as the round's scheduled leader.
        fn sign_leader_block<D: Digest>(
            &self,
            block: LeaderBlock<V, D>,
        ) -> Result<SignedLeaderBlock<V, D>, Error> {
            self.ensure_leader(&block)?;
            let expected = self.parameters.leader(block.view());
            let attestation = self.sign_expected(Subject::leader_block(&block), expected)?;
            Ok(SignedLeaderBlock::new(block, attestation))
        }
    }

    mocks_pub! {
        /// Signs one complete consensus vote with the local ordinary key.
        fn sign_vote<D: Digest>(&self, body: VoteBody<D>) -> Result<Vote<V, D>, Error> {
            self.ensure_vote_body(&body)?;
            let attestation = self.sign_attestation(Subject::vote(&body))?;
            Ok(Vote::new(body, attestation))
        }
    }

    mocks_pub! {
        /// Signs an attributed abstention for a round.
        fn sign_novote(&self, round: Round) -> Result<NoVote<V>, Error> {
            let attestation = self.sign_attestation(Subject::NoVote(round))?;
            Ok(NoVote::new(round, attestation)?)
        }
    }

    mocks_pub! {
        /// Signs a threshold share authorizing a round to be nullified.
        fn sign_nullify(&self, round: Round) -> Result<Nullify<V>, Error> {
            let share = self.sign_share(&self.signer_keys()?.nullification, Subject::Nullify(round))?;
            Ok(Nullify::new(round, share)?)
        }
    }

    fn sign_attestation(&self, subject: Subject) -> Result<Attestation<V>, Error> {
        self.ensure_epoch(subject.epoch())?;
        let keys = self.signer_keys()?;
        let signature = ops::sign_message::<V>(
            &keys.ordinary,
            subject.namespace(&self.namespace),
            &subject.message(),
        );
        Ok(Attestation::new(keys.da.index, signature.into()))
    }

    fn sign_expected(
        &self,
        subject: Subject,
        expected: Participant,
    ) -> Result<Attestation<V>, Error> {
        let attestation = self.sign_attestation(subject)?;
        if attestation.signer() != expected {
            return Err(Error::Signer);
        }
        Ok(attestation)
    }

    /// Signs `subject` with one of the local threshold shares.
    fn sign_share(&self, share: &Share, subject: Subject) -> Result<ThresholdShare<V>, Error> {
        self.ensure_epoch(subject.epoch())?;
        let share = threshold::sign_message::<V>(
            share,
            subject.namespace(&self.namespace),
            &subject.message(),
        );
        Ok(ThresholdShare::new(share.index, share.value.into()))
    }
}
