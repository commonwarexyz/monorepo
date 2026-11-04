//! Signing Multimmit subjects with the local participant's role keys.

use super::{Error, Generic};
use crate::{
    Epochable, Viewable,
    multimmit::{
        scheme::{DaSubject, NullifySubject, OrdinarySubject, RoleDigest, Scheme},
        types::{
            DaVote, LeaderBlock, NoVote, Nullify, SignedLeaderBlock, SignedTransactionBlock,
            TransactionBlockHeader, Vote, VoteBody,
        },
    },
    types::Round,
};
use commonware_cryptography::{
    Digest,
    certificate::{Attestation, Scheme as _},
};
use commonware_utils::Participant;

impl<S: Scheme> Generic<S> {
    mocks_pub! {
        /// Signs a transaction-block header as its chain's producer.
        fn sign_transaction_block<D: Digest>(
            &self,
            header: TransactionBlockHeader<D>,
        ) -> Result<SignedTransactionBlock<S, D>, Error> {
            let expected = self.producer(header.chain())?;
            let attestation =
                self.sign_expected(OrdinarySubject::transaction_block(&header), expected)?;
            Ok(SignedTransactionBlock::new(header, attestation))
        }
    }

    mocks_pub! {
        /// Signs a data-availability vote for a header on a configured chain.
        fn sign_da_vote<D: Digest>(
            &self,
            header: TransactionBlockHeader<D>,
        ) -> Result<DaVote<S, D>, Error> {
            self.ensure_chain(header.chain())?;
            let subject = DaSubject::new(&header);
            self.ensure_epoch(subject.epoch())?;
            let attestation = self
                .da
                .sign::<RoleDigest>(subject)
                .ok_or(Error::VerifierOnly)?;
            Ok(DaVote::new(header, attestation))
        }
    }

    mocks_pub! {
        /// Signs a leader block as its view's scheduled leader.
        fn sign_leader_block<D: Digest>(
            &self,
            block: LeaderBlock<S, D>,
        ) -> Result<SignedLeaderBlock<S, D>, Error> {
            self.ensure_leader(&block)?;
            let expected = self.parameters.leader(block.view());
            let attestation = self.sign_expected(OrdinarySubject::leader_block(&block), expected)?;
            Ok(SignedLeaderBlock::new(block, attestation))
        }
    }

    mocks_pub! {
        /// Signs a vote body.
        fn sign_vote<D: Digest>(&self, body: VoteBody<D>) -> Result<Vote<S, D>, Error> {
            self.ensure_vote_body(&body)?;
            let attestation = self.sign_ordinary(OrdinarySubject::vote(&body))?;
            Ok(Vote::new(body, attestation))
        }
    }

    mocks_pub! {
        /// Signs an abstention for `round`.
        fn sign_novote(&self, round: Round) -> Result<NoVote<S>, Error> {
            let attestation = self.sign_ordinary(OrdinarySubject::novote(round))?;
            Ok(NoVote::new(round, attestation)?)
        }
    }

    mocks_pub! {
        /// Signs a nullify share for `round`.
        fn sign_nullify(&self, round: Round) -> Result<Nullify<S>, Error> {
            self.ensure_epoch(round.epoch())?;
            let attestation = self
                .nullify
                .sign::<RoleDigest>(NullifySubject::new(round))
                .ok_or(Error::VerifierOnly)?;
            Ok(Nullify::new(round, attestation)?)
        }
    }

    fn sign_ordinary(&self, subject: OrdinarySubject) -> Result<Attestation<S::Ordinary>, Error> {
        self.ensure_epoch(subject.epoch())?;
        self.ordinary
            .sign::<RoleDigest>(subject)
            .ok_or(Error::VerifierOnly)
    }

    /// Signs `subject` only when the local participant is `expected`, so a key never signs an
    /// ordinary subject it would discard.
    fn sign_expected(
        &self,
        subject: OrdinarySubject,
        expected: Participant,
    ) -> Result<Attestation<S::Ordinary>, Error> {
        self.ensure_epoch(subject.epoch())?;
        match self.me() {
            None => Err(Error::VerifierOnly),
            Some(me) if me != expected => Err(Error::Signer),
            Some(_) => self.sign_ordinary(subject),
        }
    }
}
