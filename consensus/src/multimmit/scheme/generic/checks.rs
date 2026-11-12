//! Role checks extracted from structurally valid artifacts, and their verification.
//!
//! An artifact's structural checks run before any check is extracted, so no signature is
//! verified for a malformed artifact. Every check names the artifact that contributed it, and a
//! failing check fails exactly that artifact.

use super::{Generic, transcript::Entry};
use crate::{
    Epochable, Viewable,
    multimmit::{
        scheme::{
            AggregateOf, DaSubject, NullifySubject, OrdinarySubject, RoleDigest, Scheme, Verified,
        },
        types::{
            Anchor, DaCertificate, DaVote, Lqc, NoVote, Nullification, Nullify, SignedLeaderBlock,
            SignedTransactionBlock, Vote, Vqc,
        },
    },
    types::Attributable as _,
};
use bytes::Bytes;
use commonware_cryptography::{
    Digest, Hasher,
    certificate::{self, Aggregator as _, Attestation, Item, Scheme as _, Subject, Term},
};
use commonware_parallel::Strategy;
use commonware_utils::{Participant, iter::NonEmpty};
use rand_core::CryptoRng;
use std::collections::{HashMap, HashSet};

/// An ordinary attestation or aggregate to verify.
pub(super) enum OrdinaryCheck<'k, S: Scheme> {
    /// One attestation over one subject.
    Attestation {
        subject: OrdinarySubject,
        attestation: &'k Attestation<S::Ordinary>,
    },
    /// An aggregate over a transcript, whose terms may carry known attestations.
    Aggregate {
        terms: Vec<Term<'k, S::Ordinary, RoleDigest>>,
        aggregate: &'k AggregateOf<S>,
    },
}

/// An attestation or certificate of a role without aggregation.
pub(super) enum RoleCheck<'k, R: certificate::Scheme, T> {
    /// One attestation over one subject.
    Attestation(T, &'k Attestation<R>),
    /// One certificate over one subject.
    Certificate(T, &'k R::Certificate),
}

/// Every check one artifact contributes.
pub(super) struct Checks<'k, S: Scheme> {
    pub(super) ordinary: Vec<OrdinaryCheck<'k, S>>,
    pub(super) da: Vec<RoleCheck<'k, S::Da, DaSubject>>,
    pub(super) nullify: Vec<RoleCheck<'k, S::Nullify, NullifySubject>>,
}

impl<S: Scheme> Default for Checks<'_, S> {
    fn default() -> Self {
        Self {
            ordinary: Vec::new(),
            da: Vec::new(),
            nullify: Vec::new(),
        }
    }
}

impl<'k, S: Scheme> Checks<'k, S> {
    fn ordinary(subject: OrdinarySubject, attestation: &'k Attestation<S::Ordinary>) -> Self {
        Self {
            ordinary: vec![OrdinaryCheck::Attestation {
                subject,
                attestation,
            }],
            ..Self::default()
        }
    }

    fn da(check: RoleCheck<'k, S::Da, DaSubject>) -> Self {
        Self {
            da: vec![check],
            ..Self::default()
        }
    }

    fn nullify(check: RoleCheck<'k, S::Nullify, NullifySubject>) -> Self {
        Self {
            nullify: vec![check],
            ..Self::default()
        }
    }
}

/// Builds the aggregate check of a transcript, attaching every known attestation that matches a
/// transcript term's signer and subject.
///
/// A known attestation whose signature does not decode is never attached, so a malformed known
/// message cannot fail an otherwise valid certificate.
pub(super) fn aggregate_check<'k, S: Scheme, D: Digest>(
    entries: Vec<Entry>,
    aggregate: &'k AggregateOf<S>,
    known: &[Verified<'k, S, D>],
) -> OrdinaryCheck<'k, S> {
    let mut held: HashMap<Participant, (OrdinarySubject, &'k Attestation<S::Ordinary>)> =
        HashMap::with_capacity(known.len());
    for message in known {
        let (signer, subject, attestation) = match *message {
            Verified::Vote(vote) => (
                vote.signer(),
                OrdinarySubject::vote(vote.body()),
                vote.attestation(),
            ),
            Verified::NoVote(novote) => (
                novote.signer(),
                OrdinarySubject::novote(novote.round()),
                novote.attestation(),
            ),
            // Certificates discharge leader-block anchors, never aggregate transcripts.
            Verified::DaCertificate(_) => continue,
        };
        if attestation.signature.get().is_some() {
            held.insert(signer, (subject, attestation));
        }
    }
    let terms = entries
        .into_iter()
        .map(|entry| {
            let known = held
                .get(&entry.signer)
                .filter(|(subject, _)| *subject == entry.subject)
                .map(|(_, attestation)| *attestation);
            Term {
                signer: entry.signer,
                subject: entry.subject,
                known,
            }
        })
        .collect();
    OrdinaryCheck::Aggregate { terms, aggregate }
}

impl<S: Scheme> Generic<S> {
    /// Returns whether `signer` indexes a committee member.
    fn known_signer(&self, signer: Participant) -> bool {
        usize::from(signer) < self.participants().len()
    }

    pub(super) fn transaction_block_checks<'k, D: Digest>(
        &self,
        block: &'k SignedTransactionBlock<S, D>,
    ) -> Option<Checks<'k, S>> {
        if self.producer(block.header().chain()).ok()? != block.signer() {
            return None;
        }
        self.ensure_epoch(block.header().epoch()).ok()?;
        Some(Checks::ordinary(
            OrdinarySubject::transaction_block(block.header()),
            block.attestation(),
        ))
    }

    pub(super) fn da_vote_checks<'k, D: Digest>(
        &self,
        vote: &'k DaVote<S, D>,
    ) -> Option<Checks<'k, S>> {
        let header = vote.header();
        if !self.attestations
            || !self.chain_in_range(header.chain())
            || self.ensure_epoch(header.epoch()).is_err()
            || !self.known_signer(vote.signer())
        {
            return None;
        }
        Some(Checks::da(RoleCheck::Attestation(
            DaSubject::new(header),
            vote.attestation(),
        )))
    }

    pub(super) fn leader_block_checks<'k, D: Digest>(
        &self,
        block: &'k SignedLeaderBlock<S, D>,
        known: &[Verified<'_, S, D>],
    ) -> Option<Checks<'k, S>> {
        if self.ensure_leader(block.block()).is_err()
            || block.signer() != self.parameters.leader(block.view())
        {
            return None;
        }
        let mut checks = Checks::ordinary(
            OrdinarySubject::leader_block(block.block()),
            block.attestation(),
        );
        for proposal in block.block().proposals() {
            let Anchor::Certificate(certificate) = proposal.anchor() else {
                continue;
            };
            if known.iter().any(
                |message| matches!(message, Verified::DaCertificate(held) if *held == certificate),
            ) {
                continue;
            }
            checks.da.push(self.da_certificate_check(certificate)?);
        }
        Some(checks)
    }

    pub(super) fn vote_checks<'k, D: Digest>(&self, vote: &'k Vote<S, D>) -> Option<Checks<'k, S>> {
        self.ensure_vote_body(vote.body()).ok()?;
        Some(Checks::ordinary(
            OrdinarySubject::vote(vote.body()),
            vote.attestation(),
        ))
    }

    pub(super) fn novote_checks<'k>(&self, novote: &'k NoVote<S>) -> Option<Checks<'k, S>> {
        self.ensure_epoch(novote.round().epoch()).ok()?;
        Some(Checks::ordinary(
            OrdinarySubject::novote(novote.round()),
            novote.attestation(),
        ))
    }

    pub(super) fn nullify_checks<'k>(&self, nullify: &'k Nullify<S>) -> Option<Checks<'k, S>> {
        self.ensure_epoch(nullify.round().epoch()).ok()?;
        if !self.attestations || !self.known_signer(nullify.signer()) {
            return None;
        }
        Some(Checks::nullify(RoleCheck::Attestation(
            NullifySubject::new(nullify.round()),
            nullify.attestation(),
        )))
    }

    pub(super) fn nullification_checks<'k>(
        &self,
        nullification: &'k Nullification<S>,
    ) -> Option<Checks<'k, S>> {
        self.ensure_epoch(nullification.epoch()).ok()?;
        Some(Checks::nullify(RoleCheck::Certificate(
            NullifySubject::new(nullification.round()),
            nullification.certificate(),
        )))
    }

    pub(super) fn da_certificate_checks<'k, D: Digest>(
        &self,
        certificate: &'k DaCertificate<S, D>,
    ) -> Option<Checks<'k, S>> {
        Some(Checks::da(self.da_certificate_check(certificate)?))
    }

    fn da_certificate_check<'k, D: Digest>(
        &self,
        certificate: &'k DaCertificate<S, D>,
    ) -> Option<RoleCheck<'k, S::Da, DaSubject>> {
        let header = certificate.header();
        if !self.chain_in_range(header.chain()) || self.ensure_epoch(header.epoch()).is_err() {
            return None;
        }
        Some(RoleCheck::Certificate(
            DaSubject::new(header),
            certificate.certificate(),
        ))
    }

    /// Verifies the checks of every artifact, returning one verdict per artifact.
    ///
    /// An artifact without checks (`None`) failed its structural checks and is invalid. Every
    /// other artifact is valid exactly when all of its checks pass.
    pub(super) fn verify_checks<R: CryptoRng>(
        &self,
        rng: &mut R,
        checks: &[Option<Checks<'_, S>>],
        strategy: &impl Strategy,
    ) -> Vec<bool> {
        let mut valid: Vec<bool> = checks.iter().map(Option::is_some).collect();

        // Ordinary checks of every artifact form one batch.
        let mut items = Vec::new();
        let mut owners = Vec::new();
        for (owner, checks) in checks.iter().enumerate() {
            let Some(checks) = checks else {
                continue;
            };
            for check in &checks.ordinary {
                items.push(match check {
                    OrdinaryCheck::Attestation {
                        subject,
                        attestation,
                    } => Item::Attestation {
                        subject: subject.clone(),
                        attestation: *attestation,
                    },
                    OrdinaryCheck::Aggregate { terms, aggregate } => Item::Aggregate {
                        terms: terms.as_slice(),
                        aggregate: *aggregate,
                    },
                });
                owners.push(owner);
            }
        }
        let verdicts = match items.as_slice() {
            [] => Vec::new(),
            [
                Item::Attestation {
                    subject,
                    attestation,
                },
            ] => vec![self.ordinary.verify_attestation::<_, RoleDigest>(
                rng,
                subject.clone(),
                attestation,
                strategy,
            )],
            _ => self
                .ordinary
                .verify_aggregates::<_, RoleDigest>(rng, &items, strategy),
        };
        drop(items);
        for (owner, verdict) in owners.into_iter().zip(verdicts) {
            if !verdict {
                valid[owner] = false;
            }
        }

        // Threshold-role checks of artifacts that are still valid.
        let da = checks
            .iter()
            .enumerate()
            .filter(|(owner, _)| valid[*owner])
            .filter_map(|(owner, checks)| checks.as_ref().map(|checks| (owner, checks)))
            .flat_map(|(owner, checks)| checks.da.iter().map(move |check| (owner, check)))
            .collect::<Vec<_>>();
        verify_role(&self.da, rng, &da, &mut valid, strategy);
        let nullify = checks
            .iter()
            .enumerate()
            .filter(|(owner, _)| valid[*owner])
            .filter_map(|(owner, checks)| checks.as_ref().map(|checks| (owner, checks)))
            .flat_map(|(owner, checks)| checks.nullify.iter().map(move |check| (owner, check)))
            .collect::<Vec<_>>();
        verify_role(&self.nullify, rng, &nullify, &mut valid, strategy);
        valid
    }

    /// Verifies the checks of one artifact.
    fn verify_one<R: CryptoRng>(
        &self,
        rng: &mut R,
        checks: Option<Checks<'_, S>>,
        strategy: &impl Strategy,
    ) -> bool {
        checks.is_some() && self.verify_checks(rng, &[checks], strategy)[0]
    }

    /// Verifies a producer's signed transaction block.
    pub fn verify_transaction_block<R: CryptoRng, D: Digest>(
        &self,
        rng: &mut R,
        block: &SignedTransactionBlock<S, D>,
        strategy: &impl Strategy,
    ) -> bool {
        self.verify_one(rng, self.transaction_block_checks(block), strategy)
    }

    /// Verifies a data-availability vote.
    pub fn verify_da_vote<R: CryptoRng, D: Digest>(
        &self,
        rng: &mut R,
        vote: &DaVote<S, D>,
        strategy: &impl Strategy,
    ) -> bool {
        self.verify_one(rng, self.da_vote_checks(vote), strategy)
    }

    /// Returns whether a data-availability vote passes every check short of its signature.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn precheck_da_vote<D: Digest>(&self, vote: &DaVote<S, D>) -> bool {
        self.da_vote_checks(vote).is_some()
    }

    /// Verifies a signed leader block and every DA certificate it anchors on.
    pub fn verify_leader_block<R: CryptoRng, D: Digest>(
        &self,
        rng: &mut R,
        block: &SignedLeaderBlock<S, D>,
        strategy: &impl Strategy,
    ) -> bool {
        self.verify_one(rng, self.leader_block_checks(block, &[]), strategy)
    }

    /// Verifies a vote.
    pub fn verify_vote<R: CryptoRng, D: Digest>(
        &self,
        rng: &mut R,
        vote: &Vote<S, D>,
        strategy: &impl Strategy,
    ) -> bool {
        self.verify_one(rng, self.vote_checks(vote), strategy)
    }

    /// Verifies an attributed abstention.
    pub fn verify_novote<R: CryptoRng>(
        &self,
        rng: &mut R,
        novote: &NoVote<S>,
        strategy: &impl Strategy,
    ) -> bool {
        self.verify_one(rng, self.novote_checks(novote), strategy)
    }

    /// Verifies a nullify share.
    pub fn verify_nullify<R: CryptoRng>(
        &self,
        rng: &mut R,
        nullify: &Nullify<S>,
        strategy: &impl Strategy,
    ) -> bool {
        self.verify_one(rng, self.nullify_checks(nullify), strategy)
    }

    /// Verifies a data-availability certificate.
    pub fn verify_da_certificate<R: CryptoRng, D: Digest>(
        &self,
        rng: &mut R,
        certificate: &DaCertificate<S, D>,
        strategy: &impl Strategy,
    ) -> bool {
        self.verify_one(rng, self.da_certificate_checks(certificate), strategy)
    }

    /// Verifies a payment chain's receipt: a data-availability certificate that also counts at
    /// least [`Self::receipt_quorum`] signers.
    ///
    /// A receipt verifies as an ordinary certificate too. The signer count is checked first, so a
    /// certificate below the receipt quorum costs no signature check.
    pub fn verify_receipt<R: CryptoRng, D: Digest>(
        &self,
        rng: &mut R,
        certificate: &DaCertificate<S, D>,
        strategy: &impl Strategy,
    ) -> bool {
        self.is_receipt(certificate.certificate())
            && self.verify_da_certificate(rng, certificate, strategy)
    }

    /// Verifies a nullification.
    pub fn verify_nullification<R: CryptoRng>(
        &self,
        rng: &mut R,
        nullification: &Nullification<S>,
        strategy: &impl Strategy,
    ) -> bool {
        self.verify_one(rng, self.nullification_checks(nullification), strategy)
    }

    /// Verifies every ordinary signature represented by a V-QC's compact transcript.
    ///
    /// Returns the certificate's identifier when it verifies.
    pub fn verify_vqc<R: CryptoRng, H: Hasher<Digest = D>, D: Digest>(
        &self,
        rng: &mut R,
        certificate: &Vqc<S, D>,
        strategy: &impl Strategy,
    ) -> Option<crate::multimmit::types::CertificateId<D>> {
        let checks = self.vqc_checks::<H, D>(certificate, &[])?;
        self.verify_one(rng, Some(checks.checks), strategy)
            .then(|| certificate.id::<H>())
    }

    /// Verifies every ordinary signature represented by an L-QC's compact transcript.
    ///
    /// Returns the certificate's identifier when it verifies.
    pub fn verify_lqc<R: CryptoRng, H: Hasher<Digest = D>, D: Digest>(
        &self,
        rng: &mut R,
        certificate: &Lqc<S, D>,
        strategy: &impl Strategy,
    ) -> Option<crate::multimmit::types::CertificateId<D>> {
        let checks = self.lqc_checks::<H, D>(certificate, &[])?;
        self.verify_one(rng, Some(checks.checks), strategy)
            .then(|| certificate.id::<H>())
    }
}

/// Verifies the attestation and certificate checks of one role, failing the owner of every
/// failing check.
///
/// Attestations are grouped by subject and each group is verified as one batch with distinct
/// signers; a repeated signer is verified on its own so that a forgery attributed to a signer
/// never fails another artifact's valid attestation by that signer. Certificates are verified as
/// one batch and bisected on failure.
/// Attestations of one role over one subject, each with the artifact that contributed it.
type Group<'c, R, T> = (T, Vec<(usize, &'c Attestation<R>)>);

fn verify_role<R, T, G>(
    role: &R,
    rng: &mut G,
    checks: &[(usize, &RoleCheck<'_, R, T>)],
    valid: &mut [bool],
    strategy: &impl Strategy,
) where
    R: for<'a> certificate::Scheme<Subject<'a, RoleDigest> = T>,
    T: Subject,
    G: CryptoRng,
{
    let mut groups: Vec<Group<'_, R, T>> = Vec::new();
    let mut positions: HashMap<Bytes, usize> = HashMap::new();
    let mut certificates: Vec<(usize, T, &R::Certificate)> = Vec::new();
    for (owner, check) in checks {
        match check {
            RoleCheck::Attestation(subject, attestation) => {
                let position = *positions.entry(subject.message()).or_insert_with(|| {
                    groups.push((subject.clone(), Vec::new()));
                    groups.len() - 1
                });
                groups[position].1.push((*owner, *attestation));
            }
            RoleCheck::Certificate(subject, certificate) => {
                certificates.push((*owner, subject.clone(), *certificate));
            }
        }
    }

    for (subject, attestations) in groups {
        let mut signers = HashSet::with_capacity(attestations.len());
        let (batch, repeated): (Vec<_>, Vec<_>) = attestations
            .into_iter()
            .partition(|(_, attestation)| signers.insert(attestation.signer));
        if let [(owner, attestation)] = batch.as_slice() {
            if !role.verify_attestation::<_, RoleDigest>(
                rng,
                subject.clone(),
                attestation,
                strategy,
            ) {
                valid[*owner] = false;
            }
        } else if !batch.is_empty() {
            let verification = role.verify_attestations::<_, RoleDigest, _>(
                rng,
                subject.clone(),
                batch
                    .iter()
                    .map(|(_, attestation)| (*attestation).clone())
                    .collect::<Vec<_>>(),
                strategy,
            );
            let invalid: HashSet<_> = verification.invalid.into_iter().collect();
            for (owner, attestation) in &batch {
                if invalid.contains(&attestation.signer) {
                    valid[*owner] = false;
                }
            }
        }
        for (owner, attestation) in repeated {
            if !role.verify_attestation::<_, RoleDigest>(
                rng,
                subject.clone(),
                attestation,
                strategy,
            ) {
                valid[owner] = false;
            }
        }
    }

    // Iterative bisection over the certificate batch.
    let mut stack = vec![(0, certificates.len())];
    while let Some((start, end)) = stack.pop() {
        if start == end {
            continue;
        }
        let range = &certificates[start..end];
        let passed = match range {
            [(_, subject, certificate)] => role.verify_certificate::<_, RoleDigest>(
                rng,
                subject.clone(),
                certificate,
                strategy,
            ),
            [(_, subject, certificate), rest @ ..] => role.verify_certificates::<_, RoleDigest, _>(
                rng,
                NonEmpty::new(
                    (subject.clone(), *certificate),
                    rest.iter()
                        .map(|(_, subject, certificate)| (subject.clone(), *certificate)),
                ),
                strategy,
            ),
            [] => true,
        };
        if passed {
            continue;
        }
        if end - start == 1 {
            valid[certificates[start].0] = false;
        } else {
            let mid = start + (end - start) / 2;
            stack.push((mid, end));
            stack.push((start, mid));
        }
    }
}
