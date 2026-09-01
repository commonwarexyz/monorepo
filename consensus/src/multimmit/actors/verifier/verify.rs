//! Execute one machine-issued verification job with the concrete Multimmit scheme.
//!
//! Every item is checked first: DA shares structurally and everything else by batched signature
//! verification. Each DA share that passes is then checked for equivocation against the shares
//! before it, and each authenticated certificate has its application-block ancestry transcript
//! validated. The machine retains the artifacts and rejects any completion whose generation,
//! cardinality, or ticket order does not match its job.

use crate::{
    multimmit::{
        algebra::{ValidatedLqc, ValidatedVqc, validate_lqc, validate_vqc_with_votes},
        machine::{Verdict, VerificationCompletion, VerificationItem, VerifyJob},
        scheme::{
            Verified,
            bls12381_threshold::{CertificateVotes, Scheme},
        },
        types::{Artifact, CodecConfig, DaVote},
    },
    types::{Attributable as _, Participant},
};
use commonware_cryptography::{Digest, Hasher, PublicKey, bls12381::primitives::variant::Variant};
use commonware_parallel::Strategy;
use rand_core::CryptoRng;
use std::sync::Arc;

/// One item's check: `Err` when invalid, otherwise the votes an authenticated certificate's
/// transcript expanded to.
type Authentication<H> = Result<Option<CertificateVotes<<H as Hasher>::Digest>>, ()>;

/// Derivations a job returns with its verdicts, each keyed by item index.
struct Derivations<V: Variant, H: Hasher> {
    vqcs: Vec<(usize, ValidatedVqc<H::Digest>)>,
    lqcs: Vec<(usize, ValidatedLqc<V, H::Digest>)>,
    da_equivocators: Vec<(usize, Participant)>,
}

/// Executes `job` and returns its completion.
///
/// V-QC and L-QC verdicts also require a coherent application-block ancestry transcript.
pub(crate) fn verify<H, P, V>(
    job: &VerifyJob<V, H::Digest>,
    rng: &mut impl CryptoRng,
    scheme: &Scheme<P, V>,
    strategy: &impl Strategy,
) -> VerificationCompletion<V, H::Digest>
where
    H: Hasher,
    P: PublicKey,
    V: Variant,
{
    let items = job.items();
    let mut derivations = Derivations::<V, H> {
        vqcs: Vec::new(),
        lqcs: Vec::new(),
        da_equivocators: Vec::new(),
    };
    let verdicts = batch_verdicts::<H, P, V>(items, rng, scheme, strategy)
        .into_iter()
        .zip(items)
        .enumerate()
        .map(|(index, (authentication, item))| {
            let Ok(votes) = authentication else {
                return Verdict::new(item.ticket(), false);
            };
            let valid = match item.artifact() {
                Artifact::DaVote(vote) => {
                    if let Some(signer) =
                        da_equivocator(scheme, vote, item.known(), &items[..index])
                    {
                        derivations.da_equivocators.push((index, signer));
                    }
                    true
                }
                artifact => validate_certificate(
                    scheme.codec_config(),
                    index,
                    artifact,
                    votes,
                    &mut derivations,
                ),
            };
            Verdict::new(item.ticket(), valid)
        })
        .collect();
    VerificationCompletion::with_validated(
        job.issued(),
        verdicts,
        derivations.vqcs,
        derivations.lqcs,
        derivations.da_equivocators,
    )
}

/// Checks every item in `items`, in order.
///
/// A data-availability share is only ever consumed by threshold recovery, which checks the whole
/// quorum with one pairing against the group identity. Paying a pairing per share here would
/// establish the same fact once per signer, so shares are admitted on their structural checks
/// alone and recovery attributes them if that check ever fails. Every other item joins one scheme
/// batch together with the messages its item already knew.
fn batch_verdicts<H, P, V>(
    items: &[VerificationItem<V, H::Digest>],
    rng: &mut impl CryptoRng,
    scheme: &Scheme<P, V>,
    strategy: &impl Strategy,
) -> Vec<Authentication<H>>
where
    H: Hasher,
    P: PublicKey,
    V: Variant,
{
    let mut valid = Vec::with_capacity(items.len());
    let mut batched = Vec::with_capacity(items.len());
    let mut artifacts = Vec::with_capacity(items.len());
    let mut known = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        if let Artifact::DaVote(vote) = item.artifact() {
            valid.push(scheme.precheck_da_vote(vote).then_some(None).ok_or(()));
            continue;
        }
        valid.push(Err(()));
        batched.push(index);
        artifacts.push(item.artifact());
        known.push(
            item.known()
                .iter()
                .filter_map(|artifact| match artifact.as_ref() {
                    Artifact::Vote(vote) => Some(Verified::Vote(vote)),
                    Artifact::NoVote(vote) => Some(Verified::NoVote(vote)),
                    Artifact::DaCertificate(certificate) => {
                        Some(Verified::DaCertificate(certificate))
                    }
                    _ => None,
                })
                .collect::<Vec<_>>(),
        );
    }
    let known = known.iter().map(Vec::as_slice).collect::<Vec<_>>();
    if !artifacts.is_empty() {
        for (position, verdict) in scheme
            .verify_artifacts_expanded::<_, H, H::Digest>(rng, &artifacts, &known, strategy)
            .into_iter()
            .enumerate()
        {
            valid[batched[position]] = verdict;
        }
    }
    valid
}

/// Returns the signer of `vote` if a conflicting share proves it equivocated.
///
/// A conflicting share has the same signer, chain, and height but another header. Candidates are
/// the shares `vote`'s item already knew, then the shares of `earlier` items in job order.
fn da_equivocator<P, V, D>(
    scheme: &Scheme<P, V>,
    vote: &DaVote<V, D>,
    known: &[Arc<Artifact<V, D>>],
    earlier: &[VerificationItem<V, D>],
) -> Option<Participant>
where
    P: PublicKey,
    V: Variant,
    D: Digest,
{
    let prior = known
        .iter()
        .chain(earlier.iter().map(VerificationItem::shared_artifact))
        .filter_map(|candidate| match candidate.as_ref() {
            Artifact::DaVote(candidate)
                if candidate.signer() == vote.signer()
                    && candidate.header().chain() == vote.header().chain()
                    && candidate.header().height() == vote.header().height()
                    && candidate.header() != vote.header() =>
            {
                Some(candidate)
            }
            _ => None,
        });
    proves_da_equivocation(vote, prior, |vote| scheme.verify_da_vote(vote)).then_some(vote.signer())
}

/// Returns whether `vote` and a conflicting share in `prior` are both authentic, proving the
/// signer equivocated.
///
/// `verify` costs a pairing, so it runs only once a conflicting share exists.
fn proves_da_equivocation<'a, V: Variant, D: Digest>(
    vote: &DaVote<V, D>,
    prior: impl IntoIterator<Item = &'a DaVote<V, D>>,
    mut verify: impl FnMut(&DaVote<V, D>) -> bool,
) -> bool {
    let mut prior = prior.into_iter().peekable();
    prior.peek().is_some() && verify(vote) && prior.any(verify)
}

/// Validates the ancestry transcript of the authenticated certificate at `index` and keeps its
/// derivation, returning whether the item is valid.
///
/// Items other than certificates carry no transcript and stay valid.
fn validate_certificate<V: Variant, H: Hasher>(
    config: CodecConfig,
    index: usize,
    artifact: &Artifact<V, H::Digest>,
    votes: Option<CertificateVotes<H::Digest>>,
    derivations: &mut Derivations<V, H>,
) -> bool {
    match artifact {
        Artifact::Vqc(certificate) => {
            let votes = votes.expect("authenticated V-QC expansion");
            let Ok(validated) =
                validate_vqc_with_votes::<H, V, H::Digest>(certificate, config, votes)
            else {
                return false;
            };
            derivations.vqcs.push((index, validated));
            true
        }
        Artifact::Lqc(certificate) => {
            let votes = votes.expect("authenticated L-QC expansion");
            let Ok(validated) = validate_lqc::<H, V, H::Digest>(certificate, config, votes) else {
                return false;
            };
            derivations.lqcs.push((index, validated));
            true
        }
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multimmit::{
        machine::{Generation, Issued, JobId, Observation, VerificationTicket},
        mocks::Committee,
        types::ChainId,
    };
    use commonware_cryptography::{
        Sha256, bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
    };
    use commonware_parallel::Sequential;
    use commonware_utils::test_rng;
    use std::cell::Cell;

    type Vote = DaVote<MinPk, Sha256Digest>;

    fn committee() -> Committee<MinPk> {
        Committee::builder(11, 6).build()
    }

    /// Returns `signer`'s share for a height-one header on chain zero committing to `label`.
    fn share(committee: &Committee<MinPk>, signer: u32, label: &[u8]) -> Vote {
        committee.da_vote(
            Participant::new(signer),
            committee.transaction_header(ChainId::new(0), Sha256::hash(&[label])),
        )
    }

    /// Returns a job over `shares`, each item knowing the shares paired with it.
    fn job(shares: Vec<(Vote, Vec<Vote>)>) -> VerifyJob<MinPk, Sha256Digest> {
        let job = JobId::new(1);
        let items = shares
            .into_iter()
            .enumerate()
            .map(|(index, (vote, known))| {
                let artifact = Artifact::DaVote(vote);
                let ticket = VerificationTicket::new(
                    job,
                    artifact.id::<Sha256>(),
                    Observation::new(1, index as u32),
                );
                let known = known
                    .into_iter()
                    .map(|vote| Arc::new(Artifact::DaVote(vote)))
                    .collect();
                VerificationItem::new(ticket, Arc::new(artifact), known)
            })
            .collect();
        VerifyJob::new(Issued::new(job, Generation::new(0)), items)
    }

    fn equivocators(job: &VerifyJob<MinPk, Sha256Digest>) -> Vec<Option<Participant>> {
        let committee = committee();
        let mut completion =
            verify::<Sha256, _, _>(job, &mut test_rng(), &committee.verifier, &Sequential);
        assert!(completion.verdicts().iter().all(|verdict| verdict.valid()));
        (0..job.items().len())
            .map(|index| completion.take_da_equivocator(index))
            .collect()
    }

    #[test]
    fn da_equivocation_verifies_only_with_a_conflicting_prior_share() {
        let committee = committee();
        let (first, second) = (
            share(&committee, 0, b"first"),
            share(&committee, 0, b"second"),
        );

        let pairings = Cell::new(0);
        let verify = |_: &Vote| {
            pairings.set(pairings.get() + 1);
            true
        };
        assert!(!proves_da_equivocation(&first, [], verify));
        assert_eq!(
            pairings.get(),
            0,
            "no share is verified without a conflicting prior"
        );
        assert!(proves_da_equivocation(&first, [&second], verify));
        assert_eq!(pairings.get(), 2);

        // A forged new share never proves equivocation, and its prior is not verified.
        pairings.set(0);
        assert!(!proves_da_equivocation(&first, [&second], |_| {
            pairings.set(pairings.get() + 1);
            false
        }));
        assert_eq!(pairings.get(), 1);

        // A valid new share with a forged prior does not prove equivocation either.
        pairings.set(0);
        assert!(!proves_da_equivocation(&first, [&second], |share| {
            pairings.set(pairings.get() + 1);
            share.header() == first.header()
        }));
        assert_eq!(pairings.get(), 2);
    }

    #[test]
    fn a_conflicting_share_is_charged_to_the_later_item() {
        let committee = committee();
        let job = job(vec![
            (share(&committee, 1, b"first"), Vec::new()),
            (share(&committee, 2, b"second"), Vec::new()),
            (share(&committee, 1, b"second"), Vec::new()),
            (share(&committee, 1, b"first"), Vec::new()),
        ]);

        // Signer 2 never conflicts, and a repeated header is not a conflict.
        let signer = Some(Participant::new(1));
        assert_eq!(equivocators(&job), [None, None, signer, signer]);
    }

    #[test]
    fn a_known_conflicting_share_proves_equivocation_on_the_first_item() {
        let committee = committee();
        let job = job(vec![
            (
                share(&committee, 1, b"first"),
                vec![share(&committee, 1, b"second")],
            ),
            (
                share(&committee, 2, b"first"),
                vec![share(&committee, 1, b"second")],
            ),
        ]);

        // A known share from another signer does not implicate this one.
        assert_eq!(equivocators(&job), [Some(Participant::new(1)), None]);
    }
}
