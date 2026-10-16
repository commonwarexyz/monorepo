use super::*;
use crate::{
    multimmit::types::{ChainId, Window},
    types::{Epoch, Height, View},
};
use commonware_codec::{Decode as _, Encode as _};
use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest as Sha256Digest};

type D = Sha256Digest;

fn config() -> CodecConfig {
    CodecConfig::new(6, 3, Window::with_bounds(2, 4, 2).unwrap()).unwrap()
}

fn round() -> Round {
    Round::new(Epoch::new(1), View::new(4))
}

fn tip(chain: u32, height: u64, salt: u8) -> BlockRef<D> {
    BlockRef::new(
        ChainId::new(chain),
        Height::new(height),
        Sha256::hash(&[&[salt], &chain.to_be_bytes(), &height.to_be_bytes()]),
    )
}

fn endorsement(heights: [u64; 3], declared: &[u32], salt: u8) -> Endorsement<D> {
    Endorsement::new(
        ChainSet::from_chains(3, declared.iter().copied().map(ChainId::new)).unwrap(),
        (0..3)
            .map(|chain| tip(chain, heights[chain as usize], salt))
            .collect::<Vec<_>>(),
        config(),
    )
    .unwrap()
}

fn leader() -> D {
    Sha256::hash(&[b"leader"])
}

/// Five votes (n - f for n = 6): signers 1 and 4 share the common entry with signer 0 skipped.
fn votes() -> Vec<(Participant, VoteContent<D>)> {
    let common = endorsement([3, 3, 3], &[2], 0);
    let entries = [
        (1, true, common.clone()),
        (2, false, endorsement([3, 2, 3], &[2], 0)),
        (3, true, endorsement([3, 3, 4], &[0, 2], 7)),
        (4, true, common.clone()),
        (5, true, common),
    ];
    entries
        .into_iter()
        .map(|(signer, final_, endorsement)| {
            (
                Participant::new(signer),
                VoteContent::new(round(), Some(leader()), final_, endorsement).unwrap(),
            )
        })
        .collect()
}

fn finals() -> Vec<(Participant, VoteContent<D>)> {
    let common = endorsement([3, 3, 3], &[], 0);
    let entries = [
        (0, None, endorsement([3, 3, 3], &[1], 0)),
        (1, Some(leader()), common.clone()),
        (3, Some(leader()), common.clone()),
        (4, Some(leader()), endorsement([2, 3, 3], &[], 0)),
        (5, Some(leader()), common),
    ];
    entries
        .into_iter()
        .map(|(signer, leader, endorsement)| {
            (
                Participant::new(signer),
                VoteContent::new(round(), leader, true, endorsement).unwrap(),
            )
        })
        .collect()
}

fn paths() -> Vec<ResolutionPath<D>> {
    vec![
        ResolutionPath::new(tip(1, 1, 0), vec![Sha256::hash(&[b"a"])], config()).unwrap(),
        ResolutionPath::new(tip(0, 1, 0), vec![Sha256::hash(&[b"b"]); 2], config()).unwrap(),
    ]
}

#[test]
fn vote_tally_round_trips_and_expands_its_contents() {
    let tally = VoteTally::from_contents(leader(), votes(), config()).unwrap();
    assert_eq!(tally.reference_signer(), Participant::new(1));
    assert_eq!(tally.deviations().len(), 2);
    assert_eq!(tally.contents(round(), leader()), votes());

    let decoded = VoteTally::<D>::decode_cfg(tally.encode(), &config()).unwrap();
    assert_eq!(decoded, tally);
    assert!(tally.encode_size() <= VoteTally::<D>::max_encode_size(config()).unwrap());
}

#[test]
fn final_tally_round_trips_and_expands_its_contents() {
    let tally = FinalTally::from_contents(finals(), paths(), config()).unwrap();
    assert_eq!(tally.reference_signer(), Participant::new(1));
    assert_eq!(tally.contents(round()), finals());
    assert!(tally.paths().windows(2).all(|pair| pair[0] < pair[1]));
    let decoded = FinalTally::<D>::decode_cfg(tally.encode(), &config()).unwrap();
    assert_eq!(decoded, tally);
}

#[test]
fn tallies_reject_wrong_kinds_and_quorums() {
    let mut wrong_leader = votes();
    wrong_leader[0].1 =
        VoteContent::new(round(), None, true, endorsement([3, 3, 3], &[2], 0)).unwrap();
    assert_eq!(
        VoteTally::from_contents(leader(), wrong_leader, config()).unwrap_err(),
        Error::Transcript
    );

    let mut non_final = finals();
    non_final[2].1 = VoteContent::new(
        round(),
        Some(leader()),
        false,
        endorsement([3, 3, 3], &[], 0),
    )
    .unwrap();
    assert_eq!(
        FinalTally::from_contents(non_final, Vec::new(), config()).unwrap_err(),
        Error::Transcript
    );

    let mut short = votes();
    short.pop();
    assert_eq!(
        VoteTally::from_contents(leader(), short, config()).unwrap_err(),
        Error::Quorum
    );

    let mut duplicate = votes();
    duplicate[1].0 = Participant::new(1);
    assert_eq!(
        VoteTally::from_contents(leader(), duplicate, config()).unwrap_err(),
        Error::Participants
    );

    let mut other_round = votes();
    other_round[3].1 = VoteContent::new(
        Round::new(Epoch::new(1), View::new(5)),
        Some(leader()),
        true,
        endorsement([3, 3, 3], &[2], 0),
    )
    .unwrap();
    assert_eq!(
        VoteTally::from_contents(leader(), other_round, config()).unwrap_err(),
        Error::Context
    );
}

/// Encodes a mutated vote tally and returns whether decoding rejects it.
fn rejects(mutate: impl FnOnce(&mut Core<D>)) -> bool {
    let mut tally = VoteTally::from_contents(leader(), votes(), config()).unwrap();
    mutate(&mut tally.0);
    VoteTally::<D>::decode_cfg(tally.encode(), &config()).is_err()
}

#[test]
fn decoding_rejects_non_canonical_vote_tallies() {
    // A reference signer other than the lowest holder of the most common entry.
    assert!(rejects(|core| core.reference_signer = Participant::new(4)));
    // A reference signer that did not sign.
    assert!(rejects(|core| core.reference_signer = Participant::new(0)));
    // Unsorted deviations.
    assert!(rejects(|core| core.deviations.reverse()));
    // A deviation for the reference signer.
    assert!(rejects(
        |core| core.deviations[0].signer = Participant::new(1)
    ));
    // A deviation that changes nothing.
    assert!(rejects(|core| {
        let deviation = &mut core.deviations[0];
        deviation.flip_final = false;
        deviation.declared = None;
        deviation.tips.clear();
    }));
    // A deviation tip equal to the reference tip.
    assert!(rejects(|core| {
        let reference = core.reference.endorsement.tips()[0];
        core.deviations[0].tips = vec![reference];
    }));
    // Deviation tips out of chain order.
    assert!(rejects(|core| {
        core.deviations[1].tips = vec![tip(2, 9, 1), tip(1, 9, 1)];
    }));
    // An empty declared difference.
    assert!(rejects(
        |core| core.deviations[0].declared = Some(ChainSet::empty(3))
    ));
    // A leader replacement, which votes for one leader block cannot carry.
    assert!(rejects(|core| core.deviations[0].leader = Some(None)));
    // A signer count other than n - f.
    assert!(rejects(|core| {
        core.signers = Signers::new(6, (0..6).map(Participant::new)).unwrap();
    }));
}

/// Rewrites the deviations of the canonical vote tally so that the signers in \`shared\` carry one
/// body and those in \`other\` another, sets the reference signer, and returns whether decoding
/// accepts the result.
fn accepts_deviations(reference: u32, shared: &[u32], other: &[u32]) -> bool {
    !rejects(|core| {
        let (other_body, shared_body) = (core.deviations[0].clone(), core.deviations[1].clone());
        core.reference_signer = Participant::new(reference);
        let with_signer = |body: &Deviation<D>, signer: &u32| Deviation {
            signer: Participant::new(*signer),
            ..body.clone()
        };
        core.deviations = shared
            .iter()
            .map(|signer| with_signer(&shared_body, signer))
            .chain(other.iter().map(|signer| with_signer(&other_body, signer)))
            .collect();
        core.deviations.sort_by_key(|deviation| deviation.signer);
    })
}

#[test]
fn decoding_checks_the_reference_against_groups_of_equal_deviations() {
    // Signers 1 to 5 signed. A group smaller than the reference holders, or tied with them from a
    // higher signer.
    assert!(accepts_deviations(1, &[2, 3], &[]));
    assert!(accepts_deviations(1, &[4, 5], &[3]));
    // A group that outnumbers the reference holders.
    assert!(!accepts_deviations(1, &[2, 3, 4], &[]));
    // A group tied with the reference holders whose lowest signer is lower.
    assert!(!accepts_deviations(3, &[1, 2], &[5]));
    // A reference signer other than the lowest signer without a deviation.
    assert!(!accepts_deviations(4, &[2, 3], &[]));
}

#[test]
fn decoding_rejects_non_canonical_final_tallies() {
    let base = FinalTally::from_contents(finals(), paths(), config()).unwrap();

    let mut flipped = base.clone();
    flipped.core.deviations[0].flip_final = true;
    assert!(FinalTally::<D>::decode_cfg(flipped.encode(), &config()).is_err());

    let mut same_leader = base.clone();
    let reference_leader = same_leader.core.reference.leader;
    same_leader.core.deviations[0].leader = Some(reference_leader);
    assert!(FinalTally::<D>::decode_cfg(same_leader.encode(), &config()).is_err());

    let mut unsorted = base.clone();
    unsorted.paths.reverse();
    assert!(FinalTally::<D>::decode_cfg(unsorted.encode(), &config()).is_err());

    let mut duplicate = base;
    duplicate.paths.push(duplicate.paths[1].clone());
    assert!(FinalTally::<D>::decode_cfg(duplicate.encode(), &config()).is_err());
}

#[test]
fn deviation_flags_are_bounded() {
    let tally = VoteTally::from_contents(leader(), votes(), config()).unwrap();
    let mut encoded = tally.encode().to_vec();
    // Locate the first deviation's flag byte: it follows its signer index.
    let core = &tally.0;
    let prefix = core.signers.encode_size()
        + core.reference_signer.encode_size()
        + 1
        + core.reference.endorsement.encode_size()
        + 1
        + core.deviations[0].signer.encode_size();
    encoded[prefix] |= 1 << 7;
    assert!(VoteTally::<D>::decode_cfg(encoded, &config()).is_err());
}

#[test]
fn resolution_paths_are_bounded() {
    let config = config();
    assert_eq!(
        ResolutionPath::new(tip(0, 1, 0), Vec::new(), config).unwrap_err(),
        Error::Window
    );
    let lead = config.window().max_tip_lead() as usize;
    assert!(ResolutionPath::new(tip(0, 1, 0), vec![leader(); lead], config).is_ok());
    assert_eq!(
        ResolutionPath::new(tip(0, 1, 0), vec![leader(); lead + 1], config).unwrap_err(),
        Error::Window
    );
    assert_eq!(
        ResolutionPath::new(tip(3, 1, 0), vec![leader()], config).unwrap_err(),
        Error::Chain
    );
    assert_eq!(
        ResolutionPath::new(tip(0, u64::MAX, 0), vec![leader()], config).unwrap_err(),
        Error::HeightOverflow
    );
}
