//! Differential campaigns over complete attributed vote histories.

use super::{FinalTips, PoolExtractor, VqcExtraction, reference::ReferenceOrdering};
use crate::{
    multimmit::{
        config::{CodecConfig, Limits},
        types::{
            Anchor, BlockRef, CertificateId, ChainId, ChainProposal, Extension, LeaderBlock,
            Position, VoteBody,
        },
    },
    types::{Epoch, Height, Participant, Round, View},
};
use commonware_cryptography::{
    Hasher, Sha256, bls12381::primitives::variant::MinSig, sha256::Digest,
};

/// Checks extraction after every sticky insertion against materialized ancestry and vote counts.
pub(crate) fn exercise(input: &[u8]) {
    let mut bytes = input.iter().copied().cycle();
    let mut next = || bytes.next().unwrap_or(0) as usize;
    let participants = [6, 7, 11, 12][next() % 4];
    let chains = 2 + next() % 5;
    let depth = 1 + next() % 6;
    let config =
        CodecConfig::new(participants, chains, Limits::new(depth as u32, 6).unwrap()).unwrap();
    let faults = (participants - 1) / 5;
    let mut anchors = (0..chains)
        .map(|chain| {
            BlockRef::new(
                ChainId::new(chain as u32),
                Height::new(next() as u64),
                Sha256::hash(&[b"algebra anchor", &(chain as u32).to_be_bytes()]),
            )
        })
        .collect::<Vec<_>>();
    for view in 1..=2 + next() % 6 {
        let proposals = anchors
            .iter()
            .map(|anchor| {
                let count = next() % (depth + 1);
                let payloads = (0..count)
                    .map(|offset| {
                        Sha256::hash(&[
                            b"algebra proposal",
                            anchor.digest().as_ref(),
                            &(view as u64).to_be_bytes(),
                            &(offset as u32).to_be_bytes(),
                        ])
                    })
                    .collect();
                ChainProposal::new(
                    anchor.chain(),
                    Anchor::Tip(*anchor),
                    payloads,
                    config.pipeline_depth(),
                )
                .unwrap()
            })
            .collect();
        let leader = LeaderBlock::<MinSig, Digest>::new(
            Round::new(Epoch::new(7), View::new(view as u64)),
            CertificateId::new(Sha256::hash(&[b"parent"])),
            Sha256::hash(&[b"history"]),
            proposals,
            config,
        )
        .unwrap();
        let mut reference = ReferenceOrdering::new(&leader, &anchors);
        // Shared templates create support thresholds; independent templates create competing branches.
        let templates = (0..4)
            .map(|_| {
                let mut positions = Vec::new();
                let mut extensions = Vec::new();
                for (chain, proposal) in leader.proposals().iter().enumerate() {
                    let position = next() % (proposal.payloads().len() + 1);
                    positions.push(Position::new(position as u32));
                    let mut parent = reference.proposals[chain][position];
                    let payloads = (0..next() % 7)
                        .map(|offset| {
                            let choice = next() % 4;
                            let payload =
                                if choice == 0 && position + offset < proposal.payloads().len() {
                                    proposal.payloads()[position + offset]
                                } else {
                                    Sha256::hash(&[
                                        b"algebra extension",
                                        parent.digest().as_ref(),
                                        &(choice as u32).to_be_bytes(),
                                        &(offset as u32).to_be_bytes(),
                                    ])
                                };
                            parent = ReferenceOrdering::child(&leader, parent, payload);
                            payload
                        })
                        .collect();
                    extensions.push(Extension::new(payloads, config.extension_bound()).unwrap());
                }
                VoteBody::for_leader::<Sha256, MinSig>(&leader, positions, extensions, config)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let mut signers = (0..participants).collect::<Vec<_>>();
        for end in (1..participants).rev() {
            signers.swap(end, next() % (end + 1));
        }
        let mut retained = Vec::new();
        let mut pool = PoolExtractor::new::<Sha256, MinSig>(&leader, config).unwrap();
        for signer in signers {
            let signer = Participant::new(signer as u32);
            let choice = next();
            let body = templates[if choice % 4 == 0 {
                (choice / 4) % templates.len()
            } else {
                0
            }]
            .clone();
            assert!(
                pool.insert::<Sha256, MinSig>(&leader, signer, &body)
                    .unwrap()
            );
            retained.push((signer, body));
            assert_eq!(pool.len(), retained.len());
            let before = pool.final_tips();
            assert!(
                !pool
                    .insert::<Sha256, MinSig>(&leader, signer, &templates[next() % templates.len()])
                    .unwrap()
            );
            assert_eq!(pool.final_tips(), before);
            let materialized = reference.materialize(&leader, &retained);
            assert!(
                materialized
                    .iter()
                    .zip(&retained)
                    .all(|(vote, (signer, _))| vote.signer == *signer)
            );
            if retained.len() > 2 * faults {
                let (actual, _) = VqcExtraction::from_votes::<Sha256, MinSig>(
                    &leader,
                    leader.digest::<Sha256>(),
                    retained.iter().map(|(signer, body)| (*signer, body)),
                    config,
                )
                .unwrap()
                .into_parts();
                assert_eq!(actual.blocks(), reference.safe(&materialized, config));
            }
            if retained.len() < participants - faults {
                assert!(pool.final_tips().is_err());
                continue;
            }
            let expected = reference.final_tips(&materialized, config);
            let incremental = pool.final_tips().unwrap();
            let batch = FinalTips::from_pool::<Sha256, MinSig, _>(
                &leader,
                retained.iter().rev().map(|(signer, body)| (*signer, body)),
                config,
            )
            .unwrap();
            assert_eq!(incremental, batch);
            assert_eq!(incremental.blocks(), expected.blocks);
            for chain in 0..chains {
                let id = ChainId::new(chain as u32);
                assert_eq!(incremental.position(id), Some(expected.positions[chain]));
                assert_eq!(incremental.settled(id), Some(expected.settled[chain]));
            }
        }
        anchors = pool.final_tips().unwrap().blocks().to_vec();
    }
}

#[cfg(test)]
mod tests {
    use super::exercise;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]
        #[test]
        fn attributed_histories_match_reference(input in proptest::collection::vec(any::<u8>(), 0..1024)) {
            exercise(&input);
        }
    }
}
