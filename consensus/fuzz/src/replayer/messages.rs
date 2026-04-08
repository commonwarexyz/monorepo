use crate::tracing::sniffer::{TraceEntry, TracedCert, TracedVote};
use commonware_codec::Encode;
use commonware_consensus::{
    simplex::types::{
        Certificate, Finalization, Finalize, Notarization, Notarize, Nullification, Nullify,
        Proposal, Vote,
    },
    types::{Epoch, Round, View},
};
use commonware_cryptography::{ed25519::PublicKey, sha256::Digest as Sha256Digest};
use commonware_parallel::Sequential;
use commonware_runtime::IoBuf;
use std::collections::HashMap;

type S = commonware_consensus::simplex::scheme::ed25519::Scheme;

/// Reconstructs a full Sha256Digest from a hex-encoded prefix (first 8 bytes).
fn digest_from_hex(hex: &str) -> Sha256Digest {
    let mut bytes = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        if i >= 32 {
            break;
        }
        let s = std::str::from_utf8(chunk).unwrap_or("00");
        bytes[i] = u8::from_str_radix(s, 16).unwrap_or(0);
    }
    Sha256Digest(bytes)
}

/// Parses a node ID like "n0" into a usize index.
fn parse_node_id(id: &str) -> usize {
    id.strip_prefix('n')
        .and_then(|s| s.parse().ok())
        .expect("invalid node id")
}

pub type ProposalParents = HashMap<(u64, String), View>;

/// Returns true if the block hash is certifiable, matching the tracing encoder.
fn is_certifiable(block_hash: &str) -> bool {
    if block_hash.len() >= 2 {
        let last_two = &block_hash[block_hash.len() - 2..];
        let last_byte = u8::from_str_radix(last_two, 16).unwrap_or(0);
        (last_byte % 11) < 9
    } else {
        true
    }
}

/// Builds a Proposal for the given view and block digest.
fn make_proposal(
    epoch: u64,
    view: u64,
    block: &str,
    parents: &ProposalParents,
) -> Proposal<Sha256Digest> {
    let round = Round::new(Epoch::new(epoch), View::new(view));
    let parent = parents
        .get(&(view, block.to_string()))
        .copied()
        .unwrap_or_else(|| {
            if view <= 1 {
                View::zero()
            } else {
                View::new(view - 1)
            }
        });
    let payload = digest_from_hex(block);
    Proposal::new(round, parent, payload)
}

/// Tracks parent views for concrete proposals keyed by (view, block).
#[derive(Default)]
pub struct ParentTracker {
    parents: ProposalParents,
    last_parent_view: u64,
    current_view: Option<u64>,
    current_view_certified: bool,
}

impl ParentTracker {
    pub fn parents(&self) -> &ProposalParents {
        &self.parents
    }

    /// Observes a traced entry and records any proposal parent it implies.
    pub fn observe_entry(&mut self, entry: &TraceEntry) {
        match entry {
            TraceEntry::Vote {
                vote:
                    TracedVote::Notarize { view, block, .. } | TracedVote::Finalize { view, block, .. },
                ..
            }
            | TraceEntry::Certificate {
                cert:
                    TracedCert::Notarization { view, block, .. }
                    | TracedCert::Finalization { view, block, .. },
                ..
            } => {
                self.advance_to_view(*view);
                self.set_parent(*view, block);
                if let TraceEntry::Certificate { cert, .. } = entry {
                    if matches!(
                        cert,
                        TracedCert::Notarization { .. } | TracedCert::Finalization { .. }
                    ) && is_certifiable(block)
                    {
                        self.current_view_certified = true;
                    }
                }
            }
            _ => {}
        }
    }

    fn advance_to_view(&mut self, view: u64) {
        match self.current_view {
            Some(current) if view > current => {
                if self.current_view_certified && current > self.last_parent_view {
                    self.last_parent_view = current;
                }
                self.current_view = Some(view);
                self.current_view_certified = false;
            }
            None => {
                self.current_view = Some(view);
                self.current_view_certified = false;
            }
            _ => {}
        }
    }

    fn set_parent(&mut self, view: u64, block: &str) {
        let key = (view, block.to_string());
        if let std::collections::hash_map::Entry::Vacant(entry) = self.parents.entry(key) {
            let parent = if self.last_parent_view > 0 {
                View::new(self.last_parent_view)
            } else if view <= 1 {
                View::zero()
            } else {
                View::new(view - 1)
            };
            entry.insert(parent);
        }
    }
}

/// Builds the same proposal-parent approximation used by the tracing encoder.
pub fn build_proposal_parents(entries: &[TraceEntry]) -> ProposalParents {
    let mut tracker = ParentTracker::default();
    let mut sorted_entries = entries.to_vec();
    sorted_entries.sort_by_key(|entry| entry.view());
    for entry in &sorted_entries {
        tracker.observe_entry(entry);
    }
    tracker.parents
}

/// Result of constructing a message from a trace entry.
pub struct ConstructedMessage {
    /// The target node that should receive this message.
    pub receiver_idx: usize,
    /// The sender public key to use in the injected message.
    pub sender_pk: PublicKey,
    /// The encoded message bytes.
    pub payload: IoBuf,
    /// Whether this is a vote or certificate (determines which channel).
    pub is_certificate: bool,
}

/// Constructs a signed vote message from a TracedVote.
pub fn construct_vote(
    receiver: &str,
    sender: &str,
    vote: &TracedVote,
    schemes: &[S],
    participants: &[PublicKey],
    epoch: u64,
    parents: &ProposalParents,
) -> ConstructedMessage {
    let receiver_idx = parse_node_id(receiver);
    let signer_idx = match vote {
        TracedVote::Notarize { sig, .. }
        | TracedVote::Nullify { sig, .. }
        | TracedVote::Finalize { sig, .. } => parse_node_id(sig),
    };
    let scheme = &schemes[signer_idx];

    let encoded: IoBuf = match vote {
        TracedVote::Notarize { view, block, .. } => {
            let proposal = make_proposal(epoch, *view, block, parents);
            let notarize =
                Notarize::<S, Sha256Digest>::sign(scheme, proposal).expect("signing must succeed");
            Vote::Notarize(notarize).encode().into()
        }
        TracedVote::Nullify { view, .. } => {
            let round = Round::new(Epoch::new(epoch), View::new(*view));
            let nullify =
                Nullify::<S>::sign::<Sha256Digest>(scheme, round).expect("signing must succeed");
            Vote::<S, Sha256Digest>::Nullify(nullify).encode().into()
        }
        TracedVote::Finalize { view, block, .. } => {
            let proposal = make_proposal(epoch, *view, block, parents);
            let finalize =
                Finalize::<S, Sha256Digest>::sign(scheme, proposal).expect("signing must succeed");
            Vote::Finalize(finalize).encode().into()
        }
    };

    let sender_idx = parse_node_id(sender);
    ConstructedMessage {
        receiver_idx,
        sender_pk: participants[sender_idx].clone(),
        payload: encoded,
        is_certificate: false,
    }
}

/// Constructs a signed certificate message from a TracedCert.
pub fn construct_certificate(
    receiver: &str,
    cert: &TracedCert,
    schemes: &[S],
    participants: &[PublicKey],
    epoch: u64,
    parents: &ProposalParents,
) -> ConstructedMessage {
    let receiver_idx = parse_node_id(receiver);
    let strategy = Sequential;

    let (sender_id, encoded): (&str, IoBuf) = match cert {
        TracedCert::Notarization {
            view,
            block,
            signers,
            ghost_sender,
        } => {
            let proposal = make_proposal(epoch, *view, block, parents);
            let notarizes: Vec<_> = signers
                .iter()
                .map(|s| {
                    let idx = parse_node_id(s);
                    Notarize::<S, Sha256Digest>::sign(&schemes[idx], proposal.clone())
                        .expect("signing must succeed")
                })
                .collect();
            let notarization =
                Notarization::from_notarizes(&schemes[0], notarizes.iter(), &strategy)
                    .expect("certificate assembly must succeed");
            (
                ghost_sender.as_str(),
                Certificate::Notarization(notarization).encode().into(),
            )
        }
        TracedCert::Nullification {
            view,
            signers,
            ghost_sender,
        } => {
            let round = Round::new(Epoch::new(epoch), View::new(*view));
            let nullifies: Vec<_> = signers
                .iter()
                .map(|s| {
                    let idx = parse_node_id(s);
                    Nullify::<S>::sign::<Sha256Digest>(&schemes[idx], round)
                        .expect("signing must succeed")
                })
                .collect();
            let nullification =
                Nullification::from_nullifies(&schemes[0], nullifies.iter(), &strategy)
                    .expect("certificate assembly must succeed");
            (
                ghost_sender.as_str(),
                Certificate::<S, Sha256Digest>::Nullification(nullification)
                    .encode()
                    .into(),
            )
        }
        TracedCert::Finalization {
            view,
            block,
            signers,
            ghost_sender,
        } => {
            let proposal = make_proposal(epoch, *view, block, parents);
            let finalizes: Vec<_> = signers
                .iter()
                .map(|s| {
                    let idx = parse_node_id(s);
                    Finalize::<S, Sha256Digest>::sign(&schemes[idx], proposal.clone())
                        .expect("signing must succeed")
                })
                .collect();
            let finalization =
                Finalization::from_finalizes(&schemes[0], finalizes.iter(), &strategy)
                    .expect("certificate assembly must succeed");
            (
                ghost_sender.as_str(),
                Certificate::Finalization(finalization).encode().into(),
            )
        }
    };

    let sender_idx = parse_node_id(sender_id);
    ConstructedMessage {
        receiver_idx,
        sender_pk: participants[sender_idx].clone(),
        payload: encoded,
        is_certificate: false, // Will be set by caller based on channel routing
    }
}

/// Constructs a message from a TraceEntry, returning the target and payload.
pub fn construct_message(
    entry: &TraceEntry,
    schemes: &[S],
    participants: &[PublicKey],
    epoch: u64,
    parents: &ProposalParents,
) -> ConstructedMessage {
    match entry {
        TraceEntry::Vote {
            sender,
            receiver,
            vote,
        } => construct_vote(
            receiver,
            sender,
            vote,
            schemes,
            participants,
            epoch,
            parents,
        ),
        TraceEntry::Certificate { receiver, cert, .. } => {
            let mut msg =
                construct_certificate(receiver, cert, schemes, participants, epoch, parents);
            msg.is_certificate = true;
            msg
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_view_certifiable_entry_does_not_reparent_same_view_proposals() {
        let entries = vec![
            TraceEntry::Vote {
                sender: "n1".into(),
                receiver: "n2".into(),
                vote: TracedVote::Notarize {
                    view: 1,
                    sig: "n1".into(),
                    block: "aa".into(),
                },
            },
            TraceEntry::Certificate {
                sender: "n1".into(),
                receiver: "n2".into(),
                cert: TracedCert::Notarization {
                    view: 1,
                    block: "aa".into(),
                    signers: vec!["n1".into(), "n2".into(), "n3".into()],
                    ghost_sender: "n1".into(),
                },
            },
            TraceEntry::Vote {
                sender: "n1".into(),
                receiver: "n3".into(),
                vote: TracedVote::Notarize {
                    view: 1,
                    sig: "n1".into(),
                    block: "bb".into(),
                },
            },
            TraceEntry::Vote {
                sender: "n2".into(),
                receiver: "n3".into(),
                vote: TracedVote::Notarize {
                    view: 2,
                    sig: "n2".into(),
                    block: "cc".into(),
                },
            },
        ];

        let parents = build_proposal_parents(&entries);

        assert_eq!(parents.get(&(1, "aa".to_string())), Some(&View::zero()));
        assert_eq!(parents.get(&(1, "bb".to_string())), Some(&View::zero()));
        assert_eq!(parents.get(&(2, "cc".to_string())), Some(&View::new(1)));
    }
}
