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


/// Builds a Proposal for the given view, parent, and block digest.
fn make_proposal(epoch: u64, view: u64, parent: u64, block: &str) -> Proposal<Sha256Digest> {
    let round = Round::new(Epoch::new(epoch), View::new(view));
    let payload = digest_from_hex(block);
    Proposal::new(round, View::new(parent), payload)
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
) -> ConstructedMessage {
    let receiver_idx = parse_node_id(receiver);
    let signer_idx = match vote {
        TracedVote::Notarize { sig, .. }
        | TracedVote::Nullify { sig, .. }
        | TracedVote::Finalize { sig, .. } => parse_node_id(sig),
    };
    let scheme = &schemes[signer_idx];

    let encoded: IoBuf = match vote {
        TracedVote::Notarize {
            view, parent, block, ..
        } => {
            let proposal = make_proposal(epoch, *view, *parent, block);
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
        TracedVote::Finalize {
            view, parent, block, ..
        } => {
            let proposal = make_proposal(epoch, *view, *parent, block);
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
) -> ConstructedMessage {
    let receiver_idx = parse_node_id(receiver);
    let strategy = Sequential;

    let (sender_id, encoded): (&str, IoBuf) = match cert {
        TracedCert::Notarization {
            view,
            parent,
            block,
            signers,
            ghost_sender,
        } => {
            let proposal = make_proposal(epoch, *view, *parent, block);
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
            parent,
            block,
            signers,
            ghost_sender,
        } => {
            let proposal = make_proposal(epoch, *view, *parent, block);
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
) -> ConstructedMessage {
    match entry {
        TraceEntry::Vote {
            sender,
            receiver,
            vote,
        } => construct_vote(receiver, sender, vote, schemes, participants, epoch),
        TraceEntry::Certificate { receiver, cert, .. } => {
            let mut msg = construct_certificate(receiver, cert, schemes, participants, epoch);
            msg.is_certificate = true;
            msg
        }
    }
}

