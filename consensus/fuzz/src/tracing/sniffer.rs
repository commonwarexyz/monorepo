//! Network sniffer that intercepts simplex consensus messages and logs them
//! in quint spec format matching `types.qnt`.
//!
//! Provides [`SniffingReceiver`], a wrapper around any [`Receiver`] that
//! transparently decodes vote and certificate messages, formats them using
//! the quint constructors (`notarize`, `nullify`, `finalize`, `notarization`,
//! `nullification`, `finalization`), and appends them to a shared [`TraceLog`].

use commonware_codec::{Decode, DecodeExt};
use commonware_consensus::simplex::types::{Attributable, Certificate, Vote};
use commonware_cryptography::{ed25519::PublicKey, sha256::Digest as Sha256Digest};
use commonware_p2p::{Message, Receiver};
use commonware_utils::{sync::Mutex, Participant};
use serde::{Deserialize, Serialize};
use std::{fmt, sync::Arc};

/// The ed25519 simplex scheme used in tests.
type S = commonware_consensus::simplex::scheme::ed25519::Scheme;
type Ed25519Vote = Vote<S, Sha256Digest>;
type Ed25519Certificate = Certificate<S, Sha256Digest>;

/// Identifies which network channel a receiver is sniffing.
pub enum ChannelKind {
    Vote,
    Certificate,
}

/// Structured representation of a traced vote.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TracedVote {
    Notarize {
        view: u64,
        parent: u64,
        sig: String,
        block: String,
    },
    Nullify {
        view: u64,
        sig: String,
    },
    Finalize {
        view: u64,
        parent: u64,
        sig: String,
        block: String,
    },
}

/// Structured representation of a traced certificate.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TracedCert {
    Notarization {
        view: u64,
        parent: u64,
        block: String,
        signers: Vec<String>,
        ghost_sender: String,
    },
    Nullification {
        view: u64,
        signers: Vec<String>,
        ghost_sender: String,
    },
    Finalization {
        view: u64,
        parent: u64,
        block: String,
        signers: Vec<String>,
        ghost_sender: String,
    },
}

/// A structured trace entry capturing sender, receiver, and message.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TraceEntry {
    Vote {
        sender: String,
        receiver: String,
        vote: TracedVote,
    },
    Certificate {
        sender: String,
        receiver: String,
        cert: TracedCert,
    },
}

impl TraceEntry {
    pub fn view(&self) -> u64 {
        match self {
            TraceEntry::Vote { vote, .. } => match vote {
                TracedVote::Notarize { view, .. }
                | TracedVote::Nullify { view, .. }
                | TracedVote::Finalize { view, .. } => *view,
            },
            TraceEntry::Certificate { cert, .. } => match cert {
                TracedCert::Notarization { view, .. }
                | TracedCert::Nullification { view, .. }
                | TracedCert::Finalization { view, .. } => *view,
            },
        }
    }
}

/// Accumulates structured trace entries.
#[derive(Default)]
pub struct TraceLog {
    pub structured: Vec<TraceEntry>,
}

/// Maps a [`Participant`] index to a quint replica ID (e.g. `"n0"`).
fn participant_id(idx: Participant) -> String {
    format!("n{}", idx.get())
}

/// Maps a public key to a quint replica ID by looking up its position
/// in the sorted participant list.
fn pk_to_id(pk: &PublicKey, participants: &[PublicKey]) -> String {
    for (i, p) in participants.iter().enumerate() {
        if p == pk {
            return format!("n{}", i);
        }
    }
    "unknown".to_string()
}

/// Formats a SHA256 digest as a full hex string for use as a quint `Block`.
/// The full 32 bytes are kept so the encoder can recompute certifiability
/// from the last byte (matching `Certifier::Sometimes` logic).
fn format_block(digest: &Sha256Digest) -> String {
    let bytes: &[u8] = digest.as_ref();
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Extracts a structured [`TracedVote`] from a decoded vote.
fn extract_vote(vote: &Ed25519Vote) -> TracedVote {
    match vote {
        Vote::Notarize(n) => TracedVote::Notarize {
            view: n.proposal.round.view().get(),
            parent: n.proposal.parent.get(),
            sig: participant_id(n.signer()),
            block: format_block(&n.proposal.payload),
        },
        Vote::Nullify(n) => TracedVote::Nullify {
            view: n.round.view().get(),
            sig: participant_id(n.signer()),
        },
        Vote::Finalize(f) => TracedVote::Finalize {
            view: f.proposal.round.view().get(),
            parent: f.proposal.parent.get(),
            sig: participant_id(f.signer()),
            block: format_block(&f.proposal.payload),
        },
    }
}

/// Extracts a structured [`TracedCert`] from a decoded certificate.
fn extract_cert(cert: &Ed25519Certificate, sender_id: &str) -> TracedCert {
    match cert {
        Certificate::Notarization(n) => TracedCert::Notarization {
            view: n.proposal.round.view().get(),
            parent: n.proposal.parent.get(),
            block: format_block(&n.proposal.payload),
            signers: n.certificate.signers.iter().map(participant_id).collect(),
            ghost_sender: sender_id.to_string(),
        },
        Certificate::Nullification(n) => TracedCert::Nullification {
            view: n.round.view().get(),
            signers: n.certificate.signers.iter().map(participant_id).collect(),
            ghost_sender: sender_id.to_string(),
        },
        Certificate::Finalization(f) => TracedCert::Finalization {
            view: f.proposal.round.view().get(),
            parent: f.proposal.parent.get(),
            block: format_block(&f.proposal.payload),
            signers: f.certificate.signers.iter().map(participant_id).collect(),
            ghost_sender: sender_id.to_string(),
        },
    }
}

/// A receiver wrapper that intercepts consensus messages and logs them
/// in quint spec format before forwarding to the inner receiver.
pub struct SniffingReceiver<R> {
    inner: R,
    channel: ChannelKind,
    node_id: String,
    participants: Vec<PublicKey>,
    cert_codec_cfg: usize,
    trace: Arc<Mutex<TraceLog>>,
}

impl<R> SniffingReceiver<R> {
    pub fn new(
        inner: R,
        channel: ChannelKind,
        node_id: String,
        participants: Vec<PublicKey>,
        trace: Arc<Mutex<TraceLog>>,
    ) -> Self {
        let cert_codec_cfg = participants.len();
        Self {
            inner,
            channel,
            node_id,
            participants,
            cert_codec_cfg,
            trace,
        }
    }
}

impl<R> fmt::Debug for SniffingReceiver<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SniffingReceiver")
            .field("node_id", &self.node_id)
            .finish()
    }
}

impl<R> Receiver for SniffingReceiver<R>
where
    R: Receiver<PublicKey = PublicKey>,
    R::Error: Send + Sync,
{
    type Error = R::Error;
    type PublicKey = PublicKey;

    async fn recv(&mut self) -> Result<Message<Self::PublicKey>, Self::Error> {
        let (sender_pk, payload) = self.inner.recv().await?;
        let sender_id = pk_to_id(&sender_pk, &self.participants);

        match self.channel {
            ChannelKind::Vote => {
                if let Ok(vote) = Ed25519Vote::decode(payload.clone()) {
                    let structured = TraceEntry::Vote {
                        sender: sender_id.clone(),
                        receiver: self.node_id.clone(),
                        vote: extract_vote(&vote),
                    };
                    self.trace.lock().structured.push(structured);
                }
            }
            ChannelKind::Certificate => {
                if let Ok(cert) =
                    Ed25519Certificate::decode_cfg(payload.clone(), &self.cert_codec_cfg)
                {
                    let structured = TraceEntry::Certificate {
                        sender: sender_id.clone(),
                        receiver: self.node_id.clone(),
                        cert: extract_cert(&cert, &sender_id),
                    };
                    self.trace.lock().structured.push(structured);
                }
            }
        }

        Ok((sender_pk, payload))
    }
}
