//! Typed replay trace format.
//!
//! MBF Iteration 1 is bound to ed25519 + sha256. Signed payloads
//! ([`Vote`], [`Certificate`], [`Proposal`]) round-trip verbatim as hex
//! of the canonical [`commonware_codec`] encoding; participants are
//! [`Participant`] indices and digests are full hex (no aliasing).
//!
//! The on-disk JSON form is handled via an internal [`raw`] module so
//! that decoding a [`Certificate`] — which needs the participant count
//! at decode time — can use [`Topology::n`] from the already-decoded
//! header. Callers should use [`Trace::from_json`] / [`Trace::to_json`];
//! [`Trace`] itself holds fully typed values.

use crate::{
    simplex::{
        metrics::TimeoutReason,
        scheme::ed25519,
        types::{Certificate, Proposal, Vote},
    },
    types::View,
};
use bytes::BytesMut;
use commonware_codec::{Decode, DecodeExt, Encode, Error as CodecError};
use commonware_cryptography::sha256::Digest as Sha256Digest;
use commonware_utils::Participant;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

// Iteration 1 is bound to ed25519 + sha256. When we generalize, these
// aliases become generic parameters on `Trace`.
type Scheme = ed25519::Scheme;
type Digest = Sha256Digest;

// --- Public typed API ---

/// A complete recorded replay session.
#[derive(Clone, Debug)]
pub struct Trace {
    pub topology: Topology,
    pub events: Vec<Event>,
    pub expected: Snapshot,
}

/// A single ingress event to the consensus engine cluster.
///
/// Four variants, matching the semantic entry points:
///
/// - [`Event::Deliver`]: a signed vote or certificate arrives at `to`
///   from `from` over the network.
/// - [`Event::Propose`]: the `leader`'s automaton completes its proposal
///   build for `proposal`. Wakes the parked oneshot inside the
///   [`ReplayAutomaton`](super::ReplayAutomaton).
/// - [`Event::Construct`]: `node` locally built `vote` (used for self-
///   loops that the engine's own broadcast path cannot observe because
///   the replay driver uses a null sender).
/// - [`Event::Timeout`]: `node` should advance its timeout for `view`
///   with the given reason.
#[derive(Clone, Debug)]
pub enum Event {
    Deliver {
        to: Participant,
        from: Participant,
        msg: Wire,
    },
    Propose {
        leader: Participant,
        proposal: Proposal<Digest>,
    },
    Construct {
        node: Participant,
        vote: Vote<Scheme, Digest>,
    },
    Timeout {
        node: Participant,
        view: View,
        reason: TimeoutReason,
    },
}

/// Network-wire payload carried by [`Event::Deliver`].
#[derive(Clone, Debug)]
pub enum Wire {
    Vote(Vote<Scheme, Digest>),
    Cert(Certificate<Scheme, Digest>),
}

/// Deterministic cluster topology needed to rehydrate keys and configure engines.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Topology {
    /// Number of participants.
    pub n: u32,
    /// Number of Byzantine participants. The first `faults` nodes
    /// (indices `0..faults`) are treated as Byzantine by the harness:
    /// the replayer does not instantiate an engine for them, so their
    /// state is not observed.
    pub faults: u32,
    /// Consensus epoch.
    pub epoch: u64,
    /// Namespace used when deriving the ed25519 fixture. Must match the
    /// namespace the trace was recorded with — otherwise public keys
    /// will not line up with signer indices in `Vote`/`Certificate`.
    #[serde(with = "serde_bytes_hex")]
    pub namespace: Vec<u8>,
    /// Voter timing knobs. Kept in the trace so fixtures are self-
    /// contained across future config changes.
    pub timing: Timing,
}

/// Timing configuration captured in the trace so replay is self-contained.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Timing {
    pub leader_timeout_ms: u64,
    pub certification_timeout_ms: u64,
    pub timeout_retry_ms: u64,
    pub fetch_timeout_ms: u64,
    pub activity_timeout: u64,
    pub skip_timeout: u64,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            leader_timeout_ms: 5_000,
            certification_timeout_ms: 10_000,
            timeout_retry_ms: 30_000,
            fetch_timeout_ms: 5_000,
            activity_timeout: 100,
            skip_timeout: 50,
        }
    }
}

/// Final observable state per non-Byzantine node.
///
/// Byzantine nodes (indices `0..topology.faults`) are not represented —
/// the replayer never instantiates them, so there is no observable
/// state to compare.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub nodes: BTreeMap<Participant, NodeSnapshot>,
}

/// Observable state for a single correct node.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodeSnapshot {
    pub notarizations: BTreeMap<View, CertStateSnapshot>,
    pub nullifications: BTreeMap<View, NullStateSnapshot>,
    pub finalizations: BTreeMap<View, CertStateSnapshot>,
    pub certified: BTreeSet<View>,
    pub notarize_signers: BTreeMap<View, BTreeSet<Participant>>,
    pub nullify_signers: BTreeMap<View, BTreeSet<Participant>>,
    pub finalize_signers: BTreeMap<View, BTreeSet<Participant>>,
    pub last_finalized: View,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertStateSnapshot {
    pub payload: Digest,
    /// `None` for threshold schemes that don't expose signer counts.
    pub signature_count: Option<u32>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NullStateSnapshot {
    pub signature_count: Option<u32>,
}

// --- Errors ---

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid hex: {0}")]
    Hex(String),
    #[error("invalid digest length: expected {expected}, got {got}")]
    DigestLength { expected: usize, got: usize },
    #[error("codec decode: {0}")]
    Codec(#[from] CodecError),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

// --- JSON load/save ---

impl Trace {
    /// Parse a trace from its canonical JSON form.
    pub fn from_json(json: &str) -> Result<Self, Error> {
        let raw: raw::RawTrace = serde_json::from_str(json)?;
        Self::from_raw(raw)
    }

    /// Serialize a trace to canonical pretty-printed JSON.
    pub fn to_json(&self) -> Result<String, Error> {
        let raw = self.to_raw();
        serde_json::to_string_pretty(&raw).map_err(Error::from)
    }

    /// Decode a [`raw::RawTrace`] into the typed form, using the topology's
    /// `n` to seed the `Certificate` codec.
    pub fn from_raw(raw: raw::RawTrace) -> Result<Self, Error> {
        let cert_cfg = raw.topology.n as usize;
        let events = raw
            .events
            .into_iter()
            .map(|e| Event::from_raw(e, cert_cfg))
            .collect::<Result<Vec<_>, Error>>()?;
        let expected = Snapshot::from_raw(raw.expected)?;
        Ok(Self {
            topology: raw.topology,
            events,
            expected,
        })
    }

    pub fn to_raw(&self) -> raw::RawTrace {
        raw::RawTrace {
            topology: self.topology.clone(),
            events: self.events.iter().map(Event::to_raw).collect(),
            expected: self.expected.to_raw(),
        }
    }
}

impl Event {
    fn to_raw(&self) -> raw::RawEvent {
        match self {
            Event::Deliver { to, from, msg } => raw::RawEvent::Deliver {
                to: to.get(),
                from: from.get(),
                msg: match msg {
                    Wire::Vote(v) => raw::RawWire::Vote {
                        hex: hex_of_encoded(v),
                    },
                    Wire::Cert(c) => raw::RawWire::Cert {
                        hex: hex_of_encoded(c),
                    },
                },
            },
            Event::Propose { leader, proposal } => raw::RawEvent::Propose {
                leader: leader.get(),
                proposal: hex_of_encoded(proposal),
            },
            Event::Construct { node, vote } => raw::RawEvent::Construct {
                node: node.get(),
                vote: hex_of_encoded(vote),
            },
            Event::Timeout { node, view, reason } => raw::RawEvent::Timeout {
                node: node.get(),
                view: view.get(),
                reason: *reason,
            },
        }
    }

    fn from_raw(raw: raw::RawEvent, cert_cfg: usize) -> Result<Self, Error> {
        Ok(match raw {
            raw::RawEvent::Deliver { to, from, msg } => {
                let wire = match msg {
                    raw::RawWire::Vote { hex } => {
                        let bytes = decode_hex(&hex)?;
                        Wire::Vote(Vote::<Scheme, Digest>::decode(bytes.as_slice())?)
                    }
                    raw::RawWire::Cert { hex } => {
                        let bytes = decode_hex(&hex)?;
                        Wire::Cert(Certificate::<Scheme, Digest>::decode_cfg(
                            bytes.as_slice(),
                            &cert_cfg,
                        )?)
                    }
                };
                Event::Deliver {
                    to: Participant::new(to),
                    from: Participant::new(from),
                    msg: wire,
                }
            }
            raw::RawEvent::Propose { leader, proposal } => {
                let bytes = decode_hex(&proposal)?;
                Event::Propose {
                    leader: Participant::new(leader),
                    proposal: Proposal::<Digest>::decode(bytes.as_slice())?,
                }
            }
            raw::RawEvent::Construct { node, vote } => {
                let bytes = decode_hex(&vote)?;
                Event::Construct {
                    node: Participant::new(node),
                    vote: Vote::<Scheme, Digest>::decode(bytes.as_slice())?,
                }
            }
            raw::RawEvent::Timeout { node, view, reason } => Event::Timeout {
                node: Participant::new(node),
                view: View::new(view),
                reason,
            },
        })
    }
}

impl Snapshot {
    fn to_raw(&self) -> raw::RawSnapshot {
        raw::RawSnapshot {
            nodes: self
                .nodes
                .iter()
                .map(|(p, s)| raw::RawNodeSnapshot {
                    node: p.get(),
                    notarizations: s
                        .notarizations
                        .iter()
                        .map(|(v, c)| (v.get(), raw::RawCertState::from(c)))
                        .collect(),
                    nullifications: s
                        .nullifications
                        .iter()
                        .map(|(v, n)| (v.get(), raw::RawNullState::from(n)))
                        .collect(),
                    finalizations: s
                        .finalizations
                        .iter()
                        .map(|(v, c)| (v.get(), raw::RawCertState::from(c)))
                        .collect(),
                    certified: s.certified.iter().map(|v| v.get()).collect(),
                    notarize_signers: view_signers_to_raw(&s.notarize_signers),
                    nullify_signers: view_signers_to_raw(&s.nullify_signers),
                    finalize_signers: view_signers_to_raw(&s.finalize_signers),
                    last_finalized: s.last_finalized.get(),
                })
                .collect(),
        }
    }

    fn from_raw(raw: raw::RawSnapshot) -> Result<Self, Error> {
        let mut nodes = BTreeMap::new();
        for n in raw.nodes {
            let snap = NodeSnapshot {
                notarizations: n
                    .notarizations
                    .into_iter()
                    .map(|(v, c)| Ok((View::new(v), CertStateSnapshot::try_from(c)?)))
                    .collect::<Result<_, Error>>()?,
                nullifications: n
                    .nullifications
                    .into_iter()
                    .map(|(v, n)| (View::new(v), NullStateSnapshot::from(n)))
                    .collect(),
                finalizations: n
                    .finalizations
                    .into_iter()
                    .map(|(v, c)| Ok((View::new(v), CertStateSnapshot::try_from(c)?)))
                    .collect::<Result<_, Error>>()?,
                certified: n.certified.into_iter().map(View::new).collect(),
                notarize_signers: view_signers_from_raw(n.notarize_signers),
                nullify_signers: view_signers_from_raw(n.nullify_signers),
                finalize_signers: view_signers_from_raw(n.finalize_signers),
                last_finalized: View::new(n.last_finalized),
            };
            nodes.insert(Participant::new(n.node), snap);
        }
        Ok(Self { nodes })
    }
}

fn view_signers_to_raw(
    map: &BTreeMap<View, BTreeSet<Participant>>,
) -> BTreeMap<u64, BTreeSet<u32>> {
    map.iter()
        .map(|(v, s)| (v.get(), s.iter().map(|p| p.get()).collect()))
        .collect()
}

fn view_signers_from_raw(
    map: BTreeMap<u64, BTreeSet<u32>>,
) -> BTreeMap<View, BTreeSet<Participant>> {
    map.into_iter()
        .map(|(v, s)| {
            (
                View::new(v),
                s.into_iter().map(Participant::new).collect(),
            )
        })
        .collect()
}

// --- hex helpers ---

fn hex_of(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

fn hex_of_encoded<T: Encode>(t: &T) -> String {
    let mut buf = BytesMut::with_capacity(t.encode_size());
    t.write(&mut buf);
    hex_of(&buf)
}

fn decode_hex(s: &str) -> Result<Vec<u8>, Error> {
    if s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::Hex(format!("not even-length hex: {s:?}")));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.as_bytes().chunks(2) {
        let hi = hex_digit(pair[0])?;
        let lo = hex_digit(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_digit(b: u8) -> Result<u8, Error> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(Error::Hex(format!("not a hex digit: {:?}", b as char))),
    }
}

fn digest_from_hex(s: &str) -> Result<Digest, Error> {
    let bytes = decode_hex(s)?;
    if bytes.len() != 32 {
        return Err(Error::DigestLength {
            expected: 32,
            got: bytes.len(),
        });
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(Sha256Digest::from(arr))
}

// --- Raw (on-disk) forms ---

pub mod raw {
    use super::{digest_from_hex, hex_of, CertStateSnapshot, Error, NullStateSnapshot};
    use crate::simplex::metrics::TimeoutReason;
    use serde::{Deserialize, Serialize};
    use std::collections::{BTreeMap, BTreeSet};

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct RawTrace {
        pub topology: super::Topology,
        pub events: Vec<RawEvent>,
        pub expected: RawSnapshot,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    pub enum RawEvent {
        Deliver { to: u32, from: u32, msg: RawWire },
        Propose { leader: u32, proposal: String },
        Construct { node: u32, vote: String },
        Timeout { node: u32, view: u64, reason: TimeoutReason },
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(tag = "channel", rename_all = "snake_case")]
    pub enum RawWire {
        Vote { hex: String },
        Cert { hex: String },
    }

    #[derive(Clone, Debug, Default, Serialize, Deserialize)]
    pub struct RawSnapshot {
        pub nodes: Vec<RawNodeSnapshot>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct RawNodeSnapshot {
        pub node: u32,
        #[serde(default)]
        pub notarizations: BTreeMap<u64, RawCertState>,
        #[serde(default)]
        pub nullifications: BTreeMap<u64, RawNullState>,
        #[serde(default)]
        pub finalizations: BTreeMap<u64, RawCertState>,
        #[serde(default)]
        pub certified: BTreeSet<u64>,
        #[serde(default)]
        pub notarize_signers: BTreeMap<u64, BTreeSet<u32>>,
        #[serde(default)]
        pub nullify_signers: BTreeMap<u64, BTreeSet<u32>>,
        #[serde(default)]
        pub finalize_signers: BTreeMap<u64, BTreeSet<u32>>,
        pub last_finalized: u64,
    }

    #[derive(Clone, Debug, Default, Serialize, Deserialize)]
    pub struct RawCertState {
        /// Hex of the 32-byte digest.
        pub payload: String,
        pub signature_count: Option<u32>,
    }

    #[derive(Clone, Debug, Default, Serialize, Deserialize)]
    pub struct RawNullState {
        pub signature_count: Option<u32>,
    }

    impl From<&CertStateSnapshot> for RawCertState {
        fn from(c: &CertStateSnapshot) -> Self {
            Self {
                payload: hex_of(c.payload.as_ref()),
                signature_count: c.signature_count,
            }
        }
    }

    impl TryFrom<RawCertState> for CertStateSnapshot {
        type Error = Error;
        fn try_from(r: RawCertState) -> Result<Self, Error> {
            Ok(Self {
                payload: digest_from_hex(&r.payload)?,
                signature_count: r.signature_count,
            })
        }
    }

    impl From<&NullStateSnapshot> for RawNullState {
        fn from(n: &NullStateSnapshot) -> Self {
            Self {
                signature_count: n.signature_count,
            }
        }
    }

    impl From<RawNullState> for NullStateSnapshot {
        fn from(r: RawNullState) -> Self {
            Self {
                signature_count: r.signature_count,
            }
        }
    }

}

// --- serde helpers ---

mod serde_bytes_hex {
    use super::{decode_hex, hex_of};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&hex_of(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(de)?;
        decode_hex(&s).map_err(serde::de::Error::custom)
    }
}

// --- Keyset rehydration ---

/// Regenerates the deterministic ed25519 keyset used by this trace. Uses
/// `commonware_runtime::deterministic::Runner::seeded(0)`'s RNG to match
/// the fuzz harness's fixture. If your trace was recorded with a
/// different RNG source, keys will not line up.
pub fn rehydrate_keys(topology: &Topology) -> commonware_cryptography::certificate::mocks::Fixture<Scheme> {
    use commonware_runtime::{deterministic, Runner};
    let captured = std::sync::Arc::new(std::sync::Mutex::new(None));
    let captured_clone = captured.clone();
    let namespace = topology.namespace.clone();
    let n = topology.n;
    let runner = deterministic::Runner::seeded(0);
    runner.start(|mut ctx| async move {
        let fixture = ed25519::fixture(&mut ctx, &namespace, n);
        *captured_clone.lock().unwrap() = Some(fixture);
    });
    let mut guard = captured.lock().unwrap();
    guard.take().expect("fixture captured")
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{sha256::Sha256, Hasher};

    fn example_topology() -> Topology {
        Topology {
            n: 4,
            faults: 0,
            epoch: 333,
            namespace: b"consensus_fuzz".to_vec(),
            timing: Timing::default(),
        }
    }

    #[test]
    fn hex_roundtrip() {
        let bytes: Vec<u8> = (0u8..=255).collect();
        let h = hex_of(&bytes);
        let back = decode_hex(&h).unwrap();
        assert_eq!(bytes, back);
    }

    #[test]
    fn digest_roundtrip() {
        let mut h = Sha256::new();
        h.update(b"hello");
        let d: Digest = h.finalize();
        let hex = hex_of(d.as_ref());
        let back = digest_from_hex(&hex).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn empty_trace_json_roundtrip() {
        let trace = Trace {
            topology: example_topology(),
            events: Vec::new(),
            expected: Snapshot::default(),
        };
        let json = trace.to_json().unwrap();
        let back = Trace::from_json(&json).unwrap();
        assert_eq!(back.topology.n, trace.topology.n);
        assert_eq!(back.topology.namespace, trace.topology.namespace);
        assert_eq!(back.events.len(), 0);
        assert!(back.expected.nodes.is_empty());
    }
}
