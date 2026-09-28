//! Opt-in, process-local diagnostic events for controlled experiments.
//!
//! A sink receives every event, independently of trace sampling. It must bound formatting and
//! queue capacity, never wait for I/O, and report losses. Events describe local observations;
//! timestamps from different processes do not establish a precise network latency.

use std::{
    fmt,
    sync::{Arc, OnceLock},
};

static SINK: OnceLock<Arc<dyn Sink>> = OnceLock::new();

/// A nonblocking consumer of borrowed event fields.
///
/// Field values use Rust debug notation inside the capture envelope. Canonical artifact bytes
/// and wire frames use hexadecimal, so captures remain decodable with the matching protocol
/// version even when debug implementations summarize their contents.
pub trait Sink: Send + Sync + 'static {
    /// Returns whether the sink is accepting events.
    fn enabled(&self) -> bool {
        true
    }

    /// Returns this capture's local monotonic elapsed nanoseconds, if accepting records.
    fn elapsed_ns(&self) -> Option<u128> {
        None
    }

    /// Records an event without retaining its borrowed fields or waiting for I/O.
    fn record(&self, kind: &'static str, fields: &[(&'static str, &dyn fmt::Debug)]);
}

/// Installs the process's diagnostic sink. A second installation returns the unused sink.
///
/// Applications should install before starting protocol actors and keep their writer guard alive
/// until the capture ends. A process hosting several replicas must supply replica attribution in
/// its sink; the experiment application runs one replica per process.
pub fn install(sink: Arc<dyn Sink>) -> Result<(), Arc<dyn Sink>> {
    SINK.set(sink)
}

/// Returns whether diagnostic records are currently accepted.
#[inline]
pub fn enabled() -> bool {
    SINK.get().is_some_and(|sink| sink.enabled())
}

/// Returns the installed capture's local monotonic timestamp, if available.
#[inline]
pub fn elapsed_ns() -> Option<u128> {
    SINK.get().and_then(|sink| sink.elapsed_ns())
}

/// Emits one event when an accepting sink is installed.
#[inline]
pub fn record(kind: &'static str, fields: &[(&'static str, &dyn fmt::Debug)]) {
    if let Some(sink) = SINK.get()
        && sink.enabled()
    {
        sink.record(kind, fields);
    }
}

/// A byte slice rendered as contiguous lowercase hexadecimal without allocating.
pub struct Hex<'a>(pub &'a [u8]);

impl fmt::Debug for Hex<'_> {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(out, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Emits an event with scalar `chain`, `height`, and hexadecimal `digest` identity fields.
/// Additional fields must not repeat these names.
pub fn block<D: commonware_cryptography::Digest>(
    kind: &'static str,
    block: super::types::BlockRef<D>,
    fields: &[(&'static str, &dyn fmt::Debug)],
) {
    if !enabled() {
        return;
    }
    let chain = block.chain().get();
    let height = block.height().get();
    let digest = block.digest();
    let hex = Hex(digest.as_ref());
    let mut all: Vec<(&'static str, &dyn fmt::Debug)> = Vec::with_capacity(3 + fields.len());
    all.extend_from_slice(&[("chain", &chain), ("height", &height), ("digest", &hex)]);
    all.extend_from_slice(fields);
    record(kind, &all);
}

#[cfg(not(target_arch = "wasm32"))]
fn body_key<H: commonware_cryptography::Hasher>(
    body: &super::types::VoteBody<H::Digest>,
) -> H::Digest {
    use commonware_codec::Encode as _;
    H::hash(&[
        b"_COMMONWARE_CONSENSUS_MULTIMMIT_DIAGNOSTIC_VOTE",
        &body.encode(),
    ])
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn vote_paths<
    H: commonware_cryptography::Hasher,
    V: commonware_cryptography::bls12381::primitives::variant::Variant,
>(
    leader: &super::types::LeaderBlock<V, H::Digest>,
    body: &super::types::VoteBody<H::Digest>,
) {
    use super::{
        algebra::{ProposalPaths, VotePaths},
        types::{ChainId, DigestedLeader},
    };
    if !enabled() {
        return;
    }
    let Ok(proposals) = ProposalPaths::new::<H, V>(leader) else {
        return;
    };
    let Ok(paths) = VotePaths::new::<H, V>(DigestedLeader::new::<H>(leader), &proposals, body)
    else {
        return;
    };
    let key = body_key::<H>(body);
    for chain in 0..proposals.len() {
        let chain = ChainId::new(chain as u32);
        let position = body.positions()[chain.get() as usize].get() as usize;
        let proposal = proposals.chain(chain).expect("reconstructed chain");
        let extension = paths.extension(chain).expect("reconstructed chain");
        let proposed_height = proposal.last().expect("proposal anchor").height().get();
        for (slot, reference) in proposal[..=position].iter().enumerate() {
            block(
                "endorsement_built",
                *reference,
                &[
                    ("epoch", &body.round().epoch().get()),
                    ("view", &body.round().view().get()),
                    ("body", &key),
                    ("leader", &body.leader()),
                    ("class", &"position"),
                    ("slot", &slot),
                    ("proposed_height", &proposed_height),
                ],
            );
        }
        for (offset, reference) in extension.iter().skip(1).enumerate() {
            block(
                "endorsement_built",
                *reference,
                &[
                    ("epoch", &body.round().epoch().get()),
                    ("view", &body.round().view().get()),
                    ("body", &key),
                    ("leader", &body.leader()),
                    ("class", &"extension"),
                    ("slot", &(offset + 1)),
                    ("proposed_height", &proposed_height),
                ],
            );
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn artifact<
    H: commonware_cryptography::Hasher,
    V: commonware_cryptography::bls12381::primitives::variant::Variant,
>(
    event: &'static str,
    id: super::types::ArtifactId<H::Digest>,
    artifact: &super::types::Artifact<V, H::Digest>,
) {
    use super::{
        algebra::ProposalPaths,
        types::{Artifact, ChainId},
    };
    if !enabled() {
        return;
    }
    if let Some(leader) = artifact.designated_leader()
        && let Ok(paths) = ProposalPaths::new::<H, V>(leader)
    {
        let digest = leader.digest::<H>();
        for index in 0..paths.len() {
            let chain = ChainId::new(index as u32);
            if let Ok(path) = paths.chain(chain) {
                for (slot, reference) in path.iter().enumerate() {
                    block(
                        "proposal_block",
                        *reference,
                        &[
                            ("event", &event),
                            ("artifact", &id),
                            ("epoch", &leader.round().epoch().get()),
                            ("view", &leader.round().view().get()),
                            ("leader", &digest),
                            ("slot", &slot),
                        ],
                    );
                }
                record(
                    "proposal_path",
                    &[
                        ("event", &event),
                        ("artifact", &id),
                        ("round", &leader.round()),
                        ("leader", &digest),
                        ("history", &leader.history()),
                        ("parent", &leader.parent()),
                        ("chain", &index),
                        ("blocks", &path),
                    ],
                );
            }
        }
    }
    if let Artifact::Vote(vote) = artifact {
        let body = vote.body();
        let key = body_key::<H>(body);
        record(
            "vote_body",
            &[
                ("event", &event),
                ("artifact", &id),
                ("body", &key),
                ("epoch", &body.round().epoch().get()),
                ("view", &body.round().view().get()),
                ("leader", &body.leader()),
                ("signer", &artifact.signer().map(|signer| signer.get())),
            ],
        );
        for (chain, (position, extension)) in
            body.positions().iter().zip(body.extensions()).enumerate()
        {
            record(
                "vote_chain",
                &[
                    ("event", &event),
                    ("artifact", &id),
                    ("round", &body.round()),
                    ("leader", &body.leader()),
                    ("signer", &artifact.signer().map(|signer| signer.get())),
                    ("chain", &chain),
                    ("position", position),
                    ("payloads", &extension.payloads()),
                ],
            );
        }
    }
    // Capture memory remains bounded even when protocol configuration permits very large proofs.
    const MAX_BYTES: usize = 64 * 1024;
    let size = artifact.encoded_len();
    if size > MAX_BYTES {
        record(
            "artifact_omitted",
            &[("event", &event), ("id", &id), ("bytes", &size)],
        );
        return;
    }
    let mut bytes = Vec::with_capacity(size);
    artifact.write_canonical_encoding(&mut bytes);
    record(
        event,
        &[
            ("id", &id),
            ("kind", &artifact.kind()),
            ("view", &artifact.view().map(|view| view.get())),
            ("signer", &artifact.signer().map(|signer| signer.get())),
            ("chain_position", &artifact.chain_position()),
            ("canonical", &Hex(&bytes)),
        ],
    );
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn history<D: commonware_cryptography::Digest>(
    commitment: D,
    record: &super::types::TipRecord<D>,
    trigger_view: crate::types::View,
) {
    if !enabled() {
        return;
    }
    for (chain, tip) in record.tips().iter().enumerate() {
        block(
            "historical_tip",
            *tip,
            &[
                ("history", &commitment),
                ("parent_history", &record.parent()),
                ("trigger_view", &trigger_view.get()),
                ("proposed_height", &record.proposed()[chain].get()),
            ],
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_hex_is_lossless() {
        assert_eq!(format!("{:?}", Hex(&[0, 15, 127, 255])), "000f7fff");
    }
}
