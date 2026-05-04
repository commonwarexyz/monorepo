//! ByzzFuzz content mutator: wraps `SmallScope` and biases toward
//! observed-value mutations (replay observed payloads/proposals/certs,
//! swap resolver request views) before falling back to local edits.

use crate::{
    byzzfuzz::observed::{CertKinds, KnownViewKinds, ObservedState},
    strategy::{SmallScope, Strategy},
    EPOCH,
};
use bytes::BytesMut;
use commonware_codec::Write;
use commonware_consensus::{
    simplex::types::Proposal,
    types::{Epoch, Round, View},
    Viewable,
};
use commonware_cryptography::sha256::Digest as Sha256Digest;
use rand::Rng;
use std::sync::Arc;

pub struct ByzzFuzzMutator {
    pool: Arc<ObservedState>,
    inner: SmallScope,
}

impl ByzzFuzzMutator {
    pub fn new(pool: Arc<ObservedState>) -> Self {
        Self {
            pool,
            // SmallScope's fault_rounds/_bound aren't read on the mutate_*
            // path; only sampled by network/messaging_faults which we don't call.
            inner: SmallScope {
                fault_rounds: 1,
                fault_rounds_bound: 1,
            },
        }
    }
}

fn proposal_with_payload(
    p: &Proposal<Sha256Digest>,
    payload: Sha256Digest,
) -> Proposal<Sha256Digest> {
    Proposal::new(
        Round::new(Epoch::new(EPOCH), View::new(p.view().get())),
        p.parent,
        payload,
    )
}

fn proposal_with_parent(p: &Proposal<Sha256Digest>, parent: u64) -> Proposal<Sha256Digest> {
    Proposal::new(
        Round::new(Epoch::new(EPOCH), View::new(p.view().get())),
        View::new(parent),
        p.payload,
    )
}

impl Strategy for ByzzFuzzMutator {
    fn random_proposal(
        &self,
        rng: &mut impl Rng,
        a: u64,
        b: u64,
        c: u64,
        d: u64,
    ) -> Proposal<Sha256Digest> {
        self.inner.random_proposal(rng, a, b, c, d)
    }

    fn proposal_with_view(
        &self,
        proposal: &Proposal<Sha256Digest>,
        view: u64,
    ) -> Proposal<Sha256Digest> {
        self.inner.proposal_with_view(proposal, view)
    }

    fn proposal_with_parent_view(
        &self,
        proposal: &Proposal<Sha256Digest>,
        view: u64,
    ) -> Proposal<Sha256Digest> {
        self.inner.proposal_with_parent_view(proposal, view)
    }

    fn mutate_proposal(
        &self,
        rng: &mut impl Rng,
        proposal: &Proposal<Sha256Digest>,
        a: u64,
        b: u64,
        c: u64,
        d: u64,
    ) -> Proposal<Sha256Digest> {
        // Bias 60% toward observed-value mutations; 40% local edits.
        // Identity mutations (== original proposal) are degenerate -- the
        // injector would re-sign and resend the same vote content. Reject
        // them and fall back to SmallScope.
        if rng.gen_bool(0.6) {
            let candidate = match rng.gen_range(0..4) {
                0 => self
                    .pool
                    .random_payload(rng)
                    .map(|payload| proposal_with_payload(proposal, payload)),
                1 => self.pool.random_proposal_any(rng).map(|other| {
                    Proposal::new(
                        Round::new(Epoch::new(EPOCH), proposal.view()),
                        other.parent,
                        other.payload,
                    )
                }),
                2 => self
                    .pool
                    .random_proposal_any(rng)
                    .map(|other| proposal_with_parent(proposal, other.parent.get())),
                _ => self.pool.random_proposal_at(rng, proposal.view().get()),
            };
            if let Some(c) = candidate {
                if c != *proposal {
                    return c;
                }
            }
        }
        self.inner.mutate_proposal(rng, proposal, a, b, c, d)
    }

    fn mutate_nullify_view(&self, rng: &mut impl Rng, a: u64, b: u64, c: u64, d: u64) -> u64 {
        // Bias toward nullifying an observed notarized/finalized view --
        // a more interesting fault than a small local view edit.
        if rng.gen_bool(0.5) {
            if let Some(v) = self.pool.random_known_view(
                rng,
                KnownViewKinds {
                    notarized: true,
                    finalized: true,
                    nullified: false,
                },
            ) {
                return v;
            }
        }
        self.inner.mutate_nullify_view(rng, a, b, c, d)
    }

    fn random_view_for_proposal(&self, rng: &mut impl Rng, a: u64, b: u64, c: u64, d: u64) -> u64 {
        self.inner.random_view_for_proposal(rng, a, b, c, d)
    }

    fn random_parent_view(&self, rng: &mut impl Rng, a: u64, b: u64, c: u64, d: u64) -> u64 {
        self.inner.random_parent_view(rng, a, b, c, d)
    }

    fn random_payload(&self, rng: &mut impl Rng) -> Sha256Digest {
        // Reuse an observed payload when available; otherwise random.
        self.pool
            .random_payload(rng)
            .unwrap_or_else(|| self.inner.random_payload(rng))
    }

    fn mutate_certificate_bytes(&self, rng: &mut impl Rng, cert: &[u8]) -> Vec<u8> {
        // Higher-signal mutations: replay observed cert bytes (often a
        // valid cert in a semantically awkward context), or apply a
        // structural edit. Byte-flip is the fallback parser-fuzzing path.
        if cert.is_empty() {
            return self.inner.mutate_certificate_bytes(rng, cert);
        }
        match rng.gen_range(0..6) {
            0 | 1 => {
                if let Some(observed) = self.pool.random_cert_bytes(rng, CertKinds::ALL) {
                    if observed != cert {
                        return observed;
                    }
                }
                self.inner.mutate_certificate_bytes(rng, cert)
            }
            2 => {
                // Tag swap: flip the discriminator byte to a different
                // valid tag. Certificate enum tag is the first byte (per
                // simplex/types.rs Write impl).
                let mut out = cert.to_vec();
                let new_tag = (out[0].wrapping_add(rng.gen_range(1..3))) % 3;
                out[0] = new_tag;
                out
            }
            3 => {
                // Truncate.
                let n = cert.len();
                let cut = rng.gen_range(1..=n);
                cert[..n - cut.min(n)].to_vec()
            }
            4 => {
                // Extend.
                let mut out = cert.to_vec();
                let extra = rng.gen_range(1..=16);
                for _ in 0..extra {
                    out.push(rng.gen());
                }
                out
            }
            _ => self.inner.mutate_certificate_bytes(rng, cert),
        }
    }

    fn mutate_resolver_bytes(&self, rng: &mut impl Rng, msg: &[u8]) -> Vec<u8> {
        // Resolver wire: id (8 BE bytes) + tag (1 byte) + payload.
        // Tag 0 = Request(U64), tag 1 = Response(Bytes), tag 2 = Error.
        if msg.len() == 17 && msg[8] == 0 {
            // Request: rewrite the U64 view bytes to an observed view.
            if let Some(observed) = self.pool.random_resolver_request_view(rng) {
                let mut current_be = [0u8; 8];
                current_be.copy_from_slice(&msg[9..17]);
                let current = u64::from_be_bytes(current_be);
                if observed != current && rng.gen_bool(0.7) {
                    let mut out = msg.to_vec();
                    out[9..17].copy_from_slice(&observed.to_be_bytes());
                    return out;
                }
            }
        }
        if msg.len() >= 9 && msg[8] == 1 {
            // Response: replace embedded cert bytes with an observed cert.
            if let Some(cert) = self.pool.random_cert_bytes(rng, CertKinds::ALL) {
                if rng.gen_bool(0.5) {
                    let mut len_buf = BytesMut::new();
                    cert.len().write(&mut len_buf);
                    let mut out = Vec::with_capacity(9 + len_buf.len() + cert.len());
                    out.extend_from_slice(&msg[..9]);
                    out.extend_from_slice(&len_buf);
                    out.extend_from_slice(&cert);
                    if out != msg {
                        return out;
                    }
                }
            }
        }
        self.inner.mutate_resolver_bytes(rng, msg)
    }

    fn repeated_proposal_index(&self, rng: &mut impl Rng, proposals_len: usize) -> Option<usize> {
        self.inner.repeated_proposal_index(rng, proposals_len)
    }

    fn network_faults(
        &self,
        required_containers: u64,
        rng: &mut impl Rng,
    ) -> Vec<(View, crate::utils::SetPartition)> {
        self.inner.network_faults(required_containers, rng)
    }

    fn messaging_faults(&self, required_containers: u64, rng: &mut impl Rng) -> Vec<(View, u8)> {
        self.inner.messaging_faults(required_containers, rng)
    }

    fn fault_bounds(&self) -> Option<(u64, u64)> {
        self.inner.fault_bounds()
    }
}
