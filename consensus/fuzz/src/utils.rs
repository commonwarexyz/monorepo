use commonware_consensus::types::View;
use commonware_cryptography::PublicKey;
use commonware_p2p::simulated::{Link, Oracle, Receiver, Sender};
use commonware_runtime::{Clock, Quota};
use std::{collections::HashMap, num::NonZeroU32};

/// FNV-1a hash for deterministic hashing.
///
/// Uses FNV-1a instead of `DefaultHasher` because `DefaultHasher` is not
/// guaranteed to be stable across Rust versions.
pub fn fnv1a_hash(bytes: &[u8]) -> u64 {
    fnv1a_hash_slices(&[bytes])
}

/// FNV-1a hash for a logical concatenation of byte slices.
pub fn fnv1a_hash_slices(slices: &[&[u8]]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

    let mut hash = FNV_OFFSET;
    for slice in slices {
        for &byte in *slice {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(FNV_PRIME);
        }
    }
    hash
}

/// Default rate limit set high enough to not interfere with normal operation
const TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);

#[derive(Clone)]
pub enum Action {
    Link(Link),
    Update(Link),
    Unlink,
}

/// A set partition of `{0, 1, 2, 3}` (n = 4) stored as block-id assignments.
/// Two nodes can communicate iff they share a block id. Replaces the previous
/// hand-picked `NetworkFault` shapes with a uniform sample over Bell(4) = 15
/// canonical partitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetPartition([u8; 4]);

impl SetPartition {
    /// All 15 canonical set partitions of `{0, 1, 2, 3}` in canonical form
    /// (each new block is numbered sequentially as it appears).
    ///
    /// Index 0 is the trivial single-block partition (= fully connected);
    /// index 14 is the all-singleton "Isolated" partition.
    pub const N4: [Self; 15] = [
        Self([0, 0, 0, 0]), // {{0,1,2,3}}      - trivial / fully connected
        Self([0, 0, 0, 1]), // {{0,1,2},{3}}
        Self([0, 0, 1, 0]), // {{0,1,3},{2}}
        Self([0, 1, 0, 0]), // {{0,2,3},{1}}
        Self([0, 1, 1, 1]), // {{0},{1,2,3}}
        Self([0, 0, 1, 1]), // {{0,1},{2,3}}
        Self([0, 1, 0, 1]), // {{0,2},{1,3}}
        Self([0, 1, 1, 0]), // {{0,3},{1,2}}
        Self([0, 0, 1, 2]), // {{0,1},{2},{3}}
        Self([0, 1, 0, 2]), // {{0,2},{1},{3}}
        Self([0, 1, 2, 0]), // {{0,3},{1},{2}}
        Self([0, 1, 1, 2]), // {{0},{1,2},{3}}
        Self([0, 1, 2, 1]), // {{0},{1,3},{2}}
        Self([0, 1, 2, 2]), // {{0},{1},{2,3}}
        Self([0, 1, 2, 3]), // {{0},{1},{2},{3}} - Isolated
    ];

    /// Returns the canonical partition at index `idx` in `N4`.
    pub const fn n4(idx: usize) -> Self {
        Self::N4[idx]
    }

    /// True iff nodes `i` and `j` are in the same block (and thus permitted
    /// to communicate). Returns false for out-of-range indices.
    pub fn connected(&self, i: usize, j: usize) -> bool {
        if i >= self.0.len() || j >= self.0.len() {
            return false;
        }
        self.0[i] == self.0[j]
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Partition {
    /// Fully connected, no fault for the run.
    Connected,
    /// One set-partition fault active for the entire run.
    Static(SetPartition),
    /// Round-indexed schedule of set-partition faults; topology reverts to
    /// fully connected outside scheduled views.
    Adaptive(Vec<(View, SetPartition)>),
}

impl Partition {
    /// Returns the active set partition (if any). `Connected` and `Adaptive(_)`
    /// (no active overlay) return `None`, meaning a full mesh.
    pub fn set_partition(&self) -> Option<&SetPartition> {
        match self {
            Partition::Connected | Partition::Adaptive(_) => None,
            Partition::Static(p) => Some(p),
        }
    }

    pub fn is_connected(&self) -> bool {
        matches!(self, Partition::Connected)
    }

    pub fn schedule(&self) -> Option<&[(View, SetPartition)]> {
        match self {
            Partition::Adaptive(schedule) => Some(schedule),
            _ => None,
        }
    }
}

pub async fn link_peers<P: PublicKey, E: Clock>(
    oracle: &mut Oracle<P, E>,
    validators: &[P],
    action: Action,
    partition: Option<&SetPartition>,
) {
    for (i1, v1) in validators.iter().enumerate() {
        for (i2, v2) in validators.iter().enumerate() {
            if v2 == v1 {
                continue;
            }
            if let Some(p) = partition {
                if !p.connected(i1, i2) {
                    continue;
                }
            }
            match action {
                Action::Update(_) | Action::Unlink => {
                    oracle.remove_link(v1.clone(), v2.clone()).await.ok();
                }
                _ => {}
            }
            match action {
                Action::Link(ref link) | Action::Update(ref link) => {
                    oracle
                        .add_link(v1.clone(), v2.clone(), link.clone())
                        .await
                        .unwrap();
                }
                _ => {}
            }
        }
    }
}

/// Apply a set partition as the full network state.
///
/// For every ordered pair (i, j), i != j: ensure a link exists if `partition`
/// permits it, and ensure the link is removed otherwise. Used by the
/// round-indexed network fault scheduler to toggle topology mid-run.
pub async fn apply_partition<P: PublicKey, E: Clock>(
    oracle: &Oracle<P, E>,
    validators: &[P],
    partition: Option<&SetPartition>,
    link: &Link,
) {
    for (i1, v1) in validators.iter().enumerate() {
        for (i2, v2) in validators.iter().enumerate() {
            if i1 == i2 {
                continue;
            }
            let want = partition.is_none_or(|p| p.connected(i1, i2));
            oracle.remove_link(v1.clone(), v2.clone()).await.ok();
            if want {
                oracle
                    .add_link(v1.clone(), v2.clone(), link.clone())
                    .await
                    .unwrap();
            }
        }
    }
}

pub async fn register<P: PublicKey, E: Clock>(
    oracle: &mut Oracle<P, E>,
    validators: &[P],
) -> HashMap<
    P,
    (
        (Sender<P, E>, Receiver<P>),
        (Sender<P, E>, Receiver<P>),
        (Sender<P, E>, Receiver<P>),
    ),
> {
    let mut registrations = HashMap::new();
    for validator in validators.iter() {
        let control = oracle.control(validator.clone());
        let pending = control.register(0, TEST_QUOTA).await.unwrap();
        let recovered = control.register(1, TEST_QUOTA).await.unwrap();
        let resolver = control.register(2, TEST_QUOTA).await.unwrap();
        registrations.insert(validator.clone(), (pending, recovered, resolver));
    }
    registrations
}
