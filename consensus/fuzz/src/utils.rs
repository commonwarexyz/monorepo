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
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

    let mut hash = FNV_OFFSET;
    for &byte in bytes {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
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

#[derive(Debug, Clone, PartialEq)]
pub enum Partition {
    /// Fully connected, no fault for the run.
    Connected,
    /// One fault active for the entire run.
    Static(NetworkFault),
    /// Round-indexed schedule of faults; topology reverts to fully connected outside entries.
    Adaptive(Vec<(View, NetworkFault)>),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NetworkFault {
    TwoPartitionsWithByzantine,
    ManyPartitionsWithByzantine,
    Isolated,
    Ring,
}

impl Partition {
    pub fn filter(&self) -> Option<fn(usize, usize, usize) -> bool> {
        match self {
            Partition::Connected | Partition::Adaptive(_) => None,
            Partition::Static(fault) => Some(fault.filter()),
        }
    }

    pub fn is_connected(&self) -> bool {
        matches!(self, Partition::Connected)
    }

    pub fn schedule(&self) -> Option<&[(View, NetworkFault)]> {
        match self {
            Partition::Adaptive(schedule) => Some(schedule),
            _ => None,
        }
    }
}

impl NetworkFault {
    pub fn filter(&self) -> fn(usize, usize, usize) -> bool {
        match self {
            NetworkFault::Isolated => |_, i, j| i == j,
            NetworkFault::TwoPartitionsWithByzantine => two_partitions_with_byzantine,
            NetworkFault::ManyPartitionsWithByzantine => many_partitions_with_byzantine,
            NetworkFault::Ring => ring,
        }
    }
}

// Byzantine node (index 0) connects both partitions, honest nodes split in half.
fn two_partitions_with_byzantine(n: usize, i: usize, j: usize) -> bool {
    if i == 0 || j == 0 {
        return true;
    }
    let mid = n / 2;
    let i_partition = if i <= mid { 1 } else { 2 };
    let j_partition = if j <= mid { 1 } else { 2 };
    i_partition == j_partition
}

// Only Byzantine node (index 0) has connections, creating a star topology.
fn many_partitions_with_byzantine(_: usize, i: usize, j: usize) -> bool {
    i == 0 || j == 0
}

// Ring topology: node i connects to i-1 and i+1 (with wraparound).
fn ring(n: usize, i: usize, j: usize) -> bool {
    i.abs_diff(j) == 1 || i.abs_diff(j) == n - 1
}

pub async fn link_peers<P: PublicKey, E: Clock>(
    oracle: &mut Oracle<P, E>,
    validators: &[P],
    action: Action,
    filter: Option<fn(usize, usize, usize) -> bool>,
) {
    for (i1, v1) in validators.iter().enumerate() {
        for (i2, v2) in validators.iter().enumerate() {
            if v2 == v1 {
                continue;
            }
            if let Some(f) = filter {
                if !f(validators.len(), i1, i2) {
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

/// Apply a partition filter as the full network state.
///
/// For every ordered pair (i, j), i != j: ensure a link exists if `filter` permits it,
/// and ensure the link is removed otherwise. Used by the round-indexed network fault
/// scheduler to toggle topology mid-run.
pub async fn apply_partition<P: PublicKey, E: Clock>(
    oracle: &Oracle<P, E>,
    validators: &[P],
    filter: Option<fn(usize, usize, usize) -> bool>,
    link: &Link,
) {
    let n = validators.len();
    for (i1, v1) in validators.iter().enumerate() {
        for (i2, v2) in validators.iter().enumerate() {
            if i1 == i2 {
                continue;
            }
            let want = filter.map_or(true, |f| f(n, i1, i2));
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
