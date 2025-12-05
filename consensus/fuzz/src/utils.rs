use arbitrary::Arbitrary;
use commonware_cryptography::PublicKey;
use commonware_p2p::simulated::{Link, Oracle, Receiver, Sender};
use std::collections::HashMap;

#[derive(Clone)]
pub enum Action {
    Link(Link),
    Update(Link),
    Unlink,
}

/// Network partition strategies for fuzz testing.
#[derive(Debug, Clone, Arbitrary, PartialEq)]
pub enum Partition {
    /// All validators connected to each other.
    Connected,
    /// Two partitions where only the Byzantine node (index 0) bridges them.
    TwoPartitionsWithByzantine,
    /// Each honest node isolated, only connected to the Byzantine node (index 0).
    ManyPartitionsWithByzantine,
    /// No connections between any validators.
    Isolated,
    /// Ring topology: node i connects to i-1 and i+1 (with wraparound).
    Linear,
}

impl Partition {
    pub fn filter(&self) -> Option<fn(usize, usize, usize) -> bool> {
        match self {
            Partition::Connected => None,
            Partition::Isolated => Some(|_, i, j| i == j),
            Partition::TwoPartitionsWithByzantine => Some(two_partitions_with_byzantine),
            Partition::ManyPartitionsWithByzantine => Some(many_partitions_with_byzantine),
            Partition::Linear => Some(linear),
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
fn linear(n: usize, i: usize, j: usize) -> bool {
    i.abs_diff(j) == 1 || i.abs_diff(j) == n - 1
}

pub async fn link_peers<P: PublicKey>(
    oracle: &mut Oracle<P>,
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

pub async fn register<P: PublicKey>(
    oracle: &mut Oracle<P>,
    validators: &[P],
) -> HashMap<
    P,
    (
        (Sender<P>, Receiver<P>),
        (Sender<P>, Receiver<P>),
        (Sender<P>, Receiver<P>),
    ),
> {
    let mut registrations = HashMap::new();
    for validator in validators.iter() {
        let mut control = oracle.control(validator.clone());
        let pending = control.register(0).await.unwrap();
        let recovered = control.register(1).await.unwrap();
        let resolver = control.register(2).await.unwrap();
        registrations.insert(validator.clone(), (pending, recovered, resolver));
    }
    registrations
}
