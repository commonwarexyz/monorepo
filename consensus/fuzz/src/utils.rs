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

#[derive(Debug, Clone, Arbitrary)]
pub enum PartitionStrategy {
    /// All validators can communicate with all others (full mesh)
    Connected,

    /// Validator 0 acts as byzantine, can talk to itself and both halves
    /// Other validators are split into two partitions that cannot communicate
    TwoPartitionsWithByzantine,

    /// The byzantine validator can send messages to all other validators.
    /// Other validators cannot communicate with each other.
    ManyPartitionsWithByzantine,

    /// No validator can communicate with any other (complete isolation)
    Isolated,

    /// Validator i can send messages to itself or the next validator
    Linear,
}

impl PartitionStrategy {
    pub fn create(&self) -> Option<fn(usize, usize, usize) -> bool> {
        match self {
            PartitionStrategy::Connected => None,
            PartitionStrategy::Isolated => Some(|_n, i, j| i == j),
            PartitionStrategy::TwoPartitionsWithByzantine => Some(two_partitions_with_byzantine),
            PartitionStrategy::ManyPartitionsWithByzantine => Some(many_partitions_with_byzantine),
            PartitionStrategy::Linear => Some(linear),
        }
    }
}

fn two_partitions_with_byzantine(n: usize, i: usize, j: usize) -> bool {
    if i == 0 || j == 0 {
        return true;
    }

    let mid = n / 2;
    let i_partition = if i <= mid { 1 } else { 2 };
    let j_partition = if j <= mid { 1 } else { 2 };

    i_partition == j_partition
}

fn many_partitions_with_byzantine(_: usize, i: usize, j: usize) -> bool {
    i == 0 || j == 0
}

fn linear(n: usize, i: usize, j: usize) -> bool {
    i + 1 % n == j % n || i == j
}

pub async fn simplex_register_peers<P: PublicKey>(
    oracle: &mut Oracle<P>,
    validators: &[P],
) -> HashMap<P, ((Sender<P>, Receiver<P>), (Sender<P>, Receiver<P>))> {
    let mut registrations = HashMap::new();
    for validator in validators.iter() {
        let (voter_sender, voter_receiver) = oracle.register(validator.clone(), 0).await.unwrap();
        let (resolver_sender, resolver_receiver) =
            oracle.register(validator.clone(), 1).await.unwrap();
        registrations.insert(
            validator.clone(),
            (
                (voter_sender, voter_receiver),
                (resolver_sender, resolver_receiver),
            ),
        );
    }
    registrations
}

pub async fn threshold_simplex_register_peers<P: PublicKey>(
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
        let (pending_sender, pending_receiver) =
            oracle.register(validator.clone(), 0).await.unwrap();
        let (recovered_sender, recovered_receiver) =
            oracle.register(validator.clone(), 1).await.unwrap();
        let (resolver_sender, resolver_receiver) =
            oracle.register(validator.clone(), 2).await.unwrap();
        registrations.insert(
            validator.clone(),
            (
                (pending_sender, pending_receiver),
                (recovered_sender, recovered_receiver),
                (resolver_sender, resolver_receiver),
            ),
        );
    }
    registrations
}

pub async fn link_peers<P: PublicKey>(
    oracle: &mut Oracle<P>,
    validators: &[P],
    action: Action,
    restrict_to: Option<fn(usize, usize, usize) -> bool>,
) {
    for (i1, v1) in validators.iter().enumerate() {
        for (i2, v2) in validators.iter().enumerate() {
            if v2 == v1 {
                continue;
            }
            if let Some(f) = restrict_to {
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

pub async fn register_validators<P: commonware_cryptography::PublicKey>(
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
        let (pending_sender, pending_receiver) =
            oracle.register(validator.clone(), 0).await.unwrap();
        let (recovered_sender, recovered_receiver) =
            oracle.register(validator.clone(), 1).await.unwrap();
        let (resolver_sender, resolver_receiver) =
            oracle.register(validator.clone(), 2).await.unwrap();
        registrations.insert(
            validator.clone(),
            (
                (pending_sender, pending_receiver),
                (recovered_sender, recovered_receiver),
                (resolver_sender, resolver_receiver),
            ),
        );
    }
    registrations
}
