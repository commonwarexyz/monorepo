use crate::simulate::engine::LookupManager;
use commonware_actor::Feedback;
use commonware_cryptography::{PublicKey, Signer};
use commonware_macros::select;
use commonware_p2p::{
    Advertisement, Blocker, Reachability, ReachabilityManager as _, ReachableTrackedPeers,
    Receiver as _, Recipients, Sender as _,
    authenticated::lookup::{
        Config as LookupConfig, DialOnlyNetwork, GenericConfig, Receiver, Sender,
        UnrestrictedAdmission,
    },
};
use commonware_runtime::{
    Clock as _, Handle, Quota, Scheduler as _, Supervisor as _, deterministic,
    deterministic::network::{Endpoint, Link, Oracle as NetworkOracle},
};
use commonware_utils::{NZU32, TryCollect, ordered::Map, sync::Mutex};
use std::{collections::BTreeSet, net::SocketAddr, sync::Arc, time::Duration};

pub(crate) type Channel<P> = (Sender<P, deterministic::Context>, Receiver<P>);

pub(crate) const fn endpoint(index: usize) -> Endpoint {
    Endpoint::new(index as u64 + 1)
}

pub(crate) fn transport(
    context: &deterministic::Context,
    nodes: usize,
    link: Link,
) -> NetworkOracle<deterministic::Context> {
    let oracle = NetworkOracle::new(Default::default());
    for index in 0..nodes {
        oracle.register(
            context
                .child("transport_registration")
                .with_attribute("index", index),
            endpoint(index),
            None,
        );
    }
    for from in 0..nodes {
        for to in 0..nodes {
            if from != to {
                oracle
                    .set_link(endpoint(from), endpoint(to), link)
                    .expect("registered transport endpoints");
            }
        }
    }
    oracle
}

fn tracked<P: PublicKey>(participants: &[P]) -> ReachableTrackedPeers<P, Endpoint> {
    let primary = participants
        .iter()
        .enumerate()
        .map(|(index, public_key)| {
            let advertisement = Advertisement::new(vec![endpoint(index)])
                .expect("one endpoint is a valid advertisement");
            (public_key.clone(), Reachability::Dialable(advertisement))
        })
        .try_collect::<Map<_, _>>()
        .expect("participants must be unique");
    ReachableTrackedPeers::primary(primary)
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub(crate) fn start_node<C: Signer>(
    context: deterministic::Context,
    transport: &NetworkOracle<deterministic::Context>,
    signer: C,
    index: usize,
    participants: &[C::PublicKey],
    namespace: &[u8],
    max_message_size: u32,
    channels: &[(u64, Quota)],
) -> (
    LookupManager<C::PublicKey>,
    Vec<Channel<C::PublicKey>>,
    Handle<()>,
) {
    let mut config = GenericConfig::from(LookupConfig::local(
        signer,
        namespace,
        SocketAddr::from(([0, 0, 0, 0], 0)),
        max_message_size,
    ));
    config.tracked_peer_sets = commonware_utils::NZUsize!(1);
    let node = transport.register(context.child("transport"), endpoint(index), None);
    let (dialer, acceptor) = node.split();
    let (network, mut oracle) = DialOnlyNetwork::new(context.child("lookup"), dialer, config);
    let mut network = network.accepting(
        acceptor,
        endpoint(index),
        UnrestrictedAdmission,
        NZU32!(1_024),
    );
    oracle.track(0, tracked(participants));
    let channels = channels
        .iter()
        .map(|(channel, quota)| network.register(*channel, *quota, 1024))
        .collect();
    (
        LookupManager::new(oracle, participants),
        channels,
        network.start(),
    )
}

/// Establishes authenticated lookup connections from `root` to every peer.
pub(crate) async fn wait_for_connections<P: PublicKey>(
    context: &deterministic::Context,
    participants: &[P],
    mut channels: Vec<Channel<P>>,
    root: usize,
) -> Vec<Handle<()>> {
    assert_eq!(participants.len(), channels.len());
    let mut participants = participants.to_vec();
    participants.swap(0, root);
    channels.swap(0, root);
    let (mut sender, mut receiver) = channels.remove(0);
    let mut handles = Vec::with_capacity(channels.len());

    for (index, (mut peer_sender, mut peer_receiver)) in channels.into_iter().enumerate() {
        handles.push(
            context
                .child("readiness")
                .with_attribute("index", index + 1)
                .spawn(move |_| async move {
                    while let Ok((peer, message)) = peer_receiver.recv().await {
                        peer_sender.send(Recipients::One(peer), message, false);
                    }
                }),
        );
    }

    for participant in participants.iter().skip(1) {
        loop {
            sender.send(Recipients::One(participant.clone()), vec![0], false);
            select! {
                result = receiver.recv() => {
                    let (peer, _) = result.expect("readiness channel closed");
                    if &peer == participant {
                        break;
                    }
                },
                _ = context.sleep(Duration::from_millis(10)) => {},
            }
        }
    }

    handles
}

#[derive(Clone)]
pub(crate) struct RecordingBlocker<P: PublicKey, B> {
    source: P,
    inner: B,
    blocked: Arc<Mutex<BTreeSet<(P, P)>>>,
}

impl<P: PublicKey, B> RecordingBlocker<P, B> {
    pub(crate) fn new(source: P, inner: B, blocked: Arc<Mutex<BTreeSet<(P, P)>>>) -> Self {
        Self {
            source,
            inner,
            blocked,
        }
    }
}

impl<P, B> Blocker for RecordingBlocker<P, B>
where
    P: PublicKey,
    B: Blocker<PublicKey = P>,
{
    type PublicKey = P;

    #[allow(
        clippy::disallowed_methods,
        reason = "recording wrapper forwards the real lookup Blocker implementation"
    )]
    fn block(&mut self, public_key: P) -> Feedback {
        let feedback = self.inner.block(public_key.clone());
        if feedback.accepted() {
            self.blocked
                .lock()
                .insert((self.source.clone(), public_key));
        }
        feedback
    }
}
