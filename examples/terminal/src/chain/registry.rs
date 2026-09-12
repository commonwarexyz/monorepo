//! Certified operator membership updates for authenticated peer tracking.

use crate::chain::{
    native::{NativeGenesis, RegistryEntry},
    state::{self, Record},
    types::Database,
};
use commonware_cryptography::{ed25519, sha256::Digest};
use commonware_p2p::{Manager, TrackedPeers};
use commonware_runtime::{Clock, Handle, Spawner};
use commonware_storage::{Context as StorageContext, mmr, qmdb::Error as QmdbError};
use commonware_utils::{ordered::Set, sync::Mutex};
use std::{sync::Arc, time::Duration};

/// Immutable registrations observed in certified applied state.
#[derive(Clone)]
pub(crate) struct RegistryView(Arc<Mutex<Vec<Arc<RegistryEntry>>>>);

impl RegistryView {
    /// Seeds the view with authenticated genesis registrations.
    pub(crate) fn new(entries: Vec<RegistryEntry>) -> Self {
        Self(Arc::new(Mutex::new(
            entries.into_iter().map(Arc::new).collect(),
        )))
    }

    /// Whether the certified registry authorizes this deployment.
    #[cfg(test)]
    pub(crate) fn contains(&self, deployment: &Digest) -> bool {
        self.0
            .lock()
            .iter()
            .any(|entry| entry.deployment.digest() == deployment)
    }

    /// Whether any certified deployment authorizes this network peer.
    pub(crate) fn contains_peer(&self, peer: &ed25519::PublicKey) -> bool {
        self.0.lock().iter().any(|entry| &entry.network_key == peer)
    }

    /// The immutable policy and peer binding for one deployment.
    pub(crate) fn get(&self, deployment: &Digest) -> Option<Arc<RegistryEntry>> {
        self.0
            .lock()
            .iter()
            .find(|entry| entry.deployment.digest() == deployment)
            .cloned()
    }

    /// All registrations, bounded by native admission policy.
    pub(crate) fn entries(&self) -> Vec<RegistryEntry> {
        self.0
            .lock()
            .iter()
            .map(|entry| entry.as_ref().clone())
            .collect()
    }
}

/// Reads only registrations after the view's certified, immutable prefix.
/// Directory and point records share one applied database snapshot.
async fn additions<E>(
    db: &Database<E>,
    native: &NativeGenesis,
    known: usize,
) -> Result<Vec<RegistryEntry>, QmdbError<mmr::Family>>
where
    E: StorageContext + Spawner,
{
    let chain = native.chain_id();
    let guard = db.read().await;
    let ids = match guard.get(&state::registry_key(&chain)).await? {
        Some(Record::Registry(ids)) => ids,
        None => return Ok(native.deployments.iter().skip(known).cloned().collect()),
        Some(_) => unreachable!("registry key has a directory record"),
    };
    let mut entries = Vec::new();
    for id in ids.into_iter().skip(known) {
        let Some(Record::RegistryEntry(entry)) =
            guard.get(&state::registry_entry_key(&chain, &id)).await?
        else {
            unreachable!("every directory member has its immutable entry");
        };
        assert_eq!(
            *entry.deployment.digest(),
            id,
            "registry entry belongs to its key"
        );
        entries.push(entry);
    }
    Ok(entries)
}

/// Publishes a new authenticated peer generation when certified membership
/// changes. The committee remains primary in every generation; registered
/// operators are non-signing secondaries. Generation zero is installed by
/// the caller before starting the network.
pub(crate) fn watch<E, M>(
    context: E,
    db: Database<E>,
    native: NativeGenesis,
    registry: RegistryView,
    mut manager: M,
    committee: Set<ed25519::PublicKey>,
) -> Handle<()>
where
    E: Spawner + Clock + StorageContext,
    M: Manager<PublicKey = ed25519::PublicKey>,
{
    context.spawn(move |context| async move {
        let mut secondaries = Set::from_iter_dedup(
            native
                .deployments
                .iter()
                .map(|entry| entry.network_key.clone()),
        );
        let initial_peers = secondaries.len();
        loop {
            let known = registry.0.lock().len();
            let entries = additions(&db, &native, known)
                .await
                .expect("failed to read the certified operator registry");
            if !entries.is_empty() {
                let peers = Set::from_iter_dedup(
                    secondaries
                        .iter()
                        .cloned()
                        .chain(entries.iter().map(|entry| entry.network_key.clone())),
                );
                if peers != secondaries {
                    // Registrations are immutable and append-only, so peer cardinality
                    // gives every observer the same generation even after catch-up.
                    let generation = (peers.len() - initial_peers) as u64;
                    assert!(
                        manager
                            .track(
                                generation,
                                TrackedPeers::new(committee.clone(), peers.clone())
                            )
                            .accepted(),
                        "peer tracker stopped accepting registry updates"
                    );
                    secondaries = peers;
                }
                registry.0.lock().extend(entries.into_iter().map(Arc::new));
            }
            context.sleep(Duration::from_millis(100)).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chain::{
            tx::{RegisterDeploymentRequest, SettlementTx},
            validator::{PAGE_CACHE_SIZE, PAGE_SIZE, db_config},
        },
        protocol::{self, Timing},
    };
    use commonware_actor::Feedback;
    use commonware_consensus::types::Height;
    use commonware_cryptography::{Hasher as _, Sha256, Signer as _};
    use commonware_glue::stateful::db::DatabaseSet;
    use commonware_macros::select;
    use commonware_p2p::{PeerSetSubscription, Provider};
    use commonware_runtime::{
        Metrics as _, Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
    };
    use commonware_utils::channel::mpsc;

    type Tracked = Arc<Mutex<Vec<(u64, TrackedPeers<ed25519::PublicKey>)>>>;

    #[derive(Clone, Debug, Default)]
    struct Recorder(Tracked);

    impl Provider for Recorder {
        type PublicKey = ed25519::PublicKey;
        async fn peer_set(&mut self, _: u64) -> Option<TrackedPeers<Self::PublicKey>> {
            None
        }
        async fn subscribe(&mut self) -> PeerSetSubscription<Self::PublicKey> {
            mpsc::unbounded_channel().1
        }
    }

    impl Manager for Recorder {
        fn track<R>(&mut self, id: u64, peers: R) -> Feedback
        where
            R: Into<TrackedPeers<Self::PublicKey>> + Send,
        {
            self.0.lock().push((id, peers.into()));
            Feedback::Ok
        }
    }

    fn reads(context: &deterministic::Context, suffix: &str) -> u64 {
        context
            .encode()
            .lines()
            .filter_map(|line| {
                let (name, value) = line.split_once(' ')?;
                name.ends_with(suffix)
                    .then(|| value.parse::<u64>().unwrap())
            })
            .sum()
    }

    #[test]
    fn registry_refresh_reads_only_new_point_entries() {
        deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
            let mut native = crate::chain::harness::native(protocol::deployments());
            for entry in &mut native.deployments {
                entry.network_key = ed25519::PrivateKey::from_seed(1).public_key();
            }
            let db = <Database<deterministic::Context> as DatabaseSet<_>>::init(
                context.child("db"),
                db_config(
                    "registry-polls",
                    CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                ),
            )
            .await;
            let known = native.deployments.len();
            let mut previous = db.read().await.root();
            for height in 1..=2 {
                let sealed = state::execute(
                    db.new_batches().await,
                    Height::new(height),
                    height,
                    &Timing::DEFAULT,
                    &native,
                    &[],
                )
                .await
                .unwrap();
                db.apply(sealed).await;
                let current = db.read().await.root();
                assert_ne!(previous, current);
                previous = current;
                let keys = reads(&context, "_get_calls_total");
                let journal = reads(&context, "_read_calls_total");
                assert!(additions(&db, &native, known).await.unwrap().is_empty());
                assert!(
                    reads(&context, "_read_calls_total") > journal,
                    "registry was not observed"
                );
                assert_eq!(
                    reads(&context, "_get_calls_total") - keys,
                    1,
                    "unchanged point entries were reloaded"
                );
            }
            let requests = (0..2)
                .map(|index| {
                    RegisterDeploymentRequest::sign(
                        native.chain_id(),
                        Sha256::hash(&[b"new-registry-point", &[index]]),
                        protocol::operator_ack_key(0),
                        ed25519::PrivateKey::from_seed(2).public_key(),
                        vec![protocol::wallets()[0].public_key()],
                        1024,
                        native.registration_fee,
                        &protocol::operator_signer(0),
                    )
                })
                .collect::<Vec<_>>();
            let expected = requests
                .iter()
                .map(|request| request.entry(&native).unwrap())
                .collect::<Vec<_>>();
            let txs = requests
                .into_iter()
                .map(SettlementTx::RegisterDeployment)
                .collect::<Vec<_>>();
            let sealed = state::execute(
                db.new_batches().await,
                Height::new(3),
                3,
                &Timing::DEFAULT,
                &native,
                &txs,
            )
            .await
            .unwrap();
            db.apply(sealed).await;
            let keys = reads(&context, "_get_calls_total");
            assert_eq!(additions(&db, &native, known).await.unwrap(), expected);
            assert_eq!(
                reads(&context, "_get_calls_total") - keys,
                3,
                "refresh must read directory and two new points"
            );
            let keys = reads(&context, "_get_calls_total");
            assert!(additions(&db, &native, known + 2).await.unwrap().is_empty());
            assert_eq!(reads(&context, "_get_calls_total") - keys, 1);
        });
    }

    #[test]
    fn applied_registration_updates_peer_generation_and_recovers() {
        deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
            let old_peer = ed25519::PrivateKey::from_seed(1).public_key();
            let new_peer = ed25519::PrivateKey::from_seed(2).public_key();
            let mut native = crate::chain::harness::native(vec![protocol::deployments().remove(0)]);
            native.deployments[0].network_key = old_peer.clone();
            let view = RegistryView::new(native.deployments.clone());
            let db = <Database<deterministic::Context> as DatabaseSet<_>>::init(
                context.child("db"), db_config("registry-test", CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE)),
            ).await;
            let committee = Set::from_iter_dedup([ed25519::PrivateKey::from_seed(3).public_key()]);
            let recorder = Recorder::default();
            let handle = watch(context.child("registry"), db.clone(), native.clone(), view.clone(), recorder.clone(), committee.clone());
            let request = RegisterDeploymentRequest::sign(
                native.chain_id(), Sha256::hash(&[b"dynamic-registration"]), protocol::operator_ack_key(0),
                new_peer.clone(), vec![protocol::wallets()[0].public_key()], 1024,
                native.registration_fee, &protocol::operator_signer(0),
            );
            let deployment = request.deployment_id();
            let sealed = state::execute(
                db.new_batches().await, Height::new(1), 1, &Timing::DEFAULT, &native,
                &[SettlementTx::RegisterDeployment(request)],
            ).await.unwrap();
            context.sleep(Duration::from_millis(200)).await;
            assert!(!view.contains(&deployment));
            assert!(recorder.0.lock().is_empty());
            assert_eq!(state::registry(&db, &native).await.unwrap().len(), 1);
            db.apply(sealed).await;
            select! {
                _ = async { while !view.contains(&deployment) { context.sleep(Duration::from_millis(1)).await; } } => {},
                _ = context.sleep(Duration::from_secs(1)) => panic!("applied registry was not published"),
            }
            let tracked = recorder.0.lock().clone();
            assert_eq!(tracked.len(), 1);
            assert_eq!(tracked[0].0, 1);
            assert_eq!(tracked[0].1.primary, committee);
            assert_eq!(tracked[0].1.secondary, Set::from_iter_dedup([old_peer, new_peer.clone()]));
            assert_eq!(view.get(&deployment).unwrap().deployment.accounts[0].balance, 0);
            let request = RegisterDeploymentRequest::sign(
                native.chain_id(), Sha256::hash(&[b"same-peer-registration"]), protocol::operator_ack_key(0),
                new_peer, vec![protocol::wallets()[0].public_key()], 2048,
                native.registration_fee, &protocol::operator_signer(0),
            );
            let second = request.deployment_id();
            let sealed = state::execute(db.new_batches().await, Height::new(2), 2, &Timing::DEFAULT, &native,
                &[SettlementTx::RegisterDeployment(request)]).await.unwrap();
            db.apply(sealed).await;
            select! {
                _ = async { while !view.contains(&second) { context.sleep(Duration::from_millis(1)).await; } } => {},
                _ = context.sleep(Duration::from_secs(1)) => panic!("same-peer registration was not published"),
            }
            assert_eq!(recorder.0.lock().len(), 1);
            let request = RegisterDeploymentRequest::sign(
                native.chain_id(), Sha256::hash(&[b"third-peer-registration"]), protocol::operator_ack_key(0),
                ed25519::PrivateKey::from_seed(4).public_key(), vec![protocol::wallets()[0].public_key()], 2048,
                native.registration_fee, &protocol::operator_signer(0),
            );
            let third = request.deployment_id();
            let sealed = state::execute(db.new_batches().await, Height::new(3), 3, &Timing::DEFAULT, &native,
                &[SettlementTx::RegisterDeployment(request)]).await.unwrap();
            db.apply(sealed).await;
            select! {
                _ = async { while !view.contains(&third) { context.sleep(Duration::from_millis(1)).await; } } => {},
                _ = context.sleep(Duration::from_secs(1)) => panic!("third-peer registration was not published"),
            }
            assert_eq!(recorder.0.lock().len(), 2);
            assert_eq!(recorder.0.lock()[1].0, 2);
            assert_eq!(state::registry(&db, &native).await.unwrap().len(), 4);
            handle.abort();
            let _ = handle.await;
            assert!(db.finalize().await.durable().await);
            let root = db.read().await.root();
            drop(db);
            let db = <Database<deterministic::Context> as DatabaseSet<_>>::init(
                context.child("reopened"), db_config("registry-test", CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE)),
            ).await;
            assert_eq!(db.read().await.root(), root);
            assert_eq!(state::registry(&db, &native).await.unwrap().len(), 4);
            let restored = RegistryView::new(native.deployments.clone());
            let replay = Recorder::default();
            watch(context.child("restarted"), db, native, restored.clone(), replay.clone(), committee);
            select! {
                _ = async { while !restored.contains(&deployment) { context.sleep(Duration::from_millis(1)).await; } } => {},
                _ = context.sleep(Duration::from_secs(1)) => panic!("registry was not restored"),
            }

            // Catch-up must name the same final peer set as incremental observation.
            assert_eq!(replay.0.lock()[0].0, recorder.0.lock().last().unwrap().0);
            assert!(restored.contains(&second));
            assert!(restored.contains(&third));
        });
    }
}
