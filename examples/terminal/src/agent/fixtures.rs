//! Shared wallet persistence and Current/MMB evidence fixtures.

use crate::protocol::{Key, state_config};
use commonware_clearing::bajillion::qmdb::{State, StateOpening, StateRoot, account_key};
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_parallel::Sequential;
use commonware_runtime::{Runner as _, deterministic};
use std::{
    collections::BTreeMap,
    fs,
    num::NonZeroU64,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static TEMP_DATABASE_ID: AtomicU64 = AtomicU64::new(0);

pub(super) struct TempDatabase {
    directory: PathBuf,
    path: PathBuf,
}

impl TempDatabase {
    pub(super) fn new() -> Self {
        let id = TEMP_DATABASE_ID.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "commonware-terminal-agent-{}-{id}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("agent.sqlite");
        Self { directory, path }
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDatabase {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

pub(super) struct StateFixture {
    root: StateRoot<Digest>,
    openings: BTreeMap<Key, StateOpening<Key, Digest>>,
}

impl StateFixture {
    pub(super) fn new(mut balances: Vec<(Key, u64)>) -> Self {
        balances.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        deterministic::Runner::default().start(|context| async move {
            let genesis = balances
                .iter()
                .map(|(account, balance)| {
                    (
                        account_key(account).unwrap(),
                        NonZeroU64::new(*balance).unwrap(),
                    )
                })
                .collect();
            let config = state_config("wallet-fixture", &context, Sequential);
            let state = State::<_, Sha256>::init(context, config, genesis)
                .await
                .unwrap();
            let root = state.root();
            let mut openings = BTreeMap::new();
            for (account, _) in balances {
                openings.insert(account.clone(), state.opening(account).await.unwrap());
            }
            Self { root, openings }
        })
    }

    pub(super) const fn root(&self) -> StateRoot<Digest> {
        self.root
    }

    pub(super) fn opening(&self, account: &Key) -> Option<StateOpening<Key, Digest>> {
        self.openings.get(account).cloned()
    }
}
