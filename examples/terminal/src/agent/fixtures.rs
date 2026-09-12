//! Real Current/MMB fixtures for wallet persistence and evidence tests.

use crate::protocol::{Key, state_config};
use commonware_clearing::bajillion::qmdb::{State, StateOpening, StateRoot, account_key};
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_parallel::Sequential;
use commonware_runtime::{Runner as _, deterministic};
use std::{collections::BTreeMap, num::NonZeroU64};

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
