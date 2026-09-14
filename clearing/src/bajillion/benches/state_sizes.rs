use super::fixtures::{BenchState, runner, state_config};
use commonware_clearing::bajillion::qmdb::{AccountKey, StateHead, StateLookup, account_key};
use commonware_codec::{Decode, Encode, EncodeSize};
use commonware_cryptography::{Sha256, Signer as _, sha256::Digest};
use commonware_cryptography_curve25519::signing::SigningKey;
use commonware_runtime::{Runner as _, Supervisor as _};
use commonware_storage::qmdb::current::ordered::ExclusionProof;
use std::num::NonZeroU64;

async fn report(label: &str, state: &BenchState, head: StateHead<Digest>, key: &AccountKey) {
    let lookup = state
        .lookup_at(head.root(), head.operations(), key)
        .await
        .expect("root and operation count identify the prefix");
    let wire = lookup.encode();
    assert_eq!(wire.len(), lookup.encode_size());
    let decoded = StateLookup::<Digest>::decode_cfg(wire.clone(), &wire.len())
        .expect("complete exclusion decodes");
    assert_eq!(decoded, lookup);
    assert_eq!(decoded.resolve::<Sha256>(&head.root(), key).unwrap(), None);
    if head.live_accounts() == 0 {
        let StateLookup::Absent(ExclusionProof::Commit(_, metadata)) = &decoded else {
            panic!("empty state discloses its commit");
        };
        assert!(metadata.is_none());
        assert_eq!(head.liability(), 0);
    } else {
        assert!(matches!(
            decoded,
            StateLookup::Absent(ExclusionProof::KeyValue(_, _))
        ));
    }
    println!(
        "clearing state boundary: context={label} operations={} live_accounts={} liability={} root_bytes={} exclusion_lookup_bytes={}",
        head.operations(),
        head.live_accounts(),
        head.liability(),
        head.root().encode_size(),
        wire.len(),
    );
}

pub(crate) fn benches() {
    runner().start(|runtime| async move {
        let key = account_key(&SigningKey::from_seed(10_000).public_key()).unwrap();
        let missing = account_key(&SigningKey::from_seed(u64::MAX).public_key()).unwrap();
        let mut state = BenchState::open(
            runtime.child("state"),
            state_config(&runtime, "state-boundary"),
        )
        .await
        .expect("native open");
        assert!(state.is_bootstrap());
        report("bootstrap", &state, *state.head(), &missing).await;
        let genesis = state.prepare(state.head(), Vec::new()).await.unwrap();
        state = state.apply(genesis).await.unwrap();
        let empty = *state.head();
        report("empty_genesis", &state, empty, &missing).await;
        let funded = state
            .prepare(state.head(), vec![(key.clone(), NonZeroU64::new(1))])
            .await
            .unwrap();
        state = state.apply(funded).await.unwrap();
        assert_eq!(state.liability(), 1);
        assert_eq!(state.live_accounts(), 1);
        report("funded", &state, *state.head(), &missing).await;
        let cleared = state
            .prepare(state.head(), vec![(key, None)])
            .await
            .unwrap();
        state = state.apply(cleared).await.unwrap();
        report("cleared", &state, *state.head(), &missing).await;
        state = state.commit().await.unwrap();
        let head = *state.head();
        drop(state);
        let state = BenchState::open(
            runtime.child("state"),
            state_config(&runtime, "state-boundary"),
        )
        .await
        .expect("native suffix recovery");
        assert_eq!(*state.head(), head);
        report("reopened_empty", &state, head, &missing).await;
        report("historical_empty", &state, empty, &missing).await;
        assert_eq!(*state.head(), head);
    });
}
