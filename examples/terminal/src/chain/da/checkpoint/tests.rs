//! The validator's latest control Commit owns both recovery and signer memory.

use super::*;
use crate::chain::da::tests::Fixture;
use commonware_clearing::bajillion::logs::Floors;
use commonware_codec::Encode as _;
use commonware_runtime::{Runner as _, Storage as _, Supervisor as _, deterministic};

#[test]
fn ack_control_uses_native_qmdb_with_bounded_history() {
    let ((deployment, expected), crash) =
        deterministic::Runner::default().start_and_recover(|context| async move {
            let mut fixture = Fixture::new(&context, "ack_native", 8).await;
            let (ballot, _, prepared) = fixture
                .prepare(
                    3,
                    3,
                    Floors {
                        activity: 0,
                        payouts: 0,
                    },
                )
                .await;
            fixture.candidate(ballot, prepared).await;
            let deployment = fixture.lane.deployment.clone();
            let mut store = fixture.lane.checkpoint.take().unwrap();
            for generation in 1..129 {
                store = store.stage(generation).await.unwrap();
                store = store.retired().await.unwrap();
            }
            let expected = store.get().unwrap().encode();
            let blobs = context
                .scan(&format!(
                    "ack_native-{}-ack-control_data",
                    deployment.digest()
                ))
                .await
                .expect("validator ACKs must be retained by the native QMDB");
            assert!(blobs.len() <= 2, "old ACK sections were not pruned");
            (deployment, expected)
        });
    deterministic::Runner::from(crash).start(|context| async move {
        let store = Store::open(context.child("reopen"), "ack_native", deployment.digest())
            .await
            .unwrap();
        assert_eq!(store.get().unwrap().encode(), expected);
        assert!(store.get().unwrap().decision.is_some());
        assert!(store.get().unwrap().candidate.is_some());
        let blobs = context
            .scan(&format!(
                "ack_native-{}-ack-control_data",
                deployment.digest()
            ))
            .await
            .unwrap();
        assert!(blobs.len() <= 2);
    });
}
