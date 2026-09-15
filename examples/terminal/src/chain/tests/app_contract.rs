use super::*;
use crate::chain::types::{Batch, Sealed};

fn application(native: &NativeGenesis) -> (App<Scheme, ()>, Block) {
    let genesis = Block::genesis(
        ed25519::PrivateKey::from_seed(0).public_key(),
        native.chain_id(),
        500,
        initial_sync_target::<deterministic::Context>(),
    );
    let app = App::new(
        genesis.clone(),
        Timing::DEFAULT,
        native.clone(),
        Finalized::default(),
    );
    (app, genesis)
}

async fn candidate(
    batches: Batch<deterministic::Context>,
    parent: &Block,
    native: &NativeGenesis,
    timestamp: u64,
    transactions: Vec<SettlementTx>,
) -> (Block, Sealed<deterministic::Context>) {
    let height = parent.height.next();
    let sealed = execute(
        batches,
        height,
        timestamp,
        &Timing::DEFAULT,
        native,
        &transactions,
    )
    .await
    .unwrap();
    let block = Block {
        context: Context {
            round: Round::new(Epoch::zero(), View::new(height.get())),
            leader: parent.context.leader.clone(),
            parent: (View::new(parent.height.get()), parent.digest()),
        },
        parent: parent.digest(),
        height,
        timestamp,
        state_root: sealed.root(),
        ops_root: sealed.ops_root(),
        range: non_empty_range!(sealed.sync_boundary(), sealed.bounds().tip.size),
        transactions,
    };
    (block, sealed)
}

async fn replay(
    context: &deterministic::Context,
    app: &mut App<Scheme, ()>,
    block: &Block,
    batches: Batch<deterministic::Context>,
) -> Option<Sealed<deterministic::Context>> {
    commonware_macros::select! {
        result = app.apply((context.child("replay"), block.context.clone()), block, batches) => result,
        _ = context.sleep(Duration::from_secs(1)) => panic!("replay waited for vote-time drift"),
    }
}

#[test]
fn apply_rejects_canonical_root_mismatch() {
    deterministic::Runner::default().start(|context| async move {
        let db = open(context.child("db"), "apply-root-contract").await;
        let native = native();
        let (mut app, genesis) = application(&native);
        let before = db.read().await.root();
        let (block, expected) = candidate(
            db.new_batches().await,
            &genesis,
            &native,
            genesis.timestamp + 1,
            Vec::new(),
        )
        .await;
        let wrong = Block {
            state_root: Digest::EMPTY,
            ..block.clone()
        };
        assert_ne!(wrong.state_root, expected.root());
        assert!(
            app.verify(
                (context.child("verify"), wrong.context.clone()),
                marshal::ancestry::from_iter([Arc::new(wrong.clone()), Arc::new(genesis)]),
                db.new_batches().await,
            )
            .await
            .is_none()
        );
        assert!(
            replay(&context, &mut app, &wrong, db.new_batches().await)
                .await
                .is_none()
        );
        let actual = replay(&context, &mut app, &block, db.new_batches().await)
            .await
            .unwrap();
        assert_eq!(
            (actual.root(), actual.ops_root()),
            (expected.root(), expected.ops_root())
        );
        assert_eq!(db.read().await.root(), before);
    });
}

#[test]
fn apply_uses_the_configured_genesis_timestamp() {
    deterministic::Runner::default().start(|context| async move {
        let db = open(context.child("db"), "apply-genesis-clock-contract").await;
        let native = native();
        let (mut app, genesis) = application(&native);
        let before = db.read().await.root();
        for timestamp in [1, genesis.timestamp - 1, genesis.timestamp, 0] {
            let (mut block, _) = candidate(
                db.new_batches().await,
                &genesis,
                &native,
                timestamp.max(1),
                Vec::new(),
            )
            .await;
            block.timestamp = timestamp;
            assert!(
                app.verify(
                    (context.child("verify"), block.context.clone()),
                    marshal::ancestry::from_iter([
                        Arc::new(block.clone()),
                        Arc::new(genesis.clone())
                    ]),
                    db.new_batches().await,
                )
                .await
                .is_none()
            );
            assert!(
                replay(&context, &mut app, &block, db.new_batches().await)
                    .await
                    .is_none()
            );
            assert_eq!(db.read().await.root(), before);
        }
        let (block, expected) = candidate(
            db.new_batches().await,
            &genesis,
            &native,
            genesis.timestamp + 1,
            Vec::new(),
        )
        .await;
        let actual = replay(&context, &mut app, &block, db.new_batches().await)
            .await
            .unwrap();
        assert_eq!(actual.root(), expected.root());
    });
}

#[test]
fn apply_uses_parent_batch_time_across_registration_without_clock_waits() {
    deterministic::Runner::default().start(|context| async move {
        let db = open(context.child("db"), "apply-parent-clock-contract").await;
        let native = native();
        let (mut app, genesis) = application(&native);
        let registration = RegisterDeploymentRequest::sign(
            native.chain_id(),
            Sha256::hash(&[b"apply-contract-registration"]),
            operator_ack_key(0),
            ed25519::PrivateKey::from_seed(88_888).public_key(),
            1024,
            native.registration_fee,
            &operator_signer(0),
        );
        let added = registration.deployment_id();
        let timestamp = now(&context).max(genesis.timestamp) + MAX_TIMESTAMP_DRIFT + 10_000;
        let (first, expected) = candidate(
            db.new_batches().await,
            &genesis,
            &native,
            timestamp,
            vec![SettlementTx::RegisterDeployment(registration)],
        )
        .await;
        let first_batch = replay(&context, &mut app, &first, db.new_batches().await)
            .await
            .unwrap();
        assert_eq!(first_batch.root(), expected.root());
        drop(expected);
        let (second, expected) = candidate(
            <Database<deterministic::Context> as DatabaseSet<_>>::fork_batches(&first_batch),
            &first,
            &native,
            timestamp + 1,
            Vec::new(),
        )
        .await;
        let expected_roots = (expected.root(), expected.ops_root());
        drop(expected);

        // The applied database is at genesis; this parent exists only in its batch.
        for stale_timestamp in [timestamp - 1, timestamp] {
            let stale = Block {
                timestamp: stale_timestamp,
                ..second.clone()
            };
            assert!(
                replay(
                    &context,
                    &mut app,
                    &stale,
                    <Database<deterministic::Context> as DatabaseSet<_>>::fork_batches(
                        &first_batch
                    ),
                )
                .await
                .is_none()
            );
        }
        let pending = replay(
            &context,
            &mut app,
            &second,
            <Database<deterministic::Context> as DatabaseSet<_>>::fork_batches(&first_batch),
        )
        .await
        .unwrap();
        assert_eq!((pending.root(), pending.ops_root()), expected_roots);
        drop(pending);
        db.apply(first_batch).await;
        let directory = registry(&db, &native).await.unwrap();
        assert_eq!(directory.len(), native.deployments.len() + 1);
        assert!(directory.contains(&added));
        let applied = replay(&context, &mut app, &second, db.new_batches().await)
            .await
            .unwrap();
        assert_eq!((applied.root(), applied.ops_root()), expected_roots);
        db.apply(applied).await;
        for deployment in &directory {
            let Some(Record::Status(status)) = read(&db, &status_key(deployment)).await else {
                panic!("registered deployment has no status");
            };
            assert_eq!(status.timestamp, second.timestamp);
        }
    });
}
