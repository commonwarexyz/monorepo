use super::{fixture::ReadFixture, *};
use crate::service::{registered_operator, start_observation};
use commonware_actor::mailbox::{self, Receiver as MailboxReceiver};
use commonware_p2p::utils::mocks::{InertSender, inert_channel};
use std::net::SocketAddr;

type Backend = Node<deterministic::Context, InertSender<ed25519::PublicKey>>;

fn registration(native: &NativeGenesis) -> RegisterDeploymentRequest {
    RegisterDeploymentRequest::sign(
        native.chain_id(),
        Sha256::hash(&[b"startup-after-rejected-deposit"]),
        operator_ack_key(0),
        native.deployments[0].network_key.clone(),
        vec![wallets()[0].public_key()],
        1024,
        native.registration_fee,
        &operator_signer(0),
    )
}

fn deposit(native: &NativeGenesis, deployment: Digest, id: &[u8]) -> DepositRequest {
    let wallet = wallets().remove(0);
    DepositRequest::sign(
        native.chain_id(),
        deployment,
        DepositEvent {
            id: Sha256::hash(&[id]),
            account: wallet.public_key(),
            amount: 7,
        },
        wallet.signer(),
    )
}

async fn follower(
    context: &deterministic::Context,
    source: &ReadFixture,
    deployment: Digest,
) -> (ReadFixture, Backend, MailboxReceiver<node::Observed>) {
    let (sender, receiver) = mailbox::new(context.child("observations"), NZUsize!(10));
    let follower_context = context.child("follower");
    let fixture = ReadFixture::configured(
        &follower_context,
        "startup-follower",
        SocketAddr::from(([127, 0, 0, 1], 19_875)),
        source.identity.clone(),
        source.scheme.clone(),
        Some(node::Observer::new(deployment, sender)),
    )
    .await;
    let (sender, _) = inert_channel([source.parent.context.leader.clone()]);
    let backend = Node::new(
        deployment,
        fixture.db.clone(),
        fixture.finalized.clone(),
        sender,
    );
    (fixture, backend, receiver)
}

async fn ready_operator(
    context: &deterministic::Context,
    source: &ReadFixture,
    backend: &mut Backend,
    entry: RegistryEntry,
    held: Option<node::Observed>,
    observations: MailboxReceiver<node::Observed>,
) -> Arc<Mutex<Operator>> {
    assert_eq!(
        entry,
        registration(&source.identity.native)
            .entry(&source.identity.native)
            .unwrap()
    );
    let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
    let (_certifier, mailbox) = node::Certifier::new(
        context.child("certifier"),
        node::Config {
            verifier: protocol.verifier(),
            chain: backend.clone(),
            mailbox_size: NZUsize!(10),
        },
    );
    let peers = (0..committee().unwrap().members().len())
        .map(|index| ed25519::PrivateKey::from_seed(index as u64).public_key())
        .collect::<Vec<_>>();
    let pipeline = node::Pipeline::new(mailbox, &peers, *entry.deployment.digest()).unwrap();
    let epoch_fee =
        source.identity.native.epoch_fee * u64::from(entry.max_dealing_bytes).div_ceil(1024);
    let operator = Arc::new(Mutex::new(
        Operator::open_remote(
            Path::new(":memory:"),
            NonZeroUsize::MIN,
            pipeline,
            &entry.deployment,
            operator_signer(0),
            operator_ack_signer(0),
            epoch_fee,
        )
        .unwrap(),
    ));
    if let Some(held) = held {
        observe(context, backend, &operator, held).await.unwrap();
    }
    start_observation(
        context,
        backend,
        operator.clone(),
        observations,
        source.identity.timing(),
    )
    .await
    .expect("startup reaches the production observation and fresh-state gate");
    operator
}

#[test]
fn dynamic_startup_skips_rejected_preregistration_deposit() {
    deterministic::Runner::timed(Duration::from_secs(90)).start(|context| async move {
        let source_context = context.child("source");
        let mut source = ReadFixture::new(&source_context).await;
        let native = source.identity.native.clone();
        let request = registration(&native);
        let deployment = request.deployment_id();
        let rejected = deposit(&native, deployment, b"unregistered-startup-deposit");
        let before = native_balance(&source.db, &native, &rejected.event.account)
            .await
            .unwrap();
        let first = source
            .direct(&context, vec![SettlementTx::Deposit(rejected.clone())])
            .await;
        assert_eq!(
            read(&source.db, &deposit_key(&deployment, &rejected.event.id)).await,
            None
        );
        assert_eq!(
            registry_entry(&source.db, &native, &deployment)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            native_balance(&source.db, &native, &rejected.event.account)
                .await
                .unwrap(),
            before
        );
        let registered = source
            .direct(
                &context,
                vec![SettlementTx::RegisterDeployment(request.clone())],
            )
            .await;
        assert_eq!(
            registry_entry(&source.db, &native, &deployment)
                .await
                .unwrap(),
            Some(request.entry(&native).unwrap())
        );

        let (mut fixture, mut backend, mut observations) =
            follower(&context, &source, deployment).await;
        fixture.publish(first.clone()).await;
        fixture.publish(registered.clone()).await;
        fixture.wait_applied(&context, &first).await;
        assert_eq!(
            fixture.marshal.get_processed_height().await,
            Some(Height::zero())
        );
        assert_eq!(
            fixture.marshal.get_block(registered.height).await,
            Some(registered.clone())
        );
        assert!(
            fixture
                .marshal
                .get_finalization(registered.height)
                .await
                .is_some()
        );
        assert_eq!(
            registry_entry(&fixture.db, &native, &deployment)
                .await
                .unwrap(),
            None
        );

        let result = registered_operator(
            &context,
            &mut backend,
            native.chain_id(),
            deployment,
            &mut observations,
        )
        .await;
        if let Err(error) = &result {
            eprintln!(
                "startup error={error:#}; applied={:?}; processed={:?}; registration_available={}",
                fixture.finalized.latest().map(|tip| tip.height),
                fixture.marshal.get_processed_height().await,
                fixture.marshal.get_block(registered.height).await.is_some()
            );
        }
        let (entry, held) =
            result.expect("rejected historical intake must not block its later registration");
        fixture.wait_applied(&context, &registered).await;
        let operator =
            ready_operator(&context, &source, &mut backend, entry, held, observations).await;
        assert_eq!(operator.lock().snapshot().unwrap().accounts[0].balance, 0);
        assert_eq!(
            read(&fixture.db, &deposit_key(&deployment, &rejected.event.id)).await,
            None
        );
        assert_eq!(
            native_balance(&fixture.db, &native, &rejected.event.account)
                .await
                .unwrap(),
            before
        );
        assert_eq!(
            registry_entry(&fixture.db, &native, &deployment)
                .await
                .unwrap(),
            Some(request.entry(&native).unwrap())
        );
        assert_eq!(backend.status(&context).await.unwrap().custody, 0);
    });
}

#[test]
fn dynamic_startup_without_registration_releases_rejected_history_and_stops() {
    deterministic::Runner::timed(Duration::from_secs(90)).start(|context| async move {
        let source_context = context.child("source");
        let mut source = ReadFixture::new(&source_context).await;
        let native = source.identity.native.clone();
        let deployment = registration(&native).deployment_id();
        let rejected = deposit(&native, deployment, b"never-registered-startup-deposit");
        let first = source
            .direct(&context, vec![SettlementTx::Deposit(rejected.clone())])
            .await;
        let (mut fixture, mut backend, mut observations) =
            follower(&context, &source, deployment).await;
        fixture.publish(first.clone()).await;
        fixture.wait_applied(&context, &first).await;
        let result = registered_operator(
            &context,
            &mut backend,
            native.chain_id(),
            deployment,
            &mut observations,
        )
        .await;
        assert!(
            result
                .err()
                .expect("unknown deployment must remain bounded")
                .to_string()
                .contains("operator registration did not appear")
        );
        assert_eq!(
            fixture.marshal.get_processed_height().await,
            Some(first.height)
        );
        assert_eq!(
            registry_entry(&fixture.db, &native, &deployment)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            read(&fixture.db, &deposit_key(&deployment, &rejected.event.id)).await,
            None
        );
    });
}

#[test]
fn dynamic_startup_stages_applied_deposit_before_acknowledging() {
    deterministic::Runner::timed(Duration::from_secs(20)).start(|context| async move {
        let source_context = context.child("source");
        let mut source = ReadFixture::new(&source_context).await;
        let native = source.identity.native.clone();
        let request = registration(&native);
        let deployment = request.deployment_id();
        let registered = source
            .direct(&context, vec![SettlementTx::RegisterDeployment(request)])
            .await;
        let applied = deposit(&native, deployment, b"applied-startup-deposit");
        let deposited = source
            .direct(&context, vec![SettlementTx::Deposit(applied.clone())])
            .await;
        let (mut fixture, mut backend, mut observations) =
            follower(&context, &source, deployment).await;
        fixture.publish(registered.clone()).await;
        fixture.publish(deposited.clone()).await;
        fixture.wait_applied(&context, &deposited).await;
        assert_eq!(
            fixture.marshal.get_processed_height().await,
            Some(registered.height)
        );
        let (entry, held) = registered_operator(
            &context,
            &mut backend,
            native.chain_id(),
            deployment,
            &mut observations,
        )
        .await
        .unwrap();
        assert!(
            held.is_some(),
            "startup retains the applied deposit for durable staging"
        );
        assert_eq!(
            fixture.marshal.get_processed_height().await,
            Some(registered.height)
        );
        let operator =
            ready_operator(&context, &source, &mut backend, entry, held, observations).await;
        assert_eq!(operator.lock().snapshot().unwrap().accounts[0].balance, 7);
        while fixture.marshal.get_processed_height().await != Some(deposited.height) {
            context.sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(operator.lock().snapshot().unwrap().accounts[0].balance, 7);
        assert_eq!(backend.status(&context).await.unwrap().custody, 7);
    });
}
