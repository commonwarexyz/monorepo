//! Runtime-owning service loops for the terminal role binaries.

use crate::{
    agent::Agent,
    chain::{
        client::{Chain, Client, EFFECT_ATTEMPTS, Env, POLL},
        native::RegistryEntry,
        node,
        query::Lookup,
        state::{FaultRecord, HardFaultReasonResponse, Record},
        tx::SettlementTx,
    },
    operator::{CloseEvent, Operator, StagedDeposit, rpc as operator_rpc},
    protocol::{MIN_DEALING_BYTES, Timing, short_digest},
    rpc, ui,
};
use anyhow::{Context, Result, bail, ensure};
use commonware_actor::mailbox::Receiver as MailboxReceiver;
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest};
use commonware_runtime::{
    Clock, Handle, Listener, Network, Runner as _, Spawner as _, Supervisor as _, tokio,
};
use commonware_utils::{Acknowledgement as _, sync::Mutex};
use std::{net::SocketAddr, num::NonZeroUsize, path::PathBuf, sync::Arc, time::Duration};

/// Registration attempts before the epoch registration is reported stuck.
const REGISTER_ATTEMPTS: usize = 120;

/// Pause between registration attempts.
const REGISTER_POLL: Duration = Duration::from_millis(500);

/// Certified read-back attempts while the operator's follower catches up to
/// an effect the chain already certified.
const CONFIRM_ATTEMPTS: usize = 8;

/// Pause between read-back attempts.
const CONFIRM_POLL: Duration = Duration::from_millis(100);

fn runtime() -> tokio::Runner {
    tokio::Runner::new(
        tokio::Config::new()
            .with_worker_threads(2)
            .with_connect_timeout(Duration::from_secs(5))
            .with_read_write_timeout(Duration::from_secs(5)),
    )
}

pub(crate) fn run_operator(
    bind: SocketAddr,
    node_dir: PathBuf,
    database: PathBuf,
    workers: NonZeroUsize,
) -> Result<()> {
    let runtime = tokio::Runner::new(
        tokio::Config::new()
            .with_worker_threads(3)
            .with_connect_timeout(Duration::from_secs(5))
            .with_read_write_timeout(Duration::from_secs(5))
            .with_storage_directory(node_dir.join("runtime")),
    );
    runtime.start(move |context| async move {
        // The operator joins the chain as a non-signing p2p secondary: every
        // settlement fact it acts on comes from its own verified finalized
        // state and every settlement input goes onto the transaction channel
        // directly. The close worker certifies over the DA channel through
        // the returned pipeline, and the deposit observation feed surfaces
        // its own deployment's finalized deposit transactions.
        let config = crate::chain::setup::OperatorConfig::load(&node_dir)
            .context("load operator node config")?;
        let (mut chain, pipeline, mut observations, mut handles) =
            node::start(context.child("node"), &node_dir)
                .await
                .context("start operator follower node")?;
        let genesis = crate::chain::setup::read_genesis(&node_dir)?;
        let (entry, held) = registered_operator(
            &context,
            &mut chain,
            genesis.native.chain_id(),
            config.deployment,
            &mut observations,
        )
        .await?;
        ensure!(
            entry.network_key == config.public_key(),
            "operator network key differs from its certified registration"
        );
        ensure!(
            entry.max_dealing_bytes >= MIN_DEALING_BYTES,
            "the stock operator requires a dealing reservation of at least {MIN_DEALING_BYTES} bytes"
        );
        let epoch_fee = genesis
            .native
            .epoch_fee
            .checked_mul(u64::from(entry.max_dealing_bytes).div_ceil(1024))
            .context("epoch fee overflow")?;

        // Execution assigns every epoch deadline at inclusion under the
        // genesis timing policy, so the operator carries no timing knob: it
        // adopts the assigned deadlines from its certified registration read.
        // The one operator is shared between the RPC loop and the deposit
        // observer, locked around each synchronous call and never across an
        // await.
        let operator = Arc::new(Mutex::new(
            Operator::open_remote(
                &database,
                workers,
                pipeline,
                &entry.deployment,
                config.clearing,
                config.ack,
                epoch_fee,
            )
            .context("initialize SQLite operator")?,
        ));

        if let Some(observed) = held {
            observe(&context, &mut chain, &operator, observed).await?;
        }

        let observer_handle = start_observation(
            &context,
            &mut chain,
            operator.clone(),
            observations,
            genesis.timing(),
        )
        .await?;
        handles.push(observer_handle);

        let driver_handle =
            start_close_driver(&context, chain.clone(), operator.clone(), genesis.timing());
        handles.push(driver_handle);
        let mut listener = context.bind(bind).await.context("bind operator RPC")?;

        // The agent-facing RPC loop, supervised alongside the node actors.
        let rpc_handle = context.child("rpc").spawn({
            let mut chain = chain.clone();
            move |context| async move {
                loop {
                    // The runtime folds every accept failure into one error
                    // class, so treat a failed accept as transient instead of
                    // tearing down the operator.
                    let (_, mut sink, mut stream) = match listener.accept().await {
                        Ok(connection) => connection,
                        Err(error) => {
                            eprintln!("accept operator RPC failed; retrying: {error}");
                            context.sleep(rpc::ACCEPT_RETRY_DELAY).await;
                            continue;
                        }
                    };
                    let Ok(request) = rpc::recv_request(&mut stream).await else {
                        continue;
                    };
                    let response = match operator_rpc::decode_request(request) {
                        Ok(request) => {
                            match prepare_request(&context, &mut chain, &operator, &request).await {
                                Ok(Some(response)) => response,
                                Ok(None) => {
                                    operator_rpc::handle_decoded(&mut operator.lock(), request)
                                }
                                Err(error) => rpc::error_response(format!("{error:#}")),
                            }
                        }
                        Err(error) => rpc::error_response(format!("{error:#}")),
                    };
                    let _ = rpc::send_response(&mut sink, &response).await;
                }
            }
        });
        handles.push(rpc_handle);
        Handle::select(handles)
            .await
            .context("operator task failed")
    })
}

pub(crate) async fn registered_operator<E: Env, C: Chain>(
    ctx: &E,
    chain: &mut C,
    chain_id: Digest,
    deployment: Digest,
    observations: &mut MailboxReceiver<node::Observed>,
) -> Result<(RegistryEntry, Option<node::Observed>)> {
    // Registration is immutable. Historical presence authenticates the operator while
    // its follower catches up; historical absence cannot reject a later registration.
    let request = chain.request(Lookup::RegistryEntry {
        chain_id,
        deployment,
    });
    let mut held: Option<node::Observed> = None;
    for attempt in 0..REGISTER_ATTEMPTS {
        if held.is_none() {
            held = observations.try_recv().ok();
        }
        match chain.read(ctx, &request).await {
            Ok(verified) => match verified.record {
                Some(Record::RegistryEntry(entry)) if *entry.deployment.digest() == deployment => {
                    return Ok((entry, held));
                }
                None => {
                    // Immutable registration absence at this applied height proves that
                    // the observed target deposits were rejected before custody intake.
                    if held
                        .as_ref()
                        .is_some_and(|observed| verified.height >= observed.height)
                    {
                        held.take()
                            .expect("the observed height was checked")
                            .ack
                            .acknowledge();
                    }
                }
                Some(_) => bail!("certified registry read returned a foreign record"),
            },
            Err(error) if attempt + 1 == REGISTER_ATTEMPTS => {
                return Err(error.context("read operator registration during catch-up"));
            }
            Err(_) => {}
        }
        ctx.sleep(REGISTER_POLL).await;
    }
    bail!("operator registration did not appear during follower catch-up")
}

/// Starts deposit observation and authenticates the state used to release RPC intake.
pub(crate) async fn start_observation<E: Env, C: Chain + Clone>(
    ctx: &E,
    chain: &mut C,
    operator: Arc<Mutex<Operator>>,
    mut observations: MailboxReceiver<node::Observed>,
    timing: Timing,
) -> Result<Handle<()>> {
    let mut observer_chain = chain.clone();
    let observer_operator = operator.clone();
    let handle = ctx.child("observer").spawn(move |context| async move {
        while let Some(observed) = observations.recv().await {
            match observe(&context, &mut observer_chain, &observer_operator, observed).await {
                Ok(staged) => {
                    for deposit in staged {
                        println!(
                            "observed deposit {}: staged {} into epoch {}",
                            short_digest(&deposit.id),
                            deposit.amount,
                            deposit.epoch
                        );
                    }
                }
                Err(error) => panic!("deposit observation failed: {error:#}"),
            }
        }
    });

    // Applied deposits acknowledge historical blocks before fresh reads can succeed.
    // RPC intake remains gated on the same recent canonical fault check as steady state.
    for attempt in 0..REGISTER_ATTEMPTS {
        match drive_closes(ctx, chain, &operator, timing).await {
            Ok(()) => return Ok(handle),
            Err(error)
                if operator.lock().ensure_store_usable().is_err()
                    || attempt + 1 == REGISTER_ATTEMPTS =>
            {
                handle.abort();
                return Err(
                    error.context("synchronize settlement lifecycle before serving operator RPC")
                );
            }
            Err(_) => {}
        }
        ctx.sleep(REGISTER_POLL).await;
    }
    unreachable!("registration attempt budget is nonzero")
}

/// Reconciles cut epochs with certified admission, finality, and deployment faults.
pub(crate) async fn observe_closes<E: Env, C: Chain>(
    ctx: &E,
    chain: &mut C,
    operator: &Mutex<Operator>,
) -> Result<()> {
    operator.lock().advance_close()?;
    let fault_request = chain.request(Lookup::Fault);
    let fault = match chain.recent(ctx, &fault_request).await?.record {
        Some(Record::Fault(fault)) => Some(fault),
        None => None,
        Some(_) => bail!("certified fault read returned a foreign record"),
    };
    let invalid_batch = fault.as_ref().and_then(|fault| match fault {
        FaultRecord::Settling(settlement) => settlement.invalid_from,
        FaultRecord::Faulted(HardFaultReasonResponse::ProvenChallenge { batch_id, .. }) => {
            Some(*batch_id)
        }
        FaultRecord::Faulted(_) => None,
    });
    let epochs = operator.lock().pending_epochs()?;
    let mut invalid_from = None;
    for epoch in epochs {
        match chain.admitted(ctx, epoch).await? {
            Some(record) if Some(record.batch_id) == invalid_batch => {
                invalid_from = Some(epoch);
                break;
            }
            Some(record) => {
                let mut operator = operator.lock();
                operator.observe_admitted(epoch, &record)?;
                if record.finalized
                    && let Some(CloseEvent::Finished(close)) = operator.poll_close(epoch)?
                {
                    println!("epoch {} close finalized", close.epoch);
                }
            }
            None if fault.is_some() => {
                invalid_from = Some(epoch);
                break;
            }
            None => {}
        }
    }
    if let Some(fault) = fault {
        let mut operator = operator.lock();
        let first = invalid_from.unwrap_or(operator.status()?.epoch);
        operator.fence_suffix(first, format!("certified deployment fault: {fault:?}"))?;
    }
    Ok(())
}

/// Keeps close progress live independently of RPC traffic and an empty backlog.
pub(crate) fn start_close_driver<E: Env, C: Chain>(
    ctx: &E,
    mut chain: C,
    operator: Arc<Mutex<Operator>>,
    timing: Timing,
) -> Handle<()> {
    ctx.child("closes").spawn(move |context| async move {
        loop {
            if let Err(error) = drive_closes(&context, &mut chain, &operator, timing).await {
                operator
                    .lock()
                    .ensure_store_usable()
                    .unwrap_or_else(|fault| panic!("close storage failed: {fault:#}"));
                eprintln!("automatic close progress will retry: {error:#}");
            }
            context.sleep(POLL).await;
        }
    })
}

/// Advances durable admission and finalized custody, then schedules the live epoch.
async fn drive_closes<E: Env, C: Chain>(
    ctx: &E,
    chain: &mut C,
    operator: &Mutex<Operator>,
    timing: Timing,
) -> Result<()> {
    observe_closes(ctx, chain, operator).await?;
    let Some(epoch) = operator.lock().automatic_epoch()? else {
        return Ok(());
    };
    let request = chain.request(Lookup::Registration);
    let verified = chain.recent(ctx, &request).await?;
    if let Some(Record::Registration(record)) = verified.record
        && record.epoch == epoch
    {
        let mut operator = operator.lock();
        if operator.automatic_epoch()? == Some(epoch) {
            operator.adopt_registration(&record)?;
            operator.close_if_due(epoch, verified.height, timing)?;
        }
        return Ok(());
    }

    // One attempt leaves admission/finality observation live while registration is pending.
    let registration = {
        let mut operator = operator.lock();
        if operator.automatic_epoch()? != Some(epoch) {
            return Ok(());
        }
        operator.signed_registration()?
    };
    chain
        .submit(ctx, &SettlementTx::RegisterEpoch(registration))
        .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_agent(
    operator: SocketAddr,
    genesis: PathBuf,
    queries: Vec<SocketAddr>,
    database: Option<PathBuf>,
    identity: usize,
    deployment: String,
    scripted: bool,
    native_balance: bool,
    transfer: Option<(String, u64)>,
) -> Result<()> {
    let completed_script = runtime().start(move |context| async move {
        let genesis =
            crate::chain::setup::read_genesis_file(&genesis).context("read genesis identity")?;
        let selected = if deployment.len() == 64 {
            let bytes =
                commonware_formatting::from_hex(&deployment).context("invalid deployment hex")?;
            commonware_cryptography::sha256::Digest::decode(bytes::Bytes::from(bytes))
                .context("invalid deployment digest")?
        } else {
            let index: usize = deployment
                .parse()
                .context("deployment must be a genesis index or hex digest")?;
            *genesis
                .native
                .deployments
                .get(index)
                .context("genesis deployment index is out of range")?
                .deployment
                .digest()
        };
        let mut chain = Client::new(&genesis, selected, queries, context.child("chain_rng"))
            .context("build chain client")?;
        let configured = chain
            .registered(&context)
            .await
            .context("authenticate selected operator deployment")?;
        let database = database.unwrap_or_else(|| {
            PathBuf::from(format!("terminal-agent-{selected}-{identity}.sqlite"))
        });
        let mut agent = Agent::open_for(
            &database,
            identity,
            selected,
            configured.deployment.operator.clone(),
        )
        .context("initialize SQLite agent")?;
        if native_balance {
            let balance = chain
                .native_balance(&context, genesis.native.chain_id(), agent.account())
                .await?;
            println!("native balance: {balance}");
            return Ok(false);
        }
        if let Some((to, amount)) = transfer {
            let bytes =
                commonware_formatting::from_hex(&to).context("invalid native recipient hex")?;
            let recipient = crate::protocol::Key::decode(bytes::Bytes::from(bytes))
                .context("invalid native recipient key")?;
            let receipt = agent
                .transfer_native(&context, &mut chain, recipient, amount)
                .await?;
            println!(
                "native transfer certified: {} to {} (id {})",
                receipt.amount, receipt.to, receipt.id
            );
            return Ok(false);
        }
        if scripted {
            Box::pin(ui::scripted(&context, operator, chain, agent)).await?;
        } else {
            Box::pin(ui::run(&context, operator, chain, agent)).await?;
        }
        Ok::<_, anyhow::Error>(scripted)
    })?;

    // The self-contained deterministic runner must start outside the live
    // runtime's cooperative task budget.
    if completed_script {
        ui::fraud_arc()?;
    }
    Ok(())
}

/// Handles the settlement interactions one decoded operator request needs
/// before the synchronous dispatch may run, or answers it outright.
///
/// The operator is locked around each synchronous call and never across an
/// await, so the deposit observer can stage between the steps. Every
/// dispatched operation revalidates its own preconditions.
pub(crate) async fn prepare_request<E: Env, C: Chain>(
    ctx: &E,
    chain: &mut C,
    operator: &Mutex<Operator>,
    request: &operator_rpc::OperatorRequest,
) -> Result<Option<rpc::Response>> {
    match request {
        operator_rpc::OperatorRequest::AcknowledgeWithdrawal(request) => {
            // The reserve retires only against the certified release record
            // at the claim's exact (batch, position), consumed by exactly
            // this evidence. A proven absence means the batch has not
            // released it yet.
            let release = chain
                .withdrawal_release(ctx, request.batch_id, request.claim.position())
                .await
                .context("confirm settlement withdrawal claim")?
                .context("withdrawal batch is not claimable yet")?;
            ensure!(
                release.claim == Sha256::hash(&[&request.claim.encode()]),
                "settlement rejected the withdrawal claim"
            );
            ensure!(
                release.released.destination == *request.claim.output().destination()
                    && release.released.amount == request.claim.output().amount(),
                "settlement returned another withdrawal output"
            );
            return Ok(Some(operator_rpc::acknowledge_withdrawal_confirmed(
                &mut operator.lock(),
                request,
            )));
        }
        operator_rpc::OperatorRequest::AcknowledgeExternalPayout(request) => {
            let release = chain
                .payout_release(ctx, request.batch_id, request.claim.position())
                .await
                .context("confirm settlement external payout claim")?
                .context("external-payout batch is not claimable yet")?;
            ensure!(
                release.claim == Sha256::hash(&[&request.claim.encode()]),
                "settlement rejected the external payout claim"
            );
            ensure!(
                &release.released.receiver == request.claim.recipient(),
                "settlement returned another external payout receiver"
            );
            return Ok(Some(operator_rpc::acknowledge_external_payout_confirmed(
                &mut operator.lock(),
                request,
            )));
        }
        _ => {}
    }

    let register = match request {
        operator_rpc::OperatorRequest::AcceptSend(request) => operator
            .lock()
            .send_requires_epoch_registration(&request.authorization, &request.entries)?,
        operator_rpc::OperatorRequest::StartClose(request) => {
            let operator = operator.lock();
            if operator.close_already_started(request.expected_epoch)? {
                false
            } else {
                operator.validate_close_start(request.expected_epoch)?;
                true
            }
        }
        _ => false,
    };
    if !register {
        return Ok(None);
    }
    register_epoch(ctx, chain, operator).await?;
    Ok(None)
}

/// Stages one finalized block's deposit transactions and acknowledges the
/// block to marshal.
///
/// The block's transactions were observed on the operator's own follower
/// feed, but inclusion is not application: a rejected transaction is
/// effect-free. Each event is therefore confirmed against the applied
/// custody record at or past the block's height, where an absence is a
/// verdict rather than lag, before the applied events are staged in one
/// durable transaction. Only then is the block acknowledged, so a crash
/// before the staging commit re-delivers the block on restart and the id
/// dedupe makes the replay a no-op. An error leaves the acknowledgement
/// unfulfilled, which stops marshal. Returns the newly staged credits.
pub(crate) async fn observe<E: Env, C: Chain>(
    ctx: &E,
    chain: &mut C,
    operator: &Mutex<Operator>,
    observed: node::Observed,
) -> Result<Vec<StagedDeposit>> {
    let mut applied = Vec::with_capacity(observed.events.len());
    for event in &observed.events {
        let mut confirmed = None;
        let request = chain.request(Lookup::Deposit { id: event.id });
        for _ in 0..EFFECT_ATTEMPTS {
            if let Ok(verified) = chain.read(ctx, &request).await
                && verified.height >= observed.height
            {
                confirmed = Some(verified.record);
                break;
            }
            ctx.sleep(POLL).await;
        }
        let Some(record) = confirmed else {
            bail!(
                "the applied settlement state never reached observed deposit height {}",
                observed.height
            );
        };
        match record {
            Some(Record::Deposit(recorded)) if recorded == *event => applied.push(event.clone()),

            // The inclusion was rejected effect-free (a replayed or foreign
            // id, or a deposit gated by an active registration), so the
            // chain holds no custody for it and nothing may be staged.
            Some(Record::Deposit(_)) | None => {}
            Some(_) => bail!("certified deposit read returned a foreign record"),
        }
    }
    let mut staged = Vec::new();
    if !applied.is_empty() {
        staged = operator
            .lock()
            .observe(&applied)
            .context("stage observed deposits")?;
    }
    observed.ack.acknowledge();
    Ok(staged)
}

/// Registers the live epoch on the chain, completes on the certified
/// registration record (the transaction's effect), and adopts the
/// chain-assigned deadlines and anchor from that record.
///
/// The submitted bytes carry only the signed boundary, re-derived from the
/// durable boundary on every attempt: while the boundary is unchanged the
/// deterministic signature makes retries byte-identical, so a lost response,
/// an in-flight duplicate, or an epoch sequence race behind the
/// predecessor's admission all converge on the one registration record for
/// the epoch (a duplicate inclusion lands on the record guard and consumes
/// nothing). When the deposit observer stages a chain-held deposit between
/// attempts, re-derivation heals the boundary in place: the stale bytes were
/// rejected effect-free, and the next attempt submits the boundary the chain
/// requires. Execution assigns the deadlines at the inclusion height, so no
/// rejection is timing-dependent. Rejections are effect-free: a registration
/// that never earns its record times out here.
///
/// The anchor and deadlines exist only in certified state, so the operator
/// learns them from its own certified registration read before any receipt
/// is issued. A restart between the submission and the read-back re-enters
/// here and adopts the same record.
async fn register_epoch<E: Env, C: Chain>(
    ctx: &E,
    chain: &mut C,
    operator: &Mutex<Operator>,
) -> Result<()> {
    let mut epoch = None;
    for attempt in 0..REGISTER_ATTEMPTS {
        if attempt > 0 {
            ctx.sleep(REGISTER_POLL).await;
        }
        let request = operator.lock().signed_registration()?;
        ensure!(
            epoch.is_none_or(|epoch| epoch == request.epoch),
            "the live epoch moved during registration"
        );
        epoch = Some(request.epoch);
        let tx = SettlementTx::RegisterEpoch(request);
        chain
            .deliver(ctx, &tx)
            .await
            .context("register settlement epoch")?;
        for _ in 0..CONFIRM_ATTEMPTS {
            let record = chain
                .registration(ctx)
                .await
                .context("read back the registered epoch")?;
            if let Some(record) = record
                && Some(record.epoch) == epoch
            {
                return operator.lock().adopt_registration(&record);
            }
            ctx.sleep(CONFIRM_POLL).await;
        }
    }
    anyhow::bail!(
        "register settlement epoch: the registration record never appeared in certified state"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        agent::{Agent, WithdrawalOutcome},
        chain::{
            harness,
            ingress::Submission,
            light::Verified,
            query::ReadRequest,
            state::{
                FaultRecord, HardFaultReasonResponse, Record, anchor_key, fault_key,
                registration_key, status_key,
            },
        },
        protocol::{DepositEvent, deployment, wallets},
    };
    use bytes::Bytes;
    use commonware_actor::mailbox;
    use commonware_clearing::bajillion::boundary::{SignedWithdrawal, WithdrawalAction};
    use commonware_codec::{Decode as _, RangeCfg};
    use commonware_consensus::{Reporter as _, marshal::Update};
    use commonware_runtime::deterministic;
    use commonware_utils::acknowledgement::Exact;
    use std::{
        fs,
        num::NonZeroU64,
        path::{Path, PathBuf},
        sync::atomic::{AtomicBool, AtomicU64, Ordering},
    };

    /// The in-process chain's query address.
    const CHAIN: SocketAddr =
        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 9_700);

    /// A query address nothing listens on.
    const UNREACHABLE: SocketAddr =
        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 9_701);

    static TEMP_DATABASE_ID: AtomicU64 = AtomicU64::new(0);

    struct TempDatabases {
        directory: PathBuf,
        agent: PathBuf,
        operator: PathBuf,
    }

    impl TempDatabases {
        fn new() -> Self {
            let id = TEMP_DATABASE_ID.fetch_add(1, Ordering::Relaxed);
            let directory = std::env::temp_dir().join(format!(
                "commonware-terminal-service-{}-{id}",
                std::process::id()
            ));
            fs::create_dir(&directory).unwrap();
            let agent = directory.join("agent.sqlite");
            let operator = directory.join("operator.sqlite");
            Self {
                directory,
                agent,
                operator,
            }
        }

        fn agent(&self) -> &Path {
            &self.agent
        }

        fn operator(&self) -> &Path {
            &self.operator
        }
    }

    impl Drop for TempDatabases {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    /// A client over the running harness chain.
    fn client(context: &deterministic::Context, control: &harness::Control) -> Client {
        Client::new(
            control.identity(),
            deployment(),
            vec![CHAIN],
            context.child("client_rng"),
        )
        .unwrap()
    }

    /// A client whose one validator address answers nothing.
    fn unreachable_client(context: &deterministic::Context) -> Client {
        let mut identity_rng = context.child("identity_rng");
        let identity = harness::identity(&mut identity_rng);
        Client::new(
            &identity,
            deployment(),
            vec![UNREACHABLE],
            context.child("client_rng"),
        )
        .unwrap()
    }

    async fn serve_operator_requests<L: commonware_runtime::Listener, const N: usize>(
        context: &deterministic::Context,
        chain: &mut Client,
        listener: &mut L,
        operator: &Mutex<Operator>,
        expected_methods: [u8; N],
    ) {
        for expected_method in expected_methods {
            let (_, mut sink, mut stream) = listener.accept().await.unwrap();
            let request = rpc::recv_request(&mut stream).await.unwrap();
            assert_eq!(request.method, expected_method);
            let request = operator_rpc::decode_request(request).unwrap();
            let prepared = prepare_request(context, chain, operator, &request)
                .await
                .unwrap();
            let response = prepared
                .unwrap_or_else(|| operator_rpc::handle_decoded(&mut operator.lock(), request));
            rpc::send_response(&mut sink, &response).await.unwrap();
        }
    }

    /// The certified fault record on the harness chain.
    async fn fault(control: &harness::Control) -> FaultRecord {
        match control.record(fault_key(&deployment())).await {
            Some(Record::Fault(fault)) => fault,
            record => panic!("expected a fault record, found {record:?}"),
        }
    }

    /// The status singleton on the harness chain.
    async fn status(control: &harness::Control) -> crate::chain::state::StatusRecord {
        match control.record(status_key(&deployment())).await {
            Some(Record::Status(status)) => status,
            record => panic!("expected the status record, found {record:?}"),
        }
    }

    /// Advances the harness chain to `height` (inclusive).
    async fn advance_to(control: &harness::Control, height: u64) {
        let current = control.advance(0).await;
        if current < height {
            control.advance(height - current).await;
        }
    }

    fn recover_pending_withdrawal_over_the_chain(
        action: WithdrawalAction,
    ) -> crate::chain::state::ClaimHardFaultResponse {
        deterministic::Runner::default().start(move |context| async move {
            let databases = TempDatabases::new();
            let control = harness::start(&context, CHAIN, "chain").await;
            let genesis_root = status(&control).await.state_root;
            let mut agent_chain = client(&context, &control);
            let mut agent = Agent::open(databases.agent(), 0).unwrap();
            let account = agent.account();
            let chain_id = agent_chain.genesis().native.chain_id();
            let native_before = agent_chain
                .native_balance(&context, chain_id, account.clone())
                .await
                .unwrap();

            // The operator serves one withdrawal opening (the retained
            // recovery evidence) and then vanishes before it can apply the
            // signed request.
            let operator =
                Mutex::new(Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap());
            let mut operator_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
                .await
                .unwrap();
            let operator_address = operator_listener.local_addr().unwrap();
            let operator_server = context.child("operator").spawn({
                let mut chain = client(&context, &control);
                move |operator_context| async move {
                    serve_operator_requests(
                        &operator_context,
                        &mut chain,
                        &mut operator_listener,
                        &operator,
                        [operator_rpc::METHOD_WITHDRAWAL_OPENING],
                    )
                    .await;
                }
            });

            let outcome = agent
                .withdraw(&context, &mut agent_chain, operator_address, action)
                .await
                .unwrap();
            let WithdrawalOutcome::Signed { request, error } = outcome else {
                panic!("disappeared operator unexpectedly applied withdrawal");
            };
            assert_eq!(request.body().action(), &action);
            assert!(format!("{error:#}").contains("apply operator withdrawal"));
            operator_server.await.unwrap();

            // The operator never carried the signed request, so the signer
            // exercises the censorship fallback: the exact request queues on
            // the chain, which the next registered close must then carry
            // verbatim. With the operator gone no close ever registers, so
            // the deadline expires into hard-fault recovery instead.
            let deadline = request.body().deadline();
            let escalated = agent
                .escalate_withdrawal(&context, &mut agent_chain)
                .await
                .unwrap();
            assert_eq!(escalated, request);
            drop(agent);

            let retained_opening_count = rusqlite::Connection::open(databases.agent())
                .unwrap()
                .query_row("SELECT COUNT(*) FROM agent_state_openings", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap();
            assert_eq!(retained_opening_count, 1);

            // The withdrawal obligation expires at its absolute deadline
            // height and permanently faults the deployment.
            advance_to(&control, deadline - 1).await;
            assert!(!status(&control).await.hard_faulted);
            advance_to(&control, deadline).await;
            assert!(matches!(
                fault(&control).await,
                FaultRecord::Faulted(HardFaultReasonResponse::ExpiredWithdrawal {
                    account: expired,
                    expired_at,
                }) if expired == account && expired_at == deadline
            ));

            let recovered_agent = Agent::open(databases.agent(), 0).unwrap();
            let release = recovered_agent
                .recover_hard_fault(&context, &mut agent_chain)
                .await
                .unwrap();
            assert_eq!(release.account, account);
            assert_eq!(release.released_custody, 100);

            // The frozen snapshot is the certified terminal record.
            let FaultRecord::Settling(snapshot) = fault(&control).await else {
                panic!("terminal settlement did not begin");
            };
            assert_eq!(snapshot.admission_fence_epoch, 0);
            assert_eq!(snapshot.invalid_from, None);
            assert_eq!(snapshot.frozen_state_root, genesis_root);
            assert_eq!(snapshot.state_liability, 400);
            assert_eq!(snapshot.unfinalized_deposit_total, 0);
            assert_eq!(snapshot.custody_balance, 400);

            // A lost response replays into the identical certified release.
            let retry = recovered_agent
                .recover_hard_fault(&context, &mut agent_chain)
                .await
                .unwrap();
            assert_eq!(retry, release);

            let after_release = status(&control).await;
            assert!(after_release.hard_faulted);
            assert_eq!(after_release.state_root, genesis_root);
            assert_eq!(after_release.claimable, 0);
            assert_eq!(after_release.custody, 300);
            assert_eq!(
                agent_chain
                    .native_balance(&context, chain_id, account.clone())
                    .await
                    .unwrap(),
                native_before + release.released_custody,
            );
            release
        })
    }

    #[test]
    fn fresh_withdrawal_application_requires_no_chain_rpc() {
        deterministic::Runner::default().start(|context| async move {
            let operator =
                Mutex::new(Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap());
            let wallet = wallets().remove(0);
            let opening = operator
                .lock()
                .withdrawal_opening(&wallet.public_key())
                .unwrap();
            let withdrawal = SignedWithdrawal::sign(
                deployment(),
                opening.root.digest,
                wallet.public_key().encode(),
                WithdrawalAction::Amount(NonZeroU64::new(7).unwrap()),
                100,
                wallet.signer(),
            );
            let request = operator_rpc::OperatorRequest::ApplyWithdrawal(
                operator_rpc::ApplyWithdrawalRequest {
                    request: withdrawal.clone(),
                },
            );

            // The operator carries the signed request itself, so application must not
            // depend on any chain round trip. The one query address is unreachable.
            let mut chain = unreachable_client(&context);
            assert!(
                prepare_request(&context, &mut chain, &operator, &request)
                    .await
                    .unwrap()
                    .is_none()
            );
            let staged = operator.lock().apply_withdrawal(withdrawal).unwrap();
            assert_eq!(staged.epoch, 0);
            assert_eq!(
                operator
                    .lock()
                    .payment_head(&wallet.public_key())
                    .unwrap()
                    .balance,
                93
            );
        });
    }

    #[test]
    fn staged_close_response_loss_retries_after_cut_without_chain_rpc() {
        deterministic::Runner::default().start(|context| async move {
            let operator =
                Mutex::new(Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap());
            let wallet = wallets().remove(0);
            let opening = operator
                .lock()
                .withdrawal_opening(&wallet.public_key())
                .unwrap();
            let close = SignedWithdrawal::sign(
                deployment(),
                opening.root.digest,
                wallet.public_key().encode(),
                WithdrawalAction::Close,
                100,
                wallet.signer(),
            );
            let first = operator.lock().apply_withdrawal(close.clone()).unwrap();
            assert_eq!(first.action, WithdrawalAction::Close);
            operator.lock().start_close(0).unwrap();

            let request = operator_rpc::OperatorRequest::ApplyWithdrawal(
                operator_rpc::ApplyWithdrawalRequest {
                    request: close.clone(),
                },
            );
            let mut chain = unreachable_client(&context);
            assert!(
                prepare_request(&context, &mut chain, &operator, &request)
                    .await
                    .unwrap()
                    .is_none()
            );
            let mut operator = operator.into_inner();
            let retry = operator.apply_withdrawal(close).unwrap();
            assert_eq!(retry.epoch, 0);
            assert_eq!(retry.action, WithdrawalAction::Close);
            operator.wait_for_closes().unwrap();
        });
    }

    #[test]
    fn first_receipt_waits_for_successful_epoch_registration() {
        deterministic::Runner::default().start(|context| async move {
            let control = harness::start(&context, CHAIN, "chain").await;
            let operator =
                Mutex::new(Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap());
            let mut identities = wallets();
            let payer = identities.remove(0);
            let receiver = identities.remove(0);
            let head = operator.lock().payment_head(&payer.public_key()).unwrap();
            let (authorization, entries) = operator
                .lock()
                .sign_send(0, &[(receiver.public_key(), 7)])
                .unwrap();
            let request =
                operator_rpc::OperatorRequest::AcceptSend(operator_rpc::AcceptSendRequest {
                    authorization: authorization.clone(),
                    entries: entries.clone(),
                });

            // An unreachable chain refuses the registration, so nothing is
            // committed and the first receipt stays gated: the operator
            // issues no context until its certified read-back returns the
            // assigned anchor.
            let mut bad = unreachable_client(&context);
            let error = prepare_request(&context, &mut bad, &operator, &request)
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("register settlement epoch"));
            assert!(operator.lock().snapshot().unwrap().payments.is_empty());
            assert!(
                operator
                    .lock()
                    .send_requires_epoch_registration(&authorization, &entries)
                    .unwrap()
            );

            // A successful registration adopts the chain-assigned deadlines
            // from the certified record, which moves the payment anchor: the
            // pre-registration send is now corrective-rejected, exactly what
            // the wallet's corrective retry handles.
            let mut good = client(&context, &control);
            assert!(
                prepare_request(&context, &mut good, &operator, &request)
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(operator.lock().snapshot().unwrap().payments.is_empty());
            let registered = match control.record(anchor_key(&deployment(), 0)).await {
                Some(Record::Anchor(anchor)) => anchor,
                record => panic!("expected the epoch-0 anchor, found {record:?}"),
            };
            let record = match control.record(registration_key(&deployment())).await {
                Some(Record::Registration(record)) => record,
                record => panic!("expected the registration record, found {record:?}"),
            };
            assert_eq!(record.anchor, registered);
            let live = operator.lock().payment_head(&payer.public_key()).unwrap();
            assert_eq!(live.context.payment().anchor(), &registered);
            assert_ne!(head.context.payment().anchor(), &registered);

            // The re-signed send retriggers the gate, which completes on the
            // same certified registration record, and then commits.
            let (resigned, resigned_entries) = operator
                .lock()
                .sign_send(0, &[(receiver.public_key(), 7)])
                .unwrap();
            let request =
                operator_rpc::OperatorRequest::AcceptSend(operator_rpc::AcceptSendRequest {
                    authorization: resigned,
                    entries: resigned_entries,
                });
            assert!(
                prepare_request(&context, &mut good, &operator, &request)
                    .await
                    .unwrap()
                    .is_none()
            );
            let mut operator = operator.into_inner();
            assert!(operator.snapshot().unwrap().payments.is_empty());
            assert!(matches!(
                operator_rpc::handle_decoded(&mut operator, request),
                rpc::Response::Success { .. }
            ));
            assert_eq!(operator.snapshot().unwrap().payments.len(), 1);
        });
    }

    #[test]
    fn startup_observer_releases_catchup_before_fresh_rpc_readiness() {
        deterministic::Runner::default().start(|context| async move {
            let operator = Arc::new(Mutex::new(
                Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap(),
            ));
            let mut chain = historical_follower();
            let (sender, receiver) =
                commonware_actor::mailbox::new(context.child("observations"), NonZeroUsize::MIN);
            let (ack, acked) = Exact::handle();
            let _ = sender.enqueue(node::Observed {
                height: 1,
                events: vec![chain.event.clone()],
                ack,
            });
            let caught_up = chain.caught_up.clone();
            let staged_operator = operator.clone();
            let account = chain.event.account.clone();
            let advancing = context.child("catchup").spawn(move |_| async move {
                acked.await.unwrap();
                assert_eq!(
                    staged_operator
                        .lock()
                        .payment_head(&account)
                        .unwrap()
                        .balance,
                    107
                );
                caught_up.store(true, Ordering::SeqCst);
            });
            let observer = start_observation(
                &context,
                &mut chain,
                operator.clone(),
                receiver,
                Timing::DEFAULT,
            )
            .await
            .unwrap();
            assert!(chain.caught_up.load(Ordering::SeqCst));
            assert!(chain.stale_reads.load(Ordering::SeqCst) > 0);
            advancing.await.unwrap();
            observer.abort();
        });
    }

    #[test]
    fn startup_uses_historical_certified_registry_presence() {
        deterministic::Runner::default().start(|context| async move {
            let mut chain = historical_follower();
            let native = harness::native(crate::protocol::deployments());
            let (_sender, mut receiver) =
                mailbox::new(context.child("startup_feed"), NonZeroUsize::MIN);
            let (registered, held) = registered_operator(
                &context,
                &mut chain,
                native.chain_id(),
                deployment(),
                &mut receiver,
            )
            .await
            .unwrap();
            assert!(held.is_none());
            assert_eq!(registered, chain.entry);
            assert!(!chain.caught_up.load(Ordering::SeqCst));
        });
    }

    #[test]
    fn startup_retries_registry_absence_while_following_history() {
        deterministic::Runner::default().start(|context| async move {
            let mut chain = historical_follower();
            chain.skip_registry_once = true;
            let native = harness::native(crate::protocol::deployments());
            let (_sender, mut receiver) =
                mailbox::new(context.child("startup_feed"), NonZeroUsize::MIN);
            let (registered, held) = registered_operator(
                &context,
                &mut chain,
                native.chain_id(),
                deployment(),
                &mut receiver,
            )
            .await
            .unwrap();
            assert!(held.is_none());
            assert_eq!(registered, chain.entry);
            assert_eq!(chain.registry_reads.load(Ordering::SeqCst), 2);
            assert!(!chain.caught_up.load(Ordering::SeqCst));
        });
    }

    #[derive(Clone)]
    struct HistoricalFollower {
        entry: RegistryEntry,
        event: DepositEvent,
        caught_up: Arc<AtomicBool>,
        stale_reads: Arc<AtomicU64>,
        registry_reads: Arc<AtomicU64>,
        skip_registry_once: bool,
    }

    fn historical_follower() -> HistoricalFollower {
        HistoricalFollower {
            entry: harness::native(crate::protocol::deployments())
                .deployments
                .remove(0),
            event: DepositEvent {
                id: Sha256::hash(&[b"historical-deposit"]),
                account: wallets()[0].public_key(),
                amount: 7,
            },
            caught_up: Arc::new(AtomicBool::new(false)),
            stale_reads: Arc::new(AtomicU64::new(0)),
            registry_reads: Arc::new(AtomicU64::new(0)),
            skip_registry_once: false,
        }
    }

    impl Chain for HistoricalFollower {
        fn deployment(&self) -> Digest {
            deployment()
        }
        async fn read<E: Env>(&mut self, _: &E, request: &ReadRequest) -> Result<Verified> {
            let record = match request.lookup {
                Lookup::RegistryEntry {
                    chain_id,
                    deployment,
                } => {
                    assert_eq!(
                        chain_id,
                        harness::native(crate::protocol::deployments()).chain_id()
                    );
                    assert_eq!(deployment, *self.entry.deployment.digest());
                    if self.registry_reads.fetch_add(1, Ordering::SeqCst) == 0
                        && self.skip_registry_once
                    {
                        None
                    } else {
                        Some(Record::RegistryEntry(self.entry.clone()))
                    }
                }
                Lookup::Deposit { id } if id == self.event.id => {
                    Some(Record::Deposit(self.event.clone()))
                }
                Lookup::Fault | Lookup::Registration => None,
                _ => bail!("unexpected historical follower read"),
            };
            Ok(Verified {
                height: 1,
                timestamp: 0,
                record,
            })
        }
        async fn recent<E: Env>(&mut self, ctx: &E, request: &ReadRequest) -> Result<Verified> {
            if !self.caught_up.load(Ordering::SeqCst) {
                self.stale_reads.fetch_add(1, Ordering::SeqCst);
                bail!("the local finalized tip is stale");
            }
            self.read(ctx, request).await
        }
        async fn submit<E: Env>(&mut self, _: &E, _: &SettlementTx) -> Result<Submission> {
            Ok(Submission::Accepted)
        }
    }

    #[test]
    fn automatic_driver_cuts_observed_work_without_rpc() {
        deterministic::Runner::default().start(|context| async move {
            let control = harness::start(&context, CHAIN, "chain").await;
            let mut chain = client(&context, &control);
            let operator =
                Mutex::new(Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap());
            let wallet = wallets().remove(0);
            let event = DepositEvent {
                id: Sha256::hash(&[b"automatic-close-deposit"]),
                account: wallet.public_key(),
                amount: 7,
            };
            let native = harness::native(crate::protocol::deployments());
            control
                .submit(SettlementTx::Deposit(
                    crate::chain::tx::DepositRequest::sign(
                        native.chain_id(),
                        deployment(),
                        event.clone(),
                        wallet.signer(),
                    ),
                ))
                .await;
            operator.lock().observe(&[event]).unwrap();
            for _ in 0..16 {
                drive_closes(&context, &mut chain, &operator, Timing::DEFAULT)
                    .await
                    .unwrap();
                if operator.lock().status().unwrap().epoch == 1 {
                    break;
                }
                control.advance(1).await;
            }
            assert_eq!(operator.lock().status().unwrap().epoch, 1);
            let registered = chain.registration(&context).await.unwrap().unwrap();
            assert!(status(&control).await.height <= registered.admission_deadline);
            operator.lock().wait_for_closes().unwrap();
        });
    }

    fn automatic_registration_freezes_withdrawal(adopt: bool) {
        deterministic::Runner::timed(Duration::from_secs(30)).start(move |context| async move {
            let databases = TempDatabases::new();
            let control = harness::start(&context, CHAIN, "chain").await;
            let mut chain = client(&context, &control);
            let mut agent = Agent::open(databases.agent(), 0).unwrap();
            let operator =
                Mutex::new(Operator::open(databases.operator(), NonZeroUsize::MIN).unwrap());
            let deposit = agent.deposit(&context, &mut chain, 10).await.unwrap();
            operator.lock().observe(&[deposit]).unwrap();
            drive_closes(&context, &mut chain, &operator, Timing::DEFAULT)
                .await
                .unwrap();
            let registered = chain.registration(&context).await.unwrap().unwrap();
            if adopt {
                drive_closes(&context, &mut chain, &operator, Timing::DEFAULT)
                    .await
                    .unwrap();
            }
            assert!(operator.lock().snapshot().unwrap().payments.is_empty());
            assert_eq!(operator.lock().status().unwrap().epoch, 0);
            assert!(
                status(&control).await.height
                    < registered.admission_deadline - Timing::DEFAULT.admission_offset + 4
            );
            drop(operator);

            // The publication boundary survives restart both before and after the
            // certified deadlines are adopted, even though no receipt was issued.
            let operator = Arc::new(Mutex::new(
                Operator::open(databases.operator(), NonZeroUsize::MIN).unwrap(),
            ));
            let before = operator
                .lock()
                .payment_head(&agent.account())
                .unwrap()
                .context;
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let server = context.child("operator").spawn({
                let operator = Arc::clone(&operator);
                let mut chain = client(&context, &control);
                move |ctx| async move {
                    serve_operator_requests(
                        &ctx,
                        &mut chain,
                        &mut listener,
                        &operator,
                        [
                            operator_rpc::METHOD_WITHDRAWAL_OPENING,
                            operator_rpc::METHOD_APPLY_WITHDRAWAL,
                        ],
                    )
                    .await;
                }
            });
            let outcome = agent
                .withdraw(
                    &context,
                    &mut chain,
                    address,
                    WithdrawalAction::Amount(NonZeroU64::new(3).unwrap()),
                )
                .await
                .unwrap();
            server.await.unwrap();
            assert!(
                matches!(outcome, WithdrawalOutcome::Signed { .. }),
                "a published registration accepted a new withdrawal without a receipt"
            );
            assert_eq!(
                operator
                    .lock()
                    .payment_head(&agent.account())
                    .unwrap()
                    .context,
                before
            );
            for _ in 0..8 {
                drive_closes(&context, &mut chain, &operator, Timing::DEFAULT)
                    .await
                    .unwrap();
                if operator.lock().status().unwrap().epoch == 1 {
                    break;
                }
                control.advance(1).await;
            }
            assert_eq!(operator.lock().status().unwrap().epoch, 1);
            assert_eq!(
                chain.registration(&context).await.unwrap().unwrap(),
                registered
            );
            assert!(!status(&control).await.hard_faulted);
            operator.lock().wait_for_closes().unwrap();
        });
    }

    #[test]
    fn automatic_registration_freezes_withdrawal_after_adoption() {
        automatic_registration_freezes_withdrawal(true);
    }

    #[test]
    fn automatic_registration_freezes_withdrawal_before_adoption_restart() {
        automatic_registration_freezes_withdrawal(false);
    }

    #[test]
    fn published_empty_epoch_recovers_before_registration_emission() {
        deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
            let databases = TempDatabases::new();
            let control = harness::start(&context, CHAIN, "chain").await;
            let mut chain = client(&context, &control);
            let mut operator = Operator::open(databases.operator(), NonZeroUsize::MIN).unwrap();
            let receiver = wallets()[1].public_key();
            let (authorization, entries) = operator.sign_send(0, &[(receiver, 1)]).unwrap();
            assert!(
                operator
                    .send_requires_epoch_registration(&authorization, &entries)
                    .unwrap()
            );
            let request = operator.signed_registration().unwrap();
            drop(operator);

            // Registration preparation is the last local action before an asynchronous
            // send. Recovery must discharge it even when emission and receipt never ran.
            let operator =
                Mutex::new(Operator::open(databases.operator(), NonZeroUsize::MIN).unwrap());
            assert_eq!(operator.lock().automatic_epoch().unwrap(), Some(0));
            assert_eq!(operator.lock().signed_registration().unwrap(), request);
            for _ in 0..8 {
                drive_closes(&context, &mut chain, &operator, Timing::DEFAULT)
                    .await
                    .unwrap();
                if operator.lock().status().unwrap().epoch == 1 {
                    break;
                }
                control.advance(1).await;
            }
            assert_eq!(operator.lock().status().unwrap().epoch, 1);
            operator.lock().wait_for_closes().unwrap();
            assert_eq!(operator.lock().automatic_epoch().unwrap(), None);
            drive_closes(&context, &mut chain, &operator, Timing::DEFAULT)
                .await
                .unwrap();
            assert_eq!(
                chain.registration(&context).await.unwrap().unwrap().epoch,
                0
            );
            assert!(!status(&control).await.hard_faulted);
        });
    }

    #[test]
    fn confirmed_deposit_invalidates_unadopted_registration_without_unfreezing_withdrawals() {
        deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
            let databases = TempDatabases::new();
            let control = harness::start(&context, CHAIN, "chain").await;
            let mut chain = client(&context, &control);
            let mut agent = Agent::open(databases.agent(), 0).unwrap();
            let mut operator = Operator::open(databases.operator(), NonZeroUsize::MIN).unwrap();
            let first = agent.deposit(&context, &mut chain, 10).await.unwrap();
            operator.observe(&[first]).unwrap();
            let old = operator.signed_registration().unwrap();
            drop(operator);

            // Custody accepts the next deposit before the earlier registration can
            // execute. Its staged root makes the queued request permanently ineligible.
            let next = agent.deposit(&context, &mut chain, 2).await.unwrap();
            let height = status(&control).await.height;
            chain
                .deliver(&context, &SettlementTx::RegisterEpoch(old.clone()))
                .await
                .unwrap();
            assert!(chain.registration(&context).await.unwrap().is_none());
            let operator =
                Mutex::new(Operator::open(databases.operator(), NonZeroUsize::MIN).unwrap());
            let (ack, acked) = Exact::handle();
            observe(
                &context,
                &mut chain,
                &operator,
                node::Observed {
                    height,
                    events: vec![next.clone()],
                    ack,
                },
            )
            .await
            .unwrap();
            acked.await.unwrap();
            assert_eq!(
                operator
                    .lock()
                    .payment_head(&agent.account())
                    .unwrap()
                    .balance,
                112
            );
            let replacement = operator.lock().signed_registration().unwrap();
            assert_ne!(old.staged_root, replacement.staged_root);
            assert!(
                operator
                    .lock()
                    .withdraw(0, WithdrawalAction::Amount(NonZeroU64::new(3).unwrap()))
                    .is_err()
            );
            drop(operator);

            let operator =
                Mutex::new(Operator::open(databases.operator(), NonZeroUsize::MIN).unwrap());
            assert_eq!(operator.lock().signed_registration().unwrap(), replacement);
            let (ack, acked) = Exact::handle();
            assert!(
                observe(
                    &context,
                    &mut chain,
                    &operator,
                    node::Observed {
                        height,
                        events: vec![next],
                        ack,
                    }
                )
                .await
                .unwrap()
                .is_empty()
            );
            acked.await.unwrap();
            assert_eq!(
                operator
                    .lock()
                    .payment_head(&agent.account())
                    .unwrap()
                    .balance,
                112
            );
            for _ in 0..8 {
                drive_closes(&context, &mut chain, &operator, Timing::DEFAULT)
                    .await
                    .unwrap();
                if operator.lock().status().unwrap().epoch == 1 {
                    break;
                }
                control.advance(1).await;
            }
            assert_eq!(operator.lock().status().unwrap().epoch, 1);
            assert!(!status(&control).await.hard_faulted);
            operator.lock().wait_for_closes().unwrap();
        });
    }

    #[test]
    fn startup_sync_fences_expired_registration_without_close_job() {
        deterministic::Runner::default().start(|context| async move {
            let databases = TempDatabases::new();
            let control = harness::start(&context, CHAIN, "chain").await;
            let mut chain = client(&context, &control);
            let operator =
                Mutex::new(Operator::open(databases.operator(), NonZeroUsize::MIN).unwrap());
            register_epoch(&context, &mut chain, &operator)
                .await
                .unwrap();
            let registered = chain.registration(&context).await.unwrap().unwrap();
            advance_to(&control, registered.admission_deadline + 1).await;
            assert!(status(&control).await.hard_faulted);
            drop(operator);

            for _ in 0..2 {
                let reopened =
                    Mutex::new(Operator::open(databases.operator(), NonZeroUsize::MIN).unwrap());
                drive_closes(&context, &mut chain, &reopened, Timing::DEFAULT)
                    .await
                    .unwrap();
                assert!(reopened.lock().pending_epochs().unwrap().is_empty());
                assert!(reopened.lock().pay(0, 1, 1).is_err());
            }
        });
    }

    #[test]
    fn registration_readback_crash_recovers_idempotently() {
        deterministic::Runner::default().start(|context| async move {
            let databases = TempDatabases::new();
            let control = harness::start(&context, CHAIN, "chain").await;
            let mut chain = client(&context, &control);
            let mut operator = Operator::open(databases.operator(), NonZeroUsize::MIN).unwrap();

            // The registration lands on the chain, but the operator crashes
            // before its certified read-back adopts the assigned record: the
            // store still holds the placeholder context.
            let request = operator.signed_registration().unwrap();
            chain
                .deliver(&context, &SettlementTx::RegisterEpoch(request))
                .await
                .unwrap();
            let registered = match control.record(anchor_key(&deployment(), 0)).await {
                Some(Record::Anchor(anchor)) => anchor,
                record => panic!("expected the epoch-0 anchor, found {record:?}"),
            };
            drop(operator);

            // The restarted operator re-runs the register flow: the same
            // signed boundary bytes land on the registration record guard (a
            // harmless conflict), and the read-back completes on the same
            // certified record.
            let operator =
                Mutex::new(Operator::open(databases.operator(), NonZeroUsize::MIN).unwrap());
            register_epoch(&context, &mut chain, &operator)
                .await
                .unwrap();
            let record = match control.record(registration_key(&deployment())).await {
                Some(Record::Registration(record)) => record,
                record => panic!("expected the registration record, found {record:?}"),
            };
            assert_eq!(record.epoch, 0);
            assert_eq!(record.anchor, registered);
            let head = operator
                .lock()
                .payment_head(&wallets()[0].public_key())
                .unwrap();
            assert_eq!(head.context.payment().anchor(), &registered);

            // Re-running the flow after adoption is a no-op replay: the same
            // bytes, the same record, the same anchor.
            register_epoch(&context, &mut chain, &operator)
                .await
                .unwrap();
            let head = operator
                .lock()
                .payment_head(&wallets()[0].public_key())
                .unwrap();
            assert_eq!(head.context.payment().anchor(), &registered);
        });
    }

    #[test]
    fn lost_payment_response_recovers_after_missed_admission() {
        deterministic::Runner::default().start(|context| async move {
            let databases = TempDatabases::new();
            let control = harness::start(&context, CHAIN, "chain").await;
            let genesis_root = status(&control).await.state_root;
            let operator =
                Mutex::new(Operator::open(databases.operator(), NonZeroUsize::MIN).unwrap());
            let mut agent = Agent::open(databases.agent(), 0).unwrap();
            let payer = agent.account();
            let mut agent_chain = client(&context, &control);

            let mut operator_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
                .await
                .unwrap();
            let operator_address = operator_listener.local_addr().unwrap();
            let operator_server = context.child("operator").spawn({
                let mut chain = client(&context, &control);
                move |operator_context| async move {
                    // The head read stages under the placeholder context, the
                    // first acceptance registers and answers the corrective.
                    // The wallet authenticates that old context cannot commit,
                    // reads the new head, and loses the accepted retry's response.
                    let mut accepted = None;
                    for expected_method in [
                        operator_rpc::METHOD_PAYMENT_HEAD,
                        operator_rpc::METHOD_ACCEPT_SEND,
                        operator_rpc::METHOD_PAYMENT_HEAD,
                        operator_rpc::METHOD_ACCEPT_SEND,
                    ] {
                        let (_, mut sink, mut stream) = operator_listener.accept().await.unwrap();
                        let request = rpc::recv_request(&mut stream).await.unwrap();
                        assert_eq!(request.method, expected_method);
                        let request = operator_rpc::decode_request(request).unwrap();
                        let prepared =
                            prepare_request(&operator_context, &mut chain, &operator, &request)
                                .await
                                .unwrap();
                        let response = prepared.unwrap_or_else(|| {
                            operator_rpc::handle_decoded(&mut operator.lock(), request)
                        });
                        if expected_method == operator_rpc::METHOD_ACCEPT_SEND
                            && let rpc::Response::Success { body } = &response
                            && let Ok(operator_rpc::AcceptSendResponse::Accepted(response)) =
                                operator_rpc::AcceptSendResponse::decode(body.clone())
                        {
                            accepted = Some(response);
                            continue;
                        }
                        rpc::send_response(&mut sink, &response).await.unwrap();
                    }
                    accepted.expect("the operator accepted one payment")
                }
            });

            // The wallet stages under the pre-registration head: the
            // registration at first receipt moves the context, so the wallet
            // adopts one corrective before the acceptance whose response is
            // then lost.
            let error = agent
                .pay(&context, &mut agent_chain, operator_address, &[(1, 7)])
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("submit payment"));
            assert_eq!(agent.receipt_count(), 0);
            let accepted = operator_server.await.unwrap();
            assert_eq!(accepted.total, 7);
            assert_eq!(accepted.acceptance.entries[0].cumulative, 7);
            assert_eq!(accepted.acceptance.ack.body().cumulative_debit(), 7);

            // The accepted send binds the chain-registered anchor, whose
            // record carries the chain-assigned deadlines.
            let registered = match control.record(anchor_key(&deployment(), 0)).await {
                Some(Record::Anchor(anchor)) => anchor,
                record => panic!("expected the epoch-0 anchor, found {record:?}"),
            };
            assert_eq!(accepted.acceptance.ack.body().anchor(), &registered);
            let admission_deadline = match control.record(registration_key(&deployment())).await {
                Some(Record::Registration(record)) => record.admission_deadline,
                record => panic!("expected the registration record, found {record:?}"),
            };
            drop(agent);

            let agent_database = rusqlite::Connection::open(databases.agent()).unwrap();
            let retained_opening_count = agent_database
                .query_row("SELECT COUNT(*) FROM agent_state_openings", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap();
            assert_eq!(retained_opening_count, 1);
            let concluded = agent_database
                .query_row(
                    "SELECT COUNT(*), SUM(state = 5) FROM agent_payments",
                    [],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                )
                .unwrap();
            // Only the retired pre-registration intent is concluded; the accepted send remains pending.
            assert_eq!(concluded, (1, 1));
            let (persisted_authorization, persisted_entries) = agent_database
                .query_row(
                    "SELECT authorization, entries FROM agent_pending_payment",
                    [],
                    |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
                )
                .unwrap();
            let pending_authorization =
                commonware_clearing::bajillion::payment::SendAuthorization::decode(Bytes::from(
                    persisted_authorization,
                ))
                .unwrap();
            let pending_entries = Vec::<crate::protocol::Entry>::decode_cfg(
                Bytes::from(persisted_entries),
                &(RangeCfg::new(1..=crate::protocol::MAX_ENTRIES), ()),
            )
            .unwrap();
            assert_eq!(pending_authorization.body(), accepted.acceptance.ack.body());
            drop(agent_database);

            let recovered_agent = Agent::open(databases.agent(), 0).unwrap();
            assert_eq!(recovered_agent.account(), payer);
            assert_eq!(recovered_agent.receipt_count(), 0);
            drop(recovered_agent);

            let mut recovered_operator =
                Operator::open(databases.operator(), NonZeroUsize::MIN).unwrap();
            let persisted_retry = recovered_operator
                .accept_send(pending_authorization, pending_entries)
                .unwrap()
                .into_accepted();
            assert_eq!(persisted_retry.acceptance, accepted.acceptance);
            let operator_snapshot = recovered_operator.snapshot().unwrap();
            assert_eq!(operator_snapshot.payments.len(), 1);
            assert_eq!(
                operator_snapshot
                    .accounts
                    .iter()
                    .find(|account| account.name == "Alice")
                    .unwrap()
                    .balance,
                93
            );
            drop(recovered_operator);

            let persisted_operator_ack = rusqlite::Connection::open(databases.operator())
                .unwrap()
                .query_row("SELECT ack FROM acks", [], |row| row.get::<_, Vec<u8>>(0))
                .unwrap();
            assert_eq!(
                Bytes::from(persisted_operator_ack),
                accepted.acceptance.ack.encode()
            );

            // The operator is gone before its close ever admits, so the
            // registration is live through its inclusive admission deadline
            // and faults on the first later block.
            let before_expiry = status(&control).await;
            assert!(!before_expiry.hard_faulted);
            assert_eq!(before_expiry.state_root, genesis_root);
            assert_eq!(before_expiry.custody, 400);
            advance_to(&control, admission_deadline).await;
            assert!(!status(&control).await.hard_faulted);
            advance_to(&control, admission_deadline + 1).await;
            assert!(matches!(
                fault(&control).await,
                FaultRecord::Faulted(HardFaultReasonResponse::ExpiredRegistration {
                    anchor,
                    epoch: 0,
                    expired_at,
                }) if anchor == registered && expired_at == admission_deadline
            ));

            // Recovery pays the frozen genesis balance, never the uncommitted
            // payment: the acknowledged send was never in a finalized close.
            let recovered_agent = Agent::open(databases.agent(), 0).unwrap();
            let release = recovered_agent
                .recover_hard_fault(&context, &mut agent_chain)
                .await
                .unwrap();
            assert_eq!(release.account, payer);
            assert_eq!(release.withdrawal, None);
            assert_eq!(release.residual, 100);
            assert_ne!(release.residual, 93);
            assert_eq!(release.released_custody, 100);

            let FaultRecord::Settling(snapshot) = fault(&control).await else {
                panic!("terminal settlement did not begin");
            };
            assert!(matches!(
                snapshot.reason,
                HardFaultReasonResponse::ExpiredRegistration { epoch: 0, .. }
            ));
            assert_eq!(snapshot.admission_fence_epoch, 0);
            assert_eq!(snapshot.invalid_from, None);
            assert_eq!(snapshot.frozen_state_root, genesis_root);
            assert_eq!(snapshot.state_liability, 400);
            assert_eq!(snapshot.unfinalized_deposit_total, 0);
            assert_eq!(snapshot.custody_balance, 400);

            // A lost response replays into the identical certified release.
            let retry = recovered_agent
                .recover_hard_fault(&context, &mut agent_chain)
                .await
                .unwrap();
            assert_eq!(retry, release);

            let after_release = status(&control).await;
            assert!(after_release.hard_faulted);
            assert_eq!(after_release.state_root, genesis_root);
            assert_eq!(after_release.claimable, 0);
            assert_eq!(after_release.custody, 300);
        });
    }

    #[test]
    fn operator_disappearance_refunds_pending_deposit_over_the_chain() {
        deterministic::Runner::default().start(|context| async move {
            let databases = TempDatabases::new();
            let control = harness::start(&context, CHAIN, "chain").await;
            let genesis_root = status(&control).await.state_root;
            let mut agent_chain = client(&context, &control);
            let mut agent = Agent::open(databases.agent(), 0).unwrap();
            let account = agent.account();

            // The deposit completes on the certified custody record alone:
            // no operator is ever contacted.
            let event = agent.deposit(&context, &mut agent_chain, 7).await.unwrap();
            assert_eq!(event.account, account);
            assert_eq!(event.amount, 7);
            drop(agent);

            // The deposit's inclusion obligation expires with no operator to
            // close an epoch, permanently faulting the deployment.
            let recorded = status(&control).await;
            assert!(!recorded.hard_faulted);
            assert_eq!(recorded.custody, 407);
            let deposit_deadline = loop {
                control.advance(1).await;
                let status = status(&control).await;
                if status.hard_faulted {
                    break status.height;
                }
                assert!(
                    status.height
                        < recorded.height
                            + crate::protocol::settlement_config(&crate::protocol::Timing::DEFAULT)
                                .deposit_inclusion_timeout
                                .get()
                            + 8,
                    "the expired deposit never faulted the deployment"
                );
            };
            assert!(matches!(
                fault(&control).await,
                FaultRecord::Faulted(HardFaultReasonResponse::ExpiredDeposit {
                    account: expired,
                    expired_at,
                }) if expired == account && expired_at == deposit_deadline
            ));

            let recovered_agent = Agent::open(databases.agent(), 0).unwrap();
            let refund = recovered_agent
                .recover_pending_deposit(&context, &mut agent_chain)
                .await
                .unwrap();
            assert_eq!(refund.account, account);
            assert_eq!(refund.amount, 7);
            drop(recovered_agent);
            let after_refund = status(&control).await;
            assert!(after_refund.hard_faulted);
            assert_eq!(after_refund.state_root, genesis_root);
            assert_eq!(after_refund.claimable, 0);
            assert_eq!(after_refund.custody, 400);

            // A lost response replays into the identical certified refund.
            let recovered_agent = Agent::open(databases.agent(), 0).unwrap();
            let retry = recovered_agent
                .recover_pending_deposit(&context, &mut agent_chain)
                .await
                .unwrap();
            assert_eq!(retry, refund);
            let after_retry = status(&control).await;
            assert_eq!(after_retry.custody, after_refund.custody);
            assert_eq!(after_retry.claimable, after_refund.claimable);
            assert_eq!(after_retry.state_root, after_refund.state_root);
        });
    }

    #[test]
    fn observed_certified_duplicate_batch_stages_once_after_reopen() {
        for conflicting_first in [false, true] {
            deterministic::Runner::default().start(move |context| async move {
                let databases = TempDatabases::new();
                let control = harness::start(&context, CHAIN, "chain").await;
                let mut chain = client(&context, &control);
                let wallet = wallets().remove(0);
                let event = DepositEvent {
                    id: Sha256::hash(&[b"certified-duplicate-event"]),
                    account: wallet.public_key(),
                    amount: 7,
                };
                let valid = crate::chain::tx::DepositRequest::sign(
                    chain.genesis().native.chain_id(),
                    deployment(),
                    event.clone(),
                    wallet.signer(),
                );
                let mut rejected = valid.clone();
                rejected.chain_id = Sha256::hash(&[b"foreign-deposit-chain"]);
                if conflicting_first {
                    rejected.event.amount += 1;
                }
                let raw_events = vec![rejected.event.clone(), event.clone()];
                let block = Arc::new(
                    control
                        .seal_batch(vec![
                            SettlementTx::Deposit(rejected),
                            SettlementTx::Deposit(valid),
                        ])
                        .await,
                );
                assert_eq!(block.transactions.len(), 2);
                assert_eq!(
                    chain.deposit(&context, event.id).await.unwrap(),
                    Some(event.clone())
                );
                assert_eq!(status(&control).await.custody, 407);
                let (sender, mut receiver) =
                    mailbox::new(context.child("duplicate_observer"), NonZeroUsize::MIN);
                let mut observer = node::Observer::new(deployment(), sender);
                for expected in [1, 0] {
                    let operator = Mutex::new(
                        Operator::open(databases.operator(), NonZeroUsize::MIN).unwrap(),
                    );
                    let (ack, mut acked) = Exact::handle();
                    assert!(
                        observer
                            .report(Update::Block(block.clone(), ack))
                            .accepted()
                    );
                    let observed = receiver.recv().await.unwrap();
                    assert_eq!(observed.events, raw_events);
                    assert_eq!(observed.events.len(), 2);
                    assert_eq!(observed.events[0].id, observed.events[1].id);
                    assert!(futures::FutureExt::now_or_never(&mut acked).is_none());
                    let staged = observe(&context, &mut chain, &operator, observed)
                        .await
                        .unwrap();
                    assert_eq!(staged.len(), expected);
                    acked.await.unwrap();
                    assert_eq!(
                        operator
                            .lock()
                            .payment_head(&event.account)
                            .unwrap()
                            .balance,
                        107
                    );
                }
            });
        }
    }

    /// The reporter-ack contract is the observer's recovery mechanism: a
    /// crash between a block's delivery and the staging commit leaves the
    /// acknowledgement unfulfilled, so marshal re-delivers the block on
    /// restart, and the deposit-id dedupe makes any further redelivery a
    /// no-op.
    #[test]
    fn observed_deposit_survives_restart_and_dedupes_redelivery() {
        deterministic::Runner::default().start(|context| async move {
            let databases = TempDatabases::new();
            let control = harness::start(&context, CHAIN, "chain").await;
            let mut chain = client(&context, &control);
            let account = wallets()[0].public_key();

            // A signed deposit enters custody through a third-party relay.
            let event = DepositEvent {
                id: Sha256::hash(&[b"observed-restart-deposit"]),
                account: account.clone(),
                amount: 7,
            };
            chain
                .deliver(
                    &context,
                    &SettlementTx::Deposit(crate::chain::tx::DepositRequest::sign(
                        chain.genesis().native.chain_id(),
                        deployment(),
                        event.clone(),
                        wallets()[0].signer(),
                    )),
                )
                .await
                .unwrap();
            let mut recorded = false;
            for _ in 0..EFFECT_ATTEMPTS {
                if chain
                    .deposit(&context, event.id)
                    .await
                    .ok()
                    .flatten()
                    .as_ref()
                    == Some(&event)
                {
                    recorded = true;
                    break;
                }
                context.sleep(POLL).await;
            }
            assert!(recorded, "the deposit earned no custody record");
            let height = status(&control).await.height;

            // The operator dies between the block's delivery and the staging
            // commit: the acknowledgement is dropped unfulfilled, which is
            // exactly the signal that stops marshal from advancing past the
            // block.
            let operator =
                Mutex::new(Operator::open(databases.operator(), NonZeroUsize::MIN).unwrap());
            let (ack, mut lost) = Exact::handle();
            drop(node::Observed {
                height,
                events: vec![event.clone()],
                ack,
            });
            assert!((&mut lost).await.is_err());
            drop(operator);

            // Marshal re-delivers the unacknowledged block on restart: the
            // deposit stages durably and only then does the block
            // acknowledge.
            let operator =
                Mutex::new(Operator::open(databases.operator(), NonZeroUsize::MIN).unwrap());
            let (ack, acked) = Exact::handle();
            observe(
                &context,
                &mut chain,
                &operator,
                node::Observed {
                    height,
                    events: vec![event.clone()],
                    ack,
                },
            )
            .await
            .unwrap();
            acked.await.unwrap();
            assert_eq!(operator.lock().payment_head(&account).unwrap().balance, 107);
            drop(operator);

            // A redelivery whose acknowledgement was itself not durable is a
            // no-op on the id dedupe: staged exactly once, no double credit.
            let operator =
                Mutex::new(Operator::open(databases.operator(), NonZeroUsize::MIN).unwrap());
            let (ack, acked) = Exact::handle();
            let staged = observe(
                &context,
                &mut chain,
                &operator,
                node::Observed {
                    height,
                    events: vec![event.clone()],
                    ack,
                },
            )
            .await
            .unwrap();
            acked.await.unwrap();
            assert!(staged.is_empty(), "a replayed event staged a new credit");
            assert_eq!(operator.lock().payment_head(&account).unwrap().balance, 107);

            // An included but rejected transaction earns no custody record,
            // so the observer skips it: the block still acknowledges, and
            // nothing stages.
            let rejected = DepositEvent {
                id: Sha256::hash(&[b"observed-rejected-deposit"]),
                account: account.clone(),
                amount: 9,
            };
            let (ack, acked) = Exact::handle();
            let staged = observe(
                &context,
                &mut chain,
                &operator,
                node::Observed {
                    height,
                    events: vec![rejected],
                    ack,
                },
            )
            .await
            .unwrap();
            acked.await.unwrap();
            assert!(staged.is_empty());
            assert_eq!(operator.lock().payment_head(&account).unwrap().balance, 107);
        });
    }

    #[test]
    fn operator_disappearance_releases_pending_amount_over_the_chain() {
        let release = recover_pending_withdrawal_over_the_chain(WithdrawalAction::Amount(
            NonZeroU64::new(7).unwrap(),
        ));
        let withdrawal = release.withdrawal.as_ref().unwrap();
        assert_eq!(withdrawal.destination().as_ref(), release.account.as_ref());
        assert_eq!(withdrawal.amount(), 7);
        assert_eq!(release.residual, 93);
    }

    #[test]
    fn operator_disappearance_releases_pending_close_tail_over_the_chain() {
        let release = recover_pending_withdrawal_over_the_chain(WithdrawalAction::Close);
        let withdrawal = release.withdrawal.as_ref().unwrap();
        assert_eq!(withdrawal.destination().as_ref(), release.account.as_ref());
        assert_eq!(withdrawal.amount(), 100);
        assert_eq!(release.residual, 0);
    }
}
