//! Runtime-owning service loops for the terminal role binaries.

#[cfg(test)]
mod epoch_overlap;
#[cfg(test)]
mod lifecycle;
mod payments;

use crate::{
    agent::Agent,
    chain::{
        client::{Chain, Client, Env, POLL, SUBMIT_ATTEMPTS},
        native::RegistryEntry,
        node,
        query::Lookup,
        state::{FaultRecord, HardFaultReasonResponse, Record},
        tx::SettlementTx,
    },
    operator::{Operator, StagedDeposit, rpc as operator_rpc},
    protocol::{MIN_DEALING_BYTES, Timing, short_digest},
    rpc, ui,
};
use anyhow::{Context, Result, bail, ensure};
use commonware_clearing::bajillion::boundary::WithdrawalBatch;
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_cryptography::sha256::Digest;
#[cfg(test)]
use commonware_cryptography::{Hasher as _, Sha256};
#[cfg(test)]
use commonware_runtime::{Clock, Listener};
use commonware_runtime::{Handle, Network, Runner as _, Spawner as _, Supervisor as _, tokio};
use commonware_utils::sync::Mutex;
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
            .with_read_write_timeout(Duration::from_secs(5))
            .with_zero_linger(false),
    )
}

pub(crate) fn run_operator(
    bind: SocketAddr,
    node_dir: PathBuf,
    database: PathBuf,
    workers: NonZeroUsize,
    proof_replica: bool,
) -> Result<()> {
    let runtime = tokio::Runner::new(
        tokio::Config::new()
            .with_worker_threads(3)
            .with_connect_timeout(Duration::from_secs(5))
            .with_read_write_timeout(Duration::from_secs(5))
            .with_zero_linger(false)
            .with_storage_directory(node_dir.join("runtime")),
    );
    runtime.start(move |context| async move {
        // The operator joins the chain as a non-signing p2p secondary: every
        // settlement fact it acts on comes from its own verified finalized
        // state and every settlement input goes onto the transaction channel
        // directly. The close worker certifies over the DA channel through
        // the returned pipeline.
        let config = crate::chain::setup::OperatorConfig::load(&node_dir)
            .context("load operator node config")?;
        let (mut chain, pipeline, mut handles) = node::start(context.child("node"), &node_dir)
            .await
            .context("start operator follower node")?;
        let genesis = crate::chain::setup::read_genesis(&node_dir)?;
        let entry = registered_operator(
            &context,
            &mut chain,
            genesis.native.chain_id(),
            config.deployment,
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

        // Settlement assigns every epoch's deadlines under the genesis timing
        // policy when the epoch becomes the admission frontier, so the
        // operator carries no timing knob: it adopts them from its certified
        // registration reads. The one operator is shared between the RPC loop
        // and the close driver, locked around each synchronous call and never
        // across an await.
        let operator = Arc::new(Mutex::new(
            Operator::open_remote(
                &database,
                workers,
                pipeline,
                &entry.deployment,
                config.clearing,
                config.ack,
                epoch_fee,
                proof_replica,
            )
            .context("initialize SQLite operator")?,
        ));
        let payment_strategy = operator.lock().payment_strategy();
        synchronize(&context, &mut chain, &operator, genesis.timing()).await?;

        let driver_handle =
            start_close_driver(&context, chain.clone(), operator.clone(), genesis.timing());
        handles.push(driver_handle);
        let timing = genesis.timing();
        let (payment_sender, payment_handle) = payments::start(
            context.child("payments"),
            chain.clone(),
            operator.clone(),
            payment_strategy,
        );
        handles.push(payment_handle);
        let listener = context.bind(bind).await.context("bind operator RPC")?;
        println!("Operator ready at {bind}");
        println!("Ready to accept payments; epochs close automatically.");

        // The agent-facing RPC loop, supervised alongside the node actors.
        let rpc_handle = context.child("rpc").spawn({
            let chain = chain.clone();
            let operator = operator.clone();
            move |context| async move {
                let request_context = context.child("request");
                payments::serve_connections(context, listener, move |request| {
                    let mut chain = chain.clone();
                    let operator = operator.clone();
                    let payment_sender = payment_sender.clone();
                    let context = request_context.child("connection");
                    async move {
                        match operator_rpc::decode_request(request) {
                            Ok(operator_rpc::OperatorRequest::AcceptSends(request)) => {
                                payments::submit(
                                    &payment_sender,
                                    request,
                                    payments::ResponseKind::Batch,
                                )
                                .await
                            }
                            Ok(operator_rpc::OperatorRequest::AcceptSend(request)) => {
                                payments::submit(
                                    &payment_sender,
                                    operator_rpc::AcceptSendsRequest {
                                        sends: vec![request],
                                    },
                                    payments::ResponseKind::Single,
                                )
                                .await
                            }
                            Ok(request) => {
                                match prepare_request(
                                    &context,
                                    &mut chain,
                                    &operator,
                                    &request,
                                    timing,
                                )
                                .await
                                {
                                    Ok(Some(response)) => response,
                                    Ok(None) => {
                                        operator_rpc::handle_decoded(&mut operator.lock(), request)
                                    }
                                    Err(error) => rpc::error_response(format!("{error:#}")),
                                }
                            }
                            Err(error) => rpc::error_response(format!("{error:#}")),
                        }
                    }
                })
                .await
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
) -> Result<RegistryEntry> {
    // Registration is immutable. Historical presence authenticates the operator while its
    // follower catches up, and historical absence cannot reject a later registration.
    let request = chain.request(Lookup::RegistryEntry {
        chain_id,
        deployment,
    });
    for attempt in 0..REGISTER_ATTEMPTS {
        match chain.read(ctx, &request).await {
            Ok(verified) => match verified.record {
                Some(Record::RegistryEntry(entry)) if *entry.deployment.digest() == deployment => {
                    return Ok(entry);
                }
                None => {}
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

/// Observes the chain's inbox and authenticates the state used to release RPC intake.
pub(crate) async fn synchronize<E: Env, C: Chain>(
    ctx: &E,
    chain: &mut C,
    operator: &Mutex<Operator>,
    timing: Timing,
) -> Result<()> {
    // Intake observed while the operator was down is recorded, and the recovered live
    // registration is authenticated, before fresh reads can succeed. RPC intake remains gated
    // on the same recent canonical fault check as steady state.
    for attempt in 0..REGISTER_ATTEMPTS {
        match drive_closes(ctx, chain, operator, timing).await {
            Ok(()) => return Ok(()),
            Err(error)
                if operator.lock().ensure_store_usable().is_err()
                    || attempt + 1 == REGISTER_ATTEMPTS =>
            {
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
    let verified = chain.recent(ctx, &fault_request).await?;
    let finalized = verified
        .payout_tip
        .context("certified fault read omitted the finalization boundary")?
        .finalized;
    if let Some(finalized) = finalized {
        operator.lock().observe_finalized(finalized)?;
    }
    let fault = match verified.record {
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
        if finalized.is_some_and(|finalized| epoch <= finalized) {
            continue;
        }
        match chain.admitted(ctx, epoch).await? {
            Some(record) if Some(record.batch_id) == invalid_batch => {
                invalid_from = Some(epoch);
                break;
            }
            Some(record) => {
                operator.lock().observe_admitted(epoch, &record)?;
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

    // A restarted operator authenticates only its live registration before
    // intake resumes: earlier closes keep progressing without holding it.
    let Some(epoch) = operator.lock().recovering_epoch() else {
        return Ok(());
    };
    let request = chain.request(Lookup::Registration { epoch });
    let verified = chain.recent(ctx, &request).await?;
    let record = match verified.record {
        Some(Record::Registration(record)) => Some(record),
        None => None,
        Some(_) => bail!("certified registration read returned a foreign record"),
    };
    let status = chain.recent_status(ctx).await?;
    ensure!(
        status.height >= verified.height,
        "settlement status predates the recovered registration read"
    );
    operator.lock().release_recovery(record.as_ref(), &status)
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

/// Records observed intake, advances durable admission and finalized custody, then schedules
/// the live epoch.
async fn drive_closes<E: Env, C: Chain>(
    ctx: &E,
    chain: &mut C,
    operator: &Mutex<Operator>,
    timing: Timing,
) -> Result<()> {
    observe(ctx, chain, operator).await?;
    observe_closes(ctx, chain, operator).await?;
    reconcile_withdrawals(ctx, chain, operator).await?;
    let Some(epoch) = operator.lock().automatic_epoch()? else {
        return Ok(());
    };
    let request = chain.request(Lookup::Registration { epoch });
    let verified = chain.recent(ctx, &request).await?;
    if let Some(Record::Registration(record)) = verified.record {
        let mut operator = operator.lock();
        if operator.automatic_epoch()? == Some(epoch) {
            operator.adopt_registration(&record)?;
            operator.close_if_due(&record, verified.height, timing)?;
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
            commonware_cryptography::sha256::Digest::decode(bytes)
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
            let recipient =
                crate::protocol::Key::decode(bytes).context("invalid native recipient key")?;
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
            let eve_database =
                database.with_file_name(format!("terminal-agent-{selected}-4.sqlite"));
            let eve = Agent::open_for(&eve_database, 4, selected, agent.operator())
                .context("initialize Eve's SQLite agent")?;
            Box::pin(ui::scripted(&context, operator, chain, agent, eve)).await?;
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

/// Releases unregistered reservations after their signed intake context is permanently invalid.
async fn reconcile_withdrawals<E: Env, C: Chain>(
    ctx: &E,
    chain: &mut C,
    operator: &Mutex<Operator>,
) -> Result<()> {
    let Some((expected, withdrawals)) = operator.lock().unregistered_withdrawals()? else {
        return Ok(());
    };
    let status = chain.recent_status(ctx).await?;
    if status.hard_faulted {
        return Ok(());
    }
    let mut barrier = status.height;
    let mut discarded = Vec::new();
    for request in withdrawals.requests() {
        // Finalized QMDB roots commit a growing operation history and cannot recur.
        // Exact queued requests retain their root and deadline until settlement consumes them.
        // A request the account queues on chain after the boundary was built cannot fail the
        // registration, which supersedes it.
        if request.body().deadline() > status.height
            && request.body().state_root() == &status.state_root.digest
        {
            continue;
        }
        let lookup = chain.request(Lookup::Withdrawal {
            account: request.account().clone(),
        });
        let queued = chain.recent(ctx, &lookup).await?;
        ensure!(
            queued.height >= status.height,
            "withdrawal queue predates the intake barrier"
        );
        barrier = barrier.max(queued.height);
        match queued.record {
            Some(Record::Withdrawal(accepted)) if accepted.request == *request => {}
            Some(Record::Withdrawal(_)) | None => discarded.push(request.clone()),
            Some(_) => bail!("certified withdrawal read returned a foreign record"),
        }
    }
    if discarded.is_empty() {
        return Ok(());
    }

    // Registration can consume a queued request between reads. Its permanent anchor must
    // therefore be absent at or after every queue exclusion before reservations are restored.
    let anchor = chain.request(Lookup::Anchor {
        epoch: expected.epoch(),
    });
    let verified = chain.recent(ctx, &anchor).await?;
    ensure!(
        verified.height >= barrier,
        "withdrawal anchor predates the intake barrier"
    );
    if verified.record.is_none() {
        operator
            .lock()
            .discard_unregistered_withdrawals(&expected, &WithdrawalBatch::new(discarded)?)?;
    }
    Ok(())
}

/// Handles the settlement interactions one decoded operator request needs
/// before the synchronous dispatch may run, or answers it outright.
///
/// The operator is locked around each synchronous call and never across an
/// await, so intake observation can take rows between the steps. Every
/// dispatched operation revalidates its own preconditions.
pub(crate) async fn prepare_request<E: Env, C: Chain>(
    ctx: &E,
    chain: &mut C,
    operator: &Mutex<Operator>,
    request: &operator_rpc::OperatorRequest,
    timing: Timing,
) -> Result<Option<rpc::Response>> {
    // Proof replica reads can wait on its catch-up, so they run outside the
    // operator lock on a blocking-capable task.
    match request {
        operator_rpc::OperatorRequest::PaymentHead(request) => {
            let snapshot = operator
                .lock()
                .head_snapshot(&request.account)
                .context("read payment head")?;
            let head = ctx
                .child("head")
                .shared(true)
                .spawn(move |_| async move { snapshot.resolve() })
                .await
                .context("payment head task failed")?
                .context("read payment head")?;
            return Ok(Some(rpc::Response::Success {
                body: operator_rpc::PaymentHeadResponse::from(head).encode(),
            }));
        }
        operator_rpc::OperatorRequest::WithdrawalOpening(request) => {
            let snapshot = operator
                .lock()
                .opening_snapshot(&request.account)
                .context("read withdrawal opening")?;
            let opening = ctx
                .child("opening")
                .shared(true)
                .spawn(move |_| async move { snapshot.resolve() })
                .await
                .context("withdrawal opening task failed")?
                .context("read withdrawal opening")?;
            return Ok(Some(rpc::Response::Success {
                body: operator_rpc::WithdrawalOpeningResponse::from(opening).encode(),
            }));
        }
        _ => {}
    }
    if let operator_rpc::OperatorRequest::ApplyWithdrawal(request) = request {
        for attempt in 0..SUBMIT_ATTEMPTS {
            if attempt > 0 {
                ctx.sleep(POLL).await;
            }
            if operator
                .lock()
                .staged_withdrawal(&request.request)?
                .is_some()
            {
                return Ok(None);
            }
            let expected = operator.lock().registration_boundary()?.0;
            let status = chain.recent_status(ctx).await?;
            ensure!(
                !status.hard_faulted,
                "withdrawal deployment is hard-faulted"
            );
            request
                .request
                .verify_deployment(&status.deployment)
                .context("verify withdrawal authorization")?;
            let inclusion = status
                .height
                .checked_add(1)
                .context("withdrawal inclusion height overflow")?;
            let config = crate::protocol::settlement_config(&timing)?;
            let minimum = inclusion
                .checked_add(config.minimum_withdrawal_notice.get())
                .context("withdrawal notice overflow")?;
            let maximum = inclusion.saturating_add(config.maximum_withdrawal_notice.get());
            let deadline = request.request.body().deadline();
            let current_root = request.request.body().state_root() == &status.state_root.digest;
            let valid_notice = (minimum..=maximum).contains(&deadline);

            let lookup = chain.request(Lookup::Withdrawal {
                account: request.request.account().clone(),
            });
            let queued = chain.recent(ctx, &lookup).await?;
            ensure!(
                queued.height >= status.height && deadline > queued.height,
                "withdrawal has expired"
            );
            let index = match queued.record {
                Some(Record::Withdrawal(accepted)) => {
                    (accepted.request == request.request).then_some(accepted.index)
                }
                None => None,
                Some(_) => bail!("certified withdrawal read returned a foreign record"),
            };
            let queued = index.is_some();
            if !queued {
                ensure!(
                    current_root,
                    "withdrawal reference root differs from the current finalized state"
                );
                ensure!(
                    valid_notice,
                    "withdrawal deadline {deadline} is outside [{minimum}, {maximum}] at height {}",
                    status.height
                );
            }

            // Publication fixes the current boundary. Keep this authorization intact
            // until the close driver opens a successor boundary for it.
            {
                let mut operator = operator.lock();
                if operator.registration_boundary()?.0 != expected {
                    continue;
                }
                if !operator.withdrawals_frozen()? {
                    // Only this operator's registrations supersede a queued request, and the
                    // unpublished boundary follows every one of them, so its store decides.
                    if let Some(index) = index {
                        ensure!(
                            !operator.superseded(&request.request, index)?,
                            "a registered withdrawal superseded the queued request"
                        );
                    }
                    return Ok(Some(operator_rpc::apply_withdrawal_confirmed(
                        &mut operator,
                        request.clone(),
                        queued,
                    )));
                }
            }
            drive_closes(ctx, chain, operator, timing).await?;
        }
        bail!("the next withdrawal boundary did not open in time; retry the saved request");
    }

    if !matches!(
        request,
        operator_rpc::OperatorRequest::AcceptSend(_) | operator_rpc::OperatorRequest::StartClose(_)
    ) {
        return Ok(None);
    }
    register_epoch(ctx, chain, operator, |operator| {
        Ok(match request {
            operator_rpc::OperatorRequest::AcceptSend(request) => operator
                .send_requires_epoch_registration(&request.authorization, &request.entries)?,
            operator_rpc::OperatorRequest::StartClose(request) => {
                if operator.close_already_started(request.expected_epoch)? {
                    false
                } else {
                    operator.validate_close_start(request.expected_epoch)?;
                    true
                }
            }
            _ => false,
        })
    })
    .await?;
    Ok(None)
}

/// Records the certified inbox entries the operator has not observed and lets its live boundary
/// take them. Returns the newly credited deposits.
///
/// An entry persists from its recording until a registration pulls it. Only this operator's
/// registrations pull, and only indices it observed, so every index from the observed cursor up
/// to the status's inbox length is present at the status height or later. A missing entry is an
/// error, never an exclusion. Observation is idempotent by index, so a failed read or commit
/// observes the same entries again, and nothing depends on block delivery.
pub(crate) async fn observe<E: Env, C: Chain>(
    ctx: &E,
    chain: &mut C,
    operator: &Mutex<Operator>,
) -> Result<Vec<StagedDeposit>> {
    let from = operator.lock().observed()?;
    let status = chain.recent_status(ctx).await?;

    // A faulted deployment refunds unadmitted deposits, so the operator credits none of them.
    if status.hard_faulted {
        return Ok(Vec::new());
    }
    let records = chain.inbox(ctx, from..status.intake).await?;
    let staged = operator
        .lock()
        .observe(from, &records)
        .context("record observed intake")?;
    for deposit in &staged {
        println!(
            "observed deposit {} at inbox index {}: staged {} for {} into epoch {}",
            short_digest(&deposit.id),
            deposit.index,
            deposit.amount,
            deposit.account,
            deposit.epoch
        );
    }
    Ok(staged)
}

/// Publishes the live boundary while its triggering request remains valid, then
/// adopts the anchor, floors, and any assigned deadlines from the certified
/// registration. Each attempt observes the certified inbox before it signs, so
/// the boundary takes the intake recorded so far. That intake is recorded at or
/// below a finalized height, so every block that can include the registration
/// builds on it. Rechecking under the operator
/// lock keeps expiry cleanup and intake observation from publishing a boundary
/// for work that is no longer eligible.
///
/// Registration waits for no earlier close: the chain accepts the live epoch
/// once its predecessor is registered, and an unfinished predecessor only
/// defers the epoch's deadlines.
async fn register_epoch<E: Env, C: Chain>(
    ctx: &E,
    chain: &mut C,
    operator: &Mutex<Operator>,
    required: impl Fn(&Operator) -> Result<bool>,
) -> Result<()> {
    let mut epoch = None;
    for attempt in 0..REGISTER_ATTEMPTS {
        if attempt > 0 {
            ctx.sleep(REGISTER_POLL).await;
        }

        // Only an attempt that will register reads the chain, so a request that needs no
        // registration never waits on it.
        if !required(&operator.lock())? {
            return Ok(());
        }
        observe(ctx, chain, operator)
            .await
            .context("register settlement epoch")?;
        reconcile_withdrawals(ctx, chain, operator).await?;
        let request = {
            let mut operator = operator.lock();
            if !required(&operator)? {
                return Ok(());
            }
            operator.signed_registration()?
        };
        let registering = request.epoch;
        ensure!(
            epoch.is_none_or(|epoch| epoch == registering),
            "the live epoch moved during registration"
        );
        epoch = Some(registering);
        chain
            .deliver(ctx, &SettlementTx::RegisterEpoch(request))
            .await
            .context("register settlement epoch")?;
        for _ in 0..CONFIRM_ATTEMPTS {
            let record = chain
                .registration_at(ctx, registering)
                .await
                .context("read back the registered epoch")?;
            if let Some(record) = record {
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
                registration_key, status_key, withdrawal_key,
            },
        },
        protocol::{DepositEvent, deployment, wallets},
    };
    use bytes::Bytes;
    use commonware_clearing::bajillion::boundary::{SignedWithdrawal, WithdrawalAction};
    use commonware_codec::{Decode as _, RangeCfg};
    use commonware_runtime::deterministic;
    use std::{
        fs,
        num::NonZeroU64,
        path::{Path, PathBuf},
        sync::{
            atomic::{AtomicBool, AtomicU64, Ordering},
            mpsc,
        },
    };

    /// The in-process chain's query address.
    const CHAIN: SocketAddr =
        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 9_700);

    /// A query address nothing listens on.
    const UNREACHABLE: SocketAddr =
        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 9_701);

    static TEMP_DATABASE_ID: AtomicU64 = AtomicU64::new(0);

    struct NoNetworkChain;

    impl Chain for NoNetworkChain {
        fn holders(&self) -> Result<Vec<SocketAddr>> {
            unreachable!("the registered payment fixture does not query the chain")
        }

        fn deployment(&self) -> Digest {
            crate::protocol::deployment()
        }

        async fn read<E: Env>(&mut self, _: &E, _: &ReadRequest) -> Result<Verified> {
            unreachable!("the registered payment fixture does not query the chain")
        }

        async fn recent<E: Env>(&mut self, _: &E, _: &ReadRequest) -> Result<Verified> {
            unreachable!("the registered payment fixture does not query the chain")
        }

        async fn inbox<E: Env>(
            &mut self,
            _: &E,
            _: std::ops::Range<u64>,
        ) -> Result<Vec<crate::chain::state::Intake>> {
            unreachable!("the registered payment fixture does not query the chain")
        }

        async fn submit<E: Env>(&mut self, _: &E, _: &SettlementTx) -> Result<Submission> {
            unreachable!("the registered payment fixture does not query the chain")
        }
    }

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
            let prepared = prepare_request(
                context,
                chain,
                operator,
                &request,
                crate::protocol::Timing::DEFAULT,
            )
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

            let mut recovered_agent = Agent::open(databases.agent(), 0).unwrap();
            let Some(release) = recovered_agent
                .recover_hard_fault(&context, &mut agent_chain)
                .await
                .unwrap()
            else {
                panic!("funded account has no hard-fault release")
            };
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
            let Some(retry) = recovered_agent
                .recover_hard_fault(&context, &mut agent_chain)
                .await
                .unwrap()
            else {
                panic!("funded account has no hard-fault release")
            };
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
    fn withdrawal_from_first_deposit_requires_a_predecessor_account() {
        for action in [
            WithdrawalAction::Amount(NonZeroU64::new(5).unwrap()),
            WithdrawalAction::Close,
        ] {
            deterministic::Runner::default().start(|context| async move {
                let control = harness::start(&context, CHAIN, "chain").await;
                let mut chain = client(&context, &control);
                let operator =
                    Mutex::new(Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap());
                let wallet = crate::protocol::eve_wallet();
                Agent::new(0)
                    .unwrap()
                    .transfer_native(&context, &mut chain, wallet.public_key(), 7)
                    .await
                    .unwrap();
                let deposit = DepositEvent {
                    id: Sha256::hash(&[b"first-deposit-withdrawal"]),
                    account: wallet.public_key(),
                    amount: 7,
                };
                chain
                    .deliver(
                        &context,
                        &SettlementTx::Deposit(crate::chain::tx::DepositRequest::sign(
                            chain.genesis().native.chain_id(),
                            deployment(),
                            deposit.clone(),
                            wallet.signer(),
                        )),
                    )
                    .await
                    .unwrap();
                let effect = chain.deposit(&context, deposit.id).await.unwrap().unwrap();
                assert_eq!(effect.event, deposit);
                assert_eq!(
                    observe(&context, &mut chain, &operator)
                        .await
                        .unwrap()
                        .len(),
                    1
                );
                assert!(
                    operator
                        .lock()
                        .withdrawal_opening(&wallet.public_key())
                        .is_err()
                );

                // The authorization is valid, but the new deposit has no predecessor leaf.
                let status = chain.recent_status(&context).await.unwrap();
                let deadline = status.height
                    + crate::protocol::settlement_config(&Timing::DEFAULT)
                        .unwrap()
                        .maximum_withdrawal_notice
                        .get();
                let withdrawal = SignedWithdrawal::sign(
                    deployment(),
                    status.state_root.digest,
                    wallet.public_key().encode(),
                    action,
                    deadline,
                    wallet.signer(),
                );
                let request = operator_rpc::OperatorRequest::ApplyWithdrawal(
                    operator_rpc::ApplyWithdrawalRequest {
                        request: withdrawal.clone(),
                    },
                );
                let response =
                    prepare_request(&context, &mut chain, &operator, &request, Timing::DEFAULT)
                        .await
                        .unwrap()
                        .unwrap();
                assert!(
                    matches!(response, rpc::Response::Error { .. }),
                    "withdrawal without a predecessor opening was carried: {response:?}"
                );
                assert!(
                    operator
                        .lock()
                        .staged_withdrawal(&withdrawal)
                        .unwrap()
                        .is_none()
                );

                // Rejecting the withdrawal leaves its deposit boundary publishable.
                register_epoch(&context, &mut chain, &operator, |_| Ok(true))
                    .await
                    .unwrap();
                let registered = chain.registration(&context).await.unwrap().unwrap();
                assert_eq!(registered.epoch, 0);
                assert!(
                    operator
                        .lock()
                        .signed_registration()
                        .unwrap()
                        .withdrawals
                        .requests()
                        .is_empty()
                );
            });
        }
    }

    #[test]
    fn withdrawal_after_payment_waits_for_next_boundary() {
        deterministic::Runner::timed(Duration::from_secs(15)).start(|context| async move {
            let control = harness::start(&context, CHAIN, "chain").await;
            let mut chain = client(&context, &control);
            let operator =
                Mutex::new(Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap());
            register_epoch(&context, &mut chain, &operator, |_| Ok(true))
                .await
                .unwrap();
            operator.lock().pay(0, 1, 5).unwrap();

            let head = chain.recent_status(&context).await.unwrap();
            let wallet = wallets().remove(0);
            let deadline = head.height
                + crate::protocol::settlement_config(&Timing::DEFAULT)
                    .unwrap()
                    .maximum_withdrawal_notice
                    .get();
            let withdrawal = SignedWithdrawal::sign(
                deployment(),
                head.state_root.digest,
                wallet.public_key().encode(),
                WithdrawalAction::Close,
                deadline,
                wallet.signer(),
            );
            let request = operator_rpc::OperatorRequest::ApplyWithdrawal(
                operator_rpc::ApplyWithdrawalRequest {
                    request: withdrawal.clone(),
                },
            );
            let response =
                prepare_request(&context, &mut chain, &operator, &request, Timing::DEFAULT)
                    .await
                    .unwrap()
                    .unwrap();
            assert!(
                matches!(response, rpc::Response::Success { .. }),
                "{response:?}"
            );
            let staged = operator
                .lock()
                .staged_withdrawal(&withdrawal)
                .unwrap()
                .unwrap();
            assert_eq!(staged.epoch, 1);
            assert!(
                chain
                    .status(&context)
                    .await
                    .unwrap()
                    .last_finalized
                    .is_none()
            );
            operator.lock().wait_for_closes().unwrap();
            let carrying = operator.lock().signed_registration().unwrap();
            let predecessor = operator
                .lock()
                .payment_head(&wallet.public_key())
                .unwrap()
                .root;
            assert_eq!(carrying.epoch, 1);
            assert_eq!(
                carrying.withdrawals.requests(),
                std::slice::from_ref(&withdrawal)
            );
            assert_ne!(withdrawal.body().state_root(), &predecessor.digest);
        });
    }

    #[derive(Clone, Copy)]
    enum WithdrawalRootAdvance {
        Fresh,
        Registered,
        Queued,
        Mixed,
    }

    fn staged_withdrawal_root_advance(action: WithdrawalAction, retention: WithdrawalRootAdvance) {
        deterministic::Runner::timed(Duration::from_secs(15)).start(|context| async move {
            let control = harness::start(&context, CHAIN, "staged-root-advance").await;
            let mut chain = client(&context, &control);
            let operator =
                Mutex::new(Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap());
            let wallets = wallets();
            let wallet = &wallets[0];
            let queued_wallet = if matches!(retention, WithdrawalRootAdvance::Mixed) {
                &wallets[1]
            } else {
                wallet
            };
            let queued_opening = operator.lock().withdrawal_opening(&queued_wallet.public_key()).unwrap();
            register_epoch(&context, &mut chain, &operator, |_| Ok(true))
                .await
                .unwrap();
            let first = chain.registration(&context).await.unwrap().unwrap();
            operator.lock().pay(0, 1, 5).unwrap();
            let close = operator.lock().complete_close(1).unwrap();
            control
                .submit(SettlementTx::Admit(crate::chain::tx::AdmitRequest::from(
                    &close,
                )))
                .await;
            let head = chain.recent_status(&context).await.unwrap();
            assert_eq!(head.last_finalized, None);
            assert!(!chain.admitted(&context, 0).await.unwrap().unwrap().finalized);
            let deadline = head.height
                + crate::protocol::settlement_config(&Timing::DEFAULT)
                    .unwrap()
                    .maximum_withdrawal_notice
                    .get();
            let withdrawal = SignedWithdrawal::sign(
                deployment(),
                head.state_root.digest,
                wallet.public_key().encode(),
                action,
                deadline,
                wallet.signer(),
            );
            let queued = matches!(retention, WithdrawalRootAdvance::Queued | WithdrawalRootAdvance::Mixed)
                .then(|| if matches!(retention, WithdrawalRootAdvance::Mixed) {
                    SignedWithdrawal::sign(
                        deployment(), head.state_root.digest, queued_wallet.public_key().encode(),
                        WithdrawalAction::Amount(NonZeroU64::new(3).unwrap()), deadline,
                        queued_wallet.signer(),
                    )
                } else { withdrawal.clone() });
            if let Some(queued) = &queued {
                control.submit(SettlementTx::QueueWithdrawal(crate::chain::tx::QueueWithdrawalRequest {
                    request: queued.clone(), opening: queued_opening.opening,
                })).await;
                assert_eq!(chain.withdrawal(&context, queued_wallet.public_key()).await.unwrap().as_ref(), Some(queued));
                let request = operator_rpc::OperatorRequest::ApplyWithdrawal(operator_rpc::ApplyWithdrawalRequest { request: queued.clone() });
                let response = prepare_request(&context, &mut chain, &operator, &request, Timing::DEFAULT).await.unwrap().unwrap();
                assert!(matches!(response, rpc::Response::Success { .. }), "{response:?}");
            }
            let request = operator_rpc::OperatorRequest::ApplyWithdrawal(
                operator_rpc::ApplyWithdrawalRequest {
                    request: withdrawal.clone(),
                },
            );
            let response =
                prepare_request(&context, &mut chain, &operator, &request, Timing::DEFAULT)
                    .await
                    .unwrap()
                    .unwrap_or_else(|| operator_rpc::handle_decoded(&mut operator.lock(), request));
            assert!(matches!(response, rpc::Response::Success { .. }), "{response:?}");
            let published = operator.lock().signed_registration().unwrap();
            assert_eq!(published.epoch, 1);
            assert_eq!(published.withdrawals.request_for(withdrawal.account()), Some(&withdrawal));
            if matches!(retention, WithdrawalRootAdvance::Registered) {
                control.submit(SettlementTx::RegisterEpoch(published.clone())).await;
                assert_eq!(chain.registration(&context).await.unwrap().unwrap().epoch, 1);
                assert!(operator.lock().unregistered_withdrawals().unwrap().is_some());
            }

            // Earlier close finality advances while the exact withdrawal authorizations remain retained.
            advance_to(&control, first.deadlines.unwrap().1 + 1).await;
            let advanced = chain.recent_status(&context).await.unwrap();
            assert_eq!(advanced.last_finalized, Some(0));
            assert_ne!(advanced.state_root.digest, head.state_root.digest);
            assert!(advanced.height < deadline);
            let anchor = chain.request(Lookup::Anchor { epoch: 1 });
            if !matches!(retention, WithdrawalRootAdvance::Fresh) {
                for _ in 0..2 {
                    reconcile_withdrawals(&context, &mut chain, &operator).await.unwrap();
                }
                let retained = operator.lock().signed_registration().unwrap();
                if matches!(retention, WithdrawalRootAdvance::Mixed) {
                    assert!(operator.lock().staged_withdrawal(&withdrawal).unwrap().is_none());
                    assert_eq!(operator.lock().payment_head(&wallet.public_key()).unwrap().balance, 95);
                    assert_eq!(retained.withdrawals.requests(), std::slice::from_ref(queued.as_ref().unwrap()));
                    assert_eq!(operator.lock().payment_head(&queued_wallet.public_key()).unwrap().balance, 102);
                } else {
                    assert_eq!(retained, published);
                    assert!(operator.lock().staged_withdrawal(&withdrawal).unwrap().is_some());
                    assert!(operator.lock().unregistered_withdrawals().unwrap().is_some());
                }
                assert!(!status(&control).await.hard_faulted);
                return;
            }
            assert!(chain.recent(&context, &anchor).await.unwrap().record.is_none());
            assert!(chain.withdrawal(&context, wallet.public_key()).await.unwrap().is_none());
            control.submit(SettlementTx::RegisterEpoch(published)).await;
            assert!(chain.recent(&context, &anchor).await.unwrap().record.is_none());

            drive_closes(&context, &mut chain, &operator, Timing::DEFAULT)
                .await
                .unwrap();
            assert!(operator.lock().staged_withdrawal(&withdrawal).unwrap().is_none());
            assert_eq!(operator.lock().payment_head(&wallet.public_key()).unwrap().balance, 95);
            let retry = operator.lock().signed_registration().unwrap();
            control.submit(SettlementTx::RegisterEpoch(retry)).await;
            let current = chain.recent_status(&context).await.unwrap();
            assert!(current.height < deadline);
            assert!(!current.hard_faulted);
            assert_eq!(
                chain.registration(&context).await.unwrap().map(|record| record.epoch),
                Some(1),
                "a staged {action:?} blocked successor registration after finalized-root advancement"
            );
        });
    }

    #[test]
    fn staged_amount_root_advance_keeps_registration_live() {
        staged_withdrawal_root_advance(
            WithdrawalAction::Amount(NonZeroU64::new(7).unwrap()),
            WithdrawalRootAdvance::Fresh,
        );
    }

    #[test]
    fn staged_close_root_advance_keeps_registration_live() {
        staged_withdrawal_root_advance(WithdrawalAction::Close, WithdrawalRootAdvance::Fresh);
    }

    #[test]
    fn registered_withdrawal_root_advance_preserves_unobserved_boundary() {
        for action in [
            WithdrawalAction::Amount(NonZeroU64::new(7).unwrap()),
            WithdrawalAction::Close,
        ] {
            staged_withdrawal_root_advance(action, WithdrawalRootAdvance::Registered);
        }
    }

    #[test]
    fn queued_withdrawal_root_advance_preserves_exact_request() {
        for action in [
            WithdrawalAction::Amount(NonZeroU64::new(7).unwrap()),
            WithdrawalAction::Close,
        ] {
            staged_withdrawal_root_advance(action, WithdrawalRootAdvance::Queued);
        }
    }

    #[test]
    fn mixed_withdrawal_root_advance_restores_only_fresh_reservation() {
        staged_withdrawal_root_advance(
            WithdrawalAction::Amount(NonZeroU64::new(7).unwrap()),
            WithdrawalRootAdvance::Mixed,
        );
    }

    #[test]
    fn queued_withdrawal_settles_the_successor_tail_after_active_epoch_spending() {
        for debit in [0, 98, 100] {
            for credit in [0, 5] {
                for action in [
                    WithdrawalAction::Amount(NonZeroU64::new(4).unwrap()),
                    WithdrawalAction::Close,
                ] {
                    deterministic::Runner::timed(Duration::from_secs(20)).start(
                        |context| async move {
                            let databases = TempDatabases::new();
                            let control =
                                harness::start(&context, CHAIN, "queued-successor-tail").await;
                            let mut chain = client(&context, &control);
                            let operator = Mutex::new(
                                Operator::open(databases.operator(), NonZeroUsize::MIN).unwrap(),
                            );
                            let wallet = wallets().remove(0);
                            let opening = operator
                                .lock()
                                .withdrawal_opening(&wallet.public_key())
                                .unwrap();
                            register_epoch(&context, &mut chain, &operator, |_| Ok(true))
                                .await
                                .unwrap();
                            let first = chain.registration(&context).await.unwrap().unwrap();
                            if debit > 0 {
                                operator.lock().pay(0, 1, debit).unwrap();
                            }
                            let deadline = status(&control).await.height
                                + crate::protocol::settlement_config(&Timing::DEFAULT)
                                    .unwrap()
                                    .maximum_withdrawal_notice
                                    .get();
                            let withdrawal = SignedWithdrawal::sign(
                                deployment(),
                                opening.root.digest,
                                wallet.public_key().encode(),
                                action,
                                deadline,
                                wallet.signer(),
                            );
                            control
                                .submit(SettlementTx::QueueWithdrawal(
                                    crate::chain::tx::QueueWithdrawalRequest {
                                        request: withdrawal.clone(),
                                        opening: opening.opening,
                                    },
                                ))
                                .await;
                            assert_eq!(
                                chain
                                    .withdrawal(&context, wallet.public_key())
                                    .await
                                    .unwrap(),
                                Some(withdrawal.clone())
                            );
                            assert_eq!(chain.registration(&context).await.unwrap(), Some(first));
                            let first_close = operator.lock().complete_close(1).unwrap();
                            assert_eq!(
                                first_close.context.withdrawal_root(),
                                &WithdrawalBatch::<crate::protocol::Key, Digest>::empty()
                                    .root::<Sha256>()
                                    .unwrap()
                            );
                            control
                                .submit(SettlementTx::Admit(crate::chain::tx::AdmitRequest::from(
                                    &first_close,
                                )))
                                .await;

                            let request = operator_rpc::OperatorRequest::ApplyWithdrawal(
                                operator_rpc::ApplyWithdrawalRequest {
                                    request: withdrawal.clone(),
                                },
                            );
                            let response = prepare_request(
                                &context,
                                &mut chain,
                                &operator,
                                &request,
                                Timing::DEFAULT,
                            )
                            .await
                            .unwrap()
                            .unwrap();
                            assert!(
                                matches!(response, rpc::Response::Success { .. }),
                                "debit={debit} credit={credit} action={action:?}: {response:?}"
                            );
                            drop(operator);
                            let operator = Mutex::new(
                                Operator::open(databases.operator(), NonZeroUsize::MIN).unwrap(),
                            );
                            assert!(
                                operator
                                    .lock()
                                    .staged_withdrawal(&withdrawal)
                                    .unwrap()
                                    .is_some()
                            );
                            let registration = operator.lock().signed_registration().unwrap();
                            assert_eq!(registration.epoch, 1);
                            assert_eq!(
                                registration.withdrawals.requests(),
                                std::slice::from_ref(&withdrawal)
                            );
                            control
                                .submit(SettlementTx::RegisterEpoch(registration))
                                .await;
                            let registered = chain.registration(&context).await.unwrap().unwrap();
                            assert_eq!(registered.epoch, 1);
                            operator.lock().adopt_registration(&registered).unwrap();
                            if credit > 0 {
                                operator.lock().pay(1, 0, credit).unwrap();
                            }
                            if debit == 100 {
                                assert!(operator.lock().pay(0, 1, 1).is_err());
                            }
                            let close = operator.lock().complete_close(2).unwrap();
                            let tail = 100 - debit + credit;
                            let expected = match action {
                                WithdrawalAction::Amount(amount) if tail >= amount.get() => {
                                    amount.get()
                                }
                                WithdrawalAction::Amount(_) => 0,
                                WithdrawalAction::Close => tail,
                            };
                            assert_eq!(close.withdrawal_total, expected);
                            let position = close.context.predecessor_logs().payouts.operations;
                            assert_eq!(close.roots.withdrawal_outputs.operations, position + 2);
                            control
                                .submit(SettlementTx::Admit(crate::chain::tx::AdmitRequest::from(
                                    &close,
                                )))
                                .await;
                            advance_to(&control, registered.deadlines.unwrap().1 + 1).await;
                            assert!(
                                chain
                                    .admitted(&context, 1)
                                    .await
                                    .unwrap()
                                    .unwrap()
                                    .finalized
                            );
                            assert_eq!(status(&control).await.claimable, expected);
                            let claim = chain
                                .payout_proof(&context, close.roots.withdrawal_outputs, position)
                                .await
                                .unwrap();
                            assert_eq!(
                                claim
                                    .verify::<Sha256>(&close.roots.withdrawal_outputs)
                                    .unwrap()
                                    .amount(),
                                expected
                            );
                            let before = chain
                                .payout_status(&context, claim.position())
                                .await
                                .unwrap();
                            assert!(before.claimed.is_none());
                            assert!(claim.verify::<Sha256>(&before.head).is_ok());
                            let claim_tx = SettlementTx::ClaimWithdrawal(
                                crate::chain::tx::WithdrawalClaimRequest {
                                    deployment: deployment(),
                                    claim: claim.clone(),
                                },
                            );
                            control.submit(claim_tx.clone()).await;
                            assert!(
                                chain
                                    .payout_status(&context, claim.position())
                                    .await
                                    .unwrap()
                                    .claimed
                                    .is_some()
                            );
                            control.submit(claim_tx).await;
                            assert!(
                                chain
                                    .payout_status(&context, claim.position())
                                    .await
                                    .unwrap()
                                    .claimed
                                    .is_some()
                            );
                            assert_eq!(status(&control).await.claimable, 0);
                            assert!(!status(&control).await.hard_faulted);

                            // Intake receipts outlive carriage. A replay after restart must
                            // return the original acknowledgment without classifying it again.
                            assert_eq!(
                                chain
                                    .withdrawal(&context, wallet.public_key())
                                    .await
                                    .unwrap(),
                                Some(withdrawal.clone())
                            );
                            drop(operator);
                            let operator = Mutex::new(
                                Operator::open(databases.operator(), NonZeroUsize::MIN).unwrap(),
                            );
                            let before = operator.lock().registration_boundary().unwrap();
                            let mut unavailable = unreachable_client(&context);
                            assert!(
                                prepare_request(
                                    &context,
                                    &mut unavailable,
                                    &operator,
                                    &request,
                                    Timing::DEFAULT,
                                )
                                .await
                                .unwrap()
                                .is_none()
                            );
                            let retry = operator_rpc::handle_decoded(&mut operator.lock(), request);
                            assert_eq!(retry.encode(), response.encode());
                            assert_eq!(operator.lock().registration_boundary().unwrap(), before);
                        },
                    );
                }
            }
        }
    }

    #[test]
    fn fresh_withdrawal_application_requires_a_certified_deadline() {
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

            let mut chain = unreachable_client(&context);
            assert!(
                prepare_request(
                    &context,
                    &mut chain,
                    &operator,
                    &request,
                    crate::protocol::Timing::DEFAULT
                )
                .await
                .is_err()
            );
            assert!(
                operator
                    .lock()
                    .staged_withdrawal(&withdrawal)
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                operator
                    .lock()
                    .payment_head(&wallet.public_key())
                    .unwrap()
                    .balance,
                100
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
            let first = operator
                .lock()
                .apply_withdrawal(close.clone(), false)
                .unwrap();
            assert_eq!(first.action, WithdrawalAction::Close);
            operator.lock().adopt_at(0, None).unwrap();
            operator.lock().start_close(0).unwrap();

            let request = operator_rpc::OperatorRequest::ApplyWithdrawal(
                operator_rpc::ApplyWithdrawalRequest {
                    request: close.clone(),
                },
            );
            let mut chain = unreachable_client(&context);
            assert!(
                prepare_request(
                    &context,
                    &mut chain,
                    &operator,
                    &request,
                    crate::protocol::Timing::DEFAULT
                )
                .await
                .unwrap()
                .is_none()
            );
            let mut operator = operator.into_inner();
            let retry = operator.apply_withdrawal(close, false).unwrap();
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
            let error = prepare_request(
                &context,
                &mut bad,
                &operator,
                &request,
                crate::protocol::Timing::DEFAULT,
            )
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

            // A successful registration adopts the certified record. The
            // anchor commits only the boundary, so the pre-registration send
            // already binds the registered anchor.
            let mut good = client(&context, &control);
            assert!(
                prepare_request(
                    &context,
                    &mut good,
                    &operator,
                    &request,
                    crate::protocol::Timing::DEFAULT
                )
                .await
                .unwrap()
                .is_none()
            );
            assert!(operator.lock().snapshot().unwrap().payments.is_empty());
            let registered = match control.record(anchor_key(&deployment(), 0)).await {
                Some(Record::Anchor(anchor)) => anchor,
                record => panic!("expected the epoch-0 anchor, found {record:?}"),
            };
            let record = match control.record(registration_key(&deployment(), 0)).await {
                Some(Record::Registration(record)) => record,
                record => panic!("expected the registration record, found {record:?}"),
            };
            assert_eq!(record.anchor, registered);
            let live = operator.lock().payment_head(&payer.public_key()).unwrap();
            assert_eq!(live.context.payment().anchor(), &registered);
            assert_eq!(head.context.payment().anchor(), &registered);

            // An adopted epoch accepts the original payment without another chain round trip.
            assert!(
                prepare_request(
                    &context,
                    &mut bad,
                    &operator,
                    &request,
                    crate::protocol::Timing::DEFAULT
                )
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
    fn payment_verification_runs_one_group_ahead_of_commits() {
        fn payment(operator: &Mutex<Operator>, payer: usize) -> operator_rpc::AcceptSendsRequest {
            let identities = wallets();
            let recipient = identities[(payer + 1) % identities.len()].public_key();
            let operator = operator.lock();
            let (authorization, entries) = operator.sign_send(payer, &[(recipient, 1)]).unwrap();
            operator_rpc::AcceptSendsRequest {
                sends: vec![operator_rpc::AcceptSendRequest {
                    authorization,
                    entries,
                }],
            }
        }

        let databases = TempDatabases::new();
        let operator_database = databases.operator().to_path_buf();
        let (operator, first, second, third) = deterministic::Runner::timed(Duration::from_secs(
            15,
        ))
        .start(move |context| async move {
            let control = harness::start(&context, CHAIN, "chain").await;
            let operator = Arc::new(Mutex::new(
                Operator::open(&operator_database, NonZeroUsize::new(2).unwrap()).unwrap(),
            ));
            let mut chain = client(&context, &control);
            register_epoch(&context, &mut chain, &operator, |_| Ok(true))
                .await
                .unwrap();
            let first = payment(&operator, 0);
            let second = payment(&operator, 1);
            let third = payment(&operator, 2);
            (operator, first, second, third)
        });

        runtime().start(move |context| async move {
            async fn wait_signal<E: Clock>(context: &E, receiver: &mpsc::Receiver<()>) {
                for _ in 0..100 {
                    if receiver.try_recv().is_ok() {
                        return;
                    }
                    context.sleep(Duration::from_millis(10)).await;
                }
                panic!("payment stage did not make progress");
            }

            struct Releases(Vec<mpsc::Sender<()>>);

            impl Drop for Releases {
                fn drop(&mut self) {
                    for release in &self.0 {
                        let _ = release.send(());
                    }
                }
            }

            let (first_entered, first_commit) = commonware_utils::channel::oneshot::channel();
            let (release_first, first_release) = mpsc::channel();
            let (second_entered, second_commit) = commonware_utils::channel::oneshot::channel();
            let (release_second, second_release) = mpsc::channel();
            let _releases = Releases(vec![release_first.clone(), release_second.clone()]);
            {
                let mut operator = operator.lock();
                operator.gate_next_payment_commit(first_entered, first_release);
                operator.gate_next_payment_commit(second_entered, second_release);
            }

            let (verifier_started, started) = mpsc::sync_channel(4);
            let (verifier_finished, finished) = mpsc::sync_channel(4);
            let hooks = payments::TestHooks {
                verifier_started,
                verifier_finished,
            };
            let strategy = operator.lock().payment_strategy();
            let (sender, coordinator) = payments::start_with_hooks(
                context.child("payments"),
                NoNetworkChain,
                operator,
                strategy,
                hooks,
            );

            let first_response = context.child("first").spawn({
                let sender = sender.clone();
                move |_| async move {
                    payments::submit(&sender, first, payments::ResponseKind::Batch).await
                }
            });
            wait_signal(&context, &started).await;
            wait_signal(&context, &finished).await;
            commonware_macros::select! {
                result = first_commit => result.unwrap(),
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("first payment writer did not reach the commit gate")
                },
            }

            let mut second_response = context.child("second").spawn({
                let sender = sender.clone();
                move |_| async move {
                    payments::submit(&sender, second, payments::ResponseKind::Batch).await
                }
            });
            wait_signal(&context, &started).await;
            wait_signal(&context, &finished).await;
            let second_waited_for_first = futures::poll!(&mut second_response).is_pending();

            let third_response =
                payments::enqueue(&sender, third, payments::ResponseKind::Batch).await;
            context.sleep(Duration::from_millis(100)).await;
            let third_waited_for_ahead =
                matches!(started.try_recv(), Err(mpsc::TryRecvError::Empty));

            release_first.send(()).unwrap();
            let first_succeeded =
                matches!(first_response.await.unwrap(), rpc::Response::Success { .. });
            commonware_macros::select! {
                result = second_commit => result.unwrap(),
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("second payment writer did not reach the commit gate")
                },
            }
            let second_waited_for_commit = futures::poll!(&mut second_response).is_pending();
            release_second.send(()).unwrap();
            let second_succeeded = matches!(
                second_response.await.unwrap(),
                rpc::Response::Success { .. }
            );
            let third_succeeded =
                matches!(third_response.await.unwrap(), rpc::Response::Success { .. });

            coordinator.abort();
            let _ = coordinator.await;
            assert!(first_succeeded && second_succeeded && third_succeeded);
            assert!(
                second_waited_for_first,
                "the ahead group acknowledged before the current commit"
            );
            assert!(
                third_waited_for_ahead,
                "a third verifier started while the ahead slot was occupied"
            );
            assert!(
                second_waited_for_commit,
                "the ahead group acknowledged inside its own commit"
            );
        });
    }

    #[test]
    fn native_large_response_survives_one_request_server_close() {
        const CLIENTS: usize = 16;
        const RESPONSE_BYTES: usize = 512 * 1024;

        runtime().start(|context| async move {
            let listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let body = Bytes::from(vec![0x5a; RESPONSE_BYTES]);
            let expected = body.clone();
            let (completed, completions) = mpsc::sync_channel(CLIENTS);
            let server = context
                .child("large_response")
                .spawn(move |context| async move {
                    payments::serve_connections_with_completion(
                        context,
                        listener,
                        move |request| {
                            assert_eq!(request.body, Bytes::from_static(b"large"));
                            let body = body.clone();
                            async move { rpc::Response::Success { body } }
                        },
                        completed,
                    )
                    .await;
                });

            let mut clients = Vec::with_capacity(CLIENTS);
            for _ in 0..CLIENTS {
                let (mut sink, stream) = context.dial(address).await.unwrap();
                rpc::send_request(
                    &mut sink,
                    &rpc::Request {
                        method: 1,
                        body: Bytes::from_static(b"large"),
                    },
                )
                .await
                .unwrap();
                clients.push((sink, stream));
            }
            for _ in 0..CLIENTS {
                let mut observed = None;
                for _ in 0..500 {
                    match completions.try_recv() {
                        Ok(sent) => {
                            observed = Some(sent);
                            break;
                        }
                        Err(mpsc::TryRecvError::Empty) => {
                            context.sleep(Duration::from_millis(10)).await;
                        }
                        Err(error) => panic!("large-response completion failed: {error}"),
                    }
                }
                assert_eq!(
                    observed,
                    Some(true),
                    "server failed to send a large response"
                );
            }
            for (_, mut stream) in clients {
                assert_eq!(
                    rpc::recv_response(&mut stream).await.unwrap(),
                    rpc::Response::Success {
                        body: expected.clone(),
                    }
                );
            }
            server.abort();
            let _ = server.await;
        });
    }

    #[test]
    fn registration_probe_recheck_error_cannot_admit_payment() {
        deterministic::Runner::default().start(|context| async move {
            let operator = Arc::new(Mutex::new(
                Operator::open(Path::new(":memory:"), NonZeroUsize::new(2).unwrap()).unwrap(),
            ));
            let identities = wallets();
            let request = {
                let operator = operator.lock();
                let (authorization, entries) = operator
                    .sign_send(0, &[(identities[1].public_key(), 1)])
                    .unwrap();
                operator_rpc::AcceptSendsRequest {
                    sends: vec![operator_rpc::AcceptSendRequest {
                        authorization,
                        entries,
                    }],
                }
            };
            let strategy = operator.lock().payment_strategy();
            operator.lock().fail_registration_probe_after(1);
            let (sender, coordinator) = payments::start(
                context.child("payments"),
                NoNetworkChain,
                operator.clone(),
                strategy,
            );

            let response = payments::submit(&sender, request, payments::ResponseKind::Batch).await;
            let no_payment_committed = operator.lock().snapshot().unwrap().payments.is_empty();

            coordinator.abort();
            let _ = coordinator.await;
            assert!(matches!(response, rpc::Response::Error { .. }));
            assert!(
                no_payment_committed,
                "a failed registration recheck admitted an unregistered payment"
            );
        });
    }

    /// Startup retries fresh reads while its follower catches up, then records
    /// the certified inbox before it releases RPC intake.
    #[test]
    fn startup_observes_the_inbox_before_fresh_rpc_readiness() {
        deterministic::Runner::default().start(|context| async move {
            let operator =
                Mutex::new(Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap());
            let mut chain = historical_follower();

            // The follower catches up only after startup has seen a stale read.
            let stale = chain.stale_reads.clone();
            let caught_up = chain.caught_up.clone();
            let catchup = context.child("catchup").spawn(move |_| async move {
                while stale.load(Ordering::SeqCst) == 0 {
                    commonware_runtime::reschedule().await;
                }
                caught_up.store(true, Ordering::SeqCst);
            });

            // Synchronization records the deposit applied during catch-up.
            synchronize(&context, &mut chain, &operator, Timing::DEFAULT)
                .await
                .unwrap();
            catchup.await.unwrap();
            assert_eq!(operator.lock().observed().unwrap(), 1);
            assert_eq!(
                operator
                    .lock()
                    .payment_head(&chain.event.account)
                    .unwrap()
                    .balance,
                107
            );
        });
    }

    #[test]
    fn startup_uses_historical_certified_registry_presence() {
        deterministic::Runner::default().start(|context| async move {
            let mut chain = historical_follower();
            let native = harness::native(crate::protocol::deployments());
            let registered =
                registered_operator(&context, &mut chain, native.chain_id(), deployment())
                    .await
                    .unwrap();
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
            let registered =
                registered_operator(&context, &mut chain, native.chain_id(), deployment())
                    .await
                    .unwrap();
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
        fn holders(&self) -> Result<Vec<SocketAddr>> {
            Ok(vec![CHAIN])
        }
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
                Lookup::Status => Some(Record::Status(crate::chain::state::StatusRecord {
                    height: 1,
                    timestamp: 0,
                    deployment: deployment(),
                    state_root: self.entry.deployment.genesis().root(),
                    last_finalized: None,
                    next_admission: 0,
                    next_registration: 0,
                    intake: 1,
                    pulled: 0,
                    custody: self.event.amount,
                    claimable: 0,
                    hard_faulted: false,
                })),
                Lookup::Intake { index: 0 } => Some(Record::Intake(
                    crate::chain::state::Intake::Deposit(self.event.clone()),
                )),
                Lookup::Fault | Lookup::Registration { .. } => None,
                _ => bail!("unexpected historical follower read"),
            };
            Ok(Verified {
                claimed: None,
                payout_tip: request.lookup.requires_payout_tip().then(|| {
                    crate::protocol::PayoutTip {
                        payouts: commonware_clearing::bajillion::logs::Heads::empty::<
                            crate::protocol::Key,
                            Sha256,
                        >()
                        .payouts,
                        finalized: None,
                    }
                }),
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
        async fn inbox<E: Env>(
            &mut self,
            ctx: &E,
            indices: std::ops::Range<u64>,
        ) -> Result<Vec<crate::chain::state::Intake>> {
            crate::chain::client::inbox(ctx, self, indices).await
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
            assert_eq!(
                observe(&context, &mut chain, &operator)
                    .await
                    .unwrap()
                    .len(),
                1
            );
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
            let registered = chain.registration_at(&context, 0).await.unwrap().unwrap();
            assert!(status(&control).await.height <= registered.deadlines.unwrap().0);
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
            agent.deposit(&context, &mut chain, 10).await.unwrap();
            assert_eq!(
                observe(&context, &mut chain, &operator)
                    .await
                    .unwrap()
                    .len(),
                1
            );
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
            assert!(status(&control).await.height < registered.height + 4);
            drop(operator);

            // The publication boundary survives restart both before and after the
            // certified registration is adopted, even though no receipt was issued.
            // An adopted live registration is authenticated again before intake.
            let operator = Arc::new(Mutex::new(
                Operator::open(databases.operator(), NonZeroUsize::MIN).unwrap(),
            ));
            observe_closes(&context, &mut chain, &operator)
                .await
                .unwrap();
            let before = operator
                .lock()
                .payment_head(&agent.account())
                .unwrap()
                .context;
            let action = WithdrawalAction::Amount(NonZeroU64::new(3).unwrap());
            let rejected = operator
                .lock()
                .withdraw(0, action)
                .err()
                .expect("direct intake must preserve the published withdrawal boundary");
            assert!(format!("{rejected:#}").contains("withdrawals are frozen"));
            assert_eq!(
                operator
                    .lock()
                    .payment_head(&agent.account())
                    .unwrap()
                    .context,
                before
            );
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
                .withdraw(&context, &mut chain, address, action)
                .await
                .unwrap();
            server.await.unwrap();
            let WithdrawalOutcome::Applied { epoch, request } = outcome else {
                panic!("the service did not carry the withdrawal in the successor: {outcome:?}");
            };
            assert_eq!(epoch, 1);
            assert_eq!(
                operator
                    .lock()
                    .staged_withdrawal(&request)
                    .unwrap()
                    .unwrap()
                    .epoch,
                1
            );
            assert_eq!(operator.lock().status().unwrap().epoch, 1);
            assert_eq!(
                chain.registration(&context).await.unwrap().unwrap(),
                registered
            );
            assert_eq!(
                chain.anchor(&context, 0).await.unwrap(),
                Some(registered.anchor)
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

    /// A deposit confirmed after the operator publishes a boundary leaves the
    /// published bytes registrable and joins the successor at cutover.
    #[test]
    fn confirmed_deposit_after_publication_joins_the_successor() {
        deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
            let databases = TempDatabases::new();
            let control = harness::start(&context, CHAIN, "chain").await;
            let mut chain = client(&context, &control);
            let mut agent = Agent::open(databases.agent(), 0).unwrap();
            let operator =
                Mutex::new(Operator::open(databases.operator(), NonZeroUsize::MIN).unwrap());

            // The operator takes the first deposit and publishes epoch 0 over it.
            agent.deposit(&context, &mut chain, 10).await.unwrap();
            assert_eq!(
                observe(&context, &mut chain, &operator)
                    .await
                    .unwrap()
                    .len(),
                1
            );
            let old = operator.lock().signed_registration().unwrap();
            assert_eq!(old.end, 1);
            drop(operator);

            // Custody accepts the next deposit before the published registration
            // executes. The deposit lands past the pulled prefix, so the old
            // signed bytes still register.
            let next = agent.deposit(&context, &mut chain, 2).await.unwrap();
            let effect = chain.deposit(&context, next.id).await.unwrap().unwrap();
            assert_eq!(effect.index, 1);
            chain
                .deliver(&context, &SettlementTx::RegisterEpoch(old.clone()))
                .await
                .unwrap();
            let registered = chain.registration(&context).await.unwrap().unwrap();
            assert_eq!(registered.epoch, 0);
            assert_eq!(registered.pulled, 0..1);

            // A restarted operator observes the later deposit but leaves it
            // untaken, so the published bytes and the withdrawal freeze hold.
            let operator =
                Mutex::new(Operator::open(databases.operator(), NonZeroUsize::MIN).unwrap());
            assert!(
                observe(&context, &mut chain, &operator)
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(operator.lock().observed().unwrap(), 2);
            assert_eq!(
                operator
                    .lock()
                    .payment_head(&agent.account())
                    .unwrap()
                    .balance,
                110
            );
            assert_eq!(operator.lock().signed_registration().unwrap(), old);
            let rejected = operator
                .lock()
                .withdraw(0, WithdrawalAction::Amount(NonZeroU64::new(3).unwrap()))
                .err()
                .expect("the published boundary must keep withdrawals frozen");
            assert!(format!("{rejected:#}").contains("withdrawals are frozen"));

            // The cutover's successor takes the later deposit and credits it.
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
                operator
                    .lock()
                    .payment_head(&agent.account())
                    .unwrap()
                    .balance,
                112
            );
            assert!(!status(&control).await.hard_faulted);
            operator.lock().wait_for_closes().unwrap();
        });
    }

    /// A fresh extra whose reply is lost is escalated onchain after the operator
    /// publishes its boundary. The queue lands past the published end, so the
    /// published registration carries it early, and the successor links the
    /// inbox entry without carrying the request again.
    #[test]
    fn rpc_extra_queued_after_publication_is_carried_once() {
        deterministic::Runner::timed(Duration::from_secs(60)).start(|context| async move {
            let databases = TempDatabases::new();
            let control = harness::start(&context, CHAIN, "chain").await;
            let mut chain = client(&context, &control);
            let mut agent = Agent::open(databases.agent(), 0).unwrap();
            let account = agent.account();
            let operator = Arc::new(Mutex::new(
                Operator::open(databases.operator(), NonZeroUsize::MIN).unwrap(),
            ));

            // The operator stages the withdrawal as a fresh extra, but its reply
            // is lost.
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 3)))
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
                        [operator_rpc::METHOD_WITHDRAWAL_OPENING],
                    )
                    .await;
                    let (_, sink, mut stream) = listener.accept().await.unwrap();
                    let request = rpc::recv_request(&mut stream).await.unwrap();
                    assert_eq!(request.method, operator_rpc::METHOD_APPLY_WITHDRAWAL);
                    let request = operator_rpc::decode_request(request).unwrap();
                    let prepared =
                        prepare_request(&ctx, &mut chain, &operator, &request, Timing::DEFAULT)
                            .await
                            .unwrap();
                    let response = prepared.unwrap_or_else(|| {
                        operator_rpc::handle_decoded(&mut operator.lock(), request)
                    });
                    assert!(
                        matches!(response, rpc::Response::Success { .. }),
                        "{response:?}"
                    );
                    drop(sink);
                }
            });
            let action = WithdrawalAction::Amount(NonZeroU64::new(5).unwrap());
            let outcome = agent
                .withdraw(&context, &mut chain, address, action)
                .await
                .unwrap();
            server.await.unwrap();
            let WithdrawalOutcome::Signed { request, .. } = outcome else {
                panic!("the lost reply confirmed the withdrawal: {outcome:?}");
            };
            assert!(
                operator
                    .lock()
                    .staged_withdrawal(&request)
                    .unwrap()
                    .is_some()
            );

            // The operator publishes epoch 0 over the empty inbox, carrying the
            // extra.
            let published = operator.lock().signed_registration().unwrap();
            assert_eq!(published.end, 0);
            assert_eq!(
                published.withdrawals.requests(),
                std::slice::from_ref(&request)
            );

            // The wallet escalates the request onchain, and the queue lands past
            // the published end.
            assert_eq!(
                agent
                    .escalate_withdrawal(&context, &mut chain)
                    .await
                    .unwrap(),
                request
            );
            let Some(Record::Withdrawal(queued)) = control
                .record(withdrawal_key(&deployment(), &account))
                .await
            else {
                panic!("the escalated request was not queued");
            };
            assert_eq!(queued.request, request);
            assert_eq!(queued.index, 0);

            // The published registration carries the queued request early.
            chain
                .deliver(&context, &SettlementTx::RegisterEpoch(published))
                .await
                .unwrap();
            let registered = chain.registration(&context).await.unwrap().unwrap();
            assert_eq!(registered.epoch, 0);
            assert_eq!(registered.pulled, 0..0);

            // The cutover's successor links the inbox entry without carrying the
            // request again.
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
            let successor = operator.lock().signed_registration().unwrap();
            assert_eq!(successor.end, 1);
            assert!(successor.withdrawals.requests().is_empty());

            // The successor's pull passes the entry, which it need not carry.
            register_epoch(&context, &mut chain, &operator, |_| Ok(true))
                .await
                .unwrap();
            let registered = chain.registration_at(&context, 1).await.unwrap().unwrap();
            assert_eq!(registered.pulled, 0..1);
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
            register_epoch(&context, &mut chain, &operator, |_| Ok(true))
                .await
                .unwrap();
            let registered = chain.registration(&context).await.unwrap().unwrap();
            advance_to(&control, registered.deadlines.unwrap().0 + 1).await;
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
            // before its certified read-back adopts the record.
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
            register_epoch(&context, &mut chain, &operator, |_| Ok(true))
                .await
                .unwrap();
            let record = match control.record(registration_key(&deployment(), 0)).await {
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
            register_epoch(&context, &mut chain, &operator, |_| Ok(true))
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
                    // The head read stages before registration. The first
                    // acceptance registers the same anchor and is accepted,
                    // and its response is lost.
                    let mut accepted = None;
                    for expected_method in [
                        operator_rpc::METHOD_PAYMENT_HEAD,
                        operator_rpc::METHOD_ACCEPT_SEND,
                    ] {
                        let (_, mut sink, mut stream) = operator_listener.accept().await.unwrap();
                        let request = rpc::recv_request(&mut stream).await.unwrap();
                        assert_eq!(request.method, expected_method);
                        let request = operator_rpc::decode_request(request).unwrap();
                        let prepared = prepare_request(
                            &operator_context,
                            &mut chain,
                            &operator,
                            &request,
                            crate::protocol::Timing::DEFAULT,
                        )
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

            // The wallet stages under the pre-registration head. Registration
            // at first receipt leaves the anchor unchanged, so the first
            // acceptance lands and its response is lost.
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

            // The accepted send binds the chain-registered anchor. Epoch 0 is
            // the admission frontier, so its record carries its deadlines.
            let registered = match control.record(anchor_key(&deployment(), 0)).await {
                Some(Record::Anchor(anchor)) => anchor,
                record => panic!("expected the epoch-0 anchor, found {record:?}"),
            };
            assert_eq!(accepted.acceptance.ack.body().anchor(), &registered);
            let admission_deadline = match control.record(registration_key(&deployment(), 0)).await
            {
                Some(Record::Registration(record)) => record.deadlines.unwrap().0,
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
                .query_row("SELECT COUNT(*) FROM agent_payments", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap();
            // No intent concluded: the accepted send remains pending.
            assert_eq!(concluded, 0);
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

            // The restarted operator authenticates its adopted live
            // registration against the chain before it answers the retry.
            let recovered_operator =
                Mutex::new(Operator::open(databases.operator(), NonZeroUsize::MIN).unwrap());
            observe_closes(
                &context,
                &mut client(&context, &control),
                &recovered_operator,
            )
            .await
            .unwrap();
            let mut recovered_operator = recovered_operator.into_inner();
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
            let mut recovered_agent = Agent::open(databases.agent(), 0).unwrap();
            let Some(release) = recovered_agent
                .recover_hard_fault(&context, &mut agent_chain)
                .await
                .unwrap()
            else {
                panic!("funded account has no hard-fault release")
            };
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
            let Some(retry) = recovered_agent
                .recover_hard_fault(&context, &mut agent_chain)
                .await
                .unwrap()
            else {
                panic!("funded account has no hard-fault release")
            };
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
                                .unwrap()
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

    /// A block holding a rejected deposit ahead of its certified twin records
    /// one inbox entry, which stages once across reopen.
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

                // The block includes both transactions, but only the valid one
                // enters custody and the inbox.
                let block = control
                    .seal_batch(vec![
                        SettlementTx::Deposit(rejected),
                        SettlementTx::Deposit(valid),
                    ])
                    .await;
                assert_eq!(block.transactions.len(), 2);
                let effect = chain.deposit(&context, event.id).await.unwrap().unwrap();
                assert_eq!(effect.event, event);
                assert_eq!(effect.index, 0);
                let recorded = status(&control).await;
                assert_eq!(recorded.custody, 407);
                assert_eq!(recorded.intake, 1);

                // Each reopened operator observes the inbox, and only the first
                // stages the credit.
                for expected in [1, 0] {
                    let operator = Mutex::new(
                        Operator::open(databases.operator(), NonZeroUsize::MIN).unwrap(),
                    );
                    let staged = observe(&context, &mut chain, &operator).await.unwrap();
                    assert_eq!(staged.len(), expected);
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

    /// A faulted deployment refunds its unadmitted deposits, so an operator that
    /// observes the inbox only after the fault credits none of them.
    #[test]
    fn observation_after_a_fault_credits_nothing() {
        deterministic::Runner::default().start(|context| async move {
            let control = harness::start(&context, CHAIN, "chain").await;
            let mut chain = client(&context, &control);
            let wallet = wallets().remove(0);
            let account = wallet.public_key();

            // A deposit enters the inbox, and no operator observes it before it expires.
            let event = DepositEvent {
                id: Sha256::hash(&[b"faulted-observation-deposit"]),
                account: account.clone(),
                amount: 7,
            };
            let request = crate::chain::tx::DepositRequest::sign(
                chain.genesis().native.chain_id(),
                deployment(),
                event,
                wallet.signer(),
            );
            chain
                .deliver(&context, &SettlementTx::Deposit(request))
                .await
                .unwrap();
            let recorded = status(&control).await;
            let timeout = crate::protocol::settlement_config(&Timing::DEFAULT)
                .unwrap()
                .deposit_inclusion_timeout
                .get();
            while !status(&control).await.hard_faulted {
                assert!(
                    status(&control).await.height < recorded.height + timeout + 8,
                    "the expired deposit never faulted the deployment"
                );
                control.advance(1).await;
            }

            // The operator observes after the fault and credits nothing.
            let operator =
                Mutex::new(Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap());
            assert!(
                observe(&context, &mut chain, &operator)
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(operator.lock().observed().unwrap(), 0);
            assert_eq!(operator.lock().payment_head(&account).unwrap().balance, 100);
        });
    }

    /// Inbox entries persist until a registration pulls them, so a crash
    /// before the observation commit loses nothing, and the observed cursor
    /// makes any replay a no-op.
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
            let request = crate::chain::tx::DepositRequest::sign(
                chain.genesis().native.chain_id(),
                deployment(),
                event.clone(),
                wallets()[0].signer(),
            );
            chain
                .deliver(&context, &SettlementTx::Deposit(request.clone()))
                .await
                .unwrap();
            let effect = chain.deposit(&context, event.id).await.unwrap().unwrap();
            assert_eq!(effect.event, event);

            // The operator dies after reading the entry but before its
            // observation commits: the cursor stays put, and the entry stays
            // certified.
            let operator =
                Mutex::new(Operator::open(databases.operator(), NonZeroUsize::MIN).unwrap());
            let record = chain.intake(&context, effect.index).await.unwrap().unwrap();
            drop(operator);

            // The restarted operator observes the entry again and stages it.
            let operator =
                Mutex::new(Operator::open(databases.operator(), NonZeroUsize::MIN).unwrap());
            let staged = observe(&context, &mut chain, &operator).await.unwrap();
            assert_eq!(staged.len(), 1);
            assert_eq!(operator.lock().payment_head(&account).unwrap().balance, 107);
            drop(operator);

            // A replay from below the durable cursor stages nothing.
            let operator =
                Mutex::new(Operator::open(databases.operator(), NonZeroUsize::MIN).unwrap());
            let staged = operator.lock().observe(effect.index, &[record]).unwrap();
            assert!(staged.is_empty(), "a replayed entry staged a new credit");
            assert_eq!(operator.lock().payment_head(&account).unwrap().balance, 107);

            // An included but rejected transaction earns no inbox entry, so
            // observation finds nothing new.
            let mut rejected = request;
            rejected.chain_id = Sha256::hash(&[b"foreign-deposit-chain"]);
            rejected.event.id = Sha256::hash(&[b"observed-rejected-deposit"]);
            control.submit(SettlementTx::Deposit(rejected)).await;
            assert_eq!(status(&control).await.intake, 1);
            let staged = observe(&context, &mut chain, &operator).await.unwrap();
            assert!(staged.is_empty());
            assert_eq!(operator.lock().observed().unwrap(), 1);
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
    struct ExpiringRegistration {
        inner: Client,
        control: harness::Control,
        on_submit: bool,
        advanced: bool,
    }

    impl Chain for ExpiringRegistration {
        fn holders(&self) -> Result<Vec<SocketAddr>> {
            self.inner.holders()
        }
        fn deployment(&self) -> Digest {
            self.inner.deployment()
        }
        async fn read<E: Env>(&mut self, ctx: &E, request: &ReadRequest) -> Result<Verified> {
            self.inner.read(ctx, request).await
        }
        async fn recent<E: Env>(&mut self, ctx: &E, request: &ReadRequest) -> Result<Verified> {
            let result = self.inner.recent(ctx, request).await?;
            if !self.on_submit && !self.advanced && matches!(request.lookup, Lookup::Status) {
                self.advanced = true;
                advance_to(&self.control, 40).await;
            }
            Ok(result)
        }
        async fn inbox<E: Env>(
            &mut self,
            ctx: &E,
            indices: std::ops::Range<u64>,
        ) -> Result<Vec<crate::chain::state::Intake>> {
            crate::chain::client::inbox(ctx, self, indices).await
        }
        async fn submit<E: Env>(&mut self, ctx: &E, tx: &SettlementTx) -> Result<Submission> {
            if self.on_submit && !self.advanced {
                assert!(matches!(tx, SettlementTx::RegisterEpoch(_)));
                self.advanced = true;
                advance_to(&self.control, 40).await;
                return Ok(Submission::Accepted);
            }
            self.inner.submit(ctx, tx).await
        }
    }

    #[test]
    fn registration_rechecks_work_after_withdrawal_expiry() {
        for on_submit in [false, true] {
            deterministic::Runner::default().start(|context| async move {
                let control = harness::start(&context, CHAIN, "registration-expiry").await;
                let inner = client(&context, &control);
                let mut chain = ExpiringRegistration {
                    inner,
                    control: control.clone(),
                    on_submit,
                    advanced: false,
                };
                let mut operator =
                    Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
                let wallet = wallets().remove(0);
                let opening = operator.withdrawal_opening(&wallet.public_key()).unwrap();
                let withdrawal = SignedWithdrawal::sign(
                    deployment(),
                    opening.root.digest,
                    wallet.public_key().encode(),
                    WithdrawalAction::Amount(NonZeroU64::new(7).unwrap()),
                    40,
                    wallet.signer(),
                );
                operator
                    .apply_withdrawal(withdrawal.clone(), false)
                    .unwrap();
                let operator = Mutex::new(operator);
                advance_to(&control, 39).await;
                let request =
                    operator_rpc::OperatorRequest::StartClose(operator_rpc::StartCloseRequest {
                        expected_epoch: 0,
                    });
                let result =
                    prepare_request(&context, &mut chain, &operator, &request, Timing::DEFAULT)
                        .await;
                assert!(
                    result.is_err(),
                    "expired work registered an empty replacement epoch"
                );
                assert!(control.record(anchor_key(&deployment(), 0)).await.is_none());
                assert!(
                    operator
                        .lock()
                        .staged_withdrawal(&withdrawal)
                        .unwrap()
                        .is_none()
                );
                assert_eq!(
                    operator
                        .lock()
                        .payment_head(&wallet.public_key())
                        .unwrap()
                        .balance,
                    100
                );
                assert_eq!(operator.lock().automatic_epoch().unwrap(), None);
                assert!(!status(&control).await.hard_faulted);
            });
        }
    }

    /// A fresh extra registers although its account queues another request on chain between
    /// publication and registration. Settlement supersedes the queued request, the successor
    /// consumes its inbox entry without carrying it, and the successor registers too.
    #[test]
    fn queue_after_publication_is_superseded_by_the_extra() {
        deterministic::Runner::timed(Duration::from_secs(15)).start(|context| async move {
            let control = harness::start(&context, CHAIN, "chain").await;
            let mut chain = client(&context, &control);
            let operator =
                Mutex::new(Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap());
            let wallet = wallets().remove(0);
            let opening = operator
                .lock()
                .withdrawal_opening(&wallet.public_key())
                .unwrap();
            let deadline = status(&control).await.height
                + crate::protocol::settlement_config(&Timing::DEFAULT)
                    .unwrap()
                    .maximum_withdrawal_notice
                    .get();
            let sign = |amount| {
                SignedWithdrawal::sign(
                    deployment(),
                    opening.root.digest,
                    wallet.public_key().encode(),
                    WithdrawalAction::Amount(NonZeroU64::new(amount).unwrap()),
                    deadline,
                    wallet.signer(),
                )
            };
            let extra = sign(3);
            let queued = sign(7);

            // The operator stages the extra and publishes epoch 0.
            let request = operator_rpc::OperatorRequest::ApplyWithdrawal(
                operator_rpc::ApplyWithdrawalRequest {
                    request: extra.clone(),
                },
            );
            let response =
                prepare_request(&context, &mut chain, &operator, &request, Timing::DEFAULT)
                    .await
                    .unwrap()
                    .unwrap_or_else(|| operator_rpc::handle_decoded(&mut operator.lock(), request));
            assert!(
                matches!(response, rpc::Response::Success { .. }),
                "{response:?}"
            );
            let published = operator.lock().signed_registration().unwrap();
            assert_eq!(published.epoch, 0);
            assert_eq!(
                published.withdrawals.requests(),
                std::slice::from_ref(&extra)
            );

            // The account queues another request before the registration executes.
            control
                .submit(SettlementTx::QueueWithdrawal(
                    crate::chain::tx::QueueWithdrawalRequest {
                        request: queued.clone(),
                        opening: opening.opening,
                    },
                ))
                .await;
            assert_eq!(
                chain
                    .withdrawal(&context, wallet.public_key())
                    .await
                    .unwrap(),
                Some(queued.clone())
            );

            // The registration still executes, and the queued request sits inside the window
            // its record names.
            control.submit(SettlementTx::RegisterEpoch(published)).await;
            let registered = chain.registration_at(&context, 0).await.unwrap().unwrap();
            assert_eq!(registered.pulled, 0..0);
            assert_eq!(registered.intake, 1);

            // The successor consumes the superseded entry without carrying it and registers.
            operator.lock().adopt_registration(&registered).unwrap();
            observe(&context, &mut chain, &operator).await.unwrap();
            let close = operator.lock().complete_close(1).unwrap();

            // The operator refuses to stage the superseded request, although the chain still
            // holds its queue record.
            let request = operator_rpc::OperatorRequest::ApplyWithdrawal(
                operator_rpc::ApplyWithdrawalRequest {
                    request: queued.clone(),
                },
            );
            let Err(error) =
                prepare_request(&context, &mut chain, &operator, &request, Timing::DEFAULT).await
            else {
                panic!("the operator staged a superseded request");
            };
            assert!(format!("{error:#}").contains("superseded the queued request"));
            assert!(
                operator
                    .lock()
                    .staged_withdrawal(&queued)
                    .unwrap()
                    .is_none()
            );
            let successor = operator.lock().signed_registration().unwrap();
            assert_eq!(successor.epoch, 1);
            assert_eq!(successor.end, 1);
            assert!(successor.withdrawals.requests().is_empty());
            control.submit(SettlementTx::RegisterEpoch(successor)).await;
            assert!(chain.registration_at(&context, 1).await.unwrap().is_some());

            // Epoch 0's close releases the extra.
            control
                .submit(SettlementTx::Admit(crate::chain::tx::AdmitRequest::from(
                    &close,
                )))
                .await;
            let (_, challenge_deadline) = registered.deadlines.unwrap();
            advance_to(&control, challenge_deadline + 1).await;
            let status = status(&control).await;
            assert_eq!(status.last_finalized, Some(0));
            assert_eq!(status.claimable, 3);
            assert!(!status.hard_faulted);
        });
    }

    #[test]
    fn queued_withdrawal_does_not_need_a_second_intake_notice() {
        deterministic::Runner::default().start(|context| async move {
            let control = harness::start(&context, CHAIN, "queued-carriage").await;
            let mut chain = client(&context, &control);
            let operator =
                Mutex::new(Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap());
            let wallet = wallets().remove(0);
            let opening = operator
                .lock()
                .withdrawal_opening(&wallet.public_key())
                .unwrap();
            let deadline = status(&control).await.height
                + 1
                + crate::protocol::settlement_config(&Timing::DEFAULT)
                    .unwrap()
                    .minimum_withdrawal_notice
                    .get();
            let withdrawal = SignedWithdrawal::sign(
                deployment(),
                opening.root.digest,
                wallet.public_key().encode(),
                WithdrawalAction::Amount(NonZeroU64::new(7).unwrap()),
                deadline,
                wallet.signer(),
            );
            control
                .submit(SettlementTx::QueueWithdrawal(
                    crate::chain::tx::QueueWithdrawalRequest {
                        request: withdrawal.clone(),
                        opening: opening.opening,
                    },
                ))
                .await;
            assert_eq!(
                chain
                    .withdrawal(&context, wallet.public_key())
                    .await
                    .unwrap(),
                Some(withdrawal.clone())
            );
            let request = operator_rpc::OperatorRequest::ApplyWithdrawal(
                operator_rpc::ApplyWithdrawalRequest {
                    request: withdrawal,
                },
            );
            let response =
                prepare_request(&context, &mut chain, &operator, &request, Timing::DEFAULT)
                    .await
                    .unwrap()
                    .unwrap();
            assert!(matches!(response, rpc::Response::Success { .. }));
            let registration = operator.lock().signed_registration().unwrap();
            assert_eq!(registration.epoch, 0);
            control
                .submit(SettlementTx::RegisterEpoch(registration))
                .await;
            let registration = chain.registration(&context).await.unwrap().unwrap();
            operator.lock().adopt_registration(&registration).unwrap();
            let close = operator.lock().complete_close(1).unwrap();
            control
                .submit(SettlementTx::Admit(crate::chain::tx::AdmitRequest::from(
                    &close,
                )))
                .await;
            let (_, challenge_deadline) = registration.deadlines.unwrap();
            advance_to(&control, challenge_deadline + 1).await;
            assert!(challenge_deadline + 1 < deadline);
            let status = status(&control).await;
            assert_eq!(status.last_finalized, Some(0));
            assert_eq!(status.claimable, 7);
            assert!(!status.hard_faulted);
        });
    }

    #[test]
    fn expired_unregistered_withdrawal_releases_its_reservation_and_publication() {
        for action in [
            WithdrawalAction::Amount(NonZeroU64::new(7).unwrap()),
            WithdrawalAction::Close,
        ] {
            deterministic::Runner::default().start(|context| async move {
                let databases = TempDatabases::new();
                let control = harness::start(&context, CHAIN, "chain").await;
                let mut chain = client(&context, &control);
                let mut operator = Operator::open(databases.operator(), NonZeroUsize::MIN).unwrap();
                let wallet = wallets().remove(0);
                let opening = operator.withdrawal_opening(&wallet.public_key()).unwrap();
                let request = SignedWithdrawal::sign(
                    deployment(),
                    opening.root.digest,
                    wallet.public_key().encode(),
                    action,
                    40,
                    wallet.signer(),
                );
                operator.apply_withdrawal(request.clone(), false).unwrap();
                let published = operator.signed_registration().unwrap();
                drop(operator);
                advance_to(&control, 40).await;
                assert!(!status(&control).await.hard_faulted);
                for _ in 0..2 {
                    let operator = Mutex::new(
                        Operator::open(databases.operator(), NonZeroUsize::MIN).unwrap(),
                    );
                    drive_closes(&context, &mut chain, &operator, Timing::DEFAULT)
                        .await
                        .unwrap();
                    assert!(
                        operator
                            .lock()
                            .staged_withdrawal(&request)
                            .unwrap()
                            .is_none()
                    );
                    assert_eq!(
                        operator
                            .lock()
                            .payment_head(&wallet.public_key())
                            .unwrap()
                            .balance,
                        100
                    );
                    assert_eq!(operator.lock().automatic_epoch().unwrap(), None);
                    assert!(chain.registration(&context).await.unwrap().is_none());
                }
                control.submit(SettlementTx::RegisterEpoch(published)).await;
                assert!(chain.registration(&context).await.unwrap().is_none());
                assert!(!status(&control).await.hard_faulted);
            });
        }
    }
}
