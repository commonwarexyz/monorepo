use super::*;
use crate::operator::CloseEvent;

#[derive(Default)]
pub(super) struct Schedule {
    withdrawals: usize,
    withdrawal_after_finality: bool,
    payment_head_before_finality: bool,
    payment_epochs: Vec<u64>,
    closes: Vec<u64>,
    withdrawal: Option<operator_rpc::WithdrawalEvidenceResponse>,
    payout: Option<operator_rpc::ExternalPayoutEvidenceResponse>,
}

async fn tick(context: &deterministic::Context) {
    // The production close worker computes on an OS thread while consensus
    // and RPC tasks advance on the deterministic runtime.
    std::thread::sleep(Duration::from_millis(2));
    context.sleep(POLL).await;
}

pub(super) async fn serve<L: Listener>(
    context: deterministic::Context,
    mut listener: L,
    operator: Arc<Mutex<Operator>>,
    mut chain: Node<deterministic::Context, TxSender>,
    genesis: Genesis,
    schedule: Arc<Mutex<Schedule>>,
) {
    let mut verifier = Client::new(
        &genesis,
        deployment(),
        (0..Walkthrough::VALIDATORS)
            .map(walkthrough_query)
            .collect(),
        context.child("schedule_verifier"),
    )
    .unwrap();
    let alice = Agent::new(0).unwrap();
    loop {
        let Ok((_, mut sink, mut stream)) = listener.accept().await else {
            context.sleep(rpc::ACCEPT_RETRY_DELAY).await;
            continue;
        };
        let Ok(request) = rpc::recv_request(&mut stream).await else {
            continue;
        };
        let request = operator_rpc::decode_request(request).unwrap();
        match &request {
            operator_rpc::OperatorRequest::PaymentHead(_) => {
                let finalized = verifier.status(&context).await.unwrap().last_finalized;
                let epoch = operator.lock().status().unwrap().epoch;
                if !schedule.lock().payment_epochs.is_empty()
                    && epoch > finalized.map_or(0, |epoch| epoch + 1)
                {
                    schedule.lock().payment_head_before_finality = true;
                }
            }
            operator_rpc::OperatorRequest::WithdrawalOpening(_) => {
                // Registration must freeze the deposit boundary before a wallet
                // can sign a withdrawal against that epoch.
                for _ in 0..EFFECT_ATTEMPTS {
                    if verifier.registration(&context).await.unwrap().is_some()
                        || verifier
                            .status(&context)
                            .await
                            .unwrap()
                            .last_finalized
                            .is_some()
                    {
                        break;
                    }
                    tick(&context).await;
                }
            }
            operator_rpc::OperatorRequest::ApplyWithdrawal(_) => {
                let status = verifier.status(&context).await.unwrap();
                let opening = operator
                    .lock()
                    .payment_head(&alice.account())
                    .unwrap()
                    .opening;
                assert_eq!(opening.account, alice.account());
                opening.verify::<Sha256>(&status.state_root).unwrap();
                let finished = matches!(
                    operator.lock().poll_close(0),
                    Ok(Some(CloseEvent::Finished(_)))
                );
                let mut schedule = schedule.lock();
                schedule.withdrawals += 1;
                schedule.withdrawal_after_finality = status.last_finalized == Some(0)
                    && !status.hard_faulted
                    && opening.balance.get() == 120
                    && finished;
            }
            operator_rpc::OperatorRequest::StartClose(request) => {
                let expected = schedule.lock().payment_epochs.last().copied().unwrap_or(0);
                assert_eq!(
                    request.expected_epoch, expected,
                    "close must name accepted work"
                );
                assert!(
                    operator.lock().status().unwrap().epoch > expected,
                    "automatic driver must cut before the client close"
                );
                schedule.lock().closes.push(request.expected_epoch);
            }
            operator_rpc::OperatorRequest::AcknowledgeWithdrawal(request) => {
                schedule.lock().withdrawal = Some((**request).clone());
            }
            operator_rpc::OperatorRequest::AcknowledgeExternalPayout(request) => {
                schedule.lock().payout = Some((**request).clone());
            }
            _ => {}
        }
        let payment = matches!(&request, operator_rpc::OperatorRequest::AcceptSend(_));
        let response = match prepare_request(&context, &mut chain, &operator, &request).await {
            Ok(Some(response)) => response,
            Ok(None) => operator_rpc::handle_decoded(&mut operator.lock(), request),
            Err(error) => rpc::error_response(format!("{error:#}")),
        };
        if payment
            && let rpc::Response::Success { body } = &response
            && let operator_rpc::AcceptSendResponse::Accepted(accepted) =
                operator_rpc::AcceptSendResponse::decode(body.clone()).unwrap()
        {
            let epoch = accepted.epoch;
            schedule.lock().payment_epochs.push(epoch);

            // Withhold the accepted response until the independent production
            // driver cuts its epoch. The next payment races its finalization.
            loop {
                if operator.lock().status().unwrap().epoch > epoch {
                    break;
                }
                tick(&context).await;
            }
            assert!(operator.lock().status().unwrap().epoch > epoch);
        }
        let _ = rpc::send_response(&mut sink, &response).await;
    }
}

pub(super) async fn run(
    context: deterministic::Context,
    genesis: Genesis,
    operator: std::net::SocketAddr,
    queries: Vec<std::net::SocketAddr>,
    schedule: Arc<Mutex<Schedule>>,
) -> anyhow::Result<()> {
    let mut chain = Client::new(
        &genesis,
        deployment(),
        queries.clone(),
        context.child("script_rng"),
    )?;
    let alice = Agent::new(0)?;
    let eve = Agent::new(4)?;
    let chain_id = genesis.native.chain_id();
    let alice_start = chain
        .native_balance(&context, chain_id, alice.account())
        .await?;
    let eve_start = chain
        .native_balance(&context, chain_id, eve.account())
        .await?;
    let script_chain = Client::new(
        &genesis,
        deployment(),
        queries,
        context.child("script_client"),
    )?;
    Box::pin(crate::ui::scripted(&context, operator, script_chain, alice)).await?;

    let (epochs, closes, withdrawal, payout) = {
        let schedule = schedule.lock();
        anyhow::ensure!(
            schedule.payment_head_before_finality,
            "next payment must race the preceding close's finality"
        );
        anyhow::ensure!(
            schedule.withdrawals == 1,
            "expected exactly one withdrawal intent"
        );
        anyhow::ensure!(
            schedule.withdrawal_after_finality,
            "withdrawal preceded finalized balance 120 and local Finished"
        );
        (
            schedule.payment_epochs.clone(),
            schedule.closes.clone(),
            schedule
                .withdrawal
                .clone()
                .context("withdrawal acknowledgement")?,
            schedule.payout.clone().context("payout acknowledgement")?,
        )
    };
    anyhow::ensure!(
        epochs.len() == 4,
        "script must accept exactly four payments"
    );
    anyhow::ensure!(
        epochs.windows(2).all(|pair| pair[0] < pair[1]),
        "payments must occupy distinct automatically cut epochs"
    );
    anyhow::ensure!(
        closes == vec![0, epochs[2], epochs[3]],
        "close requests must identify each completed work arc: {closes:?}"
    );
    let release = chain
        .withdrawal_release(&context, withdrawal.batch_id, withdrawal.claim.position())
        .await?
        .context("certified withdrawal release")?;
    anyhow::ensure!(
        release.released.amount == 3
            && release.released.destination == Agent::new(0)?.account().encode(),
        "incorrect withdrawal release"
    );
    let release = chain
        .payout_release(&context, payout.batch_id, payout.claim.position())
        .await?
        .context("certified external payout release")?;
    anyhow::ensure!(
        release.released.amount == 2 && release.released.receiver == eve.account(),
        "incorrect external payout release"
    );
    let status = chain.status(&context).await?;
    anyhow::ensure!(
        status.last_finalized == Some(epochs[3])
            && status.custody == 415
            && status.claimable == 0
            && !status.hard_faulted,
        "unexpected final status: {status:?}"
    );
    anyhow::ensure!(
        chain.registration(&context).await?.is_none() && chain.fault(&context).await?.is_none(),
        "script left registration or fault"
    );
    for (identity, balance) in [106, 106, 102, 101].into_iter().enumerate() {
        let wallet = Agent::new(identity)?;
        let head = operator_rpc::payment_head(
            &context,
            operator,
            operator_rpc::PaymentHeadRequest {
                account: wallet.account(),
            },
        )
        .await?;
        anyhow::ensure!(
            head.opening.account == wallet.account(),
            "opening names another account"
        );
        head.opening.verify::<Sha256>(&status.state_root)?;
        anyhow::ensure!(
            head.opening.balance.get() == balance,
            "incorrect certified balance for identity {identity}"
        );
    }
    anyhow::ensure!(
        chain
            .native_balance(&context, chain_id, Agent::new(0)?.account())
            .await?
            == alice_start - 17,
        "incorrect Alice native delta"
    );
    anyhow::ensure!(
        chain
            .native_balance(&context, chain_id, eve.account())
            .await?
            == eve_start + 2,
        "incorrect Eve native delta"
    );
    Ok(())
}

#[derive(Clone)]
struct Done;

impl ExitCondition<ed25519::PublicKey, State<Threshold>> for Done {
    fn name(&self) -> &str {
        "production script completed"
    }
    fn requires_polling(&self) -> bool {
        true
    }
    fn reached<'a>(
        &'a self,
        _: &'a ProgressTracker<ed25519::PublicKey>,
        states: &'a [&'a State<Threshold>],
        _: usize,
    ) -> Pin<Box<dyn Future<Output = Result<bool, String>> + Send + 'a>> {
        Box::pin(async move {
            Ok(states
                .first()
                .is_some_and(|state| state.client.lock().is_some()))
        })
    }
}

#[test]
fn production_script_with_automatic_closes() {
    let receiver = std::env::temp_dir().join(format!(
        "commonware-terminal-receiver-{}.sqlite",
        std::process::id()
    ));
    for suffix in ["", "-wal", "-shm"] {
        let mut path = receiver.clone().into_os_string();
        path.push(suffix);
        let _ = std::fs::remove_file(path);
    }
    let mut engine = Walkthrough::new(1);
    engine.automatic = Some(Arc::default());
    let result = PlanBuilder::new(engine)
        .seed(0)
        .timeout(Duration::from_secs(600))
        .exit_condition(Done)
        .property(ClientSucceeded)
        .property(Monotonic)
        .run();
    for suffix in ["", "-wal", "-shm"] {
        let mut path = receiver.clone().into_os_string();
        path.push(suffix);
        let _ = std::fs::remove_file(path);
    }
    result.unwrap();
}
