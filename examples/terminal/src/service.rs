//! Runtime-owning service loops for the three terminal binaries.

use crate::{
    agent::Agent,
    operator::{Operator, rpc as operator_rpc},
    rpc,
    settlement::{rpc as settlement_rpc, store as settlement_store},
    ui,
};
use anyhow::{Context, Result, ensure};
use commonware_runtime::{Clock, Listener, Network, Runner as _, tokio};
use std::{net::SocketAddr, num::NonZeroUsize, path::PathBuf, time::Duration};

fn runtime() -> tokio::Runner {
    tokio::Runner::new(
        tokio::Config::new()
            .with_worker_threads(2)
            .with_connect_timeout(Duration::from_secs(5))
            .with_read_write_timeout(Duration::from_secs(5)),
    )
}

pub(crate) fn run_settlement(bind: SocketAddr, database: PathBuf) -> Result<()> {
    runtime().start(move |context| async move {
        let mut settlement =
            settlement_store::Store::open(&database).context("initialize SQLite settlement")?;
        rpc::serve(&context, bind, |request| settlement.handle(request))
            .await
            .context("serve settlement")
    })
}

pub(crate) fn run_operator(
    bind: SocketAddr,
    settlement_address: SocketAddr,
    database: PathBuf,
    workers: NonZeroUsize,
) -> Result<()> {
    runtime().start(move |context| async move {
        let mut operator = Operator::open_remote(&database, workers, settlement_address)
            .context("initialize SQLite operator")?;
        let mut listener = context.bind(bind).await.context("bind operator RPC")?;

        loop {
            // The runtime folds every accept failure into one error class, so treat a failed
            // accept as transient instead of tearing down the operator.
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
                    match prepare_request(&context, settlement_address, &mut operator, &request)
                        .await
                    {
                        Ok(Some(response)) => response,
                        Ok(None) => operator_rpc::handle_decoded(&mut operator, request),
                        Err(error) => rpc::error_response(format!("{error:#}")),
                    }
                }
                Err(error) => rpc::error_response(format!("{error:#}")),
            };
            let _ = rpc::send_response(&mut sink, &response).await;
        }
    })
}

pub(crate) fn run_agent(
    operator: SocketAddr,
    settlement: SocketAddr,
    database: PathBuf,
    identity: usize,
    scripted: bool,
) -> Result<()> {
    runtime().start(move |context| async move {
        let agent = Agent::open(&database, identity).context("initialize SQLite agent")?;
        if scripted {
            Box::pin(ui::scripted(&context, operator, settlement, agent)).await
        } else {
            Box::pin(ui::run(&context, operator, settlement, agent)).await
        }
    })
}

async fn prepare_request<E: Network>(
    network: &E,
    settlement_address: SocketAddr,
    operator: &mut Operator,
    request: &operator_rpc::OperatorRequest,
) -> Result<Option<rpc::Response>> {
    match request {
        operator_rpc::OperatorRequest::AcknowledgeWithdrawal(request) => {
            let release = match settlement_rpc::claim_withdrawal(
                network,
                settlement_address,
                settlement_rpc::WithdrawalClaimRequest {
                    batch_id: request.batch_id,
                    claim: request.claim.clone(),
                },
            )
            .await
            .context("confirm settlement withdrawal claim")?
            {
                settlement_rpc::WithdrawalClaimResponse::Released(release) => release,
                settlement_rpc::WithdrawalClaimResponse::Unavailable => {
                    anyhow::bail!("withdrawal batch is not claimable yet")
                }
                settlement_rpc::WithdrawalClaimResponse::Invalid => {
                    anyhow::bail!("settlement rejected the withdrawal claim")
                }
            };
            ensure!(
                release.destination == *request.claim.output().destination()
                    && release.amount == request.claim.output().amount(),
                "settlement returned another withdrawal output"
            );
            return Ok(Some(operator_rpc::acknowledge_withdrawal_confirmed(
                operator, request,
            )));
        }
        operator_rpc::OperatorRequest::AcknowledgeExternalPayout(request) => {
            let payout = match settlement_rpc::claim_external_payout(
                network,
                settlement_address,
                settlement_rpc::ExternalPayoutClaimRequest {
                    batch_id: request.batch_id,
                    claim: request.claim.clone(),
                },
            )
            .await
            .context("confirm settlement external payout claim")?
            {
                settlement_rpc::ExternalPayoutClaimResponse::Released(payout) => payout,
                settlement_rpc::ExternalPayoutClaimResponse::Unavailable => {
                    anyhow::bail!("external-payout batch is not claimable yet")
                }
                settlement_rpc::ExternalPayoutClaimResponse::Invalid => {
                    anyhow::bail!("settlement rejected the external payout claim")
                }
            };
            ensure!(
                &payout.recipient == request.claim.recipient(),
                "settlement returned another external payout recipient"
            );
            return Ok(Some(operator_rpc::acknowledge_external_payout_confirmed(
                operator, request,
            )));
        }
        _ => {}
    }

    let register = match request {
        operator_rpc::OperatorRequest::AcceptSend(request) => {
            operator.send_requires_epoch_registration(&request.send)?
        }
        operator_rpc::OperatorRequest::StartClose(request) => {
            if operator.close_already_started(request.expected_epoch)? {
                false
            } else {
                operator.validate_close_start(request.expected_epoch)?;
                true
            }
        }
        operator_rpc::OperatorRequest::ApplyDeposit(request) => {
            let confirmation =
                settlement_rpc::confirm_deposit(network, settlement_address, request.clone())
                    .await
                    .context("confirm settlement deposit")?;
            ensure!(
                confirmation == settlement_rpc::DepositConfirmation::Recorded,
                "deposit is not recorded by settlement"
            );
            false
        }
        _ => false,
    };
    if !register {
        return Ok(None);
    }

    let registration = operator.settlement_registration()?;
    settlement_rpc::register_epoch(
        network,
        settlement_address,
        settlement_rpc::RegisterEpochRequest {
            epoch: registration.epoch,
            predecessor_liability: registration.predecessor_liability,
            deposits_root: registration.deposits_root,
            staged_root: registration.staged_root,
            withdrawals: registration.withdrawals,
            openings: registration.openings,
            signature: registration.signature,
        },
    )
    .await
    .context("register settlement epoch")?;
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        agent::{DepositOutcome, WithdrawalOutcome},
        protocol::wallets,
        settlement::{Settlement, rpc as settlement_rpc},
    };
    use bytes::Bytes;
    use commonware_clearing::bajillion::{
        boundary::{DepositBatch, SignedWithdrawal, WithdrawalAction},
        payment::SignedSend,
    };
    use commonware_codec::{DecodeExt as _, Encode as _};
    use commonware_runtime::{Spawner as _, Supervisor as _, deterministic};
    use std::{
        fs,
        num::NonZeroU64,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

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

    async fn serve_operator_requests<E: Network, const N: usize>(
        network: &E,
        settlement_address: SocketAddr,
        listener: &mut E::Listener,
        operator: &mut Operator,
        expected_methods: [u8; N],
    ) {
        for expected_method in expected_methods {
            let (_, mut sink, mut stream) = listener.accept().await.unwrap();
            let request = rpc::recv_request(&mut stream).await.unwrap();
            assert_eq!(request.method, expected_method);
            let request = operator_rpc::decode_request(request).unwrap();
            let prepared = prepare_request(network, settlement_address, operator, &request)
                .await
                .unwrap();
            let response =
                prepared.unwrap_or_else(|| operator_rpc::handle_decoded(operator, request));
            rpc::send_response(&mut sink, &response).await.unwrap();
        }
    }

    fn recover_pending_withdrawal_over_framed_rpc(
        action: WithdrawalAction,
    ) -> settlement_rpc::ClaimHardFaultResponse {
        deterministic::Runner::default().start(move |context| async move {
            let databases = TempDatabases::new();
            let mut settlement = Settlement::new().unwrap();
            let genesis = settlement.status().unwrap();
            let expected_action = action;
            let mut agent = Agent::open(databases.agent(), 0).unwrap();
            let account = agent.account();
            let expected_account = account.clone();
            let mut settlement_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
                .await
                .unwrap();
            let settlement_address = settlement_listener.local_addr().unwrap();
            let settlement_server = context.child("settlement").spawn(move |_| async move {
                let mut withdrawal_deadline = None;
                for expected_method in [
                    settlement_rpc::METHOD_STATUS,
                    settlement_rpc::METHOD_QUEUE_WITHDRAWAL,
                    settlement_rpc::METHOD_BEGIN_HARD_FAULT_SETTLEMENT,
                    settlement_rpc::METHOD_CLAIM_HARD_FAULT,
                    settlement_rpc::METHOD_STATUS,
                ] {
                    let (_, mut sink, mut stream) = settlement_listener.accept().await.unwrap();
                    let request = rpc::recv_request(&mut stream).await.unwrap();
                    assert_eq!(request.method, expected_method);

                    if request.method == settlement_rpc::METHOD_QUEUE_WITHDRAWAL {
                        let queued =
                            settlement_rpc::QueueWithdrawalRequest::decode(request.body.clone())
                                .unwrap();
                        assert_eq!(queued.request.body().action(), &expected_action);
                        withdrawal_deadline = Some(queued.request.body().deadline());
                    }
                    if request.method == settlement_rpc::METHOD_BEGIN_HARD_FAULT_SETTLEMENT {
                        let deadline = withdrawal_deadline.unwrap();
                        let before_expiry = settlement.status().unwrap();
                        assert!(!before_expiry.hard_faulted);
                        assert!(before_expiry.now < deadline);
                        settlement.advance_logical_time(deadline).unwrap();
                        let after_expiry = settlement.status().unwrap();
                        assert_eq!(after_expiry.now, deadline);
                        assert!(after_expiry.hard_faulted);
                    }

                    let response = settlement_rpc::handle(&mut settlement, request);
                    if expected_method == settlement_rpc::METHOD_BEGIN_HARD_FAULT_SETTLEMENT {
                        let rpc::Response::Success { body } = &response else {
                            panic!("hard-fault settlement failed: {response:?}");
                        };
                        let hard_fault =
                            settlement_rpc::BeginHardFaultSettlementResponse::decode(body.clone())
                                .unwrap();
                        assert_eq!(
                            hard_fault.reason,
                            settlement_rpc::HardFaultReasonResponse::ExpiredWithdrawal {
                                account: expected_account.clone(),
                                expired_at: withdrawal_deadline.unwrap(),
                            }
                        );
                        assert_eq!(hard_fault.admission_fence_epoch, 0);
                        assert_eq!(hard_fault.invalid_from, None);
                        assert_eq!(hard_fault.frozen_state_root, genesis.state_root);
                        assert_eq!(hard_fault.state_liability, 400);
                        assert_eq!(hard_fault.unfinalized_deposit_total, 0);
                        assert_eq!(hard_fault.custody_balance, 400);
                    }
                    rpc::send_response(&mut sink, &response).await.unwrap();
                }
                withdrawal_deadline.unwrap()
            });

            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            let mut operator_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
                .await
                .unwrap();
            let operator_address = operator_listener.local_addr().unwrap();
            let operator_server =
                context
                    .child("operator")
                    .spawn(move |operator_context| async move {
                        serve_operator_requests(
                            &operator_context,
                            settlement_address,
                            &mut operator_listener,
                            &mut operator,
                            [
                                operator_rpc::METHOD_WITHDRAWAL_OPENING,
                                operator_rpc::METHOD_WITHDRAWAL_OPENING,
                            ],
                        )
                        .await;
                    });

            let opening = operator_rpc::withdrawal_opening(
                &context,
                operator_address,
                operator_rpc::WithdrawalOpeningRequest {
                    account: account.clone(),
                },
            )
            .await
            .unwrap();
            let outcome = agent
                .withdraw(&context, settlement_address, operator_address, action)
                .await
                .unwrap();
            let WithdrawalOutcome::Signed { request, error } = outcome else {
                panic!("disappeared operator unexpectedly applied withdrawal");
            };
            assert_eq!(request.body().action(), &action);
            assert!(format!("{error:#}").contains("apply operator withdrawal"));
            operator_server.await.unwrap();
            drop(agent);

            // The operator never carried the signed request, so the signer exercises the
            // censorship fallback: queue the exact request at settlement so its deadline
            // becomes an on-chain obligation that expires into hard-fault recovery.
            settlement_rpc::queue_withdrawal(
                &context,
                settlement_address,
                settlement_rpc::QueueWithdrawalRequest {
                    request,
                    openings: vec![opening.opening],
                },
            )
            .await
            .unwrap();

            let retained_opening_count = rusqlite::Connection::open(databases.agent())
                .unwrap()
                .query_row("SELECT COUNT(*) FROM agent_state_openings", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap();
            assert_eq!(retained_opening_count, 1);

            let recovered_agent = Agent::open(databases.agent(), 0).unwrap();
            let release = recovered_agent
                .recover_hard_fault(&context, settlement_address)
                .await
                .unwrap();
            assert_eq!(release.account, account);
            assert_eq!(release.released_custody, 100);

            let after_release = settlement_rpc::status(&context, settlement_address)
                .await
                .unwrap();
            assert!(after_release.hard_faulted);
            assert_eq!(after_release.state_root, genesis.state_root);
            assert_eq!(after_release.claimable_balance, 0);
            assert_eq!(after_release.custody_balance, 300);
            settlement_server.await.unwrap();
            release
        })
    }

    #[test]
    fn fresh_withdrawal_application_requires_no_settlement_rpc() {
        deterministic::Runner::default().start(|context| async move {
            let settlement_status = Settlement::new().unwrap().status().unwrap();
            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            let wallet = wallets().remove(0);
            let opening = operator.withdrawal_opening(&wallet.public_key()).unwrap();
            assert_eq!(opening.root, settlement_status.state_root);
            let withdrawal = SignedWithdrawal::sign(
                settlement_status.deployment,
                opening.root.digest,
                Bytes::from_static(b"destination"),
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
            // depend on any settlement round trip. The settlement address is unreachable.
            assert!(
                prepare_request(
                    &context,
                    SocketAddr::from(([127, 0, 0, 1], 1)),
                    &mut operator,
                    &request,
                )
                .await
                .unwrap()
                .is_none()
            );
            let staged = operator.apply_withdrawal(withdrawal).unwrap();
            assert_eq!(staged.epoch, 0);
            assert_eq!(
                operator
                    .payment_quote(&wallet.public_key())
                    .unwrap()
                    .state
                    .balance,
                93
            );
        });
    }

    #[test]
    fn staged_close_response_loss_retries_after_cut_without_settlement_rpc() {
        deterministic::Runner::default().start(|context| async move {
            let settlement_status = Settlement::new().unwrap().status().unwrap();
            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            let wallet = wallets().remove(0);
            let opening = operator.withdrawal_opening(&wallet.public_key()).unwrap();
            let close = SignedWithdrawal::sign(
                settlement_status.deployment,
                opening.root.digest,
                Bytes::from_static(b"destination"),
                WithdrawalAction::Close,
                100,
                wallet.signer(),
            );
            let first = operator.apply_withdrawal(close.clone()).unwrap();
            assert_eq!(first.action, WithdrawalAction::Close);
            operator.start_close(0).unwrap();

            let request = operator_rpc::OperatorRequest::ApplyWithdrawal(
                operator_rpc::ApplyWithdrawalRequest {
                    request: close.clone(),
                },
            );
            assert!(
                prepare_request(
                    &context,
                    SocketAddr::from(([127, 0, 0, 1], 1)),
                    &mut operator,
                    &request,
                )
                .await
                .unwrap()
                .is_none()
            );
            let retry = operator.apply_withdrawal(close).unwrap();
            assert_eq!(retry.epoch, 0);
            assert_eq!(retry.action, WithdrawalAction::Close);
            operator.wait_for_closes().unwrap();
        });
    }

    #[test]
    fn first_receipt_waits_for_successful_epoch_registration() {
        deterministic::Runner::default().start(|context| async move {
            let mut settlement = Settlement::new().unwrap();
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let settlement_address = listener.local_addr().unwrap();
            let settlement_server = context.child("settlement").spawn(move |_| async move {
                for attempt in 0..2 {
                    let (_, mut sink, mut stream) = listener.accept().await.unwrap();
                    let request = rpc::recv_request(&mut stream).await.unwrap();
                    let response = if attempt == 0 {
                        rpc::Response::Error {
                            error: Bytes::from_static(b"registration rejected"),
                        }
                    } else {
                        settlement_rpc::handle(&mut settlement, request)
                    };
                    rpc::send_response(&mut sink, &response).await.unwrap();
                }
            });

            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            let mut identities = wallets();
            let payer = identities.remove(0);
            let recipient = identities.remove(0);
            let quote = operator.payment_quote(&payer.public_key()).unwrap();
            let send = SignedSend::sign_next(
                &quote.context,
                payer.signer(),
                recipient.public_key(),
                7,
                quote.state.cumulative_debit,
            )
            .unwrap();
            let request =
                operator_rpc::OperatorRequest::AcceptSend(operator_rpc::AcceptSendRequest {
                    send: send.clone(),
                });

            let error = prepare_request(&context, settlement_address, &mut operator, &request)
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("registration rejected"));
            assert!(operator.snapshot().unwrap().payments.is_empty());
            assert!(operator.send_requires_epoch_registration(&send).unwrap());

            assert!(
                prepare_request(&context, settlement_address, &mut operator, &request,)
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(operator.snapshot().unwrap().payments.is_empty());

            assert!(matches!(
                operator_rpc::handle_decoded(&mut operator, request),
                rpc::Response::Success { .. }
            ));
            assert_eq!(operator.snapshot().unwrap().payments.len(), 1);
            settlement_server.await.unwrap();
        });
    }

    #[test]
    fn lost_payment_response_recovers_after_missed_admission() {
        deterministic::Runner::default().start(|context| async move {
            let databases = TempDatabases::new();
            let mut operator = Operator::open(databases.operator(), NonZeroUsize::MIN).unwrap();
            let mut agent = Agent::open(databases.agent(), 0).unwrap();
            let payer = agent.account();
            let registration = operator.settlement_registration().unwrap();

            // The fresh operator carries no deposits, so the empty batch is its boundary.
            let epoch_context = crate::protocol::epoch_context(
                registration.epoch,
                &DepositBatch::empty(),
                &registration.withdrawals,
                registration.predecessor_liability,
            )
            .unwrap();
            let admission_deadline = epoch_context.admission_deadline();
            let fault_tick = admission_deadline.checked_add(1).unwrap();
            assert_eq!(fault_tick, epoch_context.challenge_deadline());
            let payment_anchor = *epoch_context.payment().anchor();

            let mut settlement = Settlement::new().unwrap();
            let genesis_status = settlement.status().unwrap();
            assert_eq!(genesis_status.custody_balance, 400);

            let mut settlement_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
                .await
                .unwrap();
            let settlement_address = settlement_listener.local_addr().unwrap();
            let settlement_server = context.child("settlement").spawn(move |_| async move {
                let mut dropped_claim_response = None;
                for (index, expected_method) in [
                    settlement_rpc::METHOD_STATUS,
                    settlement_rpc::METHOD_REGISTER_EPOCH,
                    settlement_rpc::METHOD_STATUS,
                    settlement_rpc::METHOD_BEGIN_HARD_FAULT_SETTLEMENT,
                    settlement_rpc::METHOD_BEGIN_HARD_FAULT_SETTLEMENT,
                    settlement_rpc::METHOD_CLAIM_HARD_FAULT,
                    settlement_rpc::METHOD_BEGIN_HARD_FAULT_SETTLEMENT,
                    settlement_rpc::METHOD_CLAIM_HARD_FAULT,
                    settlement_rpc::METHOD_STATUS,
                ]
                .into_iter()
                .enumerate()
                {
                    let (_, mut sink, mut stream) = settlement_listener.accept().await.unwrap();
                    let request = rpc::recv_request(&mut stream).await.unwrap();
                    assert_eq!(request.method, expected_method);

                    if index == 3 {
                        let before_expiry = settlement.status().unwrap();
                        assert!(!before_expiry.hard_faulted);
                        assert!(before_expiry.now <= admission_deadline);

                        // Registration is live through its inclusive admission deadline and
                        // faults only on the first later logical tick.
                        settlement.advance_logical_time(fault_tick).unwrap();
                        let after_expiry = settlement.status().unwrap();
                        assert_eq!(after_expiry.now, fault_tick);
                        assert!(after_expiry.hard_faulted);
                    }

                    let response = settlement_rpc::handle(&mut settlement, request);
                    if index == 5 {
                        dropped_claim_response = Some(response);
                        continue;
                    }
                    if index == 7 {
                        assert_eq!(dropped_claim_response.as_ref(), Some(&response));
                    }
                    rpc::send_response(&mut sink, &response).await.unwrap();
                }
            });

            let mut operator_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
                .await
                .unwrap();
            let operator_address = operator_listener.local_addr().unwrap();
            let operator_server =
                context
                    .child("operator")
                    .spawn(move |operator_context| async move {
                        let mut accepted = None;
                        for expected_method in [
                            operator_rpc::METHOD_PAYMENT_QUOTE,
                            operator_rpc::METHOD_ACCEPT_SEND,
                        ] {
                            let (_, mut sink, mut stream) =
                                operator_listener.accept().await.unwrap();
                            let request = rpc::recv_request(&mut stream).await.unwrap();
                            assert_eq!(request.method, expected_method);
                            let request = operator_rpc::decode_request(request).unwrap();
                            let prepared = prepare_request(
                                &operator_context,
                                settlement_address,
                                &mut operator,
                                &request,
                            )
                            .await
                            .unwrap();
                            let response = prepared.unwrap_or_else(|| {
                                operator_rpc::handle_decoded(&mut operator, request)
                            });
                            if expected_method == operator_rpc::METHOD_ACCEPT_SEND {
                                let rpc::Response::Success { body } = response else {
                                    panic!("operator did not accept the staged payment");
                                };
                                accepted = Some(
                                    operator_rpc::AcceptedBatchResponse::decode(body).unwrap(),
                                );
                                continue;
                            }
                            rpc::send_response(&mut sink, &response).await.unwrap();
                        }
                        accepted.expect("the operator accepted one payment")
                    });

            let error = agent
                .pay(&context, settlement_address, operator_address, &[(1, 7)])
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("submit payment"));
            assert_eq!(agent.receipt_count(), 0);
            let accepted = operator_server.await.unwrap();
            assert_eq!(accepted.epoch, registration.epoch);
            assert_eq!(accepted.total, 7);
            assert_eq!(accepted.acceptance.receipts[0].body().amount(), 7);
            assert_eq!(accepted.acceptance.send.body().anchor(), &payment_anchor);
            assert_eq!(accepted.acceptance.send.body().cumulative_debit(), 7);
            drop(agent);

            let agent_database = rusqlite::Connection::open(databases.agent()).unwrap();
            let retained_opening_count = agent_database
                .query_row("SELECT COUNT(*) FROM agent_state_openings", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap();
            assert_eq!(retained_opening_count, 1);
            let settled_count = agent_database
                .query_row("SELECT COUNT(*) FROM agent_payments", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap();
            assert_eq!(settled_count, 0);
            let persisted_send = agent_database
                .query_row("SELECT send FROM agent_pending_payment", [], |row| {
                    row.get::<_, Vec<u8>>(0)
                })
                .unwrap();
            let pending_send = SignedSend::decode(Bytes::from(persisted_send)).unwrap();
            assert_eq!(&pending_send, &accepted.acceptance.send);
            drop(agent_database);

            let recovered_agent = Agent::open(databases.agent(), 0).unwrap();
            assert_eq!(recovered_agent.account(), payer);
            assert_eq!(recovered_agent.receipt_count(), 0);
            drop(recovered_agent);

            let mut recovered_operator =
                Operator::open(databases.operator(), NonZeroUsize::MIN).unwrap();
            let persisted_retry = recovered_operator.accept_send(pending_send).unwrap();
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

            let persisted_operator_receipt = rusqlite::Connection::open(databases.operator())
                .unwrap()
                .query_row("SELECT encoded FROM payments", [], |row| {
                    row.get::<_, Vec<u8>>(0)
                })
                .unwrap();
            assert_eq!(
                Bytes::from(persisted_operator_receipt),
                accepted
                    .acceptance
                    .payments()
                    .next()
                    .expect("acceptance has one entry")
                    .encode()
            );

            // The operator is gone before recovery. Only the live settlement server participates.
            let before_expiry = settlement_rpc::status(&context, settlement_address)
                .await
                .unwrap();
            assert!(!before_expiry.hard_faulted);
            assert!(before_expiry.now <= admission_deadline);
            assert_eq!(before_expiry.state_root, genesis_status.state_root);
            assert_eq!(before_expiry.custody_balance, 400);

            let hard_fault =
                settlement_rpc::begin_hard_fault_settlement(&context, settlement_address)
                    .await
                    .unwrap();
            assert_eq!(
                hard_fault.reason,
                settlement_rpc::HardFaultReasonResponse::ExpiredRegistration {
                    anchor: payment_anchor,
                    epoch: registration.epoch,
                    expired_at: admission_deadline,
                }
            );
            assert_eq!(hard_fault.admission_fence_epoch, registration.epoch);
            assert_eq!(hard_fault.invalid_from, None);
            assert_eq!(hard_fault.frozen_state_root, genesis_status.state_root);
            assert_eq!(hard_fault.state_liability, 400);
            assert_eq!(hard_fault.unfinalized_deposit_total, 0);
            assert_eq!(hard_fault.custody_balance, 400);

            let recovered_agent = Agent::open(databases.agent(), 0).unwrap();
            let lost_response = recovered_agent
                .recover_hard_fault(&context, settlement_address)
                .await
                .unwrap_err();
            assert!(format!("{lost_response:#}").contains("claim hard-fault payer state"));
            drop(recovered_agent);

            let recovered_agent = Agent::open(databases.agent(), 0).unwrap();
            let release = recovered_agent
                .recover_hard_fault(&context, settlement_address)
                .await
                .unwrap();
            assert_eq!(release.account, payer);
            assert_eq!(release.withdrawal, None);
            assert_eq!(release.residual, 100);
            assert_ne!(release.residual, 93);
            assert_eq!(release.released_custody, 100);
            assert_ne!(release.released_custody, 93);

            let after_release = settlement_rpc::status(&context, settlement_address)
                .await
                .unwrap();
            assert!(after_release.hard_faulted);
            assert_eq!(after_release.state_root, genesis_status.state_root);
            assert_eq!(after_release.claimable_balance, 0);
            assert_eq!(after_release.custody_balance, 300);

            settlement_server.await.unwrap();
        });
    }

    #[test]
    fn operator_disappearance_refunds_pending_deposit_over_framed_rpc() {
        deterministic::Runner::default().start(|context| async move {
            let databases = TempDatabases::new();
            let mut settlement = Settlement::new().unwrap();
            let genesis = settlement.status().unwrap();
            let deposit_deadline = crate::protocol::settlement_config()
                .deposit_inclusion_timeout
                .get();
            let mut settlement_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
                .await
                .unwrap();
            let settlement_address = settlement_listener.local_addr().unwrap();
            let settlement_server = context.child("settlement").spawn(move |_| async move {
                for expected_method in [
                    settlement_rpc::METHOD_DEPOSIT,
                    settlement_rpc::METHOD_CONFIRM_DEPOSIT,
                    settlement_rpc::METHOD_BEGIN_HARD_FAULT_SETTLEMENT,
                    settlement_rpc::METHOD_CLAIM_PENDING_DEPOSIT,
                    settlement_rpc::METHOD_STATUS,
                    settlement_rpc::METHOD_CLAIM_PENDING_DEPOSIT,
                    settlement_rpc::METHOD_STATUS,
                ] {
                    let (_, mut sink, mut stream) = settlement_listener.accept().await.unwrap();
                    let request = rpc::recv_request(&mut stream).await.unwrap();
                    assert_eq!(request.method, expected_method);

                    if request.method == settlement_rpc::METHOD_BEGIN_HARD_FAULT_SETTLEMENT {
                        let before_expiry = settlement.status().unwrap();
                        assert!(!before_expiry.hard_faulted);
                        assert!(before_expiry.now < deposit_deadline);
                        assert_eq!(before_expiry.custody_balance, 407);
                        settlement.advance_logical_time(deposit_deadline).unwrap();
                        let after_expiry = settlement.status().unwrap();
                        assert_eq!(after_expiry.now, deposit_deadline);
                        assert!(after_expiry.hard_faulted);
                    }

                    let response = settlement_rpc::handle(&mut settlement, request);
                    rpc::send_response(&mut sink, &response).await.unwrap();
                }
            });

            let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
            let mut agent = Agent::open(databases.agent(), 0).unwrap();
            let account = agent.account();
            let mut operator_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
                .await
                .unwrap();
            let operator_address = operator_listener.local_addr().unwrap();
            let operator_server =
                context
                    .child("operator")
                    .spawn(move |operator_context| async move {
                        serve_operator_requests(
                            &operator_context,
                            settlement_address,
                            &mut operator_listener,
                            &mut operator,
                            [operator_rpc::METHOD_APPLY_DEPOSIT],
                        )
                        .await;
                    });

            let applied = agent
                .deposit(&context, settlement_address, operator_address, 7)
                .await
                .unwrap();
            let DepositOutcome::Applied { event, .. } = applied else {
                panic!("operator did not acknowledge the recorded deposit");
            };
            assert_eq!(event.account, account);
            assert_eq!(event.amount, 7);
            operator_server.await.unwrap();
            drop(agent);

            let hard_fault =
                settlement_rpc::begin_hard_fault_settlement(&context, settlement_address)
                    .await
                    .unwrap();
            assert_eq!(
                hard_fault.reason,
                settlement_rpc::HardFaultReasonResponse::ExpiredDeposit {
                    account: account.clone(),
                    expired_at: deposit_deadline,
                }
            );
            assert_eq!(hard_fault.admission_fence_epoch, 0);
            assert_eq!(hard_fault.invalid_from, None);
            assert_eq!(hard_fault.frozen_state_root, genesis.state_root);
            assert_eq!(hard_fault.state_liability, 400);
            assert_eq!(hard_fault.unfinalized_deposit_total, 7);
            assert_eq!(hard_fault.custody_balance, 407);

            let recovered_agent = Agent::open(databases.agent(), 0).unwrap();
            let refund = recovered_agent
                .recover_pending_deposit(&context, settlement_address)
                .await
                .unwrap();
            assert_eq!(refund.account, account);
            assert_eq!(refund.amount, 7);
            drop(recovered_agent);
            let after_refund = settlement_rpc::status(&context, settlement_address)
                .await
                .unwrap();
            assert!(after_refund.hard_faulted);
            assert_eq!(after_refund.state_root, genesis.state_root);
            assert_eq!(after_refund.claimable_balance, 0);
            assert_eq!(after_refund.custody_balance, 400);

            let recovered_agent = Agent::open(databases.agent(), 0).unwrap();
            let retry = recovered_agent
                .recover_pending_deposit(&context, settlement_address)
                .await
                .unwrap();
            assert_eq!(retry, refund);
            let after_retry = settlement_rpc::status(&context, settlement_address)
                .await
                .unwrap();
            assert_eq!(after_retry, after_refund);
            settlement_server.await.unwrap();
        });
    }

    #[test]
    fn operator_disappearance_releases_pending_amount_over_framed_rpc() {
        let release = recover_pending_withdrawal_over_framed_rpc(WithdrawalAction::Amount(
            NonZeroU64::new(7).unwrap(),
        ));
        let withdrawal = release.withdrawal.as_ref().unwrap();
        assert_eq!(withdrawal.destination().as_ref(), b"Alice");
        assert_eq!(withdrawal.amount(), 7);
        assert_eq!(release.residual, 93);
    }

    #[test]
    fn operator_disappearance_releases_pending_close_tail_over_framed_rpc() {
        let release = recover_pending_withdrawal_over_framed_rpc(WithdrawalAction::Close);
        let withdrawal = release.withdrawal.as_ref().unwrap();
        assert_eq!(withdrawal.destination().as_ref(), b"Alice");
        assert_eq!(withdrawal.amount(), 100);
        assert_eq!(release.residual, 0);
    }
}
