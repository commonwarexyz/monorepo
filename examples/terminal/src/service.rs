//! Runtime-owning service loops for the settlement and operator binaries.

use crate::{
    agent::Agent, operator::Operator, operator_rpc, rpc, settlement::Settlement, settlement_rpc, ui,
};
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use commonware_runtime::{Listener, Network, Runner as _, tokio};
use std::{net::SocketAddr, num::NonZeroUsize, path::PathBuf, time::Duration};

const MAX_ERROR_BYTES: usize = 1_024;

fn runtime() -> tokio::Runner {
    tokio::Runner::new(
        tokio::Config::new()
            .with_worker_threads(2)
            .with_connect_timeout(Duration::from_secs(5))
            .with_read_write_timeout(Duration::from_secs(5)),
    )
}

fn error_response(error: anyhow::Error) -> rpc::Response {
    let mut message = format!("{error:#}");
    if message.len() > MAX_ERROR_BYTES {
        let mut end = MAX_ERROR_BYTES;
        while !message.is_char_boundary(end) {
            end -= 1;
        }
        message.truncate(end);
    }
    rpc::Response::Error {
        error: Bytes::from(message),
    }
}

pub(crate) fn run_settlement(bind: SocketAddr) -> Result<()> {
    runtime().start(move |context| async move {
        let mut settlement = Settlement::new().context("initialize settlement")?;
        rpc::serve(&context, bind, |request| {
            settlement_rpc::handle(&mut settlement, request)
        })
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
            let (_, mut sink, mut stream) =
                listener.accept().await.context("accept operator RPC")?;
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
                        Err(error) => error_response(error),
                    }
                }
                Err(error) => error_response(error),
            };
            let _ = rpc::send_response(&mut sink, &response).await;
        }
    })
}

pub(crate) fn run_agent(
    operator: SocketAddr,
    settlement: SocketAddr,
    identity: usize,
    scripted: bool,
) -> Result<()> {
    runtime().start(move |context| async move {
        let agent = Agent::new(identity)?;
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
            let release = settlement_rpc::claim_withdrawal(
                network,
                settlement_address,
                settlement_rpc::WithdrawalClaimRequest {
                    batch_id: request.batch_id,
                    claim: request.claim.clone(),
                },
            )
            .await
            .context("confirm settlement withdrawal claim")?;
            ensure!(
                release.destination == *request.claim.request().body().destination(),
                "settlement returned another withdrawal destination"
            );
            return Ok(Some(operator_rpc::acknowledge_withdrawal_confirmed(
                operator, request,
            )));
        }
        operator_rpc::OperatorRequest::AcknowledgeExternalPayout(request) => {
            let payout = settlement_rpc::claim_external_payout(
                network,
                settlement_address,
                settlement_rpc::ExternalPayoutClaimRequest {
                    batch_id: request.batch_id,
                    claim: request.claim.clone(),
                },
            )
            .await
            .context("confirm settlement external payout claim")?;
            ensure!(
                payout.recipient == request.claim.row().account,
                "settlement returned another external payout recipient"
            );
            return Ok(Some(operator_rpc::acknowledge_external_payout_confirmed(
                operator, request,
            )));
        }
        _ => {}
    }

    let freeze = match request {
        operator_rpc::OperatorRequest::AcceptSend(request) => {
            operator.send_requires_boundary_freeze(&request.send)?
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
            settlement_rpc::confirm_deposit(network, settlement_address, request.clone())
                .await
                .context("confirm settlement deposit")?;
            false
        }
        operator_rpc::OperatorRequest::ApplyWithdrawal(request) => {
            if operator.staged_withdrawal(&request.request)?.is_none() {
                settlement_rpc::confirm_withdrawal(network, settlement_address, &request.request)
                    .await
                    .context("confirm settlement withdrawal")?;
            }
            false
        }
        _ => false,
    };
    if !freeze {
        return Ok(None);
    }

    let boundary = operator.settlement_boundary()?;
    settlement_rpc::freeze(
        network,
        settlement_address,
        settlement_rpc::FreezeRequest {
            epoch: boundary.epoch,
            deposits: boundary.deposits,
            withdrawals: boundary.withdrawals,
            signature: boundary.signature,
        },
    )
    .await
    .context("freeze settlement boundary")?;
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{protocol::wallets, settlement_rpc};
    use commonware_clearing::bajillion::boundary::{SignedWithdrawal, WithdrawalAction};
    use commonware_runtime::{Spawner as _, Supervisor as _, deterministic};
    use std::{num::NonZeroU64, path::Path};

    #[test]
    fn unqueued_withdrawal_is_rejected_before_operator_mutation() {
        deterministic::Runner::default().start(|context| async move {
            let mut settlement = Settlement::new().unwrap();
            let settlement_status = settlement.status();
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let settlement_address = listener.local_addr().unwrap();
            let settlement_server = context.child("settlement").spawn(move |_| async move {
                let (_, mut sink, mut stream) = listener.accept().await.unwrap();
                let request = rpc::recv_request(&mut stream).await.unwrap();
                let response = settlement_rpc::handle(&mut settlement, request);
                rpc::send_response(&mut sink, &response).await.unwrap();
            });

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
                    request: withdrawal,
                },
            );

            let error = prepare_request(&context, settlement_address, &mut operator, &request)
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("withdrawal is not queued"));
            assert_eq!(
                operator
                    .payment_quote(&wallet.public_key())
                    .unwrap()
                    .state
                    .balance,
                100
            );
            settlement_server.await.unwrap();
        });
    }

    #[test]
    fn staged_close_response_loss_retries_after_cut_without_settlement_rpc() {
        deterministic::Runner::default().start(|context| async move {
            let settlement_status = Settlement::new().unwrap().status();
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
}
