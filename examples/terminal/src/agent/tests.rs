use super::{
    custody::withdrawal_deadline,
    store::{IncomingSummary, PendingWithdrawalClaim},
    *,
};
use crate::{
    operator::{Operator, rpc as operator_rpc},
    protocol::{
        Acceptance, AccountCache, Key, Wallet, deployment, external_identity, operator_key, wallets,
    },
    rpc,
    settlement::{Settlement, SettlementSubmission, rpc as settlement_rpc},
};
use bytes::Bytes;
use commonware_clearing::bajillion::{
    boundary::{DepositBatch, WithdrawalAction, WithdrawalBatch},
    payment::{Payment, PaymentContext, SignedReceipt, SignedSend},
    state::{AccountState, StateLeaf},
    transition::BatchId,
};
use commonware_codec::{DecodeExt as _, Encode};
use commonware_cryptography::{Hasher, Sha256, sha256::Digest};
use commonware_runtime::{
    Listener as _, Network, Runner as _, Spawner as _, Supervisor as _, deterministic,
};
use commonware_utils::TestRng;
use std::{
    fs,
    net::SocketAddr,
    num::{NonZeroU64, NonZeroUsize},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static TEMP_DATABASE_ID: AtomicU64 = AtomicU64::new(0);

struct TempDatabase {
    directory: PathBuf,
    path: PathBuf,
}

impl TempDatabase {
    fn new() -> Self {
        let id = TEMP_DATABASE_ID.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "commonware-terminal-agent-{}-{id}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("agent.sqlite");
        Self { directory, path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDatabase {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

async fn respond_rpc<L: commonware_runtime::Listener>(
    listener: &mut L,
    handle: impl FnOnce(rpc::Request) -> rpc::Response,
) {
    let (_, mut sink, mut stream) = listener.accept().await.unwrap();
    let request = rpc::recv_request(&mut stream).await.unwrap();
    let response = handle(request);
    rpc::send_response(&mut sink, &response).await.unwrap();
}

async fn respond<L: commonware_runtime::Listener>(
    listener: &mut L,
    handle: impl FnOnce(operator_rpc::OperatorRequest) -> rpc::Response,
) {
    respond_rpc(listener, |request| {
        handle(operator_rpc::decode_request(request).unwrap())
    })
    .await;
}

async fn respond_registration<L: commonware_runtime::Listener>(
    listener: &mut L,
    context: &PaymentContext<Key, Digest>,
) {
    respond_rpc(listener, |request| {
        assert_eq!(request.method, settlement_rpc::METHOD_CONFIRM_REGISTRATION);
        assert_eq!(
            settlement_rpc::RegistrationQuery::decode(request.body).unwrap(),
            settlement_rpc::RegistrationQuery {
                epoch: context.epoch(),
                anchor: *context.anchor(),
                state_root: settlement_status_response().state_root,
            }
        );
        rpc::Response::Success { body: Bytes::new() }
    })
    .await;
}

fn accepted(outcome: PaymentOutcome) -> operator_rpc::AcceptedBatchResponse {
    match outcome {
        PaymentOutcome::Accepted(payment) => *payment,
        PaymentOutcome::CommittedUnheld { epoch, total } => {
            panic!("epoch {epoch} payment for {total} committed without receipts")
        }
    }
}

/// Opens a withdrawal-claim intent directly, standing in for a completed withdrawal.
fn open_withdrawal_intent(agent: &mut Agent) {
    agent.store.open_withdrawal_claim().unwrap();
    agent.pending_withdrawal_claim = Some(PendingWithdrawalClaim {
        evidence: None,
        result: None,
    });
}

async fn respond_claim_roots<L: commonware_runtime::Listener>(
    listener: &mut L,
    batch: BatchId<Digest>,
    roots: Option<settlement_rpc::ClaimRootsResponse>,
) {
    respond_rpc(listener, move |request| {
        assert_eq!(request.method, settlement_rpc::METHOD_CLAIM_ROOTS);
        assert_eq!(
            settlement_rpc::ClaimRootsRequest::decode(request.body).unwrap(),
            settlement_rpc::ClaimRootsRequest { batch_id: batch }
        );
        rpc::Response::Success {
            body: roots.encode(),
        }
    })
    .await;
}

fn claim_roots_response(
    roots: &commonware_clearing::bajillion::transition::RootBundle<Digest>,
) -> settlement_rpc::ClaimRootsResponse {
    settlement_rpc::ClaimRootsResponse {
        withdrawal_outputs: roots.withdrawal_outputs,
        change: roots.change,
    }
}

fn quote_response_with_debit(
    context: PaymentContext<Key, Digest>,
    state: AccountState,
    leaf_debit: u64,
) -> operator_rpc::PaymentQuoteResponse {
    let account = wallets()[0].public_key();
    let opening = AccountCache::new::<Sha256>(vec![StateLeaf {
        account: account.clone(),
        state: AccountState {
            balance: 100,
            active: true,
            cumulative_debit: leaf_debit,
            ..AccountState::default()
        },
    }])
    .unwrap();
    operator_rpc::PaymentQuoteResponse {
        context,
        state,
        root: opening.root(),
        opening: opening.opening(&account).unwrap(),
    }
}

fn payment_quote_response(
    context: PaymentContext<Key, Digest>,
    state: AccountState,
) -> operator_rpc::PaymentQuoteResponse {
    quote_response_with_debit(context, state, 0)
}

fn settlement_status_response() -> settlement_rpc::StatusResponse {
    let quote = payment_quote_response(
        PaymentContext::new(Sha256::hash(&[b"status-root"]), 0, operator_key()),
        AccountState::default(),
    );
    settlement_rpc::StatusResponse {
        now: 0,
        deployment: deployment(),
        state_root: quote.root,
        last_finalized: None,
        custody_balance: 400,
        claimable_balance: 0,
        hard_faulted: false,
    }
}

#[derive(Clone, Copy, Debug)]
enum PaymentQuoteGateCase {
    WrongDeployment,
    HardFaulted,
    MismatchedStateRoot,
    WrongAccount,
    InactivePayer,
    ZeroBalance,
    InvalidProof,
}

impl PaymentQuoteGateCase {
    const ALL: [Self; 7] = [
        Self::WrongDeployment,
        Self::HardFaulted,
        Self::MismatchedStateRoot,
        Self::WrongAccount,
        Self::InactivePayer,
        Self::ZeroBalance,
        Self::InvalidProof,
    ];

    const fn actor(self) -> &'static str {
        match self {
            Self::WrongDeployment => "wrong_deployment",
            Self::HardFaulted => "hard_faulted",
            Self::MismatchedStateRoot => "mismatched_state_root",
            Self::WrongAccount => "wrong_account",
            Self::InactivePayer => "inactive_payer",
            Self::ZeroBalance => "zero_balance",
            Self::InvalidProof => "invalid_proof",
        }
    }

    const fn expected_error(self) -> &'static str {
        match self {
            Self::WrongDeployment => "settlement status has an unexpected deployment",
            Self::HardFaulted => "settlement is permanently hard-faulted",
            Self::MismatchedStateRoot => "payer opening is not the exact settlement head",
            Self::WrongAccount => "payer opening belongs to another account",
            Self::InactivePayer | Self::ZeroBalance => "payer opening is not live",
            Self::InvalidProof => "verify payer state opening",
        }
    }

    fn corrupt(
        self,
        quote: &mut operator_rpc::PaymentQuoteResponse,
        status: &mut settlement_rpc::StatusResponse,
    ) {
        match self {
            Self::WrongDeployment => {
                status.deployment = Sha256::hash(&[b"wrong-settlement-deployment"]);
            }
            Self::HardFaulted => status.hard_faulted = true,
            Self::MismatchedStateRoot => {
                status.state_root.digest = Sha256::hash(&[b"different-state-root"]);
            }
            Self::WrongAccount => {
                let account = wallets()[2].public_key();
                let opening = AccountCache::new::<Sha256>(vec![StateLeaf {
                    account: account.clone(),
                    state: quote.opening.leaf.state,
                }])
                .unwrap();
                quote.root = opening.root();
                quote.opening = opening.opening(&account).unwrap();
                status.state_root = quote.root;
            }
            Self::InactivePayer => quote.opening.leaf.state.active = false,
            Self::ZeroBalance => quote.opening.leaf.state.balance = 0,
            Self::InvalidProof => {
                quote.opening.proof.proof.leaf_count = 2;
                quote
                    .opening
                    .proof
                    .proof
                    .siblings
                    .push(Sha256::hash(&[b"invalid-payer-opening"]));
            }
        }
    }
}

#[test]
fn payment_debit_is_local_and_advances_only_after_a_verified_receipt() {
    deterministic::Runner::default().start(|context| async move {
        let operator = Wallet::from_seed("operator", 1);
        let impostor = Wallet::from_seed("impostor", 1_001);
        let payment_context = PaymentContext::new(
            Sha256::hash(&[b"agent-payment-counter"]),
            7,
            operator.public_key(),
        );
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let operator_address = listener.local_addr().unwrap();
        let operator_server = context.child("operator").spawn(move |_| async move {
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::PaymentQuote(_)
                ));
                rpc::Response::Success {
                    body: payment_quote_response(
                        payment_context.clone(),
                        AccountState {
                            balance: 100,
                            cumulative_debit: 10_000,
                            ..AccountState::default()
                        },
                    )
                    .encode(),
                }
            })
            .await;
            respond(&mut listener, |request| {
                assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                rpc::Response::Success {
                    body: settlement_status_response().encode(),
                }
            })
            .await;

            let mut first_payment = None;
            respond(&mut listener, |request| {
                let operator_rpc::OperatorRequest::AcceptSend(request) = request else {
                    panic!("payment retry unexpectedly requested another quote");
                };
                assert_eq!(request.send.body().cumulative_debit(), 7);
                let recipient = request.send.body().entries()[0].recipient().clone();
                let receipt = SignedReceipt::issue_next::<Sha256, _>(
                    &payment_context,
                    &request.send,
                    &recipient,
                    0,
                    0,
                    0,
                    operator.signer(),
                )
                .unwrap();
                let linked =
                    Payment::new::<Sha256>(&payment_context, request.send.clone(), receipt)
                        .unwrap();
                let (send, receipt) = linked.into_parts();
                first_payment = Some(Acceptance {
                    send,
                    receipts: vec![receipt],
                });
                let forged = SignedReceipt::sign_body_by_authority(
                    first_payment.as_ref().unwrap().receipts[0].body().clone(),
                    impostor.signer(),
                );
                rpc::Response::Success {
                    body: operator_rpc::AcceptedBatchResponse {
                        epoch: payment_context.epoch(),
                        sequence: 0,
                        total: 7,
                        acceptance: Acceptance {
                            send: request.send,
                            receipts: vec![forged],
                        },
                    }
                    .encode(),
                }
            })
            .await;
            let first_payment = first_payment.unwrap();

            // The retry re-quotes to confirm the staged context is still live before it
            // resubmits the exact bytes.
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::PaymentQuote(_)
                ));
                rpc::Response::Success {
                    body: payment_quote_response(
                        payment_context.clone(),
                        AccountState {
                            balance: 93,
                            cumulative_debit: 10_007,
                            ..AccountState::default()
                        },
                    )
                    .encode(),
                }
            })
            .await;
            respond(&mut listener, |request| {
                let operator_rpc::OperatorRequest::AcceptSend(request) = request else {
                    panic!("live retry unexpectedly skipped its resubmission");
                };
                assert_eq!(request.send, first_payment.send);
                rpc::Response::Success {
                    body: operator_rpc::AcceptedBatchResponse {
                        epoch: payment_context.epoch(),
                        sequence: 0,
                        total: 7,
                        acceptance: first_payment.clone(),
                    }
                    .encode(),
                }
            })
            .await;
            respond_registration(&mut listener, &payment_context).await;

            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::PaymentQuote(_)
                ));
                rpc::Response::Success {
                    body: payment_quote_response(
                        payment_context.clone(),
                        AccountState {
                            balance: 93,
                            cumulative_debit: 20_000,
                            ..AccountState::default()
                        },
                    )
                    .encode(),
                }
            })
            .await;
            respond(&mut listener, |request| {
                assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                rpc::Response::Success {
                    body: settlement_status_response().encode(),
                }
            })
            .await;

            respond(&mut listener, |request| {
                let operator_rpc::OperatorRequest::AcceptSend(request) = request else {
                    panic!("expected the second signed send");
                };
                assert_eq!(request.send.body().cumulative_debit(), 10);
                let recipient = request.send.body().entries()[0].recipient().clone();
                let receipt = SignedReceipt::issue_next::<Sha256, _>(
                    &payment_context,
                    &request.send,
                    &recipient,
                    0,
                    7,
                    1,
                    operator.signer(),
                )
                .unwrap();
                let (send, receipt) =
                    Payment::new::<Sha256>(&payment_context, request.send, receipt)
                        .unwrap()
                        .into_parts();
                let payment = Acceptance {
                    send,
                    receipts: vec![receipt],
                };
                rpc::Response::Success {
                    body: operator_rpc::AcceptedBatchResponse {
                        epoch: payment_context.epoch(),
                        sequence: 1,
                        total: 3,
                        acceptance: payment,
                    }
                    .encode(),
                }
            })
            .await;
            respond_registration(&mut listener, &payment_context).await;
        });

        let mut agent = Agent::new(0).unwrap();
        let rejected = agent
            .pay(&context, operator_address, operator_address, &[(1, 7)])
            .await
            .unwrap_err();
        assert!(format!("{rejected:#}").contains("verify operator receipt"));
        assert_eq!(agent.receipt_count(), 0);

        let payment = accepted(
            agent
                .pay(&context, operator_address, operator_address, &[(1, 7)])
                .await
                .unwrap(),
        );
        assert_eq!(payment.acceptance.receipts[0].body().amount(), 7);
        assert_eq!(agent.receipt_count(), 1);

        let payment = accepted(
            agent
                .pay(&context, operator_address, operator_address, &[(1, 3)])
                .await
                .unwrap(),
        );
        assert_eq!(payment.acceptance.receipts[0].body().amount(), 3);
        assert_eq!(agent.receipt_count(), 2);
        operator_server.await.unwrap();
    });
}

#[test]
fn stale_uncommitted_payment_is_abandoned_on_the_finalized_endpoint_proof() {
    deterministic::Runner::default().start(|context| async move {
        let operator = Wallet::from_seed("operator", 1);
        let cut = PaymentContext::new(
            Sha256::hash(&[b"stale-cut-epoch-0"]),
            0,
            operator.public_key(),
        );
        let live = PaymentContext::new(
            Sha256::hash(&[b"stale-cut-epoch-1"]),
            1,
            operator.public_key(),
        );
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let operator_address = listener.local_addr().unwrap();
        let cut_context = cut.clone();
        let live_context = live.clone();
        let operator_server = context.child("operator").spawn(move |_| async move {
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::PaymentQuote(_)
                ));
                rpc::Response::Success {
                    body: payment_quote_response(
                        cut_context.clone(),
                        AccountState {
                            balance: 100,
                            ..AccountState::default()
                        },
                    )
                    .encode(),
                }
            })
            .await;
            respond(&mut listener, |request| {
                assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                rpc::Response::Success {
                    body: settlement_status_response().encode(),
                }
            })
            .await;

            // The first accept response is lost, so the send stays staged and uncommitted.
            {
                let (_, _sink, mut stream) = listener.accept().await.unwrap();
                let request = rpc::recv_request(&mut stream).await.unwrap();
                assert!(matches!(
                    operator_rpc::decode_request(request).unwrap(),
                    operator_rpc::OperatorRequest::AcceptSend(_)
                ));
            }

            // The retry re-quotes and learns the staged epoch was cut. The quote's
            // verified opening still carries the prior endpoint, and the staged epoch
            // has finalized, so the wallet abandons on settlement's proof alone.
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::PaymentQuote(_)
                ));
                rpc::Response::Success {
                    body: payment_quote_response(
                        live_context.clone(),
                        AccountState {
                            balance: 100,
                            ..AccountState::default()
                        },
                    )
                    .encode(),
                }
            })
            .await;
            respond(&mut listener, |request| {
                assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                let mut status = settlement_status_response();
                status.last_finalized = Some(0);
                rpc::Response::Success {
                    body: status.encode(),
                }
            })
            .await;

            // The wallet re-stages against the live epoch and this send commits.
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::PaymentQuote(_)
                ));
                rpc::Response::Success {
                    body: payment_quote_response(
                        live_context.clone(),
                        AccountState {
                            balance: 100,
                            ..AccountState::default()
                        },
                    )
                    .encode(),
                }
            })
            .await;
            respond(&mut listener, |request| {
                assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                rpc::Response::Success {
                    body: settlement_status_response().encode(),
                }
            })
            .await;
            respond(&mut listener, |request| {
                let operator_rpc::OperatorRequest::AcceptSend(request) = request else {
                    panic!("re-stage did not resubmit a fresh send");
                };
                assert_eq!(request.send.body().epoch(), live_context.epoch());
                assert_eq!(request.send.body().cumulative_debit(), 7);
                let recipient = request.send.body().entries()[0].recipient().clone();
                let receipt = SignedReceipt::issue_next::<Sha256, _>(
                    &live_context,
                    &request.send,
                    &recipient,
                    0,
                    0,
                    0,
                    operator.signer(),
                )
                .unwrap();
                let (send, receipt) = Payment::new::<Sha256>(&live_context, request.send, receipt)
                    .unwrap()
                    .into_parts();
                rpc::Response::Success {
                    body: operator_rpc::AcceptedBatchResponse {
                        epoch: live_context.epoch(),
                        sequence: 0,
                        total: 7,
                        acceptance: Acceptance {
                            send,
                            receipts: vec![receipt],
                        },
                    }
                    .encode(),
                }
            })
            .await;
            respond_registration(&mut listener, &live_context).await;
        });

        let mut agent = Agent::new(0).unwrap();
        let error = agent
            .pay(&context, operator_address, operator_address, &[(1, 7)])
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("submit payment"));
        let pending = agent.pending_payment.as_ref().unwrap();
        assert_eq!(pending.send.body().epoch(), cut.epoch());
        assert_eq!(agent.cumulative_debit, 0);

        let payment = accepted(
            agent
                .pay(&context, operator_address, operator_address, &[(1, 7)])
                .await
                .unwrap(),
        );
        assert_eq!(payment.epoch, live.epoch());
        assert_eq!(payment.acceptance.receipts[0].body().amount(), 7);
        assert_eq!(agent.cumulative_debit, 7);
        assert_eq!(agent.receipt_count(), 1);
        assert!(agent.pending_payment.is_none());
        operator_server.await.unwrap();
    });
}

#[test]
fn committed_payment_resolves_from_the_finalized_endpoint_without_a_verdict() {
    deterministic::Runner::default().start(|context| async move {
        let operator = Wallet::from_seed("operator", 1);
        let committed = PaymentContext::new(
            Sha256::hash(&[b"committed-across-cut-0"]),
            0,
            operator.public_key(),
        );
        let successor_context = PaymentContext::new(
            Sha256::hash(&[b"committed-across-cut-1"]),
            1,
            operator.public_key(),
        );
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let operator_address = listener.local_addr().unwrap();
        let committed_context = committed.clone();
        let operator_server = context.child("operator").spawn(move |_| async move {
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::PaymentQuote(_)
                ));
                rpc::Response::Success {
                    body: payment_quote_response(
                        committed_context.clone(),
                        AccountState {
                            balance: 100,
                            ..AccountState::default()
                        },
                    )
                    .encode(),
                }
            })
            .await;
            respond(&mut listener, |request| {
                assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                rpc::Response::Success {
                    body: settlement_status_response().encode(),
                }
            })
            .await;

            // The operator commits the batch, but its response is lost before the wallet
            // records it.
            let recorded;
            {
                let (_, _sink, mut stream) = listener.accept().await.unwrap();
                let request = rpc::recv_request(&mut stream).await.unwrap();
                let operator_rpc::OperatorRequest::AcceptSend(request) =
                    operator_rpc::decode_request(request).unwrap()
                else {
                    panic!("expected the initially staged send");
                };
                assert_eq!(request.send.body().cumulative_debit(), 7);
                let recipient = request.send.body().entries()[0].recipient().clone();
                let receipt = SignedReceipt::issue_next::<Sha256, _>(
                    &committed_context,
                    &request.send,
                    &recipient,
                    0,
                    0,
                    0,
                    operator.signer(),
                )
                .unwrap();
                let (send, receipt) =
                    Payment::new::<Sha256>(&committed_context, request.send, receipt)
                        .unwrap()
                        .into_parts();
                recorded = operator_rpc::AcceptedBatchResponse {
                    epoch: committed_context.epoch(),
                    sequence: 0,
                    total: 7,
                    acceptance: Acceptance {
                        send,
                        receipts: vec![receipt],
                    },
                };
            }

            // The retry re-quotes and learns the committed epoch was cut. The verified
            // opening of the finalized head carries the staged successor endpoint, so
            // the wallet concludes commitment itself and only fetches the receipts.
            let quote = quote_response_with_debit(
                successor_context.clone(),
                AccountState {
                    balance: 93,
                    ..AccountState::default()
                },
                7,
            );
            let mut status = settlement_status_response();
            status.state_root = quote.root;
            status.last_finalized = Some(0);
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::PaymentQuote(_)
                ));
                rpc::Response::Success {
                    body: quote.encode(),
                }
            })
            .await;
            respond(&mut listener, |request| {
                assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                rpc::Response::Success {
                    body: status.encode(),
                }
            })
            .await;
            respond(&mut listener, |request| {
                let operator_rpc::OperatorRequest::AcceptedBatch(request) = request else {
                    panic!("the receipts fetch did not name the exact staged bytes");
                };
                assert_eq!(request.send, recorded.acceptance.send);
                rpc::Response::Success {
                    body: Some(recorded).encode(),
                }
            })
            .await;
        });

        let mut agent = Agent::new(0).unwrap();
        let error = agent
            .pay(&context, operator_address, operator_address, &[(1, 7)])
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("submit payment"));
        assert_eq!(
            agent.pending_payment.as_ref().unwrap().send.body().epoch(),
            0
        );

        let payment = accepted(
            agent
                .pay(&context, operator_address, operator_address, &[(1, 7)])
                .await
                .unwrap(),
        );
        assert_eq!(payment.epoch, committed.epoch());
        assert_eq!(payment.acceptance.receipts[0].body().amount(), 7);
        assert_eq!(agent.cumulative_debit, 7);
        assert_eq!(agent.receipt_count(), 1);
        assert!(agent.pending_payment.is_none());
        operator_server.await.unwrap();
    });
}

#[test]
fn unfinalized_staged_epoch_keeps_resolution_undecidable() {
    deterministic::Runner::default().start(|context| async move {
        let operator = Wallet::from_seed("operator", 1);
        let cut = PaymentContext::new(
            Sha256::hash(&[b"unavailable-probe-0"]),
            0,
            operator.public_key(),
        );
        let live_context = PaymentContext::new(
            Sha256::hash(&[b"unavailable-probe-1"]),
            1,
            operator.public_key(),
        );
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let operator_address = listener.local_addr().unwrap();
        let cut_context = cut.clone();
        let operator_server = context.child("operator").spawn(move |_| async move {
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::PaymentQuote(_)
                ));
                rpc::Response::Success {
                    body: payment_quote_response(
                        cut_context.clone(),
                        AccountState {
                            balance: 100,
                            ..AccountState::default()
                        },
                    )
                    .encode(),
                }
            })
            .await;
            respond(&mut listener, |request| {
                assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                rpc::Response::Success {
                    body: settlement_status_response().encode(),
                }
            })
            .await;
            // The first accept response is lost, so the send stays staged and uncommitted.
            {
                let (_, _sink, mut stream) = listener.accept().await.unwrap();
                let request = rpc::recv_request(&mut stream).await.unwrap();
                assert!(matches!(
                    operator_rpc::decode_request(request).unwrap(),
                    operator_rpc::OperatorRequest::AcceptSend(_)
                ));
            }
            // The retry re-quotes and learns the staged epoch was cut, but nothing has
            // finalized yet, so commitment is not decidable and everything is kept.
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::PaymentQuote(_)
                ));
                rpc::Response::Success {
                    body: payment_quote_response(
                        live_context.clone(),
                        AccountState {
                            balance: 100,
                            ..AccountState::default()
                        },
                    )
                    .encode(),
                }
            })
            .await;
            respond(&mut listener, |request| {
                assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                rpc::Response::Success {
                    body: settlement_status_response().encode(),
                }
            })
            .await;
        });

        let mut agent = Agent::new(0).unwrap();
        let error = agent
            .pay(&context, operator_address, operator_address, &[(1, 7)])
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("submit payment"));
        let staged = agent.pending_payment.as_ref().unwrap().send.clone();
        assert_eq!(staged.body().epoch(), cut.epoch());

        // An undecidable resolution must retry, never abandon: the exact staged send
        // stays pending and the debit endpoint does not advance.
        let error = agent
            .pay(&context, operator_address, operator_address, &[(1, 7)])
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("not yet decidable"));
        assert_eq!(
            agent.pending_payment.as_ref().unwrap().send.encode(),
            staged.encode()
        );
        assert_eq!(agent.cumulative_debit, 0);
        assert_eq!(agent.receipt_count(), 0);
        operator_server.await.unwrap();
    });
}

#[test]
fn finalized_endpoint_commits_without_receipts_when_the_fetch_fails() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let operator = Wallet::from_seed("operator", 1);
        let cut = PaymentContext::new(
            Sha256::hash(&[b"unheld-receipts-0"]),
            0,
            operator.public_key(),
        );
        let live = PaymentContext::new(
            Sha256::hash(&[b"unheld-receipts-1"]),
            1,
            operator.public_key(),
        );
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let operator_address = listener.local_addr().unwrap();
        let cut_context = cut.clone();
        let live_context = live.clone();
        let operator_server = context.child("operator").spawn(move |_| async move {
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::PaymentQuote(_)
                ));
                rpc::Response::Success {
                    body: payment_quote_response(
                        cut_context.clone(),
                        AccountState {
                            balance: 100,
                            ..AccountState::default()
                        },
                    )
                    .encode(),
                }
            })
            .await;
            respond(&mut listener, |request| {
                assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                rpc::Response::Success {
                    body: settlement_status_response().encode(),
                }
            })
            .await;

            // The accept response is lost and the operator later serves no batch for
            // the send: only settlement's finalized endpoint proves the commitment.
            {
                let (_, _sink, mut stream) = listener.accept().await.unwrap();
                let request = rpc::recv_request(&mut stream).await.unwrap();
                assert!(matches!(
                    operator_rpc::decode_request(request).unwrap(),
                    operator_rpc::OperatorRequest::AcceptSend(_)
                ));
            }
            let quote = quote_response_with_debit(
                live_context.clone(),
                AccountState {
                    balance: 93,
                    ..AccountState::default()
                },
                7,
            );
            let mut status = settlement_status_response();
            status.state_root = quote.root;
            status.last_finalized = Some(0);
            let resolution_status = status;
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::PaymentQuote(_)
                ));
                rpc::Response::Success {
                    body: quote.encode(),
                }
            })
            .await;
            respond(&mut listener, |request| {
                assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                rpc::Response::Success {
                    body: resolution_status.encode(),
                }
            })
            .await;
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::AcceptedBatch(_)
                ));
                rpc::Response::Success {
                    body: None::<operator_rpc::AcceptedBatchResponse>.encode(),
                }
            })
            .await;

            // The carve-out lets the next send proceed against the live epoch even
            // though the finalized batch's receipts are unheld.
            let quote = quote_response_with_debit(
                live_context.clone(),
                AccountState {
                    balance: 93,
                    cumulative_debit: 7,
                    ..AccountState::default()
                },
                7,
            );
            let mut status = settlement_status_response();
            status.state_root = quote.root;
            status.last_finalized = Some(0);
            let fresh_status = status;
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::PaymentQuote(_)
                ));
                rpc::Response::Success {
                    body: quote.encode(),
                }
            })
            .await;
            respond(&mut listener, |request| {
                assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                rpc::Response::Success {
                    body: fresh_status.encode(),
                }
            })
            .await;
            respond(&mut listener, |request| {
                let operator_rpc::OperatorRequest::AcceptSend(request) = request else {
                    panic!("expected the successor send");
                };
                assert_eq!(request.send.body().cumulative_debit(), 10);
                let recipient = request.send.body().entries()[0].recipient().clone();
                let receipt = SignedReceipt::issue_next::<Sha256, _>(
                    &live_context,
                    &request.send,
                    &recipient,
                    0,
                    0,
                    0,
                    operator.signer(),
                )
                .unwrap();
                let (send, receipt) = Payment::new::<Sha256>(&live_context, request.send, receipt)
                    .unwrap()
                    .into_parts();
                rpc::Response::Success {
                    body: operator_rpc::AcceptedBatchResponse {
                        epoch: live_context.epoch(),
                        sequence: 0,
                        total: 3,
                        acceptance: Acceptance {
                            send,
                            receipts: vec![receipt],
                        },
                    }
                    .encode(),
                }
            })
            .await;
            respond_rpc(&mut listener, |request| {
                assert_eq!(request.method, settlement_rpc::METHOD_CONFIRM_REGISTRATION);
                rpc::Response::Success { body: Bytes::new() }
            })
            .await;
        });

        let mut agent = Agent::open(database.path(), 0).unwrap();
        let error = agent
            .pay(&context, operator_address, operator_address, &[(1, 7)])
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("submit payment"));

        let outcome = agent
            .pay(&context, operator_address, operator_address, &[(1, 7)])
            .await
            .unwrap();
        assert!(matches!(
            outcome,
            PaymentOutcome::CommittedUnheld { epoch: 0, total: 7 }
        ));
        assert_eq!(agent.cumulative_debit, 7);
        assert_eq!(agent.receipt_count(), 0);
        assert!(agent.pending_payment.is_none());
        drop(agent);

        // The unheld commit is durable: the endpoint survives restart without any
        // retained receipts, and the next send debits its exact successor.
        let mut recovered = Agent::open(database.path(), 0).unwrap();
        assert_eq!(recovered.cumulative_debit, 7);
        assert_eq!(recovered.receipt_count(), 0);
        assert!(recovered.pending_payment.is_none());
        let payment = accepted(
            recovered
                .pay(&context, operator_address, operator_address, &[(1, 3)])
                .await
                .unwrap(),
        );
        assert_eq!(payment.acceptance.receipts[0].body().amount(), 3);
        assert_eq!(recovered.cumulative_debit, 10);
        operator_server.await.unwrap();
    });
}

#[test]
fn forged_resolution_opening_fails_verification_and_retries() {
    deterministic::Runner::default().start(|context| async move {
        let operator = Wallet::from_seed("operator", 1);
        let cut = PaymentContext::new(
            Sha256::hash(&[b"forged-resolution-0"]),
            0,
            operator.public_key(),
        );
        let live = PaymentContext::new(
            Sha256::hash(&[b"forged-resolution-1"]),
            1,
            operator.public_key(),
        );
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let operator_address = listener.local_addr().unwrap();
        let cut_context = cut.clone();
        let live_context = live.clone();
        let operator_server = context.child("operator").spawn(move |_| async move {
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::PaymentQuote(_)
                ));
                rpc::Response::Success {
                    body: payment_quote_response(
                        cut_context.clone(),
                        AccountState {
                            balance: 100,
                            ..AccountState::default()
                        },
                    )
                    .encode(),
                }
            })
            .await;
            respond(&mut listener, |request| {
                assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                rpc::Response::Success {
                    body: settlement_status_response().encode(),
                }
            })
            .await;
            {
                let (_, _sink, mut stream) = listener.accept().await.unwrap();
                let request = rpc::recv_request(&mut stream).await.unwrap();
                assert!(matches!(
                    operator_rpc::decode_request(request).unwrap(),
                    operator_rpc::OperatorRequest::AcceptSend(_)
                ));
            }

            // A lying operator serves a corrupted opening under settlement's true head
            // root. It cannot forge the Merkle proof, so resolution rejects it and the
            // wallet retries with everything intact.
            let mut quote = payment_quote_response(
                live_context.clone(),
                AccountState {
                    balance: 100,
                    ..AccountState::default()
                },
            );
            quote.opening.proof.proof.leaf_count = 2;
            quote
                .opening
                .proof
                .proof
                .siblings
                .push(Sha256::hash(&[b"forged-resolution-opening"]));
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::PaymentQuote(_)
                ));
                rpc::Response::Success {
                    body: quote.encode(),
                }
            })
            .await;
            respond(&mut listener, |request| {
                assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                let mut status = settlement_status_response();
                status.last_finalized = Some(0);
                rpc::Response::Success {
                    body: status.encode(),
                }
            })
            .await;
        });

        let mut agent = Agent::new(0).unwrap();
        let error = agent
            .pay(&context, operator_address, operator_address, &[(1, 7)])
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("submit payment"));
        let staged = agent.pending_payment.as_ref().unwrap().send.clone();

        // The forged opening cannot cause a wrong abandon or a wrong commit.
        let error = agent
            .pay(&context, operator_address, operator_address, &[(1, 7)])
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("verify payer state opening"));
        assert_eq!(
            agent.pending_payment.as_ref().unwrap().send.encode(),
            staged.encode()
        );
        assert_eq!(agent.cumulative_debit, 0);
        assert_eq!(agent.receipt_count(), 0);
        operator_server.await.unwrap();
        let _ = live;
    });
}

#[test]
fn finalized_endpoint_below_the_committed_endpoint_is_reported_not_healed() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let operator = Wallet::from_seed("operator", 1);
        let live =
            PaymentContext::new(Sha256::hash(&[b"omitted-send-0"]), 0, operator.public_key());
        let successor =
            PaymentContext::new(Sha256::hash(&[b"omitted-send-1"]), 1, operator.public_key());
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let operator_address = listener.local_addr().unwrap();
        let live_context = live.clone();
        let successor_context = successor.clone();
        let operator_server = context.child("operator").spawn(move |_| async move {
            // The first payment commits normally and advances the durable endpoint on
            // the operator acknowledgment, before anything finalizes.
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::PaymentQuote(_)
                ));
                rpc::Response::Success {
                    body: payment_quote_response(
                        live_context.clone(),
                        AccountState {
                            balance: 100,
                            ..AccountState::default()
                        },
                    )
                    .encode(),
                }
            })
            .await;
            respond(&mut listener, |request| {
                assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                rpc::Response::Success {
                    body: settlement_status_response().encode(),
                }
            })
            .await;
            respond(&mut listener, |request| {
                let operator_rpc::OperatorRequest::AcceptSend(request) = request else {
                    panic!("expected the first signed send");
                };
                assert_eq!(request.send.body().cumulative_debit(), 7);
                let recipient = request.send.body().entries()[0].recipient().clone();
                let receipt = SignedReceipt::issue_next::<Sha256, _>(
                    &live_context,
                    &request.send,
                    &recipient,
                    0,
                    0,
                    0,
                    operator.signer(),
                )
                .unwrap();
                let (send, receipt) = Payment::new::<Sha256>(&live_context, request.send, receipt)
                    .unwrap()
                    .into_parts();
                rpc::Response::Success {
                    body: operator_rpc::AcceptedBatchResponse {
                        epoch: live_context.epoch(),
                        sequence: 0,
                        total: 7,
                        acceptance: Acceptance {
                            send,
                            receipts: vec![receipt],
                        },
                    }
                    .encode(),
                }
            })
            .await;
            respond_registration(&mut listener, &live_context).await;

            // A second send is staged and its accept response is lost.
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::PaymentQuote(_)
                ));
                rpc::Response::Success {
                    body: payment_quote_response(
                        live_context.clone(),
                        AccountState {
                            balance: 93,
                            ..AccountState::default()
                        },
                    )
                    .encode(),
                }
            })
            .await;
            respond(&mut listener, |request| {
                assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                rpc::Response::Success {
                    body: settlement_status_response().encode(),
                }
            })
            .await;
            {
                let (_, _sink, mut stream) = listener.accept().await.unwrap();
                let request = rpc::recv_request(&mut stream).await.unwrap();
                assert!(matches!(
                    operator_rpc::decode_request(request).unwrap(),
                    operator_rpc::OperatorRequest::AcceptSend(_)
                ));
            }

            // A Byzantine operator finalizes a close omitting BOTH sends: the verified
            // finalized endpoint sits below the committed one on every retry.
            for _ in 0..2 {
                respond(&mut listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::PaymentQuote(_)
                    ));
                    rpc::Response::Success {
                        body: payment_quote_response(
                            successor_context.clone(),
                            AccountState {
                                balance: 93,
                                ..AccountState::default()
                            },
                        )
                        .encode(),
                    }
                })
                .await;
                respond(&mut listener, |request| {
                    assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                    let mut status = settlement_status_response();
                    status.last_finalized = Some(0);
                    rpc::Response::Success {
                        body: status.encode(),
                    }
                })
                .await;
            }
        });

        let mut agent = Agent::open(database.path(), 0).unwrap();
        accepted(
            agent
                .pay(&context, operator_address, operator_address, &[(1, 7)])
                .await
                .unwrap(),
        );
        assert_eq!(agent.cumulative_debit, 7);
        let error = agent
            .pay(&context, operator_address, operator_address, &[(1, 3)])
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("submit payment"));
        let staged = agent.pending_payment.as_ref().unwrap().send.clone();

        // The mismatch names the fraud instead of panicking or healing, and it
        // survives restart with the slot intact.
        let error = agent
            .pay(&context, operator_address, operator_address, &[(1, 3)])
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("omitted an acknowledged send"));
        assert_eq!(agent.cumulative_debit, 7);
        drop(agent);

        let mut recovered = Agent::open(database.path(), 0).unwrap();
        assert_eq!(recovered.cumulative_debit, 7);
        let error = recovered
            .pay(&context, operator_address, operator_address, &[(1, 3)])
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("omitted an acknowledged send"));
        assert_eq!(
            recovered.pending_payment.as_ref().unwrap().send.encode(),
            staged.encode()
        );
        assert_eq!(recovered.cumulative_debit, 7);
        assert_eq!(recovered.receipt_count(), 1);
        operator_server.await.unwrap();
    });
}

#[test]
fn deterministically_rejected_sends_are_never_staged() {
    deterministic::Runner::default().start(|context| async move {
        let operator = Wallet::from_seed("operator", 1);
        let payment_context =
            PaymentContext::new(Sha256::hash(&[b"never-staged"]), 7, operator.public_key());
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let operator_address = listener.local_addr().unwrap();
        let operator_server = context.child("operator").spawn(move |_| async move {
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::PaymentQuote(_)
                ));
                rpc::Response::Success {
                    body: payment_quote_response(
                        payment_context.clone(),
                        AccountState {
                            balance: 100,
                            ..AccountState::default()
                        },
                    )
                    .encode(),
                }
            })
            .await;
            respond(&mut listener, |request| {
                assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                rpc::Response::Success {
                    body: settlement_status_response().encode(),
                }
            })
            .await;
        });

        // A self entry is rejected before any request or durable staging.
        let mut agent = Agent::new(0).unwrap();
        let error = agent
            .pay(&context, operator_address, operator_address, &[(0, 7)])
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("self-payments"));
        assert!(agent.pending_payment.is_none());

        // An unaffordable batch total is rejected after the quote, before staging, so the
        // wallet can immediately stage an acceptable send instead.
        let error = agent
            .pay(
                &context,
                operator_address,
                operator_address,
                &[(1, 60), (2, 41)],
            )
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("insufficient available balance"));
        assert!(agent.pending_payment.is_none());
        operator_server.await.unwrap();
    });
}

#[test]
fn withdrawal_deadline_caps_at_the_clock_horizon() {
    assert_eq!(withdrawal_deadline(7), 57);
    assert_eq!(withdrawal_deadline(u64::MAX - 20), u64::MAX);
}

#[test]
fn pending_deposit_recovery_validates_the_settlement_refund() {
    deterministic::Runner::default().start(|context| async move {
        let agent = Agent::new(0).unwrap();
        let account = agent.account();
        let mut settlement_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
            .await
            .unwrap();
        let settlement_address = settlement_listener.local_addr().unwrap();
        let expected_account = account.clone();
        let settlement_server = context.child("settlement").spawn(move |_| async move {
            respond_rpc(&mut settlement_listener, |request| {
                assert_eq!(request.method, settlement_rpc::METHOD_CLAIM_PENDING_DEPOSIT);
                let claim =
                    settlement_rpc::ClaimPendingDepositRequest::decode(request.body).unwrap();
                assert_eq!(claim.account, expected_account);
                rpc::Response::Success {
                    body: settlement_rpc::ClaimPendingDepositResponse {
                        account: wallets()[1].public_key(),
                        amount: 7,
                    }
                    .encode(),
                }
            })
            .await;
            respond_rpc(&mut settlement_listener, |request| {
                assert_eq!(request.method, settlement_rpc::METHOD_CLAIM_PENDING_DEPOSIT);
                let claim =
                    settlement_rpc::ClaimPendingDepositRequest::decode(request.body).unwrap();
                assert_eq!(claim.account, expected_account);
                rpc::Response::Success {
                    body: settlement_rpc::ClaimPendingDepositResponse {
                        account: expected_account,
                        amount: 0,
                    }
                    .encode(),
                }
            })
            .await;
        });

        let error = agent
            .recover_pending_deposit(&context, settlement_address)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("refunded another account"));
        let error = agent
            .recover_pending_deposit(&context, settlement_address)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("zero deposit refund"));
        settlement_server.await.unwrap();
    });
}

#[test]
fn deposit_response_loss_preserves_exact_retry_until_acknowledged() {
    deterministic::Runner::default().start(|context| async move {
        let mut settlement = Settlement::new().unwrap();
        let mut settlement_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
            .await
            .unwrap();
        let settlement_address = settlement_listener.local_addr().unwrap();
        let settlement_server = context.child("settlement").spawn(move |_| async move {
            for _ in 0..2 {
                respond_rpc(&mut settlement_listener, |request| {
                    assert_eq!(request.method, settlement_rpc::METHOD_DEPOSIT);
                    settlement_rpc::handle(&mut settlement, request)
                })
                .await;
            }
            settlement.status().unwrap().custody_balance
        });

        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        let mut operator_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
            .await
            .unwrap();
        let operator_address = operator_listener.local_addr().unwrap();
        let operator_server = context.child("operator").spawn(move |_| async move {
            let (_, sink, mut stream) = operator_listener.accept().await.unwrap();
            let first = rpc::recv_request(&mut stream).await.unwrap();
            assert_eq!(first.method, operator_rpc::METHOD_APPLY_DEPOSIT);
            let first_body = first.body.clone();
            let first = operator_rpc::decode_request(first).unwrap();
            assert!(matches!(
                operator_rpc::handle_decoded(&mut operator, first),
                rpc::Response::Success { .. }
            ));
            drop(sink);

            respond_rpc(&mut operator_listener, |request| {
                assert_eq!(request.method, operator_rpc::METHOD_APPLY_DEPOSIT);
                assert_eq!(request.body, first_body);
                let request = operator_rpc::decode_request(request).unwrap();
                operator_rpc::handle_decoded(&mut operator, request)
            })
            .await;
        });

        let mut agent = Agent::new(0).unwrap();
        let first = agent
            .deposit(&context, settlement_address, operator_address, 7)
            .await
            .unwrap();
        let DepositOutcome::Recorded { event, error } = first else {
            panic!("lost operator response unexpectedly applied deposit");
        };
        assert!(format!("{error:#}").contains("credit operator deposit"));
        assert_eq!(agent.pending_deposit.as_ref(), Some(&event));
        assert_eq!(agent.deposit_nonce, 0);

        let retry = agent
            .deposit(&context, settlement_address, operator_address, 7)
            .await
            .unwrap();
        let DepositOutcome::Applied {
            epoch,
            event: applied,
        } = retry
        else {
            panic!("exact deposit retry was not acknowledged");
        };
        assert_eq!(epoch, 0);
        assert_eq!(applied, event);
        assert!(agent.pending_deposit.is_none());
        assert_eq!(agent.deposit_nonce, 1);
        assert_eq!(settlement_server.await.unwrap(), 407);
        operator_server.await.unwrap();
    });
}

#[test]
fn deposit_nonce_overflow_precedes_custody() {
    deterministic::Runner::default().start(|context| async move {
        let mut agent = Agent::new(0).unwrap();
        agent.deposit_nonce = u64::MAX;
        let error = agent
            .deposit(
                &context,
                SocketAddr::from(([127, 0, 0, 1], 1)),
                SocketAddr::from(([127, 0, 0, 1], 2)),
                7,
            )
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("deposit nonce overflow"));
        assert!(agent.pending_deposit.is_none());
    });
}

#[test]
fn conflicting_deposit_acks_preserve_pending_custody() {
    deterministic::Runner::default().start(|context| async move {
        for case in 0..4 {
            let mut settlement_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 10 + case * 2)))
                .await
                .unwrap();
            let settlement_address = settlement_listener.local_addr().unwrap();
            let settlement_server = context.child("settlement").spawn(move |_| async move {
                respond_rpc(&mut settlement_listener, |request| {
                    assert_eq!(request.method, settlement_rpc::METHOD_DEPOSIT);
                    rpc::Response::Success { body: Bytes::new() }
                })
                .await;
            });

            let mut operator_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 11 + case * 2)))
                .await
                .unwrap();
            let operator_address = operator_listener.local_addr().unwrap();
            let operator_server = context.child("operator").spawn(move |_| async move {
                respond_rpc(&mut operator_listener, |request| {
                    assert_eq!(request.method, operator_rpc::METHOD_APPLY_DEPOSIT);
                    let operator_rpc::OperatorRequest::ApplyDeposit(request) =
                        operator_rpc::decode_request(request).unwrap()
                    else {
                        panic!("expected a deposit request");
                    };
                    if case == 3 {
                        return rpc::Response::Success {
                            body: Bytes::from_static(&[0]),
                        };
                    }
                    let mut ack = operator_rpc::DepositAck {
                        epoch: 0,
                        id: request.id,
                        account: request.account,
                        amount: request.amount,
                    };
                    match case {
                        0 => ack.id = Sha256::hash(&[b"another-deposit-id"]),
                        1 => ack.account = wallets()[1].public_key(),
                        2 => ack.amount += 1,
                        _ => unreachable!(),
                    }
                    rpc::Response::Success { body: ack.encode() }
                })
                .await;
            });

            let mut agent = Agent::new(0).unwrap();
            let outcome = agent
                .deposit(&context, settlement_address, operator_address, 7)
                .await
                .unwrap();
            let DepositOutcome::Recorded { event, .. } = outcome else {
                panic!("conflicting operator response cleared pending custody");
            };
            assert_eq!(agent.pending_deposit.as_ref(), Some(&event));
            assert_eq!(agent.deposit_nonce, 0);
            settlement_server.await.unwrap();
            operator_server.await.unwrap();
        }
    });
}

#[test]
fn withdrawal_response_loss_and_wrong_ack_preserve_one_exact_request() {
    deterministic::Runner::default().start(|context| async move {
        let mut settlement = Settlement::new().unwrap();
        let mut settlement_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
            .await
            .unwrap();
        let settlement_address = settlement_listener.local_addr().unwrap();
        let settlement_server = context.child("settlement").spawn(move |_| async move {
            respond_rpc(&mut settlement_listener, |request| {
                assert_eq!(request.method, settlement_rpc::METHOD_STATUS);
                settlement_rpc::handle(&mut settlement, request)
            })
            .await;
        });

        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        let mut operator_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
            .await
            .unwrap();
        let operator_address = operator_listener.local_addr().unwrap();
        let operator_server = context.child("operator").spawn(move |_| async move {
            respond_rpc(&mut operator_listener, |request| {
                assert_eq!(request.method, operator_rpc::METHOD_WITHDRAWAL_OPENING);
                let request = operator_rpc::decode_request(request).unwrap();
                operator_rpc::handle_decoded(&mut operator, request)
            })
            .await;

            let (_, sink, mut stream) = operator_listener.accept().await.unwrap();
            let first = rpc::recv_request(&mut stream).await.unwrap();
            assert_eq!(first.method, operator_rpc::METHOD_APPLY_WITHDRAWAL);
            let first_body = first.body.clone();
            let first = operator_rpc::decode_request(first).unwrap();
            assert!(matches!(
                operator_rpc::handle_decoded(&mut operator, first),
                rpc::Response::Success { .. }
            ));
            drop(sink);

            respond_rpc(&mut operator_listener, |request| {
                assert_eq!(request.method, operator_rpc::METHOD_APPLY_WITHDRAWAL);
                assert_eq!(request.body, first_body);
                let request = operator_rpc::decode_request(request).unwrap();
                assert!(matches!(
                    operator_rpc::handle_decoded(&mut operator, request),
                    rpc::Response::Success { .. }
                ));
                rpc::Response::Success {
                    body: operator_rpc::WithdrawalAck {
                        epoch: 0,
                        digest: Sha256::hash(&[b"another-withdrawal"]),
                    }
                    .encode(),
                }
            })
            .await;

            respond_rpc(&mut operator_listener, |request| {
                assert_eq!(request.method, operator_rpc::METHOD_APPLY_WITHDRAWAL);
                assert_eq!(request.body, first_body);
                let request = operator_rpc::decode_request(request).unwrap();
                operator_rpc::handle_decoded(&mut operator, request)
            })
            .await;
        });

        let action = WithdrawalAction::Amount(NonZeroU64::new(7).unwrap());
        let mut agent = Agent::new(0).unwrap();
        let first = agent
            .withdraw(&context, settlement_address, operator_address, action)
            .await
            .unwrap();
        let WithdrawalOutcome::Signed { request, error } = first else {
            panic!("lost operator response unexpectedly applied withdrawal");
        };
        assert!(format!("{error:#}").contains("apply operator withdrawal"));
        assert!(agent.pending_withdrawal.is_some());

        let wrong_ack = agent
            .withdraw(&context, settlement_address, operator_address, action)
            .await
            .unwrap();
        let WithdrawalOutcome::Signed {
            request: retained,
            error,
        } = wrong_ack
        else {
            panic!("wrong operator acknowledgement cleared withdrawal");
        };
        assert_eq!(retained, request);
        assert!(format!("{error:#}").contains("another withdrawal"));
        assert!(agent.pending_withdrawal.is_some());

        let retry = agent
            .withdraw(&context, settlement_address, operator_address, action)
            .await
            .unwrap();
        let WithdrawalOutcome::Applied {
            epoch,
            request: applied,
        } = retry
        else {
            panic!("exact withdrawal retry was not acknowledged");
        };
        assert_eq!(epoch, 0);
        assert_eq!(applied, request);
        assert!(agent.pending_withdrawal.is_none());
        settlement_server.await.unwrap();
        operator_server.await.unwrap();
    });
}

#[test]
fn withdrawal_uses_only_the_exact_retained_head_when_the_operator_is_unreachable() {
    deterministic::Runner::default().start(|context| async move {
        let account = wallets()[0].public_key();
        let current = AccountCache::new::<Sha256>(vec![StateLeaf {
            account: account.clone(),
            state: AccountState {
                balance: 100,
                active: true,
                ..AccountState::default()
            },
        }])
        .unwrap();
        let stale = AccountCache::new::<Sha256>(vec![StateLeaf {
            account: account.clone(),
            state: AccountState {
                balance: 99,
                active: true,
                ..AccountState::default()
            },
        }])
        .unwrap();
        let current_root = current.root();
        let current_opening = current.opening(&account).unwrap();
        let stale_root = stale.root();
        let stale_opening = stale.opening(&account).unwrap();
        assert_ne!(current_root, stale_root);

        let mut agent = Agent::new(0).unwrap();
        agent
            .store
            .retain_recovery_opening(&current_root, &current_opening)
            .unwrap();
        agent
            .store
            .retain_recovery_opening(&stale_root, &stale_opening)
            .unwrap();

        let mut settlement_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
            .await
            .unwrap();
        let settlement_address = settlement_listener.local_addr().unwrap();
        let settlement_server = context.child("settlement").spawn(move |_| async move {
            respond_rpc(&mut settlement_listener, |request| {
                assert_eq!(request.method, settlement_rpc::METHOD_STATUS);
                let mut status = settlement_status_response();
                status.state_root = current_root;
                rpc::Response::Success {
                    body: status.encode(),
                }
            })
            .await;
        });

        let outcome = agent
            .withdraw(
                &context,
                settlement_address,
                SocketAddr::from(([127, 0, 0, 1], 2)),
                WithdrawalAction::Amount(NonZeroU64::new(7).unwrap()),
            )
            .await
            .unwrap();
        let WithdrawalOutcome::Signed { request, error } = outcome else {
            panic!("unreachable operator unexpectedly applied withdrawal");
        };
        assert_eq!(
            request.body().action(),
            &WithdrawalAction::Amount(NonZeroU64::new(7).unwrap())
        );
        assert_eq!(request.body().state_root(), &current_root.digest);
        assert!(format!("{error:#}").contains("apply operator withdrawal"));
        assert_eq!(agent.pending_withdrawal.as_ref(), Some(&request));
        settlement_server.await.unwrap();

        let mut wrong_only = Agent::new(0).unwrap();
        wrong_only
            .store
            .retain_recovery_opening(&stale_root, &stale_opening)
            .unwrap();
        let mut settlement_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 3)))
            .await
            .unwrap();
        let settlement_address = settlement_listener.local_addr().unwrap();
        let settlement_server = context
            .child("wrong_only_settlement")
            .spawn(move |_| async move {
                respond_rpc(&mut settlement_listener, |request| {
                    assert_eq!(request.method, settlement_rpc::METHOD_STATUS);
                    let mut status = settlement_status_response();
                    status.state_root = current_root;
                    rpc::Response::Success {
                        body: status.encode(),
                    }
                })
                .await;
            });

        let error = wrong_only
            .withdraw(
                &context,
                settlement_address,
                SocketAddr::from(([127, 0, 0, 1], 4)),
                WithdrawalAction::Close,
            )
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("read withdrawal opening"));
        assert!(wrong_only.pending_withdrawal.is_none());
        settlement_server.await.unwrap();
    });
}

#[test]
fn forged_quote_operator_is_rejected_before_staging() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let impostor = Wallet::from_seed("impostor", 1_001);
        let payment_context = PaymentContext::new(
            Sha256::hash(&[b"forged-quote-operator"]),
            7,
            impostor.public_key(),
        );
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let operator_address = listener.local_addr().unwrap();
        let operator_server = context.child("operator").spawn(move |_| async move {
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::PaymentQuote(_)
                ));
                rpc::Response::Success {
                    body: payment_quote_response(
                        payment_context,
                        AccountState {
                            balance: 100,
                            cumulative_debit: 50_000,
                            ..AccountState::default()
                        },
                    )
                    .encode(),
                }
            })
            .await;
        });

        let mut agent = Agent::open(database.path(), 0).unwrap();
        let error = agent
            .pay(&context, operator_address, operator_address, &[(1, 7)])
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("unexpected operator"));
        drop(agent);

        let recovered = Agent::open(database.path(), 0).unwrap();
        assert_eq!(recovered.cumulative_debit, 0);
        assert!(recovered.pending_payment.is_none());
        operator_server.await.unwrap();
    });
}

#[test]
fn adversarial_payment_quotes_are_rejected_before_send_or_persistence() {
    deterministic::Runner::default().start(|context| async move {
        for (case_index, case) in PaymentQuoteGateCase::ALL.into_iter().enumerate() {
            let database = TempDatabase::new();
            let payment_context = PaymentContext::new(
                Sha256::hash(&[b"adversarial-payment-quote"]),
                7,
                operator_key(),
            );
            let mut quote = payment_quote_response(
                payment_context,
                AccountState {
                    balance: 100,
                    ..AccountState::default()
                },
            );
            let mut status = settlement_status_response();
            status.state_root = quote.root;
            case.corrupt(&mut quote, &mut status);
            let rejected_root = quote.root;
            let base_port = u16::try_from(case_index).unwrap() * 2;

            let mut operator_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], base_port + 1)))
                .await
                .unwrap();
            let operator_address = operator_listener.local_addr().unwrap();
            let mut settlement_listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], base_port + 2)))
                .await
                .unwrap();
            let settlement_address = settlement_listener.local_addr().unwrap();
            let server = context.child(case.actor()).spawn(move |_| async move {
                respond(&mut operator_listener, |request| {
                    let operator_rpc::OperatorRequest::PaymentQuote(request) = request else {
                        panic!("expected one payment quote request");
                    };
                    assert_eq!(request.account, wallets()[0].public_key());
                    rpc::Response::Success {
                        body: quote.encode(),
                    }
                })
                .await;
                respond_rpc(&mut settlement_listener, |request| {
                    assert_eq!(request.method, settlement_rpc::METHOD_STATUS);
                    assert_eq!(request.body, settlement_rpc::StatusRequest.encode());
                    rpc::Response::Success {
                        body: status.encode(),
                    }
                })
                .await;
            });

            let mut agent = Agent::open(database.path(), 0).unwrap();
            let error = agent
                .pay(&context, settlement_address, operator_address, &[(1, 7)])
                .await
                .unwrap_err();
            let error = format!("{error:#}");
            assert!(
                error.contains(case.expected_error()),
                "{case:?} returned an unexpected error: {error}"
            );
            drop(agent);
            server.await.unwrap();

            let recovered = Agent::open(database.path(), 0).unwrap();
            assert_eq!(recovered.cumulative_debit, 0, "{case:?}");
            assert!(recovered.pending_payment.is_none(), "{case:?}");
            assert_eq!(recovered.receipt_count(), 0, "{case:?}");
            assert!(
                recovered
                    .store
                    .recovery_opening(&rejected_root)
                    .unwrap()
                    .is_none(),
                "{case:?} retained an unauthenticated payer opening"
            );
        }
    });
}

#[test]
fn unregistered_valid_payment_context_does_not_commit() {
    deterministic::Runner::default().start(|context| async move {
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();

        let mut operator_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
            .await
            .unwrap();
        let operator_address = operator_listener.local_addr().unwrap();
        let operator_server = context.child("operator").spawn(move |_| async move {
            let mut first_send = None;
            for expected in [
                operator_rpc::METHOD_PAYMENT_QUOTE,
                operator_rpc::METHOD_ACCEPT_SEND,
                operator_rpc::METHOD_PAYMENT_QUOTE,
                operator_rpc::METHOD_ACCEPT_SEND,
            ] {
                respond_rpc(&mut operator_listener, |request| {
                    assert_eq!(request.method, expected);
                    let request = operator_rpc::decode_request(request).unwrap();
                    if let operator_rpc::OperatorRequest::AcceptSend(request) = &request {
                        if let Some(first) = &first_send {
                            assert_eq!(&request.send, first);
                        } else {
                            first_send = Some(request.send.clone());
                        }
                    }
                    operator_rpc::handle_decoded(&mut operator, request)
                })
                .await;
            }
        });

        let mut settlement = Settlement::new().unwrap();
        let mut settlement_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
            .await
            .unwrap();
        let settlement_address = settlement_listener.local_addr().unwrap();
        let settlement_server = context.child("settlement").spawn(move |_| async move {
            for expected in [
                settlement_rpc::METHOD_STATUS,
                settlement_rpc::METHOD_CONFIRM_REGISTRATION,
            ] {
                respond_rpc(&mut settlement_listener, |request| {
                    assert_eq!(request.method, expected);
                    settlement_rpc::handle(&mut settlement, request)
                })
                .await;
            }
            settlement
                .register_epoch(
                    0,
                    400,
                    DepositBatch::<Key>::empty().root::<Sha256>().unwrap(),
                    DepositBatch::<Key>::empty().root::<Sha256>().unwrap(),
                    WithdrawalBatch::empty(),
                    &[],
                )
                .unwrap();
            respond_rpc(&mut settlement_listener, |request| {
                assert_eq!(request.method, settlement_rpc::METHOD_CONFIRM_REGISTRATION);
                settlement_rpc::handle(&mut settlement, request)
            })
            .await;
        });

        let mut agent = Agent::new(0).unwrap();
        let error = agent
            .pay(&context, settlement_address, operator_address, &[(1, 7)])
            .await
            .unwrap_err();
        let error = format!("{error:#}");
        assert!(error.contains("confirm payment registration"));
        assert!(error.contains("payment registration is no longer live"));
        assert_eq!(agent.cumulative_debit, 0);
        assert_eq!(agent.receipt_count(), 0);
        let pending = agent.pending_payment.as_ref().unwrap();
        assert!(
            agent
                .store
                .recovery_opening(&pending.recovery_root)
                .unwrap()
                .is_some()
        );

        let payment = accepted(
            agent
                .pay(&context, settlement_address, operator_address, &[(1, 7)])
                .await
                .unwrap(),
        );
        assert_eq!(payment.acceptance.receipts[0].body().amount(), 7);
        assert_eq!(agent.cumulative_debit, 7);
        assert_eq!(agent.receipt_count(), 1);
        assert!(agent.pending_payment.is_none());
        operator_server.await.unwrap();
        settlement_server.await.unwrap();
    });
}

#[test]
fn response_loss_restart_retries_byte_identical_pending_send() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let operator = Wallet::from_seed("operator", 1);
        let payment_context = PaymentContext::new(
            Sha256::hash(&[b"response-loss-restart"]),
            7,
            operator.public_key(),
        );
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let operator_address = listener.local_addr().unwrap();
        let operator_server = context.child("operator").spawn(move |_| async move {
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::PaymentQuote(_)
                ));
                rpc::Response::Success {
                    body: payment_quote_response(
                        payment_context.clone(),
                        AccountState {
                            balance: 100,
                            cumulative_debit: 50_000,
                            ..AccountState::default()
                        },
                    )
                    .encode(),
                }
            })
            .await;
            respond(&mut listener, |request| {
                assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                rpc::Response::Success {
                    body: settlement_status_response().encode(),
                }
            })
            .await;

            let accepted;
            let first_send;
            {
                let (_, _sink, mut stream) = listener.accept().await.unwrap();
                let request = rpc::recv_request(&mut stream).await.unwrap();
                let operator_rpc::OperatorRequest::AcceptSend(request) =
                    operator_rpc::decode_request(request).unwrap()
                else {
                    panic!("expected the initially staged send");
                };
                assert_eq!(request.send.body().cumulative_debit(), 7);
                first_send = request.send;
                let recipient = first_send.body().entries()[0].recipient().clone();
                let receipt = SignedReceipt::issue_next::<Sha256, _>(
                    &payment_context,
                    &first_send,
                    &recipient,
                    0,
                    0,
                    0,
                    operator.signer(),
                )
                .unwrap();
                let (send, receipt) =
                    Payment::new::<Sha256>(&payment_context, first_send.clone(), receipt)
                        .unwrap()
                        .into_parts();
                accepted = Acceptance {
                    send,
                    receipts: vec![receipt],
                };
            }

            // The restarted retry re-quotes to confirm the staged context is still live.
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::PaymentQuote(_)
                ));
                rpc::Response::Success {
                    body: payment_quote_response(
                        payment_context.clone(),
                        AccountState {
                            balance: 93,
                            cumulative_debit: 50_007,
                            ..AccountState::default()
                        },
                    )
                    .encode(),
                }
            })
            .await;
            respond(&mut listener, |request| {
                let operator_rpc::OperatorRequest::AcceptSend(request) = request else {
                    panic!("restart retry unexpectedly skipped its resubmission");
                };
                assert_eq!(request.send.encode(), first_send.encode());
                rpc::Response::Success {
                    body: operator_rpc::AcceptedBatchResponse {
                        epoch: payment_context.epoch(),
                        sequence: 0,
                        total: 7,
                        acceptance: accepted,
                    }
                    .encode(),
                }
            })
            .await;
            respond_registration(&mut listener, &payment_context).await;
        });

        let mut agent = Agent::open(database.path(), 0).unwrap();
        let error = agent
            .pay(&context, operator_address, operator_address, &[(1, 7)])
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("submit payment"));
        assert!(agent.pending_payment.is_some());
        drop(agent);

        let mut recovered = Agent::open(database.path(), 0).unwrap();
        assert!(recovered.pending_payment.is_some());
        let payment = accepted(
            recovered
                .pay(&context, operator_address, operator_address, &[(1, 7)])
                .await
                .unwrap(),
        );
        assert_eq!(payment.acceptance.receipts[0].body().amount(), 7);
        assert_eq!(recovered.cumulative_debit, 7);
        assert_eq!(recovered.receipt_count(), 1);
        assert!(recovered.pending_payment.is_none());
        drop(recovered);

        let recovered = Agent::open(database.path(), 0).unwrap();
        assert!(recovered.pending_payment.is_none());
        assert_eq!(recovered.receipt_count(), 1);
        operator_server.await.unwrap();
    });
}

#[test]
fn successful_receipt_commit_survives_restart_and_advances_next_debit() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let operator = Wallet::from_seed("operator", 1);
        let payment_context = PaymentContext::new(
            Sha256::hash(&[b"successful-payment-restart"]),
            7,
            operator.public_key(),
        );
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let operator_address = listener.local_addr().unwrap();
        let operator_server = context.child("operator").spawn(move |_| async move {
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::PaymentQuote(_)
                ));
                rpc::Response::Success {
                    body: payment_quote_response(
                        payment_context.clone(),
                        AccountState {
                            balance: 100,
                            cumulative_debit: 10_000,
                            ..AccountState::default()
                        },
                    )
                    .encode(),
                }
            })
            .await;
            respond(&mut listener, |request| {
                assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                rpc::Response::Success {
                    body: settlement_status_response().encode(),
                }
            })
            .await;
            respond(&mut listener, |request| {
                let operator_rpc::OperatorRequest::AcceptSend(request) = request else {
                    panic!("expected the first signed send");
                };
                assert_eq!(request.send.body().cumulative_debit(), 7);
                let recipient = request.send.body().entries()[0].recipient().clone();
                let receipt = SignedReceipt::issue_next::<Sha256, _>(
                    &payment_context,
                    &request.send,
                    &recipient,
                    0,
                    0,
                    0,
                    operator.signer(),
                )
                .unwrap();
                let (send, receipt) =
                    Payment::new::<Sha256>(&payment_context, request.send, receipt)
                        .unwrap()
                        .into_parts();
                let payment = Acceptance {
                    send,
                    receipts: vec![receipt],
                };
                rpc::Response::Success {
                    body: operator_rpc::AcceptedBatchResponse {
                        epoch: payment_context.epoch(),
                        sequence: 0,
                        total: 7,
                        acceptance: payment,
                    }
                    .encode(),
                }
            })
            .await;
            respond_registration(&mut listener, &payment_context).await;
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::PaymentQuote(_)
                ));
                rpc::Response::Success {
                    body: payment_quote_response(
                        payment_context.clone(),
                        AccountState {
                            balance: 93,
                            cumulative_debit: 20_000,
                            ..AccountState::default()
                        },
                    )
                    .encode(),
                }
            })
            .await;
            respond(&mut listener, |request| {
                assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                rpc::Response::Success {
                    body: settlement_status_response().encode(),
                }
            })
            .await;
            respond(&mut listener, |request| {
                let operator_rpc::OperatorRequest::AcceptSend(request) = request else {
                    panic!("expected the second signed send");
                };
                assert_eq!(request.send.body().cumulative_debit(), 10);
                let recipient = request.send.body().entries()[0].recipient().clone();
                let receipt = SignedReceipt::issue_next::<Sha256, _>(
                    &payment_context,
                    &request.send,
                    &recipient,
                    0,
                    7,
                    1,
                    operator.signer(),
                )
                .unwrap();
                let (send, receipt) =
                    Payment::new::<Sha256>(&payment_context, request.send, receipt)
                        .unwrap()
                        .into_parts();
                let payment = Acceptance {
                    send,
                    receipts: vec![receipt],
                };
                rpc::Response::Success {
                    body: operator_rpc::AcceptedBatchResponse {
                        epoch: payment_context.epoch(),
                        sequence: 1,
                        total: 3,
                        acceptance: payment,
                    }
                    .encode(),
                }
            })
            .await;
            respond_registration(&mut listener, &payment_context).await;
        });

        let mut agent = Agent::open(database.path(), 0).unwrap();
        agent
            .pay(&context, operator_address, operator_address, &[(1, 7)])
            .await
            .unwrap();
        drop(agent);

        let mut recovered = Agent::open(database.path(), 0).unwrap();
        assert_eq!(recovered.cumulative_debit, 7);
        assert_eq!(recovered.receipt_count(), 1);
        recovered
            .pay(&context, operator_address, operator_address, &[(1, 3)])
            .await
            .unwrap();
        drop(recovered);

        let recovered = Agent::open(database.path(), 0).unwrap();
        assert_eq!(recovered.cumulative_debit, 10);
        assert_eq!(recovered.receipt_count(), 2);
        operator_server.await.unwrap();
    });
}

#[test]
fn withdrawal_claim_ack_loss_recovers_after_agent_restart() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        operator
            .withdraw(0, WithdrawalAction::Amount(NonZeroU64::new(25).unwrap()))
            .unwrap();
        operator.start_close(0).unwrap();
        operator.wait_for_closes().unwrap();

        let account = wallets()[0].public_key();
        let roots = claim_roots_response(&operator.settlement_roots(0).unwrap());
        let evidence = operator.withdrawal_evidence(&account).unwrap();
        let evidence = operator_rpc::WithdrawalEvidenceResponse {
            batch_id: evidence.batch_id,
            account: evidence.account,
            claim: evidence.claim,
        };
        let release = settlement_rpc::WithdrawalResponse {
            amount: evidence.claim.output().amount(),
            destination: evidence.claim.output().destination().clone(),
        };

        let mut settlement_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
            .await
            .unwrap();
        let settlement_address = settlement_listener.local_addr().unwrap();
        let settlement_evidence = evidence.clone();
        let settlement_release = release.clone();
        let settlement_server = context.child("settlement").spawn(move |_| async move {
            respond_claim_roots(
                &mut settlement_listener,
                settlement_evidence.batch_id,
                Some(roots),
            )
            .await;
            for _ in 0..2 {
                respond_rpc(&mut settlement_listener, |request| {
                    assert_eq!(request.method, settlement_rpc::METHOD_CLAIM_WITHDRAWAL);
                    let request =
                        settlement_rpc::WithdrawalClaimRequest::decode(request.body).unwrap();
                    assert_eq!(request.batch_id, settlement_evidence.batch_id);
                    assert_eq!(request.claim, settlement_evidence.claim);
                    rpc::Response::Success {
                        body: settlement_rpc::WithdrawalClaimResponse::Released(
                            settlement_release.clone(),
                        )
                        .encode(),
                    }
                })
                .await;
            }
        });

        let mut operator_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
            .await
            .unwrap();
        let operator_address = operator_listener.local_addr().unwrap();
        let operator_evidence = evidence.clone();
        let operator_server = context.child("operator").spawn(move |_| async move {
            respond(&mut operator_listener, |request| {
                let operator_rpc::OperatorRequest::WithdrawalEvidence(request) = request else {
                    panic!("expected withdrawal evidence request");
                };
                assert_eq!(request.account, operator_evidence.account);
                rpc::Response::Success {
                    body: operator_rpc::WithdrawalEvidenceResponse {
                        batch_id: operator_evidence.batch_id,
                        account: operator_evidence.account.clone(),
                        claim: operator_evidence.claim.clone(),
                    }
                    .encode(),
                }
            })
            .await;

            let (_, sink, mut stream) = operator_listener.accept().await.unwrap();
            let request =
                operator_rpc::decode_request(rpc::recv_request(&mut stream).await.unwrap())
                    .unwrap();
            let operator_rpc::OperatorRequest::AcknowledgeWithdrawal(request) = request else {
                panic!("expected withdrawal acknowledgement");
            };
            assert_eq!(request.as_ref(), &operator_evidence);
            assert!(matches!(
                operator_rpc::acknowledge_withdrawal_confirmed(&mut operator, &request),
                rpc::Response::Success { .. }
            ));
            drop(sink);

            respond(&mut operator_listener, |request| {
                let operator_rpc::OperatorRequest::AcknowledgeWithdrawal(request) = request else {
                    panic!("restart requested withdrawal evidence again");
                };
                assert_eq!(request.as_ref(), &operator_evidence);
                operator_rpc::acknowledge_withdrawal_confirmed(&mut operator, &request)
            })
            .await;
        });

        let mut agent = Agent::open(database.path(), 0).unwrap();
        open_withdrawal_intent(&mut agent);
        let lost = agent
            .claim_withdrawal(&context, settlement_address, operator_address)
            .await
            .unwrap_err();
        assert!(format!("{lost:#}").contains("acknowledge claimed withdrawal"));
        drop(agent);

        // The released-but-unacknowledged claim survives the restart with its exact
        // evidence pinned, and the retry goes straight to settlement without a fetch.
        let mut recovered = Agent::open(database.path(), 0).unwrap();
        let held = recovered.pending_withdrawal_claim.clone().unwrap();
        assert_eq!(held.evidence.as_ref(), Some(&evidence));
        assert_eq!(held.result.as_ref(), Some(&release));
        assert_eq!(
            recovered
                .claim_withdrawal(&context, settlement_address, operator_address)
                .await
                .unwrap(),
            release
        );
        assert!(recovered.pending_withdrawal_claim.is_none());
        drop(recovered);

        let recovered = Agent::open(database.path(), 0).unwrap();
        assert!(recovered.pending_withdrawal_claim.is_none());
        operator_server.await.unwrap();
        settlement_server.await.unwrap();
    });
}

#[test]
fn external_payout_ack_loss_recovers_after_agent_restart() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        operator.pay(0, operator.wallet_count(), 100).unwrap();
        operator.start_close(0).unwrap();
        operator.wait_for_closes().unwrap();

        let identity = wallets().len();
        let account = external_identity().key;
        let roots = claim_roots_response(&operator.settlement_roots(0).unwrap());
        let evidence = operator.external_payout_evidence(&account).unwrap();
        let evidence = operator_rpc::ExternalPayoutEvidenceResponse {
            batch_id: evidence.batch_id,
            claim: evidence.claim,
        };
        let payout = settlement_rpc::ExternalPayoutResponse {
            recipient: account.clone(),
            amount: 100,
        };

        let mut settlement_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 3)))
            .await
            .unwrap();
        let settlement_address = settlement_listener.local_addr().unwrap();
        let settlement_evidence = evidence.clone();
        let settlement_payout = payout.clone();
        let settlement_server = context.child("settlement").spawn(move |_| async move {
            respond_claim_roots(
                &mut settlement_listener,
                settlement_evidence.batch_id,
                Some(roots),
            )
            .await;
            for _ in 0..2 {
                respond_rpc(&mut settlement_listener, |request| {
                    assert_eq!(request.method, settlement_rpc::METHOD_CLAIM_EXTERNAL_PAYOUT);
                    let request =
                        settlement_rpc::ExternalPayoutClaimRequest::decode(request.body).unwrap();
                    assert_eq!(request.batch_id, settlement_evidence.batch_id);
                    assert_eq!(request.claim, settlement_evidence.claim);
                    rpc::Response::Success {
                        body: settlement_rpc::ExternalPayoutClaimResponse::Released(
                            settlement_payout.clone(),
                        )
                        .encode(),
                    }
                })
                .await;
            }
        });

        let mut operator_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 4)))
            .await
            .unwrap();
        let operator_address = operator_listener.local_addr().unwrap();
        let operator_evidence = evidence.clone();
        let operator_server = context.child("operator").spawn(move |_| async move {
            respond(&mut operator_listener, |request| {
                let operator_rpc::OperatorRequest::ExternalPayoutEvidence(request) = request else {
                    panic!("expected external-payout evidence request");
                };
                assert_eq!(request.account, account);
                rpc::Response::Success {
                    body: operator_rpc::ExternalPayoutEvidenceResponse {
                        batch_id: operator_evidence.batch_id,
                        claim: operator_evidence.claim.clone(),
                    }
                    .encode(),
                }
            })
            .await;

            let (_, sink, mut stream) = operator_listener.accept().await.unwrap();
            let request =
                operator_rpc::decode_request(rpc::recv_request(&mut stream).await.unwrap())
                    .unwrap();
            let operator_rpc::OperatorRequest::AcknowledgeExternalPayout(request) = request else {
                panic!("expected external-payout acknowledgement");
            };
            assert_eq!(request.as_ref(), &operator_evidence);
            assert!(matches!(
                operator_rpc::acknowledge_external_payout_confirmed(&mut operator, &request),
                rpc::Response::Success { .. }
            ));
            drop(sink);

            respond(&mut operator_listener, |request| {
                let operator_rpc::OperatorRequest::AcknowledgeExternalPayout(request) = request
                else {
                    panic!("restart requested external-payout evidence again");
                };
                assert_eq!(request.as_ref(), &operator_evidence);
                operator_rpc::acknowledge_external_payout_confirmed(&mut operator, &request)
            })
            .await;
        });

        let mut agent = Agent::open(database.path(), identity).unwrap();
        let lost = agent
            .claim_external_payout(&context, settlement_address, operator_address)
            .await
            .unwrap_err();
        assert!(format!("{lost:#}").contains("acknowledge claimed external payout"));
        drop(agent);

        let mut recovered = Agent::open(database.path(), identity).unwrap();
        assert!(recovered.pending_payout_claim.is_some());
        assert_eq!(
            recovered
                .claim_external_payout(&context, settlement_address, operator_address)
                .await
                .unwrap(),
            payout
        );
        assert!(recovered.pending_payout_claim.is_none());
        drop(recovered);

        let recovered = Agent::open(database.path(), identity).unwrap();
        assert!(recovered.pending_payout_claim.is_none());
        operator_server.await.unwrap();
        settlement_server.await.unwrap();
    });
}

#[test]
fn foreign_withdrawal_evidence_is_never_cached() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        operator
            .withdraw(1, WithdrawalAction::Amount(NonZeroU64::new(25).unwrap()))
            .unwrap();
        operator.start_close(0).unwrap();
        operator.wait_for_closes().unwrap();

        // Bob's certified claim pays destination "Bob". A hostile operator relabels the
        // evidence with Alice's account and serves it to Alice.
        let victim = wallets()[0].public_key();
        let roots = claim_roots_response(&operator.settlement_roots(0).unwrap());
        let evidence = operator
            .withdrawal_evidence(&wallets()[1].public_key())
            .unwrap();
        let forged = operator_rpc::WithdrawalEvidenceResponse {
            batch_id: evidence.batch_id,
            account: victim,
            claim: evidence.claim,
        };

        let batch = forged.batch_id;
        let mut settlement_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
            .await
            .unwrap();
        let settlement_address = settlement_listener.local_addr().unwrap();
        let settlement_server = context.child("settlement").spawn(move |_| async move {
            respond_claim_roots(&mut settlement_listener, batch, Some(roots)).await;
        });
        let mut operator_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
            .await
            .unwrap();
        let operator_address = operator_listener.local_addr().unwrap();
        let operator_server = context.child("operator").spawn(move |_| async move {
            respond(&mut operator_listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::WithdrawalEvidence(_)
                ));
                rpc::Response::Success {
                    body: forged.encode(),
                }
            })
            .await;
        });

        // The genuine claim verifies against the batch's own root and the forged
        // account label passes its check, so only the destination binding stands
        // between Alice and caching Bob's claim as her own.
        let mut agent = Agent::open(database.path(), 0).unwrap();
        open_withdrawal_intent(&mut agent);
        let error = agent
            .claim_withdrawal(&context, settlement_address, operator_address)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("another destination"));
        assert!(
            agent
                .pending_withdrawal_claim
                .as_ref()
                .is_some_and(|held| held.evidence.is_none())
        );
        drop(agent);

        // Nothing was cached, so a restarted wallet fetches fresh evidence.
        let recovered = Agent::open(database.path(), 0).unwrap();
        assert!(
            recovered
                .pending_withdrawal_claim
                .as_ref()
                .is_some_and(|held| held.evidence.is_none())
        );
        operator_server.await.unwrap();
        settlement_server.await.unwrap();
    });
}

#[test]
fn staged_deposit_survives_restart_and_retries_the_same_id() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let mut settlement = Settlement::new().unwrap();
        let mut settlement_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
            .await
            .unwrap();
        let settlement_address = settlement_listener.local_addr().unwrap();
        let settlement_server = context.child("settlement").spawn(move |_| async move {
            for _ in 0..2 {
                respond_rpc(&mut settlement_listener, |request| {
                    assert_eq!(request.method, settlement_rpc::METHOD_DEPOSIT);
                    settlement_rpc::handle(&mut settlement, request)
                })
                .await;
            }
            settlement.status().unwrap().custody_balance
        });

        // Settlement records custody, then the wallet dies before the operator credit.
        // The unreachable operator stands in for that crash window.
        let mut agent = Agent::open(database.path(), 0).unwrap();
        let first = agent
            .deposit(
                &context,
                settlement_address,
                SocketAddr::from(([127, 0, 0, 1], 9)),
                7,
            )
            .await
            .unwrap();
        let DepositOutcome::Recorded { event, .. } = first else {
            panic!("unreachable operator unexpectedly applied deposit");
        };
        drop(agent);

        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        let mut operator_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
            .await
            .unwrap();
        let operator_address = operator_listener.local_addr().unwrap();
        let operator_server = context.child("operator").spawn(move |_| async move {
            respond_rpc(&mut operator_listener, |request| {
                assert_eq!(request.method, operator_rpc::METHOD_APPLY_DEPOSIT);
                let request = operator_rpc::decode_request(request).unwrap();
                operator_rpc::handle_decoded(&mut operator, request)
            })
            .await;
        });

        // The restarted wallet restores the exact staged event, so the retry replays
        // the recorded id even though its volatile nonce differs.
        let mut recovered = Agent::open(database.path(), 0).unwrap();
        assert_eq!(recovered.pending_deposit.as_ref(), Some(&event));
        recovered.deposit_nonce = 41;
        let retry = recovered
            .deposit(&context, settlement_address, operator_address, 7)
            .await
            .unwrap();
        let DepositOutcome::Applied { event: applied, .. } = retry else {
            panic!("restored deposit retry was not acknowledged");
        };
        assert_eq!(applied, event);
        assert!(recovered.pending_deposit.is_none());
        assert_eq!(recovered.deposit_nonce, 42);
        drop(recovered);

        let reopened = Agent::open(database.path(), 0).unwrap();
        assert!(reopened.pending_deposit.is_none());
        assert_eq!(settlement_server.await.unwrap(), 407);
        operator_server.await.unwrap();
    });
}

#[test]
fn unrecorded_deposit_rejection_discards_the_staged_event() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let mut settlement_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
            .await
            .unwrap();
        let settlement_address = settlement_listener.local_addr().unwrap();
        let settlement_server = context.child("settlement").spawn(move |_| async move {
            // The first rejection cannot be classified: the confirmation connection
            // dies, so the staged event must survive for an exact retry.
            let mut first_deposit = Bytes::new();
            respond_rpc(&mut settlement_listener, |request| {
                assert_eq!(request.method, settlement_rpc::METHOD_DEPOSIT);
                first_deposit = request.body;
                rpc::error_response("deposit capacity".to_string())
            })
            .await;
            {
                let (_, _sink, mut stream) = settlement_listener.accept().await.unwrap();
                let request = rpc::recv_request(&mut stream).await.unwrap();
                assert_eq!(request.method, settlement_rpc::METHOD_CONFIRM_DEPOSIT);
            }

            // The retry replays the exact staged event, and this time settlement
            // states the id was never recorded, so no custody moved.
            respond_rpc(&mut settlement_listener, |request| {
                assert_eq!(request.method, settlement_rpc::METHOD_DEPOSIT);
                assert_eq!(request.body, first_deposit);
                rpc::error_response("deposit capacity".to_string())
            })
            .await;
            respond_rpc(&mut settlement_listener, |request| {
                assert_eq!(request.method, settlement_rpc::METHOD_CONFIRM_DEPOSIT);
                rpc::Response::Success {
                    body: settlement_rpc::DepositConfirmation::Unknown.encode(),
                }
            })
            .await;
        });

        let mut agent = Agent::open(database.path(), 0).unwrap();
        let error = agent
            .deposit(
                &context,
                settlement_address,
                SocketAddr::from(([127, 0, 0, 1], 9)),
                7,
            )
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("record settlement deposit"));
        assert!(agent.pending_deposit.is_some());

        let error = agent
            .deposit(
                &context,
                settlement_address,
                SocketAddr::from(([127, 0, 0, 1], 9)),
                7,
            )
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("record settlement deposit"));
        assert!(agent.pending_deposit.is_none());
        drop(agent);

        // The discard is durable, so the flow is not wedged on the rejected event.
        let recovered = Agent::open(database.path(), 0).unwrap();
        assert!(recovered.pending_deposit.is_none());
        settlement_server.await.unwrap();
    });
}

#[test]
fn unfinalized_batch_evidence_is_not_cached_and_completes_after_finalization() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        operator
            .withdraw(0, WithdrawalAction::Amount(NonZeroU64::new(25).unwrap()))
            .unwrap();
        operator.start_close(0).unwrap();
        operator.wait_for_closes().unwrap();

        let account = wallets()[0].public_key();
        let roots = claim_roots_response(&operator.settlement_roots(0).unwrap());
        let evidence = operator.withdrawal_evidence(&account).unwrap();
        let honest = operator_rpc::WithdrawalEvidenceResponse {
            batch_id: evidence.batch_id,
            account: evidence.account,
            claim: evidence.claim,
        };

        // Well formed and destination bound, but naming a batch settlement does not
        // know: an unknown batch is not finalized, so nothing may enter the cache and
        // the claim retries later.
        let poisoned = operator_rpc::WithdrawalEvidenceResponse {
            batch_id: BatchId::new(Sha256::hash(&[b"mislabeled-withdrawal-batch"])),
            account: honest.account.clone(),
            claim: honest.claim.clone(),
        };
        let release = settlement_rpc::WithdrawalResponse {
            amount: honest.claim.output().amount(),
            destination: honest.claim.output().destination().clone(),
        };

        let mut settlement_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
            .await
            .unwrap();
        let settlement_address = settlement_listener.local_addr().unwrap();
        let honest_batch = honest.batch_id;
        let honest_claim = honest.claim.clone();
        let poisoned_batch = poisoned.batch_id;
        let settlement_release = release.clone();
        let settlement_server = context.child("settlement").spawn(move |_| async move {
            respond_claim_roots(&mut settlement_listener, poisoned_batch, None).await;
            respond_claim_roots(&mut settlement_listener, honest_batch, Some(roots)).await;
            respond_rpc(&mut settlement_listener, |request| {
                assert_eq!(request.method, settlement_rpc::METHOD_CLAIM_WITHDRAWAL);
                let request = settlement_rpc::WithdrawalClaimRequest::decode(request.body).unwrap();
                assert_eq!(request.batch_id, honest_batch);
                assert_eq!(request.claim, honest_claim);
                rpc::Response::Success {
                    body: settlement_rpc::WithdrawalClaimResponse::Released(settlement_release)
                        .encode(),
                }
            })
            .await;
        });

        let mut operator_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
            .await
            .unwrap();
        let operator_address = operator_listener.local_addr().unwrap();
        let operator_evidence = honest.clone();
        let operator_server = context.child("operator").spawn(move |_| async move {
            respond(&mut operator_listener, move |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::WithdrawalEvidence(_)
                ));
                rpc::Response::Success {
                    body: poisoned.encode(),
                }
            })
            .await;
            respond(&mut operator_listener, move |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::WithdrawalEvidence(_)
                ));
                rpc::Response::Success {
                    body: operator_evidence.encode(),
                }
            })
            .await;
            respond(&mut operator_listener, |request| {
                let operator_rpc::OperatorRequest::AcknowledgeWithdrawal(request) = request else {
                    panic!("expected withdrawal acknowledgement");
                };
                operator_rpc::acknowledge_withdrawal_confirmed(&mut operator, &request)
            })
            .await;
        });

        let mut agent = Agent::open(database.path(), 0).unwrap();
        open_withdrawal_intent(&mut agent);
        let error = agent
            .claim_withdrawal(&context, settlement_address, operator_address)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("has not finalized"));
        assert!(
            agent
                .pending_withdrawal_claim
                .as_ref()
                .is_some_and(|held| held.evidence.is_none())
        );
        drop(agent);

        // Nothing entered the cache, and the next fetch verifies against the
        // finalized batch and completes the claim.
        let mut recovered = Agent::open(database.path(), 0).unwrap();
        assert_eq!(
            recovered
                .claim_withdrawal(&context, settlement_address, operator_address)
                .await
                .unwrap(),
            release
        );
        assert!(recovered.pending_withdrawal_claim.is_none());
        operator_server.await.unwrap();
        settlement_server.await.unwrap();
    });
}

#[test]
fn cached_evidence_claims_after_the_operator_vanishes() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        operator
            .withdraw(0, WithdrawalAction::Amount(NonZeroU64::new(25).unwrap()))
            .unwrap();
        operator.start_close(0).unwrap();
        operator.wait_for_closes().unwrap();

        let account = wallets()[0].public_key();
        let roots = claim_roots_response(&operator.settlement_roots(0).unwrap());
        let evidence = operator.withdrawal_evidence(&account).unwrap();
        let honest = operator_rpc::WithdrawalEvidenceResponse {
            batch_id: evidence.batch_id,
            account: evidence.account,
            claim: evidence.claim,
        };
        let release = settlement_rpc::WithdrawalResponse {
            amount: honest.claim.output().amount(),
            destination: honest.claim.output().destination().clone(),
        };

        let mut settlement_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
            .await
            .unwrap();
        let settlement_address = settlement_listener.local_addr().unwrap();
        let honest_batch = honest.batch_id;
        let settlement_release = release.clone();
        let settlement_server = context.child("settlement").spawn(move |_| async move {
            respond_claim_roots(&mut settlement_listener, honest_batch, Some(roots)).await;

            // The first submission's response is lost after the evidence was cached.
            {
                let (_, _sink, mut stream) = settlement_listener.accept().await.unwrap();
                let request = rpc::recv_request(&mut stream).await.unwrap();
                assert_eq!(request.method, settlement_rpc::METHOD_CLAIM_WITHDRAWAL);
            }
            respond_rpc(&mut settlement_listener, |request| {
                assert_eq!(request.method, settlement_rpc::METHOD_CLAIM_WITHDRAWAL);
                rpc::Response::Success {
                    body: settlement_rpc::WithdrawalClaimResponse::Released(settlement_release)
                        .encode(),
                }
            })
            .await;
        });

        // The operator serves the evidence once, cached at its first verified fetch,
        // and then vanishes for good.
        let mut operator_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
            .await
            .unwrap();
        let operator_address = operator_listener.local_addr().unwrap();
        let operator_evidence = honest.clone();
        let operator_server = context.child("operator").spawn(move |_| async move {
            respond(&mut operator_listener, move |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::WithdrawalEvidence(_)
                ));
                rpc::Response::Success {
                    body: operator_evidence.encode(),
                }
            })
            .await;
        });

        let mut agent = Agent::open(database.path(), 0).unwrap();
        open_withdrawal_intent(&mut agent);
        let error = agent
            .claim_withdrawal(&context, settlement_address, operator_address)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("claim settlement withdrawal"));
        operator_server.await.unwrap();

        // The reserve still releases from the cached copy with the operator gone, and
        // the recorded result survives with only the acknowledgement outstanding.
        let error = agent
            .claim_withdrawal(&context, settlement_address, operator_address)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("acknowledge claimed withdrawal"));
        let held = agent.pending_withdrawal_claim.clone().unwrap();
        assert_eq!(held.evidence.as_ref(), Some(&honest));
        assert_eq!(held.result.as_ref(), Some(&release));
        drop(agent);

        let recovered = Agent::open(database.path(), 0).unwrap();
        let held = recovered.pending_withdrawal_claim.unwrap();
        assert_eq!(held.evidence, Some(honest));
        assert_eq!(held.result, Some(release));
        settlement_server.await.unwrap();
    });
}

#[test]
fn unfinalized_batch_payout_evidence_is_not_cached_and_completes_after_finalization() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        operator.pay(0, operator.wallet_count(), 100).unwrap();
        operator.start_close(0).unwrap();
        operator.wait_for_closes().unwrap();

        let identity = wallets().len();
        let account = external_identity().key;
        let roots = claim_roots_response(&operator.settlement_roots(0).unwrap());
        let evidence = operator.external_payout_evidence(&account).unwrap();
        let honest = operator_rpc::ExternalPayoutEvidenceResponse {
            batch_id: evidence.batch_id,
            claim: evidence.claim,
        };

        // Recipient bound, but naming a batch settlement does not know: an unknown
        // batch is not finalized, so nothing may enter the cache.
        let poisoned = operator_rpc::ExternalPayoutEvidenceResponse {
            batch_id: BatchId::new(Sha256::hash(&[b"mislabeled-payout-batch"])),
            claim: honest.claim.clone(),
        };
        let payout = settlement_rpc::ExternalPayoutResponse {
            recipient: account.clone(),
            amount: 100,
        };

        let mut settlement_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 3)))
            .await
            .unwrap();
        let settlement_address = settlement_listener.local_addr().unwrap();
        let honest_batch = honest.batch_id;
        let poisoned_batch = poisoned.batch_id;
        let settlement_payout = payout.clone();
        let settlement_server = context.child("settlement").spawn(move |_| async move {
            respond_claim_roots(&mut settlement_listener, poisoned_batch, None).await;
            respond_claim_roots(&mut settlement_listener, honest_batch, Some(roots)).await;
            respond_rpc(&mut settlement_listener, |request| {
                assert_eq!(request.method, settlement_rpc::METHOD_CLAIM_EXTERNAL_PAYOUT);
                let request =
                    settlement_rpc::ExternalPayoutClaimRequest::decode(request.body).unwrap();
                assert_eq!(request.batch_id, honest_batch);
                rpc::Response::Success {
                    body: settlement_rpc::ExternalPayoutClaimResponse::Released(settlement_payout)
                        .encode(),
                }
            })
            .await;
        });

        let mut operator_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 4)))
            .await
            .unwrap();
        let operator_address = operator_listener.local_addr().unwrap();
        let operator_evidence = honest.clone();
        let operator_server = context.child("operator").spawn(move |_| async move {
            respond(&mut operator_listener, move |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::ExternalPayoutEvidence(_)
                ));
                rpc::Response::Success {
                    body: poisoned.encode(),
                }
            })
            .await;
            respond(&mut operator_listener, move |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::ExternalPayoutEvidence(_)
                ));
                rpc::Response::Success {
                    body: operator_evidence.encode(),
                }
            })
            .await;
            respond(&mut operator_listener, |request| {
                let operator_rpc::OperatorRequest::AcknowledgeExternalPayout(request) = request
                else {
                    panic!("expected external-payout acknowledgement");
                };
                operator_rpc::acknowledge_external_payout_confirmed(&mut operator, &request)
            })
            .await;
        });

        let mut agent = Agent::open(database.path(), identity).unwrap();
        let error = agent
            .claim_external_payout(&context, settlement_address, operator_address)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("has not finalized"));
        assert!(
            agent
                .pending_payout_claim
                .as_ref()
                .is_some_and(|held| held.evidence.is_none())
        );
        drop(agent);

        // Nothing entered the cache, and the next fetch verifies against the
        // finalized batch and completes the claim.
        let mut recovered = Agent::open(database.path(), identity).unwrap();
        assert_eq!(
            recovered
                .claim_external_payout(&context, settlement_address, operator_address)
                .await
                .unwrap(),
            payout
        );
        assert!(recovered.pending_payout_claim.is_none());
        operator_server.await.unwrap();
        settlement_server.await.unwrap();
    });
}

#[test]
fn released_evidence_is_immutable_until_acknowledged() {
    deterministic::Runner::default().start(|_context| async move {
        let database = TempDatabase::new();
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        operator
            .withdraw(0, WithdrawalAction::Amount(NonZeroU64::new(25).unwrap()))
            .unwrap();
        operator.start_close(0).unwrap();
        operator.wait_for_closes().unwrap();

        let account = wallets()[0].public_key();
        let evidence = operator.withdrawal_evidence(&account).unwrap();
        let honest = operator_rpc::WithdrawalEvidenceResponse {
            batch_id: evidence.batch_id,
            account: evidence.account,
            claim: evidence.claim,
        };
        let release = settlement_rpc::WithdrawalResponse {
            amount: honest.claim.output().amount(),
            destination: honest.claim.output().destination().clone(),
        };

        let mut agent = Agent::open(database.path(), 0).unwrap();
        agent.store.open_withdrawal_claim().unwrap();
        agent.store.cache_withdrawal_claim(&honest).unwrap();
        agent
            .store
            .record_withdrawal_result(&honest, &release)
            .unwrap();

        // A recorded release pins its evidence until the acknowledgement completes,
        // so an overwrite attempt fails instead of replacing it.
        let replacement = operator_rpc::WithdrawalEvidenceResponse {
            batch_id: BatchId::new(Sha256::hash(&[b"replacement-batch"])),
            account: honest.account.clone(),
            claim: honest.claim.clone(),
        };
        let error = agent
            .store
            .cache_withdrawal_claim(&replacement)
            .unwrap_err();
        assert!(format!("{error:#}").contains("immutable"));
        drop(agent);

        let recovered = Agent::open(database.path(), 0).unwrap();
        let held = recovered.pending_withdrawal_claim.unwrap();
        assert_eq!(held.evidence, Some(honest));
        assert_eq!(held.result, Some(release));
    });
}

#[test]
fn endpoint_resolved_payment_recovers_after_hard_fault_frozen_at_its_head() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let operator = Wallet::from_seed("operator", 1);
        let cut = PaymentContext::new(
            Sha256::hash(&[b"endpoint-resolution-recovery-0"]),
            0,
            operator.public_key(),
        );
        let live = PaymentContext::new(
            Sha256::hash(&[b"endpoint-resolution-recovery-1"]),
            1,
            operator.public_key(),
        );
        let account = wallets()[0].public_key();

        // The finalized head H whose verified opening resolves the send as committed.
        let quote = quote_response_with_debit(
            live.clone(),
            AccountState {
                balance: 93,
                ..AccountState::default()
            },
            7,
        );
        let frozen_root = quote.root;
        let frozen_opening = quote.opening.clone();
        let mut status = settlement_status_response();
        status.state_root = frozen_root;
        status.last_finalized = Some(0);

        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let cut_context = cut.clone();
        let claim_account = account.clone();
        let server = context.child("server").spawn(move |_| async move {
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::PaymentQuote(_)
                ));
                rpc::Response::Success {
                    body: payment_quote_response(
                        cut_context.clone(),
                        AccountState {
                            balance: 100,
                            ..AccountState::default()
                        },
                    )
                    .encode(),
                }
            })
            .await;
            respond(&mut listener, |request| {
                assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                rpc::Response::Success {
                    body: settlement_status_response().encode(),
                }
            })
            .await;

            // The accept response is lost, so only the endpoint rule can resolve.
            {
                let (_, _sink, mut stream) = listener.accept().await.unwrap();
                let request = rpc::recv_request(&mut stream).await.unwrap();
                assert!(matches!(
                    operator_rpc::decode_request(request).unwrap(),
                    operator_rpc::OperatorRequest::AcceptSend(_)
                ));
            }
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::PaymentQuote(_)
                ));
                rpc::Response::Success {
                    body: quote.encode(),
                }
            })
            .await;
            respond(&mut listener, |request| {
                assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                rpc::Response::Success {
                    body: status.encode(),
                }
            })
            .await;
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::AcceptedBatch(_)
                ));
                rpc::Response::Success {
                    body: None::<operator_rpc::AcceptedBatchResponse>.encode(),
                }
            })
            .await;

            // The operator vanished and the deployment hard-faulted frozen at H.
            respond_rpc(&mut listener, |request| {
                assert_eq!(
                    request.method,
                    settlement_rpc::METHOD_BEGIN_HARD_FAULT_SETTLEMENT
                );
                rpc::Response::Success {
                    body: settlement_rpc::BeginHardFaultSettlementResponse {
                        reason: settlement_rpc::HardFaultReasonResponse::ExpiredRegistration {
                            anchor: *live.anchor(),
                            epoch: 1,
                            expired_at: 22,
                        },
                        admission_fence_epoch: 1,
                        invalid_from: None,
                        frozen_state_root: frozen_root,
                        state_liability: 100,
                        unfinalized_deposit_total: 0,
                        custody_balance: 100,
                    }
                    .encode(),
                }
            })
            .await;
            respond_rpc(&mut listener, |request| {
                assert_eq!(request.method, settlement_rpc::METHOD_CLAIM_HARD_FAULT);
                let claim = settlement_rpc::ClaimHardFaultRequest::decode(request.body).unwrap();
                assert_eq!(claim.opening, frozen_opening);
                rpc::Response::Success {
                    body: settlement_rpc::ClaimHardFaultResponse {
                        account: claim_account,
                        withdrawal: None,
                        residual: 100,
                        released_custody: 100,
                    }
                    .encode(),
                }
            })
            .await;
        });

        let mut agent = Agent::open(database.path(), 0).unwrap();
        let error = agent
            .pay(&context, address, address, &[(1, 7)])
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("submit payment"));

        // The endpoint rule resolves the send as committed at H, and the verified
        // opening is retained without any staging path running.
        let outcome = agent
            .pay(&context, address, address, &[(1, 7)])
            .await
            .unwrap();
        assert!(matches!(
            outcome,
            PaymentOutcome::CommittedUnheld { epoch: 0, total: 7 }
        ));
        drop(agent);

        // Recovery finds the opening retained at resolution, with no other head read.
        let recovered = Agent::open(database.path(), 0).unwrap();
        let release = recovered
            .recover_hard_fault(&context, address)
            .await
            .unwrap();
        assert_eq!(release.account, account);
        assert_eq!(release.released_custody, 100);
        server.await.unwrap();
    });
}

#[test]
fn false_epoch_withdrawal_ack_cannot_strand_the_claim() {
    deterministic::Runner::default().start(|context| async move {
        let mut settlement = Settlement::new().unwrap();
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        let account = wallets()[0].public_key();
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server_account = account.clone();
        let server = context.child("server").spawn(move |_| async move {
            respond_rpc(&mut listener, |request| {
                assert_eq!(request.method, settlement_rpc::METHOD_STATUS);
                settlement_rpc::handle(&mut settlement, request)
            })
            .await;
            respond_rpc(&mut listener, |request| {
                assert_eq!(request.method, operator_rpc::METHOD_WITHDRAWAL_OPENING);
                let request = operator_rpc::decode_request(request).unwrap();
                operator_rpc::handle_decoded(&mut operator, request)
            })
            .await;

            // A Byzantine operator acknowledges the exact request but lies about the
            // epoch. The digest binds the request, the epoch binds nothing.
            respond_rpc(&mut listener, |request| {
                let operator_rpc::OperatorRequest::ApplyWithdrawal(request) =
                    operator_rpc::decode_request(request).unwrap()
                else {
                    panic!("expected the signed withdrawal");
                };
                let digest = operator_rpc::withdrawal_digest(&request.request);
                operator.apply_withdrawal(request.request).unwrap();
                rpc::Response::Success {
                    body: operator_rpc::WithdrawalAck { epoch: 999, digest }.encode(),
                }
            })
            .await;

            // The true reserve finalizes in the real epoch-0 batch.
            operator.start_close(0).unwrap();
            operator.wait_for_closes().unwrap();
            let roots = claim_roots_response(&operator.settlement_roots(0).unwrap());
            let evidence = operator.withdrawal_evidence(&server_account).unwrap();
            let evidence = operator_rpc::WithdrawalEvidenceResponse {
                batch_id: evidence.batch_id,
                account: evidence.account,
                claim: evidence.claim,
            };
            let release = settlement_rpc::WithdrawalResponse {
                amount: evidence.claim.output().amount(),
                destination: evidence.claim.output().destination().clone(),
            };

            let served = evidence.clone();
            respond(&mut listener, move |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::WithdrawalEvidence(_)
                ));
                rpc::Response::Success {
                    body: served.encode(),
                }
            })
            .await;
            respond_claim_roots(&mut listener, evidence.batch_id, Some(roots)).await;
            let settlement_release = release.clone();
            respond_rpc(&mut listener, |request| {
                assert_eq!(request.method, settlement_rpc::METHOD_CLAIM_WITHDRAWAL);
                rpc::Response::Success {
                    body: settlement_rpc::WithdrawalClaimResponse::Released(settlement_release)
                        .encode(),
                }
            })
            .await;
            respond(&mut listener, |request| {
                let operator_rpc::OperatorRequest::AcknowledgeWithdrawal(request) = request else {
                    panic!("expected withdrawal acknowledgement");
                };
                operator_rpc::acknowledge_withdrawal_confirmed(&mut operator, &request)
            })
            .await;
            release
        });

        let mut agent = Agent::new(0).unwrap();
        let action = WithdrawalAction::Amount(NonZeroU64::new(7).unwrap());
        let outcome = agent
            .withdraw(&context, address, address, action)
            .await
            .unwrap();

        // The lie lands only in the display value. The durable intent carries no
        // epoch, so nothing pins the claim to the false batch.
        let WithdrawalOutcome::Applied { epoch, .. } = outcome else {
            panic!("acknowledged withdrawal was not applied");
        };
        assert_eq!(epoch, 999);

        let release = agent
            .claim_withdrawal(&context, address, address)
            .await
            .unwrap();
        assert_eq!(release, server.await.unwrap());
        assert_eq!(release.amount, 7);
        assert!(agent.pending_withdrawal_claim.is_none());
    });
}

#[test]
fn withdrawal_is_refused_while_a_prior_claim_is_unfinished() {
    deterministic::Runner::default().start(|context| async move {
        let mut settlement = Settlement::new().unwrap();
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        let account = wallets()[0].public_key();
        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server_account = account.clone();
        let server = context.child("server").spawn(move |_| async move {
            // The first withdrawal is applied and its epoch closes.
            respond_rpc(&mut listener, |request| {
                assert_eq!(request.method, settlement_rpc::METHOD_STATUS);
                settlement_rpc::handle(&mut settlement, request)
            })
            .await;
            for method in [
                operator_rpc::METHOD_WITHDRAWAL_OPENING,
                operator_rpc::METHOD_APPLY_WITHDRAWAL,
            ] {
                respond_rpc(&mut listener, |request| {
                    assert_eq!(request.method, method);
                    let request = operator_rpc::decode_request(request).unwrap();
                    operator_rpc::handle_decoded(&mut operator, request)
                })
                .await;
            }
            operator.start_close(0).unwrap();
            operator.wait_for_closes().unwrap();
            let roots = claim_roots_response(&operator.settlement_roots(0).unwrap());
            let evidence = operator.withdrawal_evidence(&server_account).unwrap();
            let batch = evidence.batch_id;
            let first_release = settlement_rpc::WithdrawalResponse {
                amount: evidence.claim.output().amount(),
                destination: evidence.claim.output().destination().clone(),
            };

            // The first claim reaches recorded-but-unacknowledged: settlement
            // releases, and the acknowledgement response is lost.
            respond_rpc(&mut listener, |request| {
                assert_eq!(request.method, operator_rpc::METHOD_WITHDRAWAL_EVIDENCE);
                let request = operator_rpc::decode_request(request).unwrap();
                operator_rpc::handle_decoded(&mut operator, request)
            })
            .await;
            respond_claim_roots(&mut listener, batch, Some(roots)).await;
            let release = first_release.clone();
            respond_rpc(&mut listener, |request| {
                assert_eq!(request.method, settlement_rpc::METHOD_CLAIM_WITHDRAWAL);
                rpc::Response::Success {
                    body: settlement_rpc::WithdrawalClaimResponse::Released(release).encode(),
                }
            })
            .await;
            {
                let (_, _sink, mut stream) = listener.accept().await.unwrap();
                let request = rpc::recv_request(&mut stream).await.unwrap();
                assert_eq!(request.method, operator_rpc::METHOD_ACKNOWLEDGE_WITHDRAWAL);
            }

            // The claim retry replays the release and completes the acknowledgement.
            let release = first_release.clone();
            respond_rpc(&mut listener, |request| {
                assert_eq!(request.method, settlement_rpc::METHOD_CLAIM_WITHDRAWAL);
                rpc::Response::Success {
                    body: settlement_rpc::WithdrawalClaimResponse::Released(release).encode(),
                }
            })
            .await;
            respond(&mut listener, |request| {
                let operator_rpc::OperatorRequest::AcknowledgeWithdrawal(request) = request else {
                    panic!("expected the first withdrawal acknowledgement");
                };
                operator_rpc::acknowledge_withdrawal_confirmed(&mut operator, &request)
            })
            .await;

            // The second withdrawal now proceeds against the advanced head.
            let head = operator.withdrawal_opening(&server_account).unwrap();
            let mut status = settlement_status_response();
            status.state_root = head.root;
            respond_rpc(&mut listener, |request| {
                assert_eq!(request.method, settlement_rpc::METHOD_STATUS);
                rpc::Response::Success {
                    body: status.encode(),
                }
            })
            .await;
            for method in [
                operator_rpc::METHOD_WITHDRAWAL_OPENING,
                operator_rpc::METHOD_APPLY_WITHDRAWAL,
            ] {
                respond_rpc(&mut listener, |request| {
                    assert_eq!(request.method, method);
                    let request = operator_rpc::decode_request(request).unwrap();
                    operator_rpc::handle_decoded(&mut operator, request)
                })
                .await;
            }
            operator.start_close(1).unwrap();
            operator.wait_for_closes().unwrap();
            let roots = claim_roots_response(&operator.settlement_roots(1).unwrap());
            let evidence = operator.withdrawal_evidence(&server_account).unwrap();
            let batch = evidence.batch_id;
            let second_release = settlement_rpc::WithdrawalResponse {
                amount: evidence.claim.output().amount(),
                destination: evidence.claim.output().destination().clone(),
            };
            respond_rpc(&mut listener, |request| {
                assert_eq!(request.method, operator_rpc::METHOD_WITHDRAWAL_EVIDENCE);
                let request = operator_rpc::decode_request(request).unwrap();
                operator_rpc::handle_decoded(&mut operator, request)
            })
            .await;
            respond_claim_roots(&mut listener, batch, Some(roots)).await;
            let release = second_release.clone();
            respond_rpc(&mut listener, |request| {
                assert_eq!(request.method, settlement_rpc::METHOD_CLAIM_WITHDRAWAL);
                rpc::Response::Success {
                    body: settlement_rpc::WithdrawalClaimResponse::Released(release).encode(),
                }
            })
            .await;
            respond(&mut listener, |request| {
                let operator_rpc::OperatorRequest::AcknowledgeWithdrawal(request) = request else {
                    panic!("expected the second withdrawal acknowledgement");
                };
                operator_rpc::acknowledge_withdrawal_confirmed(&mut operator, &request)
            })
            .await;
            (first_release, second_release)
        });

        let mut agent = Agent::new(0).unwrap();
        let first = agent
            .withdraw(
                &context,
                address,
                address,
                WithdrawalAction::Amount(NonZeroU64::new(7).unwrap()),
            )
            .await
            .unwrap();
        assert!(matches!(first, WithdrawalOutcome::Applied { .. }));
        let lost = agent
            .claim_withdrawal(&context, address, address)
            .await
            .unwrap_err();
        assert!(format!("{lost:#}").contains("acknowledge claimed withdrawal"));

        // A second withdrawal is refused cleanly while the recorded claim is
        // unfinished, and the pinned claim state survives untouched.
        let refused = agent
            .withdraw(
                &context,
                address,
                address,
                WithdrawalAction::Amount(NonZeroU64::new(5).unwrap()),
            )
            .await
            .unwrap_err();
        assert!(format!("{refused:#}").contains("pending withdrawal claim must complete"));
        let held = agent.pending_withdrawal_claim.clone().unwrap();
        assert!(held.evidence.is_some());
        assert!(held.result.is_some());

        // Completing the first claim unblocks the second withdrawal, and both
        // reserves release.
        let first_release = agent
            .claim_withdrawal(&context, address, address)
            .await
            .unwrap();
        assert!(agent.pending_withdrawal_claim.is_none());
        let second = agent
            .withdraw(
                &context,
                address,
                address,
                WithdrawalAction::Amount(NonZeroU64::new(5).unwrap()),
            )
            .await
            .unwrap();
        assert!(matches!(second, WithdrawalOutcome::Applied { .. }));
        let second_release = agent
            .claim_withdrawal(&context, address, address)
            .await
            .unwrap();
        assert!(agent.pending_withdrawal_claim.is_none());
        assert_eq!((first_release, second_release), server.await.unwrap());
    });
}

#[test]
fn balance_poll_retains_the_head_for_hard_fault_recovery() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let operator = Wallet::from_seed("operator", 1);
        let payment_context = PaymentContext::new(
            Sha256::hash(&[b"balance-poll-retention"]),
            0,
            operator.public_key(),
        );
        let account = wallets()[0].public_key();
        let quote = payment_quote_response(
            payment_context,
            AccountState {
                balance: 100,
                ..AccountState::default()
            },
        );
        let frozen_root = quote.root;
        let frozen_opening = quote.opening.clone();
        let mut status = settlement_status_response();
        status.state_root = frozen_root;

        let mut listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let claim_account = account.clone();
        let server = context.child("server").spawn(move |_| async move {
            respond(&mut listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::PaymentQuote(_)
                ));
                rpc::Response::Success {
                    body: quote.encode(),
                }
            })
            .await;
            respond(&mut listener, |request| {
                assert!(matches!(request, operator_rpc::OperatorRequest::Status));
                rpc::Response::Success {
                    body: status.encode(),
                }
            })
            .await;

            // The operator vanished and the deployment hard-faulted frozen at the
            // polled head.
            respond_rpc(&mut listener, |request| {
                assert_eq!(
                    request.method,
                    settlement_rpc::METHOD_BEGIN_HARD_FAULT_SETTLEMENT
                );
                rpc::Response::Success {
                    body: settlement_rpc::BeginHardFaultSettlementResponse {
                        reason: settlement_rpc::HardFaultReasonResponse::ExpiredRegistration {
                            anchor: Sha256::hash(&[b"balance-poll-anchor"]),
                            epoch: 0,
                            expired_at: 10,
                        },
                        admission_fence_epoch: 0,
                        invalid_from: None,
                        frozen_state_root: frozen_root,
                        state_liability: 100,
                        unfinalized_deposit_total: 0,
                        custody_balance: 100,
                    }
                    .encode(),
                }
            })
            .await;
            respond_rpc(&mut listener, |request| {
                assert_eq!(request.method, settlement_rpc::METHOD_CLAIM_HARD_FAULT);
                let claim = settlement_rpc::ClaimHardFaultRequest::decode(request.body).unwrap();
                assert_eq!(claim.opening, frozen_opening);
                rpc::Response::Success {
                    body: settlement_rpc::ClaimHardFaultResponse {
                        account: claim_account,
                        withdrawal: None,
                        residual: 100,
                        released_custody: 100,
                    }
                    .encode(),
                }
            })
            .await;
        });

        // Balance polling alone verifies and retains the current head opening.
        let mut agent = Agent::open(database.path(), 0).unwrap();
        assert_eq!(
            agent.balance(&context, address, address).await.unwrap(),
            100
        );
        drop(agent);

        let recovered = Agent::open(database.path(), 0).unwrap();
        let release = recovered
            .recover_hard_fault(&context, address)
            .await
            .unwrap();
        assert_eq!(release.account, account);
        assert_eq!(release.released_custody, 100);
        server.await.unwrap();
    });
}

/// Builds a deterministic omitting close: the admitted close credits a deposit to a bystander
/// and omits Bob, while Bob holds an operator-signed receipt crediting him.
fn omitting_close() -> crate::protocol::OmittingClose {
    crate::protocol::omitting_close(&mut TestRng::new(7)).unwrap()
}

/// Registers and admits an omitting close so its challenge window is open.
fn admit_omitting(settlement: &mut Settlement, fixture: &crate::protocol::OmittingClose) {
    settlement.deposit(fixture.deposit.clone()).unwrap();
    let root = fixture.deposits.root::<Sha256>().unwrap();
    settlement
        .register_epoch(0, 400, root, root, WithdrawalBatch::empty(), &[])
        .unwrap();
    assert_eq!(
        settlement
            .admit_submission(SettlementSubmission::from(&fixture.result))
            .unwrap(),
        crate::settlement::AdmissionOutcome::Pending
    );
}

/// The batch identity settlement anchors an admitted close on.
fn admitted_batch(fixture: &crate::protocol::OmittingClose) -> BatchId<Digest> {
    fixture.result.header.batch_id::<Sha256>()
}

fn incoming_response(
    pairs: &[(Payment<Key, Digest>, u64)],
) -> operator_rpc::IncomingPaymentsResponse {
    operator_rpc::IncomingPaymentsResponse {
        next_cursor: pairs.last().map_or(0, |(_, cursor)| *cursor),
        pairs: pairs
            .iter()
            .map(|(pair, cursor)| operator_rpc::IncomingPair {
                epoch: pair.send().body().epoch(),
                cursor: *cursor,
                payment: pair.clone(),
            })
            .collect(),
    }
}

/// A held receipt in `shard` credited by Alice under the omitting close's epoch context.
fn held_in_shard(fixture: &crate::protocol::OmittingClose, shard: u64) -> Payment<Key, Digest> {
    let context = fixture.result.payment_context.clone();
    let alice = &wallets()[0];
    let bob = wallets()[1].public_key();
    let previous_debit = shard * 5;
    let send =
        SignedSend::sign_next(&context, alice.signer(), bob.clone(), 5, previous_debit).unwrap();
    let receipt = SignedReceipt::issue_next::<Sha256, _>(
        &context,
        &send,
        &bob,
        shard,
        0,
        0,
        crate::protocol::Protocol::new(NonZeroUsize::MIN)
            .unwrap()
            .operator(),
    )
    .unwrap();
    Payment::from_parts_unchecked(send, receipt)
}

/// (c) THE POINT: a recipient holding a verified receipt convicts a close that omits its
/// credit, end to end through the real settlement RPC dispatch, and the close is invalidated.
#[test]
fn omitted_credit_is_convicted_by_the_held_receipt() {
    deterministic::Runner::default().start(|context| async move {
        let fixture = omitting_close();
        let bob_pair = fixture.held_pair.clone();
        let batch_id = admitted_batch(&fixture);
        let change_root = fixture.result.roots.change;
        let bob_lookup = fixture.held_lookup.clone();

        let mut settlement = Settlement::new().unwrap();
        admit_omitting(&mut settlement, &fixture);
        assert!(!settlement.status().unwrap().hard_faulted);

        let mut settlement_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
            .await
            .unwrap();
        let settlement_address = settlement_listener.local_addr().unwrap();
        let settlement_server = context.child("settlement").spawn(move |_| async move {
            // Intake anchors on the epoch roots, reconciliation reads status then the epoch
            // roots then submits the challenge, and the test then reads the faulted status.
            for _ in 0..5 {
                respond_rpc(&mut settlement_listener, |request| {
                    settlement_rpc::handle(&mut settlement, request)
                })
                .await;
            }
            settlement.status().unwrap().hard_faulted
        });

        let mut operator_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
            .await
            .unwrap();
        let operator_address = operator_listener.local_addr().unwrap();
        let operator_server = context.child("operator").spawn(move |_| async move {
            respond(&mut operator_listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::IncomingPayments(_)
                ));
                rpc::Response::Success {
                    body: incoming_response(&[(bob_pair, 1)]).encode(),
                }
            })
            .await;
            respond(&mut operator_listener, move |request| {
                let operator_rpc::OperatorRequest::CommittedShardTip(request) = request else {
                    panic!("expected a committed shard-tip request");
                };
                assert_eq!(request.shard, 0);
                assert_eq!(request.epoch, 0);
                rpc::Response::Success {
                    body: operator_rpc::CommittedShardTipResponse {
                        batch_id,
                        change_root,
                        lookup: bob_lookup,
                    }
                    .encode(),
                }
            })
            .await;
        });

        let mut bob = Agent::new(1).unwrap();
        bob.intake_incoming(&context, settlement_address, operator_address)
            .await
            .unwrap();
        let ledger = bob.incoming();
        assert_eq!(ledger.count, 1);
        assert_eq!(ledger.total, 5);

        let summary = bob
            .reconcile(&context, settlement_address, operator_address)
            .await
            .unwrap();
        assert_eq!(summary.convicted, [0]);

        // The proven challenge invalidated the close: settlement is hard-faulted, and Bob
        // durably recorded the epoch as decided so it is no longer reconciled or retried.
        let after = settlement_rpc::status(&context, settlement_address)
            .await
            .unwrap();
        assert!(after.hard_faulted);
        assert!(bob.store.unreconciled_incoming_epochs().unwrap().is_empty());
        assert_eq!(bob.last_reconciled_epoch(), None);

        assert!(settlement_server.await.unwrap());
        operator_server.await.unwrap();
    });
}

/// Item 1: a pair whose context anchor is not the one settlement registered has no close to
/// adjudicate against, so intake refuses it. It never becomes reliance-grade, and the durable
/// cursor still advances past it so a poisoned pair cannot wedge intake.
#[test]
fn fabricated_anchor_pair_is_refused_at_intake() {
    deterministic::Runner::default().start(|context| async move {
        // A sig-valid pair over an operator-chosen anchor with no settlement obligation.
        let bogus = PaymentContext::new(
            Sha256::hash(&[b"fabricated-unregistered-anchor"]),
            0,
            operator_key(),
        );
        let alice = &wallets()[0];
        let bob = wallets()[1].public_key();
        let payer = alice.public_key();
        let send = SignedSend::sign_next(&bogus, alice.signer(), bob.clone(), 5, 0).unwrap();
        let invoice = send.tx_id::<Sha256>().into_digest();
        let receipt = crate::protocol::Protocol::new(NonZeroUsize::MIN).unwrap();
        let receipt = SignedReceipt::issue_next::<Sha256, _>(
            &bogus,
            &send,
            &bob,
            0,
            0,
            0,
            receipt.operator(),
        )
        .unwrap();
        let pair = Payment::from_parts_unchecked(send, receipt);

        // Settlement registered a different anchor for epoch 0 than the operator's forgery.
        let registered = crate::protocol::epoch_context(
            0,
            &DepositBatch::empty(),
            &WithdrawalBatch::empty(),
            400,
        )
        .unwrap();
        assert_ne!(registered.payment().anchor(), bogus.anchor());
        let anchor = settlement_rpc::EpochRootsResponse {
            anchor: *registered.payment().anchor(),
            admitted: None,
        };
        let mut settlement_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
            .await
            .unwrap();
        let settlement_address = settlement_listener.local_addr().unwrap();
        let settlement_server = context.child("settlement").spawn(move |_| async move {
            respond_rpc(&mut settlement_listener, |request| {
                assert_eq!(request.method, settlement_rpc::METHOD_EPOCH_ROOTS);
                rpc::Response::Success {
                    body: Some(anchor).encode(),
                }
            })
            .await;
        });

        let mut operator_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
            .await
            .unwrap();
        let operator_address = operator_listener.local_addr().unwrap();
        let operator_server = context.child("operator").spawn(move |_| async move {
            respond(&mut operator_listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::IncomingPayments(_)
                ));
                rpc::Response::Success {
                    body: incoming_response(&[(pair, 1)]).encode(),
                }
            })
            .await;
        });

        let mut bob = Agent::new(1).unwrap();
        bob.intake_incoming(&context, settlement_address, operator_address)
            .await
            .unwrap();

        // The forged pair is not stored, so it never reaches the service-accounting query, and
        // the cursor advanced past it.
        assert_eq!(
            bob.incoming(),
            IncomingSummary {
                total: 0,
                count: 0,
                cursor: 1,
            }
        );
        assert_eq!(bob.paid(&payer, &invoice).unwrap(), None);

        settlement_server.await.unwrap();
        operator_server.await.unwrap();
    });
}

/// Item 2A: one proven challenge invalidates the whole close, so a wallet holding understated
/// receipts in several shards convicts once and stops rather than resubmitting distinct
/// evidence under the same batch and tripping settlement's evidence-replay guard.
#[test]
fn multi_shard_understatement_convicts_once() {
    deterministic::Runner::default().start(|context| async move {
        let fixture = omitting_close();
        let batch_id = admitted_batch(&fixture);
        let change_root = fixture.result.roots.change;
        let lookup = fixture.held_lookup.clone();
        let shard_zero = fixture.held_pair.clone();
        let shard_one = held_in_shard(&fixture, 1);

        let mut settlement = Settlement::new().unwrap();
        admit_omitting(&mut settlement, &fixture);

        let mut settlement_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
            .await
            .unwrap();
        let settlement_address = settlement_listener.local_addr().unwrap();
        let settlement_server = context.child("settlement").spawn(move |_| async move {
            // Intake epoch-roots, reconcile status and epoch-roots, and exactly one challenge.
            for _ in 0..4 {
                respond_rpc(&mut settlement_listener, |request| {
                    settlement_rpc::handle(&mut settlement, request)
                })
                .await;
            }
            settlement.status().unwrap().hard_faulted
        });

        let mut operator_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
            .await
            .unwrap();
        let operator_address = operator_listener.local_addr().unwrap();
        let operator_server = context.child("operator").spawn(move |_| async move {
            respond(&mut operator_listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::IncomingPayments(_)
                ));
                rpc::Response::Success {
                    body: incoming_response(&[(shard_zero, 1), (shard_one, 2)]).encode(),
                }
            })
            .await;

            // Only the first shard is ever fetched: a second committed-shard-tip request would
            // block here forever, so completing proves the loop stopped after one conviction.
            respond(&mut operator_listener, move |request| {
                let operator_rpc::OperatorRequest::CommittedShardTip(request) = request else {
                    panic!("expected a committed shard-tip request");
                };
                assert_eq!(request.shard, 0);
                rpc::Response::Success {
                    body: operator_rpc::CommittedShardTipResponse {
                        batch_id,
                        change_root,
                        lookup,
                    }
                    .encode(),
                }
            })
            .await;
        });

        let mut bob = Agent::new(1).unwrap();
        bob.intake_incoming(&context, settlement_address, operator_address)
            .await
            .unwrap();
        assert_eq!(bob.incoming().count, 2);

        let summary = bob
            .reconcile(&context, settlement_address, operator_address)
            .await
            .unwrap();
        assert_eq!(summary.convicted, [0]);
        assert!(bob.store.unreconciled_incoming_epochs().unwrap().is_empty());
        assert!(settlement_server.await.unwrap());
        operator_server.await.unwrap();
    });
}

/// Item 2B: a decodable tip whose batch and root match the anchor but whose lookup cannot be
/// cryptographically resolved is demoted to a soft per-epoch refusal, not a `?` that aborts
/// the reconcile pass. The epoch stays unreconciled and retries rather than shadowing others.
#[test]
fn unresolvable_lookup_is_a_soft_refusal_not_an_abort() {
    deterministic::Runner::default().start(|context| async move {
        let fixture = omitting_close();
        let batch_id = admitted_batch(&fixture);
        let change_root = fixture.result.roots.change;
        let bob_pair = fixture.held_pair.clone();

        // A lookup built against another close's root: it decodes and is served under the
        // anchored batch and root, but it cannot resolve against this close's change root.
        let mut foreign = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        foreign.pay(0, 1, 5).unwrap();
        foreign.start_close(0).unwrap();
        foreign.wait_for_closes().unwrap();
        let foreign_lookup = foreign
            .committed_shard_tip(&wallets()[1].public_key(), 0, 0)
            .unwrap()
            .lookup;
        assert!(
            foreign_lookup
                .resolve::<Sha256>(&change_root, &wallets()[1].public_key(), 0)
                .is_err()
        );

        let mut settlement = Settlement::new().unwrap();
        admit_omitting(&mut settlement, &fixture);
        let mut settlement_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
            .await
            .unwrap();
        let settlement_address = settlement_listener.local_addr().unwrap();
        let settlement_server = context.child("settlement").spawn(move |_| async move {
            // Intake epoch-roots, then reconcile status and epoch-roots. No challenge is sent.
            for _ in 0..3 {
                respond_rpc(&mut settlement_listener, |request| {
                    settlement_rpc::handle(&mut settlement, request)
                })
                .await;
            }
        });

        let poison_body = operator_rpc::CommittedShardTipResponse {
            batch_id,
            change_root,
            lookup: foreign_lookup,
        }
        .encode();
        let mut operator_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
            .await
            .unwrap();
        let operator_address = operator_listener.local_addr().unwrap();
        let operator_server = context.child("operator").spawn(move |_| async move {
            respond(&mut operator_listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::IncomingPayments(_)
                ));
                rpc::Response::Success {
                    body: incoming_response(&[(bob_pair, 1)]).encode(),
                }
            })
            .await;
            respond(&mut operator_listener, move |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::CommittedShardTip(_)
                ));
                rpc::Response::Success { body: poison_body }
            })
            .await;
        });

        let mut bob = Agent::new(1).unwrap();
        bob.intake_incoming(&context, settlement_address, operator_address)
            .await
            .unwrap();

        // The unresolvable lookup did not abort the pass with an error, and it neither
        // convicted nor reconciled: the epoch stays unreconciled and retries.
        let summary = bob
            .reconcile(&context, settlement_address, operator_address)
            .await
            .unwrap();
        assert!(summary.is_empty());
        assert_eq!(bob.store.unreconciled_incoming_epochs().unwrap(), [0]);
        settlement_server.await.unwrap();
        operator_server.await.unwrap();
    });
}

/// Item 2D: a finalized close that understated a held receipt past the challenge window is an
/// enforcement dead end, recorded loudly rather than silently skipped.
#[test]
fn finalized_understatement_alarms() {
    deterministic::Runner::default().start(|context| async move {
        let fixture = omitting_close();
        let batch_id = admitted_batch(&fixture);
        let change_root = fixture.result.roots.change;
        let lookup = fixture.held_lookup.clone();
        let bob_pair = fixture.held_pair.clone();
        let anchor = *fixture.result.payment_context.anchor();

        let finalized_roots = settlement_rpc::EpochRootsResponse {
            anchor,
            admitted: Some(settlement_rpc::AdmittedRootsResponse {
                batch_id,
                change: change_root,
                finalized: true,
            }),
        };
        let mut settlement_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
            .await
            .unwrap();
        let settlement_address = settlement_listener.local_addr().unwrap();
        let settlement_server = context.child("settlement").spawn(move |_| async move {
            for _ in 0..3 {
                respond_rpc(&mut settlement_listener, |request| match request.method {
                    settlement_rpc::METHOD_STATUS => rpc::Response::Success {
                        body: settlement_status_response().encode(),
                    },
                    settlement_rpc::METHOD_EPOCH_ROOTS => rpc::Response::Success {
                        body: Some(finalized_roots).encode(),
                    },
                    method => panic!("unexpected settlement method {method}"),
                })
                .await;
            }
        });

        let mut operator_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
            .await
            .unwrap();
        let operator_address = operator_listener.local_addr().unwrap();
        let operator_server = context.child("operator").spawn(move |_| async move {
            respond(&mut operator_listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::IncomingPayments(_)
                ));
                rpc::Response::Success {
                    body: incoming_response(&[(bob_pair, 1)]).encode(),
                }
            })
            .await;
            respond(&mut operator_listener, move |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::CommittedShardTip(_)
                ));
                rpc::Response::Success {
                    body: operator_rpc::CommittedShardTipResponse {
                        batch_id,
                        change_root,
                        lookup,
                    }
                    .encode(),
                }
            })
            .await;
        });

        let mut bob = Agent::new(1).unwrap();
        bob.intake_incoming(&context, settlement_address, operator_address)
            .await
            .unwrap();
        let summary = bob
            .reconcile(&context, settlement_address, operator_address)
            .await
            .unwrap();

        // The dead end is loud and terminal: recorded, surfaced, and never reconciled.
        assert_eq!(summary.unenforceable, [0]);
        assert!(summary.reconciled.is_empty() && summary.convicted.is_empty());
        assert!(bob.store.unreconciled_incoming_epochs().unwrap().is_empty());
        assert_eq!(bob.last_reconciled_epoch(), None);
        settlement_server.await.unwrap();
        operator_server.await.unwrap();
    });
}

/// A finalized close whose committed evidence the operator withholds is an alarm, not a silent
/// retry: conviction is no longer possible and coverage cannot be verified, so the dead end is
/// surfaced once per stretch of withholding while the epoch keeps retrying, and it self-heals
/// into a terminal verdict if the evidence is eventually served.
#[test]
fn withheld_evidence_past_finalization_alarms_once() {
    deterministic::Runner::default().start(|context| async move {
        let fixture = omitting_close();
        let batch_id = admitted_batch(&fixture);
        let change_root = fixture.result.roots.change;
        let lookup = fixture.held_lookup.clone();
        let bob_pair = fixture.held_pair.clone();
        let anchor = *fixture.result.payment_context.anchor();

        let finalized_roots = settlement_rpc::EpochRootsResponse {
            anchor,
            admitted: Some(settlement_rpc::AdmittedRootsResponse {
                batch_id,
                change: change_root,
                finalized: true,
            }),
        };
        let mut settlement_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
            .await
            .unwrap();
        let settlement_address = settlement_listener.local_addr().unwrap();
        let settlement_server = context.child("settlement").spawn(move |_| async move {
            // Intake epoch-roots, then status and epoch-roots for each of three reconciles.
            for _ in 0..7 {
                respond_rpc(&mut settlement_listener, |request| match request.method {
                    settlement_rpc::METHOD_STATUS => rpc::Response::Success {
                        body: settlement_status_response().encode(),
                    },
                    settlement_rpc::METHOD_EPOCH_ROOTS => rpc::Response::Success {
                        body: Some(finalized_roots).encode(),
                    },
                    method => panic!("unexpected settlement method {method}"),
                })
                .await;
            }
        });

        let mut operator_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
            .await
            .unwrap();
        let operator_address = operator_listener.local_addr().unwrap();
        let operator_server = context.child("operator").spawn(move |_| async move {
            respond(&mut operator_listener, |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::IncomingPayments(_)
                ));
                rpc::Response::Success {
                    body: incoming_response(&[(bob_pair, 1)]).encode(),
                }
            })
            .await;

            // Two stretches of withholding, then the real served lookup.
            for _ in 0..2 {
                respond(&mut operator_listener, |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::CommittedShardTip(_)
                    ));
                    rpc::Response::Error {
                        error: Bytes::from_static(b"withheld"),
                    }
                })
                .await;
            }
            respond(&mut operator_listener, move |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::CommittedShardTip(_)
                ));
                rpc::Response::Success {
                    body: operator_rpc::CommittedShardTipResponse {
                        batch_id,
                        change_root,
                        lookup,
                    }
                    .encode(),
                }
            })
            .await;
        });

        let mut bob = Agent::new(1).unwrap();
        bob.intake_incoming(&context, settlement_address, operator_address)
            .await
            .unwrap();

        // The first withheld pass alarms, the second is latched, and the epoch keeps retrying.
        let first = bob
            .reconcile(&context, settlement_address, operator_address)
            .await
            .unwrap();
        assert_eq!(first.withheld, [0]);
        assert!(first.reconciled.is_empty() && first.convicted.is_empty());
        assert!(first.unenforceable.is_empty());
        assert_eq!(bob.store.unreconciled_incoming_epochs().unwrap(), [0]);
        let second = bob
            .reconcile(&context, settlement_address, operator_address)
            .await
            .unwrap();
        assert!(second.is_empty());
        assert_eq!(bob.store.unreconciled_incoming_epochs().unwrap(), [0]);

        // Served evidence self-heals the withheld latch into the terminal verdict.
        let third = bob
            .reconcile(&context, settlement_address, operator_address)
            .await
            .unwrap();
        assert_eq!(third.unenforceable, [0]);
        assert!(third.withheld.is_empty());
        assert!(bob.store.unreconciled_incoming_epochs().unwrap().is_empty());
        settlement_server.await.unwrap();
        operator_server.await.unwrap();
    });
}

/// (a) Happy path: pairs are fetched incrementally, verified, persisted, survive restart,
/// and the finalized epoch reconciles cleanly and is durably marked. The committed-side
/// evidence is served by a real operator reconstructing the close from its retained log.
#[test]
fn verified_incoming_reconciles_and_survives_restart() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let mut operator = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN).unwrap();
        operator.pay(0, 1, 5).unwrap();
        operator.pay(0, 1, 3).unwrap();
        operator.start_close(0).unwrap();
        operator.wait_for_closes().unwrap();
        let roots = operator.settlement_roots(0).unwrap();

        // The reconstructed committed-side evidence matches the finalized roots, so the
        // settlement anchor below names the exact close the operator serves lookups for.
        let evidence = operator
            .committed_shard_tip(&wallets()[1].public_key(), 0, 0)
            .unwrap();
        assert_eq!(evidence.change_root, roots.change);
        let anchor_digest = *crate::protocol::epoch_context(
            0,
            &DepositBatch::empty(),
            &WithdrawalBatch::empty(),
            400,
        )
        .unwrap()
        .payment()
        .anchor();

        let mut settlement_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
            .await
            .unwrap();
        let settlement_address = settlement_listener.local_addr().unwrap();
        let mut status = settlement_status_response();
        status.state_root = roots.successor;
        status.last_finalized = Some(0);
        let epoch_roots = settlement_rpc::EpochRootsResponse {
            anchor: anchor_digest,
            admitted: Some(settlement_rpc::AdmittedRootsResponse {
                batch_id: evidence.batch_id,
                change: roots.change,
                finalized: true,
            }),
        };
        let settlement_server = context.child("settlement").spawn(move |_| async move {
            for _ in 0..3 {
                respond_rpc(&mut settlement_listener, |request| match request.method {
                    settlement_rpc::METHOD_STATUS => rpc::Response::Success {
                        body: status.encode(),
                    },
                    settlement_rpc::METHOD_EPOCH_ROOTS => rpc::Response::Success {
                        body: Some(epoch_roots).encode(),
                    },
                    method => panic!("unexpected settlement method {method}"),
                })
                .await;
            }
        });

        let mut operator_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
            .await
            .unwrap();
        let operator_address = operator_listener.local_addr().unwrap();
        let operator_server = context.child("operator").spawn(move |_| async move {
            for _ in 0..3 {
                let (_, mut sink, mut stream) = operator_listener.accept().await.unwrap();
                let request = rpc::recv_request(&mut stream).await.unwrap();
                let request = operator_rpc::decode_request(request).unwrap();
                let response = operator_rpc::handle_decoded(&mut operator, request);
                rpc::send_response(&mut sink, &response).await.unwrap();
            }
        });

        let mut bob = Agent::open(database.path(), 1).unwrap();
        bob.intake_incoming(&context, settlement_address, operator_address)
            .await
            .unwrap();
        let ledger = bob.incoming();
        assert_eq!(ledger.count, 2);
        assert_eq!(ledger.total, 8);
        let cursor = ledger.cursor;

        // A second intake is incremental: nothing new is fetched and the cursor holds.
        bob.intake_incoming(&context, settlement_address, operator_address)
            .await
            .unwrap();
        assert_eq!(bob.incoming(), ledger);
        assert_eq!(bob.incoming().cursor, cursor);

        let summary = bob
            .reconcile(&context, settlement_address, operator_address)
            .await
            .unwrap();
        assert_eq!(summary.reconciled, [0]);
        assert_eq!(bob.last_reconciled_epoch(), Some(0));
        drop(bob);

        // The held pairs, cursor, and reconciled mark all survive a restart.
        let recovered = Agent::open(database.path(), 1).unwrap();
        assert_eq!(recovered.incoming().count, 2);
        assert_eq!(recovered.incoming().total, 8);
        assert_eq!(recovered.incoming().cursor, cursor);
        assert_eq!(recovered.last_reconciled_epoch(), Some(0));
        assert!(
            recovered
                .store
                .unreconciled_incoming_epochs()
                .unwrap()
                .is_empty()
        );

        settlement_server.await.unwrap();
        operator_server.await.unwrap();
    });
}

/// (b) Crash windows: the cursor and pairs are durable before any reliance, and a refetch of
/// the same page is idempotent, so a lost response never duplicates or loses a credit.
#[test]
fn incoming_intake_is_durable_and_refetch_is_idempotent() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let anchor = Sha256::hash(&[b"intake-idempotent"]);
        let context_root = PaymentContext::new(anchor, 4, operator_key());
        let alice = &wallets()[0];
        let bob = wallets()[1].public_key();
        let send = SignedSend::sign_next(&context_root, alice.signer(), bob.clone(), 5, 0).unwrap();
        let receipt = SignedReceipt::issue_next::<Sha256, _>(
            &context_root,
            &send,
            &bob,
            0,
            0,
            0,
            crate::protocol::Protocol::new(NonZeroUsize::MIN)
                .unwrap()
                .operator(),
        )
        .unwrap();
        let pair = Payment::from_parts_unchecked(send, receipt);

        let epoch_roots = settlement_rpc::EpochRootsResponse {
            anchor,
            admitted: None,
        };
        let mut settlement_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
            .await
            .unwrap();
        let settlement_address = settlement_listener.local_addr().unwrap();
        let settlement_server = context.child("settlement").spawn(move |_| async move {
            for _ in 0..2 {
                respond_rpc(&mut settlement_listener, |request| {
                    assert_eq!(request.method, settlement_rpc::METHOD_EPOCH_ROOTS);
                    rpc::Response::Success {
                        body: Some(epoch_roots).encode(),
                    }
                })
                .await;
            }
        });

        let mut operator_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
            .await
            .unwrap();
        let operator_address = operator_listener.local_addr().unwrap();
        let served = pair.clone();
        let operator_server = context.child("operator").spawn(move |_| async move {
            // Both intakes see the same page, standing in for a lost commit that refetches.
            for _ in 0..2 {
                let served = served.clone();
                respond(&mut operator_listener, move |request| {
                    assert!(matches!(
                        request,
                        operator_rpc::OperatorRequest::IncomingPayments(_)
                    ));
                    rpc::Response::Success {
                        body: incoming_response(&[(served, 1)]).encode(),
                    }
                })
                .await;
            }
        });

        let mut bob = Agent::open(database.path(), 1).unwrap();
        bob.intake_incoming(&context, settlement_address, operator_address)
            .await
            .unwrap();
        assert_eq!(bob.incoming().count, 1);
        assert_eq!(bob.incoming().total, 5);
        drop(bob);

        // The pair and cursor are durable before any reliance, so the reopened wallet holds
        // them, and the provider service-accounting query answers from that held evidence.
        let mut recovered = Agent::open(database.path(), 1).unwrap();
        assert_eq!(recovered.incoming().count, 1);
        assert_eq!(recovered.incoming().cursor, 1);
        let credit = recovered
            .paid(
                &alice.public_key(),
                &pair.send().tx_id::<Sha256>().into_digest(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(credit.amount, 5);

        // Refetching the exact page reinserts nothing and leaves the ledger unchanged.
        recovered
            .intake_incoming(&context, settlement_address, operator_address)
            .await
            .unwrap();
        assert_eq!(recovered.incoming().count, 1);
        assert_eq!(recovered.incoming().total, 5);
        settlement_server.await.unwrap();
        operator_server.await.unwrap();
    });
}

/// Item 3: the censorship-fallback exit. When the operator will not carry a signed withdrawal,
/// the wallet escalates the exact retained request and its head opening directly to settlement,
/// where the demo's existing hard-fault recovery releases it.
#[test]
fn signed_withdrawal_escalates_to_settlement() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let mut settlement = Settlement::new().unwrap();
        let genesis = settlement.status().unwrap();
        let account = wallets()[0].public_key();

        let mut agent = Agent::open(database.path(), 0).unwrap();
        let mut settlement_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 1)))
            .await
            .unwrap();
        let settlement_address = settlement_listener.local_addr().unwrap();
        let expected_account = account.clone();
        let settlement_server = context.child("settlement").spawn(move |_| async move {
            let mut queued = None;
            for expected_method in [
                settlement_rpc::METHOD_STATUS,
                settlement_rpc::METHOD_QUEUE_WITHDRAWAL,
            ] {
                respond_rpc(&mut settlement_listener, |request| {
                    assert_eq!(request.method, expected_method);
                    if request.method == settlement_rpc::METHOD_QUEUE_WITHDRAWAL {
                        let request =
                            settlement_rpc::QueueWithdrawalRequest::decode(request.body.clone())
                                .unwrap();
                        assert_eq!(request.request.account(), &expected_account);
                        queued = Some(request.request.body().deadline());
                    }
                    settlement_rpc::handle(&mut settlement, request)
                })
                .await;
            }
            queued
        });

        // A vanished operator: it serves one head opening and then disappears, so the
        // withdrawal application fails and returns Signed with the opening retained.
        let opening = Operator::open(Path::new(":memory:"), NonZeroUsize::MIN)
            .unwrap()
            .withdrawal_opening(&account)
            .unwrap();
        let opening_body = operator_rpc::WithdrawalOpeningResponse {
            root: opening.root,
            opening: opening.opening,
        }
        .encode();
        let mut operator_listener = context
            .bind(SocketAddr::from(([127, 0, 0, 1], 2)))
            .await
            .unwrap();
        let operator_address = operator_listener.local_addr().unwrap();
        let operator_server = context.child("operator").spawn(move |_| async move {
            respond(&mut operator_listener, move |request| {
                assert!(matches!(
                    request,
                    operator_rpc::OperatorRequest::WithdrawalOpening(_)
                ));
                rpc::Response::Success { body: opening_body }
            })
            .await;
        });

        let outcome = agent
            .withdraw(
                &context,
                settlement_address,
                operator_address,
                WithdrawalAction::Amount(NonZeroU64::new(7).unwrap()),
            )
            .await
            .unwrap();
        let WithdrawalOutcome::Signed { request, .. } = outcome else {
            panic!("the vanished operator unexpectedly applied the withdrawal");
        };
        operator_server.await.unwrap();

        // Escalation queues the exact retained request at settlement.
        let escalated = agent
            .escalate_withdrawal(&context, settlement_address)
            .await
            .unwrap();
        assert_eq!(escalated, request);

        // The claim slot opens durably: the operator may have applied the request and lost only
        // the response, and the carried claim must stay recoverable across a restart.
        assert!(agent.pending_withdrawal_claim.is_some());
        drop(agent);
        let reopened = Agent::open(database.path(), 0).unwrap();
        assert!(reopened.pending_withdrawal_claim.is_some());

        let queued_deadline = settlement_server.await.unwrap().unwrap();
        assert_eq!(queued_deadline, request.body().deadline());
        assert_eq!(genesis.state_root.digest, *request.body().state_root());
    });
}

/// (d) Payer regression guard: the provider intake and reconciliation are additive. A wallet
/// holding no incoming credits touches neither operator nor settlement during reconciliation,
/// and the empty provider ledger survives the schema across a restart.
#[test]
fn payer_flow_is_unaffected_by_provider_state() {
    deterministic::Runner::default().start(|context| async move {
        let database = TempDatabase::new();
        let payer = Agent::open(database.path(), 0).unwrap();
        assert_eq!(payer.incoming(), IncomingSummary::default());
        assert_eq!(payer.last_reconciled_epoch(), None);
        drop(payer);

        // Reconciliation with no held credits is a pure no-op: the unreachable operator and
        // settlement are never dialed, so the payer path can never be gated by it.
        let mut payer = Agent::open(database.path(), 0).unwrap();
        let summary = payer
            .reconcile(
                &context,
                SocketAddr::from(([127, 0, 0, 1], 1)),
                SocketAddr::from(([127, 0, 0, 1], 2)),
            )
            .await
            .unwrap();
        assert!(summary.is_empty());
        assert_eq!(payer.incoming(), IncomingSummary::default());
        assert_eq!(payer.last_reconciled_epoch(), None);
        drop(payer);

        // The additive schema leaves the reopened payer's empty provider ledger intact.
        let recovered = Agent::open(database.path(), 0).unwrap();
        assert_eq!(recovered.incoming(), IncomingSummary::default());
        assert_eq!(recovered.last_reconciled_epoch(), None);
    });
}
