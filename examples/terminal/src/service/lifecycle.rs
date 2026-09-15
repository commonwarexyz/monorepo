//! Native lifecycle trace execution over the service, SQLite operator, and certified chain.

use super::*;
use crate::{
    chain::{
        harness,
        ingress::Submission,
        light::Verified,
        query::{
            Evidence, EvidenceBody, EvidenceLookup, EvidenceRequest, EvidenceResponse, ReadRequest,
        },
        state::StatusRecord,
        tx::QueueWithdrawalRequest,
    },
    protocol::{Key, SettlementResult, deployment, wallets},
    withdrawal_model::{
        self as model, Acknowledgement, Action, Instance, Outcome, OutputId, PacketId, Projection,
        ReadKind, ReadPhase, RequestId, Trace, TransferId, Withdrawal,
    },
};
use commonware_clearing::bajillion::{
    boundary::{SignedWithdrawal, WithdrawalAction},
    qmdb::{StateLookup, StateOpening, account_key},
};
use commonware_runtime::deterministic;
use commonware_utils::channel::{mpsc, oneshot};
use std::{
    collections::BTreeMap,
    fs,
    sync::atomic::{AtomicU64, Ordering},
};

const ADDRESS: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 9_702);
static DATABASE_ID: AtomicU64 = AtomicU64::new(0);
const TIMING: Timing = Timing {
    admission_offset: 64,
    challenge_duration: 1,
};
const REGISTRATION_SPACING: u64 = 16;

struct Database(PathBuf);

impl Database {
    fn new() -> Self {
        let id = DATABASE_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "commonware-terminal-lifecycle-{}-{id}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn open(&self) -> Operator {
        Operator::open(&self.0.join("operator.sqlite"), NonZeroUsize::MIN).unwrap()
    }
}

impl Drop for Database {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

enum ReadEvent {
    Requested {
        lookup: Lookup,
        capture: oneshot::Sender<()>,
    },
    Captured {
        lookup: Lookup,
        verified: Box<Verified>,
        deliver: oneshot::Sender<()>,
    },
    Finished(Result<(), String>),
}

/// Both gates surround a real authenticated client read. Delivery cannot replace its value.
struct GatedChain {
    client: Client,
    events: mpsc::Sender<ReadEvent>,
}

impl GatedChain {
    async fn capture(&mut self, lookup: &Lookup) -> Result<()> {
        ensure!(
            matches!(
                lookup,
                Lookup::Status | Lookup::Withdrawal { .. } | Lookup::Anchor { .. }
            ),
            "unexpected reconciliation lookup: {lookup:?}"
        );
        let (capture, permit) = oneshot::channel();
        self.events
            .send(ReadEvent::Requested {
                lookup: lookup.clone(),
                capture,
            })
            .await?;
        permit.await.context("capture gate canceled")
    }

    async fn deliver(&mut self, lookup: &Lookup, verified: Verified) -> Result<Verified> {
        let (deliver, permit) = oneshot::channel();
        self.events
            .send(ReadEvent::Captured {
                lookup: lookup.clone(),
                verified: Box::new(verified.clone()),
                deliver,
            })
            .await?;
        permit.await.context("delivery gate canceled")?;
        Ok(verified)
    }
}

impl Chain for GatedChain {
    fn deployment(&self) -> Digest {
        self.client.deployment()
    }
    fn holders(&self) -> Result<Vec<SocketAddr>> {
        self.client.holders()
    }

    async fn read<E: Env>(&mut self, ctx: &E, request: &ReadRequest) -> Result<Verified> {
        self.capture(&request.lookup).await?;
        let verified = self.client.read(ctx, request).await?;
        self.deliver(&request.lookup, verified).await
    }

    async fn recent<E: Env>(&mut self, ctx: &E, request: &ReadRequest) -> Result<Verified> {
        self.capture(&request.lookup).await?;
        let verified = self.client.recent(ctx, request).await?;
        self.deliver(&request.lookup, verified).await
    }

    async fn submit<E: Env>(&mut self, ctx: &E, tx: &SettlementTx) -> Result<Submission> {
        self.client.submit(ctx, tx).await
    }
}

struct Reconciliation {
    task: Handle<()>,
    events: mpsc::Receiver<ReadEvent>,
}

struct Native {
    operator: Option<Arc<Mutex<Operator>>>,
    control: harness::Control,
    reconciliation: Option<Reconciliation>,
    event: Option<ReadEvent>,
    database: Database,
    requests: [Option<SavedRequest>; 3],
    packets: BTreeMap<PacketId, RegisterEpochRequest>,
    closes: Vec<SettlementResult>,
    payments: [Option<operator_rpc::AcceptSendRequest>; 2],
}

struct SavedRequest {
    request: SignedWithdrawal<Key, Digest>,
    opening: StateOpening<Key, Digest>,
}

impl Native {
    async fn new(context: &deterministic::Context) -> Self {
        let database = Database::new();
        Self {
            operator: Some(Arc::new(Mutex::new(database.open()))),
            control: harness::start_with_native(
                context,
                ADDRESS,
                "lifecycle",
                harness::native(crate::protocol::deployments()),
                TIMING,
            )
            .await,
            reconciliation: None,
            event: None,
            database,
            requests: std::array::from_fn(|_| None),
            packets: BTreeMap::new(),
            closes: Vec::new(),
            payments: [None, None],
        }
    }

    fn client(&self, context: &deterministic::Context) -> Client {
        Client::new(
            self.control.identity(),
            deployment(),
            vec![ADDRESS],
            context.child("client_rng"),
        )
        .unwrap()
    }

    fn operator(&self) -> &Arc<Mutex<Operator>> {
        self.operator.as_ref().unwrap()
    }

    async fn status(&mut self, context: &deterministic::Context) -> StatusRecord {
        self.client(context).recent_status(context).await.unwrap()
    }

    async fn sign(
        &mut self,
        context: &deterministic::Context,
        slot: usize,
        account: usize,
        action: WithdrawalAction,
    ) -> Result<()> {
        ensure!(
            self.requests[slot].is_none(),
            "request slot is already signed"
        );
        let wallet = wallets().remove(account);
        let status = self.status(context).await;
        let lookup = match status.last_finalized {
            Some(epoch) => {
                let admitted = self
                    .client(context)
                    .admitted(context, epoch)
                    .await?
                    .context("finalized admission is missing")?;
                EvidenceLookup::SuccessorState {
                    batch: admitted.batch_id.into_digest(),
                    account: wallet.public_key(),
                }
            }
            None => EvidenceLookup::GenesisState {
                account: wallet.public_key(),
            },
        };
        let evidence = self
            .control
            .evidence(EvidenceRequest::new(deployment(), lookup))
            .await;
        let opening = match evidence {
            EvidenceResponse::Served(Evidence::Genesis(opening))
            | EvidenceResponse::Served(Evidence::Close {
                body: EvidenceBody::State(opening),
                ..
            }) => opening,
            _ => bail!("signing account has no finalized membership"),
        };
        opening.verify::<Sha256>(&status.state_root)?;
        let deadline = status.height
            + crate::protocol::settlement_config(&TIMING)?
                .maximum_withdrawal_notice
                .get();
        let request = SignedWithdrawal::sign(
            deployment(),
            status.state_root.digest,
            wallet.public_key().encode(),
            action,
            deadline,
            wallet.signer(),
        );
        self.requests[slot] = Some(SavedRequest { request, opening });
        Ok(())
    }

    async fn queue(&mut self, slot: usize) -> Result<()> {
        let saved = self.requests[slot]
            .as_ref()
            .context("request is unsigned")?;
        self.control
            .submit(SettlementTx::QueueWithdrawal(QueueWithdrawalRequest {
                request: saved.request.clone(),
                opening: saved.opening.clone(),
            }))
            .await;
        Ok(())
    }

    async fn apply(
        &mut self,
        context: &deterministic::Context,
        slot: usize,
    ) -> Result<rpc::Response> {
        let saved = self.requests[slot]
            .as_ref()
            .context("request is unsigned")?;
        let request =
            operator_rpc::OperatorRequest::ApplyWithdrawal(operator_rpc::ApplyWithdrawalRequest {
                request: saved.request.clone(),
            });
        let response = prepare_request(
            context,
            &mut self.client(context),
            self.operator(),
            &request,
            TIMING,
        )
        .await?;
        Ok(response
            .unwrap_or_else(|| operator_rpc::handle_decoded(&mut self.operator().lock(), request)))
    }

    async fn freeze(&mut self, context: &deterministic::Context) -> Result<PacketId> {
        let epoch = self.operator().lock().registration_boundary()?.0.epoch();
        let request =
            registration_request(context, &mut self.client(context), self.operator(), epoch)
                .await?;
        let requests = self.request_mask(&request.withdrawals)?;
        let queued = request
            .withdrawals
            .requests()
            .iter()
            .filter(|withdrawal| {
                !request
                    .openings
                    .iter()
                    .any(|opening| opening.account == *withdrawal.account())
            })
            .try_fold(0, |mask, request| {
                Ok::<_, anyhow::Error>(mask | self.request_id(request)?.bit())
            })?;
        let id = PacketId {
            epoch: epoch.try_into()?,
            requests,
            queued,
        };
        self.packets.insert(id, request);
        Ok(id)
    }

    async fn publish(&mut self, context: &deterministic::Context, packet: PacketId) -> Result<()> {
        if let Some(previous) = self.client(context).registration(context).await?
            && previous.epoch + 1 == u64::from(packet.epoch)
        {
            // Separate live leases so finalizing the predecessor leaves room to admit
            // its successor. Every intervening empty block still executes native state.
            let earliest = previous
                .challenge_deadline
                .checked_add(REGISTRATION_SPACING)
                .context("registration schedule exceeds the clock")?
                .saturating_sub(TIMING.admission_offset);
            let current = self.status(context).await.height;
            if current < earliest {
                self.control.advance(earliest - current).await;
            }
        }
        let request = self
            .packets
            .get(&packet)
            .context("registration packet is unavailable")?;
        self.control
            .submit(SettlementTx::RegisterEpoch(request.clone()))
            .await;
        Ok(())
    }

    async fn adopt(&mut self, context: &deterministic::Context) -> Result<()> {
        let registered = self
            .client(context)
            .registration(context)
            .await?
            .context("registration is absent")?;
        self.operator().lock().adopt_registration(&registered)
    }

    fn cut(&mut self) -> Result<()> {
        let close = self
            .operator()
            .lock()
            .complete_close(self.closes.len() as u64 + 1)?;
        self.closes.push(close);
        Ok(())
    }

    async fn admit(&mut self, epoch: usize) -> Result<()> {
        let close = self.closes.get(epoch).context("close is unavailable")?;
        self.control
            .submit(SettlementTx::Admit(crate::chain::tx::AdmitRequest::from(
                close,
            )))
            .await;
        Ok(())
    }

    fn start_reconcile(&mut self, context: &deterministic::Context) {
        assert!(self.reconciliation.is_none());
        let (events, receiver) = mpsc::channel(1);
        let mut chain = GatedChain {
            client: self.client(context),
            events: events.clone(),
        };
        let operator = self.operator().clone();
        let task = context.child("reconcile").spawn(move |context| async move {
            let result = reconcile_withdrawals(&context, &mut chain, &operator)
                .await
                .map_err(|error| format!("{error:#}"));
            let _ = events.send(ReadEvent::Finished(result)).await;
        });
        self.reconciliation = Some(Reconciliation {
            task,
            events: receiver,
        });
    }

    async fn next_read_event(&mut self) -> ReadEvent {
        self.reconciliation
            .as_mut()
            .unwrap()
            .events
            .recv()
            .await
            .expect("reconciliation event")
    }

    async fn restart(&mut self) {
        // Await cancellation before releasing the authoritative SQL owner.
        if let Some(reconciliation) = self.reconciliation.take() {
            reconciliation.task.abort();
            let _ = reconciliation.task.await;
        }
        self.event = None;
        let previous = self.operator.take().unwrap();
        assert_eq!(Arc::strong_count(&previous), 1);
        drop(previous);
        self.operator = Some(Arc::new(Mutex::new(self.database.open())));
    }

    fn request_id(&self, request: &SignedWithdrawal<Key, Digest>) -> Result<RequestId> {
        RequestId::ALL
            .into_iter()
            .find(|id| {
                self.requests[id.index()]
                    .as_ref()
                    .is_some_and(|saved| saved.request == *request)
            })
            .context("runtime withdrawal is outside the signed trace catalog")
    }

    fn request_mask(&self, requests: &WithdrawalBatch<Key, Digest>) -> Result<u8> {
        requests.requests().iter().try_fold(0, |mask, request| {
            Ok(mask | self.request_id(request)?.bit())
        })
    }

    fn read_kind(lookup: &Lookup) -> ReadKind {
        match lookup {
            Lookup::Status => ReadKind::Status,
            Lookup::Anchor { epoch } => ReadKind::Anchor((*epoch).try_into().unwrap()),
            Lookup::Withdrawal { account } => ReadKind::Withdrawal(
                wallets()
                    .iter()
                    .position(|wallet| wallet.public_key() == *account)
                    .unwrap(),
            ),
            _ => panic!("unexpected reconciliation read"),
        }
    }

    async fn receive_event(&mut self) -> Outcome {
        let event = self.next_read_event().await;
        let outcome = match &event {
            ReadEvent::Requested { lookup, .. } => {
                Outcome::Awaiting(Self::read_kind(lookup), ReadPhase::Requested)
            }
            ReadEvent::Captured { lookup, .. } => {
                Outcome::Awaiting(Self::read_kind(lookup), ReadPhase::Captured)
            }
            ReadEvent::Finished(result) => {
                let outcome = if result.is_ok() {
                    Outcome::Accepted
                } else {
                    Outcome::Rejected
                };
                let reconciliation = self.reconciliation.take().unwrap();
                reconciliation.task.await.unwrap();
                self.event = None;
                return outcome;
            }
        };
        self.event = Some(event);
        outcome
    }

    fn claim(&self, output: OutputId) -> Result<operator_rpc::AcknowledgeWithdrawalRequest> {
        let close = self
            .closes
            .get(usize::from(output.epoch))
            .context("claim close is unavailable")?;
        let account = wallets().remove(output.account).public_key();
        let position = close
            .withdrawals
            .requests()
            .iter()
            .position(|request| request.account() == &account)
            .context("claim account has no withdrawal output")?;
        Ok(operator_rpc::AcknowledgeWithdrawalRequest {
            batch_id: close.header.batch_id::<Sha256>(),
            account,
            claim: close.withdrawal_claims[position].clone(),
        })
    }

    async fn execute(
        &mut self,
        context: &deterministic::Context,
        instance: Instance,
        action: Action,
    ) -> Result<Outcome> {
        let outcome = match action {
            Action::Sign(id) => {
                if self.requests[id.index()].is_some() {
                    return Ok(Outcome::Unchanged);
                }
                let action = match instance.withdrawal(id) {
                    Withdrawal::Amount(amount) => {
                        WithdrawalAction::Amount(std::num::NonZeroU64::new(amount).unwrap())
                    }
                    Withdrawal::Close => WithdrawalAction::Close,
                };
                self.sign(context, id.index(), id.account(), action).await?;
                Outcome::Accepted
            }
            Action::Queue(id) => {
                let key = wallets().remove(id.account()).public_key();
                let before = self
                    .client(context)
                    .withdrawal(context, key.clone())
                    .await?;
                self.queue(id.index()).await?;
                let after = self.client(context).withdrawal(context, key).await?;
                if after.as_ref()
                    == self.requests[id.index()]
                        .as_ref()
                        .map(|saved| &saved.request)
                {
                    if before == after {
                        Outcome::Unchanged
                    } else {
                        Outcome::Accepted
                    }
                } else {
                    Outcome::Rejected
                }
            }
            Action::Apply(id) => {
                let response = self.apply(context, id.index()).await?;
                if matches!(response, rpc::Response::Success { .. }) {
                    let saved = self.requests[id.index()].as_ref().unwrap();
                    let acknowledgment = self
                        .operator()
                        .lock()
                        .staged_withdrawal(&saved.request)?
                        .context("successful application has no durable acknowledgment")?;
                    Outcome::Acknowledged(Acknowledgement {
                        epoch: acknowledgment.epoch.try_into()?,
                        request: id,
                    })
                } else {
                    Outcome::Rejected
                }
            }
            Action::Freeze => {
                let packets = self.packets.len();
                self.freeze(context).await?;
                if self.packets.len() == packets {
                    Outcome::Unchanged
                } else {
                    Outcome::Accepted
                }
            }
            Action::Publish(packet) => {
                let lookup = self.client(context).request(Lookup::Anchor {
                    epoch: u64::from(packet.epoch),
                });
                let before = self.client(context).recent(context, &lookup).await?.record;
                self.publish(context, packet).await?;
                let after = self.client(context).recent(context, &lookup).await?.record;
                let accepted = self.project(context).await?.anchors[usize::from(packet.epoch)]
                    == Some(PacketId {
                        queued: 0,
                        ..packet
                    });
                if accepted {
                    if before.is_some() && before == after {
                        Outcome::Unchanged
                    } else {
                        Outcome::Accepted
                    }
                } else {
                    Outcome::Rejected
                }
            }
            Action::ObserveRegistration => {
                let before = self.operator().lock().registration_boundary()?.0;
                self.adopt(context).await?;
                if self.operator().lock().registration_boundary()?.0 == before {
                    Outcome::Unchanged
                } else {
                    Outcome::Accepted
                }
            }
            Action::Pay(transfer) => {
                let (index, payer, receiver, amount) = match transfer {
                    TransferId::Debit => (0, 0, 1, instance.debit),
                    TransferId::Credit => (1, 1, 0, instance.credit),
                };
                if amount == 0 {
                    return Ok(Outcome::Unchanged);
                }
                let replay = self.payments[index].is_some();
                let request = match &self.payments[index] {
                    Some(request) => request.clone(),
                    None => {
                        let (authorization, entries) = self.operator().lock().sign_send(
                            payer,
                            &[(wallets().remove(receiver).public_key(), amount)],
                        )?;
                        operator_rpc::AcceptSendRequest {
                            authorization,
                            entries,
                        }
                    }
                };
                let response = operator_rpc::handle_decoded(
                    &mut self.operator().lock(),
                    operator_rpc::OperatorRequest::AcceptSend(request.clone()),
                );
                match response {
                    rpc::Response::Success { body }
                        if matches!(
                            operator_rpc::AcceptSendResponse::decode(body.clone())?,
                            operator_rpc::AcceptSendResponse::Accepted(_)
                        ) =>
                    {
                        self.payments[index] = Some(request);
                        if replay {
                            Outcome::Unchanged
                        } else {
                            Outcome::Accepted
                        }
                    }
                    _ => Outcome::Rejected,
                }
            }
            Action::Cut => {
                self.cut()?;
                Outcome::Accepted
            }
            Action::Admit(epoch) => {
                let before = self
                    .client(context)
                    .admitted(context, u64::from(epoch))
                    .await?;
                self.admit(usize::from(epoch)).await?;
                let after = self
                    .client(context)
                    .admitted(context, u64::from(epoch))
                    .await?;
                if before.is_some() && before == after {
                    Outcome::Unchanged
                } else if after.is_some() {
                    Outcome::Accepted
                } else {
                    Outcome::Rejected
                }
            }
            Action::Finalize => {
                let before = self.status(context).await;
                let target = self
                    .closes
                    .iter()
                    .filter(|close| {
                        before
                            .last_finalized
                            .is_none_or(|last| close.context.payment().epoch() > last)
                    })
                    .map(|close| close.context.challenge_deadline() + 1)
                    .min()
                    .context("no pending close to finalize")?;
                if before.height < target {
                    self.control.advance(target - before.height).await;
                }
                if self.status(context).await.last_finalized == before.last_finalized {
                    Outcome::Unchanged
                } else {
                    Outcome::Accepted
                }
            }
            Action::StartReconcile => {
                if self.reconciliation.is_some() {
                    return Ok(Outcome::Rejected);
                }
                self.start_reconcile(context);
                self.receive_event().await
            }
            Action::CaptureRead => {
                ensure!(
                    matches!(self.event, Some(ReadEvent::Requested { .. })),
                    "capture without requested read"
                );
                let Some(ReadEvent::Requested { capture, .. }) = self.event.take() else {
                    bail!("capture without requested read");
                };
                capture
                    .send(())
                    .map_err(|_| anyhow::anyhow!("capture gate was canceled"))?;
                self.receive_event().await
            }
            Action::DeliverRead => {
                ensure!(
                    matches!(self.event, Some(ReadEvent::Captured { .. })),
                    "delivery without captured read"
                );
                let Some(ReadEvent::Captured { deliver, .. }) = self.event.take() else {
                    bail!("delivery without captured read");
                };
                deliver
                    .send(())
                    .map_err(|_| anyhow::anyhow!("delivery gate was canceled"))?;
                self.receive_event().await
            }
            Action::Restart => {
                self.restart().await;
                Outcome::Accepted
            }
            Action::Claim(output) => {
                let claim = self.claim(output)?;
                let before = self
                    .client(context)
                    .withdrawal_release(context, claim.batch_id, claim.claim.position())
                    .await?;
                self.control
                    .submit(SettlementTx::ClaimWithdrawal(
                        crate::chain::tx::WithdrawalClaimRequest {
                            deployment: deployment(),
                            batch_id: claim.batch_id,
                            claim: claim.claim.clone(),
                        },
                    ))
                    .await;
                let after = self
                    .client(context)
                    .withdrawal_release(context, claim.batch_id, claim.claim.position())
                    .await?;
                if before.is_some() && before == after {
                    Outcome::Unchanged
                } else if after.is_some() {
                    Outcome::Accepted
                } else {
                    Outcome::Rejected
                }
            }
            Action::Acknowledge(output) => {
                let request = operator_rpc::OperatorRequest::AcknowledgeWithdrawal(Box::new(
                    self.claim(output)?,
                ));
                let response = prepare_request(
                    context,
                    &mut self.client(context),
                    self.operator(),
                    &request,
                    TIMING,
                )
                .await?;
                if response
                    .is_some_and(|response| matches!(response, rpc::Response::Success { .. }))
                {
                    Outcome::Accepted
                } else {
                    Outcome::Rejected
                }
            }
        };
        Ok(outcome)
    }

    async fn project(&mut self, context: &deterministic::Context) -> Result<Projection> {
        let snapshot = self.operator().lock().snapshot()?;
        let (payment, withdrawals) = self.operator().lock().registration_boundary()?;
        let wallets = wallets();
        let mut balances = [0; model::ACCOUNTS];
        let mut present = [false; model::ACCOUNTS];
        let mut boundary = [None; model::ACCOUNTS];
        for account in 0..model::ACCOUNTS {
            let stored = snapshot
                .accounts
                .iter()
                .find(|stored| stored.name == wallets[account].name)
                .context("snapshot lacks trace account")?;
            balances[account] = stored.balance;
            present[account] = stored.present;
            boundary[account] = withdrawals
                .request_for(&wallets[account].public_key())
                .map(|request| self.request_id(request))
                .transpose()?;
        }
        let mut acknowledgements = [None; model::REQUESTS];
        for id in RequestId::ALL {
            if let Some(saved) = &self.requests[id.index()]
                && let Ok(Some(acknowledgment)) =
                    self.operator().lock().staged_withdrawal(&saved.request)
            {
                acknowledgements[id.index()] = Some(Acknowledgement {
                    epoch: acknowledgment.epoch.try_into()?,
                    request: id,
                });
            }
        }
        let mut chain = self.client(context);
        let status = chain.recent_status(context).await?;
        ensure!(
            !status.hard_faulted,
            "trace left the timely lease domain at height {}",
            status.height
        );
        let registered = chain.registration(context).await?;
        let mut receipts = [None; model::ACCOUNTS];
        for account in 0..model::ACCOUNTS {
            receipts[account] = chain
                .withdrawal(context, wallets[account].public_key())
                .await?
                .as_ref()
                .map(|request| self.request_id(request))
                .transpose()?;
        }
        let mut anchors = [None; model::EPOCHS];
        let mut admitted = [false; model::EPOCHS];
        let mut adopted = false;
        for epoch in 0..model::EPOCHS {
            let lookup = chain.request(Lookup::Anchor {
                epoch: epoch as u64,
            });
            match chain.recent(context, &lookup).await?.record {
                Some(Record::Anchor(anchor)) => {
                    if payment.epoch() == epoch as u64 {
                        adopted = payment.anchor() == &anchor;
                    }
                    let requests = if let Some(close) = self.closes.get(epoch) {
                        ensure!(
                            close.context.payment().anchor() == &anchor,
                            "stored close differs from permanent native anchor"
                        );
                        self.request_mask(&close.withdrawals)?
                    } else {
                        let registered = registered
                            .as_ref()
                            .filter(|record| {
                                record.epoch == epoch as u64 && record.anchor == anchor
                            })
                            .context("uncut native anchor has no current registration")?;
                        let request = self
                            .packets
                            .values()
                            .find(|request| {
                                request.epoch == epoch as u64
                                    && request
                                        .withdrawals
                                        .root::<Sha256>()
                                        .is_ok_and(|root| root == registered.withdrawals_root)
                            })
                            .context("native registration differs from every delivered packet")?;
                        self.request_mask(&request.withdrawals)?
                    };
                    anchors[epoch] = Some(PacketId {
                        epoch: epoch.try_into()?,
                        requests,
                        queued: 0,
                    });
                }
                None => {}
                Some(_) => bail!("native anchor lookup has another record type"),
            }
            admitted[epoch] = chain.admitted(context, epoch as u64).await?.is_some();
        }
        let mut outputs = [[None; model::ACCOUNTS]; model::EPOCHS];
        let mut released = [[None; model::ACCOUNTS]; model::EPOCHS];
        let mut claim_head = [None; model::ACCOUNTS];
        for account in 0..model::ACCOUNTS {
            match self
                .operator()
                .lock()
                .withdrawal_evidence(&wallets[account].public_key())
            {
                Ok(evidence) => {
                    claim_head[account] = Some(OutputId {
                        epoch: evidence.witness.context.payment().epoch().try_into()?,
                        account,
                    });
                }
                Err(error)
                    if error.to_string()
                        == "there is no finalized withdrawal claim for this account" => {}
                Err(error) => return Err(error),
            }
        }
        for close in &self.closes {
            let epoch: usize = close.context.payment().epoch().try_into()?;
            for (request, claim) in close
                .withdrawals
                .requests()
                .iter()
                .zip(&close.withdrawal_claims)
            {
                let account = wallets
                    .iter()
                    .position(|wallet| wallet.public_key() == *request.account())
                    .unwrap();
                outputs[epoch][account] = Some(
                    claim
                        .verify::<Sha256>(&close.roots.withdrawal_outputs)?
                        .amount(),
                );
                if let Some(release) = chain
                    .withdrawal_release(
                        context,
                        close.header.batch_id::<Sha256>(),
                        claim.position(),
                    )
                    .await?
                {
                    ensure!(
                        release.claim == Sha256::hash(&[&claim.encode()]),
                        "released claim differs from retained output"
                    );
                    released[epoch][account] = Some(release.released.amount);
                }
            }
        }
        let mut finalized_balances = [0; model::ACCOUNTS];
        for account in 0..model::ACCOUNTS {
            let key = wallets[account].public_key();
            let lookup = match status.last_finalized {
                Some(epoch) => {
                    let close = chain
                        .admitted(context, epoch)
                        .await?
                        .context("finalized close is absent")?;
                    ensure!(
                        close.roots.successor == status.state_root,
                        "status root differs from finalized admission"
                    );
                    EvidenceLookup::SuccessorState {
                        batch: close.batch_id.into_digest(),
                        account: key.clone(),
                    }
                }
                None => EvidenceLookup::GenesisState {
                    account: key.clone(),
                },
            };
            finalized_balances[account] = match self
                .control
                .evidence(EvidenceRequest::new(deployment(), lookup))
                .await
            {
                EvidenceResponse::Served(Evidence::Genesis(opening))
                | EvidenceResponse::Served(Evidence::Close {
                    body: EvidenceBody::State(opening),
                    ..
                }) => {
                    ensure!(
                        opening.account == key,
                        "finalized proof is for another account"
                    );
                    opening.verify::<Sha256>(&status.state_root)?.get()
                }
                EvidenceResponse::Served(Evidence::GenesisAbsent(proof))
                | EvidenceResponse::Served(Evidence::Close {
                    body: EvidenceBody::StateAbsent(proof),
                    ..
                }) => {
                    ensure!(
                        StateLookup::Absent(proof)
                            .resolve::<Sha256>(&status.state_root, &account_key(&key)?)?
                            .is_none(),
                        "absence proof returned a balance"
                    );
                    0
                }
                _ => bail!("validator did not serve finalized state evidence"),
            };
        }
        let read = match &self.event {
            Some(ReadEvent::Requested { lookup, .. }) => {
                Some((Self::read_kind(lookup), ReadPhase::Requested))
            }
            Some(ReadEvent::Captured { lookup, .. }) => {
                Some((Self::read_kind(lookup), ReadPhase::Captured))
            }
            Some(ReadEvent::Finished(_)) | None => None,
        };
        Ok(Projection {
            epoch: snapshot.epoch.try_into()?,
            balances,
            present,
            boundary,
            frozen: self.operator().lock().withdrawals_frozen()?,
            adopted,
            acknowledgements,
            receipts,
            anchors,
            admitted,
            finalized: status.last_finalized.map(u8::try_from).transpose()?,
            root: status
                .last_finalized
                .map_or(0, |epoch| u8::try_from(epoch + 1).unwrap()),
            finalized_balances,
            outputs,
            released,
            claim_head,
            custody: status.custody,
            claimable: status.claimable,
            read,
        })
    }
}

async fn replay(context: &deterministic::Context, trace: Trace) {
    let model = model::WithdrawalModel::new(trace.instance);
    let mut expected = model.initial_state();
    let mut native = Native::new(context).await;
    assert_eq!(
        native.project(context).await.unwrap(),
        model.projection(&expected),
        "{} initial state",
        trace.name
    );
    for (index, action) in trace.actions.iter().copied().enumerate() {
        let transition = model.step(&expected, action);
        let observed = native
            .execute(context, trace.instance, action)
            .await
            .unwrap_or_else(|error| panic!("{} step {index}: {action:?}: {error:#}", trace.name));
        assert_eq!(
            observed, transition.outcome,
            "{} step {index}: {action:?}",
            trace.name
        );
        assert_eq!(
            native.project(context).await.unwrap(),
            model.projection(&transition.state),
            "{} step {index}: {action:?}",
            trace.name
        );
        expected = transition.state;
    }
    native.restart().await;
}

#[test]
fn generated_withdrawal_lifecycle_traces_match_native_service() {
    let traces = model::WithdrawalModel::generated_traces();
    println!(
        "replaying {} native traces containing {} actions",
        traces.len(),
        traces
            .iter()
            .map(|trace| trace.actions.len())
            .sum::<usize>()
    );
    for trace in traces {
        deterministic::Runner::timed(Duration::from_secs(60)).start(move |context| async move {
            replay(&context, trace).await;
        });
    }
}

#[test]
fn restart_cancels_a_captured_certified_read_before_reopening_sql() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
        let mut native = Native::new(&context).await;
        let wallet = wallets().remove(0);
        let opening = native
            .operator()
            .lock()
            .withdrawal_opening(&wallet.public_key())
            .unwrap();
        let request = SignedWithdrawal::sign(
            deployment(),
            opening.root.digest,
            wallet.public_key().encode(),
            WithdrawalAction::Close,
            100,
            wallet.signer(),
        );
        let acknowledgment = native
            .operator()
            .lock()
            .apply_withdrawal(request.clone(), false)
            .unwrap();
        native.start_reconcile(&context);
        let ReadEvent::Requested { lookup, capture } = native.next_read_event().await else {
            panic!("expected pending status read");
        };
        assert_eq!(lookup, Lookup::Status);
        capture.send(()).unwrap();
        let ReadEvent::Captured {
            lookup,
            verified,
            deliver,
        } = native.next_read_event().await
        else {
            panic!("expected captured status read");
        };
        assert_eq!(lookup, Lookup::Status);
        assert!(matches!(verified.record, Some(Record::Status(_))));
        native.restart().await;
        assert!(deliver.send(()).is_err());
        let replay = native
            .operator()
            .lock()
            .staged_withdrawal(&request)
            .unwrap()
            .unwrap();
        assert_eq!(replay.epoch, acknowledgment.epoch);
        assert_eq!(replay.action, acknowledgment.action);

        native.start_reconcile(&context);
        loop {
            match native.next_read_event().await {
                ReadEvent::Requested { capture, .. } => capture.send(()).unwrap(),
                ReadEvent::Captured { deliver, .. } => deliver.send(()).unwrap(),
                ReadEvent::Finished(result) => {
                    result.unwrap();
                    break;
                }
            }
        }
        native.restart().await;
        assert!(
            native
                .operator()
                .lock()
                .staged_withdrawal(&request)
                .unwrap()
                .is_some()
        );
    });
}
