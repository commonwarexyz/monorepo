//! Native lifecycle trace execution over the service, SQLite operator, and certified chain.

use super::*;
use crate::{
    chain::{
        harness,
        ingress::Submission,
        light::Verified,
        query::{Evidence, EvidenceLookup, EvidenceRequest, EvidenceResponse, ReadRequest},
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
    logs::{LogHead, PayoutOperation},
    qmdb::{StateLookup, StateOpening, account_key},
    transition::{WithdrawalClaim, WithdrawalOutput},
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
    published: [Option<PublishedPacket>; model::EPOCHS],
    closes: Vec<SettlementResult>,
    payments: [Option<operator_rpc::AcceptSendRequest>; 2],
    claim_cache: BTreeMap<OutputId, CachedClaim>,
}

struct SavedRequest {
    request: SignedWithdrawal<Key, Digest>,
    opening: StateOpening<Key, Digest>,
}

struct PublishedPacket {
    anchor: Digest,
    packet: PacketId,
}

#[derive(Clone)]
struct CachedClaim {
    head: LogHead<Digest>,
    claim: WithdrawalClaim<Digest>,
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
            published: std::array::from_fn(|_| None),
            closes: Vec::new(),
            payments: [None, None],
            claim_cache: BTreeMap::new(),
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
        let mut chain = self.client(context);
        let operations = match status.last_finalized {
            Some(epoch) => {
                let admitted = chain
                    .admitted(context, epoch)
                    .await?
                    .context("finalized admission is missing")?;
                ensure!(
                    admitted.finalized && admitted.roots.successor == status.state_root,
                    "finalized admission differs from the status root"
                );
                admitted.roots.successor_operations
            }
            None => {
                let registered = chain.registered(context).await?;
                let genesis = registered.deployment.genesis();
                ensure!(
                    genesis.root() == status.state_root,
                    "registered genesis differs from the status root"
                );
                genesis.operations()
            }
        };
        let lookup = EvidenceLookup::State {
            root: status.state_root,
            operations,
            account: wallet.public_key(),
        };
        let evidence = self
            .control
            .evidence(EvidenceRequest::new(deployment(), lookup))
            .await;
        let EvidenceResponse::Served(Evidence::State(lookup)) = evidence else {
            bail!("signing account has no finalized state proof");
        };
        lookup.resolve::<Sha256>(&status.state_root, &account_key(&wallet.public_key())?)?;
        let StateLookup::Present(value) = lookup else {
            bail!("signing account has no finalized membership");
        };
        let opening = StateOpening {
            account: wallet.public_key(),
            balance: value.balance,
            proof: value.proof,
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

    fn close_requests(&self, close: &SettlementResult) -> Result<&WithdrawalBatch<Key, Digest>> {
        self.packets
            .values()
            .find(|request| {
                request.epoch == close.context.payment().epoch()
                    && request
                        .withdrawals
                        .root::<Sha256>()
                        .is_ok_and(|root| &root == close.context.withdrawal_root())
            })
            .map(|request| &request.withdrawals)
            .context("close has no matching retained registration packet")
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

    async fn payout_proof(
        &self,
        context: &deterministic::Context,
        head: LogHead<Digest>,
        index: u64,
    ) -> Result<WithdrawalClaim<Digest>> {
        let operator_claim = { self.operator().lock().payout_proof(head, index) };
        let claim = match operator_claim {
            Ok(claim) => claim,
            Err(_) => {
                self.client(context)
                    .payout_proof(context, head, index)
                    .await?
            }
        };
        ensure!(claim.position() == index, "payout proof has another index");
        let verified = claim.verify::<Sha256>(&head)?;
        ensure!(
            &verified == claim.output(),
            "payout proof authenticates another output"
        );
        Ok(claim)
    }

    async fn payout_outputs(
        &self,
        context: &deterministic::Context,
        head: LogHead<Digest>,
    ) -> Result<(BTreeMap<OutputId, WithdrawalOutput>, Vec<OutputId>)> {
        let chain = self.client(context);
        let mut outputs = BTreeMap::new();
        let mut commits = Vec::new();
        let mut cursor = 0;
        while cursor < head.operations {
            let (start, operations) = chain.payout_operations(context, head, cursor).await?;
            ensure!(
                start == cursor,
                "lifecycle payout prefix is unavailable at the authenticated head"
            );
            let count = u64::try_from(operations.len())?;
            let end = start
                .checked_add(count)
                .context("payout operation page exceeds the position domain")?;
            ensure!(
                count > 0 && end <= head.operations,
                "payout operation page has invalid bounds"
            );
            for (offset, operation) in operations.into_iter().enumerate() {
                let position = start
                    .checked_add(u64::try_from(offset)?)
                    .context("payout operation position overflow")?;
                match operation {
                    PayoutOperation::Append(output) => {
                        ensure!(
                            outputs.insert(position, output).is_none(),
                            "payout operation page repeated a position"
                        );
                    }
                    PayoutOperation::Commit(None, _) => {
                        if position != 0 {
                            commits.push(position);
                        }
                    }
                    PayoutOperation::Commit(Some(_), _) => {
                        bail!("payout operation page contains application commit metadata")
                    }
                }
            }
            cursor = end;
        }
        Ok((outputs, commits))
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
                let epoch = self.operator().lock().registration_boundary()?.0.epoch();
                if epoch > 0
                    && self
                        .client(context)
                        .admitted(context, epoch - 1)
                        .await?
                        .is_none()
                {
                    return Ok(Outcome::Rejected);
                }
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
                    let anchor = self
                        .client(context)
                        .anchor(context, u64::from(packet.epoch))
                        .await?
                        .context("accepted publication has no permanent native anchor")?;
                    self.published[usize::from(packet.epoch)] = Some(PublishedPacket {
                        anchor,
                        packet: PacketId {
                            queued: 0,
                            ..packet
                        },
                    });
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
            Action::Fault => {
                if self.status(context).await.hard_faulted {
                    Outcome::Unchanged
                } else {
                    let registration = self
                        .client(context)
                        .registration(context)
                        .await?
                        .context("fault action requires an active registration")?;
                    let height = self.status(context).await.height;
                    if height <= registration.admission_deadline {
                        self.control
                            .advance(registration.admission_deadline - height + 1)
                            .await;
                    }
                    if self.status(context).await.hard_faulted {
                        Outcome::Accepted
                    } else {
                        Outcome::Rejected
                    }
                }
            }
            Action::Refresh(output) => {
                let status = self.client(context).payout_status(context, output).await?;
                let claim = self.payout_proof(context, status.head, output).await?;
                self.claim_cache.insert(
                    output,
                    CachedClaim {
                        head: status.head,
                        claim,
                    },
                );
                Outcome::Accepted
            }
            Action::Claim(output) => {
                let Some(cached) = self.claim_cache.get(&output).cloned() else {
                    return Ok(Outcome::Rejected);
                };
                let before = self.client(context).payout_status(context, output).await?;
                if before.head != cached.head {
                    return Ok(Outcome::Rejected);
                }
                if before.claimed.is_some() {
                    return Ok(Outcome::Unchanged);
                }
                let expected = cached.claim.output().clone();
                self.control
                    .submit(SettlementTx::ClaimWithdrawal(
                        crate::chain::tx::WithdrawalClaimRequest {
                            deployment: deployment(),
                            claim: cached.claim,
                        },
                    ))
                    .await;
                let after = self.client(context).payout_status(context, output).await?;
                let current = self.payout_proof(context, after.head, output).await?;
                ensure!(
                    current.output() == &expected,
                    "current payout head changed an existing output"
                );
                if after.claimed.is_some() {
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
        let payout_tip = chain.payout_checkpoint(context).await?;
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
            if status
                .last_finalized
                .is_some_and(|last| epoch as u64 <= last)
            {
                let close = self
                    .closes
                    .get(epoch)
                    .context("finalized trace epoch has no retained local close")?;
                let anchor = *close.context.payment().anchor();
                if payment.epoch() == epoch as u64 {
                    adopted = payment.anchor() == &anchor;
                }
                anchors[epoch] = Some(PacketId {
                    epoch: epoch.try_into()?,
                    requests: self.request_mask(self.close_requests(close)?)?,
                    queued: 0,
                });
                admitted[epoch] = true;
                continue;
            }
            if let Some(anchor) = chain.anchor(context, epoch as u64).await? {
                if payment.epoch() == epoch as u64 {
                    adopted = payment.anchor() == &anchor;
                }
                let requests = if let Some(close) = self.closes.get(epoch) {
                    ensure!(
                        close.context.payment().anchor() == &anchor,
                        "stored close differs from permanent native anchor"
                    );
                    self.request_mask(self.close_requests(close)?)?
                } else if let Some(published) = &self.published[epoch] {
                    ensure!(
                        published.anchor == anchor,
                        "permanent native anchor changed after publication"
                    );
                    published.packet.requests
                } else {
                    let registered = registered
                        .as_ref()
                        .filter(|record| record.epoch == epoch as u64 && record.anchor == anchor)
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
            admitted[epoch] = chain.admitted(context, epoch as u64).await?.is_some();
        }
        let mut outputs = [[None; model::ACCOUNTS]; model::EPOCHS];
        let mut released = [[None; model::ACCOUNTS]; model::EPOCHS];
        let mut claimed = BTreeMap::new();
        let mut claim_head = [None; model::ACCOUNTS];
        let (finalized_outputs, finalized_commits) =
            self.payout_outputs(context, payout_tip.payouts).await?;
        for position in finalized_commits {
            let payout = chain.payout_status(context, position).await?;
            ensure!(
                payout.head == payout_tip.payouts,
                "commit status differs from the current finalized head"
            );
            let range = payout
                .claimed
                .context("a finalized payout commit is not structurally claimed")?;
            ensure!(
                range.start <= position && position < range.end,
                "claimed range does not contain its finalized commit"
            );
            if let Some(prior) = claimed.insert(range.start, range.end) {
                ensure!(prior == range.end, "claimed range views disagree");
            }
        }
        for close in &self.closes {
            let epoch: usize = close.context.payment().epoch().try_into()?;
            let finalized = status
                .last_finalized
                .is_some_and(|last| epoch as u64 <= last);
            let start = close.context.predecessor_logs().payouts.operations;
            let end = close
                .roots
                .withdrawal_outputs
                .operations
                .checked_sub(1)
                .context("close payout head omits its commit")?;
            ensure!(start <= end, "close payout head precedes its input");
            for position in start..end {
                let output = if finalized {
                    finalized_outputs
                        .get(&position)
                        .cloned()
                        .context("finalized payout append is unavailable")?
                } else {
                    self.payout_proof(context, close.roots.withdrawal_outputs, position)
                        .await?
                        .output()
                        .clone()
                };
                let account = wallets
                    .iter()
                    .position(|wallet| {
                        output.destination().as_ref() == wallet.public_key().as_ref()
                    })
                    .context("payout destination is outside the trace accounts")?;
                ensure!(
                    outputs[epoch][account].replace(output.amount()).is_none(),
                    "close contains repeated outputs for one trace account"
                );
                if finalized {
                    let payout = chain.payout_status(context, position).await?;
                    ensure!(
                        payout.head == payout_tip.payouts,
                        "payout status differs from the current finalized head"
                    );
                    let claim = self.payout_proof(context, payout.head, position).await?;
                    ensure!(
                        claim.output() == &output,
                        "payout page and point opening disagree"
                    );
                    match payout.claimed {
                        Some(range) => {
                            released[epoch][account] = Some(output.amount());
                            ensure!(
                                range.start <= position && position < range.end,
                                "claimed range does not contain its payout output"
                            );
                            if let Some(prior) = claimed.insert(range.start, range.end) {
                                ensure!(prior == range.end, "claimed range views disagree");
                            }
                        }
                        None => {
                            claim_head[account].get_or_insert(position);
                        }
                    }
                }
            }
        }
        let state_operations = match status.last_finalized {
            Some(epoch) => {
                let close = chain
                    .admitted(context, epoch)
                    .await?
                    .context("finalized close is absent")?;
                ensure!(
                    close.finalized && close.roots.successor == status.state_root,
                    "status root differs from finalized admission"
                );
                close.roots.successor_operations
            }
            None => {
                let registered = chain.registered(context).await?;
                let genesis = registered.deployment.genesis();
                ensure!(
                    genesis.root() == status.state_root,
                    "registered genesis differs from the status root"
                );
                genesis.operations()
            }
        };
        let mut finalized_balances = [0; model::ACCOUNTS];
        for account in 0..model::ACCOUNTS {
            let key = wallets[account].public_key();
            let lookup = EvidenceLookup::State {
                root: status.state_root,
                operations: state_operations,
                account: key.clone(),
            };
            finalized_balances[account] = match self
                .control
                .evidence(EvidenceRequest::new(deployment(), lookup))
                .await
            {
                EvidenceResponse::Served(Evidence::State(lookup)) => lookup
                    .resolve::<Sha256>(&status.state_root, &account_key(&key)?)?
                    .map_or(0, |balance| balance.get()),
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
            faulted: status.hard_faulted,
            acknowledgements,
            receipts,
            anchors,
            admitted,
            finalized: status.last_finalized.map(u8::try_from).transpose()?,
            root: status
                .last_finalized
                .map_or(0, |epoch| u8::try_from(epoch + 1).unwrap()),
            finalized_balances,
            payout_head: payout_tip.payouts.operations,
            claimed,
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
            native.project(context).await.unwrap_or_else(|error| {
                panic!(
                    "{} step {index}: {action:?} projection: {error:#}; path: {:?}",
                    trace.name,
                    &trace.actions[..=index]
                )
            }),
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
            Box::pin(replay(&context, trace)).await;
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
