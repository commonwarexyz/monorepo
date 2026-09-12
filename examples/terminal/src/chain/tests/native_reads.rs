use super::{
    fixture::{ReadFixture, ReadProvider},
    *,
};
use crate::{
    chain::{
        client::{Chain, Env},
        validator::{INGRESS_BYTES, INGRESS_CAPACITY, INGRESS_LEASE},
    },
    protocol::{MAX_ACCOUNTS, Wallet},
};
use commonware_utils::channel::oneshot;
use std::{fs, net::SocketAddr, path::PathBuf};

struct NativeWalletDatabase(PathBuf);

impl NativeWalletDatabase {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let directory = std::env::temp_dir().join(format!(
            "commonware-terminal-native-full-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&directory).unwrap();
        Self(directory)
    }
}

impl Drop for NativeWalletDatabase {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Default)]
struct TransferProxy {
    submissions: Vec<Bytes>,
    reads: usize,
    capture: Option<oneshot::Sender<Bytes>>,
    response: TransferSubmission,
}

#[derive(Clone, Copy, Debug, Default)]
enum TransferSubmission {
    #[default]
    Full,
    Error,
    Pending,
}

#[test]
fn durable_native_transfer_completes_from_receipt_after_full_retries() {
    durable_native_transfer_completes_from_receipt(TransferSubmission::Full);
}

#[test]
fn durable_native_transfer_completes_when_submission_errors() {
    durable_native_transfer_completes_from_receipt(TransferSubmission::Error);
}

#[test]
fn durable_native_transfer_completes_when_submission_stalls() {
    durable_native_transfer_completes_from_receipt(TransferSubmission::Pending);
}

fn durable_native_transfer_completes_from_receipt(response: TransferSubmission) {
    deterministic::Runner::timed(Duration::from_secs(300)).start(move |context| async move {
        let database = NativeWalletDatabase::new();
        let path = database.0.join("wallet.sqlite");
        let mut fixture = ReadFixture::new(&context).await;
        fixture.seal(&context, true).await;
        let native = fixture.identity.native.clone();
        let query_address = fixture.address;
        let proxy_address = SocketAddr::from(([127, 0, 0, 1], 19_875));
        let mut listener = context.bind(proxy_address).await.unwrap();
        let proxy = Arc::new(Mutex::new(TransferProxy::default()));
        let observed = proxy.clone();
        context.child("full_transfer_proxy").spawn(move |context| async move {
            loop {
                let (_, mut sink, mut stream) = listener.accept().await.unwrap();
                let observed = observed.clone();
                context.child("request").spawn(move |context| async move {
                let request = rpc::recv_request(&mut stream).await.unwrap();
                let response = match request.method {
                    query::METHOD_SUBMIT_TX => {
                        assert!(matches!(
                            SettlementTx::decode(request.body.clone()).unwrap(),
                            SettlementTx::NativeTransfer(_)
                        ));
                        let response = {
                            let mut state = observed.lock();
                            state.submissions.push(request.body.clone());
                            if let Some(capture) = state.capture.take() {
                                capture.send(request.body).unwrap();
                            }
                            state.response
                        };
                        match response {
                            TransferSubmission::Full => rpc::Response::Success {
                                body: ingress::Submission::Full.encode(),
                            },
                            TransferSubmission::Error => rpc::Response::Error {
                                error: Bytes::from_static(b"submission unavailable"),
                            },
                            TransferSubmission::Pending => std::future::pending().await,
                        }
                    }
                    query::METHOD_READ => {
                        assert!(matches!(
                            ReadRequest::decode(request.body.clone()).unwrap().lookup,
                            Lookup::NativeTransfer { .. }
                        ));
                        let body = rpc::invoke(
                            &context,
                            query_address,
                            "query",
                            request.method,
                            request.body,
                        )
                        .await
                        .unwrap();
                        observed.lock().reads += 1;
                        rpc::Response::Success { body }
                    }
                    _ => panic!("the wallet transfer uses only submission and receipt reads"),
                };
                let _ = rpc::send_response(&mut sink, &response).await;
                });
            }
        });
        let mut chain = Client::new(
            &fixture.identity,
            deployment(),
            vec![proxy_address],
            test_rng(),
        )
        .unwrap();
        let mut agent = Agent::open(&path, 0).unwrap();
        let from = agent.account();
        let to = operator_key();
        let sender_before = native_balance(&fixture.db, &native, &from).await.unwrap();
        let recipient_before = native_balance(&fixture.db, &native, &to).await.unwrap();
        let absent = agent
            .transfer_native(&context, &mut chain, to.clone(), 17)
            .await;
        assert!(absent.is_err(), "Full cannot authorize completion without a receipt");
        let saved = {
            let state = proxy.lock();
            assert_eq!(state.submissions.len(), 50);
            SettlementTx::decode(state.submissions[0].clone()).unwrap()
        };
        let SettlementTx::NativeTransfer(request) = &saved else {
            unreachable!()
        };
        assert_eq!(request.from, from);
        assert_eq!(request.to, to);
        assert_eq!(request.amount, 17);
        let mut canonical = fixture.client(deployment());
        assert_eq!(
            canonical
                .native_transfer(&context, native.chain_id(), from.clone(), request.id)
                .await
                .unwrap(),
            None
        );
        drop(agent);

        proxy.lock().response = response;
        let mut absent_retry = Agent::open(&path, 0).unwrap();
        commonware_macros::select! {
            result = absent_retry.transfer_native(&context, &mut chain, to.clone(), 17) => {
                assert!(result.is_err(), "submission failure cannot prove an absent transfer");
            },
            _ = context.sleep(Duration::from_secs(30)) => {},
        }
        drop(absent_retry);

        fixture.submit(&context, saved.clone()).await;
        let applied = fixture.seal(&context, true).await;
        assert_eq!(applied.transactions, vec![saved.clone()]);
        assert_eq!(
            canonical
                .native_transfer(&context, native.chain_id(), from.clone(), request.id)
                .await
                .unwrap(),
            Some(request.clone())
        );
        let reads_before = proxy.lock().reads;
        let submissions_before = proxy.lock().submissions.len();
        proxy.lock().response = response;
        let exact_bytes = saved.encode();
        let mut recovered = Agent::open(&path, 0).unwrap();
        let completed = commonware_macros::select! {
            result = recovered.transfer_native(&context, &mut chain, to.clone(), 17) => result,
            _ = context.sleep(Duration::from_secs(30)) => {
                panic!("a certified transfer waited for a {response:?} submission response");
            },
        };
        {
            let state = proxy.lock();
            assert!(state.submissions.iter().all(|bytes| *bytes == exact_bytes));
            eprintln!(
                "durable native transfer: applied_height={} Full_submissions={} receipt_reads_after_restart={} result={completed:?}",
                applied.height.get(), state.submissions.len(), state.reads - reads_before,
            );
        }
        assert_eq!(native_balance(&fixture.db, &native, &from).await.unwrap(), sender_before - 17);
        assert_eq!(native_balance(&fixture.db, &native, &to).await.unwrap(), recipient_before + 17);
        assert_eq!(fixture.finalized.latest().unwrap().height, applied.height.get());
        assert_eq!(
            completed.expect("a durable exact receipt completes without a submission response"),
            *request
        );
        assert_eq!(proxy.lock().submissions.len(), submissions_before);
        assert_eq!(proxy.lock().reads, reads_before + 1);
        drop(recovered);

        // Reopening can stage a different transfer only after durable completion cleared the old intent.
        let (capture, captured) = oneshot::channel();
        proxy.lock().capture = Some(capture);
        let mut reopened = Agent::open(&path, 0).unwrap();
        let next = commonware_macros::select! {
            result = reopened.transfer_native(&context, &mut chain, to.clone(), 18) => {
                panic!("a new transfer must reach submission: {result:?}");
            },
            bytes = captured => SettlementTx::decode(bytes.unwrap()).unwrap(),
        };
        let SettlementTx::NativeTransfer(next) = next else {
            unreachable!()
        };
        assert_eq!(next.amount, 18);
        assert_ne!(next.id, request.id);
        assert_eq!(native_balance(&fixture.db, &native, &from).await.unwrap(), sender_before - 17);
        assert_eq!(native_balance(&fixture.db, &native, &to).await.unwrap(), recipient_before + 17);
    });
}

/// Runs real RPCs while controlling proposal opportunities around ingress retention.
struct AdmissionRetention {
    context: deterministic::Context,
    fixture: ReadFixture,
    client: Client,
    saved: SettlementTx,
    deadline: u64,
    submitted_at: u64,
    polls: usize,
    submissions: Vec<(usize, Bytes)>,
    accepted: Vec<u64>,
    included_at: Option<u64>,
    exhausted: Option<oneshot::Sender<()>>,
}

impl Chain for AdmissionRetention {
    fn deployment(&self) -> Digest {
        self.client.deployment()
    }

    async fn read<E: Env>(
        &mut self,
        context: &E,
        request: &ReadRequest,
    ) -> anyhow::Result<light::Verified> {
        let verified = self.client.read(context, request).await?;
        assert_eq!(request.lookup, Lookup::Fault);
        assert_eq!(verified.record, None);
        Ok(verified)
    }

    async fn recent<E: Env>(
        &mut self,
        context: &E,
        request: &ReadRequest,
    ) -> anyhow::Result<light::Verified> {
        assert_eq!(request.lookup, Lookup::Admitted { epoch: 0 });
        let block = self.fixture.seal(&self.context, true).await;
        assert!(block.height.get() < self.deadline);
        if block.transactions.is_empty() {
            assert!(self.included_at.is_none());
        } else {
            assert_eq!(block.transactions, vec![self.saved.clone()]);
            assert!(self.included_at.replace(block.height.get()).is_none());
        }
        let verified = self.client.recent(context, request).await?;
        assert_eq!(verified.height, block.height.get());
        assert_eq!(verified.record.is_some(), self.included_at.is_some());
        self.polls += 1;

        // Stop at a completed proof so the retry control cannot race an unfinished proposal.
        if self.polls == 125 && verified.record.is_none() {
            self.exhausted.take().unwrap().send(()).unwrap();
            std::future::pending::<()>().await;
        }
        Ok(verified)
    }

    async fn submit<E: Env>(
        &mut self,
        context: &E,
        tx: &SettlementTx,
    ) -> anyhow::Result<ingress::Submission> {
        let bytes = tx.encode();
        assert_eq!(bytes, self.saved.encode());
        self.submissions.push((self.polls, bytes));
        match self.submissions.len() {
            2 => {
                return Ok(ingress::Submission::Full);
            }
            3 => anyhow::bail!("injected renewal transport failure"),
            4 => std::future::pending::<()>().await,
            _ => {}
        }
        let submitted = self.client.submit(context, tx).await?;
        assert_eq!(submitted, ingress::Submission::Accepted);
        let height = self.fixture.finalized.latest().unwrap().height;
        self.accepted.push(height);
        if self.submissions.len() == 1 {
            assert_eq!(height, self.submitted_at);

            // Consensus permits this finite omission; no proposal borrows the target before expiry.
            for offset in 1..=INGRESS_LEASE * 4 {
                let block = self
                    .fixture
                    .seal_with(&self.context, true, ReadProvider(None))
                    .await;
                assert_eq!(block.height.get(), self.submitted_at + offset);
                assert!(block.transactions.is_empty());
            }
            assert!(
                ingress::Provider::drain(
                    &mut self.fixture.ingress,
                    MAX_BLOCK_TXS,
                    MAX_BLOCK_BYTES,
                )
                .await
                .is_empty()
            );
            let absent = self
                .fixture
                .fetch(&self.context, &req(Lookup::Admitted { epoch: 0 }))
                .await?;
            assert_eq!(absent.height, self.submitted_at + INGRESS_LEASE * 4);
            assert_eq!(absent.record, None);
            assert!(absent.height < self.deadline);
        }
        Ok(submitted)
    }
}

#[test]
fn admission_survives_ingress_retention_and_transient_renewal_failures() {
    deterministic::Runner::timed(Duration::from_secs(60)).start(|context| async move {
        let mut fixture = ReadFixture::with_timing(&context, Timing::GENESIS).await;
        fixture.seal(&context, true).await;
        let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
        let predecessor = genesis_cache();
        let chain_id = fixture.identity.native.chain_id();
        let label = b"admission-retention-deposit";
        let (_, deposit, register) =
            fixture_boundary(chain_id, &protocol, 0, &predecessor, label);
        for tx in [&deposit, &register] {
            fixture.submit(&context, tx.clone()).await;
            assert_eq!(fixture.seal(&context, true).await.transactions, vec![tx.clone()]);
        }
        let mut client = fixture.client(deployment());
        let registration = client.registration(&context).await.unwrap().unwrap();
        let submitted_at = fixture.finalized.latest().unwrap().height;
        assert_eq!(registration.epoch, 0);
        assert_eq!(registration.admission_deadline, submitted_at + 300);
        let close = close_fixture(
            chain_id,
            &protocol,
            0,
            predecessor,
            label,
            registration.admission_deadline,
            registration.challenge_deadline,
        );
        assert_eq!(close.deposit_tx, deposit);
        assert_eq!(close.register_tx, register);
        let saved = close.admit_tx;
        assert_eq!(SettlementTx::decode(saved.encode()).unwrap(), saved);
        let SettlementTx::Admit(request) = saved.clone() else {
            unreachable!()
        };
        let batch_id = request.header.batch_id::<Sha256>();
        let roots = request.roots;
        let (exhausted, exhaustion) = oneshot::channel();
        let mut race = AdmissionRetention {
            context: context.child("admission_retention"),
            fixture,
            client,
            saved: saved.clone(),
            deadline: registration.admission_deadline,
            submitted_at,
            polls: 0,
            submissions: Vec::new(),
            accepted: Vec::new(),
            included_at: None,
            exhausted: Some(exhausted),
        };
        let result = commonware_macros::select! {
            result = crate::chain::client::admit(&context, &mut race, request) => Some(result),
            exhausted = exhaustion => {
                exhausted.unwrap();
                None
            },
        };
        let completed_at = race.included_at;
        let before_control = race.client.admitted(&context, 0).await.unwrap();
        assert_eq!(before_control.is_some(), completed_at.is_some());
        if result.is_none() {
            assert_eq!(race.polls, 125);
            assert_eq!(before_control, None);
        }

        // An exact retry before the immutable deadline proves the retained close can still apply.
        let control = race.client.submit(&context, &saved).await.unwrap();
        assert_eq!(
            control,
            if before_control.is_some() { ingress::Submission::Full } else { ingress::Submission::Accepted }
        );
        let block = race.fixture.seal(&context, true).await;
        assert!(block.height.get() < race.deadline);
        assert_eq!(block.transactions, if before_control.is_some() { Vec::new() } else { vec![saved.clone()] });
        let admitted = race.client.admitted(&context, 0).await.unwrap().unwrap();
        assert_eq!(admitted.batch_id, batch_id);
        assert_eq!(admitted.roots, roots);
        assert_eq!(race.client.fault(&context).await.unwrap(), None);
        let replay = race.client.submit(&context, &saved).await.unwrap();
        assert_eq!(replay, ingress::Submission::Full);
        eprintln!(
            "admission retention: polls={} accepted={:?} completed={completed_at:?} exact_retry_applied={} deadline={} result={result:?}",
            race.polls, race.accepted, block.height.get(), race.deadline,
        );
        result
            .expect("the consumer must renew its expired admission while certified effects are absent")
            .expect("transient renewal failures must preserve certified effect polling");
        assert!(completed_at.is_some());
        assert_eq!(race.accepted.len(), 2);
        assert_eq!(race.accepted[0], submitted_at);
        assert!(race.accepted[1] > submitted_at + INGRESS_LEASE * 4);
        assert_eq!(race.submissions.len(), 5);
        for pair in race.submissions.windows(2) {
            assert!(pair[0].0 < pair[1].0, "proof polling continues between renewal attempts");
        }
    });
}

/// Finalizes a pending registration between its second absence proof and the next client operation.
struct RegistrationRace {
    context: deterministic::Context,
    fixture: ReadFixture,
    client: Client,
    saved: SettlementTx,
    expected: RegistryEntry,
    funded_height: u64,
    absent_heights: Vec<u64>,
    entry_heights: Vec<u64>,
    balance_reads: Vec<(u64, u64)>,
    submissions: Vec<(u64, Bytes)>,
    certified_zero: Option<light::Verified>,
}

impl Chain for RegistrationRace {
    fn deployment(&self) -> Digest {
        self.client.deployment()
    }

    async fn read<E: Env>(
        &mut self,
        context: &E,
        request: &ReadRequest,
    ) -> anyhow::Result<light::Verified> {
        let verified = self.client.read(context, request).await?;
        match &request.lookup {
            Lookup::RegistryEntry {
                chain_id,
                deployment,
            } => {
                assert_eq!(*chain_id, self.fixture.identity.native.chain_id());
                assert_eq!(deployment, self.expected.deployment.digest());
                if let Some(record) = &verified.record {
                    assert_eq!(record, &Record::RegistryEntry(self.expected.clone()));
                    self.entry_heights.push(verified.height);
                } else {
                    assert_eq!(verified.height, self.funded_height);
                    self.absent_heights.push(verified.height);
                    if self.absent_heights.len() == 2 {
                        assert_eq!(
                            self.submissions,
                            vec![(self.funded_height, self.saved.encode())]
                        );
                        let block = self.fixture.seal(&self.context, true).await;
                        assert_eq!(block.height.get(), self.funded_height + 1);
                        assert_eq!(block.transactions, vec![self.saved.clone()]);

                        // This independent verified read leaves the polling client's height at the obtained absence.
                        let balance_request = ReadRequest::new(
                            *deployment,
                            Lookup::NativeBalance {
                                chain_id: *chain_id,
                                account: self.expected.deployment.operator.clone(),
                            },
                        );
                        let zero = self.fixture.fetch(&self.context, &balance_request).await?;
                        assert_eq!(zero.height, block.height.get());
                        assert_eq!(zero.record, Some(Record::NativeBalance(0)));
                        self.certified_zero = Some(zero);
                    }
                }
            }
            Lookup::NativeBalance { .. } => {
                let Some(Record::NativeBalance(balance)) = &verified.record else {
                    panic!("the funded operator has an explicit native balance")
                };
                self.balance_reads.push((verified.height, *balance));
            }
            _ => panic!("registration completion reads only its entry and native balance"),
        }
        Ok(verified)
    }

    async fn recent<E: Env>(
        &mut self,
        context: &E,
        request: &ReadRequest,
    ) -> anyhow::Result<light::Verified> {
        self.read(context, request).await
    }

    async fn submit<E: Env>(
        &mut self,
        context: &E,
        tx: &SettlementTx,
    ) -> anyhow::Result<ingress::Submission> {
        let bytes = tx.encode();
        assert_eq!(bytes, self.saved.encode());
        let submitted = self.client.submit(context, tx).await?;
        assert_eq!(
            submitted,
            if self.submissions.is_empty() {
                ingress::Submission::Accepted
            } else {
                ingress::Submission::Full
            }
        );
        self.submissions
            .push((self.fixture.finalized.latest().unwrap().height, bytes));
        Ok(submitted)
    }
}

#[test]
fn registration_completion_survives_its_fee_debit() {
    deterministic::Runner::timed(Duration::from_secs(20)).start(|context| async move {
        let mut fixture = ReadFixture::new(&context).await;
        fixture.seal(&context, false).await;
        let native = fixture.identity.native.clone();
        let chain_id = native.chain_id();
        let fee = native.registration_fee;
        assert!(fee > 0);
        let owner = operator_signer(71);
        assert_ne!(owner.public_key(), native.fee_recipient);
        assert!(
            !native
                .balances
                .iter()
                .any(|account| account.key == owner.public_key())
        );
        let initial_recipient = native_balance(&fixture.db, &native, &native.fee_recipient)
            .await
            .unwrap();
        let funding = SettlementTx::NativeTransfer(NativeTransferRequest::sign(
            chain_id,
            Sha256::hash(&[b"registration-race-funding"]),
            owner.public_key(),
            fee,
            &operator_signer(0),
        ));
        fixture.submit(&context, funding.clone()).await;
        let funded = fixture.seal(&context, true).await;
        assert_eq!(funded.transactions, vec![funding]);
        let funded_height = funded.height.get();
        let balance_request = req(Lookup::NativeBalance {
            chain_id,
            account: owner.public_key(),
        });
        let balance = fixture.fetch(&context, &balance_request).await.unwrap();
        assert_eq!(balance.height, funded_height);
        assert_eq!(balance.record, Some(Record::NativeBalance(fee)));
        let request = RegisterDeploymentRequest::sign(
            chain_id,
            Sha256::hash(&[b"registration-race-request"]),
            operator_ack_key(71),
            native.deployments[0].network_key.clone(),
            vec![wallets()[0].public_key()],
            1024,
            fee,
            &owner,
        );
        let expected = request.entry(&native).unwrap();
        let deployment = request.deployment_id();
        let saved = SettlementTx::RegisterDeployment(request.clone());
        assert_eq!(SettlementTx::decode(saved.encode()).unwrap(), saved);
        let client = fixture.client(deployment);
        let mut race = RegistrationRace {
            context: context.child("registration_race"),
            fixture,
            client,
            saved: saved.clone(),
            expected: expected.clone(),
            funded_height,
            absent_heights: Vec::new(),
            entry_heights: Vec::new(),
            balance_reads: Vec::new(),
            submissions: Vec::new(),
            certified_zero: None,
        };
        let result =
            crate::chain::setup::complete_registration(&context, &mut race, &native, request).await;
        assert_eq!(race.absent_heights, vec![funded_height, funded_height]);
        let zero = race
            .certified_zero
            .as_ref()
            .expect("the second genuine absence finalized the queued request");
        assert_eq!(zero.height, funded_height + 1);
        assert_eq!(zero.record, Some(Record::NativeBalance(0)));
        assert_eq!(race.submissions[0], (funded_height, saved.encode()));
        eprintln!(
            "registration race: absent={:?} zero_height={} balances={:?} result={result:?}",
            race.absent_heights, zero.height, race.balance_reads
        );
        result.expect("an exact certified registration must complete after consuming its fee");
        assert_eq!(race.entry_heights, vec![funded_height + 1]);
        assert_eq!(race.submissions.len(), 51);
        assert!(
            race.submissions[1..]
                .iter()
                .all(|submission| *submission == (funded_height + 1, saved.encode()))
        );
        assert_eq!(
            native_balance(&race.fixture.db, &native, &owner.public_key())
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            native_balance(&race.fixture.db, &native, &native.fee_recipient)
                .await
                .unwrap(),
            initial_recipient + fee
        );

        // The consumed retry never enters the proposal queue and cannot charge a second fee.
        let replayed = race.fixture.seal(&context, true).await;
        assert_eq!(replayed.height.get(), funded_height + 2);
        assert!(replayed.transactions.is_empty());
        let read = race
            .fixture
            .fetch(
                &context,
                &ReadRequest::new(
                    deployment,
                    Lookup::RegistryEntry {
                        chain_id,
                        deployment,
                    },
                ),
            )
            .await
            .unwrap();
        assert_eq!(read.height, replayed.height.get());
        assert_eq!(read.record, Some(Record::RegistryEntry(expected)));
        assert_eq!(
            native_balance(&race.fixture.db, &native, &owner.public_key())
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            native_balance(&race.fixture.db, &native, &native.fee_recipient)
                .await
                .unwrap(),
            initial_recipient + fee
        );
    });
}

#[test]
fn certified_registry_fits_busy_block() {
    deterministic::Runner::timed(Duration::from_secs(120)).start(|context| async move {
        let mut fixture = ReadFixture::new(&context).await;
        fixture.seal(&context, false).await;
        let native = fixture.identity.native.clone();
        let chain_id = native.chain_id();
        let directory_request = req(Lookup::Registry { chain_id });
        let mut expected_ids = native
            .deployments
            .iter()
            .map(|entry| *entry.deployment.digest())
            .collect::<Vec<_>>();
        let read = fixture.fetch(&context, &directory_request).await.unwrap();
        assert_eq!(read.record, Some(Record::Registry(expected_ids.clone())));
        assert_eq!(
            fixture
                .client(deployment())
                .registered(&context)
                .await
                .unwrap(),
            native.deployments[0]
        );

        let payer = operator_signer(0);
        let initial_payer = native_balance(&fixture.db, &native, &payer.public_key())
            .await
            .unwrap();
        let initial_recipient = native_balance(&fixture.db, &native, &native.fee_recipient)
            .await
            .unwrap();
        let accounts = (0..MAX_ACCOUNTS)
            .map(|index| {
                Wallet::from_seed("registered-account", 10_000 + index as u64).public_key()
            })
            .collect::<Vec<_>>();
        let mut last_entry = None;
        let batch_fee = 31 * native.registration_fee;
        assert_eq!(batch_fee, 310);
        for batch in 0u8..2 {
            let mut transactions = Vec::with_capacity(31);
            for offset in 0u8..31 {
                let index = batch * 31 + offset;
                let registration = RegisterDeploymentRequest::sign(
                    chain_id,
                    Sha256::hash(&[b"native-read-registration", &[index]]),
                    operator_ack_key(0),
                    native.deployments[0].network_key.clone(),
                    accounts.clone(),
                    native.max_dealing_bytes,
                    native.registration_fee,
                    &payer,
                );
                expected_ids.push(registration.deployment_id());
                last_entry = Some(registration.entry(&native).unwrap());
                let tx = SettlementTx::RegisterDeployment(registration);
                fixture.submit(&context, tx.clone()).await;
                transactions.push(tx);
            }
            let bytes = transactions
                .iter()
                .map(|tx| tx.encode_size())
                .sum::<usize>();
            assert!(transactions.len() <= INGRESS_CAPACITY.get());
            assert!(bytes <= INGRESS_BYTES.get());
            assert!(bytes + transactions[0].encode_size() > INGRESS_BYTES.get());
            let block = fixture.seal(&context, false).await;
            assert_eq!(block.transactions, transactions);
            assert_eq!(registry(&fixture.db, &native).await.unwrap(), expected_ids);
            let paid = u64::from(batch + 1) * batch_fee;
            assert_eq!(
                native_balance(&fixture.db, &native, &payer.public_key())
                    .await
                    .unwrap(),
                initial_payer - paid
            );
            assert_eq!(
                native_balance(&fixture.db, &native, &native.fee_recipient)
                    .await
                    .unwrap(),
                initial_recipient + paid
            );
            eprintln!(
                "certified paid registrations: {} at height {} (batch bytes={bytes})",
                (batch + 1) * 31,
                block.height.get()
            );
        }
        let cost = 2 * batch_fee;
        assert_eq!(cost, 620);
        let expected_balance = initial_payer - cost;
        let last_entry = last_entry.unwrap();
        let last_id = *last_entry.deployment.digest();
        assert_eq!(last_entry.deployment.accounts.len(), MAX_ACCOUNTS);
        assert_eq!(expected_ids.len(), 64);
        assert_eq!(expected_ids.last(), Some(&last_id));
        let directory = Record::Registry(expected_ids.clone());
        assert_eq!(directory.encode_size(), 2_050);
        assert_eq!(Record::decode(directory.encode()).unwrap(), directory);
        let point = Record::RegistryEntry(last_entry.clone());
        assert!(point.encode_size() < rpc::MAX_BODY_SIZE);
        assert_eq!(Record::decode(point.encode()).unwrap(), point);
        let point_request = req(Lookup::RegistryEntry {
            chain_id,
            deployment: last_id,
        });

        let small = fixture.seal(&context, false).await;
        let read = fixture.fetch(&context, &directory_request).await.unwrap();
        assert_eq!(read.height, small.height.get());
        assert_eq!(read.record, Some(directory.clone()));
        assert_eq!(
            fixture.client(last_id).registered(&context).await.unwrap(),
            last_entry
        );

        // Dynamic lanes become available only after the production watcher publishes applied entries.
        while !fixture.registry.contains(&last_id) {
            context.sleep(Duration::from_millis(1)).await;
        }
        let busy = fixture.busy(&context, &expected_ids[..5]).await;
        let guard = fixture.db.read().await;
        let proof = query::ReadProof::Present {
            proof: guard.key_value_proof(point_request.key()).await.unwrap(),
            record: guard.get(&point_request.key()).await.unwrap().unwrap(),
        };
        drop(guard);
        let response = CertifiedRead {
            finalization: fixture
                .marshal
                .get_finalization(busy.height)
                .await
                .unwrap()
                .encode(),
            block: fixture
                .marshal
                .get_block(&busy.digest())
                .await
                .unwrap()
                .encode(),
            proof,
        };
        let verified = light::verify_read::<deterministic::Context, Threshold>(
            &mut test_rng(),
            &fixture.scheme,
            &point_request,
            &response,
        )
        .unwrap();
        assert_eq!(verified.height, busy.height.get());
        assert_eq!(verified.record, Some(point.clone()));
        let body = ReadResponse::Certified(response).encode();
        assert!(body.len() <= rpc::MAX_BODY_SIZE);
        eprintln!(
            "certified registry point: directory={} entry={} block={} response={} height={}",
            directory.encode_size(),
            point.encode_size(),
            busy.encode_size(),
            body.len(),
            busy.height.get()
        );
        for (request, record) in [(&directory_request, &directory), (&point_request, &point)] {
            let read = fixture.fetch(&context, request).await.unwrap();
            assert_eq!(read.height, busy.height.get());
            assert_eq!(read.record.as_ref(), Some(record));
        }
        assert_eq!(
            fixture.client(last_id).registered(&context).await.unwrap(),
            last_entry
        );
        assert_eq!(
            fixture
                .client(last_id)
                .native_balance(&context, chain_id, payer.public_key())
                .await
                .unwrap(),
            expected_balance
        );
        assert_eq!(
            fixture.finalized.latest().unwrap().height,
            busy.height.get()
        );

        // A valid point proof stops authorizing startup when its held certified tip becomes stale.
        let stale_at = busy.timestamp + RECENCY_THRESHOLD + 1;
        context
            .sleep(Duration::from_millis(
                stale_at.saturating_sub(now(&context)),
            ))
            .await;
        let error = fixture
            .client(last_id)
            .registered(&context)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("recency bound"), "{error:#}");
        assert_eq!(
            fixture.finalized.latest().unwrap().height,
            busy.height.get()
        );
        let recovered = fixture.seal(&context, false).await;
        let read = fixture.fetch(&context, &directory_request).await.unwrap();
        assert_eq!(read.height, recovered.height.get());
        assert_eq!(read.record, Some(directory));
        assert_eq!(
            fixture.client(last_id).registered(&context).await.unwrap(),
            last_entry
        );
    });
}
