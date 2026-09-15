//! In-process single-validator chain over the deterministic runtime.
//!
//! The harness executes real blocks through [`super::state::execute`] against a real
//! settlement database, certifies every block with a one-participant BLS
//! threshold committee dealt at startup, and serves the real query wire
//! protocol (`METHOD_SUBMIT_TX`, `METHOD_READ`, and `METHOD_EVIDENCE`), so
//! [`crate::chain::client`] runs against it unmodified. Submissions seal
//! immediately into their own block, and a background ticker seals empty
//! blocks so deadlines and finalization progress while clients poll.
//!
//! The in-process committee retains validated fixture closes for deterministic replay and
//! proof construction. Responses use the production query codecs and verification rules.

use crate::{
    chain::{
        da::sync::{METHOD_NATIVE, NativeRequest, NativeResponse, Query as NativeQuery},
        ingress::Submission,
        native::{NativeGenesis, RegistryEntry},
        query::{
            CertifiedRead, Evidence, EvidenceLookup, EvidenceRequest, EvidenceResponse,
            METHOD_EVIDENCE, METHOD_READ, METHOD_SUBMIT_TX, ReadProof, ReadRequest, ReadResponse,
        },
        setup::{Genesis, ValidatorEntry, native_genesis},
        state::{Record, admitted_key, execute, registry_entry_key},
        tx::SettlementTx,
        types::{Block, Database, MAX_TX_BYTES, StateKey, now},
        validator::{NAMESPACE, SHARING_MODE, Scheme, db_config},
    },
    protocol::{Deployment, Timing, committee, deployments, genesis_balances, retained_closes},
    rpc::{self, error_response},
};
use commonware_clearing::bajillion::{
    custody::Epoch as CustodyEpoch, qmdb::account_key, transition::WithdrawalClaim,
};
use commonware_codec::{Decode as _, Encode as _};
use commonware_consensus::{
    simplex::types::{Context, Finalization, Finalize, Proposal},
    types::{Epoch, Height, Round, View},
};
use commonware_cryptography::{
    Digest as _, Digestible as _, Sha256, Signer as _,
    bls12381::{dkg::feldman_desmedt::deal, primitives::variant::MinSig},
    ed25519,
    sha256::Digest,
};
use commonware_glue::stateful::db::{DatabaseSet, Merkleized as _};
use commonware_macros::select;
use commonware_parallel::Sequential;
use commonware_runtime::{
    Clock as _, Listener as _, Network as _, Runner as _, Spawner as _, Supervisor as _,
    buffer::paged::CacheRef, deterministic,
};
use commonware_storage::qmdb::sync::Source as _;
use commonware_utils::{
    N3f1, NZU16, NZUsize,
    channel::{fallible::OneshotExt as _, mpsc, oneshot},
    iter::NonEmpty,
    non_empty_range,
    ordered::Set,
};
use std::{collections::BTreeMap, net::SocketAddr, time::Duration};

/// Idle block cadence: empty blocks seal at this interval so deadlines and
/// finalization progress while clients poll.
const TICK: Duration = Duration::from_millis(250);

/// One control message for the chain task.
#[allow(clippy::large_enum_variant)]
enum Message {
    #[cfg(test)]
    SealBatch {
        transactions: Vec<SettlementTx>,
        response: oneshot::Sender<Block>,
    },
    /// Submit one transaction and return its sealing height.
    Submit {
        tx: Box<SettlementTx>,
        response: oneshot::Sender<u64>,
    },
    /// Seal `blocks` empty blocks.
    #[cfg(test)]
    Advance {
        blocks: u64,
        response: oneshot::Sender<u64>,
    },
    /// Serve one certified read at the latest sealed block.
    Read {
        request: ReadRequest,
        response: oneshot::Sender<ReadResponse>,
    },
    /// Serve one proof request from the simulation's native replicas.
    Evidence {
        request: EvidenceRequest,
        response: oneshot::Sender<EvidenceResponse>,
    },
    /// Serve one native operation request from the simulation's replica.
    Native {
        request: NativeRequest,
        response: oneshot::Sender<NativeResponse>,
    },
    /// Read one record directly from applied state, for assertions.
    Record {
        key: StateKey,
        response: oneshot::Sender<Option<Record>>,
    },
    /// The served read and submission counts, for hot-path pins.
    #[cfg(test)]
    Counts {
        response: oneshot::Sender<(u64, u64)>,
    },
}

/// Control handle over one running harness chain.
#[derive(Clone)]
pub(crate) struct Control {
    identity: Genesis,
    sender: mpsc::Sender<Message>,
}

impl Control {
    /// Executes and certifies a batch, including canonically rejected inputs.
    #[cfg(test)]
    pub(crate) async fn seal_batch(&self, transactions: Vec<SettlementTx>) -> Block {
        let (response, receiver) = oneshot::channel();
        let _ = self
            .sender
            .send(Message::SealBatch {
                transactions,
                response,
            })
            .await;
        receiver.await.expect("chain answers batch sealing")
    }

    /// The genesis threshold identity certified reads verify against.
    pub(crate) const fn identity(&self) -> &Genesis {
        &self.identity
    }

    /// Executes one transaction directly and returns its sealing height.
    pub(crate) async fn submit(&self, tx: SettlementTx) -> u64 {
        let (response, receiver) = oneshot::channel();
        let message = Message::Submit {
            tx: Box::new(tx),
            response,
        };
        let _ = self.sender.send(message).await;
        receiver.await.expect("the chain task answers submissions")
    }

    /// Seals `blocks` empty blocks, returning the new height.
    #[cfg(test)]
    pub(crate) async fn advance(&self, blocks: u64) -> u64 {
        let (response, receiver) = oneshot::channel();
        let _ = self
            .sender
            .send(Message::Advance { blocks, response })
            .await;
        receiver.await.expect("the chain task answers advances")
    }

    /// Serves one certified read at the latest sealed block.
    pub(crate) async fn read(&self, request: ReadRequest) -> ReadResponse {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.send(Message::Read { request, response }).await;
        receiver.await.expect("the chain task answers reads")
    }

    /// Serves one proof request from the simulation's native replicas.
    pub(crate) async fn evidence(&self, request: EvidenceRequest) -> EvidenceResponse {
        let (response, receiver) = oneshot::channel();
        let _ = self
            .sender
            .send(Message::Evidence { request, response })
            .await;
        receiver
            .await
            .expect("the chain task answers evidence requests")
    }

    /// Serves one native operation request.
    pub(crate) async fn native(&self, request: NativeRequest) -> NativeResponse {
        let (response, receiver) = oneshot::channel();
        let _ = self
            .sender
            .send(Message::Native { request, response })
            .await;
        receiver
            .await
            .expect("the chain task answers native requests")
    }

    /// Reads one record directly from applied state, for assertions.
    pub(crate) async fn record(&self, key: StateKey) -> Option<Record> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.send(Message::Record { key, response }).await;
        receiver.await.expect("the chain task answers record reads")
    }

    /// Returns the (served reads, served submissions) counters.
    #[cfg(test)]
    pub(crate) async fn counts(&self) -> (u64, u64) {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.send(Message::Counts { response }).await;
        receiver.await.expect("the chain task answers count reads")
    }
}

/// The latest sealed block and its certificate, as served bytes.
struct Latest {
    height: u64,
    timestamp: u64,
    digest: Digest,
    block: bytes::Bytes,
    finalization: bytes::Bytes,
}

struct Node {
    db: Database<deterministic::Context>,
    scheme: Scheme,
    leader: ed25519::PublicKey,
    native: NativeGenesis,
    timing: Timing,
    prefix: String,
    /// Each configured deployment's account owner and next canonical epoch.
    genesis: BTreeMap<
        Digest,
        (
            commonware_clearing::bajillion::replica::Replica<
                deterministic::Context,
                Sha256,
                crate::protocol::Key,
            >,
            u64,
        ),
    >,
    latest: Option<Latest>,
    reads: u64,
    submissions: u64,
}

impl Node {
    async fn native(
        &mut self,
        context: &deterministic::Context,
        request: NativeRequest,
    ) -> NativeResponse {
        let entry = {
            let db = self.db.read().await;
            match db
                .get(&registry_entry_key(
                    &self.native.chain_id(),
                    &request.deployment,
                ))
                .await
                .unwrap()
            {
                Some(Record::RegistryEntry(entry)) => entry,
                _ => return NativeResponse::Unavailable,
            }
        };
        let (mut state, mut next) = match self.genesis.remove(&request.deployment) {
            Some(state) => state,
            None => {
                let state = crate::protocol::init_replica(
                    context.child("native-replica"),
                    &format!("{}-replica-{}", self.prefix, request.deployment),
                    Sequential,
                    genesis_balances(&entry.deployment).unwrap(),
                )
                .await
                .unwrap();
                (state, 0)
            }
        };
        let retained = retained_closes();
        let relevant = retained
            .iter()
            .filter(|close| close.context.deployment() == &request.deployment)
            .collect::<Vec<_>>();
        let mut canonical = BTreeMap::new();
        let mut tail = None;
        {
            let db = self.db.read().await;
            for close in &relevant {
                let epoch = close.context.payment().epoch();
                if let Some(Record::Admitted(admitted)) = db
                    .get(&admitted_key(&request.deployment, epoch))
                    .await
                    .unwrap()
                    && tail.is_none_or(|(latest, _, _)| epoch > latest)
                {
                    tail = Some((epoch, admitted.roots.successor, admitted.roots.logs()));
                }
            }
        }
        while let Some((epoch, root, heads)) = tail {
            let Some(close) = relevant.iter().find(|close| {
                close.context.payment().epoch() == epoch
                    && close.roots.successor == root
                    && close.roots.logs() == heads
            }) else {
                break;
            };
            canonical.insert(epoch, *close);
            tail = epoch.checked_sub(1).map(|previous| {
                (
                    previous,
                    *close.context.predecessor_root(),
                    *close.context.predecessor_logs(),
                )
            });
        }
        while let Some(close) = canonical.get(&next) {
            if *close.context.predecessor_root() != state.state().root() {
                break;
            }
            let candidate = state
                .prepare(
                    &state.head(),
                    close.mutations.clone(),
                    close.close.activity_input::<Sha256>(),
                    close.close.withdrawal_outputs().to_vec(),
                    close.context.floors(),
                )
                .await
                .expect("canonical retained mutations");
            state = state
                .apply(candidate)
                .await
                .expect("harness balance application");
            next += 1;
        }
        let response = match request.query {
            NativeQuery::Payouts(request) => state
                .logs()
                .payout_source()
                .serve(request)
                .await
                .map_or(NativeResponse::Unavailable, |(response, _)| {
                    NativeResponse::Data(response.encode())
                }),
            _ => NativeResponse::Unavailable,
        };
        self.genesis.insert(request.deployment, (state, next));
        response
    }

    /// Seals one block carrying `transactions` at the local clock reading
    /// `clock` (milliseconds since the Unix epoch) and certifies it.
    async fn seal(&mut self, clock: u64, transactions: Vec<SettlementTx>) -> u64 {
        let height = self.latest.as_ref().map_or(0, |latest| latest.height) + 1;
        let parent = self
            .latest
            .as_ref()
            .map_or(Digest::EMPTY, |latest| latest.digest);

        // The proposer timestamp rule: the local clock, floored one past the
        // parent so timestamps stay strictly monotonic.
        let timestamp = self
            .latest
            .as_ref()
            .map_or(0, |latest| latest.timestamp)
            .checked_add(1)
            .expect("harness timestamps fit u64")
            .max(clock);
        let batch = self.db.new_batches().await;
        let sealed = execute(
            batch,
            Height::new(height),
            timestamp,
            &self.timing,
            &self.native,
            &transactions,
        )
        .await
        .expect("harness block execution succeeds");
        let block = Block {
            context: Context {
                round: Round::new(Epoch::zero(), View::new(height)),
                leader: self.leader.clone(),
                parent: (View::zero(), Digest::EMPTY),
            },
            parent,
            height: Height::new(height),
            timestamp,
            state_root: sealed.root(),
            ops_root: sealed.ops_root(),
            range: non_empty_range!(sealed.sync_boundary(), sealed.bounds().tip.size),
            transactions,
        };
        self.db.apply(sealed).await;

        let proposal = Proposal {
            round: block.context.round,
            parent: View::zero(),
            payload: block.digest(),
        };
        let finalize = Finalize::sign(&self.scheme, proposal).expect("the harness committee signs");
        let finalization = Finalization::from_finalizes(
            &self.scheme,
            NonEmpty::try_new([&finalize].into_iter()).expect("one finalize is non-empty"),
            &Sequential,
        )
        .expect("the one-participant quorum assembles");
        self.latest = Some(Latest {
            height,
            timestamp,
            digest: block.digest(),
            block: block.encode(),
            finalization: finalization.encode(),
        });
        height
    }

    /// Serves one certified read at the latest sealed block.
    async fn read(&self, request: &ReadRequest) -> ReadResponse {
        let Some(latest) = &self.latest else {
            return ReadResponse::Unavailable;
        };
        let guard = self.db.read().await;
        let key = request.key();
        let proof = match guard.get(&key).await.expect("harness state read succeeds") {
            Some(record) => ReadProof::Present {
                proof: guard
                    .key_value_proof(key)
                    .await
                    .expect("present key proves"),
                record,
            },
            None => ReadProof::Absent {
                proof: guard
                    .exclusion_proof(&key)
                    .await
                    .expect("absent key proves"),
            },
        };
        let payout = if request.lookup.requires_payout_tip() {
            let key = crate::chain::state::payout_head_key(&request.deployment);
            let Some(Record::PayoutHead(head)) = guard.get(&key).await.unwrap() else {
                return ReadResponse::Unavailable;
            };
            Some(crate::chain::query::PayoutHeadProof {
                tip: head,
                proof: guard.key_value_proof(key).await.unwrap(),
            })
        } else {
            None
        };
        ReadResponse::Certified(CertifiedRead {
            finalization: latest.finalization.clone(),
            block: latest.block.clone(),
            proof,
            payout,
        })
    }

    /// Reconstructs a native replica from the simulation's validated closes and opens a proof.
    #[commonware_macros::boxed]
    async fn evidence(
        &mut self,
        context: &deterministic::Context,
        request: &EvidenceRequest,
    ) -> EvidenceResponse {
        let entry = {
            let db = self.db.read().await;
            match db
                .get(&registry_entry_key(
                    &self.native.chain_id(),
                    &request.deployment,
                ))
                .await
                .unwrap()
            {
                Some(Record::RegistryEntry(entry)) => entry,
                _ => return EvidenceResponse::Unknown,
            }
        };
        let (mut state, mut next) = match self.genesis.remove(&request.deployment) {
            Some(state) => state,
            None => {
                let state = crate::protocol::init_replica(
                    context.child("replica"),
                    &format!("{}-replica-{}", self.prefix, request.deployment),
                    Sequential,
                    genesis_balances(&entry.deployment).unwrap(),
                )
                .await
                .unwrap();
                (state, 0)
            }
        };
        let retained = retained_closes();
        let relevant = retained
            .iter()
            .filter(|close| close.context.deployment() == &request.deployment)
            .collect::<Vec<_>>();
        // Retained certified admissions fix the native roots and select the fixture prefix.
        let mut canonical = std::collections::BTreeMap::new();
        let mut tail = None;
        {
            let db = self.db.read().await;
            for close in &relevant {
                let epoch = close.context.payment().epoch();
                if let Some(Record::Admitted(admitted)) = db
                    .get(&admitted_key(&request.deployment, epoch))
                    .await
                    .unwrap()
                    && tail.is_none_or(|(latest, _, _)| epoch > latest)
                {
                    tail = Some((epoch, admitted.roots.successor, admitted.roots.logs()));
                }
            }
        }
        while let Some((epoch, root, heads)) = tail {
            let Some(close) = relevant.iter().find(|close| {
                close.context.payment().epoch() == epoch
                    && close.roots.successor == root
                    && close.roots.logs() == heads
            }) else {
                break;
            };
            canonical.insert(epoch, *close);
            tail = epoch.checked_sub(1).map(|previous| {
                (
                    previous,
                    *close.context.predecessor_root(),
                    *close.context.predecessor_logs(),
                )
            });
        }
        while let Some(close) = canonical.get(&next) {
            if *close.context.predecessor_root() != state.state().root() {
                break;
            }
            let candidate = state
                .prepare(
                    &state.head(),
                    close.mutations.clone(),
                    close.close.activity_input::<Sha256>(),
                    close.close.withdrawal_outputs().to_vec(),
                    close.context.floors(),
                )
                .await
                .expect("canonical retained mutations");
            assert_eq!(candidate.state().root(), close.roots.successor);
            assert_eq!(candidate.head().logs, close.roots.logs());
            state = state
                .apply(candidate)
                .await
                .expect("harness balance application");
            next += 1;
        }
        let response = match &request.lookup {
            EvidenceLookup::Payout { head, index } => match state
                .logs()
                .payout_opening(head, *index, std::num::NonZeroU64::MIN)
                .await
            {
                Ok((opening, outputs)) => match outputs.as_slice() {
                    [commonware_clearing::bajillion::logs::PayoutOperation::Append(output)] => {
                        EvidenceResponse::Served(Evidence::Payout(WithdrawalClaim::new(
                            output.clone(),
                            opening,
                        )))
                    }
                    _ => EvidenceResponse::Unsealed,
                },
                Err(_) => EvidenceResponse::Unsealed,
            },
            EvidenceLookup::State {
                root,
                operations,
                account,
            } => state
                .state()
                .lookup_at(*root, *operations, &account_key(account).unwrap())
                .await
                .map_or(EvidenceResponse::Unsealed, |lookup| {
                    EvidenceResponse::Served(Evidence::State(lookup))
                }),
            lookup => {
                let generated: anyhow::Result<Evidence> = async {
                    Ok(match lookup {
                        EvidenceLookup::Account {
                            epoch,
                            range,
                            account,
                        } => Evidence::Account(
                            CustodyEpoch::at(state.logs(), *epoch, *range)
                                .await?
                                .account_lookup(state.logs(), account)
                                .await?,
                        ),
                        EvidenceLookup::CommittedEntry {
                            epoch,
                            range,
                            payer,
                            recipient,
                            ..
                        } => Evidence::CommittedEntry(
                            CustodyEpoch::at(state.logs(), *epoch, *range)
                                .await?
                                .higher_entry_lookup(state.logs(), payer, recipient)
                                .await?,
                        ),
                        _ => unreachable!(),
                    })
                }
                .await;
                generated.map_or(EvidenceResponse::Unsealed, EvidenceResponse::Served)
            }
        };
        self.genesis.insert(request.deployment, (state, next));
        response
    }
}

/// Deals the one-participant committee and starts the chain: the actor task,
/// the query listener at `address`, and the idle ticker. Returns once the
/// genesis block is sealed and the listener is bound.
/// Deals a throwaway one-participant identity without starting a chain, for
/// tests that only need a verifier.
#[cfg(test)]
pub(crate) fn identity(rng: &mut impl rand_core::CryptoRng) -> Genesis {
    let signer = ed25519::PrivateKey::from_seed(4_242);
    let players = Set::from_iter_dedup([signer.public_key()]);
    let (identity, _) =
        deal::<MinSig, _, N3f1>(rng, SHARING_MODE, players).expect("the harness deal succeeds");
    Genesis::new(
        identity,
        0,
        Timing::DEFAULT,
        native(deployments()),
        validators(SocketAddr::from(([127, 0, 0, 1], 0))),
    )
}

/// The clearing committee with every member served at `address`: the harness
/// answers evidence for every validator, so the complete committee resolves to
/// it.
fn validators(address: SocketAddr) -> Vec<ValidatorEntry> {
    committee()
        .expect("the demo committee is statically valid")
        .members()
        .iter()
        .map(|clearing| ValidatorEntry {
            clearing: *clearing,
            query: address,
        })
        .collect()
}

pub(crate) async fn start(
    context: &deterministic::Context,
    address: SocketAddr,
    prefix: &str,
) -> Control {
    start_with(context, address, prefix, deployments()).await
}

/// Starts the harness chain configured with an explicit deployment set, for
/// tests that host several deployments on one in-process chain.
pub(crate) async fn start_with(
    context: &deterministic::Context,
    address: SocketAddr,
    prefix: &str,
    configured: Vec<Deployment>,
) -> Control {
    start_with_native(
        context,
        address,
        prefix,
        native(configured),
        crate::protocol::Timing::DEFAULT,
    )
    .await
}

/// Generates trusted native genesis for deterministic fixtures.
pub(crate) fn native(mut configured: Vec<Deployment>) -> NativeGenesis {
    deterministic::Runner::default().start(|context| async move {
        for deployment in &mut configured {
            deployment.generate(context.child("genesis")).await.unwrap();
        }
        let empty = crate::protocol::empty_genesis(context.child("empty"))
            .await
            .unwrap();
        native_genesis(
            configured
                .into_iter()
                .enumerate()
                .map(|(index, deployment)| RegistryEntry {
                    deployment,
                    network_key: ed25519::PrivateKey::from_seed(50_000 + index as u64).public_key(),
                    max_dealing_bytes: 4 * 1024 * 1024,
                })
                .collect(),
            &empty,
        )
    })
}

/// Starts a certified chain with explicit native allocations and resource policy.
pub(crate) async fn start_with_native(
    context: &deterministic::Context,
    address: SocketAddr,
    prefix: &str,
    native: NativeGenesis,
    timing: Timing,
) -> Control {
    let mut balances = BTreeMap::new();
    for entry in &native.deployments {
        let deployment = &entry.deployment;
        let state = crate::protocol::init_replica(
            context.child("replica"),
            &format!("{prefix}-replica-{}", deployment.digest()),
            Sequential,
            genesis_balances(deployment).unwrap(),
        )
        .await
        .unwrap();
        balances.insert(*deployment.digest(), (state, 0));
    }
    let mut rng = context.child("harness_rng");
    let signer = ed25519::PrivateKey::from_seed(4_242);
    let players = Set::from_iter_dedup([signer.public_key()]);
    let (identity, shares) = deal::<MinSig, _, N3f1>(&mut rng, SHARING_MODE, players)
        .expect("the harness deal succeeds");
    let identity = Genesis::new(
        identity,
        now(context),
        timing,
        native.clone(),
        validators(address),
    );
    let share = shares
        .get_value(&signer.public_key())
        .cloned()
        .expect("the dealer shares its one participant");
    let scheme = Scheme::signer(
        NAMESPACE,
        identity.players().clone(),
        identity.public().clone(),
        share,
    )
    .expect("the dealt share matches the harness committee");

    let page_cache = CacheRef::from_pooler(context, NZU16!(1024), NZUsize!(16));
    let db = <Database<deterministic::Context> as DatabaseSet<deterministic::Context>>::init(
        context.child("harness_db"),
        db_config(prefix, page_cache),
    )
    .await;
    let mut node = Node {
        db,
        scheme,
        leader: signer.public_key(),
        genesis: balances,
        native,
        timing,
        prefix: prefix.into(),
        latest: None,
        reads: 0,
        submissions: 0,
    };

    // Seal the first block before serving so every read is answerable.
    node.seal(now(context), Vec::new()).await;

    let (sender, mut mailbox) = mpsc::channel::<Message>(64);
    let control = Control {
        identity,
        sender: sender.clone(),
    };

    // The chain task: seals, reads, and the idle ticker in one owner.
    context.child("harness_chain").spawn({
        move |context| async move {
            let mut tick_at = context.current() + TICK;
            loop {
                select! {
                    _ = context.sleep_until(tick_at) => {
                        node.seal(now(&context), Vec::new()).await;
                        tick_at = context.current() + TICK;
                    },
                    message = mailbox.recv() => {
                        let Some(message) = message else {
                            return;
                        };
                        match message {
                            #[cfg(test)]
                            Message::SealBatch { transactions, response } => {
                                node.seal(now(&context), transactions).await;
                                tick_at = context.current() + TICK;
                                response.send_lossy(Block::decode_cfg(node.latest.as_ref().unwrap().block.clone(), &()).unwrap());
                            }

                            Message::Submit { tx, response } => {
                                node.submissions += 1;
                                let height = node.seal(now(&context), vec![*tx]).await;
                                tick_at = context.current() + TICK;
                                response.send_lossy(height);
                            }
                            #[cfg(test)]
                            Message::Advance { blocks, response } => {
                                let mut height = node
                                    .latest
                                    .as_ref()
                                    .map_or(0, |latest| latest.height);
                                for _ in 0..blocks {
                                    height = node.seal(now(&context), Vec::new()).await;
                                    tick_at = context.current() + TICK;
                                }
                                response.send_lossy(height);
                            }
                            Message::Read { request, response } => {
                                node.reads += 1;
                                response.send_lossy(node.read(&request).await);
                            }
                            Message::Evidence { request, response } => {
                                response.send_lossy(node.evidence(&context, &request).await);
                            }
                            Message::Native { request, response } => {
                                response.send_lossy(node.native(&context, request).await);
                            }
                            Message::Record { key, response } => {
                                let guard = node.db.read().await;
                                let record = guard
                                    .get(&key)
                                    .await
                                    .expect("harness state read succeeds");
                                response.send_lossy(record);
                            }
                            #[cfg(test)]
                            Message::Counts { response } => {
                                response.send_lossy((node.reads, node.submissions));
                            }
                        }
                    },
                }
            }
        }
    });

    // The query listener, speaking the real wire protocol.
    let listener_control = Control {
        identity: control.identity.clone(),
        sender,
    };
    let mut listener = context
        .bind(address)
        .await
        .expect("the harness query address binds");
    context
        .child("harness_query")
        .spawn(move |context| async move {
            loop {
                let Ok((_, mut sink, mut stream)) = listener.accept().await else {
                    context.sleep(rpc::ACCEPT_RETRY_DELAY).await;
                    continue;
                };
                let Ok(request) = rpc::recv_request(&mut stream).await else {
                    continue;
                };
                let response = match request.method {
                    METHOD_SUBMIT_TX => {
                        if request.body.len() > MAX_TX_BYTES {
                            respond(&Submission::Oversized)
                        } else {
                            match SettlementTx::decode_cfg(request.body, &()) {
                                Ok(tx) => {
                                    listener_control.submit(tx).await;
                                    respond(&Submission::Accepted)
                                }
                                Err(_) => {
                                    error_response("submitted transaction does not decode".into())
                                }
                            }
                        }
                    }
                    METHOD_READ => match ReadRequest::decode_cfg(request.body, &()) {
                        Ok(read) => respond(&listener_control.read(read).await),
                        Err(_) => error_response("read request does not decode".into()),
                    },
                    METHOD_EVIDENCE => match EvidenceRequest::decode_cfg(request.body, &()) {
                        Ok(evidence) => respond(&listener_control.evidence(evidence).await),
                        Err(_) => error_response("evidence request does not decode".into()),
                    },
                    METHOD_NATIVE => match NativeRequest::decode_cfg(request.body, &()) {
                        Ok(native) => respond(&listener_control.native(native).await),
                        Err(_) => error_response("native request does not decode".into()),
                    },
                    method => error_response(format!("unknown query method {method}")),
                };
                let _ = rpc::send_response(&mut sink, &response).await;
            }
        });
    control
}

fn respond(body: &impl commonware_codec::Encode) -> rpc::Response {
    rpc::Response::Success {
        body: body.encode(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{chain::query::Lookup, protocol::deployment};

    #[test]
    fn status_reads_do_not_postpone_empty_blocks() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let control = start(&context, SocketAddr::from(([127, 0, 0, 1], 9991)), "tick").await;
            let started = context.current();
            let request = ReadRequest::new(deployment(), Lookup::Status);
            let mut first = None;
            let mut last_height = 0;
            let mut last_read = started;
            for step in 0..=10 {
                context
                    .sleep_until(started + Duration::from_millis(step * 100))
                    .await;
                let ReadResponse::Certified(read) = control.read(request.clone()).await else {
                    panic!("the initialized harness must serve a certified read");
                };
                let block = Block::decode_cfg(read.block, &()).unwrap();
                first.get_or_insert(block.height.get());
                last_height = block.height.get();
                let completed = context.current();
                assert!(completed.duration_since(last_read).unwrap() < TICK);
                last_read = completed;
            }
            assert_eq!(control.counts().await, (11, 0));
            assert!(
                last_height >= first.unwrap() + 2,
                "reads suppressed empty blocks"
            );
        });
    }
}
