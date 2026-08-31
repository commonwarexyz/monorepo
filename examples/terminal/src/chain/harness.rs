//! In-process single-validator chain over the deterministic runtime.
//!
//! The harness executes real blocks through [`state::execute`] against a real
//! settlement database, certifies every block with a one-participant BLS
//! threshold committee dealt at startup, and serves the real query wire
//! protocol (`METHOD_SUBMIT_TX` and `METHOD_READ`), so [`crate::chain::client`]
//! runs against it unmodified. Submissions seal immediately into their own
//! block, and a background ticker seals empty blocks so deadlines and
//! finalization progress while clients poll.
//!
//! The scripted walkthrough uses it as the fraud arc's throwaway deployment,
//! and the wallet and operator tests use it as the settlement side.

use crate::{
    chain::{
        ingress::Submission,
        query::{
            CertifiedRead, METHOD_READ, METHOD_SUBMIT_TX, ReadProof, ReadRequest, ReadResponse,
            Submitted,
        },
        setup::Genesis,
        state::{Advice, Record, advise, execute},
        tx::SettlementTx,
        types::{Block, Database, MAX_TX_BYTES, StateKey, now},
        validator::{NAMESPACE, SHARING_MODE, Scheme, db_config},
    },
    protocol::{Deployment, Timing, deployments},
    rpc::{self, error_response},
};
use commonware_codec::{Decode as _, Encode as _, EncodeSize as _};
use commonware_consensus::{
    simplex::types::{Context, Finalization, Finalize, Proposal},
    types::{Epoch, Height, Round, View},
};
use commonware_cryptography::{
    Digest as _, Digestible as _, Signer as _,
    bls12381::{dkg::feldman_desmedt::deal, primitives::variant::MinSig},
    ed25519,
    sha256::Digest,
};
use commonware_glue::stateful::db::{DatabaseSet, Merkleized as _};
use commonware_macros::select;
use commonware_parallel::Sequential;
use commonware_runtime::{
    Clock as _, Listener as _, Network as _, Spawner as _, Supervisor as _,
    buffer::paged::CacheRef, deterministic,
};
use commonware_utils::{
    N3f1, NZU16, NZUsize,
    channel::{fallible::OneshotExt as _, mpsc, oneshot},
    iter::NonEmpty,
    non_empty_range,
    ordered::Set,
};
use std::{net::SocketAddr, time::Duration};

/// Idle block cadence: empty blocks seal at this interval so deadlines and
/// finalization progress while clients poll.
const TICK: Duration = Duration::from_millis(250);

/// One control message for the chain task.
#[allow(clippy::large_enum_variant)]
enum Message {
    /// Submit one transaction, sealing it into its own block. Answers the
    /// sealing height and the pre-inclusion dry-run advice.
    Submit {
        tx: Box<SettlementTx>,
        response: oneshot::Sender<(u64, Advice)>,
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
    /// The genesis threshold identity certified reads verify against.
    pub(crate) const fn identity(&self) -> &Genesis {
        &self.identity
    }

    /// Submits one transaction directly, returning the height that sealed it
    /// and the pre-inclusion dry-run advice.
    pub(crate) async fn submit(&self, tx: SettlementTx) -> (u64, Advice) {
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
    deployments: Vec<Deployment>,
    latest: Option<Latest>,
    reads: u64,
    submissions: u64,
}

impl Node {
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
            &Timing::DEFAULT,
            &self.deployments,
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
        ReadResponse::Certified(CertifiedRead {
            finalization: latest.finalization.clone(),
            block: latest.block.clone(),
            proof,
        })
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
    Genesis::new(identity, 0, Timing::DEFAULT, deployments())
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
    let mut rng = context.child("harness_rng");
    let signer = ed25519::PrivateKey::from_seed(4_242);
    let players = Set::from_iter_dedup([signer.public_key()]);
    let (identity, shares) = deal::<MinSig, _, N3f1>(&mut rng, SHARING_MODE, players)
        .expect("the harness deal succeeds");
    let identity = Genesis::new(identity, now(context), Timing::DEFAULT, configured.clone());
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
        deployments: configured,
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
            loop {
                select! {
                    message = mailbox.recv() => {
                        let Some(message) = message else {
                            return;
                        };
                        match message {
                            Message::Submit { tx, response } => {
                                node.submissions += 1;
                                let advice = advise(&node.db, &node.deployments, &tx)
                                    .await
                                    .expect("harness dry-run succeeds");
                                let height = node.seal(now(&context), vec![*tx]).await;
                                response.send_lossy((height, advice));
                            }
                            #[cfg(test)]
                            Message::Advance { blocks, response } => {
                                let mut height = node
                                    .latest
                                    .as_ref()
                                    .map_or(0, |latest| latest.height);
                                for _ in 0..blocks {
                                    height = node.seal(now(&context), Vec::new()).await;
                                }
                                response.send_lossy(height);
                            }
                            Message::Read { request, response } => {
                                node.reads += 1;
                                response.send_lossy(node.read(&request).await);
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
                    _ = context.sleep(TICK) => {
                        node.seal(now(&context), Vec::new()).await;
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
                            respond(&Submitted {
                                admission: Submission::Oversized,
                                advice: None,
                            })
                        } else {
                            match SettlementTx::decode_cfg(request.body, &()) {
                                Ok(tx) if tx.encode_size() <= MAX_TX_BYTES => {
                                    let (_, advice) = listener_control.submit(tx).await;
                                    respond(&Submitted {
                                        admission: Submission::Accepted,
                                        advice: Some(advice),
                                    })
                                }
                                Ok(_) => respond(&Submitted {
                                    admission: Submission::Oversized,
                                    advice: None,
                                }),
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
