//! Certified query server: transaction submission and certified reads.
//!
//! The server reuses the terminal's one-request/one-response framing (see
//! [`crate::rpc`]) with concurrent accepts and an async handler. It exposes
//! two methods:
//!
//! - [`METHOD_SUBMIT_TX`] feeds the ingress mailbox and returns the advisory
//!   [`Submitted`] answer: the queue admission result plus a typed dry-run
//!   verdict against the serving validator's latest applied state
//!   ([`crate::chain::state::advise`]). Both halves are unauthenticated UX
//!   advice: acceptance promises gossip and proposal attempts, never
//!   inclusion, and the authoritative answer is the submitter's certified
//!   read of the transaction's effect record (rejections are effect-free).
//! - [`METHOD_READ`] answers one [`ReadRequest`] with a [`CertifiedRead`]:
//!   the finalization certificate, the finalized block bytes, and a presence
//!   or absence proof against the block's canonical state root. The snapshot
//!   is consistent by construction: the database read guard is taken first,
//!   the served (height, digest, root) is resolved from the finalized index
//!   under that guard and checked against the database root, and the proof is
//!   generated before the guard drops. Clients verify with
//!   [`crate::chain::light`].
//!
//! Reads the finalized index or the marshal archives cannot answer yet return
//! the typed [`ReadResponse::Unavailable`] instead of an error.

use crate::{
    chain::{
        app::Finalized,
        ingress::{Mailbox as IngressMailbox, Submission},
        state::{
            Advice, Record, admitted_key, advise, anchor_key, claim_roots_key, deposit_key,
            fault_key, hard_fault_key, payout_release_key, refund_key, registration_key,
            status_key, withdrawal_key, withdrawal_release_key,
        },
        tx::SettlementTx,
        types::{Block, Database, Exclusion, MAX_TX_BYTES, Proof, StateKey},
    },
    protocol::{Deployment, Key},
    rpc::{self, ACCEPT_RETRY_DELAY, error_response},
};
use bytes::{Buf, BufMut, Bytes};
use commonware_clearing::bajillion::transition::BatchId;
use commonware_codec::{
    Decode as _, Encode as _, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt as _, Write,
};
use commonware_consensus::{
    marshal::{core::Mailbox as MarshalMailbox, standard::Standard},
    types::Height,
};
use commonware_cryptography::{certificate::Scheme, sha256::Digest};
use commonware_runtime::{Clock, Handle, Listener as _, Metrics, Network, Spawner};
use commonware_storage::Context as StorageContext;
use commonware_utils::Acknowledgement;
use std::net::SocketAddr;
use tracing::debug;

/// Submits one settlement transaction into the ingress queue.
pub(crate) const METHOD_SUBMIT_TX: u8 = 0;

/// Answers one certified read.
pub(crate) const METHOD_READ: u8 = 1;

/// Maximum Merkle digests accepted in one decoded proof.
pub(crate) const MAX_PROOF_DIGESTS: usize = 4_096;

/// Maximum encoded bytes accepted for one certified-read component.
pub(crate) const MAX_READ_BYTES: usize = rpc::MAX_BODY_SIZE / 2;

/// One certified-read lookup, covering one deployment's settlement read
/// surface: status, epoch roots (anchor plus admitted), claim roots, deposit
/// custody, the registration singleton, queued withdrawals, released claims,
/// the fault singleton, and terminal releases.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Lookup {
    /// The status singleton.
    Status,
    /// The registered payment anchor for one epoch.
    Anchor { epoch: u64 },
    /// The admitted close record for one epoch.
    Admitted { epoch: u64 },
    /// The claim roots of one finalized batch.
    ClaimRoots { batch: Digest },
    /// The custody record for one deposit id.
    Deposit { id: Digest },
    /// The registration singleton.
    Registration,
    /// The queued withdrawal for one account.
    Withdrawal { account: Key },
    /// One released withdrawal by (batch, position).
    WithdrawalRelease { batch: Digest, position: u32 },
    /// One released external payout by (batch, position).
    PayoutRelease { batch: Digest, position: u32 },
    /// One hard-fault release by account.
    HardFault { account: Key },
    /// One deposit refund by account.
    Refund { account: Key },
    /// The fault singleton.
    Fault,
}

/// One certified-read key request: the deployment whose records it reads
/// plus the lookup within that deployment's domains. Every read is
/// deployment-scoped: the requested key derives from the named deployment,
/// so a proof never answers for another deployment's records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReadRequest {
    pub(crate) deployment: Digest,
    pub(crate) lookup: Lookup,
}

impl ReadRequest {
    pub(crate) const fn new(deployment: Digest, lookup: Lookup) -> Self {
        Self { deployment, lookup }
    }

    /// The state key this request resolves to.
    pub(crate) fn key(&self) -> StateKey {
        let deployment = &self.deployment;
        match &self.lookup {
            Lookup::Status => status_key(deployment),
            Lookup::Anchor { epoch } => anchor_key(deployment, *epoch),
            Lookup::Admitted { epoch } => admitted_key(deployment, *epoch),
            Lookup::ClaimRoots { batch } => claim_roots_key(deployment, &BatchId::new(*batch)),
            Lookup::Deposit { id } => deposit_key(deployment, id),
            Lookup::Registration => registration_key(deployment),
            Lookup::Withdrawal { account } => withdrawal_key(deployment, account),
            Lookup::WithdrawalRelease { batch, position } => {
                withdrawal_release_key(deployment, &BatchId::new(*batch), *position)
            }
            Lookup::PayoutRelease { batch, position } => {
                payout_release_key(deployment, &BatchId::new(*batch), *position)
            }
            Lookup::HardFault { account } => hard_fault_key(deployment, account),
            Lookup::Refund { account } => refund_key(deployment, account),
            Lookup::Fault => fault_key(deployment),
        }
    }
}

impl Write for ReadRequest {
    fn write(&self, buf: &mut impl BufMut) {
        self.deployment.write(buf);
        self.lookup.write(buf);
    }
}

impl EncodeSize for ReadRequest {
    fn encode_size(&self) -> usize {
        self.deployment.encode_size() + self.lookup.encode_size()
    }
}

impl Read for ReadRequest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            deployment: Digest::read(buf)?,
            lookup: Lookup::read(buf)?,
        })
    }
}

impl Write for Lookup {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Status => 0_u8.write(buf),
            Self::Anchor { epoch } => {
                1_u8.write(buf);
                epoch.write(buf);
            }
            Self::Admitted { epoch } => {
                2_u8.write(buf);
                epoch.write(buf);
            }
            Self::ClaimRoots { batch } => {
                3_u8.write(buf);
                batch.write(buf);
            }
            Self::Deposit { id } => {
                4_u8.write(buf);
                id.write(buf);
            }
            Self::Registration => 5_u8.write(buf),
            Self::Withdrawal { account } => {
                6_u8.write(buf);
                account.write(buf);
            }
            Self::WithdrawalRelease { batch, position } => {
                7_u8.write(buf);
                batch.write(buf);
                position.write(buf);
            }
            Self::PayoutRelease { batch, position } => {
                8_u8.write(buf);
                batch.write(buf);
                position.write(buf);
            }
            Self::HardFault { account } => {
                9_u8.write(buf);
                account.write(buf);
            }
            Self::Refund { account } => {
                10_u8.write(buf);
                account.write(buf);
            }
            Self::Fault => 11_u8.write(buf),
        }
    }
}

impl EncodeSize for Lookup {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Status | Self::Registration | Self::Fault => 0,
            Self::Anchor { epoch } | Self::Admitted { epoch } => epoch.encode_size(),
            Self::ClaimRoots { batch } => batch.encode_size(),
            Self::Deposit { id } => id.encode_size(),
            Self::WithdrawalRelease { batch, position }
            | Self::PayoutRelease { batch, position } => {
                batch.encode_size() + position.encode_size()
            }
            Self::Withdrawal { account }
            | Self::HardFault { account }
            | Self::Refund { account } => account.encode_size(),
        }
    }
}

impl Read for Lookup {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::Status),
            1 => Ok(Self::Anchor {
                epoch: u64::read(buf)?,
            }),
            2 => Ok(Self::Admitted {
                epoch: u64::read(buf)?,
            }),
            3 => Ok(Self::ClaimRoots {
                batch: Digest::read(buf)?,
            }),
            4 => Ok(Self::Deposit {
                id: Digest::read(buf)?,
            }),
            5 => Ok(Self::Registration),
            6 => Ok(Self::Withdrawal {
                account: Key::read(buf)?,
            }),
            7 => Ok(Self::WithdrawalRelease {
                batch: Digest::read(buf)?,
                position: u32::read(buf)?,
            }),
            8 => Ok(Self::PayoutRelease {
                batch: Digest::read(buf)?,
                position: u32::read(buf)?,
            }),
            9 => Ok(Self::HardFault {
                account: Key::read(buf)?,
            }),
            10 => Ok(Self::Refund {
                account: Key::read(buf)?,
            }),
            11 => Ok(Self::Fault),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

/// Presence or absence proof for one requested key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ReadProof {
    /// The key holds `record`, proven present.
    Present { record: Record, proof: Proof },
    /// The key is proven absent.
    Absent { proof: Exclusion },
}

impl Write for ReadProof {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Present { record, proof } => {
                0_u8.write(buf);
                record.write(buf);
                proof.write(buf);
            }
            Self::Absent { proof } => {
                1_u8.write(buf);
                proof.write(buf);
            }
        }
    }
}

impl EncodeSize for ReadProof {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Present { record, proof } => record.encode_size() + proof.encode_size(),
            Self::Absent { proof } => proof.encode_size(),
        }
    }
}

impl Read for ReadProof {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::Present {
                record: Record::read(buf)?,
                proof: Proof::read_cfg(buf, &(MAX_PROOF_DIGESTS, ()))?,
            }),
            1 => Ok(Self::Absent {
                proof: Exclusion::read_cfg(buf, &(MAX_PROOF_DIGESTS, ((), ()), ()))?,
            }),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

/// One certified read: the finalization certificate, the finalized block
/// bytes, and a proof against the block's canonical state root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CertifiedRead {
    /// Encoded simplex finalization certifying the block.
    pub(crate) finalization: Bytes,
    /// Encoded chain block.
    pub(crate) block: Bytes,
    /// Presence or absence proof for the requested key.
    pub(crate) proof: ReadProof,
}

impl Write for CertifiedRead {
    fn write(&self, buf: &mut impl BufMut) {
        self.finalization.write(buf);
        self.block.write(buf);
        self.proof.write(buf);
    }
}

impl EncodeSize for CertifiedRead {
    fn encode_size(&self) -> usize {
        self.finalization.encode_size() + self.block.encode_size() + self.proof.encode_size()
    }
}

impl Read for CertifiedRead {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            finalization: Bytes::read_cfg(buf, &RangeCfg::new(0..=MAX_READ_BYTES))?,
            block: Bytes::read_cfg(buf, &RangeCfg::new(0..=MAX_READ_BYTES))?,
            proof: ReadProof::read(buf)?,
        })
    }
}

/// One certified-read response.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum ReadResponse {
    /// The certified read.
    Certified(CertifiedRead),
    /// The snapshot needed for a certified answer is not available yet: no
    /// block has finalized, the applied state is ahead of the finalized
    /// index, or the marshal archives lack the height. Retry later.
    Unavailable,
}

impl Write for ReadResponse {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Certified(read) => {
                0_u8.write(buf);
                read.write(buf);
            }
            Self::Unavailable => 1_u8.write(buf),
        }
    }
}

impl EncodeSize for ReadResponse {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Certified(read) => read.encode_size(),
            Self::Unavailable => 0,
        }
    }
}

impl Read for ReadResponse {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::Certified(CertifiedRead::read(buf)?)),
            1 => Ok(Self::Unavailable),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

/// The advisory answer to one submission: the queue admission result plus a
/// dry-run verdict when the answering path holds applied state to peek at.
///
/// Both halves are unauthenticated UX advice, never authorization or
/// evidence: the authoritative answer is a certified read of the
/// transaction's effect record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Submitted {
    pub(crate) admission: Submission,
    /// Dry-run verdict against the answering validator's latest applied
    /// state, or `None` for paths that assess nothing (p2p submission).
    pub(crate) advice: Option<Advice>,
}

impl Write for Submitted {
    fn write(&self, buf: &mut impl BufMut) {
        self.admission.write(buf);
        self.advice.write(buf);
    }
}

impl EncodeSize for Submitted {
    fn encode_size(&self) -> usize {
        self.admission.encode_size() + self.advice.encode_size()
    }
}

impl Read for Submitted {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            admission: Submission::read(buf)?,
            advice: Option::<Advice>::read(buf)?,
        })
    }
}

/// Query server configuration.
pub(crate) struct Config<E, S, A>
where
    E: StorageContext + Spawner,
    S: Scheme,
    A: Acknowledgement,
{
    /// Listen address.
    pub(crate) address: SocketAddr,
    /// The configured deployment set the dry-run advises against.
    pub(crate) deployments: Vec<Deployment>,
    /// The applied settlement database.
    pub(crate) db: Database<E>,
    /// The finalized (height, digest, root) index maintained by the app.
    pub(crate) finalized: Finalized,
    /// Marshal mailbox serving finalizations and blocks.
    pub(crate) marshal: MarshalMailbox<S, Standard<Block>>,
    /// Ingress mailbox receiving local submissions.
    pub(crate) ingress: IngressMailbox<A>,
}

/// Starts the query server: concurrent accepts with one bounded request per
/// connection.
pub(crate) fn start<E, S, A>(context: E, config: Config<E, S, A>) -> Handle<()>
where
    E: Clock + Network + Spawner + Metrics + StorageContext,
    S: Scheme,
    A: Acknowledgement,
{
    context.spawn(move |context| run(context, config))
}

async fn run<E, S, A>(context: E, config: Config<E, S, A>)
where
    E: Clock + Network + Spawner + Metrics + StorageContext,
    S: Scheme,
    A: Acknowledgement,
{
    let mut listener = match context.bind(config.address).await {
        Ok(listener) => listener,
        Err(error) => {
            tracing::error!(?error, address = %config.address, "query server failed to bind");
            return;
        }
    };
    loop {
        let (_, mut sink, mut stream) = match listener.accept().await {
            Ok(connection) => connection,
            Err(error) => {
                debug!(?error, "query accept failed; retrying");
                context.sleep(ACCEPT_RETRY_DELAY).await;
                continue;
            }
        };
        let deployments = config.deployments.clone();
        let db = config.db.clone();
        let finalized = config.finalized.clone();
        let marshal = config.marshal.clone();
        let ingress = config.ingress.clone();
        context.child("connection").spawn(move |_| async move {
            let Ok(request) = rpc::recv_request(&mut stream).await else {
                return;
            };
            let response = handle(&deployments, &db, &finalized, &marshal, &ingress, request).await;
            let _ = rpc::send_response(&mut sink, &response).await;
        });
    }
}

/// Handles one decoded request.
async fn handle<E, S, A>(
    deployments: &[Deployment],
    db: &Database<E>,
    finalized: &Finalized,
    marshal: &MarshalMailbox<S, Standard<Block>>,
    ingress: &IngressMailbox<A>,
    request: rpc::Request,
) -> rpc::Response
where
    E: StorageContext + Spawner,
    S: Scheme,
    A: Acknowledgement,
{
    match request.method {
        METHOD_SUBMIT_TX => {
            if request.body.len() > MAX_TX_BYTES {
                return respond(&Submitted {
                    admission: Submission::Oversized,
                    advice: None,
                });
            }
            let Ok(tx) = SettlementTx::decode_cfg(request.body, &()) else {
                return error_response("submitted transaction does not decode".into());
            };
            let advice = match advise(db, deployments, &tx).await {
                Ok(advice) => advice,
                Err(error) => return error_response(format!("dry-run failed: {error}")),
            };
            respond(&Submitted {
                admission: ingress.submit(tx).await,
                advice: Some(advice),
            })
        }
        METHOD_READ => {
            let Ok(request) = ReadRequest::decode_cfg(request.body, &()) else {
                return error_response("read request does not decode".into());
            };
            match read(db, finalized, marshal, &request).await {
                Ok(response) => respond(&response),
                Err(error) => error_response(format!("read failed: {error}")),
            }
        }
        method => error_response(format!("unknown query method {method}")),
    }
}

fn respond(body: &impl commonware_codec::Encode) -> rpc::Response {
    rpc::Response::Success {
        body: body.encode(),
    }
}

/// Serves one certified read from a consistent snapshot.
async fn read<E, S>(
    db: &Database<E>,
    finalized: &Finalized,
    marshal: &MarshalMailbox<S, Standard<Block>>,
    request: &ReadRequest,
) -> anyhow::Result<ReadResponse>
where
    E: StorageContext + Spawner,
    S: Scheme,
{
    // The read guard pins the applied database while the finalized index
    // entry is resolved and the proof is generated, so both describe one
    // canonical root. Certificate fetches happen after the guard drops:
    // finalizations are immutable per height, so consistency is preserved
    // without holding the database against writers.
    let (height, digest, proof) = {
        let guard = db.read().await;
        let Some(tip) = finalized.latest() else {
            return Ok(ReadResponse::Unavailable);
        };

        // The applied database runs ahead of the finalized index between
        // apply and the finalized hook. Decline instead of serving a proof
        // that would not verify against the served finalization.
        if guard.root() != tip.root {
            return Ok(ReadResponse::Unavailable);
        }
        let key = request.key();
        let proof = match guard.get(&key).await? {
            Some(record) => ReadProof::Present {
                proof: guard.key_value_proof(key).await?,
                record,
            },
            None => ReadProof::Absent {
                proof: guard.exclusion_proof(&key).await?,
            },
        };
        (tip.height, tip.digest, proof)
    };
    let Some(finalization) = marshal.get_finalization(Height::new(height)).await else {
        return Ok(ReadResponse::Unavailable);
    };
    let Some(block) = marshal.get_block(&digest).await else {
        return Ok(ReadResponse::Unavailable);
    };
    Ok(ReadResponse::Certified(CertifiedRead {
        finalization: finalization.encode(),
        block: block.encode(),
        proof,
    }))
}
