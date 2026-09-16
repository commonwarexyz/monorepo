//! Certified query server: transaction submission and certified reads.
//!
//! The server reuses the terminal's one-request/one-response framing (see
//! [`crate::rpc`]) with concurrent accepts and an async handler. It exposes
//! three methods:
//!
//! - [`METHOD_SUBMIT_TX`] submits owned bytes for ingress qualification and
//!   returns an advisory [`crate::chain::ingress::Submission`]. Clients resolve
//!   execution through
//!   certified effect records; accepted requests can become stale before inclusion.
//! - [`METHOD_READ`] answers one [`ReadRequest`] with a [`CertifiedRead`]:
//!   the finalization certificate, the finalized block bytes, and a presence
//!   or absence proof against the block's canonical state root. The snapshot
//!   is consistent by construction: the database read guard is taken first,
//!   the served (height, digest, root) is resolved from the finalized index
//!   under that guard and checked against the database root, and the proof is
//!   generated before the guard drops. Clients verify with
//!   [`crate::chain::light`].
//! - [`METHOD_EVIDENCE`] answers one [`EvidenceRequest`] with an
//!   [`EvidenceResponse`] from the validator's native QMDBs (see
//!   [`crate::chain::da`]): state, activity, and payout proofs. Every served opening
//!   verifies against certified roots the client already holds, so nothing
//!   here is trusted unverified.
//!
//! Reads the finalized index or the marshal archives cannot answer yet return
//! the typed [`ReadResponse::Unavailable`] instead of an error.

use crate::{
    chain::{
        app::Finalized,
        da::Mailbox as SealerMailbox,
        ingress::Mailbox as IngressMailbox,
        state::{
            Record, admitted_key, anchor_key, deposit_key, fault_key, hard_fault_key,
            native_balance_key, native_transfer_key, payout_head_key, refund_key, registration_key,
            registry_entry_key, registry_key, status_key, unclaimed_key, withdrawal_key,
        },
        types::{Block, Database, Exclusion, Proof, StateKey},
    },
    protocol::Key,
    rpc::{self, ACCEPT_RETRY_DELAY, error_response},
};
use bytes::{BufMut, Bytes};
use commonware_clearing::bajillion::{
    challenge::{AccountLookup, HigherEntryLookup},
    logs::LogHead,
    qmdb::{StateLookup, StateRoot},
    transition::{ActivityRange, WithdrawalClaim},
};
use commonware_codec::{
    Buf, Decode as _, DecodeExt as _, Encode as _, EncodeSize, Error as CodecError, RangeCfg, Read,
    ReadExt as _, Write,
};
use commonware_consensus::{
    marshal::{core::Mailbox as MarshalMailbox, standard::Standard},
    types::Height,
};
use commonware_cryptography::{certificate::Scheme, sha256::Digest};
use commonware_macros::select;
use commonware_runtime::{Clock, Handle, Listener as _, Metrics, Network, Spawner};
use commonware_storage::Context as StorageContext;
use commonware_utils::Acknowledgement;
use futures::{FutureExt as _, StreamExt as _, stream::FuturesUnordered};
use std::net::SocketAddr;
use tracing::debug;

#[cfg(test)]
mod source_frame;

/// Submits one settlement transaction into the ingress queue.
pub(crate) const METHOD_SUBMIT_TX: u8 = 0;

/// Answers one certified read.
pub(crate) const METHOD_READ: u8 = 1;

/// Answers one proof request from the validator's retained native operations.
pub(crate) const METHOD_EVIDENCE: u8 = 2;

/// Maximum Merkle digests accepted in one decoded proof.
pub(crate) const MAX_PROOF_DIGESTS: usize = 4_096;

/// Maximum encoded bytes accepted for one certified-read component.
pub(crate) const MAX_READ_BYTES: usize = rpc::MAX_BODY_SIZE / 2;

/// One certified read of deployment settlement state or shared native funds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Lookup {
    /// Shared native funds under the immutable chain domain.
    NativeBalance { chain_id: Digest, account: Key },
    /// The bounded directory of registered deployment IDs.
    Registry { chain_id: Digest },
    /// One immutable deployment configuration and its authenticated genesis allocations.
    RegistryEntry {
        chain_id: Digest,
        deployment: Digest,
    },
    /// The successful native transfer with this replay identity.
    NativeTransfer {
        chain_id: Digest,
        from: Key,
        id: Digest,
    },
    /// The status singleton.
    Status,
    /// The registered payment anchor for one epoch.
    Anchor { epoch: u64 },
    /// The admitted close record for one epoch.
    Admitted { epoch: u64 },
    /// The paired finalized activity and payout commitments.
    PayoutHead,
    /// The custody record for one deposit id.
    Deposit { id: Digest },
    /// The registration singleton.
    Registration,
    /// The latest accepted withdrawal receipt, retained after carriage.
    Withdrawal { account: Key },
    /// The interval containing this native payout index, if still unclaimed.
    Unclaimed { index: u64 },
    /// One hard-fault release by account.
    HardFault { account: Key },
    /// One deposit refund by account and settlement phase.
    Refund { account: Key, terminal: bool },
    /// The fault singleton.
    Fault,
}

impl Lookup {
    /// Reads whose interpretation depends on the same finalized log boundary.
    pub(crate) const fn requires_payout_tip(&self) -> bool {
        matches!(
            self,
            Self::Unclaimed { .. } | Self::Anchor { .. } | Self::Admitted { .. } | Self::Fault
        )
    }
}

/// One certified read. Clearing keys bind the named deployment; shared native
/// keys bind the lookup's immutable chain identity and account or replay identifier.
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
            Lookup::NativeBalance { chain_id, account } => native_balance_key(chain_id, account),
            Lookup::Registry { chain_id } => registry_key(chain_id),
            Lookup::RegistryEntry {
                chain_id,
                deployment,
            } => registry_entry_key(chain_id, deployment),
            Lookup::NativeTransfer { chain_id, from, id } => {
                native_transfer_key(chain_id, from, id)
            }
            Lookup::Status => status_key(deployment),
            Lookup::Anchor { epoch } => anchor_key(deployment, *epoch),
            Lookup::Admitted { epoch } => admitted_key(deployment, *epoch),
            Lookup::PayoutHead => payout_head_key(deployment),
            Lookup::Deposit { id } => deposit_key(deployment, id),
            Lookup::Registration => registration_key(deployment),
            Lookup::Withdrawal { account } => withdrawal_key(deployment, account),
            Lookup::Unclaimed { index } => unclaimed_key(deployment, *index),
            Lookup::HardFault { account } => hard_fault_key(deployment, account),
            Lookup::Refund { account, terminal } => refund_key(deployment, account, *terminal),
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
            Self::PayoutHead => 3_u8.write(buf),
            Self::Deposit { id } => {
                4_u8.write(buf);
                id.write(buf);
            }
            Self::Registration => 5_u8.write(buf),
            Self::Withdrawal { account } => {
                6_u8.write(buf);
                account.write(buf);
            }
            Self::Unclaimed { index } => {
                7_u8.write(buf);
                index.write(buf);
            }
            Self::HardFault { account } => {
                9_u8.write(buf);
                account.write(buf);
            }
            Self::Refund { account, terminal } => {
                10_u8.write(buf);
                account.write(buf);
                terminal.write(buf);
            }
            Self::Fault => 11_u8.write(buf),
            Self::NativeBalance { chain_id, account } => {
                12_u8.write(buf);
                chain_id.write(buf);
                account.write(buf);
            }
            Self::Registry { chain_id } => {
                13_u8.write(buf);
                chain_id.write(buf);
            }
            Self::RegistryEntry {
                chain_id,
                deployment,
            } => {
                15_u8.write(buf);
                chain_id.write(buf);
                deployment.write(buf);
            }
            Self::NativeTransfer { chain_id, from, id } => {
                14_u8.write(buf);
                chain_id.write(buf);
                from.write(buf);
                id.write(buf);
            }
        }
    }
}

impl EncodeSize for Lookup {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::NativeBalance { chain_id, account } => {
                chain_id.encode_size() + account.encode_size()
            }
            Self::Registry { chain_id } => chain_id.encode_size(),
            Self::RegistryEntry {
                chain_id,
                deployment,
            } => chain_id.encode_size() + deployment.encode_size(),
            Self::NativeTransfer { chain_id, from, id } => {
                chain_id.encode_size() + from.encode_size() + id.encode_size()
            }
            Self::Status | Self::Registration | Self::Fault | Self::PayoutHead => 0,
            Self::Anchor { epoch } | Self::Admitted { epoch } => epoch.encode_size(),
            Self::Deposit { id } => id.encode_size(),
            Self::Unclaimed { index } => index.encode_size(),
            Self::Withdrawal { account } | Self::HardFault { account } => account.encode_size(),
            Self::Refund { account, terminal } => account.encode_size() + terminal.encode_size(),
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
            3 => Ok(Self::PayoutHead),
            4 => Ok(Self::Deposit {
                id: Digest::read(buf)?,
            }),
            5 => Ok(Self::Registration),
            6 => Ok(Self::Withdrawal {
                account: Key::read(buf)?,
            }),
            7 => Ok(Self::Unclaimed {
                index: u64::read(buf)?,
            }),
            9 => Ok(Self::HardFault {
                account: Key::read(buf)?,
            }),
            10 => Ok(Self::Refund {
                account: Key::read(buf)?,
                terminal: bool::read(buf)?,
            }),
            11 => Ok(Self::Fault),
            12 => Ok(Self::NativeBalance {
                chain_id: Digest::read(buf)?,
                account: Key::read(buf)?,
            }),
            13 => Ok(Self::Registry {
                chain_id: Digest::read(buf)?,
            }),
            14 => Ok(Self::NativeTransfer {
                chain_id: Digest::read(buf)?,
                from: Key::read(buf)?,
                id: Digest::read(buf)?,
            }),
            15 => Ok(Self::RegistryEntry {
                chain_id: Digest::read(buf)?,
                deployment: Digest::read(buf)?,
            }),
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

impl ReadProof {
    /// Interprets a verified ordered proof at a payout index as interval coverage.
    pub(crate) fn unclaimed(
        &self,
        request: &ReadRequest,
    ) -> Option<commonware_clearing::bajillion::settlement::UnclaimedInterval> {
        let Lookup::Unclaimed { index } = request.lookup else {
            return None;
        };
        let (start, end) = match self {
            Self::Present {
                record: Record::Unclaimed(end),
                ..
            } => (index, *end),
            Self::Absent {
                proof: Exclusion::KeyValue(_, update),
            } => {
                let start = crate::chain::state::unclaimed_start(&request.deployment, &update.key)?;
                let Record::Unclaimed(end) = update.value else {
                    return None;
                };
                (start, end)
            }
            _ => return None,
        };
        (start <= index && index < end)
            .then_some(commonware_clearing::bajillion::settlement::UnclaimedInterval { start, end })
    }
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

/// The finalized payout identity proven at the same chain root as a settlement lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PayoutHeadProof {
    pub(crate) tip: crate::protocol::PayoutTip,
    pub(crate) proof: Proof,
}
impl Write for PayoutHeadProof {
    fn write(&self, buf: &mut impl BufMut) {
        self.tip.write(buf);
        self.proof.write(buf);
    }
}
impl EncodeSize for PayoutHeadProof {
    fn encode_size(&self) -> usize {
        self.tip.encode_size() + self.proof.encode_size()
    }
}
impl Read for PayoutHeadProof {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            tip: crate::protocol::PayoutTip::read(buf)?,
            proof: Proof::read_cfg(buf, &(MAX_PROOF_DIGESTS, ()))?,
        })
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
    pub(crate) payout: Option<PayoutHeadProof>,
}

impl Write for CertifiedRead {
    fn write(&self, buf: &mut impl BufMut) {
        self.finalization.write(buf);
        self.block.write(buf);
        self.proof.write(buf);
        self.payout.write(buf);
    }
}

impl EncodeSize for CertifiedRead {
    fn encode_size(&self) -> usize {
        self.finalization.encode_size()
            + self.block.encode_size()
            + self.proof.encode_size()
            + self.payout.encode_size()
    }
}

impl Read for CertifiedRead {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            finalization: Bytes::read_cfg(buf, &RangeCfg::new(0..=MAX_READ_BYTES))?,
            block: Bytes::read_cfg(buf, &RangeCfg::new(0..=MAX_READ_BYTES))?,
            proof: ReadProof::read(buf)?,
            payout: Option::<PayoutHeadProof>::read(buf)?,
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

/// One proof lookup against retained native QMDB operations.
///
/// Root and range authority belongs to the caller. Only candidate certification names a batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum EvidenceLookup {
    /// A Current proof at the requested root and native operation boundary.
    State {
        root: StateRoot<Digest>,
        operations: u64,
        account: Key,
    },
    /// A payer's committed outgoing entry or its authenticated absence.
    CommittedEntry {
        epoch: u64,
        range: ActivityRange<Digest>,
        payer: Key,
        recipient: Key,
    },
    /// The account activity lookup within an independently authenticated epoch range.
    Account {
        epoch: u64,
        range: ActivityRange<Digest>,
        account: Key,
    },
    /// A native payout at the supplied finalized head and global index.
    Payout { head: LogHead<Digest>, index: u64 },
}
impl Write for EvidenceLookup {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::State {
                root,
                operations,
                account,
            } => {
                0u8.write(buf);
                root.write(buf);
                operations.write(buf);
                account.write(buf);
            }
            Self::CommittedEntry {
                epoch,
                range,
                payer,
                recipient,
            } => {
                3u8.write(buf);
                epoch.write(buf);
                range.write(buf);
                payer.write(buf);
                recipient.write(buf);
            }
            Self::Account {
                epoch,
                range,
                account,
            } => {
                4u8.write(buf);
                epoch.write(buf);
                range.write(buf);
                account.write(buf);
            }
            Self::Payout { head, index } => {
                10u8.write(buf);
                head.write(buf);
                index.write(buf);
            }
        }
    }
}
impl EncodeSize for EvidenceLookup {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::State {
                root,
                operations,
                account,
            } => root.encode_size() + operations.encode_size() + account.encode_size(),
            Self::CommittedEntry {
                epoch,
                range,
                payer,
                recipient,
            } => {
                epoch.encode_size()
                    + range.encode_size()
                    + payer.encode_size()
                    + recipient.encode_size()
            }
            Self::Account {
                epoch,
                range,
                account,
            } => epoch.encode_size() + range.encode_size() + account.encode_size(),
            Self::Payout { head, index } => head.encode_size() + index.encode_size(),
        }
    }
}
impl Read for EvidenceLookup {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::State {
                root: StateRoot::read(buf)?,
                operations: u64::read(buf)?,
                account: Key::read(buf)?,
            }),
            3 => Ok(Self::CommittedEntry {
                epoch: u64::read(buf)?,
                range: ActivityRange::read(buf)?,
                payer: Key::read(buf)?,
                recipient: Key::read(buf)?,
            }),
            4 => Ok(Self::Account {
                epoch: u64::read(buf)?,
                range: ActivityRange::read(buf)?,
                account: Key::read(buf)?,
            }),
            10 => Ok(Self::Payout {
                head: LogHead::read(buf)?,
                index: u64::read(buf)?,
            }),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

/// One evidence request: the deployment whose native operations it reads plus
/// the lookup within them. A validator serving several deployments routes by
/// the digest to the corresponding native replica.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EvidenceRequest {
    pub(crate) deployment: Digest,
    pub(crate) lookup: EvidenceLookup,
}

impl EvidenceRequest {
    pub(crate) const fn new(deployment: Digest, lookup: EvidenceLookup) -> Self {
        Self { deployment, lookup }
    }
}

impl Write for EvidenceRequest {
    fn write(&self, buf: &mut impl BufMut) {
        self.deployment.write(buf);
        self.lookup.write(buf);
    }
}

impl EncodeSize for EvidenceRequest {
    fn encode_size(&self) -> usize {
        self.deployment.encode_size() + self.lookup.encode_size()
    }
}

impl Read for EvidenceRequest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            deployment: Digest::read(buf)?,
            lookup: EvidenceLookup::read(buf)?,
        })
    }
}

/// Native proofs and bounded candidate certification evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum Evidence {
    /// Current membership or absence under an independently trusted root and key.
    State(StateLookup<Digest>),
    /// Account activity under an independently authenticated epoch range.
    Account(AccountLookup<Key, Digest>),
    /// A payer's terminal entry under an independently authenticated epoch range.
    CommittedEntry(HigherEntryLookup<Key, Digest>),
    /// A payout opened under the caller's independently trusted payout head.
    Payout(WithdrawalClaim<Digest>),
}
impl Write for Evidence {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::State(value) => {
                1u8.write(buf);
                value.write(buf);
            }
            Self::Account(value) => {
                2u8.write(buf);
                value.write(buf);
            }
            Self::CommittedEntry(value) => {
                3u8.write(buf);
                value.write(buf);
            }
            Self::Payout(value) => {
                4u8.write(buf);
                value.write(buf);
            }
        }
    }
}
impl EncodeSize for Evidence {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::State(value) => value.encode_size(),
            Self::Account(value) => value.encode_size(),
            Self::CommittedEntry(value) => value.encode_size(),
            Self::Payout(value) => value.encode_size(),
        }
    }
}
impl Read for Evidence {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            1 => Ok(Self::State(StateLookup::read_cfg(buf, &MAX_PROOF_DIGESTS)?)),
            2 => Ok(Self::Account(AccountLookup::read(buf)?)),
            3 => Ok(Self::CommittedEntry(HigherEntryLookup::read(buf)?)),
            4 => Ok(Self::Payout(WithdrawalClaim::read_cfg(
                buf,
                &RangeCfg::new(..=crate::protocol::MAX_DESTINATION_BYTES),
            )?)),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

/// One evidence response.
///
/// Only [`Self::Served`] carries anything verifiable. The other answers are
/// unauthenticated routing advice: a client that cannot get an answer from
/// one holder asks the next committee member.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum EvidenceResponse {
    /// The requested evidence.
    Served(Evidence),
    /// This validator has not retained the requested close.
    Unsealed,
    /// The deployment is not served by this validator.
    Unknown,
    /// The requested activity or claim is unavailable. This is routing advice,
    /// not authenticated absence; state absence has a verifiable proof.
    Absent,
}

impl Write for EvidenceResponse {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Served(evidence) => {
                0_u8.write(buf);
                evidence.write(buf);
            }
            Self::Unsealed => 2_u8.write(buf),
            Self::Unknown => 4_u8.write(buf),
            Self::Absent => 5_u8.write(buf),
        }
    }
}

impl EncodeSize for EvidenceResponse {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Served(evidence) => evidence.encode_size(),
            Self::Unsealed | Self::Unknown | Self::Absent => 0,
        }
    }
}

impl Read for EvidenceResponse {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::Served(Evidence::read(buf)?)),
            2 => Ok(Self::Unsealed),
            4 => Ok(Self::Unknown),
            5 => Ok(Self::Absent),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

/// The frontend buffers at most 16 request frames (4 MiB each). Ingress owns
/// separately bounded work after handoff. Shared limits do not guarantee public
/// availability under an unlimited unauthenticated connection flood.
pub(super) const MAX_CONNECTIONS: usize = 16;
pub(super) const REQUEST_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Query server configuration.
pub(crate) struct Config<E, S, A>
where
    E: StorageContext + Spawner,
    S: Scheme,
    A: Acknowledgement,
{
    /// Listen address.
    pub(crate) address: SocketAddr,
    /// The applied settlement database.
    pub(crate) db: Database<E>,
    /// The finalized (height, digest, root) index maintained by the app.
    pub(crate) finalized: Finalized,
    /// Marshal mailbox serving finalizations and blocks.
    pub(crate) marshal: MarshalMailbox<S, Standard<Block>>,
    /// Ingress mailbox receiving local submissions.
    pub(crate) ingress: IngressMailbox<A>,
    /// The sealer serving evidence from retained native operations, or `None`
    /// where no sealer runs (evidence requests are then refused). The sealer
    /// stops when the last clone of this mailbox is dropped, so the mailbox
    /// must outlive the sealer.
    pub(crate) sealer: Option<SealerMailbox>,
}

/// Starts the query server: concurrent accepts with one bounded request per
/// connection.
pub(crate) fn start<E, S, A>(context: E, config: Config<E, S, A>) -> Handle<()>
where
    E: Clock + Network + Spawner + Metrics + StorageContext,
    S: Scheme,
    A: Acknowledgement,
{
    let address = config.address;
    start_server(context, address, move |request| {
        let db = config.db.clone();
        let finalized = config.finalized.clone();
        let marshal = config.marshal.clone();
        let ingress = config.ingress.clone();
        let sealer = config.sealer.clone();
        async move {
            handle(
                &db,
                &finalized,
                &marshal,
                &ingress,
                sealer.as_ref(),
                request,
            )
            .await
        }
    })
}

fn start_server<E, F, Fut>(context: E, address: SocketAddr, handler: F) -> Handle<()>
where
    E: Clock + Network + Spawner + Metrics,
    F: Fn(rpc::Request) -> Fut + Clone + Send + 'static,
    Fut: std::future::Future<Output = rpc::Response> + Send + 'static,
{
    context.spawn(move |context| run(context, address, handler))
}

async fn run<E, F, Fut>(context: E, address: SocketAddr, handler: F)
where
    E: Clock + Network + Spawner + Metrics,
    F: Fn(rpc::Request) -> Fut + Clone + Send + 'static,
    Fut: std::future::Future<Output = rpc::Response> + Send + 'static,
{
    let mut listener = match context.bind(address).await {
        Ok(listener) => listener,
        Err(error) => {
            tracing::error!(?error, %address, "query server failed to bind");
            return;
        }
    };
    // Slots include request buffering, state/evidence work, and response writes.
    // Finished handles are reaped before accepting another connection.
    let mut connections = FuturesUnordered::<Handle<()>>::new();
    loop {
        while let Some(Some(result)) = connections.next().now_or_never() {
            result.expect("query connection task failed");
        }
        let accepted = select! {
            result = async {
                if connections.is_empty() { std::future::pending().await } else { connections.next().await }
            } => {
                result.expect("connection exists").expect("query connection task failed");
                continue;
            },
            accepted = listener.accept() => accepted,
        };
        let (_, mut sink, mut stream) = match accepted {
            Ok(connection) => connection,
            Err(error) => {
                debug!(?error, "query accept failed; retrying");
                context.sleep(ACCEPT_RETRY_DELAY).await;
                continue;
            }
        };
        if connections.len() >= MAX_CONNECTIONS {
            continue;
        }
        let handler = handler.clone();
        connections.push(
            context
                .child("connection")
                .spawn(move |context| async move {
                    let request = select! {
                        request = rpc::recv_request(&mut stream) => request,
                        _ = context.sleep(REQUEST_READ_TIMEOUT) => return,
                    };
                    let Ok(request) = request else { return };
                    let response = handler(request).await;
                    select! {
                        _ = rpc::send_response(&mut sink, &response) => {},
                        _ = context.sleep(REQUEST_READ_TIMEOUT) => {},
                    }
                }),
        );
    }
}

/// Handles one decoded request.
async fn handle<E, S, A>(
    db: &Database<E>,
    finalized: &Finalized,
    marshal: &MarshalMailbox<S, Standard<Block>>,
    ingress: &IngressMailbox<A>,
    sealer: Option<&SealerMailbox>,
    request: rpc::Request,
) -> rpc::Response
where
    E: StorageContext + Spawner,
    S: Scheme,
    A: Acknowledgement,
{
    match request.method {
        METHOD_SUBMIT_TX => match ingress.submit_raw(request.body.into()).await {
            Ok(submission) => respond(&submission),
            Err(error) => error_response(format!("submission failed: {error:#}")),
        },
        METHOD_READ => {
            let Ok(request) = ReadRequest::decode_cfg(request.body, &()) else {
                return error_response("read request does not decode".into());
            };
            match read(db, finalized, marshal, &request).await {
                Ok(response) => respond(&response),
                Err(error) => error_response(format!("read failed: {error}")),
            }
        }
        _ => evidence_response(sealer, request).await,
    }
}

async fn evidence_response(sealer: Option<&SealerMailbox>, request: rpc::Request) -> rpc::Response {
    match request.method {
        METHOD_EVIDENCE => {
            let Ok(request) = EvidenceRequest::decode_cfg(request.body, &()) else {
                return error_response("evidence request does not decode".into());
            };
            let Some(sealer) = sealer else {
                return error_response("evidence is not served by this validator".into());
            };
            match sealer.serve(request).await {
                Ok(response) => respond(&response),
                Err(error) => error_response(format!("evidence failed: {error}")),
            }
        }
        crate::chain::da::sync::METHOD_NATIVE => {
            let Ok(request) = crate::chain::da::sync::NativeRequest::decode(request.body) else {
                return error_response("native request does not decode".into());
            };
            let Some(sealer) = sealer else {
                return error_response("native evidence is not served by this validator".into());
            };
            match sealer.native(request).await {
                Ok(response) => respond(&response),
                Err(error) => error_response(format!("native evidence failed: {error}")),
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
    let (height, digest, proof, payout) = {
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
        let payout = if request.lookup.requires_payout_tip() {
            let key = payout_head_key(&request.deployment);
            let Some(Record::PayoutHead(payout_tip)) = guard.get(&key).await? else {
                return Ok(ReadResponse::Unavailable);
            };
            Some(PayoutHeadProof {
                tip: payout_tip,
                proof: guard.key_value_proof(key).await?,
            })
        } else {
            None
        };
        (tip.height, tip.digest, proof, payout)
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
        payout,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{deployments, genesis_balances, identities, state_config};
    use commonware_clearing::bajillion::qmdb::{State, StateLookup, account_key};
    use commonware_codec::FixedSize as _;
    use commonware_cryptography::{Hasher as _, Sha256};
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner as _, deterministic};

    #[test]
    fn native_read_keys_bind_chain_and_transfer_owner() {
        let accounts = identities();
        let chain_id = Sha256::hash(&[b"chain"]);
        let id = Sha256::hash(&[b"transfer"]);
        let lookups = [
            Lookup::NativeBalance {
                chain_id,
                account: accounts[0].key.clone(),
            },
            Lookup::Registry { chain_id },
            Lookup::RegistryEntry {
                chain_id,
                deployment: id,
            },
            Lookup::NativeTransfer {
                chain_id,
                from: accounts[0].key.clone(),
                id,
            },
        ];
        for lookup in lookups {
            let request = ReadRequest::new(Sha256::hash(&[b"deployment"]), lookup);
            assert_eq!(ReadRequest::decode(request.encode()).unwrap(), request);
            assert_eq!(
                request.key(),
                ReadRequest::new(
                    Sha256::hash(&[b"another deployment"]),
                    request.lookup.clone()
                )
                .key()
            );
        }
        let request = |chain_id, from| {
            ReadRequest::new(
                Sha256::hash(&[b"deployment"]),
                Lookup::NativeTransfer { chain_id, from, id },
            )
        };
        assert_ne!(
            request(chain_id, accounts[0].key.clone()).key(),
            request(chain_id, accounts[1].key.clone()).key()
        );
        assert_ne!(
            request(chain_id, accounts[0].key.clone()).key(),
            request(Sha256::hash(&[b"other chain"]), accounts[0].key.clone()).key()
        );
    }

    #[test]
    fn registry_entry_lookup_binds_chain_and_deployment() {
        let lookup = |chain_id, deployment| {
            ReadRequest::new(
                Sha256::hash(&[b"outer deployment"]),
                Lookup::RegistryEntry {
                    chain_id,
                    deployment,
                },
            )
        };
        let chain = Sha256::hash(&[b"chain"]);
        let deployment = Sha256::hash(&[b"registered deployment"]);
        let request = lookup(chain, deployment);
        assert_eq!(ReadRequest::decode(request.encode()).unwrap(), request);
        assert_ne!(
            request.key(),
            lookup(Sha256::hash(&[b"other chain"]), deployment).key()
        );
        assert_ne!(
            request.key(),
            lookup(chain, Sha256::hash(&[b"other deployment"])).key()
        );
        assert_ne!(
            request.key(),
            ReadRequest::new(deployment, Lookup::Registry { chain_id: chain }).key()
        );
    }

    #[test]
    fn registry_entry_record_rejects_non_prime_order_genesis_key() {
        let deployment = crate::chain::harness::native(deployments())
            .deployments
            .remove(0)
            .deployment;
        let account_offset = 1
            + Digest::SIZE
            + Key::SIZE
            + deployment.operator_ack.encode_size()
            + deployment.accounts.len().encode_size();
        let entry = crate::chain::native::RegistryEntry {
            network_key: commonware_cryptography::ed25519::PublicKey::decode(
                deployment.operator.encode(),
            )
            .unwrap(),
            deployment,
            max_dealing_bytes: 1,
        };
        let record = Record::RegistryEntry(entry);
        assert_eq!(Record::decode(record.encode()).unwrap(), record);
        let mut invalid = record.encode().to_vec();
        invalid[account_offset..account_offset + Key::SIZE].fill(0);
        invalid[account_offset] = 1;
        assert!(Record::decode(Bytes::from(invalid)).is_err());
    }

    #[test]
    fn evidence_request_codecs_round_trip() {
        let account = identities()[0].key.clone();
        let batch = Sha256::hash(&[b"batch"]);
        let result = crate::chain::tests::epoch_fixture().result;
        let heads = result.roots.logs();
        let range = result.roots.activity_range(&result.context).unwrap();
        let lookups = vec![
            EvidenceLookup::State {
                root: StateRoot { digest: batch },
                operations: u64::MAX,
                account: account.clone(),
            },
            EvidenceLookup::Account {
                epoch: 7,
                range,
                account: account.clone(),
            },
            EvidenceLookup::CommittedEntry {
                epoch: 7,
                range,
                payer: account,
                recipient: identities()[1].key.clone(),
            },
            EvidenceLookup::Payout {
                head: heads.payouts,
                index: u64::MAX,
            },
        ];
        for lookup in lookups {
            let request = EvidenceRequest::new(batch, lookup);
            let bytes = request.encode();
            assert_eq!(bytes.len(), request.encode_size());
            assert_eq!(EvidenceRequest::decode(bytes).unwrap(), request);
        }
        for tag in [2, 6, 9, 11, 12, 13, 255] {
            assert!(EvidenceLookup::decode(Bytes::from(vec![tag])).is_err());
        }
    }

    #[test]
    fn payout_evidence_codec_round_trips() {
        let mut bytes = bytes::BytesMut::new();
        Bytes::from_static(b"destination").write(&mut bytes);
        7u64.write(&mut bytes);
        commonware_clearing::bajillion::logs::Opening::<Digest> {
            start: 9,
            proof: Default::default(),
        }
        .write(&mut bytes);
        let claim = WithdrawalClaim::decode_cfg(
            bytes.freeze(),
            &RangeCfg::new(..=crate::protocol::MAX_DESTINATION_BYTES),
        )
        .unwrap();
        let evidence = Evidence::Payout(claim);
        let encoded = evidence.encode();
        assert_eq!(encoded.len(), evidence.encode_size());
        assert_eq!(Evidence::decode(encoded.clone()).unwrap(), evidence);
        for end in 0..encoded.len() {
            assert!(Evidence::decode(encoded.slice(..end)).is_err());
        }
    }

    #[test]
    fn balance_evidence_codec_preserves_membership_absence_and_bounds() {
        deterministic::Runner::default().start(|context| async move {
            let config = state_config(
                "query-proofs",
                crate::protocol::fixture_page_cache(&context),
                Sequential,
            );
            let state = State::<_, Sha256>::init(
                context,
                config,
                genesis_balances(&deployments()[0]).unwrap(),
            )
            .await
            .unwrap();
            let account = identities()[0].key.clone();
            let present = state.lookup(&account_key(&account).unwrap()).await.unwrap();
            let absent = crate::protocol::eve_identity().key;
            let StateLookup::Absent(proof) =
                state.lookup(&account_key(&absent).unwrap()).await.unwrap()
            else {
                panic!("zero-balance account is absent")
            };
            let responses = vec![
                EvidenceResponse::Served(Evidence::State(present)),
                EvidenceResponse::Served(Evidence::State(StateLookup::Absent(proof.clone()))),
                EvidenceResponse::Unsealed,
                EvidenceResponse::Unknown,
                EvidenceResponse::Absent,
            ];
            for response in responses {
                let bytes = response.encode();
                assert_eq!(bytes.len(), response.encode_size());
                assert_eq!(EvidenceResponse::decode(bytes.clone()).unwrap(), response);
                if matches!(response, EvidenceResponse::Served(_)) {
                    for end in 0..bytes.len() {
                        assert!(EvidenceResponse::decode(bytes.slice(..end)).is_err());
                    }
                }
            }
            assert_eq!(
                StateLookup::Absent(proof.clone())
                    .resolve::<Sha256>(&state.root(), &account_key(&absent).unwrap())
                    .unwrap(),
                None
            );
            assert!(
                StateLookup::<Digest>::decode_cfg(StateLookup::Absent(proof).encode(), &0).is_err()
            );
            for tag in [5, 6, 7, 8, 255] {
                assert!(Evidence::decode(Bytes::from(vec![tag])).is_err());
            }
        });
    }
}
