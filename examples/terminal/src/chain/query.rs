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
//! - [`METHOD_EVIDENCE`] answers one [`EvidenceRequest`] with an
//!   [`EvidenceResponse`] from the validator's retained sealed dealings (see
//!   [`crate::chain::da`]): per-account openings a challenge, a chain
//!   withdrawal, or a claim needs, the deployment's genesis state, and the
//!   slice intervals another validator catches up from. Every served opening
//!   verifies against certified roots the client already holds, so nothing
//!   here is trusted unverified.
//!
//! Reads the finalized index or the marshal archives cannot answer yet return
//! the typed [`ReadResponse::Unavailable`] instead of an error.

use crate::{
    chain::{
        app::Finalized,
        da::{Mailbox as SealerMailbox, SliceRange},
        ingress::{Mailbox as IngressMailbox, Submission},
        state::{
            Advice, Record, admitted_key, advise, anchor_key, claim_roots_key, deposit_key,
            fault_key, hard_fault_key, payout_release_key, refund_key, registration_key,
            status_key, withdrawal_key, withdrawal_release_key,
        },
        tx::SettlementTx,
        types::{Block, Database, Exclusion, MAX_TX_BYTES, Proof, StateKey},
    },
    protocol::{Deployment, Key, MAX_DESTINATION_BYTES, MAX_SLICES, limits},
    rpc::{self, ACCEPT_RETRY_DELAY, error_response},
};
use bytes::{Buf, BufMut, Bytes};
use commonware_clearing::bajillion::{
    challenge::{AccountLookup, ChangeOpening, HigherEntryLookup, StateOpening},
    commitment::{RangeOpening, VectorRoot},
    transition::{BatchId, ExternalPayoutClaim, Header, RootBundle, WithdrawalClaim},
    vector::TransposeEntry,
};
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
use std::{net::SocketAddr, ops::Range};
use tracing::debug;

/// Submits one settlement transaction into the ingress queue.
pub(crate) const METHOD_SUBMIT_TX: u8 = 0;

/// Answers one certified read.
pub(crate) const METHOD_READ: u8 = 1;

/// Answers one evidence request from the validator's retained sealed
/// dealings.
pub(crate) const METHOD_EVIDENCE: u8 = 2;

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

/// One evidence lookup within one deployment's retained sealed dealings.
///
/// Close-bound lookups name the batch id of the sealed close and the account
/// whose slice the serving validator must hold. [`Self::GenesisState`] opens
/// the deployment's genesis state, which every validator holds whole, and
/// [`Self::Interval`] returns one slice's retained live leaves at a certified
/// state root for another holder's catch-up.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum EvidenceLookup {
    /// The account's leaf under the close's predecessor state root.
    PredecessorState { batch: Digest, account: Key },
    /// The account's leaf under the close's successor state root.
    SuccessorState { batch: Digest, account: Key },
    /// The account's compact change value under the change root.
    Change { batch: Digest, account: Key },
    /// The payer's committed terminal entry for `recipient`, or its
    /// authenticated absence from the change vector.
    CommittedEntry {
        batch: Digest,
        payer: Key,
        recipient: Key,
    },
    /// The payer lookup for a higher-debit challenge: the compact change
    /// opening, or the authenticated absence with predecessor state.
    Account { batch: Digest, account: Key },
    /// The account's validator-derived withdrawal output for claiming.
    WithdrawalOutput { batch: Digest, account: Key },
    /// The recipient's credited transpose range under the transpose root.
    Credits { batch: Digest, recipient: Key },
    /// The account's leaf under the deployment's genesis state root.
    GenesisState { account: Key },
    /// One slice's retained live leaves at `root`, with the guards that
    /// prove the slice complete.
    Interval {
        root: VectorRoot<Digest>,
        slice: u16,
    },
    /// The account's external payout claim under the change root.
    ExternalPayout { batch: Digest, account: Key },
}

impl EvidenceLookup {
    /// The sealed close this lookup addresses, or `None` for a lookup outside
    /// any close (genesis state and interval catch-up).
    pub(crate) const fn batch(&self) -> Option<&Digest> {
        match self {
            Self::PredecessorState { batch, .. }
            | Self::SuccessorState { batch, .. }
            | Self::Change { batch, .. }
            | Self::CommittedEntry { batch, .. }
            | Self::Account { batch, .. }
            | Self::WithdrawalOutput { batch, .. }
            | Self::Credits { batch, .. }
            | Self::ExternalPayout { batch, .. } => Some(batch),
            Self::GenesisState { .. } | Self::Interval { .. } => None,
        }
    }

    /// The account whose slice the serving validator must hold, or `None`
    /// for an interval lookup, which names its slice directly.
    pub(crate) const fn account(&self) -> Option<&Key> {
        match self {
            Self::PredecessorState { account, .. }
            | Self::SuccessorState { account, .. }
            | Self::Change { account, .. }
            | Self::Account { account, .. }
            | Self::WithdrawalOutput { account, .. }
            | Self::GenesisState { account }
            | Self::ExternalPayout { account, .. } => Some(account),
            Self::CommittedEntry { payer, .. } => Some(payer),
            Self::Credits { recipient, .. } => Some(recipient),
            Self::Interval { .. } => None,
        }
    }
}

impl Write for EvidenceLookup {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::PredecessorState { batch, account } => {
                0_u8.write(buf);
                batch.write(buf);
                account.write(buf);
            }
            Self::SuccessorState { batch, account } => {
                1_u8.write(buf);
                batch.write(buf);
                account.write(buf);
            }
            Self::Change { batch, account } => {
                2_u8.write(buf);
                batch.write(buf);
                account.write(buf);
            }
            Self::CommittedEntry {
                batch,
                payer,
                recipient,
            } => {
                3_u8.write(buf);
                batch.write(buf);
                payer.write(buf);
                recipient.write(buf);
            }
            Self::Account { batch, account } => {
                4_u8.write(buf);
                batch.write(buf);
                account.write(buf);
            }
            Self::WithdrawalOutput { batch, account } => {
                5_u8.write(buf);
                batch.write(buf);
                account.write(buf);
            }
            Self::Credits { batch, recipient } => {
                6_u8.write(buf);
                batch.write(buf);
                recipient.write(buf);
            }
            Self::GenesisState { account } => {
                7_u8.write(buf);
                account.write(buf);
            }
            Self::Interval { root, slice } => {
                8_u8.write(buf);
                root.write(buf);
                slice.write(buf);
            }
            Self::ExternalPayout { batch, account } => {
                9_u8.write(buf);
                batch.write(buf);
                account.write(buf);
            }
        }
    }
}

impl EncodeSize for EvidenceLookup {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::PredecessorState { batch, account }
            | Self::SuccessorState { batch, account }
            | Self::Change { batch, account }
            | Self::Account { batch, account }
            | Self::WithdrawalOutput { batch, account }
            | Self::ExternalPayout { batch, account } => {
                batch.encode_size() + account.encode_size()
            }
            Self::CommittedEntry {
                batch,
                payer,
                recipient,
            } => batch.encode_size() + payer.encode_size() + recipient.encode_size(),
            Self::Credits { batch, recipient } => batch.encode_size() + recipient.encode_size(),
            Self::GenesisState { account } => account.encode_size(),
            Self::Interval { root, slice } => root.encode_size() + slice.encode_size(),
        }
    }
}

impl Read for EvidenceLookup {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::PredecessorState {
                batch: Digest::read(buf)?,
                account: Key::read(buf)?,
            }),
            1 => Ok(Self::SuccessorState {
                batch: Digest::read(buf)?,
                account: Key::read(buf)?,
            }),
            2 => Ok(Self::Change {
                batch: Digest::read(buf)?,
                account: Key::read(buf)?,
            }),
            3 => Ok(Self::CommittedEntry {
                batch: Digest::read(buf)?,
                payer: Key::read(buf)?,
                recipient: Key::read(buf)?,
            }),
            4 => Ok(Self::Account {
                batch: Digest::read(buf)?,
                account: Key::read(buf)?,
            }),
            5 => Ok(Self::WithdrawalOutput {
                batch: Digest::read(buf)?,
                account: Key::read(buf)?,
            }),
            6 => Ok(Self::Credits {
                batch: Digest::read(buf)?,
                recipient: Key::read(buf)?,
            }),
            7 => Ok(Self::GenesisState {
                account: Key::read(buf)?,
            }),
            8 => Ok(Self::Interval {
                root: VectorRoot::read(buf)?,
                slice: u16::read(buf)?,
            }),
            9 => Ok(Self::ExternalPayout {
                batch: Digest::read(buf)?,
                account: Key::read(buf)?,
            }),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

/// One evidence request: the deployment whose sealed dealings it reads plus
/// the lookup within them. A validator serving several deployments routes by
/// the digest and never answers one deployment's request from another's
/// dealings.
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

/// One close-bound opening served from a sealed proof slice, byte-equal to
/// what the whole-close constructors produce and verifiable against the
/// served roots.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum EvidenceBody {
    /// A state leaf opening (predecessor or successor state).
    State(StateOpening<Key, Digest>),
    /// The higher-debit payer lookup.
    Account(AccountLookup<Key, Digest>),
    /// A compact change opening.
    Change(ChangeOpening<Digest>),
    /// The composed higher-entry lookup.
    CommittedEntry(HigherEntryLookup<Key, Digest>),
    /// A withdrawal output claim.
    WithdrawalOutput(WithdrawalClaim<Digest>),
    /// An external payout claim.
    ExternalPayout(ExternalPayoutClaim<Key, Digest>),
    /// The recipient's contiguous credited transpose entries with their
    /// opening under the transpose root.
    Credits {
        entries: Vec<TransposeEntry<Key>>,
        opening: RangeOpening<Digest>,
    },
}

impl Write for EvidenceBody {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::State(opening) => {
                0_u8.write(buf);
                opening.write(buf);
            }
            Self::Account(lookup) => {
                1_u8.write(buf);
                lookup.write(buf);
            }
            Self::Change(opening) => {
                2_u8.write(buf);
                opening.write(buf);
            }
            Self::CommittedEntry(lookup) => {
                3_u8.write(buf);
                lookup.write(buf);
            }
            Self::WithdrawalOutput(claim) => {
                4_u8.write(buf);
                claim.write(buf);
            }
            Self::ExternalPayout(claim) => {
                5_u8.write(buf);
                claim.write(buf);
            }
            Self::Credits { entries, opening } => {
                6_u8.write(buf);
                entries.write(buf);
                opening.write(buf);
            }
        }
    }
}

impl EncodeSize for EvidenceBody {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::State(opening) => opening.encode_size(),
            Self::Account(lookup) => lookup.encode_size(),
            Self::Change(opening) => opening.encode_size(),
            Self::CommittedEntry(lookup) => lookup.encode_size(),
            Self::WithdrawalOutput(claim) => claim.encode_size(),
            Self::ExternalPayout(claim) => claim.encode_size(),
            Self::Credits { entries, opening } => entries.encode_size() + opening.encode_size(),
        }
    }
}

impl Read for EvidenceBody {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::State(StateOpening::read(buf)?)),
            1 => Ok(Self::Account(AccountLookup::read(buf)?)),
            2 => Ok(Self::Change(ChangeOpening::read(buf)?)),
            3 => Ok(Self::CommittedEntry(HigherEntryLookup::read(buf)?)),
            4 => Ok(Self::WithdrawalOutput(WithdrawalClaim::read_cfg(
                buf,
                &RangeCfg::new(0..=MAX_DESTINATION_BYTES),
            )?)),
            5 => Ok(Self::ExternalPayout(ExternalPayoutClaim::read(buf)?)),
            6 => {
                // A recipient's credits are one contiguous run of the
                // anchor-bound transpose, so its total entry limit bounds
                // both the entries and the opening they are proven under.
                let max_entries = usize::try_from(limits().max_total_entries())
                    .map_err(|_| CodecError::Invalid("EvidenceBody", "entry limit"))?;
                Ok(Self::Credits {
                    entries: Vec::<TransposeEntry<Key>>::read_cfg(
                        buf,
                        &(RangeCfg::new(1..=max_entries), ()),
                    )?,
                    opening: RangeOpening::read_cfg(buf, &max_entries)?,
                })
            }
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

/// One served piece of evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum Evidence {
    /// Close-bound evidence: the sealed header, the roots it commits, and the
    /// opening. The client checks the header against the chain's admitted
    /// record before trusting the roots the body verifies under.
    Close {
        header: Header<Digest>,
        roots: RootBundle<Digest>,
        body: EvidenceBody,
    },
    /// One account opened under the deployment's genesis state root.
    Genesis(StateOpening<Key, Digest>),
    /// One slice's live leaves at the requested root, with the adjacent
    /// guards outside the slice (or the vector ends) proving it complete.
    Interval(SliceRange),
}

impl Write for Evidence {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Close {
                header,
                roots,
                body,
            } => {
                0_u8.write(buf);
                header.write(buf);
                roots.write(buf);
                body.write(buf);
            }
            Self::Genesis(opening) => {
                1_u8.write(buf);
                opening.write(buf);
            }
            Self::Interval(range) => {
                2_u8.write(buf);
                range.write(buf);
            }
        }
    }
}

impl EncodeSize for Evidence {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Close {
                header,
                roots,
                body,
            } => header.encode_size() + roots.encode_size() + body.encode_size(),
            Self::Genesis(opening) => opening.encode_size(),
            Self::Interval(range) => range.encode_size(),
        }
    }
}

impl Read for Evidence {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::Close {
                header: Header::read(buf)?,
                roots: RootBundle::read(buf)?,
                body: EvidenceBody::read(buf)?,
            }),
            1 => Ok(Self::Genesis(StateOpening::read(buf)?)),
            2 => Ok(Self::Interval(SliceRange::read(buf)?)),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

/// One evidence response.
///
/// Only [`Self::Served`] carries anything verifiable. The other answers are
/// unauthenticated routing advice: a client that cannot get an answer from
/// one holder asks the next in the slice's quorum.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum EvidenceResponse {
    /// The requested evidence.
    Served(Evidence),
    /// The account's slice is outside this validator's assigned spans, which
    /// are returned so the client can pick a holder.
    NotHolder { spans: Vec<Range<u16>> },
    /// This validator holds no sealed dealing for the batch (or no interval
    /// at the root).
    Unsealed,
    /// The batch finalized and its dealing was released after its challenge
    /// window closed.
    Pruned,
    /// The deployment is not served by this validator.
    Unknown,
    /// The held slice has nothing to open for the lookup: the account is not
    /// live in the requested state, has no changed row, no withdrawal, no
    /// payout, or no credit in this close.
    Absent,
}

impl Write for EvidenceResponse {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Served(evidence) => {
                0_u8.write(buf);
                evidence.write(buf);
            }
            Self::NotHolder { spans } => {
                1_u8.write(buf);
                spans.len().write(buf);
                for span in spans {
                    span.start.write(buf);
                    span.end.write(buf);
                }
            }
            Self::Unsealed => 2_u8.write(buf),
            Self::Pruned => 3_u8.write(buf),
            Self::Unknown => 4_u8.write(buf),
            Self::Absent => 5_u8.write(buf),
        }
    }
}

impl EncodeSize for EvidenceResponse {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Served(evidence) => evidence.encode_size(),
            Self::NotHolder { spans } => {
                spans.len().encode_size()
                    + spans
                        .iter()
                        .map(|span| span.start.encode_size() + span.end.encode_size())
                        .sum::<usize>()
            }
            Self::Unsealed | Self::Pruned | Self::Unknown | Self::Absent => 0,
        }
    }
}

impl Read for EvidenceResponse {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::Served(Evidence::read(buf)?)),
            1 => {
                let count = usize::read_cfg(buf, &RangeCfg::new(..=MAX_SLICES))?;
                let mut spans = Vec::with_capacity(count);
                for _ in 0..count {
                    let span = u16::read(buf)?..u16::read(buf)?;
                    if span.start >= span.end || usize::from(span.end) > MAX_SLICES {
                        return Err(CodecError::Invalid(
                            "EvidenceResponse",
                            "span is not canonical",
                        ));
                    }
                    spans.push(span);
                }
                Ok(Self::NotHolder { spans })
            }
            2 => Ok(Self::Unsealed),
            3 => Ok(Self::Pruned),
            4 => Ok(Self::Unknown),
            5 => Ok(Self::Absent),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
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
    /// The sealer serving evidence from retained sealed dealings, or `None`
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
        let sealer = config.sealer.clone();
        context.child("connection").spawn(move |_| async move {
            let Ok(request) = rpc::recv_request(&mut stream).await else {
                return;
            };
            let response = handle(
                &deployments,
                &db,
                &finalized,
                &marshal,
                &ingress,
                sealer.as_ref(),
                request,
            )
            .await;
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
    sealer: Option<&SealerMailbox>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chain::da::{genesis_cache, genesis_range, slice_ranges},
        protocol::{MAX_ACCOUNTS, SLICE_BITS, deployments, identities},
    };
    use bytes::BytesMut;
    use commonware_clearing::bajillion::state::StateLeaf;
    use commonware_codec::{DecodeExt as _, FixedSize as _};
    use commonware_cryptography::{Hasher as _, Sha256};

    fn digest(name: &[u8]) -> Digest {
        Sha256::hash(&[name])
    }

    fn root(name: &[u8]) -> VectorRoot<Digest> {
        VectorRoot {
            digest: digest(name),
        }
    }

    #[test]
    fn evidence_request_codecs_round_trip() {
        let account = identities()[0].key.clone();
        let other = identities()[1].key.clone();
        let batch = digest(b"batch");
        let lookups = [
            EvidenceLookup::PredecessorState {
                batch,
                account: account.clone(),
            },
            EvidenceLookup::SuccessorState {
                batch,
                account: account.clone(),
            },
            EvidenceLookup::Change {
                batch,
                account: account.clone(),
            },
            EvidenceLookup::CommittedEntry {
                batch,
                payer: account.clone(),
                recipient: other.clone(),
            },
            EvidenceLookup::Account {
                batch,
                account: account.clone(),
            },
            EvidenceLookup::WithdrawalOutput {
                batch,
                account: account.clone(),
            },
            EvidenceLookup::Credits {
                batch,
                recipient: other,
            },
            EvidenceLookup::GenesisState {
                account: account.clone(),
            },
            EvidenceLookup::Interval {
                root: root(b"interval"),
                slice: 3,
            },
            EvidenceLookup::ExternalPayout { batch, account },
        ];
        for (tag, lookup) in lookups.into_iter().enumerate() {
            let request = EvidenceRequest::new(digest(b"deployment"), lookup);
            let encoded = request.encode();
            assert_eq!(encoded.len(), request.encode_size());
            assert_eq!(encoded[Digest::SIZE], tag as u8);
            assert_eq!(EvidenceRequest::decode(encoded).unwrap(), request);
        }
        assert!(matches!(
            EvidenceLookup::decode(Bytes::from_static(&[10])),
            Err(CodecError::InvalidEnum(10))
        ));
    }

    #[test]
    fn evidence_response_codecs_round_trip() {
        let genesis = genesis_cache(&deployments()[0]);
        let account = identities()[0].key.clone();
        let opening = genesis.opening(&account).unwrap();
        let ranges = slice_ranges(
            &genesis_range(&genesis),
            genesis.leaves(),
            &(0..MAX_SLICES as u16),
            SLICE_BITS,
        )
        .unwrap();
        let header = Header::decode(digest(b"header").encode()).unwrap();
        let roots = RootBundle {
            change: root(b"change"),
            withdrawal_outputs: root(b"outputs"),
            successor: root(b"successor"),
            coverage: root(b"coverage"),
            transpose: root(b"transpose"),
            transpose_len: 7,
        };
        let responses = [
            EvidenceResponse::Served(Evidence::Genesis(opening.clone())),
            EvidenceResponse::Served(Evidence::Interval(ranges[0].clone())),
            EvidenceResponse::Served(Evidence::Close {
                header,
                roots,
                body: EvidenceBody::State(opening),
            }),
            EvidenceResponse::NotHolder {
                spans: vec![0..2, 3..4],
            },
            EvidenceResponse::Unsealed,
            EvidenceResponse::Pruned,
            EvidenceResponse::Unknown,
            EvidenceResponse::Absent,
        ];
        for response in responses {
            let encoded = response.encode();
            assert_eq!(encoded.len(), response.encode_size());
            assert_eq!(EvidenceResponse::decode(encoded).unwrap(), response);
        }
        assert!(matches!(
            EvidenceResponse::decode(Bytes::from_static(&[6])),
            Err(CodecError::InvalidEnum(6))
        ));
        assert!(matches!(
            Evidence::decode(Bytes::from_static(&[3])),
            Err(CodecError::InvalidEnum(3))
        ));
        assert!(matches!(
            EvidenceBody::decode(Bytes::from_static(&[7])),
            Err(CodecError::InvalidEnum(7))
        ));
    }

    #[test]
    fn evidence_codecs_reject_out_of_bound_shapes() {
        // More spans than slices, and a span that is empty or past the
        // partition, are refused.
        let mut encoded = BytesMut::new();
        1_u8.write(&mut encoded);
        (MAX_SLICES + 1).write(&mut encoded);
        assert!(EvidenceResponse::decode(encoded.freeze()).is_err());
        for span in [(2_u16, 1_u16), (0, MAX_SLICES as u16 + 1)] {
            let mut encoded = BytesMut::new();
            1_u8.write(&mut encoded);
            1_usize.write(&mut encoded);
            span.0.write(&mut encoded);
            span.1.write(&mut encoded);
            assert!(EvidenceResponse::decode(encoded.freeze()).is_err());
        }

        // A credit range with no entries is refused.
        let mut encoded = BytesMut::new();
        6_u8.write(&mut encoded);
        0_usize.write(&mut encoded);
        assert!(EvidenceBody::decode(encoded.freeze()).is_err());

        // A slice range with more members than accounts is refused.
        let genesis = genesis_cache(&deployments()[0]);
        let leaf: StateLeaf<crate::protocol::Key> = genesis.leaves()[0].clone();
        let ranges = slice_ranges(
            &genesis_range(&genesis),
            genesis.leaves(),
            &(0..MAX_SLICES as u16),
            SLICE_BITS,
        )
        .unwrap();
        let mut oversized = ranges[0].clone();
        oversized.members = vec![leaf; MAX_ACCOUNTS + 1];
        assert!(SliceRange::decode(oversized.encode()).is_err());
    }
}
