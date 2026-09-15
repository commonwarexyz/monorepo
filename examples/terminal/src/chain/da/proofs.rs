//! Individually addressable proof ingredients published before the canonical close journal.

#[cfg(test)]
mod tests;

use super::Sealed;
use crate::{
    chain::{
        query::{Evidence, EvidenceBody, EvidenceLookup, EvidenceResponse},
        validator::{IO_BUFFER_SIZE, PAGE_CACHE_SIZE, PAGE_SIZE},
    },
    protocol::{
        Key, MAX_ACCEPTED_PAYMENTS, MAX_ACTIVITY_ROWS, MAX_DESTINATION_BYTES, MAX_WITHDRAWALS,
        WithdrawalWitness,
    },
};
use anyhow::{Context as _, Result, bail, ensure};
use bytes::BufMut;
use commonware_clearing::bajillion::{
    boundary::SignedWithdrawal,
    challenge::{AccountLookup, ChangeAbsence, ChangeOpening, HigherEntryLookup},
    commitment::{Builder, Opening, RangeOpening, Tree, VectorKind},
    state::{ChangeGuard, ChangeValue},
    transition::{Close, CloseContext, Header, RootBundle, WithdrawalClaim, WithdrawalOutput},
    vector::{OutEntry, OutTipLookup},
};
use commonware_codec::{
    Buf, Encode as _, EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt as _,
    Write,
};
use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest};
use commonware_parallel::Sequential;
use commonware_runtime::buffer::paged::CacheRef;
use commonware_storage::{
    Context as StorageContext,
    archive::{Archive as _, Identifier, immutable},
    bmt,
};
use commonware_utils::NZU64;
use std::cmp::Ordering;

const NAMESPACE: &[u8] = b"_COMMONWARE_TERMINAL_PROOF_RECORD";

/// Leaves followed by shared nodes; construction and decoding check the full ordinal extent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Span {
    leaves: u64,
    len: u32,
}

impl Span {
    fn reserve(next: &mut u64, len: usize) -> Result<Self> {
        let len = u32::try_from(len)?;
        let leaves = reserve(next, u64::from(len) + node_count(len))?;
        Ok(Self { leaves, len })
    }

    fn nodes(self) -> u64 {
        self.leaves + u64::from(self.len)
    }

    fn end(self) -> u64 {
        self.nodes() + node_count(self.len)
    }
}

impl Write for Span {
    fn write(&self, buf: &mut impl BufMut) {
        self.leaves.write(buf);
        self.len.write(buf);
    }
}

impl FixedSize for Span {
    const SIZE: usize = u64::SIZE + u32::SIZE;
}

impl Read for Span {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let value = Self {
            leaves: u64::read(buf)?,
            len: u32::read(buf)?,
        };
        if value
            .leaves
            .checked_add(u64::from(value.len) + node_count(value.len))
            .is_none()
        {
            return Err(CodecError::Invalid("ProofSpan", "ordinal extent overflows"));
        }
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Descriptor {
    pub(super) context: CloseContext<Key, Digest>,
    pub(super) header: Header<Digest>,
    pub(super) roots: RootBundle<Digest>,
    withdrawal_total: u64,
    pub(super) predecessor_operations: u64,
    pub(super) operations: u64,
    changes: Span,
    withdrawals: Span,
}

impl Descriptor {
    fn matches(&self, sealed: &Sealed) -> bool {
        self.context == sealed.context
            && self.header == sealed.header
            && self.roots == sealed.roots
            && self.withdrawal_total == sealed.withdrawal_total
            && self.predecessor_operations == sealed.predecessor_operations
            && self.operations == sealed.operations
            && self.withdrawals.len as usize == sealed.withdrawals.len()
    }
}

impl Write for Descriptor {
    fn write(&self, buf: &mut impl BufMut) {
        self.context.write(buf);
        self.header.write(buf);
        self.roots.write(buf);
        self.withdrawal_total.write(buf);
        self.predecessor_operations.write(buf);
        self.operations.write(buf);
        self.changes.write(buf);
        self.withdrawals.write(buf);
    }
}

impl EncodeSize for Descriptor {
    fn encode_size(&self) -> usize {
        self.context.encode_size()
            + self.header.encode_size()
            + self.roots.encode_size()
            + u64::SIZE * 3
            + Span::SIZE * 2
    }
}

impl Read for Descriptor {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let value = Self {
            context: CloseContext::read(buf)?,
            header: Header::read(buf)?,
            roots: RootBundle::read(buf)?,
            withdrawal_total: u64::read(buf)?,
            predecessor_operations: u64::read(buf)?,
            operations: u64::read(buf)?,
            changes: Span::read(buf)?,
            withdrawals: Span::read(buf)?,
        };
        if value.changes.len as usize > MAX_ACTIVITY_ROWS
            || value.withdrawals.len as usize > MAX_WITHDRAWALS
        {
            return Err(CodecError::Invalid(
                "ProofDescriptor",
                "vector exceeds native limit",
            ));
        }
        if value
            .withdrawals
            .end()
            .checked_add(node_count(value.withdrawals.len))
            .is_none()
        {
            return Err(CodecError::Invalid(
                "ProofDescriptor",
                "output extent overflows",
            ));
        }
        Ok(value)
    }
}

#[derive(Clone, Debug)]
struct Change {
    guard: ChangeGuard<Key, Digest>,
    value: ChangeValue<Digest>,
    entries: Span,
}

impl Write for Change {
    fn write(&self, buf: &mut impl BufMut) {
        self.guard.write(buf);
        self.value.write(buf);
        self.entries.write(buf);
    }
}

impl EncodeSize for Change {
    fn encode_size(&self) -> usize {
        self.guard.encode_size() + self.value.encode_size() + Span::SIZE
    }
}

impl Read for Change {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let value = Self {
            guard: ChangeGuard::read(buf)?,
            value: ChangeValue::read(buf)?,
            entries: Span::read(buf)?,
        };
        if value.entries.len as usize > MAX_ACCEPTED_PAYMENTS {
            return Err(CodecError::Invalid(
                "ProofChange",
                "outgoing vector exceeds native limit",
            ));
        }
        Ok(value)
    }
}

enum Record {
    Descriptor(Box<Descriptor>),
    Change(Change),
    Entry(OutEntry<Key>),
    Withdrawal {
        request: SignedWithdrawal<Key, Digest>,
        output: WithdrawalOutput,
    },
    Node(Digest),
}

impl Record {
    fn key(&self) -> Result<&Key> {
        match self {
            Self::Change(value) => Ok(value.guard.account()),
            Self::Entry(value) => Ok(&value.recipient),
            Self::Withdrawal { request, .. } => Ok(request.account()),
            _ => bail!("proof span contains a non-leaf record"),
        }
    }
}

impl Write for Record {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Descriptor(value) => {
                0u8.write(buf);
                value.write(buf);
            }
            Self::Change(value) => {
                1u8.write(buf);
                value.write(buf);
            }
            Self::Entry(value) => {
                2u8.write(buf);
                value.write(buf);
            }
            Self::Withdrawal { request, output } => {
                3u8.write(buf);
                request.write(buf);
                output.write(buf);
            }
            Self::Node(value) => {
                4u8.write(buf);
                value.write(buf);
            }
        }
    }
}

impl EncodeSize for Record {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Descriptor(value) => value.encode_size(),
            Self::Change(value) => value.encode_size(),
            Self::Entry(value) => value.encode_size(),
            Self::Withdrawal { request, output } => request.encode_size() + output.encode_size(),
            Self::Node(value) => value.encode_size(),
        }
    }
}

impl Read for Record {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(match u8::read(buf)? {
            0 => Self::Descriptor(Box::new(Descriptor::read(buf)?)),
            1 => Self::Change(Change::read(buf)?),
            2 => Self::Entry(OutEntry::read(buf)?),
            3 => {
                let cfg = RangeCfg::new(0..=MAX_DESTINATION_BYTES);
                Self::Withdrawal {
                    request: SignedWithdrawal::read_cfg(buf, &cfg)?,
                    output: WithdrawalOutput::read_cfg(buf, &cfg)?,
                }
            }
            4 => Self::Node(Digest::read(buf)?),
            tag => return Err(CodecError::InvalidEnum(tag)),
        })
    }
}

// The proof archive commits a descriptor and all its indexed ingredients in one sync.
// Only the canonical journal authorizes serving that descriptor to callers.
pub(super) struct Store<E: StorageContext> {
    archive: immutable::Archive<E, Digest, Record>,
    deployment: Digest,
}

impl<E: StorageContext> Store<E> {
    pub(super) async fn open(context: E, partition: &str, deployment: Digest) -> Result<Self> {
        let prefix = format!("{partition}-{deployment}-proofs-v1");
        let cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
        let archive = immutable::Archive::init(
            context,
            immutable::Config {
                metadata_partition: format!("{prefix}-metadata"),
                freezer_table_partition: format!("{prefix}-table"),
                freezer_table_initial_size: 4096,
                freezer_table_resize_frequency: 4,
                freezer_table_resize_chunk_size: 1024,
                freezer_key_partition: format!("{prefix}-key"),
                freezer_key_page_cache: cache,
                freezer_value_partition: format!("{prefix}-value"),
                freezer_value_target_size: 128 * 1024 * 1024,
                freezer_value_compression: None,
                ordinal_partition: format!("{prefix}-ordinal"),
                items_per_section: NZU64!(1024),
                freezer_key_write_buffer: IO_BUFFER_SIZE,
                freezer_value_write_buffer: IO_BUFFER_SIZE,
                ordinal_write_buffer: IO_BUFFER_SIZE,
                replay_buffer: IO_BUFFER_SIZE,
                codec_config: (),
            },
        )
        .await?;
        Ok(Self {
            archive,
            deployment,
        })
    }

    fn key(&self, batch: &Digest, descriptor: bool, index: u64) -> Digest {
        Sha256::hash(&[
            NAMESPACE,
            self.deployment.as_ref(),
            batch.as_ref(),
            &[u8::from(descriptor)],
            &index.to_be_bytes(),
        ])
    }

    pub(super) async fn descriptor(&self, batch: &Digest) -> Result<Option<Descriptor>> {
        let key = self.key(batch, true, 0);
        let Some(record) = self.archive.get(Identifier::Key(&key)).await? else {
            return Ok(None);
        };
        let Record::Descriptor(value) = record else {
            bail!("proof descriptor key contains another record kind");
        };
        ensure!(
            value.context.deployment() == &self.deployment
                && value.header.batch_id::<Sha256>().digest() == batch
                && value.header.verify::<Sha256, Key>(
                    &value.context,
                    &value.roots,
                    value.withdrawal_total
                ),
            "proof descriptor context mismatch"
        );
        Ok(Some(*value))
    }

    /// Checks a recovery anchor already read from the canonical close journal.
    pub(super) async fn check(&self, sealed: &Sealed) -> Result<()> {
        let batch = sealed.header.batch_id::<Sha256>().into_digest();
        let value = self
            .descriptor(&batch)
            .await?
            .context("canonical close has no proof index; incompatible validator storage")?;
        ensure!(value.matches(sealed), "canonical proof descriptor mismatch");
        Ok(())
    }

    /// Publishes proof ingredients for a validated candidate before canonical journaling.
    pub(super) async fn retain(
        mut self,
        sealed: &Sealed,
        close: &Close<Key, Digest>,
    ) -> Result<Self> {
        ensure!(
            sealed.context.deployment() == &self.deployment
                && close.header == sealed.header
                && close.roots == sealed.roots
                && close.withdrawal_total == sealed.withdrawal_total
                && sealed.header.verify::<Sha256, Key>(
                    &sealed.context,
                    &sealed.roots,
                    sealed.withdrawal_total
                ),
            "proof export differs from validated descriptor"
        );
        let batch = sealed.header.batch_id::<Sha256>().into_digest();
        let (leaves, guards, change_tree) = close.change_evidence();
        let (outputs, output_tree) = close.withdrawal_evidence();
        let requests = sealed.withdrawals.requests();
        ensure!(
            leaves.len() <= MAX_ACTIVITY_ROWS
                && leaves.len() == guards.len()
                && leaves.len() == close.out_vectors.len()
                && requests.len() <= MAX_WITHDRAWALS
                && requests.len() == outputs.len()
                && change_tree.root() == sealed.roots.change
                && output_tree.root() == sealed.roots.withdrawal_outputs,
            "proof export vector mismatch"
        );
        if let Some(value) = self.descriptor(&batch).await? {
            ensure!(
                value.matches(sealed) && value.changes.len as usize == leaves.len(),
                "conflicting proof export"
            );
            return Ok(self);
        }

        let mut next = match self.archive.last_index() {
            Some(last) => last
                .checked_add(1)
                .context("proof archive index overflow")?,
            None => 0,
        };
        let changes = Span::reserve(&mut next, leaves.len())?;
        let withdrawals = Span::reserve(&mut next, requests.len())?;
        let withdrawal_outputs = reserve(&mut next, node_count(withdrawals.len))?;
        self = self
            .tree(changes.nodes(), changes.len, change_tree, &batch)
            .await?;
        self = self
            .tree(withdrawal_outputs, withdrawals.len, output_tree, &batch)
            .await?;

        let mut request_tree = Builder::<Sha256>::new(VectorKind::Withdrawal, withdrawals.len)?;
        for (position, (request, output)) in requests.iter().zip(outputs).enumerate() {
            request_tree.add_encoded(&request.encode())?;
            self = self
                .put(
                    withdrawals
                        .leaves
                        .checked_add(u64::try_from(position)?)
                        .context("proof index overflow")?,
                    &batch,
                    &Record::Withdrawal {
                        request: request.clone(),
                        output: output.clone(),
                    },
                )
                .await?;
        }
        let request_tree = request_tree.build(&Sequential)?;
        ensure!(
            request_tree.root() == *sealed.context.withdrawal_root(),
            "withdrawal request root mismatch"
        );
        self = self
            .tree(withdrawals.nodes(), withdrawals.len, &request_tree, &batch)
            .await?;
        drop(request_tree);

        for (position, ((leaf, guard), vector)) in leaves
            .iter()
            .zip(guards)
            .zip(&close.out_vectors)
            .enumerate()
        {
            ensure!(
                leaf.account() == guard.account()
                    && vector.payer() == leaf.account()
                    && vector.epoch() == sealed.context.payment().epoch()
                    && vector.entries().len() <= MAX_ACCEPTED_PAYMENTS,
                "outgoing vector context mismatch"
            );
            let entries = Span::reserve(&mut next, vector.entries().len())?;
            let mut tree = Builder::<Sha256>::new(VectorKind::OutEntry, entries.len)?;
            tree.add_values(vector.entries(), &Sequential)?;
            let tree = tree.build(&Sequential)?;
            ensure!(
                tree.root() == leaf.send_root(),
                "outgoing vector root mismatch"
            );
            for (entry_position, entry) in vector.entries().iter().enumerate() {
                self = self
                    .put(
                        entries
                            .leaves
                            .checked_add(u64::try_from(entry_position)?)
                            .context("proof index overflow")?,
                        &batch,
                        &Record::Entry(entry.clone()),
                    )
                    .await?;
            }
            self = self
                .tree(entries.nodes(), entries.len, &tree, &batch)
                .await?;
            self = self
                .put(
                    changes
                        .leaves
                        .checked_add(u64::try_from(position)?)
                        .context("proof index overflow")?,
                    &batch,
                    &Record::Change(Change {
                        guard: guard.clone(),
                        value: leaf.value(),
                        entries,
                    }),
                )
                .await?;
        }

        let descriptor = Descriptor {
            context: sealed.context.clone(),
            header: sealed.header,
            roots: sealed.roots,
            withdrawal_total: sealed.withdrawal_total,
            predecessor_operations: sealed.predecessor_operations,
            operations: sealed.operations,
            changes,
            withdrawals,
        };
        let key = self.key(&batch, true, 0);
        self.archive = self
            .archive
            .put(next, key, &Record::Descriptor(Box::new(descriptor)))
            .await?;
        self.archive = self.archive.sync().await?;
        Ok(self)
    }

    async fn put(mut self, index: u64, batch: &Digest, record: &Record) -> Result<Self> {
        let key = self.key(batch, false, index);
        self.archive = self.archive.put(index, key, record).await?;
        Ok(self)
    }

    async fn tree(
        mut self,
        nodes: u64,
        len: u32,
        tree: &Tree<Digest>,
        batch: &Digest,
    ) -> Result<Self> {
        let mut count = 0u64;
        for (_, digest) in tree.proof_nodes() {
            let index = nodes
                .checked_add(count)
                .context("proof node index overflow")?;
            self = self.put(index, batch, &Record::Node(digest)).await?;
            count += 1;
        }
        ensure!(count == node_count(len), "proof tree shape mismatch");
        Ok(self)
    }

    async fn leaf(&self, span: Span, position: u32) -> Result<Record> {
        ensure!(position < span.len, "proof leaf position out of bounds");
        let index = span
            .leaves
            .checked_add(u64::from(position))
            .context("proof leaf index overflow")?;
        self.archive
            .get(Identifier::Index(index))
            .await?
            .context("missing indexed proof leaf")
    }

    async fn find(&self, span: Span, key: &Key) -> Result<std::result::Result<(u32, Record), u32>> {
        let mut low = 0;
        let mut high = span.len;
        while low < high {
            let position = low + (high - low) / 2;
            let record = self.leaf(span, position).await?;
            match record.key()?.as_ref().cmp(key.as_ref()) {
                Ordering::Less => low = position + 1,
                Ordering::Greater => high = position,
                Ordering::Equal => return Ok(Ok((position, record))),
            }
        }
        Ok(Err(low))
    }

    async fn proof(
        &self,
        nodes: u64,
        len: u32,
        start: u32,
        count: u32,
    ) -> Result<bmt::Proof<Digest>> {
        if count == 0 {
            ensure!(len == 0 && start == 0, "invalid empty proof range");
            return Ok(bmt::Proof::default());
        }
        let end = start
            .checked_add(count)
            .filter(|end| *end <= len)
            .context("proof range out of bounds")?;
        let positions = bmt::range_proof_positions(len, start, end - 1)?;
        let mut siblings = Vec::with_capacity(positions.len());
        let mut level = 0;
        let mut width = u64::from(len);
        let mut offset = nodes;
        for (target_level, index) in positions {
            while level < target_level {
                offset = offset
                    .checked_add(width & !1)
                    .context("proof node index overflow")?;
                width = width.div_ceil(2);
                level += 1;
            }
            let index = u64::try_from(index)?;
            ensure!(
                index < (width & !1),
                "proof schedule requested an unstored node"
            );
            let index = offset
                .checked_add(index)
                .context("proof node index overflow")?;
            let Some(Record::Node(digest)) = self.archive.get(Identifier::Index(index)).await?
            else {
                bail!("missing indexed proof node");
            };
            siblings.push(digest);
        }
        Ok(bmt::Proof {
            leaf_count: len,
            siblings,
        })
    }

    async fn opening(&self, span: Span, position: u32) -> Result<Opening<Digest>> {
        Ok(Opening {
            position,
            proof: self.proof(span.nodes(), span.len, position, 1).await?,
        })
    }

    async fn bracket(
        &self,
        span: Span,
        position: u32,
    ) -> Result<(Option<Record>, Option<Record>, RangeOpening<Digest>)> {
        ensure!(position <= span.len, "proof bracket position out of bounds");
        let predecessor = match position.checked_sub(1) {
            Some(position) => Some(self.leaf(span, position).await?),
            None => None,
        };
        let successor = if position < span.len {
            Some(self.leaf(span, position).await?)
        } else {
            None
        };
        let start = position - u32::from(predecessor.is_some());
        let count = u32::from(predecessor.is_some()) + u32::from(successor.is_some());
        let proof = self.proof(span.nodes(), span.len, start, count).await?;
        Ok((predecessor, successor, RangeOpening { start, proof }))
    }

    async fn change(
        &self,
        span: Span,
        account: &Key,
    ) -> Result<std::result::Result<(Change, Opening<Digest>), ChangeAbsence<Key, Digest>>> {
        match self.find(span, account).await? {
            Ok((position, Record::Change(value))) => {
                Ok(Ok((value, self.opening(span, position).await?)))
            }
            Ok(_) => bail!("change span contains another leaf kind"),
            Err(position) => {
                let (predecessor, successor, opening) = self.bracket(span, position).await?;
                let guard = |record| match record {
                    Record::Change(value) => Ok(value.guard),
                    _ => bail!("change bracket contains another leaf kind"),
                };
                Ok(Err(ChangeAbsence {
                    predecessor: predecessor.map(guard).transpose()?,
                    successor: successor.map(guard).transpose()?,
                    opening,
                }))
            }
        }
    }

    async fn account(
        &self,
        descriptor: &Descriptor,
        account: &Key,
    ) -> Result<AccountLookup<Key, Digest>> {
        let lookup = match self.change(descriptor.changes, account).await? {
            Ok((change, proof)) => AccountLookup::Present(Box::new(ChangeOpening {
                value: change.value,
                proof,
            })),
            Err(absence) => AccountLookup::Absent(absence),
        };
        lookup.resolve::<Sha256>(&descriptor.roots.change, account)?;
        Ok(lookup)
    }

    async fn entry(&self, span: Span, recipient: &Key) -> Result<OutTipLookup<Key, Digest>> {
        match self.find(span, recipient).await? {
            Ok((position, Record::Entry(value))) => Ok(OutTipLookup::Present {
                cumulative: value.cumulative,
                count: value.count,
                opening: self.opening(span, position).await?,
            }),
            Ok(_) => bail!("outgoing span contains another leaf kind"),
            Err(position) => {
                let (predecessor, successor, opening) = self.bracket(span, position).await?;
                let entry = |record| match record {
                    Record::Entry(value) => Ok(value),
                    _ => bail!("outgoing bracket contains another leaf kind"),
                };
                Ok(OutTipLookup::Absent {
                    predecessor: predecessor.map(entry).transpose()?,
                    successor: successor.map(entry).transpose()?,
                    opening,
                })
            }
        }
    }

    /// Builds one response from the descriptor authorized by the canonical journal.
    pub(super) async fn answer(
        &self,
        descriptor: &Descriptor,
        lookup: &EvidenceLookup,
    ) -> Result<EvidenceResponse> {
        ensure!(
            descriptor.context.deployment() == &self.deployment
                && lookup.batch() == Some(descriptor.header.batch_id::<Sha256>().digest()),
            "proof request descriptor mismatch"
        );
        let body = match lookup {
            EvidenceLookup::Change { account, .. } => {
                match self.account(descriptor, account).await? {
                    AccountLookup::Present(opening) => EvidenceBody::Change(*opening),
                    AccountLookup::Absent(_) => return Ok(EvidenceResponse::Absent),
                }
            }
            EvidenceLookup::Account { account, .. } => {
                EvidenceBody::Account(self.account(descriptor, account).await?)
            }
            EvidenceLookup::CommittedEntry {
                payer, recipient, ..
            } => {
                let lookup = match self.change(descriptor.changes, payer).await? {
                    Ok((change, proof)) => HigherEntryLookup::Present {
                        value: change.value.core(),
                        proof,
                        entry: self.entry(change.entries, recipient).await?,
                    },
                    Err(absence) => HigherEntryLookup::Absent(absence),
                };
                lookup.resolve::<Sha256>(&descriptor.roots.change, payer, recipient)?;
                EvidenceBody::CommittedEntry(lookup)
            }
            EvidenceLookup::WithdrawalOutput { account, .. } => {
                let found = self.find(descriptor.withdrawals, account).await?;
                let (position, request, output) = match found {
                    Ok((position, Record::Withdrawal { request, output })) => {
                        (position, request, output)
                    }
                    Ok(_) => bail!("withdrawal span contains another leaf kind"),
                    Err(_) => return Ok(EvidenceResponse::Absent),
                };
                let witness = WithdrawalWitness {
                    context: descriptor.context.clone(),
                    withdrawal_total: descriptor.withdrawal_total,
                    request,
                    opening: self.opening(descriptor.withdrawals, position).await?,
                    claim: WithdrawalClaim::new(
                        output,
                        Opening {
                            position,
                            proof: self
                                .proof(
                                    descriptor.withdrawals.end(),
                                    descriptor.withdrawals.len,
                                    position,
                                    1,
                                )
                                .await?,
                        },
                    ),
                };
                ensure!(
                    witness.verify(
                        &descriptor.roots,
                        &self.deployment,
                        account,
                        witness.request.body().destination().as_ref(),
                    )? == descriptor.header.batch_id::<Sha256>(),
                    "withdrawal proof descriptor mismatch"
                );
                EvidenceBody::WithdrawalOutput(witness)
            }
            _ => bail!("non-activity lookup passed to proof store"),
        };
        Ok(EvidenceResponse::Served(Evidence::Close {
            header: descriptor.header,
            roots: descriptor.roots,
            body,
        }))
    }
}

fn reserve(next: &mut u64, count: u64) -> Result<u64> {
    let first = *next;
    *next = next
        .checked_add(count)
        .context("proof archive index overflow")?;
    Ok(first)
}

fn node_count(len: u32) -> u64 {
    let mut width = u64::from(len);
    let mut count = 0;
    while width > 1 {
        count += width & !1;
        width = width.div_ceil(2);
    }
    count
}
