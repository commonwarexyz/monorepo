//! Original proof sources retained by the native activity log.
//!
//! A source proof authenticates an epoch's Commit under a finalized activity head. The embedding
//! supplies the payout head from the same finalized snapshot. Native operations and original
//! vectors are the source of account and withdrawal proofs.

use crate::bajillion::{
    boundary::{SignedWithdrawal, WithdrawalBatch},
    challenge::{AccountLookup, ChangeAbsence, ChangeOpening, HigherEntryLookup},
    commitment::MAX_VECTOR_LENGTH,
    logs::{Heads, Logs, Opening},
    serve::ServeError,
    state::{AccountChange, ChangeValue, ChangeValueCore, SettlementOutput},
    transition::{ActivityRange, CloseContext, TransitionError, WithdrawalClaim, WithdrawalOutput},
    vector::{OutEntry, OutVector},
};
use alloc::{boxed::Box, vec::Vec};
use bytes::{Buf as _, BufMut, Bytes};
use commonware_codec::{
    Buf, DecodeExt, EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt, Write,
};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_parallel::Strategy;
use commonware_runtime::Spawner;
use commonware_storage::{
    Context,
    merkle::{Family as _, mmr},
};
use core::num::NonZeroU64;

/// Original terminal sequence and outgoing entries for one native Guard.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceRow<P: PublicKey> {
    terminal_seq: u64,
    entries: Vec<OutEntry<P>>,
}

impl<P: PublicKey> SourceRow<P> {
    /// Returns the terminal sequence, including valid sequence zero.
    pub const fn terminal_seq(&self) -> u64 {
        self.terminal_seq
    }

    /// Returns the original outgoing-vector leaves.
    pub fn entries(&self) -> &[OutEntry<P>] {
        &self.entries
    }
}

impl<P: PublicKey> Write for SourceRow<P> {
    fn write(&self, buf: &mut impl BufMut) {
        self.terminal_seq.write(buf);
        self.entries.write(buf);
    }
}

impl<P: PublicKey> EncodeSize for SourceRow<P> {
    fn encode_size(&self) -> usize {
        u64::SIZE + self.entries.encode_size()
    }
}

impl<P: PublicKey> Read for SourceRow<P> {
    type Cfg = RangeCfg<usize>;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let terminal_seq = u64::read(buf)?;
        let count = usize::read_cfg(buf, cfg)?;
        if count > buf.remaining() / OutEntry::<P>::SIZE {
            return Err(CodecError::InvalidLength(count));
        }
        let entries = OutEntry::<P>::read_vec(buf, count, &())?;
        if entries.is_empty() && terminal_seq != 0 {
            return Err(CodecError::Invalid(
                "SourceRow",
                "empty vector has nonzero sequence",
            ));
        }
        Ok(Self {
            terminal_seq,
            entries,
        })
    }
}

/// Original source information carried by one activity Commit.
///
/// Rows follow the epoch's sorted native Guards. The native payout log owns released amounts;
/// outgoing totals, BMT roots and proof nodes are derived from these original leaves.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceMetadata<P: PublicKey, D: Digest> {
    context: CloseContext<P, D>,
    rows: Vec<SourceRow<P>>,
    withdrawals: WithdrawalBatch<P, D>,
}

impl<P: PublicKey, D: Digest> SourceMetadata<P, D> {
    pub(crate) fn from_close(
        context: &CloseContext<P, D>,
        leaves: &[AccountChange<P, D>],
        vectors: &[OutVector<P>],
        withdrawals: &WithdrawalBatch<P, D>,
    ) -> Self {
        Self {
            context: context.clone(),
            rows: leaves
                .iter()
                .zip(vectors)
                .map(|(leaf, vector)| SourceRow {
                    terminal_seq: leaf.terminal_seq(),
                    entries: vector.entries().to_vec(),
                })
                .collect(),
            withdrawals: withdrawals.clone(),
        }
    }

    /// Returns the original registered context.
    pub const fn context(&self) -> &CloseContext<P, D> {
        &self.context
    }

    /// Returns the original sources in Guard order.
    pub fn rows(&self) -> &[SourceRow<P>] {
        &self.rows
    }

    /// Returns the exact signed withdrawal boundary.
    pub const fn withdrawals(&self) -> &WithdrawalBatch<P, D> {
        &self.withdrawals
    }

    fn range<H: Hasher<Digest = D>>(
        &self,
        heads: &Heads<D>,
        commit: u64,
    ) -> Result<ActivityRange<D>, TransitionError> {
        let predecessor = self.context.predecessor_logs();
        let floors = self.context.floors();
        let start = predecessor.activity.operations;
        let payout_end = predecessor
            .payouts
            .operations
            .checked_add(self.withdrawals.len() as u64)
            .ok_or(TransitionError::LogRange)?;
        if !self.context.epoch_context().verify_anchor::<H>()
            || self.withdrawals.root::<H>()? != *self.context.withdrawal_root()
            || start == 0
            || predecessor.activity.floor >= start
            || floors.activity < predecessor.activity.floor
            || floors.activity >= start
            || predecessor.payouts.operations == 0
            || predecessor.payouts.floor >= predecessor.payouts.operations
            || floors.payouts < predecessor.payouts.floor
            || floors.payouts >= predecessor.payouts.operations
            || start.checked_add(self.rows.len() as u64) != Some(commit)
            || commit >= heads.activity.operations
            || payout_end >= heads.payouts.operations
            || heads.activity.operations > mmr::Family::MAX_LEAVES
            || heads.payouts.operations > mmr::Family::MAX_LEAVES
            || heads.activity.floor >= heads.activity.operations
            || heads.payouts.floor >= heads.payouts.operations
        {
            return Err(TransitionError::LogRange);
        }
        Ok(ActivityRange {
            start,
            end: commit,
            head: heads.activity,
        })
    }
}

impl<P: PublicKey, D: Digest> Write for SourceMetadata<P, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.context.write(buf);
        self.rows.write(buf);
        self.withdrawals.write(buf);
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for SourceMetadata<P, D> {
    fn encode_size(&self) -> usize {
        self.context.encode_size() + self.rows.encode_size() + self.withdrawals.encode_size()
    }
}

impl<P: PublicKey, D: Digest> Read for SourceMetadata<P, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let context = CloseContext::<P, D>::read(buf)?;
        let limits = context.limits();
        let maximum = limits
            .max_rows()
            .min(u64::from(MAX_VECTOR_LENGTH))
            .min((buf.remaining() / (u64::SIZE + 1)) as u64) as usize;
        let count = usize::read_cfg(buf, &RangeCfg::new(..=maximum))?;
        let mut rows = Vec::with_capacity(count);
        let mut remaining_entries = limits.max_total_entries();
        for _ in 0..count {
            let maximum = limits
                .max_account_entries()
                .min(remaining_entries)
                .min(u64::from(MAX_VECTOR_LENGTH))
                .min((buf.remaining() / OutEntry::<P>::SIZE) as u64)
                as usize;
            let row = SourceRow::read_cfg(buf, &RangeCfg::new(..=maximum))?;
            remaining_entries -= row.entries.len() as u64;
            rows.push(row);
        }
        let minimum_withdrawal =
            P::SIZE + 2 * D::SIZE + 2 * u8::SIZE + u64::SIZE + P::Signature::SIZE;
        let maximum = limits
            .max_withdrawals()
            .min(u64::from(MAX_VECTOR_LENGTH))
            .min((buf.remaining() / minimum_withdrawal) as u64) as usize;
        let available = buf.remaining();
        let withdrawals = WithdrawalBatch::read_cfg(
            buf,
            &(RangeCfg::new(..=maximum), RangeCfg::new(..=available)),
        )?;
        Ok(Self {
            context,
            rows,
            withdrawals,
        })
    }
}

/// Native authentication of an epoch's original sources under a finalized activity head.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceProof<D: Digest> {
    /// Exact activity Commit metadata bytes.
    pub metadata: Bytes,
    /// Native opening of the Commit containing those bytes.
    pub opening: Opening<D>,
}

impl<D: Digest> SourceProof<D> {
    /// Verifies against activity and payout heads from one authenticated finalized snapshot.
    ///
    /// The returned source authorizes its old Guard interval under the current activity root.
    /// Physical retention may keep that interval even after the committed floor has passed it.
    pub fn verify<H: Hasher<Digest = D>, P: PublicKey>(
        &self,
        heads: &Heads<D>,
    ) -> Result<Source<P, D>, TransitionError> {
        let context = CloseContext::<P, D>::read(&mut self.metadata.clone())?;
        self.opening.verify_activity_metadata::<H, P>(
            &heads.activity,
            &self.metadata,
            context.floors().activity,
        )?;
        let metadata = SourceMetadata::<P, D>::decode(self.metadata.clone())?;
        let range = metadata.range::<H>(heads, self.opening.start)?;
        Ok(Source {
            metadata,
            range,
            heads: *heads,
        })
    }
}

impl<D: Digest> Write for SourceProof<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.metadata.write(buf);
        self.opening.write(buf);
    }
}

impl<D: Digest> EncodeSize for SourceProof<D> {
    fn encode_size(&self) -> usize {
        self.metadata.encode_size() + self.opening.encode_size()
    }
}

impl<D: Digest> Read for SourceProof<D> {
    type Cfg = RangeCfg<usize>;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            metadata: Bytes::read_cfg(buf, cfg)?,
            opening: Opening::read(buf)?,
        })
    }
}

/// Source context and range authenticated under one finalized pair of native heads.
#[derive(Clone, Debug)]
pub struct Source<P: PublicKey, D: Digest> {
    metadata: SourceMetadata<P, D>,
    range: ActivityRange<D>,
    heads: Heads<D>,
}

impl<P: PublicKey, D: Digest> Source<P, D> {
    /// Returns the authenticated original context.
    pub const fn context(&self) -> &CloseContext<P, D> {
        &self.metadata.context
    }

    /// Returns the source epoch's exact Guard interval under the finalized activity head.
    pub const fn activity_range(&self) -> &ActivityRange<D> {
        &self.range
    }

    /// Returns the paired heads used to authenticate this source.
    pub const fn heads(&self) -> Heads<D> {
        self.heads
    }

    /// Returns the authenticated original withdrawal requests.
    pub const fn withdrawals(&self) -> &WithdrawalBatch<P, D> {
        &self.metadata.withdrawals
    }

    /// Returns the native payout location for this account's signed request.
    pub fn withdrawal_index(&self, account: &P) -> Option<u64> {
        let index = self
            .metadata
            .withdrawals
            .requests()
            .binary_search_by(|request| request.account().as_ref().cmp(account.as_ref()))
            .ok()?;
        self.context()
            .predecessor_logs()
            .payouts
            .operations
            .checked_add(index as u64)
    }

    /// Binds an exact signed request and its output to this finalized source snapshot.
    pub fn verify_withdrawal<H: Hasher<Digest = D>>(
        &self,
        request: &SignedWithdrawal<P, D>,
        claim: &WithdrawalClaim<D>,
    ) -> Result<WithdrawalOutput, TransitionError> {
        if self.withdrawals().request_for(request.account()) != Some(request)
            || self.withdrawal_index(request.account()) != Some(claim.position())
        {
            return Err(TransitionError::WithdrawalClaim);
        }
        let output = claim.verify::<H>(&self.heads.payouts)?;
        if output.destination() != request.body().destination() {
            return Err(TransitionError::WithdrawalClaim);
        }
        Ok(output)
    }
}

/// Ephemeral proof-serving view over one retained native epoch.
///
/// Loading may walk preceding Commit operations. Callers authenticate returned proofs against
/// their chosen paired heads to establish finality.
pub struct Epoch<P: PublicKey, D: Digest> {
    metadata: SourceMetadata<P, D>,
    encoded: Bytes,
    commit: u64,
}

impl<P: PublicKey, D: Digest> Epoch<P, D> {
    /// Finds an epoch by walking retained predecessor Commit locations.
    pub async fn load<E, H, S>(logs: &Logs<E, H, P, S>, epoch: u64) -> Result<Self, TransitionError>
    where
        E: Context + Spawner,
        H: Hasher<Digest = D>,
        S: Strategy,
    {
        let heads = *logs.head();
        let mut commit = heads
            .activity
            .operations
            .checked_sub(1)
            .ok_or(TransitionError::SourceUnavailable)?;
        while commit != 0 {
            let (encoded, _, opening) = logs.activity_metadata_at(&heads.activity, commit).await?;
            let proof = SourceProof {
                metadata: encoded.clone(),
                opening,
            };
            let source = proof.verify::<H, P>(&heads)?;
            let found = source.context().payment().epoch();
            if found == epoch {
                return Ok(Self {
                    metadata: source.metadata,
                    encoded,
                    commit,
                });
            }
            if found < epoch {
                return Err(TransitionError::SourceUnavailable);
            }
            let previous = source
                .context()
                .predecessor_logs()
                .activity
                .operations
                .checked_sub(1)
                .ok_or(TransitionError::LogRange)?;
            if previous >= commit {
                return Err(TransitionError::LogRange);
            }
            commit = previous;
        }
        Err(TransitionError::SourceUnavailable)
    }

    /// Returns the retained original context; authenticate its source proof before remote use.
    pub const fn context(&self) -> &CloseContext<P, D> {
        &self.metadata.context
    }

    /// Opens the original source Commit under the requested finalized head.
    pub async fn source_proof<E, H, S>(
        &self,
        logs: &Logs<E, H, P, S>,
        heads: &Heads<D>,
    ) -> Result<SourceProof<D>, TransitionError>
    where
        E: Context + Spawner,
        H: Hasher<Digest = D>,
        S: Strategy,
    {
        let (metadata, _, opening) = logs
            .activity_metadata_at(&heads.activity, self.commit)
            .await?;
        if metadata != self.encoded {
            return Err(TransitionError::ChangeRoot);
        }
        let proof = SourceProof { metadata, opening };
        proof.verify::<H, P>(heads)?;
        Ok(proof)
    }

    async fn find<E, H, S>(
        &self,
        logs: &Logs<E, H, P, S>,
        account: &P,
    ) -> Result<Result<u64, u64>, TransitionError>
    where
        E: Context + Spawner,
        H: Hasher<Digest = D>,
        S: Strategy,
    {
        let mut start = self.context().predecessor_logs().activity.operations;
        let mut end = self.commit;
        while start < end {
            let middle = start + (end - start) / 2;
            let guard = logs.activity_guard_at(middle).await?;
            match guard.account().as_ref().cmp(account.as_ref()) {
                core::cmp::Ordering::Less => start = middle + 1,
                core::cmp::Ordering::Greater => end = middle,
                core::cmp::Ordering::Equal => return Ok(Ok(middle)),
            }
        }
        Ok(Err(start))
    }

    async fn value<E, H, S>(
        &self,
        logs: &Logs<E, H, P, S>,
        source: &Source<P, D>,
        index: u64,
        account: &P,
    ) -> Result<ChangeValue<D>, TransitionError>
    where
        E: Context + Spawner,
        H: Hasher<Digest = D>,
        S: Strategy,
    {
        let ordinal = index
            .checked_sub(source.range.start)
            .and_then(|i| usize::try_from(i).ok())
            .ok_or(TransitionError::LogRange)?;
        let row = self
            .metadata
            .rows
            .get(ordinal)
            .ok_or(TransitionError::LogRange)?;
        let vector = OutVector::new(
            self.context().payment().epoch(),
            account.clone(),
            row.entries.clone(),
        )?;
        let output = if let Some(index) = source.withdrawal_index(account) {
            let output = logs.payout_at(index).await?;
            let (opening, _) = logs
                .payout_opening(&source.heads.payouts, index, NonZeroU64::MIN)
                .await?;
            let claim = WithdrawalClaim::new(output, opening);
            let request = source
                .withdrawals()
                .request_for(account)
                .ok_or(TransitionError::WithdrawalClaim)?;
            SettlementOutput::Withdrawal(source.verify_withdrawal::<H>(request, &claim)?.amount())
        } else {
            SettlementOutput::None
        };
        let value = ChangeValue::from_core(
            ChangeValueCore::from_sources(output, vector.totals()?.0, row.terminal_seq),
            vector.root::<H, D>()?,
        );
        Ok(value)
    }

    /// Generates compact account membership or ordered absence from retained native operations.
    pub async fn account_lookup<E, H, S>(
        &self,
        logs: &Logs<E, H, P, S>,
        heads: &Heads<D>,
        account: &P,
    ) -> Result<AccountLookup<P, D>, ServeError>
    where
        E: Context + Spawner,
        H: Hasher<Digest = D>,
        S: Strategy,
    {
        let source = self
            .source_proof(logs, heads)
            .await?
            .verify::<H, P>(heads)?;
        let lookup = match self.find(logs, account).await? {
            Ok(index) => {
                let value = self.value(logs, &source, index, account).await?;
                let (proof, _) = logs
                    .activity_opening(&heads.activity, index, NonZeroU64::MIN)
                    .await
                    .map_err(TransitionError::from)?;
                AccountLookup::Present(Box::new(ChangeOpening { value, proof }))
            }
            Err(index) => {
                let predecessor = if index > source.range.start {
                    Some(
                        logs.activity_guard_at(index - 1)
                            .await
                            .map_err(TransitionError::from)?,
                    )
                } else {
                    None
                };
                let successor = if index < source.range.end {
                    Some(
                        logs.activity_guard_at(index)
                            .await
                            .map_err(TransitionError::from)?,
                    )
                } else {
                    None
                };
                let count = u64::from(predecessor.is_some()) + u64::from(successor.is_some());
                let opening = if let Some(count) = NonZeroU64::new(count) {
                    Some(
                        logs.activity_opening(
                            &heads.activity,
                            index - u64::from(predecessor.is_some()),
                            count,
                        )
                        .await
                        .map_err(TransitionError::from)?
                        .0,
                    )
                } else {
                    None
                };
                AccountLookup::Absent(ChangeAbsence {
                    predecessor,
                    successor,
                    opening,
                })
            }
        };
        lookup.resolve::<H>(&source.range, account)?;
        Ok(lookup)
    }

    /// Rebuilds one payer's BMT and combines its lookup with the native Guard proof.
    pub async fn higher_entry_lookup<E, H, S>(
        &self,
        logs: &Logs<E, H, P, S>,
        heads: &Heads<D>,
        payer: &P,
        recipient: &P,
    ) -> Result<HigherEntryLookup<P, D>, ServeError>
    where
        E: Context + Spawner,
        H: Hasher<Digest = D>,
        S: Strategy,
    {
        let account = self.account_lookup(logs, heads, payer).await?;
        let range = self.metadata.range::<H>(heads, self.commit)?;
        let lookup = match account {
            AccountLookup::Present(opening) => {
                let ordinal = usize::try_from(opening.proof.start - range.start)
                    .map_err(|_| TransitionError::LogRange)?;
                let vector = OutVector::new(
                    self.context().payment().epoch(),
                    payer.clone(),
                    self.metadata.rows[ordinal].entries.clone(),
                )
                .map_err(TransitionError::from)?;
                HigherEntryLookup::Present {
                    value: opening.value.core(),
                    proof: opening.proof,
                    entry: vector
                        .lookup::<H, D>(recipient)
                        .map_err(TransitionError::from)?,
                }
            }
            AccountLookup::Absent(absence) => HigherEntryLookup::Absent(absence),
        };
        lookup.resolve::<H>(&range, payer, recipient)?;
        Ok(lookup)
    }

    /// Opens the exact registered account's payout under the requested finalized head.
    pub async fn withdrawal_claim<E, H, S>(
        &self,
        logs: &Logs<E, H, P, S>,
        heads: &Heads<D>,
        account: &P,
    ) -> Result<WithdrawalClaim<D>, TransitionError>
    where
        E: Context + Spawner,
        H: Hasher<Digest = D>,
        S: Strategy,
    {
        let source = self
            .source_proof(logs, heads)
            .await?
            .verify::<H, P>(heads)?;
        let index = source
            .withdrawal_index(account)
            .ok_or(TransitionError::WithdrawalClaim)?;
        let output = logs.payout_at(index).await?;
        let (opening, _) = logs
            .payout_opening(&heads.payouts, index, NonZeroU64::MIN)
            .await?;
        let claim = WithdrawalClaim::new(output, opening);
        source.verify_withdrawal::<H>(
            source
                .withdrawals()
                .request_for(account)
                .ok_or(TransitionError::WithdrawalClaim)?,
            &claim,
        )?;
        Ok(claim)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a, P> arbitrary::Arbitrary<'a> for SourceRow<P>
where
    P: PublicKey + for<'b> arbitrary::Arbitrary<'b>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let entries = u.arbitrary::<Vec<OutEntry<P>>>()?;
        let terminal_seq = if entries.is_empty() {
            0
        } else {
            u.arbitrary()?
        };
        Ok(Self {
            terminal_seq,
            entries,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a, P, D> arbitrary::Arbitrary<'a> for SourceMetadata<P, D>
where
    P: PublicKey + for<'b> arbitrary::Arbitrary<'b>,
    D: Digest + for<'b> arbitrary::Arbitrary<'b>,
    P::Signature: for<'b> arbitrary::Arbitrary<'b>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let context = u.arbitrary::<CloseContext<P, D>>()?;
        let limits = context.limits();
        let mut rows = u.arbitrary::<Vec<SourceRow<P>>>()?;
        rows.truncate(limits.max_rows().min(u64::from(MAX_VECTOR_LENGTH)) as usize);
        let mut remaining = limits.max_total_entries();
        for row in &mut rows {
            let count = limits
                .max_account_entries()
                .min(remaining)
                .min(u64::from(MAX_VECTOR_LENGTH));
            row.entries.truncate(count as usize);
            remaining -= row.entries.len() as u64;
            if row.entries.is_empty() {
                row.terminal_seq = 0;
            }
        }
        let mut withdrawals = u.arbitrary::<WithdrawalBatch<P, D>>()?;
        if withdrawals.len() as u64 > limits.max_withdrawals() {
            withdrawals = WithdrawalBatch::empty();
        }
        Ok(Self {
            context,
            rows,
            withdrawals,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a, D> arbitrary::Arbitrary<'a> for SourceProof<D>
where
    D: Digest + for<'b> arbitrary::Arbitrary<'b>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            metadata: Bytes::from(u.arbitrary::<Vec<u8>>()?),
            opening: u.arbitrary()?,
        })
    }
}
