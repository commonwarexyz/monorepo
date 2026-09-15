//! Native append-only activity and payout histories.
//!
//! Each accepted close appends its activity rows, original outgoing entries, and then the keyless
//! QMDB commit operation. Native locations are stable protocol indices; commit locations are
//! intentional gaps between epoch ranges. Payout operation framing directly distinguishes output
//! appends from metadata-free commits.

use super::{commitment, state::AccountChange, transition::WithdrawalOutput, vector::OutEntry};
use bytes::BufMut;
use commonware_codec::{
    Buf, EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt as _, Write,
};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_macros::select;
use commonware_parallel::{Sequential, Strategy};
use commonware_storage::{
    Context,
    merkle::{Family as _, Location, mmr},
    qmdb::{
        self,
        any::value::VariableEncoding,
        keyless::{self, batch::MerkleizedBatch},
    },
};
use core::{future::Future, num::NonZeroU64};
use std::sync::Arc;
use thiserror::Error;

const ACTIVITY_ROW_ROLE: u8 = 0;
const ACTIVITY_ENTRY_ROLE: u8 = 1;

/// A typed value in the activity log.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActivityRecord<P: PublicKey, D: Digest> {
    /// One participating account in the epoch's ordered row prefix.
    Row(AccountChange<P, D>),
    /// One original cumulative outgoing entry in the row-delimited suffix.
    Entry(OutEntry<P>),
}

#[cfg(feature = "arbitrary")]
impl<'a, P, D> arbitrary::Arbitrary<'a> for ActivityRecord<P, D>
where
    P: PublicKey + for<'b> arbitrary::Arbitrary<'b>,
    D: Digest + for<'b> arbitrary::Arbitrary<'b>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        match u.int_in_range(0..=1)? {
            0 => Ok(Self::Row(u.arbitrary()?)),
            1 => {
                let count = u.int_in_range(1..=u64::MAX)?;
                Ok(Self::Entry(OutEntry {
                    recipient: u.arbitrary()?,
                    cumulative: u.int_in_range(count..=u64::MAX)?,
                    count,
                }))
            }
            _ => unreachable!(),
        }
    }
}

impl<P: PublicKey, D: Digest> Write for ActivityRecord<P, D> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Row(row) => {
                ACTIVITY_ROW_ROLE.write(buf);
                row.write(buf);
            }
            Self::Entry(entry) => {
                ACTIVITY_ENTRY_ROLE.write(buf);
                entry.write(buf);
            }
        }
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for ActivityRecord<P, D> {
    fn encode_size(&self) -> usize {
        u8::SIZE
            + match self {
                Self::Row(row) => row.encode_size(),
                Self::Entry(entry) => entry.encode_size(),
            }
    }
}

impl<P: PublicKey, D: Digest> Read for ActivityRecord<P, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            ACTIVITY_ROW_ROLE => Ok(Self::Row(AccountChange::read(buf)?)),
            ACTIVITY_ENTRY_ROLE => {
                let entry = OutEntry::read(buf)?;
                if !valid_entry(&entry) {
                    return Err(CodecError::Invalid(
                        "ActivityRecord",
                        "infeasible outgoing entry",
                    ));
                }
                Ok(Self::Entry(entry))
            }
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

/// Unencoded input for one native activity append-and-commit batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivityInput<P: PublicKey, D: Digest> {
    /// Full activity rows, in canonical account-byte order.
    rows: Vec<AccountChange<P, D>>,
    /// Canonical outgoing entries grouped by each row's terminal debit.
    entries: Vec<OutEntry<P>>,
}

impl<P: PublicKey, D: Digest> ActivityInput<P, D> {
    /// Construct one activity batch input.
    pub const fn new(rows: Vec<AccountChange<P, D>>, entries: Vec<OutEntry<P>>) -> Self {
        Self { rows, entries }
    }

    /// Return the ordered activity rows.
    pub fn rows(&self) -> &[AccountChange<P, D>] {
        &self.rows
    }

    /// Return the row-delimited outgoing entries.
    pub fn entries(&self) -> &[OutEntry<P>] {
        &self.entries
    }

    /// Consume the input into its native batch components.
    #[allow(clippy::type_complexity)]
    pub fn into_parts(self) -> (Vec<AccountChange<P, D>>, Vec<OutEntry<P>>) {
        (self.rows, self.entries)
    }
}

/// Native activity operation encoding.
pub type ActivityOperation<P, D> =
    keyless::Operation<mmr::Family, VariableEncoding<ActivityRecord<P, D>>>;
/// Native payout operation encoding.
pub type PayoutOperation = keyless::Operation<mmr::Family, VariableEncoding<WithdrawalOutput>>;
/// Native variable activity-log database.
pub type ActivityDb<E, H, P, S> =
    keyless::variable::Db<mmr::Family, E, ActivityRecord<P, <H as Hasher>::Digest>, H, S>;
/// Native variable-log database.
pub type PayoutDb<E, H, S> = keyless::variable::Db<mmr::Family, E, WithdrawalOutput, H, S>;
/// Independently owned native log handles.
pub type Parts<E, H, P, S> = (ActivityDb<E, H, P, S>, PayoutDb<E, H, S>);
type ActivityBatch<P, D, S> =
    MerkleizedBatch<mmr::Family, D, VariableEncoding<ActivityRecord<P, D>>, S>;
type PayoutBatch<D, S> = MerkleizedBatch<mmr::Family, D, VariableEncoding<WithdrawalOutput>, S>;

/// Physical configuration for the two native logs.
#[derive(Clone)]
pub struct Config<S: Strategy = Sequential> {
    /// Typed activity log.
    pub activity: keyless::variable::Config<(), S>,
    /// Variable-size payout log.
    pub payouts: keyless::variable::Config<RangeCfg<usize>, S>,
}

/// Descriptor of a keyless MMR prefix; callers authenticate its root and context separately.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct LogHead<D: Digest> {
    /// Native keyless root, including the selected inactive-peak bagging.
    pub root: D,
    /// Exclusive native operation count.
    pub operations: u64,
    /// Inactivity floor carried by the final commit operation.
    pub floor: u64,
}

impl<D: Digest> LogHead<D> {
    /// Construct a head after checking the native count and commit-floor domain.
    pub const fn try_new(root: D, operations: u64, floor: u64) -> Result<Self, Error> {
        let operations_loc = Location::<mmr::Family>::new(operations);
        let floor_loc = Location::<mmr::Family>::new(floor);
        if operations == 0
            || !operations_loc.is_valid()
            || !floor_loc.is_valid_index()
            || floor >= operations
        {
            return Err(Error::Head);
        }
        Ok(Self {
            root,
            operations,
            floor,
        })
    }

    /// Build the native peer-sync target while preserving a caller-selected retained prefix.
    pub fn target(&self, start: u64) -> Result<qmdb::sync::Target<mmr::Family, D>, Error> {
        Self::try_new(self.root, self.operations, self.floor)?;
        let start = Location::new(start);
        let end = Location::new(self.operations);
        if !start.is_valid() || start > Location::new(self.floor) || start >= end {
            return Err(Error::Target);
        }
        let range = commonware_utils::range::NonEmptyRange::try_from(start..end)
            .map_err(|_| Error::Target)?;
        Ok(qmdb::sync::Target {
            root: self.root,
            range,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a, D> arbitrary::Arbitrary<'a> for LogHead<D>
where
    D: Digest + arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let operations = u.int_in_range(1..=*mmr::Family::MAX_LEAVES)?;
        Ok(Self {
            root: u.arbitrary()?,
            operations,
            floor: u.int_in_range(0..=operations - 1)?,
        })
    }
}

impl<D: Digest> Write for LogHead<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.root.write(buf);
        self.operations.write(buf);
        self.floor.write(buf);
    }
}

impl<D: Digest> FixedSize for LogHead<D> {
    const SIZE: usize = D::SIZE + u64::SIZE * 2;
}

impl<D: Digest> Read for LogHead<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Self::try_new(D::read(buf)?, u64::read(buf)?, u64::read(buf)?)
            .map_err(|_| CodecError::Invalid("LogHead", "invalid operation count or floor"))
    }
}

/// Heads of both cumulative logs.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Heads<D: Digest> {
    /// Activity-log head.
    pub activity: LogHead<D>,
    /// Payout-log head.
    pub payouts: LogHead<D>,
}

impl<D: Digest> Heads<D> {
    /// Derive the two canonical bootstrap commits without opening storage.
    pub fn empty<P, H>() -> Self
    where
        P: PublicKey,
        H: Hasher<Digest = D>,
    {
        Self {
            activity: LogHead {
                root: keyless::initial_root::<mmr::Family, VariableEncoding<ActivityRecord<P, D>>, H>(
                ),
                operations: 1,
                floor: 0,
            },
            payouts: LogHead {
                root: keyless::initial_root::<mmr::Family, VariableEncoding<WithdrawalOutput>, H>(),
                operations: 1,
                floor: 0,
            },
        }
    }
}

impl<D: Digest> Write for Heads<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.activity.write(buf);
        self.payouts.write(buf);
    }
}

impl<D: Digest> FixedSize for Heads<D> {
    const SIZE: usize = LogHead::<D>::SIZE * 2;
}

impl<D: Digest> Read for Heads<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            activity: LogHead::read(buf)?,
            payouts: LogHead::read(buf)?,
        })
    }
}

/// Canonical floors captured at registration.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Floors {
    /// Activity-log floor.
    pub activity: u64,
    /// Payout-log floor.
    pub payouts: u64,
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for Floors {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let max = *mmr::Family::MAX_LEAVES - 1;
        Ok(Self {
            activity: u.int_in_range(0..=max)?,
            payouts: u.int_in_range(0..=max)?,
        })
    }
}

impl Write for Floors {
    fn write(&self, buf: &mut impl BufMut) {
        self.activity.write(buf);
        self.payouts.write(buf);
    }
}

impl FixedSize for Floors {
    const SIZE: usize = u64::SIZE * 2;
}

impl Read for Floors {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let result = Self {
            activity: u64::read(buf)?,
            payouts: u64::read(buf)?,
        };
        if Location::<mmr::Family>::new(result.activity).is_valid_index()
            && Location::<mmr::Family>::new(result.payouts).is_valid_index()
        {
            Ok(result)
        } else {
            Err(CodecError::Invalid("Floors", "floor exceeds MMR capacity"))
        }
    }
}

/// Native range opening at an exact cumulative log head.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Opening<D: Digest> {
    /// First native operation covered by the proof.
    pub start: u64,
    /// Native MMR range proof.
    pub proof: mmr::Proof<D>,
}

#[cfg(feature = "arbitrary")]
impl<'a, D> arbitrary::Arbitrary<'a> for Opening<D>
where
    D: Digest + for<'b> arbitrary::Arbitrary<'b>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let mut proof = u.arbitrary::<mmr::Proof<D>>()?;
        proof
            .digests
            .truncate(mmr::MAX_PROOF_DIGESTS_PER_ELEMENT * 2);
        Ok(Self {
            start: u.int_in_range(0..=*mmr::Family::MAX_LEAVES - 1)?,
            proof,
        })
    }
}

impl<D: Digest> Opening<D> {
    /// Verify activity rows at an arbitrary row-only subrange.
    pub fn verify_activity<H, P>(
        &self,
        head: &LogHead<D>,
        values: &[AccountChange<P, D>],
    ) -> Result<(), Error>
    where
        H: Hasher<Digest = D>,
        P: PublicKey,
    {
        let operations = values
            .iter()
            .cloned()
            .map(|row| ActivityOperation::Append(ActivityRecord::Row(row)))
            .collect::<Vec<_>>();
        self.verify::<H, _>(head, &operations)
    }

    /// Verify one payout append at its stable native location.
    pub fn verify_payout<H>(&self, head: &LogHead<D>, value: &WithdrawalOutput) -> Result<(), Error>
    where
        H: Hasher<Digest = D>,
    {
        let operations: [PayoutOperation; 1] = [PayoutOperation::Append(value.clone())];
        self.verify::<H, _>(head, &operations)
    }

    fn verify<H: Hasher<Digest = D>, Op: commonware_codec::Encode>(
        &self,
        head: &LogHead<D>,
        operations: &[Op],
    ) -> Result<(), Error> {
        LogHead::try_new(head.root, head.operations, head.floor)?;
        let start = Location::<mmr::Family>::new(self.start);
        let end = start
            .checked_add(u64::try_from(operations.len()).map_err(|_| Error::Bounds)?)
            .ok_or(Error::Bounds)?;
        let commit = Location::<mmr::Family>::new(head.operations - 1);
        if operations.is_empty()
            || !start.is_valid_index()
            || end > commit
            || self.proof.leaves != Location::new(head.operations)
            || self.proof.inactive_peaks
                != mmr::Family::inactive_peaks(
                    Location::new(head.operations),
                    Location::new(head.floor),
                )
            || !qmdb::verify_proof::<H, mmr::Family, _>(&self.proof, start, operations, &head.root)
        {
            return Err(Error::Proof);
        }
        Ok(())
    }
}

impl<D: Digest> Write for Opening<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.start.write(buf);
        self.proof.write(buf);
    }
}

impl<D: Digest> EncodeSize for Opening<D> {
    fn encode_size(&self) -> usize {
        u64::SIZE + self.proof.encode_size()
    }
}

impl<D: Digest> Read for Opening<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let start = u64::read(buf)?;
        if !Location::<mmr::Family>::new(start).is_valid_index() {
            return Err(CodecError::Invalid("Opening", "start exceeds MMR capacity"));
        }
        Ok(Self {
            start,
            proof: mmr::Proof::read_cfg(buf, &(mmr::MAX_PROOF_DIGESTS_PER_ELEMENT * 2))?,
        })
    }
}

/// The two native cumulative logs and their validated live heads.
pub struct Logs<E: Context, H: Hasher, P: PublicKey, S: Strategy = Sequential> {
    activity: ActivityDb<E, H, P, S>,
    payouts: PayoutDb<E, H, S>,
    payout_cfg: RangeCfg<usize>,
    head: Heads<H::Digest>,
}

impl<E: Context, H: Hasher, P: PublicKey, S: Strategy> Logs<E, H, P, S> {
    /// Open both native logs and derive their recovered heads.
    pub async fn open(context: E, config: Config<S>) -> Result<Self, Error> {
        validate_partitions(&config)?;
        let payout_cfg = config.payouts.log.codec_config;
        let activity = ActivityDb::init(context.child("activity"), config.activity).await?;
        let payouts = PayoutDb::init(context.child("payouts"), config.payouts).await?;
        let head = Heads {
            activity: head(&activity),
            payouts: head(&payouts),
        };
        Ok(Self {
            activity,
            payouts,
            payout_cfg,
            head,
        })
    }

    /// Assemble already-opened native stores after checking their recovered heads.
    pub fn from_parts(
        activity: ActivityDb<E, H, P, S>,
        payouts: PayoutDb<E, H, S>,
        payout_cfg: RangeCfg<usize>,
    ) -> Self {
        let head = Heads {
            activity: head(&activity),
            payouts: head(&payouts),
        };
        Self {
            activity,
            payouts,
            payout_cfg,
            head,
        }
    }

    /// Assemble native peer-sync results and bind them to an authenticated checkpoint.
    pub fn from_parts_checked(
        activity: ActivityDb<E, H, P, S>,
        payouts: PayoutDb<E, H, S>,
        payout_cfg: RangeCfg<usize>,
        expected: &Heads<H::Digest>,
    ) -> Result<Self, Error> {
        let logs = Self::from_parts(activity, payouts, payout_cfg);
        if logs.head() != expected {
            return Err(Error::Head);
        }
        Ok(logs)
    }

    /// Return both native handles for peer-sync integration.
    pub fn into_parts(self) -> Parts<E, H, P, S> {
        (self.activity, self.payouts)
    }

    /// Return the validated live log heads.
    pub const fn head(&self) -> &Heads<H::Digest> {
        &self.head
    }

    /// Return the activity native source.
    pub const fn activity_source(&self) -> &ActivityDb<E, H, P, S> {
        &self.activity
    }

    /// Return the payout native source.
    pub const fn payout_source(&self) -> &PayoutDb<E, H, S> {
        &self.payouts
    }

    /// Return each native journal's oldest retained operation.
    pub fn retained_starts(&self) -> Floors {
        Floors {
            activity: *self.activity.bounds().start,
            payouts: *self.payouts.bounds().start,
        }
    }

    /// Read and authenticate a raw activity operation at an exact historical head.
    pub async fn raw_activity_record_at(
        &self,
        head: &LogHead<H::Digest>,
        index: u64,
    ) -> Result<ActivityOperation<P, H::Digest>, Error> {
        let (_, mut operations) = self.activity_opening(head, index, NonZeroU64::MIN).await?;
        operations.pop().ok_or(Error::Row)
    }

    /// Read an activity row Append at a retained native location.
    pub async fn activity_row_at(&self, index: u64) -> Result<AccountChange<P, H::Digest>, Error> {
        match self
            .raw_activity_record_at(&self.head.activity, index)
            .await?
        {
            ActivityOperation::Append(ActivityRecord::Row(row)) => Ok(row),
            _ => Err(Error::Row),
        }
    }

    /// Read a payout append at a retained native location.
    pub async fn payout_at(&self, index: u64) -> Result<WithdrawalOutput, Error> {
        if index >= self.head.payouts.operations - 1 {
            return Err(Error::Row);
        }
        let (_, operations) = self
            .payouts
            .proof(Location::new(index), NonZeroU64::MIN)
            .await?;
        match operations.into_iter().next() {
            Some(PayoutOperation::Append(output)) => Ok(output),
            _ => Err(Error::Row),
        }
    }

    /// Prepare one append-and-commit batch in each log.
    ///
    /// Positive rows must carry roots already validated against their entries by the transition
    /// owner. This layer validates canonical row/entry framing without rebuilding those trees.
    pub async fn prepare(
        &self,
        expected: &Heads<H::Digest>,
        activity_input: ActivityInput<P, H::Digest>,
        outputs: Vec<WithdrawalOutput>,
        floors: Floors,
    ) -> Result<PreparedLogs<P, H::Digest, S>, Error> {
        if expected != self.head() {
            return Err(Error::Predecessor);
        }
        let (rows, entries) = activity_input.into_parts();
        validate_activity::<H, P>(&rows, &entries)?;
        if outputs
            .iter()
            .any(|output| !self.payout_cfg.contains(&output.destination().len()))
        {
            return Err(Error::Bounds);
        }
        let activity_len = rows.len().checked_add(entries.len()).ok_or(Error::Bounds)?;
        validate_floor(expected.activity, floors.activity, activity_len)?;
        validate_floor(expected.payouts, floors.payouts, outputs.len())?;

        let mut activity = self.activity.new_batch();
        for row in rows {
            activity = activity.append(ActivityRecord::Row(row));
        }
        for entry in entries {
            activity = activity.append(ActivityRecord::Entry(entry));
        }
        let activity = activity.merkleize(&self.activity, None, Location::new(floors.activity));

        let mut payouts = self.payouts.new_batch();
        for output in outputs {
            payouts = payouts.append(output);
        }
        let payouts = payouts.merkleize(&self.payouts, None, Location::new(floors.payouts));
        let (activity, payouts) = join(activity, payouts).await;

        let head = Heads {
            activity: batch_head(&activity),
            payouts: batch_head(&payouts),
        };
        Ok(PreparedLogs {
            predecessor: *expected,
            head,
            activity,
            payouts,
        })
    }

    /// Apply both prepared native batches. Any error consumes the entire owner.
    pub async fn apply(self, prepared: PreparedLogs<P, H::Digest, S>) -> Result<Self, Error> {
        if prepared.predecessor != self.head {
            return Err(Error::Predecessor);
        }
        let Self {
            activity,
            payouts,
            payout_cfg,
            ..
        } = self;
        let (activity, payouts) = join(
            activity.apply_batch(prepared.activity),
            payouts.apply_batch(prepared.payouts),
        )
        .await;
        let (activity, _) = activity?;
        let (payouts, _) = payouts?;
        Ok(Self {
            activity,
            payouts,
            payout_cfg,
            head: prepared.head,
        })
    }

    /// Durably commit both logs.
    pub async fn commit(self) -> Result<Self, Error> {
        let Self {
            activity,
            payouts,
            payout_cfg,
            head,
        } = self;
        let (activity, payouts) = join(activity.commit(), payouts.commit()).await;
        Ok(Self {
            activity: activity?,
            payouts: payouts?,
            payout_cfg,
            head,
        })
    }

    /// Fully synchronize both logs.
    pub async fn sync(self) -> Result<Self, Error> {
        let Self {
            activity,
            payouts,
            payout_cfg,
            head,
        } = self;
        let (activity, payouts) = join(activity.sync(), payouts.sync()).await;
        Ok(Self {
            activity: activity?,
            payouts: payouts?,
            payout_cfg,
            head,
        })
    }

    /// Rewind both logs to an authenticated shared checkpoint.
    pub async fn rewind(mut self, target: &Heads<H::Digest>) -> Result<Self, Error> {
        validate_rewind(&self.head.activity, &target.activity)?;
        validate_rewind(&self.head.payouts, &target.payouts)?;
        self.activity = self
            .activity
            .rewind(Location::new(target.activity.operations))
            .await?;
        if head(&self.activity) != target.activity {
            return Err(Error::Head);
        }
        self.payouts = self
            .payouts
            .rewind(Location::new(target.payouts.operations))
            .await?;
        if head(&self.payouts) != target.payouts {
            return Err(Error::Head);
        }
        self.head = *target;
        Ok(self)
    }

    /// Prune each log to a caller-authenticated retained boundary.
    pub async fn prune(mut self, floors: Floors) -> Result<Self, Error> {
        if floors.activity > self.head.activity.floor || floors.payouts > self.head.payouts.floor {
            return Err(Error::Target);
        }
        self.activity = self.activity.prune(Location::new(floors.activity)).await?;
        self.payouts = self.payouts.prune(Location::new(floors.payouts)).await?;
        Ok(self)
    }

    /// Destroy both native log generations.
    pub async fn destroy(self) -> Result<(), Error> {
        let (activity, payouts) = self.into_parts();
        let activity_result = activity.destroy().await;
        let payout_result = payouts.destroy().await;
        activity_result?;
        payout_result?;
        Ok(())
    }

    /// Generate an activity proof at a retained historical head.
    pub async fn activity_opening(
        &self,
        head: &LogHead<H::Digest>,
        start: u64,
        count: NonZeroU64,
    ) -> Result<(Opening<H::Digest>, Vec<ActivityOperation<P, H::Digest>>), Error> {
        LogHead::try_new(head.root, head.operations, head.floor)?;
        let (proof, operations) = self
            .activity
            .historical_proof(Location::new(head.operations), Location::new(start), count)
            .await?;
        if !qmdb::verify_proof::<H, mmr::Family, _>(
            &proof,
            Location::new(start),
            &operations,
            &head.root,
        ) {
            return Err(Error::Head);
        }
        Ok((Opening { start, proof }, operations))
    }

    /// Generate a payout proof at a retained historical head.
    pub async fn payout_opening(
        &self,
        head: &LogHead<H::Digest>,
        start: u64,
        count: NonZeroU64,
    ) -> Result<(Opening<H::Digest>, Vec<PayoutOperation>), Error> {
        LogHead::try_new(head.root, head.operations, head.floor)?;
        let (proof, operations) = self
            .payouts
            .historical_proof(Location::new(head.operations), Location::new(start), count)
            .await?;
        if !qmdb::verify_proof::<H, mmr::Family, _>(
            &proof,
            Location::new(start),
            &operations,
            &head.root,
        ) {
            return Err(Error::Head);
        }
        Ok((Opening { start, proof }, operations))
    }
}

/// A prepared pair of native append-and-commit batches.
pub struct PreparedLogs<P: PublicKey, D: Digest, S: Strategy = Sequential> {
    predecessor: Heads<D>,
    head: Heads<D>,
    activity: Arc<ActivityBatch<P, D, S>>,
    payouts: Arc<PayoutBatch<D, S>>,
}

impl<P: PublicKey, D: Digest, S: Strategy> PreparedLogs<P, D, S> {
    /// Return the exact predecessor.
    pub const fn predecessor(&self) -> &Heads<D> {
        &self.predecessor
    }

    /// Return the candidate heads.
    pub const fn head(&self) -> &Heads<D> {
        &self.head
    }

    /// Return all new activity operations, including the final commit.
    pub fn activity_operations(&self) -> (u64, Arc<Vec<ActivityOperation<P, D>>>) {
        let (start, operations) = self.activity.operations();
        (*start, operations)
    }

    /// Return all new payout operations, including the final commit.
    pub fn payout_operations(&self) -> (u64, Arc<Vec<PayoutOperation>>) {
        let (start, operations) = self.payouts.operations();
        (*start, operations)
    }
}

/// Drive both futures to completion, including when either result is an error.
pub(super) fn join<A, B>(
    left: impl Future<Output = A>,
    right: impl Future<Output = B>,
) -> impl Future<Output = (A, B)> {
    // Store-owning futures are large; keep the combined frame out of the replica future.
    Box::pin(async move {
        let mut left = core::pin::pin!(left);
        let mut right = core::pin::pin!(right);
        select! {
            output = &mut left => (output, right.await),
            output = &mut right => (left.await, output),
        }
    })
}

const fn valid_entry<P: PublicKey>(entry: &OutEntry<P>) -> bool {
    entry.cumulative != 0 && entry.count != 0 && entry.cumulative >= entry.count
}

fn validate_activity<H: Hasher, P: PublicKey>(
    rows: &[AccountChange<P, H::Digest>],
    entries: &[OutEntry<P>],
) -> Result<(), Error> {
    if rows.len() > commitment::MAX_VECTOR_LENGTH as usize {
        return Err(Error::Bounds);
    }
    if rows
        .windows(2)
        .any(|pair| pair[0].account().as_ref() >= pair[1].account().as_ref())
    {
        return Err(Error::Order);
    }

    let empty_root = commitment::empty_root::<H>(commitment::VectorKind::OutEntry);
    let mut cursor = 0usize;
    for row in rows {
        let debit = row.terminal_debit();
        if debit == 0 {
            if row.terminal_seq() != 0 || row.send_root() != empty_root {
                return Err(Error::Original);
            }
            continue;
        }

        let mut previous_recipient: Option<&P> = None;
        let mut group_len = 0usize;
        let mut total_credit = 0u64;
        let mut total_count = 0u64;
        while total_credit < debit {
            let entry = entries.get(cursor).ok_or(Error::Original)?;
            if !valid_entry(entry)
                || previous_recipient
                    .is_some_and(|previous| previous.as_ref() >= entry.recipient.as_ref())
            {
                return Err(Error::Original);
            }
            group_len = group_len.checked_add(1).ok_or(Error::Bounds)?;
            if group_len > commitment::MAX_VECTOR_LENGTH as usize {
                return Err(Error::Original);
            }
            total_credit = total_credit
                .checked_add(entry.cumulative)
                .ok_or(Error::Original)?;
            total_count = total_count
                .checked_add(entry.count)
                .ok_or(Error::Original)?;
            if total_credit > debit {
                return Err(Error::Original);
            }
            previous_recipient = Some(&entry.recipient);
            cursor = cursor.checked_add(1).ok_or(Error::Bounds)?;
        }
    }
    if cursor != entries.len() {
        return Err(Error::Original);
    }
    Ok(())
}

fn validate_floor<D: Digest>(head: LogHead<D>, floor: u64, rows: usize) -> Result<(), Error> {
    let floor = Location::<mmr::Family>::new(floor);
    let commit = Location::<mmr::Family>::new(head.operations)
        .checked_add(u64::try_from(rows).map_err(|_| Error::Bounds)?)
        .ok_or(Error::Bounds)?;
    commit.checked_add(1).ok_or(Error::Bounds)?;
    if !floor.is_valid_index() || *floor < head.floor || floor > commit {
        return Err(Error::Floor);
    }
    Ok(())
}

fn validate_rewind<D: Digest>(live: &LogHead<D>, target: &LogHead<D>) -> Result<(), Error> {
    LogHead::try_new(target.root, target.operations, target.floor)?;
    if target.operations > live.operations {
        return Err(Error::Target);
    }
    Ok(())
}

fn head<E, H, V, C, S>(db: &keyless::Keyless<mmr::Family, E, V, C, H, S>) -> LogHead<H::Digest>
where
    E: Context,
    H: Hasher,
    V: qmdb::any::value::ValueEncoding,
    C: commonware_storage::journal::contiguous::Mutable<Item = keyless::Operation<mmr::Family, V>>,
    S: Strategy,
    keyless::Operation<mmr::Family, V>: commonware_codec::EncodeShared,
{
    LogHead {
        root: db.root(),
        operations: *db.bounds().end,
        floor: *db.inactivity_floor_loc(),
    }
}

fn batch_head<D, V, S>(batch: &MerkleizedBatch<mmr::Family, D, V, S>) -> LogHead<D>
where
    D: Digest,
    V: qmdb::any::value::ValueEncoding,
    S: Strategy,
    keyless::Operation<mmr::Family, V>: commonware_codec::EncodeShared,
{
    LogHead {
        root: batch.root(),
        operations: *batch.bounds().tip.size,
        floor: *batch.bounds().inactivity_floor,
    }
}

pub(super) fn physical_partitions<S: Strategy>(config: &Config<S>) -> Vec<String> {
    let mut partitions = Vec::with_capacity(16);
    for merkle in [&config.activity.merkle, &config.payouts.merkle] {
        let journal = &merkle.journal_partition;
        partitions.extend([
            journal.clone(),
            format!("{journal}-blobs"),
            format!("{journal}-metadata"),
            merkle.metadata_partition.clone(),
        ]);
    }
    for log in [
        config.activity.log.partition.as_str(),
        config.payouts.log.partition.as_str(),
    ] {
        let offsets = format!("{log}_offsets");
        partitions.extend([
            format!("{log}_data"),
            offsets.clone(),
            format!("{offsets}-blobs"),
            format!("{offsets}-metadata"),
        ]);
    }
    partitions
}

fn validate_partitions<S: Strategy>(config: &Config<S>) -> Result<(), Error> {
    let mut partitions = physical_partitions(config);
    partitions.sort_unstable();
    if partitions.windows(2).any(|pair| pair[0] == pair[1]) {
        Err(Error::Partition)
    } else {
        Ok(())
    }
}

/// Failure to construct, mutate, or prove the native logs.
#[derive(Debug, Error)]
pub enum Error {
    /// A native storage operation failed. Mutable callers must discard the entire owner.
    #[error("flat log storage: {0}")]
    Storage(#[from] qmdb::Error<mmr::Family>),
    /// Native partitions overlap.
    #[error("flat log partitions must be distinct")]
    Partition,
    /// The supplied head is outside the native count/floor domain.
    #[error("invalid flat log head")]
    Head,
    /// A candidate belongs to another live prefix.
    #[error("flat log predecessor does not match")]
    Predecessor,
    /// Activity rows are not strictly ordered.
    #[error("activity rows are not strictly account-sorted")]
    Order,
    /// Original entries do not form canonical row-delimited payer groups.
    #[error("activity entries are not canonical for their rows")]
    Original,
    /// A registered floor regresses or exceeds its candidate commit location.
    #[error("invalid flat log floor")]
    Floor,
    /// Native location arithmetic overflowed.
    #[error("flat log range exceeds MMR capacity")]
    Bounds,
    /// A retained or sync target is invalid.
    #[error("invalid flat log target")]
    Target,
    /// A native opening does not authenticate the exact operation range and head.
    #[error("invalid flat log proof")]
    Proof,
    /// The requested location is not a retained append of the requested role.
    #[error("native location is not a retained append of the requested role")]
    Row,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bajillion::{custody::Epoch, transition::ActivityRange};
    use bytes::Bytes;
    use commonware_codec::{Decode as _, DecodeExt as _, Encode as _};
    use commonware_cryptography::{Sha256, Signer as _, sha256::Digest as ShaDigest};
    use commonware_cryptography_curve25519::signing::{
        SigningKey, StrictVerifyingKey as VerifyingKey,
    };
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
    };
    use commonware_storage::{journal::contiguous::variable, merkle::full};
    use commonware_utils::{NZU16, NZU64, NZUsize};
    use core::{
        pin::Pin,
        task::{Context as TaskContext, Poll},
    };
    use std::sync::atomic::{AtomicBool, Ordering};

    type TestLogs = Logs<deterministic::Context, Sha256, VerifyingKey, Sequential>;
    type TestActivityDb = ActivityDb<deterministic::Context, Sha256, VerifyingKey, Sequential>;

    fn activity_row(
        account: VerifyingKey,
        debit: u64,
        seq: u64,
        send_root: commitment::VectorRoot<ShaDigest>,
    ) -> AccountChange<VerifyingKey, ShaDigest> {
        let mut bytes = Vec::new();
        account.write(&mut bytes);
        debit.write(&mut bytes);
        seq.write(&mut bytes);
        send_root.write(&mut bytes);
        AccountChange::decode(Bytes::from(bytes)).unwrap()
    }

    fn outgoing_root(
        payer: VerifyingKey,
        entries: &[OutEntry<VerifyingKey>],
    ) -> commitment::VectorRoot<ShaDigest> {
        crate::bajillion::vector::OutVector::new(0, payer, entries.to_vec())
            .unwrap()
            .root::<Sha256, ShaDigest>()
            .unwrap()
    }

    async fn activity_operation_at(
        db: &TestActivityDb,
        index: u64,
    ) -> ActivityOperation<VerifyingKey, ShaDigest> {
        let (_, mut operations) = db
            .proof(Location::new(index), NonZeroU64::MIN)
            .await
            .unwrap();
        assert_eq!(operations.len(), 1);
        operations.pop().unwrap()
    }

    struct Rendezvous {
        polled: Arc<AtomicBool>,
        peer_polled: Arc<AtomicBool>,
    }

    impl Future for Rendezvous {
        type Output = ();

        fn poll(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
            self.polled.store(true, Ordering::SeqCst);
            if self.peer_polled.load(Ordering::SeqCst) {
                Poll::Ready(())
            } else {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    struct DelayedResult {
        remaining: usize,
        completed: Arc<AtomicBool>,
    }

    impl Future for DelayedResult {
        type Output = Result<(), u8>;

        fn poll(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
            if self.remaining == 0 {
                self.completed.store(true, Ordering::SeqCst);
                Poll::Ready(Ok(()))
            } else {
                self.remaining -= 1;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    #[test]
    fn join_polls_both_and_observes_completion_after_error() {
        deterministic::Runner::default().start(|_| async move {
            let left_polled = Arc::new(AtomicBool::new(false));
            let right_polled = Arc::new(AtomicBool::new(false));
            join(
                Rendezvous {
                    polled: left_polled.clone(),
                    peer_polled: right_polled.clone(),
                },
                Rendezvous {
                    polled: right_polled.clone(),
                    peer_polled: left_polled.clone(),
                },
            )
            .await;
            assert!(left_polled.load(Ordering::SeqCst));
            assert!(right_polled.load(Ordering::SeqCst));

            let right_completed = Arc::new(AtomicBool::new(false));
            let (left, right) = join(
                async { Err::<(), _>(1) },
                DelayedResult {
                    remaining: 1,
                    completed: right_completed.clone(),
                },
            )
            .await;
            assert_eq!(left, Err(1));
            assert_eq!(right, Ok(()));
            assert!(right_completed.load(Ordering::SeqCst));

            let left_completed = Arc::new(AtomicBool::new(false));
            let (left, right) = join(
                DelayedResult {
                    remaining: 1,
                    completed: left_completed.clone(),
                },
                async { Err::<(), _>(2) },
            )
            .await;
            assert_eq!(left, Ok(()));
            assert_eq!(right, Err(2));
            assert!(left_completed.load(Ordering::SeqCst));
        });
    }

    #[test]
    fn activity_record_codec_is_bounded_and_role_tagged() {
        let payer = SigningKey::from_seed(1).public_key();
        let recipient = SigningKey::from_seed(2).public_key();
        let row = activity_row(
            payer,
            2,
            u64::MAX,
            commitment::VectorRoot {
                digest: Sha256::hash(&[b"outgoing"]),
            },
        );
        let records = [
            ActivityRecord::Row(row),
            ActivityRecord::Entry(OutEntry {
                recipient: recipient.clone(),
                cumulative: 2,
                count: 1,
            }),
        ];
        for (role, record) in records.into_iter().enumerate() {
            let encoded = record.encode();
            assert_eq!(encoded[0], role as u8);
            assert_eq!(
                ActivityRecord::<VerifyingKey, ShaDigest>::decode(encoded).unwrap(),
                record
            );
        }

        for (cumulative, count) in [(0, 1), (1, 0), (1, 2)] {
            let mut infeasible = Vec::new();
            ACTIVITY_ENTRY_ROLE.write(&mut infeasible);
            recipient.write(&mut infeasible);
            cumulative.write(&mut infeasible);
            count.write(&mut infeasible);
            assert!(
                ActivityRecord::<VerifyingKey, ShaDigest>::decode(Bytes::from(infeasible)).is_err()
            );
        }
        assert!(
            ActivityRecord::<VerifyingKey, ShaDigest>::decode(Bytes::from_static(&[2])).is_err()
        );
    }

    fn config(context: &deterministic::Context, suffix: &str) -> Config<Sequential> {
        let cache = CacheRef::from_pooler(context, NZU16!(128), NZUsize!(16));
        let merkle = |role: &str| full::Config {
            journal_partition: format!("logs-{suffix}-{role}-merkle-journal"),
            metadata_partition: format!("logs-{suffix}-{role}-merkle-metadata"),
            items_per_blob: NZU64!(64),
            write_buffer: NZUsize!(4096),
            replay_buffer: NZUsize!(4096),
            strategy: Sequential,
            page_cache: cache.clone(),
        };
        Config {
            activity: keyless::variable::Config {
                merkle: merkle("activity"),
                log: variable::Config {
                    partition: format!("logs-{suffix}-activity-log"),
                    items_per_section: NZU64!(64),
                    compression: None,
                    codec_config: (),
                    page_cache: cache.clone(),
                    write_buffer: NZUsize!(4096),
                    replay_buffer: NZUsize!(4096),
                },
            },
            payouts: keyless::variable::Config {
                merkle: merkle("payouts"),
                log: variable::Config {
                    partition: format!("logs-{suffix}-payouts-log"),
                    items_per_section: NZU64!(64),
                    compression: None,
                    codec_config: (0..=4096).into(),
                    page_cache: cache,
                    write_buffer: NZUsize!(4096),
                    replay_buffer: NZUsize!(4096),
                },
            },
        }
    }

    #[test]
    fn empty_close_keeps_commit_gap_and_rewinds() {
        deterministic::Runner::default().start(|context| async move {
            let cfg = config(&context, "empty");
            let logs = TestLogs::open(context.child("open"), cfg.clone())
                .await
                .unwrap();
            let bootstrap = *logs.head();
            assert_eq!(bootstrap, Heads::empty::<VerifyingKey, Sha256>());
            assert!(matches!(
                (LogHead {
                    root: bootstrap.activity.root,
                    operations: 0,
                    floor: 0,
                })
                .target(0),
                Err(Error::Head)
            ));

            let prepared = logs
                .prepare(
                    &bootstrap,
                    ActivityInput::new(Vec::new(), Vec::new()),
                    Vec::new(),
                    Floors {
                        activity: 0,
                        payouts: 0,
                    },
                )
                .await
                .unwrap();
            let candidate = *prepared.head();
            assert_eq!(candidate.activity.operations, 2);
            assert_eq!(candidate.payouts.operations, 2);
            let (activity_start, activity_ops) = prepared.activity_operations();
            assert_eq!(activity_start, 1);
            assert!(matches!(
                activity_ops.as_slice(),
                [ActivityOperation::Commit(None, floor)] if **floor == 0
            ));

            let logs = logs.apply(prepared).await.unwrap().commit().await.unwrap();
            assert!(matches!(logs.activity_row_at(1).await, Err(Error::Row)));
            let logs = logs.rewind(&bootstrap).await.unwrap().sync().await.unwrap();
            assert_eq!(*logs.head(), bootstrap);
            drop(logs);

            let reopened = TestLogs::open(context.child("reopen"), cfg).await.unwrap();
            assert_eq!(*reopened.head(), bootstrap);
            reopened.destroy().await.unwrap();
        });
    }

    #[test]
    fn activity_originals_are_appends_and_commit_is_metadata_free() {
        deterministic::Runner::default().start(|context| async move {
            let logs = TestLogs::open(context.child("open"), config(&context, "originals"))
                .await
                .unwrap();
            let payer = SigningKey::from_seed(7).public_key();
            let mut recipients = [
                SigningKey::from_seed(8).public_key(),
                SigningKey::from_seed(9).public_key(),
            ];
            recipients.sort_by(|left, right| left.as_ref().cmp(right.as_ref()));
            let entries = [
                OutEntry {
                    recipient: recipients[0].clone(),
                    cumulative: 10,
                    count: 3,
                },
                OutEntry {
                    recipient: recipients[1].clone(),
                    cumulative: 2,
                    count: 1,
                },
            ];
            let row = activity_row(payer.clone(), 12, 0, outgoing_root(payer, &entries));
            let predecessor = *logs.head();
            let prepared = logs
                .prepare(
                    &predecessor,
                    ActivityInput::new(vec![row.clone()], entries.to_vec()),
                    Vec::new(),
                    Floors {
                        activity: 0,
                        payouts: 0,
                    },
                )
                .await
                .unwrap();
            let (_, operations) = prepared.activity_operations();
            assert!(matches!(
                operations.as_slice(),
                [
                    ActivityOperation::Append(ActivityRecord::Row(stored_row)),
                    ActivityOperation::Append(ActivityRecord::Entry(first_entry)),
                    ActivityOperation::Append(ActivityRecord::Entry(second_entry)),
                    ActivityOperation::Commit(None, floor),
                ] if stored_row == &row
                    && first_entry == &entries[0]
                    && second_entry == &entries[1]
                    && **floor == 0
            ));
            drop(prepared);
            logs.destroy().await.unwrap();
        });
    }

    #[test]
    fn bounded_activity_corpus_crosses_native_sync_boundaries() {
        deterministic::Runner::default().start(|context| async move {
            const ENTRY_OPERATION_SIZE: usize = u8::SIZE * 2 + VerifyingKey::SIZE + u64::SIZE * 2;
            const ENTRY_COUNT: usize = 257;

            assert_eq!(ENTRY_OPERATION_SIZE, 50);
            assert!(ENTRY_COUNT <= commitment::MAX_VECTOR_LENGTH as usize);

            let payer = SigningKey::from_seed(1).public_key();
            let mut recipients = (0..ENTRY_COUNT)
                .map(|index| {
                    SigningKey::from_seed(u64::try_from(index).unwrap().checked_add(2).unwrap())
                        .public_key()
                })
                .collect::<Vec<_>>();
            recipients.sort_by(|left, right| left.as_ref().cmp(right.as_ref()));
            assert!(
                recipients
                    .windows(2)
                    .all(|pair| pair[0].as_ref() < pair[1].as_ref())
            );
            let first_recipient = recipients.first().unwrap().clone();
            let last_recipient = recipients.last().unwrap().clone();

            let entries = recipients
                .into_iter()
                .map(|recipient| OutEntry {
                    recipient,
                    cumulative: 1,
                    count: 1,
                })
                .collect::<Vec<_>>();
            let send_root = outgoing_root(payer.clone(), &entries);
            let row = activity_row(
                payer,
                u64::try_from(ENTRY_COUNT).unwrap(),
                u64::MAX,
                send_root,
            );

            let mut source_cfg = config(&context, "activity-boundaries-source");
            source_cfg.activity.merkle.items_per_blob = NZU64!(128);
            source_cfg.activity.log.items_per_section = NZU64!(128);
            let source_reopen_cfg = source_cfg.clone();
            let logs = TestLogs::open(context.child("source_open"), source_cfg)
                .await
                .unwrap();
            let predecessor = *logs.head();
            let prepared = logs
                .prepare(
                    &predecessor,
                    ActivityInput::new(vec![row.clone()], entries),
                    Vec::new(),
                    Floors {
                        activity: 0,
                        payouts: 0,
                    },
                )
                .await
                .unwrap();
            let candidate = *prepared.head();
            let (activity_start, operations) = prepared.activity_operations();
            assert_eq!(operations.len(), 259);
            assert_eq!(candidate.activity.operations, 260);
            assert_eq!(candidate.activity.operations.div_ceil(128), 3);
            let max_record_size = u8::SIZE + VerifyingKey::SIZE + u64::SIZE * 2 + ShaDigest::SIZE;
            assert_eq!(max_record_size, 81);
            assert_eq!(ActivityRecord::Row(row.clone()).encode_size(), 81);
            assert_eq!(
                ActivityOperation::Append(ActivityRecord::Row(row.clone())).encode_size(),
                82
            );
            let ActivityOperation::Append(ActivityRecord::Entry(first_entry)) = &operations[1]
            else {
                panic!("first original is not an Entry append");
            };
            assert_eq!(
                ActivityRecord::<VerifyingKey, ShaDigest>::Entry(first_entry.clone()).encode_size(),
                49
            );
            assert_eq!(operations[1].encode_size(), ENTRY_OPERATION_SIZE);
            assert!(operations.iter().all(|operation| match operation {
                ActivityOperation::Append(record) => {
                    record.encode_size() <= max_record_size
                        && operation.encode_size() <= u8::SIZE + max_record_size
                }
                ActivityOperation::Commit(None, _) => {
                    operation.encode_size() <= u8::SIZE + max_record_size
                }
                ActivityOperation::Commit(Some(_), _) => false,
            }));
            drop(operations);
            let logs = logs.apply(prepared).await.unwrap().commit().await.unwrap();
            drop(logs);

            let source = TestLogs::open(context.child("source_reopen"), source_reopen_cfg)
                .await
                .unwrap();
            assert_eq!(*source.head(), candidate);
            let (source_activity, source_payouts) = source.into_parts();
            let source_activity = Arc::new(source_activity);

            let mut destination_cfg = config(&context, "activity-boundaries-destination").activity;
            destination_cfg.merkle.items_per_blob = NZU64!(128);
            destination_cfg.log.items_per_section = NZU64!(128);
            let destination_reopen_cfg = destination_cfg.clone();
            let imported: TestActivityDb = qmdb::sync::sync(qmdb::sync::engine::Config {
                context: context.child("destination_import"),
                source: source_activity.clone(),
                target: candidate.activity.target(0).unwrap(),
                max_outstanding_requests: 4,
                fetch_batch_size: NZU64!(128),
                apply_batch_size: NZU64!(128),
                db_config: destination_cfg,
                update_rx: None,
                finish_rx: None,
                reached_target_tx: None,
                max_retained_roots: 1,
            })
            .await
            .unwrap();
            assert_eq!(head(&imported), candidate.activity);
            assert_eq!(imported.get_metadata().await.unwrap(), None);
            assert!(matches!(
                activity_operation_at(&imported, activity_start).await,
                ActivityOperation::Append(ActivityRecord::Row(stored)) if stored == row
            ));
            assert!(matches!(
                activity_operation_at(&imported, activity_start + 1).await,
                ActivityOperation::Append(ActivityRecord::Entry(entry))
                    if entry.recipient == first_recipient
                        && entry.cumulative == 1
                        && entry.count == 1
            ));
            assert!(matches!(
                activity_operation_at(&imported, candidate.activity.operations - 2).await,
                ActivityOperation::Append(ActivityRecord::Entry(entry))
                    if entry.recipient == last_recipient
                        && entry.cumulative == 1
                        && entry.count == 1
            ));
            drop(imported);

            let imported =
                TestActivityDb::init(context.child("destination_reopen"), destination_reopen_cfg)
                    .await
                    .unwrap();
            assert_eq!(head(&imported), candidate.activity);
            assert_eq!(imported.get_metadata().await.unwrap(), None);
            assert!(matches!(
                activity_operation_at(&imported, candidate.activity.operations - 1).await,
                ActivityOperation::Commit(None, floor) if *floor == 0
            ));
            imported.destroy().await.unwrap();
            source_payouts.destroy().await.unwrap();
            Arc::try_unwrap(source_activity)
                .unwrap_or_else(|_| panic!("native activity source still retained"))
                .destroy()
                .await
                .unwrap();
        });
    }

    #[test]
    fn row_openings_exclude_commit_and_bind_roles() {
        deterministic::Runner::default().start(|context| async move {
            let logs = TestLogs::open(context.child("open"), config(&context, "rows"))
                .await
                .unwrap();
            let account = SigningKey::from_seed(7).public_key();

            let mut output_bytes = Vec::new();
            Bytes::from_static(b"destination").write(&mut output_bytes);
            9u64.write(&mut output_bytes);
            let output =
                WithdrawalOutput::decode_cfg(Bytes::from(output_bytes), &(0..=64usize).into())
                    .unwrap();
            let recipient = SigningKey::from_seed(8).public_key();
            let entry = OutEntry {
                recipient,
                cumulative: 4,
                count: 1,
            };
            let row = activity_row(
                account.clone(),
                4,
                3,
                outgoing_root(account, core::slice::from_ref(&entry)),
            );

            let predecessor = *logs.head();
            let prepared = logs
                .prepare(
                    &predecessor,
                    ActivityInput::new(vec![row.clone()], vec![entry.clone()]),
                    vec![output.clone()],
                    Floors {
                        activity: 0,
                        payouts: 0,
                    },
                )
                .await
                .unwrap();
            let head = *prepared.head();
            let logs = logs.apply(prepared).await.unwrap();
            assert_eq!(
                logs.activity_row_at(predecessor.activity.operations)
                    .await
                    .unwrap(),
                row
            );

            let one = NonZeroU64::new(1).unwrap();
            let (activity, operations) = logs
                .activity_opening(&head.activity, predecessor.activity.operations, one)
                .await
                .unwrap();
            assert!(matches!(
                operations.as_slice(),
                [ActivityOperation::Append(ActivityRecord::Row(value))] if value == &row
            ));
            activity
                .verify_activity::<Sha256, VerifyingKey>(&head.activity, &[row])
                .unwrap();
            assert!(matches!(
                logs.raw_activity_record_at(
                    &head.activity,
                    predecessor.activity.operations + 1,
                )
                .await
                .unwrap(),
                ActivityOperation::Append(ActivityRecord::Entry(value)) if value == entry
            ));

            let (payout, operations) = logs
                .payout_opening(&head.payouts, predecessor.payouts.operations, one)
                .await
                .unwrap();
            assert!(matches!(
                operations.as_slice(),
                [PayoutOperation::Append(value)] if value == &output
            ));
            payout
                .verify_payout::<Sha256>(&head.payouts, &output)
                .unwrap();
            assert!(matches!(
                logs.payout_at(head.payouts.operations - 1).await,
                Err(Error::Row)
            ));
            logs.destroy().await.unwrap();
        });
    }

    #[test]
    fn preparation_rejects_commit_beyond_capacity() {
        let root = Sha256::hash(&[b"capacity"]);
        let max = *mmr::Family::MAX_LEAVES;
        let almost_full = LogHead {
            root,
            operations: max - 1,
            floor: 0,
        };
        assert!(matches!(
            validate_floor(almost_full, 0, 1),
            Err(Error::Bounds)
        ));

        let full = LogHead {
            root,
            operations: max,
            floor: 0,
        };
        assert!(matches!(validate_floor(full, 0, 0), Err(Error::Bounds)));
    }

    #[test]
    fn partition_validation_includes_native_derived_names() {
        deterministic::Runner::default().start(|context| async move {
            let mut merkle_overlap = config(&context, "merkle-overlap");
            merkle_overlap.activity.merkle.metadata_partition = format!(
                "{}-metadata",
                merkle_overlap.activity.merkle.journal_partition
            );
            assert!(matches!(
                validate_partitions(&merkle_overlap),
                Err(Error::Partition)
            ));

            let mut log_overlap = config(&context, "log-overlap");
            log_overlap.activity.merkle.metadata_partition =
                format!("{}_data", log_overlap.activity.log.partition);
            assert!(matches!(
                validate_partitions(&log_overlap),
                Err(Error::Partition)
            ));
        });
    }

    #[test]
    fn preparation_enforces_row_delimited_entry_grammar_before_mutation() {
        deterministic::Runner::default().start(|context| async move {
            let logs = TestLogs::open(context.child("open"), config(&context, "original-order"))
                .await
                .unwrap();
            let predecessor = *logs.head();
            let mut accounts = [
                SigningKey::from_seed(1).public_key(),
                SigningKey::from_seed(2).public_key(),
                SigningKey::from_seed(3).public_key(),
            ];
            accounts.sort_by(|left, right| left.as_ref().cmp(right.as_ref()));
            let mut recipients = [
                SigningKey::from_seed(4).public_key(),
                SigningKey::from_seed(5).public_key(),
            ];
            recipients.sort_by(|left, right| left.as_ref().cmp(right.as_ref()));
            let entry = |recipient: VerifyingKey, cumulative, count| OutEntry {
                recipient,
                cumulative,
                count,
            };
            let arbitrary_root = || commitment::VectorRoot {
                digest: Sha256::hash(&[b"outgoing"]),
            };
            let empty_root = commitment::empty_root::<Sha256>(commitment::VectorKind::OutEntry);
            let positive =
                |debit, seq| activity_row(accounts[0].clone(), debit, seq, arbitrary_root());
            let zero = |seq, root| activity_row(accounts[0].clone(), 0, seq, root);
            let invalid = vec![
                (vec![positive(1, 0)], Vec::new()),
                (
                    vec![zero(0, empty_root)],
                    vec![entry(recipients[0].clone(), 1, 1)],
                ),
                (
                    vec![positive(1, 0)],
                    vec![entry(recipients[0].clone(), 2, 1)],
                ),
                (
                    vec![positive(2, 0)],
                    vec![entry(recipients[0].clone(), 1, 1)],
                ),
                (
                    vec![positive(u64::MAX, 0)],
                    vec![
                        entry(recipients[0].clone(), u64::MAX - 1, 1),
                        entry(recipients[1].clone(), 2, 1),
                    ],
                ),
                (
                    vec![positive(2, 0)],
                    vec![
                        entry(recipients[1].clone(), 1, 1),
                        entry(recipients[0].clone(), 1, 1),
                    ],
                ),
                (vec![zero(1, empty_root)], Vec::new()),
                (vec![zero(0, arbitrary_root())], Vec::new()),
            ];

            for (rows, entries) in invalid {
                let result = logs
                    .prepare(
                        &predecessor,
                        ActivityInput::new(rows, entries),
                        Vec::new(),
                        Floors {
                            activity: 0,
                            payouts: 0,
                        },
                    )
                    .await;
                assert!(matches!(result, Err(Error::Original)));
                assert_eq!(*logs.head(), predecessor);
            }

            let reversed = vec![
                activity_row(accounts[1].clone(), 0, 0, empty_root),
                activity_row(accounts[0].clone(), 0, 0, empty_root),
            ];
            assert!(matches!(
                logs.prepare(
                    &predecessor,
                    ActivityInput::new(reversed, Vec::new()),
                    Vec::new(),
                    Floors {
                        activity: 0,
                        payouts: 0,
                    },
                )
                .await,
                Err(Error::Order)
            ));

            let entries = vec![
                entry(recipients[0].clone(), 1, 1),
                entry(recipients[1].clone(), 2, 1),
                entry(recipients[0].clone(), 3, 2),
            ];
            let rows = vec![
                activity_row(
                    accounts[0].clone(),
                    3,
                    0,
                    outgoing_root(accounts[0].clone(), &entries[..2]),
                ),
                activity_row(accounts[1].clone(), 0, 0, empty_root),
                activity_row(
                    accounts[2].clone(),
                    3,
                    7,
                    outgoing_root(accounts[2].clone(), &entries[2..]),
                ),
            ];
            let prepared = logs
                .prepare(
                    &predecessor,
                    ActivityInput::new(rows, entries),
                    Vec::new(),
                    Floors {
                        activity: 0,
                        payouts: 0,
                    },
                )
                .await
                .unwrap();
            assert_eq!(prepared.head().activity.operations, 8);
            drop(prepared);
            logs.destroy().await.unwrap();
        });
    }

    #[test]
    fn preparation_rejects_oversized_payout_destination_before_mutation() {
        deterministic::Runner::default().start(|context| async move {
            let mut cfg = config(&context, "payout-bound");
            cfg.payouts.log.codec_config = (0..=0).into();
            let reopen_cfg = cfg.clone();
            let logs = TestLogs::open(context.child("open"), cfg).await.unwrap();
            let predecessor = *logs.head();

            let mut output_bytes = Vec::new();
            Bytes::from_static(b"destination").write(&mut output_bytes);
            1u64.write(&mut output_bytes);
            let output =
                WithdrawalOutput::decode_cfg(Bytes::from(output_bytes), &(0..=64usize).into())
                    .unwrap();
            let result = logs
                .prepare(
                    &predecessor,
                    ActivityInput::new(Vec::new(), Vec::new()),
                    vec![output],
                    Floors {
                        activity: 0,
                        payouts: 0,
                    },
                )
                .await;
            assert!(matches!(result, Err(Error::Bounds)));
            assert_eq!(*logs.head(), predecessor);

            let mut zero_bytes = Vec::new();
            Bytes::new().write(&mut zero_bytes);
            0u64.write(&mut zero_bytes);
            let zero = WithdrawalOutput::decode_cfg(Bytes::from(zero_bytes), &(0..=0usize).into())
                .unwrap();
            let mut positive_bytes = Vec::new();
            Bytes::new().write(&mut positive_bytes);
            1u64.write(&mut positive_bytes);
            let positive =
                WithdrawalOutput::decode_cfg(Bytes::from(positive_bytes), &(0..=0usize).into())
                    .unwrap();
            let prepared = logs
                .prepare(
                    &predecessor,
                    ActivityInput::new(Vec::new(), Vec::new()),
                    vec![zero, positive],
                    Floors {
                        activity: 0,
                        payouts: 0,
                    },
                )
                .await
                .unwrap();
            let candidate = *prepared.head();
            let logs = logs.apply(prepared).await.unwrap().commit().await.unwrap();
            assert_eq!(*logs.head(), candidate);
            drop(logs);

            let reopened = TestLogs::open(context.child("reopen"), reopen_cfg)
                .await
                .unwrap();
            assert_eq!(*reopened.head(), candidate);
            let zero = reopened.payout_at(1).await.unwrap();
            assert!(zero.destination().is_empty());
            assert_eq!(zero.amount(), 0);
            let positive = reopened.payout_at(2).await.unwrap();
            assert!(positive.destination().is_empty());
            assert_eq!(positive.amount(), 1);
            reopened.destroy().await.unwrap();
        });
    }

    #[test]
    fn row_lookups_reject_value_bearing_commits() {
        deterministic::Runner::default().start(|context| async move {
            let logs = TestLogs::open(context.child("open"), config(&context, "commit-value"))
                .await
                .unwrap();
            let account = SigningKey::from_seed(9).public_key();
            let row = activity_row(
                account.clone(),
                0,
                0,
                commitment::empty_root::<Sha256>(commitment::VectorKind::OutEntry),
            );

            let mut output_bytes = Vec::new();
            Bytes::from_static(b"commit-destination").write(&mut output_bytes);
            11u64.write(&mut output_bytes);
            let output =
                WithdrawalOutput::decode_cfg(Bytes::from(output_bytes), &(0..=64usize).into())
                    .unwrap();

            let (activity, payouts) = logs.into_parts();
            let activity_batch = activity
                .new_batch()
                .merkleize(&activity, Some(ActivityRecord::Row(row)), Location::new(0))
                .await;
            let (activity, _) = activity.apply_batch(activity_batch).await.unwrap();
            let activity_batch = activity
                .new_batch()
                .merkleize(&activity, None, Location::new(0))
                .await;
            let (activity, _) = activity.apply_batch(activity_batch).await.unwrap();

            let payout_batch = payouts
                .new_batch()
                .merkleize(&payouts, Some(output), Location::new(0))
                .await;
            let (payouts, _) = payouts.apply_batch(payout_batch).await.unwrap();
            let payout_batch = payouts
                .new_batch()
                .merkleize(&payouts, None, Location::new(0))
                .await;
            let (payouts, _) = payouts.apply_batch(payout_batch).await.unwrap();

            let logs = TestLogs::from_parts(activity, payouts, (0..=4096).into());
            assert!(matches!(logs.activity_row_at(1).await, Err(Error::Row)));
            assert!(matches!(logs.payout_at(1).await, Err(Error::Row)));
            let epoch = Epoch::at(
                &logs,
                0,
                ActivityRange {
                    start: 1,
                    end: 2,
                    head: logs.head().activity,
                },
            )
            .await
            .unwrap();
            assert!(epoch.account_lookup(&logs, &account).await.is_err());
            assert!(
                epoch
                    .higher_entry_lookup(&logs, &account, &account)
                    .await
                    .is_err()
            );
            logs.destroy().await.unwrap();
        });
    }
}
