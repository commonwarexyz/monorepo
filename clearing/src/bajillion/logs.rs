//! Native append-only activity and payout histories.
//!
//! Each accepted close appends its rows followed by the keyless QMDB commit operation. Native
//! locations are stable protocol indices; commit locations are intentional gaps between row
//! ranges. Activity values distinguish compact Guard appends from source Metadata commits; payout
//! operation framing directly distinguishes output appends from metadata-free commits.

use super::{state::ChangeGuard, transition::WithdrawalOutput};
use bytes::{BufMut, Bytes};
use commonware_codec::{
    Buf, EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt as _, Write,
};
use commonware_cryptography::{Digest, Hasher, PublicKey};
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
use core::num::NonZeroU64;
use std::sync::Arc;
use thiserror::Error;

const ACTIVITY_GUARD_ROLE: u8 = 0;
const ACTIVITY_METADATA_ROLE: u8 = 1;

/// Byte limits for one activity Commit's source metadata.
pub type ActivityCfg = RangeCfg<usize>;

/// A typed value in the activity log.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActivityRecord<P: PublicKey, D: Digest> {
    /// A compact changed-account guard in the epoch's ordered Append range.
    Guard(ChangeGuard<P, D>),
    /// Original source data carried only by the epoch's terminal Commit.
    Metadata(Bytes),
}

#[cfg(feature = "arbitrary")]
impl<'a, P, D> arbitrary::Arbitrary<'a> for ActivityRecord<P, D>
where
    P: PublicKey + for<'b> arbitrary::Arbitrary<'b>,
    D: Digest + for<'b> arbitrary::Arbitrary<'b>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        match u.int_in_range(0..=1)? {
            0 => Ok(Self::Guard(u.arbitrary()?)),
            1 => Ok(Self::Metadata(Bytes::from(u.arbitrary::<Vec<u8>>()?))),
            _ => unreachable!(),
        }
    }
}

impl<P: PublicKey, D: Digest> Write for ActivityRecord<P, D> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Guard(guard) => {
                ACTIVITY_GUARD_ROLE.write(buf);
                guard.write(buf);
            }
            Self::Metadata(data) => {
                ACTIVITY_METADATA_ROLE.write(buf);
                data.write(buf);
            }
        }
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for ActivityRecord<P, D> {
    fn encode_size(&self) -> usize {
        u8::SIZE
            + match self {
                Self::Guard(guard) => guard.encode_size(),
                Self::Metadata(data) => data.encode_size(),
            }
    }
}

impl<P: PublicKey, D: Digest> Read for ActivityRecord<P, D> {
    type Cfg = ActivityCfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            ACTIVITY_GUARD_ROLE => Ok(Self::Guard(ChangeGuard::read(buf)?)),
            ACTIVITY_METADATA_ROLE => Ok(Self::Metadata(Bytes::read_cfg(buf, cfg)?)),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

/// Unencoded input for one native activity append-and-commit batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivityInput<P: PublicKey, D: Digest> {
    /// Compact guards, in canonical account-byte order.
    guards: Vec<ChangeGuard<P, D>>,
    /// Canonically encoded original sources needed for on-demand proof construction.
    metadata: Bytes,
}

impl<P: PublicKey, D: Digest> ActivityInput<P, D> {
    /// Construct one activity batch input.
    pub const fn new(guards: Vec<ChangeGuard<P, D>>, metadata: Bytes) -> Self {
        Self { guards, metadata }
    }

    /// Return the ordered compact guards.
    pub fn guards(&self) -> &[ChangeGuard<P, D>] {
        &self.guards
    }

    /// Return the encoded original source metadata.
    pub const fn metadata(&self) -> &Bytes {
        &self.metadata
    }

    /// Consume the input into its native batch components.
    pub fn into_parts(self) -> (Vec<ChangeGuard<P, D>>, Bytes) {
        (self.guards, self.metadata)
    }
}

/// Native activity operation encoding.
pub type ActivityOperation<P, D> =
    keyless::Operation<mmr::Family, VariableEncoding<ActivityRecord<P, D>>>;
/// Native payout operation encoding.
pub type PayoutOperation = keyless::Operation<mmr::Family, VariableEncoding<WithdrawalOutput>>;
/// Native log sync request.
pub type Request = qmdb::sync::Request<mmr::Family>;
/// Native activity sync response.
pub type ActivityResponse<P, D> = qmdb::sync::Response<mmr::Family, ActivityOperation<P, D>, D>;
/// Native payout sync response.
pub type PayoutResponse<D> = qmdb::sync::Response<mmr::Family, PayoutOperation, D>;
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
    /// Variable-size activity log.
    pub activity: keyless::variable::Config<ActivityCfg, S>,
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
    /// Verify activity appends at an arbitrary row-only subrange.
    pub fn verify_activity<H, P>(
        &self,
        head: &LogHead<D>,
        values: &[ChangeGuard<P, D>],
    ) -> Result<(), Error>
    where
        H: Hasher<Digest = D>,
        P: PublicKey,
    {
        let operations = values
            .iter()
            .cloned()
            .map(|guard| ActivityOperation::Append(ActivityRecord::Guard(guard)))
            .collect::<Vec<_>>();
        self.verify::<H, _>(head, &operations)
    }

    /// Verify one activity Metadata Commit at any retained historical position.
    pub fn verify_activity_metadata<H, P>(
        &self,
        head: &LogHead<D>,
        metadata: &Bytes,
        floor: u64,
    ) -> Result<(), Error>
    where
        H: Hasher<Digest = D>,
        P: PublicKey,
    {
        LogHead::try_new(head.root, head.operations, head.floor)?;
        let start = Location::<mmr::Family>::new(self.start);
        let floor = Location::<mmr::Family>::new(floor);
        if !start.is_valid_index()
            || start >= Location::new(head.operations)
            || !floor.is_valid_index()
            || floor > start
            || self.proof.leaves != Location::new(head.operations)
            || self.proof.inactive_peaks
                != mmr::Family::inactive_peaks(
                    Location::new(head.operations),
                    Location::new(head.floor),
                )
        {
            return Err(Error::Proof);
        }
        let operation = [ActivityOperation::<P, D>::Commit(
            Some(ActivityRecord::Metadata(metadata.clone())),
            floor,
        )];
        if !qmdb::verify_proof::<H, mmr::Family, _>(&self.proof, start, &operation, &head.root) {
            return Err(Error::Proof);
        }
        Ok(())
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
    activity_cfg: ActivityCfg,
    payout_cfg: RangeCfg<usize>,
    head: Heads<H::Digest>,
}

impl<E: Context, H: Hasher, P: PublicKey, S: Strategy> Logs<E, H, P, S> {
    /// Open both native logs and derive their recovered heads.
    pub async fn open(context: E, config: Config<S>) -> Result<Self, Error> {
        validate_partitions(&config)?;
        let activity_cfg = config.activity.log.codec_config;
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
            activity_cfg,
            payout_cfg,
            head,
        })
    }

    /// Assemble already-opened native stores after checking their recovered heads.
    pub fn from_parts(
        activity: ActivityDb<E, H, P, S>,
        payouts: PayoutDb<E, H, S>,
        activity_cfg: ActivityCfg,
        payout_cfg: RangeCfg<usize>,
    ) -> Self {
        let head = Heads {
            activity: head(&activity),
            payouts: head(&payouts),
        };
        Self {
            activity,
            payouts,
            activity_cfg,
            payout_cfg,
            head,
        }
    }

    /// Assemble native peer-sync results and bind them to an authenticated checkpoint.
    pub fn from_parts_checked(
        activity: ActivityDb<E, H, P, S>,
        payouts: PayoutDb<E, H, S>,
        activity_cfg: ActivityCfg,
        payout_cfg: RangeCfg<usize>,
        expected: &Heads<H::Digest>,
    ) -> Result<Self, Error> {
        let logs = Self::from_parts(activity, payouts, activity_cfg, payout_cfg);
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

    /// Serve one untrusted native activity-sync request.
    pub async fn serve_activity(
        &self,
        request: Request,
    ) -> Result<(ActivityResponse<P, H::Digest>, qmdb::sync::FeedbackTx), Error> {
        Ok(qmdb::sync::Source::serve(&self.activity, request).await?)
    }

    /// Serve one untrusted native payout-sync request.
    pub async fn serve_payout(
        &self,
        request: Request,
    ) -> Result<(PayoutResponse<H::Digest>, qmdb::sync::FeedbackTx), Error> {
        Ok(qmdb::sync::Source::serve(&self.payouts, request).await?)
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

    /// Read a compact activity guard Append at a retained native location.
    pub async fn activity_guard_at(&self, index: u64) -> Result<ChangeGuard<P, H::Digest>, Error> {
        match self
            .raw_activity_record_at(&self.head.activity, index)
            .await?
        {
            ActivityOperation::Append(ActivityRecord::Guard(guard)) => Ok(guard),
            _ => Err(Error::Row),
        }
    }

    /// Read source metadata from an activity Commit at a retained historical head.
    pub async fn activity_metadata_at(
        &self,
        head: &LogHead<H::Digest>,
        index: u64,
    ) -> Result<(Bytes, u64, Opening<H::Digest>), Error> {
        let (proof, operations) = self.activity_opening(head, index, NonZeroU64::MIN).await?;
        match operations.into_iter().next() {
            Some(ActivityOperation::Commit(Some(ActivityRecord::Metadata(metadata)), floor)) => {
                Ok((metadata, *floor, proof))
            }
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
        let (guards, metadata) = activity_input.into_parts();
        if guards
            .windows(2)
            .any(|pair| pair[0].account().as_ref() >= pair[1].account().as_ref())
        {
            return Err(Error::Order);
        }
        if !self.activity_cfg.contains(&metadata.len()) {
            return Err(Error::Bounds);
        }
        if outputs
            .iter()
            .any(|output| !self.payout_cfg.contains(&output.destination().len()))
        {
            return Err(Error::Bounds);
        }
        validate_floor(expected.activity, floors.activity, guards.len())?;
        validate_floor(expected.payouts, floors.payouts, outputs.len())?;

        let mut activity = self.activity.new_batch();
        for guard in guards {
            activity = activity.append(ActivityRecord::Guard(guard));
        }
        let activity = activity
            .merkleize(
                &self.activity,
                Some(ActivityRecord::Metadata(metadata)),
                Location::new(floors.activity),
            )
            .await;

        let mut payouts = self.payouts.new_batch();
        for output in outputs {
            payouts = payouts.append(output);
        }
        let payouts = payouts
            .merkleize(&self.payouts, None, Location::new(floors.payouts))
            .await;

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
    pub async fn apply(mut self, prepared: PreparedLogs<P, H::Digest, S>) -> Result<Self, Error> {
        if prepared.predecessor != self.head {
            return Err(Error::Predecessor);
        }
        (self.activity, _) = self.activity.apply_batch(prepared.activity).await?;
        (self.payouts, _) = self.payouts.apply_batch(prepared.payouts).await?;
        self.head = prepared.head;
        Ok(self)
    }

    /// Durably commit both logs.
    pub async fn commit(mut self) -> Result<Self, Error> {
        self.activity = self.activity.commit().await?;
        self.payouts = self.payouts.commit().await?;
        Ok(self)
    }

    /// Fully synchronize both logs.
    pub async fn sync(mut self) -> Result<Self, Error> {
        self.activity = self.activity.sync().await?;
        self.payouts = self.payouts.sync().await?;
        Ok(self)
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

    /// Alias for [`Self::activity_opening`] used by history transports.
    pub async fn activity_proof(
        &self,
        head: &LogHead<H::Digest>,
        start: u64,
        count: NonZeroU64,
    ) -> Result<(Opening<H::Digest>, Vec<ActivityOperation<P, H::Digest>>), Error> {
        self.activity_opening(head, start, count).await
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

    /// Alias for [`Self::payout_opening`] used by history transports.
    pub async fn payout_proof(
        &self,
        head: &LogHead<H::Digest>,
        start: u64,
        count: NonZeroU64,
    ) -> Result<(Opening<H::Digest>, Vec<PayoutOperation>), Error> {
        self.payout_opening(head, start, count).await
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

    /// Prove the full new activity range, including the final commit.
    pub fn activity_proof<E, H>(&self, logs: &Logs<E, H, P, S>) -> Result<Opening<D>, Error>
    where
        E: Context,
        H: Hasher<Digest = D>,
    {
        let (start, _) = self.activity.operations();
        Ok(Opening {
            start: *start,
            proof: self.activity.proof(&logs.activity)?,
        })
    }

    /// Prove the full new payout range, including the final commit.
    pub fn payout_proof<E, H>(&self, logs: &Logs<E, H, P, S>) -> Result<Opening<D>, Error>
    where
        E: Context,
        H: Hasher<Digest = D>,
    {
        let (start, _) = self.payouts.operations();
        Ok(Opening {
            start: *start,
            proof: self.payouts.proof(&logs.payouts)?,
        })
    }

    /// Return the activity Merkle frontier needed to import this batch range.
    pub fn activity_pinned_nodes<E, H>(&self, logs: &Logs<E, H, P, S>) -> Result<Vec<D>, Error>
    where
        E: Context,
        H: Hasher<Digest = D>,
    {
        Ok(self.activity.pinned_nodes(&logs.activity)?)
    }

    /// Return the payout Merkle frontier needed to import this batch range.
    pub fn payout_pinned_nodes<E, H>(&self, logs: &Logs<E, H, P, S>) -> Result<Vec<D>, Error>
    where
        E: Context,
        H: Hasher<Digest = D>,
    {
        Ok(self.payouts.pinned_nodes(&logs.payouts)?)
    }
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
    /// Activity guards are not strictly ordered.
    #[error("activity guards are not strictly account-sorted")]
    Order,
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
    /// The requested location is a commit, is outside the authenticated head, or is pruned.
    #[error("native location is not a retained append row")]
    Row,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use commonware_codec::{Decode as _, DecodeExt as _};
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

    type TestLogs = Logs<deterministic::Context, Sha256, VerifyingKey, Sequential>;

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
                    codec_config: (0..=4096).into(),
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
                    ActivityInput::new(Vec::new(), Bytes::new()),
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
            let activity_opening = prepared.activity_proof(&logs).unwrap();
            assert_eq!(activity_start, 1);
            assert!(matches!(
                activity_ops.as_slice(),
                [ActivityOperation::Commit(
                    Some(ActivityRecord::Metadata(metadata)),
                    floor
                )] if metadata.is_empty() && **floor == 0
            ));
            assert!(qmdb::verify_proof::<Sha256, mmr::Family, _>(
                &activity_opening.proof,
                Location::new(activity_start),
                activity_ops.as_slice(),
                &candidate.activity.root,
            ));
            assert!(matches!(
                activity_opening.verify_activity::<Sha256, VerifyingKey>(&candidate.activity, &[]),
                Err(Error::Proof)
            ));

            let logs = logs.apply(prepared).await.unwrap().commit().await.unwrap();
            assert!(matches!(logs.activity_guard_at(1).await, Err(Error::Row)));
            let logs = logs.rewind(&bootstrap).await.unwrap().sync().await.unwrap();
            assert_eq!(*logs.head(), bootstrap);
            drop(logs);

            let reopened = TestLogs::open(context.child("reopen"), cfg).await.unwrap();
            assert_eq!(*reopened.head(), bootstrap);
            reopened.destroy().await.unwrap();
        });
    }

    #[test]
    fn row_openings_exclude_commit_and_bind_roles() {
        deterministic::Runner::default().start(|context| async move {
            let logs = TestLogs::open(context.child("open"), config(&context, "rows"))
                .await
                .unwrap();
            let account = SigningKey::from_seed(7).public_key();
            let mut guard_bytes = Vec::new();
            account.write(&mut guard_bytes);
            Sha256::hash(&[b"change"]).write(&mut guard_bytes);
            let guard =
                ChangeGuard::<VerifyingKey, ShaDigest>::decode(Bytes::from(guard_bytes)).unwrap();

            let mut output_bytes = Vec::new();
            Bytes::from_static(b"destination").write(&mut output_bytes);
            9u64.write(&mut output_bytes);
            let output =
                WithdrawalOutput::decode_cfg(Bytes::from(output_bytes), &(0..=64usize).into())
                    .unwrap();
            let metadata = Bytes::from_static(b"source metadata");

            let predecessor = *logs.head();
            let prepared = logs
                .prepare(
                    &predecessor,
                    ActivityInput::new(vec![guard.clone()], metadata.clone()),
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

            let one = NonZeroU64::new(1).unwrap();
            let (activity, operations) = logs
                .activity_opening(&head.activity, predecessor.activity.operations, one)
                .await
                .unwrap();
            assert!(matches!(
                operations.as_slice(),
                [ActivityOperation::Append(ActivityRecord::Guard(value))] if value == &guard
            ));
            activity
                .verify_activity::<Sha256, VerifyingKey>(&head.activity, &[guard])
                .unwrap();
            assert!(
                activity
                    .verify_activity_metadata::<Sha256, VerifyingKey>(&head.activity, &metadata, 0,)
                    .is_err()
            );

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
    fn metadata_commits_verify_at_terminal_and_historical_locations() {
        deterministic::Runner::default().start(|context| async move {
            let mut logs = TestLogs::open(context.child("open"), config(&context, "metadata"))
                .await
                .unwrap();
            let metadata = [
                Bytes::from_static(b"a"),
                Bytes::from_static(b"b"),
                Bytes::from_static(b"c"),
                Bytes::from_static(b"d"),
            ];
            let mut commits = Vec::new();
            for value in &metadata {
                let predecessor = *logs.head();
                commits.push(predecessor.activity.operations);
                let prepared = logs
                    .prepare(
                        &predecessor,
                        ActivityInput::new(Vec::new(), value.clone()),
                        Vec::new(),
                        Floors {
                            activity: predecessor.activity.operations - 1,
                            payouts: predecessor.payouts.operations - 1,
                        },
                    )
                    .await
                    .unwrap();
                logs = logs.apply(prepared).await.unwrap();
            }

            let target = logs.head().activity;
            assert_eq!(target.operations, 5);
            assert_eq!(target.floor, 3);
            let (historical_metadata, historical_floor, historical) = logs
                .activity_metadata_at(&target, commits[0])
                .await
                .unwrap();
            assert_eq!(historical_metadata, metadata[0]);
            assert_eq!(historical_floor, 0);
            historical
                .verify_activity_metadata::<Sha256, VerifyingKey>(
                    &target,
                    &metadata[0],
                    historical_floor,
                )
                .unwrap();
            assert!(
                historical
                    .verify_activity_metadata::<Sha256, VerifyingKey>(
                        &target,
                        &metadata[1],
                        historical_floor,
                    )
                    .is_err()
            );
            assert!(
                historical
                    .verify_activity_metadata::<Sha256, VerifyingKey>(
                        &target,
                        &metadata[0],
                        historical_floor + 1,
                    )
                    .is_err()
            );

            let (terminal_metadata, terminal_floor, terminal) = logs
                .activity_metadata_at(&target, commits[3])
                .await
                .unwrap();
            assert_eq!(terminal_metadata, metadata[3]);
            assert_eq!(terminal_floor, target.floor);
            terminal
                .verify_activity_metadata::<Sha256, VerifyingKey>(
                    &target,
                    &metadata[3],
                    terminal_floor,
                )
                .unwrap();

            let mut wrong_root = target;
            wrong_root.root = Sha256::hash(&[b"wrong"]);
            assert!(
                historical
                    .verify_activity_metadata::<Sha256, VerifyingKey>(
                        &wrong_root,
                        &metadata[0],
                        historical_floor,
                    )
                    .is_err()
            );
            let mut wrong_count = target;
            wrong_count.operations -= 1;
            assert!(
                historical
                    .verify_activity_metadata::<Sha256, VerifyingKey>(
                        &wrong_count,
                        &metadata[0],
                        historical_floor,
                    )
                    .is_err()
            );
            let mut wrong_floor = target;
            wrong_floor.floor = wrong_floor.operations - 1;
            assert!(
                historical
                    .verify_activity_metadata::<Sha256, VerifyingKey>(
                        &wrong_floor,
                        &metadata[0],
                        historical_floor,
                    )
                    .is_err()
            );
            let mut wrong_location = historical.clone();
            wrong_location.start += 1;
            assert!(
                wrong_location
                    .verify_activity_metadata::<Sha256, VerifyingKey>(
                        &target,
                        &metadata[0],
                        historical_floor,
                    )
                    .is_err()
            );
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
    fn preparation_rejects_oversized_metadata_before_mutation() {
        deterministic::Runner::default().start(|context| async move {
            let logs = TestLogs::open(context.child("open"), config(&context, "metadata-bound"))
                .await
                .unwrap();
            let predecessor = *logs.head();
            let result = logs
                .prepare(
                    &predecessor,
                    ActivityInput::new(Vec::new(), Bytes::from(vec![0; 4097])),
                    Vec::new(),
                    Floors {
                        activity: 0,
                        payouts: 0,
                    },
                )
                .await;
            assert!(matches!(result, Err(Error::Bounds)));
            assert_eq!(*logs.head(), predecessor);
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
                    ActivityInput::new(Vec::new(), Bytes::new()),
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
                    ActivityInput::new(Vec::new(), Bytes::new()),
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
    fn row_lookups_reject_metadata_bearing_commits() {
        deterministic::Runner::default().start(|context| async move {
            let logs = TestLogs::open(context.child("open"), config(&context, "metadata"))
                .await
                .unwrap();
            let account = SigningKey::from_seed(9).public_key();
            let mut guard_bytes = Vec::new();
            account.write(&mut guard_bytes);
            Sha256::hash(&[b"metadata-change"]).write(&mut guard_bytes);
            let guard =
                ChangeGuard::<VerifyingKey, ShaDigest>::decode(Bytes::from(guard_bytes)).unwrap();

            let mut output_bytes = Vec::new();
            Bytes::from_static(b"metadata-destination").write(&mut output_bytes);
            11u64.write(&mut output_bytes);
            let output =
                WithdrawalOutput::decode_cfg(Bytes::from(output_bytes), &(0..=64usize).into())
                    .unwrap();

            let (activity, payouts) = logs.into_parts();
            let activity_batch = activity
                .new_batch()
                .merkleize(
                    &activity,
                    Some(ActivityRecord::Guard(guard)),
                    Location::new(0),
                )
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

            let logs =
                TestLogs::from_parts(activity, payouts, (0..=4096).into(), (0..=4096).into());
            assert!(matches!(logs.activity_guard_at(1).await, Err(Error::Row)));
            assert!(matches!(logs.payout_at(1).await, Err(Error::Row)));
            logs.destroy().await.unwrap();
        });
    }
}
