//! Chain-sealed deposits and unilateral withdrawal authorizations.

use crate::bajillion::commitment::{self, VectorKind, VectorRoot};
use alloc::vec::Vec;
use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{
    Encode, EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt as _, Write,
};
use commonware_cryptography::{Digest, Hasher, PublicKey, Signer};
use thiserror::Error;

fn vector_len(len: usize) -> Result<u32, commitment::Error> {
    let reported = u64::try_from(len).unwrap_or(u64::MAX);
    u32::try_from(len).map_err(|_| commitment::Error::TooManyValues(reported))
}

/// Signature namespace for account-authorized withdrawals.
pub const WITHDRAWAL_SIGNATURE_NAMESPACE: &[u8] = b"_COMMONWARE_CLEARING_BOUNDARY_WITHDRAWAL";
/// Hash namespace for stable withdrawal identifiers.
pub const WITHDRAWAL_ID_HASH_NAMESPACE: &[u8] = b"_COMMONWARE_CLEARING_BOUNDARY_WITHDRAWAL_ID";

/// Absolute settlement-chain time used as a withdrawal deadline.
pub type Deadline = u64;

/// One chain-sealed deposit assigned to an account.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DepositRecord<P: PublicKey> {
    account: P,
    amount: u64,
}

impl<P: PublicKey> DepositRecord<P> {
    /// Creates a positive deposit record.
    pub fn new(account: P, amount: u64) -> Result<Self, BoundaryError> {
        if amount == 0 {
            return Err(BoundaryError::ZeroDeposit);
        }
        Ok(Self { account, amount })
    }

    /// Constructs an unchecked record for adversarial decoding fixtures.
    pub const fn from_raw_unchecked(account: P, amount: u64) -> Self {
        Self { account, amount }
    }

    /// Returns the credited account.
    pub const fn account(&self) -> &P {
        &self.account
    }

    /// Returns the deposited amount.
    pub const fn amount(&self) -> u64 {
        self.amount
    }
}

impl<P: PublicKey> Write for DepositRecord<P> {
    fn write(&self, buf: &mut impl BufMut) {
        self.account.write(buf);
        self.amount.write(buf);
    }
}

impl<P: PublicKey> FixedSize for DepositRecord<P> {
    const SIZE: usize = P::SIZE + u64::SIZE;
}

impl<P: PublicKey> Read for DepositRecord<P> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            account: P::read(buf)?,
            amount: u64::read(buf)?,
        })
    }
}

/// Exact account-sorted deposit boundary for one epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DepositBatch<P: PublicKey> {
    records: Vec<DepositRecord<P>>,
    total: u64,
}

impl<P: PublicKey> DepositBatch<P> {
    /// Sorts records by account and constructs a unique positive deposit batch.
    pub fn new(mut records: Vec<DepositRecord<P>>) -> Result<Self, BoundaryError> {
        records.sort_unstable_by(|left, right| left.account.cmp(&right.account));
        Self::from_sorted(records)
    }

    /// Returns an empty deposit boundary.
    pub const fn empty() -> Self {
        Self {
            records: Vec::new(),
            total: 0,
        }
    }

    fn from_sorted(records: Vec<DepositRecord<P>>) -> Result<Self, BoundaryError> {
        if records.iter().any(|record| record.amount == 0) {
            return Err(BoundaryError::ZeroDeposit);
        }
        if records
            .windows(2)
            .any(|pair| pair[0].account >= pair[1].account)
        {
            return Err(BoundaryError::NonCanonicalDeposits);
        }
        let total = records.iter().try_fold(0_u64, |total, record| {
            total
                .checked_add(record.amount)
                .ok_or(BoundaryError::ArithmeticOverflow)
        })?;
        Ok(Self { records, total })
    }

    /// Returns the canonical records.
    pub fn records(&self) -> &[DepositRecord<P>] {
        &self.records
    }

    /// Returns the number of credited accounts.
    pub const fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns whether the boundary has no deposits.
    pub const fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Returns the checked aggregate deposit amount.
    pub const fn total(&self) -> u64 {
        self.total
    }

    /// Returns one account's deposit, or zero when the account is absent.
    pub fn amount_for(&self, account: &P) -> u64 {
        self.records
            .binary_search_by(|record| record.account.cmp(account))
            .ok()
            .map_or(0, |index| self.records[index].amount)
    }

    /// Returns the record for an account, if present.
    pub fn record_for(&self, account: &P) -> Option<&DepositRecord<P>> {
        self.records
            .binary_search_by(|record| record.account.cmp(account))
            .ok()
            .map(|index| &self.records[index])
    }

    /// Commits the exact sorted deposit records for inclusion in an epoch anchor.
    pub fn root<H: Hasher>(&self) -> Result<VectorRoot<H::Digest>, commitment::Error> {
        let len = vector_len(self.records.len())?;
        let mut builder = commitment::Builder::<H>::new(VectorKind::Deposit, len)?;
        for record in &self.records {
            builder.add_encoded(record.encode().as_ref())?;
        }
        Ok(builder.build()?.root())
    }
}

impl<P: PublicKey> Default for DepositBatch<P> {
    fn default() -> Self {
        Self::empty()
    }
}

impl<P: PublicKey> Write for DepositBatch<P> {
    fn write(&self, buf: &mut impl BufMut) {
        self.records.write(buf);
    }
}

impl<P: PublicKey> EncodeSize for DepositBatch<P> {
    fn encode_size(&self) -> usize {
        self.records.encode_size()
    }
}

impl<P: PublicKey> Read for DepositBatch<P> {
    type Cfg = RangeCfg<usize>;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let records = Vec::<DepositRecord<P>>::read_cfg(buf, &(*cfg, ()))?;
        Self::from_sorted(records).map_err(|error| match error {
            BoundaryError::ZeroDeposit => {
                CodecError::Invalid("clearing::DepositBatch", "deposit amount is zero")
            }
            BoundaryError::NonCanonicalDeposits => CodecError::Invalid(
                "clearing::DepositBatch",
                "deposit accounts are not strictly sorted and unique",
            ),
            BoundaryError::ArithmeticOverflow => CodecError::Invalid(
                "clearing::DepositBatch",
                "aggregate deposit amount overflows u64",
            ),
            _ => unreachable!("deposit validation returned a withdrawal error"),
        })
    }
}

/// Hash of a canonical account-attributed unsigned withdrawal authorization.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct WithdrawalId<D: Digest>(D);

impl<D: Digest> WithdrawalId<D> {
    /// Wraps a digest as a withdrawal identifier.
    pub const fn new(digest: D) -> Self {
        Self(digest)
    }

    /// Returns the underlying digest.
    pub const fn digest(&self) -> &D {
        &self.0
    }

    /// Consumes the identifier and returns its digest.
    pub const fn into_digest(self) -> D {
        self.0
    }
}

impl<D: Digest> Write for WithdrawalId<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl<D: Digest> FixedSize for WithdrawalId<D> {
    const SIZE: usize = D::SIZE;
}

impl<D: Digest> Read for WithdrawalId<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self(D::read(buf)?))
    }
}

/// Canonical withdrawal tuple signed by an account.
///
/// The signed fields are exactly `(deployment, state_root, destination, amount, full_close,
/// absolute_deadline)`. The signing account is carried by [`SignedWithdrawal`] so the destination
/// remains opaque adapter-defined bytes rather than a clearing account key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WithdrawalBody<D: Digest> {
    deployment: D,
    state_root: D,
    destination: Bytes,
    amount: u64,
    full_close: bool,
    deadline: Deadline,
}

impl<D: Digest> WithdrawalBody<D> {
    /// Creates a withdrawal body with a positive amount, or a zero-amount full close.
    pub fn new(
        deployment: D,
        state_root: D,
        destination: Bytes,
        amount: u64,
        full_close: bool,
        deadline: Deadline,
    ) -> Result<Self, BoundaryError> {
        if amount == 0 && !full_close {
            return Err(BoundaryError::ZeroWithdrawal);
        }
        Ok(Self {
            deployment,
            state_root,
            destination,
            amount,
            full_close,
            deadline,
        })
    }

    /// Constructs an arbitrary raw body without checking withdrawal invariants.
    ///
    /// This models everything a faulty account authority may sign in challenge tests. Normal
    /// construction should use [`Self::new`].
    pub const fn from_raw_unchecked(
        deployment: D,
        state_root: D,
        destination: Bytes,
        amount: u64,
        full_close: bool,
        deadline: Deadline,
    ) -> Self {
        Self {
            deployment,
            state_root,
            destination,
            amount,
            full_close,
            deadline,
        }
    }

    /// Returns the deployment identifier.
    pub const fn deployment(&self) -> &D {
        &self.deployment
    }

    /// Returns the finalized state root authorizing the withdrawal.
    pub const fn state_root(&self) -> &D {
        &self.state_root
    }

    /// Returns the opaque asset-adapter destination bytes.
    pub const fn destination(&self) -> &Bytes {
        &self.destination
    }

    /// Returns the requested amount.
    pub const fn amount(&self) -> u64 {
        self.amount
    }

    /// Returns whether successful application must deactivate the account.
    pub const fn full_close(&self) -> bool {
        self.full_close
    }

    /// Returns the absolute settlement-chain deadline.
    pub const fn deadline(&self) -> Deadline {
        self.deadline
    }

    const fn validate(&self) -> Result<(), BoundaryError> {
        if self.amount == 0 && !self.full_close {
            return Err(BoundaryError::ZeroWithdrawal);
        }
        Ok(())
    }
}

impl<D: Digest> Write for WithdrawalBody<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.deployment.write(buf);
        self.state_root.write(buf);
        self.destination.write(buf);
        self.amount.write(buf);
        self.full_close.write(buf);
        self.deadline.write(buf);
    }
}

impl<D: Digest> EncodeSize for WithdrawalBody<D> {
    fn encode_size(&self) -> usize {
        D::SIZE * 2 + self.destination.encode_size() + u64::SIZE + bool::SIZE + u64::SIZE
    }

    fn encode_inline_size(&self) -> usize {
        D::SIZE * 2 + self.destination.encode_inline_size() + u64::SIZE + bool::SIZE + u64::SIZE
    }
}

impl<D: Digest> Read for WithdrawalBody<D> {
    type Cfg = RangeCfg<usize>;

    fn read_cfg(buf: &mut impl Buf, destination_cfg: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            deployment: D::read(buf)?,
            state_root: D::read(buf)?,
            destination: Bytes::read_cfg(buf, destination_cfg)?,
            amount: u64::read(buf)?,
            full_close: bool::read(buf)?,
            deadline: u64::read(buf)?,
        })
    }
}

/// Account-attributed signature over a withdrawal tuple.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedWithdrawal<P: PublicKey, D: Digest> {
    account: P,
    body: WithdrawalBody<D>,
    account_signature: P::Signature,
}

impl<P: PublicKey, D: Digest> SignedWithdrawal<P, D> {
    /// Creates and signs a withdrawal authorization.
    #[allow(clippy::too_many_arguments)]
    pub fn sign<S: Signer<PublicKey = P, Signature = P::Signature>>(
        deployment: D,
        state_root: D,
        destination: Bytes,
        amount: u64,
        full_close: bool,
        deadline: Deadline,
        account: &S,
    ) -> Result<Self, BoundaryError> {
        let body = WithdrawalBody::new(
            deployment,
            state_root,
            destination,
            amount,
            full_close,
            deadline,
        )?;
        Ok(Self::sign_body_by_authority(body, account))
    }

    /// Signs an explicit body with the supplied account authority.
    ///
    /// This intentionally permits a semantically invalid body to model everything a faulty
    /// account can authorize. Call [`Self::verify_context`] before relying on the result.
    pub fn sign_body_by_authority<S: Signer<PublicKey = P, Signature = P::Signature>>(
        body: WithdrawalBody<D>,
        account: &S,
    ) -> Self {
        let account_signature = account.sign(WITHDRAWAL_SIGNATURE_NAMESPACE, &body.encode());
        Self {
            account: account.public_key(),
            body,
            account_signature,
        }
    }

    /// Constructs a raw envelope without checking its account, signature, or body.
    ///
    /// This is intended for adversarial decoding fixtures. Normal construction should use
    /// [`Self::sign`] or [`Self::sign_body_by_authority`].
    pub const fn from_raw_unchecked(
        account: P,
        body: WithdrawalBody<D>,
        account_signature: P::Signature,
    ) -> Self {
        Self {
            account,
            body,
            account_signature,
        }
    }

    /// Returns the authorizing account.
    pub const fn account(&self) -> &P {
        &self.account
    }

    /// Returns the signed withdrawal tuple.
    pub const fn body(&self) -> &WithdrawalBody<D> {
        &self.body
    }

    /// Returns the account signature.
    pub const fn signature(&self) -> &P::Signature {
        &self.account_signature
    }

    /// Returns the stable identifier derived from the account and unsigned body.
    pub fn id<H: Hasher<Digest = D>>(&self) -> WithdrawalId<D> {
        let body = self.body.encode();
        WithdrawalId(H::hash(&[
            WITHDRAWAL_ID_HASH_NAMESPACE,
            self.account.as_ref(),
            body.as_ref(),
        ]))
    }

    /// Consumes the authorization into its raw parts.
    pub fn into_parts(self) -> (P, WithdrawalBody<D>, P::Signature) {
        (self.account, self.body, self.account_signature)
    }

    /// Verifies the signature and basic amount invariant without binding a context.
    pub fn verify_signature(&self) -> Result<(), BoundaryError> {
        self.body.validate()?;
        if !self.account.verify(
            WITHDRAWAL_SIGNATURE_NAMESPACE,
            &self.body.encode(),
            &self.account_signature,
        ) {
            return Err(BoundaryError::InvalidWithdrawalSignature);
        }
        Ok(())
    }

    /// Verifies the deployment, signature, and basic amount invariant.
    ///
    /// The authorization root remains request-local: one sealed batch may contain
    /// withdrawals queued against different finalized roots.
    pub fn verify_deployment(&self, deployment: &D) -> Result<(), BoundaryError> {
        if self.body.deployment != *deployment {
            return Err(BoundaryError::WrongContext);
        }
        self.verify_signature()
    }

    /// Verifies the exact deployment and finalized state root plus the account signature.
    pub fn verify_context(&self, deployment: &D, state_root: &D) -> Result<(), BoundaryError> {
        if self.body.deployment != *deployment || self.body.state_root != *state_root {
            return Err(BoundaryError::WrongContext);
        }
        self.verify_signature()
    }
}

impl<P: PublicKey, D: Digest> Write for SignedWithdrawal<P, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.account.write(buf);
        self.body.write(buf);
        self.account_signature.write(buf);
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for SignedWithdrawal<P, D> {
    fn encode_size(&self) -> usize {
        P::SIZE + self.body.encode_size() + P::Signature::SIZE
    }

    fn encode_inline_size(&self) -> usize {
        P::SIZE + self.body.encode_inline_size() + P::Signature::SIZE
    }
}

impl<P: PublicKey, D: Digest> Read for SignedWithdrawal<P, D> {
    type Cfg = RangeCfg<usize>;

    fn read_cfg(buf: &mut impl Buf, destination_cfg: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            account: P::read(buf)?,
            body: WithdrawalBody::read_cfg(buf, destination_cfg)?,
            account_signature: P::Signature::read(buf)?,
        })
    }
}

/// Bounded decoding configuration for [`WithdrawalBatch`].
///
/// The first range limits record count and the second limits each destination byte length.
pub type WithdrawalBatchCfg = (RangeCfg<usize>, RangeCfg<usize>);

/// Exact account-sorted withdrawal boundary for one epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WithdrawalBatch<P: PublicKey, D: Digest> {
    requests: Vec<SignedWithdrawal<P, D>>,
    total: u64,
}

impl<P: PublicKey, D: Digest> WithdrawalBatch<P, D> {
    /// Sorts requests by account and constructs a unique withdrawal boundary.
    pub fn new(mut requests: Vec<SignedWithdrawal<P, D>>) -> Result<Self, BoundaryError> {
        requests.sort_unstable_by(|left, right| left.account.cmp(&right.account));
        Self::from_sorted(requests)
    }

    /// Returns an empty withdrawal boundary.
    pub const fn empty() -> Self {
        Self {
            requests: Vec::new(),
            total: 0,
        }
    }

    fn from_sorted(requests: Vec<SignedWithdrawal<P, D>>) -> Result<Self, BoundaryError> {
        for request in &requests {
            request.body.validate()?;
        }
        if requests
            .windows(2)
            .any(|pair| pair[0].account >= pair[1].account)
        {
            return Err(BoundaryError::NonCanonicalWithdrawals);
        }
        let total = requests.iter().try_fold(0_u64, |total, request| {
            total
                .checked_add(request.body.amount)
                .ok_or(BoundaryError::ArithmeticOverflow)
        })?;
        Ok(Self { requests, total })
    }

    /// Returns the canonical requests.
    pub fn requests(&self) -> &[SignedWithdrawal<P, D>] {
        &self.requests
    }

    /// Returns the number of authorizing accounts.
    pub const fn len(&self) -> usize {
        self.requests.len()
    }

    /// Returns whether the boundary has no withdrawals.
    pub const fn is_empty(&self) -> bool {
        self.requests.is_empty()
    }

    /// Returns the checked aggregate withdrawal amount.
    pub const fn total(&self) -> u64 {
        self.total
    }

    /// Returns the request for an account, if present.
    pub fn request_for(&self, account: &P) -> Option<&SignedWithdrawal<P, D>> {
        self.requests
            .binary_search_by(|request| request.account.cmp(account))
            .ok()
            .map(|index| &self.requests[index])
    }

    /// Returns one account's requested amount, or zero when absent.
    pub fn amount_for(&self, account: &P) -> u64 {
        self.request_for(account)
            .map_or(0, |request| request.body.amount)
    }

    /// Verifies every request against the exact deployment and finalized state root.
    pub fn verify_context(&self, deployment: &D, state_root: &D) -> Result<(), BoundaryError> {
        for request in &self.requests {
            request.verify_context(deployment, state_root)?;
        }
        Ok(())
    }

    /// Verifies every request's deployment and signature.
    ///
    /// Authorization roots are deliberately checked when each request enters
    /// settlement state, because requests in one later boundary may have been
    /// queued against different finalized roots.
    pub fn verify_deployment(&self, deployment: &D) -> Result<(), BoundaryError> {
        for request in &self.requests {
            request.verify_deployment(deployment)?;
        }
        Ok(())
    }

    /// Commits the exact sorted signed withdrawals for inclusion in an epoch anchor.
    pub fn root<H: Hasher<Digest = D>>(&self) -> Result<VectorRoot<D>, commitment::Error> {
        let len = vector_len(self.requests.len())?;
        let mut builder = commitment::Builder::<H>::new(VectorKind::Withdrawal, len)?;
        for request in &self.requests {
            builder.add_encoded(request.encode().as_ref())?;
        }
        Ok(builder.build()?.root())
    }
}

impl<P: PublicKey, D: Digest> Default for WithdrawalBatch<P, D> {
    fn default() -> Self {
        Self::empty()
    }
}

impl<P: PublicKey, D: Digest> Write for WithdrawalBatch<P, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.requests.write(buf);
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for WithdrawalBatch<P, D> {
    fn encode_size(&self) -> usize {
        self.requests.encode_size()
    }

    fn encode_inline_size(&self) -> usize {
        self.requests.encode_inline_size()
    }
}

impl<P: PublicKey, D: Digest> Read for WithdrawalBatch<P, D> {
    type Cfg = WithdrawalBatchCfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let requests = Vec::<SignedWithdrawal<P, D>>::read_cfg(buf, &(cfg.0, cfg.1))?;
        Self::from_sorted(requests).map_err(|error| match error {
            BoundaryError::ZeroWithdrawal => CodecError::Invalid(
                "clearing::WithdrawalBatch",
                "zero amount requires a full close",
            ),
            BoundaryError::NonCanonicalWithdrawals => CodecError::Invalid(
                "clearing::WithdrawalBatch",
                "withdrawal accounts are not strictly sorted and unique",
            ),
            BoundaryError::ArithmeticOverflow => CodecError::Invalid(
                "clearing::WithdrawalBatch",
                "aggregate withdrawal amount overflows u64",
            ),
            _ => unreachable!("batch validation performed signature or context checks"),
        })
    }
}

/// Boundary construction or verification failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum BoundaryError {
    /// Deposit records must carry value.
    #[error("deposit amount must be positive")]
    ZeroDeposit,
    /// A zero withdrawal amount is valid only for a full close.
    #[error("zero withdrawal amount requires a full close")]
    ZeroWithdrawal,
    /// Deposit accounts are not strictly sorted and unique.
    #[error("deposit accounts are not strictly sorted and unique")]
    NonCanonicalDeposits,
    /// Withdrawal accounts are not strictly sorted and unique.
    #[error("withdrawal accounts are not strictly sorted and unique")]
    NonCanonicalWithdrawals,
    /// Aggregate boundary arithmetic overflowed.
    #[error("checked boundary arithmetic overflowed")]
    ArithmeticOverflow,
    /// A withdrawal binds another deployment or finalized state root.
    #[error("withdrawal binds another deployment or finalized state root")]
    WrongContext,
    /// The attributed account did not sign the withdrawal tuple.
    #[error("withdrawal account signature is invalid")]
    InvalidWithdrawalSignature,
}

#[cfg(feature = "arbitrary")]
mod arbitrary_impls {
    use super::*;

    fn bytes<'a>(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Bytes> {
        let len = usize::from(u.arbitrary::<u8>()? % 65);
        Ok(Bytes::copy_from_slice(u.bytes(len)?))
    }

    impl<'a, P> arbitrary::Arbitrary<'a> for DepositRecord<P>
    where
        P: PublicKey + arbitrary::Arbitrary<'a>,
    {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self {
                account: u.arbitrary()?,
                amount: u.arbitrary()?,
            })
        }
    }

    impl<'a, P> arbitrary::Arbitrary<'a> for DepositBatch<P>
    where
        P: PublicKey + arbitrary::Arbitrary<'a>,
    {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            let len = usize::from(u.arbitrary::<u8>()? % 33);
            let mut records: Vec<DepositRecord<P>> = Vec::with_capacity(len);
            for _ in 0..len {
                records.push(DepositRecord {
                    account: u.arbitrary()?,
                    amount: u.arbitrary::<u32>()? as u64 + 1,
                });
            }
            records.sort_unstable_by(|left, right| left.account.cmp(&right.account));
            records.dedup_by(|left, right| left.account == right.account);
            Self::from_sorted(records).map_err(|_| arbitrary::Error::IncorrectFormat)
        }
    }

    impl<'a, D> arbitrary::Arbitrary<'a> for WithdrawalId<D>
    where
        D: Digest + arbitrary::Arbitrary<'a>,
    {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self(u.arbitrary()?))
        }
    }

    impl<'a, D> arbitrary::Arbitrary<'a> for WithdrawalBody<D>
    where
        D: Digest + arbitrary::Arbitrary<'a>,
    {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self {
                deployment: u.arbitrary()?,
                state_root: u.arbitrary()?,
                destination: bytes(u)?,
                amount: u.arbitrary()?,
                full_close: u.arbitrary()?,
                deadline: u.arbitrary()?,
            })
        }
    }

    impl<'a, P, D> arbitrary::Arbitrary<'a> for SignedWithdrawal<P, D>
    where
        P: PublicKey + arbitrary::Arbitrary<'a>,
        P::Signature: arbitrary::Arbitrary<'a>,
        D: Digest + arbitrary::Arbitrary<'a>,
    {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self {
                account: u.arbitrary()?,
                body: u.arbitrary()?,
                account_signature: u.arbitrary()?,
            })
        }
    }

    impl<'a, P, D> arbitrary::Arbitrary<'a> for WithdrawalBatch<P, D>
    where
        P: PublicKey + arbitrary::Arbitrary<'a>,
        P::Signature: arbitrary::Arbitrary<'a>,
        D: Digest + arbitrary::Arbitrary<'a>,
    {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            let len = usize::from(u.arbitrary::<u8>()? % 33);
            let mut requests = Vec::with_capacity(len);
            for _ in 0..len {
                let mut request: SignedWithdrawal<P, D> = u.arbitrary()?;
                request.body.amount = u.arbitrary::<u32>()? as u64;
                if request.body.amount == 0 {
                    request.body.full_close = true;
                }
                requests.push(request);
            }
            requests.sort_unstable_by(|left, right| left.account.cmp(&right.account));
            requests.dedup_by(|left, right| left.account == right.account);
            Self::from_sorted(requests).map_err(|_| arbitrary::Error::IncorrectFormat)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{Decode, Encode};
    use commonware_cryptography::{
        Sha256,
        curve25519::{SigningKey, VerifyingKey},
        sha256::Digest as ShaDigest,
    };

    type TestDeposits = DepositBatch<VerifyingKey>;
    type TestWithdrawal = SignedWithdrawal<VerifyingKey, ShaDigest>;
    type TestWithdrawals = WithdrawalBatch<VerifyingKey, ShaDigest>;

    fn context() -> (ShaDigest, ShaDigest) {
        (Sha256::hash(&[b"deployment"]), Sha256::hash(&[b"state"]))
    }

    fn withdrawal(
        account: &SigningKey,
        amount: u64,
        full_close: bool,
        destination: &'static [u8],
    ) -> TestWithdrawal {
        let (deployment, state_root) = context();
        SignedWithdrawal::sign(
            deployment,
            state_root,
            Bytes::from_static(destination),
            amount,
            full_close,
            99,
            account,
        )
        .unwrap()
    }

    #[test]
    fn withdrawal_decode_rejects_a_low_order_account_identity() {
        let mut encoded = withdrawal(&SigningKey::from_seed(1), 1, false, b"destination")
            .encode()
            .to_vec();
        encoded[..VerifyingKey::SIZE].fill(0);
        encoded[0] = 1;
        assert!(TestWithdrawal::decode_cfg(encoded.as_slice(), &(..=32).into()).is_err());
    }

    #[test]
    fn deposits_are_sorted_unique_checked_and_searchable() {
        let a = SigningKey::from_seed(1).public_key();
        let b = SigningKey::from_seed(2).public_key();
        let deposits = DepositBatch::new(vec![
            DepositRecord::new(b.clone(), 7).unwrap(),
            DepositRecord::new(a.clone(), 5).unwrap(),
        ])
        .unwrap();
        assert!(deposits.records()[0].account() < deposits.records()[1].account());
        assert_eq!(deposits.total(), 12);
        assert_eq!(deposits.amount_for(&a), 5);
        assert_eq!(
            deposits.amount_for(&SigningKey::from_seed(3).public_key()),
            0
        );

        assert_eq!(
            DepositBatch::new(vec![
                DepositRecord::new(a.clone(), 1).unwrap(),
                DepositRecord::new(a, 2).unwrap(),
            ]),
            Err(BoundaryError::NonCanonicalDeposits)
        );
        assert_eq!(DepositRecord::new(b, 0), Err(BoundaryError::ZeroDeposit));
    }

    #[test]
    fn boundary_totals_never_wrap() {
        let a = SigningKey::from_seed(1).public_key();
        let b = SigningKey::from_seed(2).public_key();
        assert_eq!(
            DepositBatch::new(vec![
                DepositRecord::new(a, u64::MAX).unwrap(),
                DepositRecord::new(b, 1).unwrap(),
            ]),
            Err(BoundaryError::ArithmeticOverflow)
        );
    }

    #[test]
    fn boundary_roots_bind_exact_sorted_records() {
        let a = SigningKey::from_seed(2);
        let b = SigningKey::from_seed(3);
        let deposits = DepositBatch::new(vec![
            DepositRecord::new(b.public_key(), 2).unwrap(),
            DepositRecord::new(a.public_key(), 1).unwrap(),
        ])
        .unwrap();
        let reversed_amounts = DepositBatch::new(vec![
            DepositRecord::new(a.public_key(), 2).unwrap(),
            DepositRecord::new(b.public_key(), 1).unwrap(),
        ])
        .unwrap();
        assert_ne!(
            deposits.root::<Sha256>().unwrap(),
            reversed_amounts.root::<Sha256>().unwrap()
        );
        assert_eq!(deposits.root::<Sha256>().unwrap().kind, VectorKind::Deposit);

        let withdrawals = WithdrawalBatch::new(vec![
            withdrawal(&b, 2, false, b"b"),
            withdrawal(&a, 1, false, b"a"),
        ])
        .unwrap();
        assert_eq!(
            withdrawals.root::<Sha256>().unwrap().kind,
            VectorKind::Withdrawal
        );
        assert_ne!(
            deposits.root::<Sha256>().unwrap().digest,
            withdrawals.root::<Sha256>().unwrap().digest
        );
    }

    #[test]
    fn withdrawal_matches_blog_tuple_and_verifies_context() {
        let account = SigningKey::from_seed(4);
        let request = withdrawal(&account, 8, false, b"adapter-destination");
        let (deployment, state_root) = context();
        assert_eq!(request.account(), &account.public_key());
        assert_eq!(request.body().deployment(), &deployment);
        assert_eq!(request.body().state_root(), &state_root);
        assert_eq!(
            request.body().destination(),
            b"adapter-destination".as_slice()
        );
        assert_eq!(request.body().amount(), 8);
        assert!(!request.body().full_close());
        assert_eq!(request.body().deadline(), 99);
        assert_eq!(request.verify_context(&deployment, &state_root), Ok(()));
        assert_eq!(
            request.verify_context(&Sha256::hash(&[b"other"]), &state_root),
            Err(BoundaryError::WrongContext)
        );
    }

    #[test]
    fn zero_value_is_reserved_for_full_close() {
        let account = SigningKey::from_seed(5);
        let (deployment, state_root) = context();
        assert_eq!(
            SignedWithdrawal::sign(deployment, state_root, Bytes::new(), 0, false, 1, &account,),
            Err(BoundaryError::ZeroWithdrawal)
        );
        assert!(
            SignedWithdrawal::sign(deployment, state_root, Bytes::new(), 0, true, 1, &account,)
                .is_ok()
        );
    }

    #[test]
    fn authority_constructor_exposes_faults_but_verification_rejects_them() {
        let account = SigningKey::from_seed(6);
        let (deployment, state_root) = context();
        let invalid =
            WithdrawalBody::from_raw_unchecked(deployment, state_root, Bytes::new(), 0, false, 10);
        let invalid = SignedWithdrawal::sign_body_by_authority(invalid, &account);
        assert_eq!(
            invalid.verify_context(&deployment, &state_root),
            Err(BoundaryError::ZeroWithdrawal)
        );
    }

    #[test]
    fn withdrawal_id_binds_account_but_excludes_signature() {
        let account = SigningKey::from_seed(7);
        let other = SigningKey::from_seed(8);
        let request = withdrawal(&account, 2, false, b"destination");
        let different_envelope =
            SignedWithdrawal::sign_body_by_authority(request.body().clone(), &other);
        assert_ne!(request.id::<Sha256>(), different_envelope.id::<Sha256>());
        assert_ne!(request.signature(), different_envelope.signature());

        let (account, body, signature) = request.clone().into_parts();
        let same_authorization = SignedWithdrawal::from_raw_unchecked(account, body, signature);
        assert_eq!(request.id::<Sha256>(), same_authorization.id::<Sha256>());
    }

    #[test]
    fn withdrawals_are_sorted_unique_searchable_and_verifiable() {
        let a = SigningKey::from_seed(9);
        let b = SigningKey::from_seed(10);
        let requests = WithdrawalBatch::new(vec![
            withdrawal(&b, 4, false, b"b"),
            withdrawal(&a, 3, false, b"a"),
        ])
        .unwrap();
        assert!(requests.requests()[0].account() < requests.requests()[1].account());
        assert_eq!(requests.total(), 7);
        assert_eq!(requests.amount_for(&a.public_key()), 3);
        let (deployment, state_root) = context();
        assert_eq!(requests.verify_context(&deployment, &state_root), Ok(()));

        assert_eq!(
            WithdrawalBatch::new(vec![
                withdrawal(&a, 1, false, b"one"),
                withdrawal(&a, 2, false, b"two"),
            ]),
            Err(BoundaryError::NonCanonicalWithdrawals)
        );
    }

    #[test]
    fn one_batch_accepts_valid_requests_from_distinct_authorization_roots() {
        let deployment = Sha256::hash(&[b"deployment"]);
        let first_root = Sha256::hash(&[b"first-root"]);
        let second_root = Sha256::hash(&[b"second-root"]);
        let first = SigningKey::from_seed(40);
        let second = SigningKey::from_seed(41);
        let requests = WithdrawalBatch::new(vec![
            SignedWithdrawal::sign(
                deployment,
                first_root,
                Bytes::from_static(b"first"),
                1,
                false,
                50,
                &first,
            )
            .unwrap(),
            SignedWithdrawal::sign(
                deployment,
                second_root,
                Bytes::from_static(b"second"),
                2,
                false,
                51,
                &second,
            )
            .unwrap(),
        ])
        .unwrap();

        assert_eq!(requests.verify_deployment(&deployment), Ok(()));
        assert_eq!(
            requests.verify_context(&deployment, &first_root),
            Err(BoundaryError::WrongContext)
        );
        assert_eq!(
            requests.verify_deployment(&Sha256::hash(&[b"other-deployment"])),
            Err(BoundaryError::WrongContext)
        );
    }

    #[test]
    fn destination_and_record_decoding_are_bounded() {
        let request = withdrawal(&SigningKey::from_seed(11), 1, false, b"four");
        let encoded = request.encode();
        assert!(matches!(
            TestWithdrawal::decode_cfg(encoded.clone(), &(..=3).into()),
            Err(CodecError::InvalidLength(4))
        ));
        assert_eq!(
            TestWithdrawal::decode_cfg(encoded, &(..=4).into()).unwrap(),
            request
        );

        let deposits = DepositBatch::new(vec![
            DepositRecord::new(SigningKey::from_seed(12).public_key(), 1).unwrap(),
            DepositRecord::new(SigningKey::from_seed(13).public_key(), 2).unwrap(),
        ])
        .unwrap();
        assert!(matches!(
            TestDeposits::decode_cfg(deposits.encode(), &(..=1).into()),
            Err(CodecError::InvalidLength(2))
        ));

        let requests = WithdrawalBatch::new(vec![
            withdrawal(&SigningKey::from_seed(14), 1, false, b"a"),
            withdrawal(&SigningKey::from_seed(15), 1, false, b"b"),
        ])
        .unwrap();
        assert!(matches!(
            TestWithdrawals::decode_cfg(requests.encode(), &((..=1).into(), (..=8).into()),),
            Err(CodecError::InvalidLength(2))
        ));
    }

    #[test]
    fn decoded_batches_reject_noncanonical_order() {
        let first = DepositRecord::new(SigningKey::from_seed(16).public_key(), 1).unwrap();
        let second = DepositRecord::new(SigningKey::from_seed(17).public_key(), 1).unwrap();
        let mut records = vec![first, second];
        records.sort_unstable_by(|left, right| right.account.cmp(&left.account));
        assert!(matches!(
            TestDeposits::decode_cfg(records.encode(), &(..=2).into()),
            Err(CodecError::Invalid("clearing::DepositBatch", _))
        ));
    }

    #[test]
    fn boundary_codec_round_trips_with_explicit_limits() {
        let deposits = DepositBatch::new(vec![
            DepositRecord::new(SigningKey::from_seed(18).public_key(), 5).unwrap(),
            DepositRecord::new(SigningKey::from_seed(19).public_key(), 6).unwrap(),
        ])
        .unwrap();
        assert_eq!(
            TestDeposits::decode_cfg(deposits.encode(), &(..=8).into()).unwrap(),
            deposits
        );

        let requests = WithdrawalBatch::new(vec![withdrawal(
            &SigningKey::from_seed(20),
            3,
            false,
            b"destination",
        )])
        .unwrap();
        assert_eq!(
            TestWithdrawals::decode_cfg(requests.encode(), &((..=8).into(), (..=32).into()),)
                .unwrap(),
            requests
        );
    }
}
