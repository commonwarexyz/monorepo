//! Closes, soft withdrawals, and the requests queued on the ledger.

use super::{Amount, Amounts, Epoch, Error, Matrix, Namespace};
use bytes::BufMut;
use commonware_codec::{
    Buf, EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt, Write,
};
use commonware_cryptography::{Digest, Hasher, PublicKey, Signer};

/// An account's signed request to withdraw up to `amount` in `epoch` through the operator.
///
/// The operator decides whether the close of `epoch` honors it. An account it ignores can still
/// withdraw through the ledger with a [ForcedWithdrawal]. Requests differing only in their
/// signature are the same request, and `tag` distinguishes otherwise identical ones.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Withdrawal<P: PublicKey, A: Amount> {
    /// Epoch whose close may pay the withdrawal.
    pub epoch: Epoch,
    /// Account withdrawing.
    pub account: P,
    /// Largest amount to withdraw.
    pub amount: A,
    /// Distinguishes requests with the same epoch, account, and amount.
    pub tag: u64,
    /// The account's signature over the request.
    pub signature: P::Signature,
}

impl<P: PublicKey, A: Amount> Withdrawal<P, A> {
    /// Size of the signed part of a request.
    const REQUEST_SIZE: usize = Epoch::SIZE + P::SIZE + A::SIZE + u64::SIZE;

    /// Signs a request to withdraw up to `amount` from `signer`'s account in `epoch`.
    pub fn sign<S: Signer<PublicKey = P, Signature = P::Signature>>(
        signer: &S,
        namespace: &Namespace,
        epoch: Epoch,
        amount: A,
        tag: u64,
    ) -> Self {
        let account = signer.public_key();
        let signature = signer.sign(
            &namespace.withdrawal,
            &Self::message(epoch, &account, amount, tag),
        );
        Self {
            epoch,
            account,
            amount,
            tag,
            signature,
        }
    }

    /// Writes the signed part of a request.
    fn write_request(epoch: Epoch, account: &P, amount: A, tag: u64, buf: &mut impl BufMut) {
        epoch.write(buf);
        account.write(buf);
        amount.write(buf);
        tag.write(buf);
    }

    /// Encodes the signed part of a request.
    fn message(epoch: Epoch, account: &P, amount: A, tag: u64) -> Vec<u8> {
        let mut message = Vec::with_capacity(Self::REQUEST_SIZE);
        Self::write_request(epoch, account, amount, tag, &mut message);
        message
    }

    /// Returns whether the amount is positive and the account signed the request.
    pub fn verify(&self, namespace: &Namespace) -> bool {
        self.amount != A::ZERO
            && self.account.verify(
                &namespace.withdrawal,
                &Self::message(self.epoch, &self.account, self.amount, self.tag),
                &self.signature,
            )
    }

    /// Returns the signed part of the request. It identifies the request and orders requests in a
    /// close.
    pub(crate) const fn request(&self) -> (Epoch, &P, A, u64) {
        (self.epoch, &self.account, self.amount, self.tag)
    }
}

impl<P: PublicKey, A: Amount> Write for Withdrawal<P, A> {
    fn write(&self, buf: &mut impl BufMut) {
        Self::write_request(self.epoch, &self.account, self.amount, self.tag, buf);
        self.signature.write(buf);
    }
}

impl<P: PublicKey, A: Amount> FixedSize for Withdrawal<P, A> {
    const SIZE: usize = Self::REQUEST_SIZE + P::Signature::SIZE;
}

impl<P: PublicKey, A: Amount> Read for Withdrawal<P, A> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            epoch: Epoch::read(buf)?,
            account: P::read(buf)?,
            amount: A::read(buf)?,
            tag: u64::read(buf)?,
            signature: P::Signature::read(buf)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<P: PublicKey, A: Amount> arbitrary::Arbitrary<'_> for Withdrawal<P, A>
where
    P: for<'a> arbitrary::Arbitrary<'a>,
    P::Signature: for<'a> arbitrary::Arbitrary<'a>,
    A: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            epoch: u.arbitrary()?,
            account: u.arbitrary()?,
            amount: u.arbitrary()?,
            tag: u.arbitrary()?,
            signature: u.arbitrary()?,
        })
    }
}

/// A deposit queued on the ledger.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Deposit<P: PublicKey, A: Amount> {
    /// Account credited.
    pub account: P,
    /// Amount deposited.
    pub amount: A,
}

/// A forced withdrawal queued on the ledger.
///
/// It requests up to `amount`, and the close processing it pays that amount or empties the
/// balance.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ForcedWithdrawal<P: PublicKey, A: Amount> {
    /// Account withdrawing.
    pub account: P,
    /// Largest amount to withdraw.
    pub amount: A,
}

/// Returns `count` as a number of queued requests.
///
/// Returns an error unless `required <= count <= queued`.
pub(crate) fn processed(required: usize, queued: usize, count: u64) -> Result<usize, Error> {
    usize::try_from(count)
        .ok()
        .filter(|count| (required..=queued).contains(count))
        .ok_or(Error::InvalidCount)
}

/// The requests queued on the ledger that the next close may process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Queue<P: PublicKey, A: Amount> {
    /// Epoch whose close the ledger expects next.
    pub epoch: Epoch,
    /// Unprocessed deposits, oldest first.
    pub deposits: Vec<Deposit<P, A>>,
    /// Number of deposits the next close must process.
    pub required_deposits: usize,
    /// Unprocessed forced withdrawals, oldest first.
    pub forced_withdrawals: Vec<ForcedWithdrawal<P, A>>,
    /// Number of forced withdrawals the next close must process.
    pub required_forced_withdrawals: usize,
}

impl<P: PublicKey, A: Amount> Queue<P, A> {
    /// Returns the oldest `deposits` deposits and `forced_withdrawals` forced withdrawals, the
    /// requests a close with these counts processes.
    ///
    /// A sharded deployment checks its counts with it before cutting, because a shard cannot cut an
    /// epoch again once assembly refuses its cut. It passes each shard's
    /// [Operator::cut](super::Operator::cut) the forced withdrawals of that shard's accounts.
    ///
    /// Returns an error unless each count is between the number of requests the close must
    /// process and the number queued.
    #[allow(clippy::type_complexity)]
    pub fn prefix(
        &self,
        deposits: u64,
        forced_withdrawals: u64,
    ) -> Result<(&[Deposit<P, A>], &[ForcedWithdrawal<P, A>]), Error> {
        let deposits = processed(self.required_deposits, self.deposits.len(), deposits)?;
        let forced_withdrawals = processed(
            self.required_forced_withdrawals,
            self.forced_withdrawals.len(),
            forced_withdrawals,
        )?;
        Ok((
            &self.deposits[..deposits],
            &self.forced_withdrawals[..forced_withdrawals],
        ))
    }
}

/// A sender's payment map settled by a close, with the sender's signature over its state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row<P: PublicKey, A: Amount> {
    /// Account paying.
    pub account: P,
    /// Cumulative amount paid to each receiver.
    pub payments: Amounts<P, A>,
    /// The sender's signature over its state in the close's epoch.
    pub signature: P::Signature,
}

impl<P: PublicKey, A: Amount> Write for Row<P, A> {
    fn write(&self, buf: &mut impl BufMut) {
        self.account.write(buf);
        self.payments.write(buf);
        self.signature.write(buf);
    }
}

impl<P: PublicKey, A: Amount> EncodeSize for Row<P, A> {
    fn encode_size(&self) -> usize {
        P::SIZE + self.payments.encode_size() + P::Signature::SIZE
    }
}

impl<P: PublicKey, A: Amount> Read for Row<P, A> {
    /// The maximum number of receivers.
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, receivers: &usize) -> Result<Self, CodecError> {
        Ok(Self {
            account: P::read(buf)?,
            payments: Amounts::read_cfg(buf, &RangeCfg::new(1..=*receivers))?,
            signature: P::Signature::read(buf)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<P: PublicKey, A: Amount> arbitrary::Arbitrary<'_> for Row<P, A>
where
    P: for<'a> arbitrary::Arbitrary<'a>,
    P::Signature: for<'a> arbitrary::Arbitrary<'a>,
    A: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let receiver = u.arbitrary()?;
        let amount = super::amounts::arbitrary_nonzero(u)?;
        let payments = Amounts::<P, A>::arbitrary(u)?
            .combine(&Amounts::new([(receiver, amount)]).expect("amount must be nonzero"))
            .map_err(|_| arbitrary::Error::IncorrectFormat)?;
        Ok(Self {
            account: u.arbitrary()?,
            payments,
            signature: u.arbitrary()?,
        })
    }
}

/// Bounds on the size of a [Close].
///
/// Validators decode a close with their limits. An [Operator](super::Operator) admits each epoch
/// within its own limits, so the close it builds decodes when those are within the validators'.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Maximum number of senders.
    pub rows: usize,
    /// Maximum number of receivers in one sender's payment map.
    pub receivers: usize,
    /// Maximum number of soft withdrawals.
    pub withdrawals: usize,
}

/// The operator's close of an epoch.
///
/// Rows are strictly increasing by account and pay at least one receiver each. Withdrawals are
/// strictly increasing by their signed request, so no request appears twice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Close<P: PublicKey, O: PublicKey, A: Amount> {
    pub(crate) epoch: Epoch,
    pub(crate) rows: Vec<Row<P, A>>,
    pub(crate) withdrawals: Vec<Withdrawal<P, A>>,
    pub(crate) deposits: u64,
    pub(crate) forced_withdrawals: u64,
    pub(crate) signature: O::Signature,
}

impl<P: PublicKey, O: PublicKey, A: Amount> Close<P, O, A> {
    /// Returns a close of rows and withdrawals already in their canonical order.
    pub(crate) fn new(
        epoch: Epoch,
        rows: Vec<Row<P, A>>,
        withdrawals: Vec<Withdrawal<P, A>>,
        deposits: u64,
        forced_withdrawals: u64,
        signature: O::Signature,
    ) -> Self {
        debug_assert!(Self::is_canonical(&rows, &withdrawals));
        Self {
            epoch,
            rows,
            withdrawals,
            deposits,
            forced_withdrawals,
            signature,
        }
    }

    /// Returns whether rows and withdrawals are strictly increasing and every row pays someone.
    fn is_canonical(rows: &[Row<P, A>], withdrawals: &[Withdrawal<P, A>]) -> bool {
        rows.iter().all(|row| !row.payments.is_empty())
            && rows
                .windows(2)
                .all(|pair| pair[0].account < pair[1].account)
            && withdrawals
                .windows(2)
                .all(|pair| pair[0].request() < pair[1].request())
    }

    /// Encodes the part of a close the operator signs.
    ///
    /// The matrix root stands in for the rows it commits to.
    pub(crate) fn message<D: Digest>(
        epoch: Epoch,
        matrix: &D,
        withdrawals: &[Withdrawal<P, A>],
        deposits: u64,
        forced_withdrawals: u64,
    ) -> Vec<u8> {
        let mut message =
            Vec::with_capacity(Epoch::SIZE + D::SIZE + withdrawals.encode_size() + 2 * u64::SIZE);
        epoch.write(&mut message);
        matrix.write(&mut message);
        withdrawals.write(&mut message);
        deposits.write(&mut message);
        forced_withdrawals.write(&mut message);
        message
    }

    /// Returns the epoch closed.
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns every sender's settled payment map, in account order.
    pub fn rows(&self) -> &[Row<P, A>] {
        &self.rows
    }

    /// Returns the soft withdrawals honored, in request order.
    pub fn withdrawals(&self) -> &[Withdrawal<P, A>] {
        &self.withdrawals
    }

    /// Returns the number of queued deposits processed.
    pub const fn deposits(&self) -> u64 {
        self.deposits
    }

    /// Returns the number of queued forced withdrawals processed.
    pub const fn forced_withdrawals(&self) -> u64 {
        self.forced_withdrawals
    }

    /// Returns the operator's signature.
    pub const fn signature(&self) -> &O::Signature {
        &self.signature
    }

    /// Returns the payment matrix the close settles.
    pub fn matrix<H: Hasher>(&self) -> Matrix<P, H::Digest, A> {
        Matrix::from_sorted::<H>(
            self.rows
                .iter()
                .map(|row| {
                    (
                        row.account.clone(),
                        row.payments.clone(),
                        row.payments.root::<H>(),
                    )
                })
                .collect(),
        )
    }
}

impl<P: PublicKey, O: PublicKey, A: Amount> Write for Close<P, O, A> {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch.write(buf);
        self.rows.write(buf);
        self.withdrawals.write(buf);
        self.deposits.write(buf);
        self.forced_withdrawals.write(buf);
        self.signature.write(buf);
    }
}

impl<P: PublicKey, O: PublicKey, A: Amount> EncodeSize for Close<P, O, A> {
    fn encode_size(&self) -> usize {
        Epoch::SIZE
            + self.rows.encode_size()
            + self.withdrawals.encode_size()
            + 2 * u64::SIZE
            + O::Signature::SIZE
    }
}

impl<P: PublicKey, O: PublicKey, A: Amount> Read for Close<P, O, A> {
    type Cfg = Limits;

    fn read_cfg(buf: &mut impl Buf, limits: &Limits) -> Result<Self, CodecError> {
        let epoch = Epoch::read(buf)?;
        let rows =
            Vec::<Row<P, A>>::read_cfg(buf, &(RangeCfg::new(..=limits.rows), limits.receivers))?;
        let withdrawals =
            Vec::<Withdrawal<P, A>>::read_cfg(buf, &(RangeCfg::new(..=limits.withdrawals), ()))?;
        if !Self::is_canonical(&rows, &withdrawals) {
            return Err(CodecError::Invalid(
                "clearing::bajillion::Close",
                "rows and withdrawals must be strictly increasing",
            ));
        }
        Ok(Self {
            epoch,
            rows,
            withdrawals,
            deposits: u64::read(buf)?,
            forced_withdrawals: u64::read(buf)?,
            signature: O::Signature::read(buf)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<P: PublicKey, O: PublicKey, A: Amount> arbitrary::Arbitrary<'_> for Close<P, O, A>
where
    P: for<'a> arbitrary::Arbitrary<'a>,
    P::Signature: for<'a> arbitrary::Arbitrary<'a>,
    O::Signature: for<'a> arbitrary::Arbitrary<'a>,
    A: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let mut rows: Vec<Row<P, A>> = u.arbitrary()?;
        rows.sort_by(|a, b| a.account.cmp(&b.account));
        rows.dedup_by(|a, b| a.account == b.account);
        let mut withdrawals: Vec<Withdrawal<P, A>> = u.arbitrary()?;
        withdrawals.sort_by(|a, b| a.request().cmp(&b.request()));
        withdrawals.dedup_by(|a, b| a.request() == b.request());
        Ok(Self {
            epoch: u.arbitrary()?,
            rows,
            withdrawals,
            deposits: u.arbitrary()?,
            forced_withdrawals: u.arbitrary()?,
            signature: u.arbitrary()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{Decode as _, DecodeExt as _, Encode as _};
    use commonware_cryptography::ed25519::{PrivateKey, PublicKey, Signature};

    const NAMESPACE: &[u8] = b"_COMMONWARE_CLEARING_CLOSE_TEST";

    const LIMITS: Limits = Limits {
        rows: 4,
        receivers: 4,
        withdrawals: 4,
    };

    /// Returns `count` signers sorted by public key.
    fn signers(count: u64) -> Vec<PrivateKey> {
        let mut signers: Vec<_> = (0..count).map(PrivateKey::from_seed).collect();
        signers.sort_by_key(|signer| signer.public_key());
        signers
    }

    fn row(signer: &PrivateKey, receiver: &PrivateKey) -> Row<PublicKey, u64> {
        Row {
            account: signer.public_key(),
            payments: Amounts::new([(receiver.public_key(), 1)]).unwrap(),
            signature: signer.sign(b"row", b"row"),
        }
    }

    fn encode(rows: &[Row<PublicKey, u64>], withdrawals: &[Withdrawal<PublicKey, u64>]) -> Vec<u8> {
        let mut encoded = Vec::new();
        1u64.write(&mut encoded);
        rows.write(&mut encoded);
        withdrawals.write(&mut encoded);
        0u64.write(&mut encoded);
        0u64.write(&mut encoded);
        PrivateKey::from_seed(9)
            .sign(b"close", b"close")
            .write(&mut encoded);
        encoded
    }

    #[test]
    fn test_withdrawal_signature() {
        let namespace = Namespace::new(NAMESPACE);
        let signer = PrivateKey::from_seed(0);
        let withdrawal = Withdrawal::<_, u64>::sign(&signer, &namespace, 3, 10, 7);
        assert_eq!(withdrawal.account, signer.public_key());
        assert!(withdrawal.verify(&namespace));
        assert!(!withdrawal.verify(&Namespace::new(b"other")));

        // Every signed field is bound by the signature.
        for tampered in [
            Withdrawal {
                epoch: 4,
                ..withdrawal.clone()
            },
            Withdrawal {
                amount: 11,
                ..withdrawal.clone()
            },
            Withdrawal {
                tag: 8,
                ..withdrawal.clone()
            },
            Withdrawal {
                account: PrivateKey::from_seed(1).public_key(),
                ..withdrawal
            },
        ] {
            assert!(!tampered.verify(&namespace));
        }

        // A zero amount never verifies.
        assert!(!Withdrawal::<_, u64>::sign(&signer, &namespace, 3, 0, 7).verify(&namespace));
    }

    #[test]
    fn test_decode_rejects_non_canonical_close() {
        let namespace = Namespace::new(NAMESPACE);
        let signers = signers(3);
        let rows = [row(&signers[0], &signers[2]), row(&signers[1], &signers[2])];
        let withdrawal = Withdrawal::sign(&signers[0], &namespace, 1, 5, 0);

        let canonical = encode(&rows, std::slice::from_ref(&withdrawal));
        let close =
            Close::<PublicKey, PublicKey, u64>::decode_cfg(canonical.clone(), &LIMITS).unwrap();
        assert_eq!(close.rows(), &rows);
        assert_eq!(close.encode().as_ref(), canonical);

        // Rows must be strictly increasing by account.
        let reversed = [rows[1].clone(), rows[0].clone()];
        let repeated = [rows[0].clone(), rows[0].clone()];
        for rows in [&reversed[..], &repeated[..]] {
            assert!(
                Close::<PublicKey, PublicKey, u64>::decode_cfg(encode(rows, &[]), &LIMITS).is_err()
            );
        }

        // A row must pay someone.
        let empty = Row {
            payments: Amounts::empty(),
            ..rows[0].clone()
        };
        assert!(
            Close::<PublicKey, PublicKey, u64>::decode_cfg(encode(&[empty], &[]), &LIMITS).is_err()
        );

        // The same request cannot appear twice, even under different signatures.
        let resigned = Withdrawal {
            signature: Signature::decode(signers[1].sign(b"other", b"other").encode()).unwrap(),
            ..withdrawal.clone()
        };
        assert!(
            Close::<PublicKey, PublicKey, u64>::decode_cfg(
                encode(&rows, &[withdrawal, resigned]),
                &LIMITS
            )
            .is_err()
        );

        // Sizes are bounded.
        let limits = Limits { rows: 1, ..LIMITS };
        assert!(Close::<PublicKey, PublicKey, u64>::decode_cfg(canonical, &limits).is_err());
    }

    #[test]
    fn test_queue_prefix() {
        let signers = signers(1);
        let account = signers[0].public_key();
        let queue: Queue<_, u64> = Queue {
            epoch: 1,
            deposits: vec![
                Deposit {
                    account: account.clone(),
                    amount: 1,
                },
                Deposit {
                    account: account.clone(),
                    amount: 2,
                },
            ],
            required_deposits: 1,
            forced_withdrawals: vec![ForcedWithdrawal { account, amount: 3 }],
            required_forced_withdrawals: 0,
        };
        let (deposits, forced) = queue.prefix(1, 0).unwrap();
        assert_eq!((deposits.len(), forced.len()), (1, 0));
        let (deposits, forced) = queue.prefix(2, 1).unwrap();
        assert_eq!((deposits.len(), forced.len()), (2, 1));
        for (deposits, forced) in [(0, 0), (3, 0), (1, 2)] {
            assert!(matches!(
                queue.prefix(deposits, forced),
                Err(Error::InvalidCount)
            ));
        }
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Withdrawal<PublicKey, u64>>,
            CodecConformance<Row<PublicKey, u64>>,
            CodecConformance<Close<PublicKey, PublicKey, u64>>,
        }
    }
}
