//! Payment states, requests, acknowledgements, receipts, and challenges.

use super::{Amount, Amounts, Epoch, Error, Namespace, Opening, amounts::leaf};
use bytes::BufMut;
use commonware_codec::{
    Buf, Encode, EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt, Write,
};
use commonware_cryptography::{Digest, Hasher, PublicKey, Signer};
use commonware_storage::bmt::Proof;

/// A sender's commitment to its payment map in one epoch.
///
/// The sender signs it to authorize the debit, the operator countersigns it to preconfirm the
/// payments, and a close settles it only on top of the sender's row in the close before.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct State<P: PublicKey, D: Digest> {
    /// Epoch of the payments.
    pub epoch: Epoch,
    /// Account paying.
    pub account: P,
    /// Root of the sender's payment map in `epoch`.
    pub payments: D,
    /// Root of the sender's payment map in the previous epoch.
    pub previous: D,
}

impl<P: PublicKey, D: Digest> State<P, D> {
    /// Signs the state as its sender.
    pub(crate) fn sign<S: Signer<PublicKey = P, Signature = P::Signature>>(
        &self,
        signer: &S,
        namespace: &Namespace,
    ) -> P::Signature {
        signer.sign(&namespace.state, &self.encode())
    }

    /// Returns whether `signature` is the sender's signature over the state.
    pub(crate) fn verify(&self, namespace: &Namespace, signature: &P::Signature) -> bool {
        self.account
            .verify(&namespace.state, &self.encode(), signature)
    }

    /// Countersigns the state as the operator.
    pub fn acknowledge<S: Signer>(&self, signer: &S, namespace: &Namespace) -> S::Signature {
        signer.sign(&namespace.acknowledgement, &self.encode())
    }

    /// Returns whether `signature` is `operator`'s countersignature over the state.
    pub fn verify_acknowledgement<O: PublicKey>(
        &self,
        namespace: &Namespace,
        operator: &O,
        signature: &O::Signature,
    ) -> bool {
        operator.verify(&namespace.acknowledgement, &self.encode(), signature)
    }
}

impl<P: PublicKey, D: Digest> Write for State<P, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch.write(buf);
        self.account.write(buf);
        self.payments.write(buf);
        self.previous.write(buf);
    }
}

impl<P: PublicKey, D: Digest> FixedSize for State<P, D> {
    const SIZE: usize = Epoch::SIZE + P::SIZE + 2 * D::SIZE;
}

impl<P: PublicKey, D: Digest> Read for State<P, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            epoch: Epoch::read(buf)?,
            account: P::read(buf)?,
            payments: D::read(buf)?,
            previous: D::read(buf)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<P: PublicKey, D: Digest> arbitrary::Arbitrary<'_> for State<P, D>
where
    P: for<'a> arbitrary::Arbitrary<'a>,
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            epoch: u.arbitrary()?,
            account: u.arbitrary()?,
            payments: u.arbitrary()?,
            previous: u.arbitrary()?,
        })
    }
}

/// Returns `payments` with `batch` added, and the root of the result.
///
/// Senders derive their states and operators admit them through this one function, so both compute
/// the same map.
fn extend<H: Hasher, P: PublicKey, A: Amount>(
    payments: &Amounts<P, A>,
    batch: &Amounts<P, A>,
) -> Result<(Amounts<P, A>, H::Digest), Error> {
    let extended = payments.combine(batch)?;
    let root = extended.root::<H>();
    Ok((extended, root))
}

/// A sender's request to pay a batch of receivers.
///
/// It carries the roots its states claim, so the sender's signature verifies from the request
/// alone, and [Verified::admit] then checks those roots against the operator's record. Each
/// signature covers one state, and each state builds on the sender's row in the close before its
/// epoch.
///
/// ```text
///                     close(epoch - 1)     close(epoch)     close(epoch + 1)  signed by
///
///   state(epoch)          previous <-------- payments                         signature
///   state(epoch + 1)                        pipelined.0 <----- root(batch)    pipelined.1
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request<P: PublicKey, D: Digest, A: Amount> {
    /// Account paying.
    pub account: P,
    /// Epoch the request is for.
    pub epoch: Epoch,
    /// Amount paid to each receiver.
    pub batch: Amounts<P, A>,
    /// Root of the sender's payment map in `epoch` with the batch added.
    pub payments: D,
    /// Root of the sender's payment map in the epoch before `epoch`.
    pub previous: D,
    /// Sender's signature over its state in `epoch`.
    pub signature: P::Signature,
    /// For a pipelined request, the root of the sender's payment map in `epoch` without the batch,
    /// and the sender's signature over its state in the next epoch. That state pays only the batch
    /// on top of that root.
    pub pipelined: Option<(D, P::Signature)>,
}

impl<P: PublicKey, D: Digest, A: Amount> Request<P, D, A> {
    /// Derives the states of `account`'s request to pay `batch` in `epoch`, where `payments` is its
    /// latest countersigned map of `epoch`. The state of `epoch` adds `batch` to `payments` on top
    /// of `previous`. If `pipelined`, the state of the next epoch pays only `batch` on top of
    /// `payments`. Signs nothing and reads nothing.
    ///
    /// Returns NoReceivers if `batch` is empty, and Overflow if the next epoch or an amount
    /// overflows.
    pub fn states<H: Hasher<Digest = D>>(
        account: P,
        epoch: Epoch,
        batch: Amounts<P, A>,
        payments: &Amounts<P, A>,
        previous: &D,
        pipelined: bool,
    ) -> Result<States<P, D, A>, Error> {
        if batch.is_empty() {
            return Err(Error::NoReceivers);
        }
        let pipelined = if pipelined {
            Some(State {
                epoch: epoch.checked_add(1).ok_or(Error::Overflow)?,
                account: account.clone(),
                payments: batch.root::<H>(),
                previous: payments.root::<H>(),
            })
        } else {
            None
        };
        let (extended, root) = extend::<H, P, A>(payments, &batch)?;
        Ok(States {
            batch,
            state: State {
                epoch,
                account,
                payments: root,
                previous: *previous,
            },
            payments: extended,
            pipelined,
        })
    }

    /// Verifies the sender's signature over the state this request asks the operator to countersign
    /// in `epoch`. That is the request's state of its own epoch, or its pipelined state of the
    /// next. Reads no storage.
    ///
    /// Returns WrongEpoch if the request has no state for `epoch`, NoReceivers if the batch is
    /// empty, and InvalidSignature if the signature does not verify.
    pub fn verify<H: Hasher<Digest = D>>(
        &self,
        namespace: &Namespace,
        epoch: Epoch,
    ) -> Result<Verified<'_, P, D, A>, Error> {
        let pipelined = if epoch == self.epoch {
            None
        } else {
            match &self.pipelined {
                Some(pipelined) if self.epoch.checked_add(1) == Some(epoch) => Some(pipelined),
                _ => {
                    return Err(Error::WrongEpoch {
                        expected: epoch,
                        found: self.epoch,
                    });
                }
            }
        };
        if self.batch.is_empty() {
            return Err(Error::NoReceivers);
        }
        let (state, signature) = match pipelined {
            None => {
                let state = State {
                    epoch,
                    account: self.account.clone(),
                    payments: self.payments,
                    previous: self.previous,
                };
                (state, &self.signature)
            }
            Some((previous, signature)) => {
                let state = State {
                    epoch,
                    account: self.account.clone(),
                    payments: self.batch.root::<H>(),
                    previous: *previous,
                };
                (state, signature)
            }
        };
        if !state.verify(namespace, signature) {
            return Err(Error::InvalidSignature);
        }
        Ok(Verified {
            request: self,
            state,
            signature,
        })
    }
}

impl<P: PublicKey, D: Digest, A: Amount> Write for Request<P, D, A> {
    fn write(&self, buf: &mut impl BufMut) {
        self.account.write(buf);
        self.epoch.write(buf);
        self.batch.write(buf);
        self.payments.write(buf);
        self.previous.write(buf);
        self.signature.write(buf);
        self.pipelined.write(buf);
    }
}

impl<P: PublicKey, D: Digest, A: Amount> EncodeSize for Request<P, D, A> {
    fn encode_size(&self) -> usize {
        P::SIZE
            + Epoch::SIZE
            + self.batch.encode_size()
            + 2 * D::SIZE
            + P::Signature::SIZE
            + self.pipelined.encode_size()
    }
}

impl<P: PublicKey, D: Digest, A: Amount> Read for Request<P, D, A> {
    /// The maximum number of receivers in a batch.
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, receivers: &usize) -> Result<Self, CodecError> {
        Ok(Self {
            account: P::read(buf)?,
            epoch: Epoch::read(buf)?,
            batch: Amounts::read_cfg(buf, &RangeCfg::new(1..=*receivers))?,
            payments: D::read(buf)?,
            previous: D::read(buf)?,
            signature: P::Signature::read(buf)?,
            pipelined: Option::<(D, P::Signature)>::read_cfg(buf, &((), ()))?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<P: PublicKey, D: Digest, A: Amount> arbitrary::Arbitrary<'_> for Request<P, D, A>
where
    P: for<'a> arbitrary::Arbitrary<'a>,
    P::Signature: for<'a> arbitrary::Arbitrary<'a>,
    D: for<'a> arbitrary::Arbitrary<'a>,
    A: From<u64> + for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let receiver = u.arbitrary()?;
        let amount = super::amounts::arbitrary_nonzero(u)?;
        let batch = Amounts::<P, A>::arbitrary(u)?
            .combine(&Amounts::new([(receiver, amount)]).expect("amount must be nonzero"))
            .map_err(|_| arbitrary::Error::IncorrectFormat)?;
        Ok(Self {
            account: u.arbitrary()?,
            epoch: u.arbitrary()?,
            batch,
            payments: u.arbitrary()?,
            previous: u.arbitrary()?,
            signature: u.arbitrary()?,
            pipelined: u.arbitrary()?,
        })
    }
}

/// The states of one request, the batch it pays, and the payment map its state of the request's
/// epoch commits to.
///
/// [Request::states] derives them, and [States::sign] or [States::request] turns them into the
/// request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct States<P: PublicKey, D: Digest, A: Amount> {
    /// The batch the request pays.
    pub batch: Amounts<P, A>,
    /// The state for the request's epoch.
    pub state: State<P, D>,
    /// The payment map `state` commits to, the sender's map with the batch added.
    pub payments: Amounts<P, A>,
    /// For a pipelined request, the state for the next epoch. It commits to `batch` alone.
    pub pipelined: Option<State<P, D>>,
}

impl<P: PublicKey, D: Digest, A: Amount> States<P, D, A> {
    /// Returns the request carrying these states and their claimed roots, with `signature` over
    /// `self.state` and `pipelined` over the pipelined state. Each signature covers its state's
    /// encoding in [Namespace::state].
    ///
    /// # Panics
    ///
    /// Panics unless `pipelined` is present exactly when the states are pipelined.
    pub fn request(
        &self,
        signature: P::Signature,
        pipelined: Option<P::Signature>,
    ) -> Request<P, D, A> {
        assert_eq!(
            self.pipelined.is_some(),
            pipelined.is_some(),
            "a pipelined signature must be given exactly when the states are pipelined"
        );
        Request {
            account: self.state.account.clone(),
            epoch: self.state.epoch,
            batch: self.batch.clone(),
            payments: self.state.payments,
            previous: self.state.previous,
            signature,
            pipelined: self
                .pipelined
                .as_ref()
                .zip(pipelined)
                .map(|(state, signature)| (state.previous, signature)),
        }
    }

    /// Signs `self.state`, and the pipelined state if any, with `signer` in [Namespace::state], and
    /// returns the request as [States::request] does.
    pub fn sign<S>(&self, signer: &S, namespace: &Namespace) -> Request<P, D, A>
    where
        S: Signer<PublicKey = P, Signature = P::Signature>,
    {
        let pipelined = self
            .pipelined
            .as_ref()
            .map(|state| state.sign(signer, namespace));
        self.request(self.state.sign(signer, namespace), pipelined)
    }
}

/// A request whose state for one epoch carries a valid sender signature.
///
/// [Verified::admit] is the only way from it to an [Admission].
#[derive(Debug)]
pub struct Verified<'a, P: PublicKey, D: Digest, A: Amount> {
    request: &'a Request<P, D, A>,
    state: State<P, D>,
    signature: &'a P::Signature,
}

impl<P: PublicKey, D: Digest, A: Amount> Verified<'_, P, D, A> {
    /// Admits the verified state against the operator's record of its sender. `latest` is the
    /// sender's latest countersigned state in the state's epoch with its map, if any. `previous` is
    /// the root of the sender's row in the close of the epoch before, or the empty map's root.
    ///
    /// Returns Retry if the state is `latest`'s, and New if it pays `latest`'s map plus the batch
    /// on top of `previous`. Returns InvalidSignature otherwise, including for a batch that
    /// overflows the map.
    #[allow(clippy::type_complexity)]
    pub fn admit<H: Hasher<Digest = D>>(
        self,
        latest: Option<(&State<P, D>, &Amounts<P, A>)>,
        previous: &D,
    ) -> Result<Admission<P, D, A>, Error> {
        if latest.is_some_and(|(state, _)| *state == self.state) {
            return Ok(Admission::Retry(self.state));
        }
        if self.state.previous != *previous {
            return Err(Error::InvalidSignature);
        }
        let empty = Amounts::empty();
        let payments = latest.map_or(&empty, |(_, payments)| payments);
        let (extended, root) = extend::<H, P, A>(payments, &self.request.batch)
            .map_err(|_| Error::InvalidSignature)?;
        if root != self.state.payments {
            return Err(Error::InvalidSignature);
        }
        Ok(Admission::New {
            state: self.state,
            payments: extended,
            signature: self.signature.clone(),
        })
    }
}

/// What the operator may countersign for a verified request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Admission<P: PublicKey, D: Digest, A: Amount> {
    /// The request repeats the sender's latest countersigned state. Countersigning it again pays
    /// nothing twice.
    Retry(State<P, D>),
    /// A new state extending the sender's latest map by the batch. With the map it commits to and
    /// the sender's signature over it, it forms the sender's row in the close.
    New {
        /// The state to countersign.
        state: State<P, D>,
        /// The payment map `state` commits to.
        payments: Amounts<P, A>,
        /// The sender's signature over `state`.
        signature: P::Signature,
    },
}

/// A preconfirmation that `state`'s sender paid `receiver` a cumulative `amount` in the state's
/// epoch.
///
/// The close of that epoch must credit the receiver at least `amount` from the sender, or the
/// receiver can halt the ledger with a [Challenge].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt<P: PublicKey, O: PublicKey, D: Digest, A: Amount> {
    /// The sender's state.
    pub state: State<P, D>,
    /// The sender's signature over `state`.
    pub signature: P::Signature,
    /// The operator's countersignature over `state`.
    pub acknowledgement: O::Signature,
    /// Account paid.
    pub receiver: P,
    /// Cumulative amount paid to `receiver` in the state's payment map.
    pub amount: A,
    /// Position of `receiver` in the state's payment map.
    pub position: u32,
    /// Opening of `receiver`'s entry under the state's payment map root.
    pub proof: Proof<D>,
}

impl<P: PublicKey, O: PublicKey, D: Digest, A: Amount> Receipt<P, O, D, A> {
    /// Returns a receipt for each of `receivers` from `state`, the sender's `signature` over it,
    /// the operator's `acknowledgement` countersigning it, and `payments`, the map it commits to.
    /// The receipts verify exactly when both signatures do.
    ///
    /// Returns InvalidReceipt if `payments` does not commit to `state` or holds no amount for a
    /// receiver.
    pub fn issue<H: Hasher<Digest = D>>(
        state: &State<P, D>,
        signature: &P::Signature,
        acknowledgement: &O::Signature,
        payments: &Amounts<P, A>,
        receivers: impl IntoIterator<Item = P>,
    ) -> Result<Vec<Self>, Error> {
        let tree = payments.tree::<H>();
        if tree.root() != state.payments {
            return Err(Error::InvalidReceipt);
        }
        receivers
            .into_iter()
            .map(|receiver| {
                let position = payments.position(&receiver).ok_or(Error::InvalidReceipt)? as u32;
                Ok(Self {
                    state: state.clone(),
                    signature: signature.clone(),
                    acknowledgement: acknowledgement.clone(),
                    amount: payments.get(&receiver),
                    receiver,
                    position,
                    proof: tree
                        .proof(position)
                        .expect("a receiver in the payment map must have a proof"),
                })
            })
            .collect()
    }

    /// Verifies that both signatures cover the state and that its payment map holds the receipt's
    /// entry. Returns InvalidReceipt otherwise.
    pub fn verify<H: Hasher<Digest = D>>(
        &self,
        namespace: &Namespace,
        operator: &O,
    ) -> Result<(), Error> {
        if !self.state.verify(namespace, &self.signature)
            || !self
                .state
                .verify_acknowledgement(namespace, operator, &self.acknowledgement)
        {
            return Err(Error::InvalidReceipt);
        }
        self.proof
            .verify_element_inclusion::<H>(
                self.position,
                &leaf::<H, P, A>(&self.receiver, self.amount),
                &self.state.payments,
            )
            .map_err(|_| Error::InvalidReceipt)
    }
}

impl<P: PublicKey, O: PublicKey, D: Digest, A: Amount> Write for Receipt<P, O, D, A> {
    fn write(&self, buf: &mut impl BufMut) {
        self.state.write(buf);
        self.signature.write(buf);
        self.acknowledgement.write(buf);
        self.receiver.write(buf);
        self.amount.write(buf);
        self.position.write(buf);
        self.proof.write(buf);
    }
}

impl<P: PublicKey, O: PublicKey, D: Digest, A: Amount> EncodeSize for Receipt<P, O, D, A> {
    fn encode_size(&self) -> usize {
        State::<P, D>::SIZE
            + P::Signature::SIZE
            + O::Signature::SIZE
            + P::SIZE
            + A::SIZE
            + u32::SIZE
            + self.proof.encode_size()
    }
}

impl<P: PublicKey, O: PublicKey, D: Digest, A: Amount> Read for Receipt<P, O, D, A> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            state: State::read(buf)?,
            signature: P::Signature::read(buf)?,
            acknowledgement: O::Signature::read(buf)?,
            receiver: P::read(buf)?,
            amount: A::read(buf)?,
            position: u32::read(buf)?,
            proof: Proof::read_cfg(buf, &1)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<P: PublicKey, O: PublicKey, D: Digest, A: Amount> arbitrary::Arbitrary<'_>
    for Receipt<P, O, D, A>
where
    P: for<'a> arbitrary::Arbitrary<'a>,
    P::Signature: for<'a> arbitrary::Arbitrary<'a>,
    O::Signature: for<'a> arbitrary::Arbitrary<'a>,
    D: for<'a> arbitrary::Arbitrary<'a>,
    A: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let siblings = u.int_in_range(0..=4)?;
        Ok(Self {
            state: u.arbitrary()?,
            signature: u.arbitrary()?,
            acknowledgement: u.arbitrary()?,
            receiver: u.arbitrary()?,
            amount: u.arbitrary()?,
            position: u.arbitrary()?,
            proof: Proof {
                leaf_count: u.arbitrary()?,
                siblings: (0..siblings)
                    .map(|_| u.arbitrary())
                    .collect::<arbitrary::Result<_>>()?,
            },
        })
    }
}

/// Evidence that a posted close credits a receiver less than a receipt promised.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge<P: PublicKey, O: PublicKey, D: Digest, A: Amount> {
    /// The receipt the close contradicts.
    pub receipt: Receipt<P, O, D, A>,
    /// Opening of the receipt's entry in the matrix of the posted close of its epoch.
    pub opening: Opening<P, D, A>,
}

impl<P: PublicKey, O: PublicKey, D: Digest, A: Amount> Challenge<P, O, D, A> {
    /// Checks that the posted close of `epoch` with payment matrix root `matrix` credits the
    /// receipt's receiver less from its sender than the receipt promises.
    ///
    /// Returns WrongEpoch unless the receipt is for `epoch`, InvalidOpening unless the opening
    /// verifies, NoContradiction unless the close credits less, and InvalidReceipt unless the
    /// receipt verifies. The receipt's signatures are checked last.
    pub fn verify<H: Hasher<Digest = D>>(
        &self,
        namespace: &Namespace,
        operator: &O,
        epoch: Epoch,
        matrix: &D,
    ) -> Result<(), Error> {
        let receipt = &self.receipt;
        if receipt.state.epoch != epoch {
            return Err(Error::WrongEpoch {
                expected: epoch,
                found: receipt.state.epoch,
            });
        }
        let credited =
            self.opening
                .verify::<H>(matrix, &receipt.state.account, &receipt.receiver)?;
        if credited >= receipt.amount {
            return Err(Error::NoContradiction);
        }
        receipt.verify::<H>(namespace, operator)
    }
}

impl<P: PublicKey, O: PublicKey, D: Digest, A: Amount> Write for Challenge<P, O, D, A> {
    fn write(&self, buf: &mut impl BufMut) {
        self.receipt.write(buf);
        self.opening.write(buf);
    }
}

impl<P: PublicKey, O: PublicKey, D: Digest, A: Amount> EncodeSize for Challenge<P, O, D, A> {
    fn encode_size(&self) -> usize {
        self.receipt.encode_size() + self.opening.encode_size()
    }
}

impl<P: PublicKey, O: PublicKey, D: Digest, A: Amount> Read for Challenge<P, O, D, A> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            receipt: Receipt::read(buf)?,
            opening: Opening::read(buf)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<P: PublicKey, O: PublicKey, D: Digest, A: Amount> arbitrary::Arbitrary<'_>
    for Challenge<P, O, D, A>
where
    P: for<'a> arbitrary::Arbitrary<'a>,
    P::Signature: for<'a> arbitrary::Arbitrary<'a>,
    O::Signature: for<'a> arbitrary::Arbitrary<'a>,
    D: for<'a> arbitrary::Arbitrary<'a>,
    A: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            receipt: u.arbitrary()?,
            opening: u.arbitrary()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bajillion::{
        Matrix,
        tests::{account, amounts, empty_root, namespace, operator_key, user},
    };
    use commonware_codec::{Decode as _, DecodeExt as _};
    use commonware_cryptography::{
        Sha256,
        ed25519::{PrivateKey, PublicKey},
        sha256::Digest,
    };

    type TestRequest = Request<PublicKey, Digest, u64>;
    type TestStates = States<PublicKey, Digest, u64>;

    /// Returns the states alice signs to pay `batch` in epoch 2 on top of `previous`, where
    /// `payments` is her latest countersigned map of epoch 2.
    fn states(
        batch: &[(u64, u64)],
        payments: &Amounts<PublicKey, u64>,
        previous: Digest,
        pipelined: bool,
    ) -> TestStates {
        TestRequest::states::<Sha256>(
            account(0),
            2,
            amounts(batch),
            payments,
            &previous,
            pipelined,
        )
        .unwrap()
    }

    /// Returns a receipt from a payment map paying two receivers.
    fn receipt() -> (Receipt<PublicKey, PublicKey, Digest, u64>, PublicKey) {
        let namespace = namespace();
        let operator = operator_key();
        let states = states(&[(2, 4), (3, 5)], &Amounts::empty(), empty_root(), false);
        let receipt = Receipt::<_, PublicKey, _, _>::issue::<Sha256>(
            &states.state,
            &states.state.sign(&user(0), &namespace),
            &states.state.acknowledge(&operator, &namespace),
            &states.payments,
            [account(3)],
        )
        .unwrap()
        .pop()
        .unwrap();
        (receipt, operator.public_key())
    }

    /// A request signed from its states verifies in each epoch it has a state for, and the operator
    /// admits the state the sender derived, with or without earlier payments in the epoch.
    #[test]
    fn test_signed_states_are_admitted() {
        let namespace = namespace();
        let previous = amounts(&[(4, 1)]).root::<Sha256>();
        for payments in [Amounts::empty(), amounts(&[(1, 3), (2, 4)])] {
            for pipelined in [false, true] {
                let states = states(&[(1, 5), (3, 6)], &payments, previous, pipelined);
                let signed = states.sign(&user(0), &namespace);
                assert_eq!(states.payments, payments.combine(&states.batch).unwrap());
                assert_eq!(states.state.payments, states.payments.root::<Sha256>());

                // The request crosses the wire with its distinct claimed roots intact. Decoding
                // refuses a batch beyond the receiver limit and a truncated encoding.
                let encoded = signed.encode();
                let request = TestRequest::decode_cfg(encoded.clone(), &2).unwrap();
                assert_eq!(request, signed);
                assert_ne!(request.payments, request.previous);
                assert!(TestRequest::decode_cfg(encoded.clone(), &1).is_err());
                assert!(TestRequest::decode_cfg(encoded.slice(..encoded.len() - 1), &2).is_err());

                // In its own epoch, the request extends the sender's latest map.
                let latest = (!payments.is_empty()).then(|| {
                    let state = State {
                        epoch: 2,
                        account: account(0),
                        payments: payments.root::<Sha256>(),
                        previous,
                    };
                    (state, payments.clone())
                });
                let admission = request
                    .verify::<Sha256>(&namespace, 2)
                    .unwrap()
                    .admit::<Sha256>(latest.as_ref().map(|(s, p)| (s, p)), &previous)
                    .unwrap();
                assert_eq!(
                    admission,
                    Admission::New {
                        state: states.state.clone(),
                        payments: states.payments.clone(),
                        signature: request.signature.clone(),
                    }
                );

                // A retry of the countersigned state is admitted as one, whatever its batch.
                let mut retried = request.clone();
                retried.batch = amounts(&[(7, 1)]);
                let admission = retried
                    .verify::<Sha256>(&namespace, 2)
                    .unwrap()
                    .admit::<Sha256>(Some((&states.state, &states.payments)), &previous)
                    .unwrap();
                assert_eq!(admission, Admission::Retry(states.state.clone()));

                // In the next epoch, a pipelined request pays only its batch on top of the map
                // the close of its epoch settles. The admission carries the signature over the
                // pipelined state, the one the sender's row in the next close needs.
                let next = request.verify::<Sha256>(&namespace, 3);
                let Some(state) = &states.pipelined else {
                    assert!(matches!(
                        next,
                        Err(Error::WrongEpoch {
                            expected: 3,
                            found: 2
                        })
                    ));
                    continue;
                };
                assert_eq!(state.previous, payments.root::<Sha256>());
                let admission = next
                    .unwrap()
                    .admit::<Sha256>(None, &payments.root::<Sha256>())
                    .unwrap();
                let (_, signature) = request.pipelined.clone().unwrap();
                assert_ne!(signature, request.signature);
                assert_eq!(
                    admission,
                    Admission::New {
                        state: state.clone(),
                        payments: states.batch.clone(),
                        signature,
                    }
                );

                // If the close of its epoch settles the map with the batch added, the pipelined
                // state does not build on the sender's row, so it is never admitted.
                assert!(matches!(
                    request
                        .verify::<Sha256>(&namespace, 3)
                        .unwrap()
                        .admit::<Sha256>(None, &states.state.payments),
                    Err(Error::InvalidSignature)
                ));
            }
        }
    }

    /// A key outside the process signs each state's encoding in the state namespace, and the
    /// request filled from those signatures is the one an in-process signer produces.
    #[test]
    fn test_external_signatures_fill_the_same_request() {
        let namespace = namespace();
        let signer = user(0);
        for pipelined in [false, true] {
            let states = states(&[(1, 5)], &amounts(&[(2, 1)]), empty_root(), pipelined);
            let signature = signer.sign(&namespace.state, &states.state.encode());
            let next = states
                .pipelined
                .as_ref()
                .map(|state| signer.sign(&namespace.state, &state.encode()));
            assert_eq!(
                states.request(signature, next),
                states.sign(&signer, &namespace)
            );
        }
    }

    #[test]
    #[should_panic(expected = "a pipelined signature must be given exactly when")]
    fn test_request_needs_a_signature_per_state() {
        let states = states(&[(1, 5)], &Amounts::empty(), empty_root(), true);
        let signature = user(0).sign(&namespace().state, &states.state.encode());
        states.request(signature, None);
    }

    #[test]
    fn test_states_refuse_unpayable_batches() {
        assert!(matches!(
            TestRequest::states::<Sha256>(
                account(0),
                2,
                Amounts::empty(),
                &Amounts::empty(),
                &empty_root(),
                false
            ),
            Err(Error::NoReceivers)
        ));
        assert!(matches!(
            TestRequest::states::<Sha256>(
                account(0),
                Epoch::MAX,
                amounts(&[(1, 1)]),
                &Amounts::empty(),
                &empty_root(),
                true
            ),
            Err(Error::Overflow)
        ));
        assert!(matches!(
            TestRequest::states::<Sha256>(
                account(0),
                2,
                amounts(&[(1, 1)]),
                &amounts(&[(1, u64::MAX)]),
                &empty_root(),
                false
            ),
            Err(Error::Overflow)
        ));
    }

    /// A request is checked against its own signature before any record of its sender is needed.
    #[test]
    fn test_verify_refuses_requests_the_sender_did_not_sign() {
        let namespace = namespace();
        let states = states(&[(1, 5)], &Amounts::empty(), empty_root(), true);
        let request = states.sign(&user(0), &namespace);

        // The request has states for its epoch and the next only.
        for epoch in [1, 4] {
            assert!(matches!(
                request.verify::<Sha256>(&namespace, epoch),
                Err(Error::WrongEpoch { expected, found: 2 }) if expected == epoch
            ));
        }

        // A request paying no one is refused before its signature is checked.
        let empty = TestRequest {
            batch: Amounts::empty(),
            ..request.clone()
        };
        assert!(matches!(
            empty.verify::<Sha256>(&namespace, 2),
            Err(Error::NoReceivers)
        ));

        // The signatures cover the account, the claimed roots, the pipelined state's batch, and
        // the deployment.
        let other = amounts(&[(9, 9)]).root::<Sha256>();
        for (epoch, request) in [
            (
                2,
                TestRequest {
                    account: account(1),
                    ..request.clone()
                },
            ),
            (
                2,
                TestRequest {
                    payments: other,
                    ..request.clone()
                },
            ),
            (
                2,
                TestRequest {
                    previous: other,
                    ..request.clone()
                },
            ),
            (
                3,
                TestRequest {
                    batch: amounts(&[(1, 6)]),
                    ..request.clone()
                },
            ),
            (
                3,
                TestRequest {
                    pipelined: Some((other, request.pipelined.clone().unwrap().1)),
                    ..request.clone()
                },
            ),
        ] {
            assert!(matches!(
                request.verify::<Sha256>(&namespace, epoch),
                Err(Error::InvalidSignature)
            ));
        }
        for epoch in [2, 3] {
            assert!(matches!(
                request.verify::<Sha256>(&Namespace::new(b"other"), epoch),
                Err(Error::InvalidSignature)
            ));
        }
    }

    /// The operator admits only the state it would countersign itself.
    #[test]
    fn test_admit_refuses_states_off_the_record() {
        let namespace = namespace();
        let paid = amounts(&[(1, 3)]);
        let latest = State {
            epoch: 2,
            account: account(0),
            payments: paid.root::<Sha256>(),
            previous: empty_root(),
        };
        let admit =
            |states: &TestStates, latest: Option<(&State<_, _>, &Amounts<_, _>)>, previous| {
                states
                    .sign(&user(0), &namespace)
                    .verify::<Sha256>(&namespace, 2)
                    .unwrap()
                    .admit::<Sha256>(latest, &previous)
            };

        // A state built on another previous map, a state that does not extend the latest map, and
        // a batch that would overflow the latest map are all refused.
        let elsewhere = states(&[(1, 5)], &paid, amounts(&[(4, 1)]).root::<Sha256>(), false);
        let stale = states(&[(1, 5)], &Amounts::empty(), empty_root(), false);
        for (states, latest) in [
            (&elsewhere, Some((&latest, &paid))),
            (&stale, Some((&latest, &paid))),
        ] {
            assert!(matches!(
                admit(states, latest, empty_root()),
                Err(Error::InvalidSignature)
            ));
        }
        let full = amounts(&[(1, u64::MAX)]);
        let fresh = states(&[(1, 1)], &Amounts::empty(), empty_root(), false);
        let at_limit = State {
            payments: full.root::<Sha256>(),
            ..latest.clone()
        };
        assert!(matches!(
            admit(&fresh, Some((&at_limit, &full)), empty_root()),
            Err(Error::InvalidSignature)
        ));

        // The state extending the latest map is admitted.
        let next = states(&[(1, 5)], &paid, empty_root(), false);
        assert!(matches!(
            admit(&next, Some((&latest, &paid)), empty_root()),
            Ok(Admission::New { .. })
        ));
    }

    #[test]
    fn test_issued_receipts_verify() {
        let namespace = namespace();
        let (receipt, operator) = receipt();
        receipt.verify::<Sha256>(&namespace, &operator).unwrap();
        assert_eq!(receipt.amount, 5);
        assert_eq!(
            Receipt::<PublicKey, PublicKey, Digest, u64>::decode(receipt.encode()).unwrap(),
            receipt
        );
    }

    #[test]
    fn test_issue_refuses_maps_that_do_not_commit_to_the_state() {
        let namespace = namespace();
        let states = states(&[(2, 4), (3, 5)], &Amounts::empty(), empty_root(), false);
        let signature = states.state.sign(&user(0), &namespace);
        let acknowledgement = states.state.acknowledge(&operator_key(), &namespace);
        let issue = |payments: &Amounts<PublicKey, u64>, receiver| {
            Receipt::<_, PublicKey, _, _>::issue::<Sha256>(
                &states.state,
                &signature,
                &acknowledgement,
                payments,
                [account(receiver)],
            )
        };
        assert!(matches!(
            issue(&amounts(&[(2, 4)]), 2),
            Err(Error::InvalidReceipt)
        ));
        assert!(matches!(
            issue(&states.payments, 1),
            Err(Error::InvalidReceipt)
        ));
        assert_eq!(issue(&states.payments, 2).unwrap()[0].amount, 4);
    }

    #[test]
    fn test_receipt_rejects_tampering() {
        let namespace = namespace();
        let (receipt, operator) = receipt();
        let other = PrivateKey::from_seed(9).public_key();
        let mut state = receipt.state.clone();
        state.epoch += 1;
        let tampered = vec![
            Receipt {
                amount: receipt.amount + 1,
                ..receipt.clone()
            },
            Receipt {
                amount: 0,
                ..receipt.clone()
            },
            Receipt {
                receiver: other.clone(),
                ..receipt.clone()
            },
            Receipt {
                position: receipt.position ^ 1,
                ..receipt.clone()
            },
            Receipt {
                acknowledgement: receipt.signature.clone(),
                ..receipt.clone()
            },
            Receipt {
                state,
                ..receipt.clone()
            },
        ];
        for tampered in tampered {
            assert!(matches!(
                tampered.verify::<Sha256>(&namespace, &operator),
                Err(Error::InvalidReceipt)
            ));
        }
        assert!(matches!(
            receipt.verify::<Sha256>(&namespace, &other),
            Err(Error::InvalidReceipt)
        ));
        assert!(matches!(
            receipt.verify::<Sha256>(&Namespace::new(b"other"), &operator),
            Err(Error::InvalidReceipt)
        ));
    }

    #[test]
    fn test_receipt_needs_the_sender_signature() {
        // Everything but the sender's signature is valid.
        let namespace = namespace();
        let (mut receipt, operator) = receipt();
        receipt.signature = receipt.state.sign(&PrivateKey::from_seed(9), &namespace);
        assert!(receipt.state.verify_acknowledgement(
            &namespace,
            &operator,
            &receipt.acknowledgement
        ));
        assert!(matches!(
            receipt.verify::<Sha256>(&namespace, &operator),
            Err(Error::InvalidReceipt)
        ));
    }

    #[test]
    fn test_signatures_are_domain_separated() {
        // The operator's countersignature never verifies as the sender's signature, even when the
        // operator signs with the sender's key.
        let namespace = namespace();
        let (receipt, _) = receipt();
        let countersignature = receipt.state.acknowledge(&user(0), &namespace);
        assert!(!receipt.state.verify(&namespace, &countersignature));
        assert!(receipt.state.verify(&namespace, &receipt.signature));
    }

    /// A challenge is checked against the posted close of its own epoch, and every refusal before
    /// the receipt's signatures costs only hashes.
    #[test]
    fn test_challenge_checks_the_close_before_the_signatures() {
        let namespace = namespace();
        let (receipt, operator) = receipt();
        let sender = receipt.state.account.clone();
        let matrix_of = |payments: Amounts<PublicKey, u64>| {
            let root = payments.root::<Sha256>();
            Matrix::<_, Digest, _>::from_sorted::<Sha256>(vec![(sender.clone(), payments, root)])
        };
        let underpaying = matrix_of(amounts(&[(3, 4)]));
        let paying = matrix_of(amounts(&[(3, 5)]));
        let challenge = |receipt: &Receipt<_, _, _, _>, matrix: &Matrix<_, _, _>| Challenge {
            receipt: receipt.clone(),
            opening: matrix.open(&sender, &receipt.receiver),
        };

        // A receipt the close credits in part contradicts it.
        let valid = challenge(&receipt, &underpaying);
        valid
            .verify::<Sha256>(&namespace, &operator, 2, &underpaying.root())
            .unwrap();

        // Another epoch's close is never the receipt's.
        assert!(matches!(
            valid.verify::<Sha256>(&namespace, &operator, 3, &underpaying.root()),
            Err(Error::WrongEpoch {
                expected: 3,
                found: 2
            })
        ));

        // A receipt whose signatures do not verify is refused only once its opening verifies and
        // the close contradicts it.
        let mut forged = receipt;
        forged.signature = user(9).sign(b"forged", b"receipt");
        let mut misopened = challenge(&forged, &underpaying);
        misopened.opening = underpaying.open(&sender, &account(2));
        assert!(matches!(
            misopened.verify::<Sha256>(&namespace, &operator, 2, &underpaying.root()),
            Err(Error::InvalidOpening)
        ));
        assert!(matches!(
            challenge(&forged, &underpaying).verify::<Sha256>(
                &namespace,
                &operator,
                2,
                &paying.root()
            ),
            Err(Error::InvalidOpening)
        ));
        assert!(matches!(
            challenge(&forged, &paying).verify::<Sha256>(&namespace, &operator, 2, &paying.root()),
            Err(Error::NoContradiction)
        ));
        assert!(matches!(
            challenge(&forged, &underpaying).verify::<Sha256>(
                &namespace,
                &operator,
                2,
                &underpaying.root()
            ),
            Err(Error::InvalidReceipt)
        ));
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<State<PublicKey, Digest>>,
            CodecConformance<Request<PublicKey, Digest, u64>>,
            CodecConformance<Receipt<PublicKey, PublicKey, Digest, u64>>,
            CodecConformance<Challenge<PublicKey, PublicKey, Digest, u64>>,
        }
    }
}
