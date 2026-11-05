//! Payment states, requests, acknowledgements, receipts, and challenges.

use super::{Amounts, Epoch, Error, Namespace, Opening, amounts::leaf};
use bytes::BufMut;
use commonware_codec::{
    Buf, Encode, EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt, Write,
};
use commonware_cryptography::{Digest, Hasher, PublicKey, Signer};
use commonware_storage::bmt::Proof;

/// A sender's payment state in one epoch.
///
/// The sender signs a state to authorize being debited its payment map in that epoch, and the
/// operator countersigns the same state to preconfirm the payments in it. Committing to the map of
/// the previous epoch lets a close settle the state only on top of the map the previous close
/// settled for the sender.
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
    pub(crate) fn acknowledge<S: Signer>(&self, signer: &S, namespace: &Namespace) -> S::Signature {
        signer.sign(&namespace.acknowledgement, &self.encode())
    }

    /// Returns whether `signature` is `operator`'s countersignature over the state.
    pub(crate) fn verify_acknowledgement<O: PublicKey>(
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

/// A sender's request to pay a batch of receivers.
///
/// The operator recomputes the state the request settles from its own record of the sender's
/// payments, so the request carries only signatures over it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request<P: PublicKey> {
    /// Account paying.
    pub account: P,
    /// Epoch the request is for.
    pub epoch: Epoch,
    /// Amount paid to each receiver.
    pub batch: Amounts<P>,
    /// Sender's signature over its state in `epoch`.
    pub signature: P::Signature,
    /// Sender's signature over its state in the epoch after `epoch`, if the request is
    /// pipelined.
    pub pipelined: Option<P::Signature>,
}

impl<P: PublicKey> Write for Request<P> {
    fn write(&self, buf: &mut impl BufMut) {
        self.account.write(buf);
        self.epoch.write(buf);
        self.batch.write(buf);
        self.signature.write(buf);
        self.pipelined.write(buf);
    }
}

impl<P: PublicKey> EncodeSize for Request<P> {
    fn encode_size(&self) -> usize {
        self.account.encode_size()
            + self.epoch.encode_size()
            + self.batch.encode_size()
            + self.signature.encode_size()
            + self.pipelined.encode_size()
    }
}

impl<P: PublicKey> Read for Request<P> {
    /// The maximum number of receivers in a batch.
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, receivers: &usize) -> Result<Self, CodecError> {
        Ok(Self {
            account: P::read(buf)?,
            epoch: Epoch::read(buf)?,
            batch: Amounts::read_cfg(buf, &RangeCfg::new(1..=*receivers))?,
            signature: P::Signature::read(buf)?,
            pipelined: Option::<P::Signature>::read(buf)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<P: PublicKey> arbitrary::Arbitrary<'_> for Request<P>
where
    P: for<'a> arbitrary::Arbitrary<'a>,
    P::Signature: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let receiver = u.arbitrary()?;
        let amount = u.int_in_range(1..=u64::MAX)?;
        let batch = Amounts::<P>::arbitrary(u)?
            .combine(&Amounts::new([(receiver, amount)]).expect("amount must be nonzero"))
            .map_err(|_| arbitrary::Error::IncorrectFormat)?;
        Ok(Self {
            account: u.arbitrary()?,
            epoch: u.arbitrary()?,
            batch,
            signature: u.arbitrary()?,
            pipelined: u.arbitrary()?,
        })
    }
}

/// The operator's countersignature over the state a request settles in `epoch`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Acknowledgement<O: PublicKey> {
    /// Epoch of the countersigned state.
    pub epoch: Epoch,
    /// The operator's signature over the state.
    pub signature: O::Signature,
}

impl<O: PublicKey> Write for Acknowledgement<O> {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch.write(buf);
        self.signature.write(buf);
    }
}

impl<O: PublicKey> FixedSize for Acknowledgement<O> {
    const SIZE: usize = Epoch::SIZE + O::Signature::SIZE;
}

impl<O: PublicKey> Read for Acknowledgement<O> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            epoch: Epoch::read(buf)?,
            signature: O::Signature::read(buf)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<O: PublicKey> arbitrary::Arbitrary<'_> for Acknowledgement<O>
where
    O::Signature: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            epoch: u.arbitrary()?,
            signature: u.arbitrary()?,
        })
    }
}

/// A preconfirmation that `state`'s sender paid `receiver` a cumulative `amount` in the state's
/// epoch.
///
/// The close of that epoch must credit the receiver at least `amount` from the sender, or the
/// receiver can halt the ledger with a [Challenge].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt<P: PublicKey, O: PublicKey, D: Digest> {
    /// The sender's state.
    pub state: State<P, D>,
    /// The sender's signature over `state`.
    pub signature: P::Signature,
    /// The operator's countersignature over `state`.
    pub acknowledgement: O::Signature,
    /// Account paid.
    pub receiver: P,
    /// Cumulative amount paid to `receiver` in the state's payment map.
    pub amount: u64,
    /// Position of `receiver` in the state's payment map.
    pub position: u32,
    /// Opening of `receiver`'s entry under the state's payment map root.
    pub proof: Proof<D>,
}

impl<P: PublicKey, O: PublicKey, D: Digest> Receipt<P, O, D> {
    /// Verifies that both signatures cover the state and that its payment map holds the receipt's
    /// entry.
    pub fn verify<H: Hasher<Digest = D>>(
        &self,
        namespace: &Namespace,
        operator: &O,
    ) -> Result<(), Error> {
        if self.amount == 0
            || !self.state.verify(namespace, &self.signature)
            || !self
                .state
                .verify_acknowledgement(namespace, operator, &self.acknowledgement)
        {
            return Err(Error::InvalidReceipt);
        }
        self.proof
            .verify_element_inclusion::<H>(
                self.position,
                &leaf::<H, P>(&self.receiver, self.amount),
                &self.state.payments,
            )
            .map_err(|_| Error::InvalidReceipt)
    }
}

impl<P: PublicKey, O: PublicKey, D: Digest> Write for Receipt<P, O, D> {
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

impl<P: PublicKey, O: PublicKey, D: Digest> EncodeSize for Receipt<P, O, D> {
    fn encode_size(&self) -> usize {
        State::<P, D>::SIZE
            + P::Signature::SIZE
            + O::Signature::SIZE
            + P::SIZE
            + u64::SIZE
            + u32::SIZE
            + self.proof.encode_size()
    }
}

impl<P: PublicKey, O: PublicKey, D: Digest> Read for Receipt<P, O, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            state: State::read(buf)?,
            signature: P::Signature::read(buf)?,
            acknowledgement: O::Signature::read(buf)?,
            receiver: P::read(buf)?,
            amount: u64::read(buf)?,
            position: u32::read(buf)?,
            proof: Proof::read_cfg(buf, &1)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<P: PublicKey, O: PublicKey, D: Digest> arbitrary::Arbitrary<'_> for Receipt<P, O, D>
where
    P: for<'a> arbitrary::Arbitrary<'a>,
    P::Signature: for<'a> arbitrary::Arbitrary<'a>,
    O::Signature: for<'a> arbitrary::Arbitrary<'a>,
    D: for<'a> arbitrary::Arbitrary<'a>,
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
pub struct Challenge<P: PublicKey, O: PublicKey, D: Digest> {
    /// The receipt the close contradicts.
    pub receipt: Receipt<P, O, D>,
    /// Opening of the receipt's entry in the matrix of the posted close of its epoch.
    pub opening: Opening<P, D>,
}

impl<P: PublicKey, O: PublicKey, D: Digest> Write for Challenge<P, O, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.receipt.write(buf);
        self.opening.write(buf);
    }
}

impl<P: PublicKey, O: PublicKey, D: Digest> EncodeSize for Challenge<P, O, D> {
    fn encode_size(&self) -> usize {
        self.receipt.encode_size() + self.opening.encode_size()
    }
}

impl<P: PublicKey, O: PublicKey, D: Digest> Read for Challenge<P, O, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            receipt: Receipt::read(buf)?,
            opening: Opening::read(buf)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<P: PublicKey, O: PublicKey, D: Digest> arbitrary::Arbitrary<'_> for Challenge<P, O, D>
where
    P: for<'a> arbitrary::Arbitrary<'a>,
    P::Signature: for<'a> arbitrary::Arbitrary<'a>,
    O::Signature: for<'a> arbitrary::Arbitrary<'a>,
    D: for<'a> arbitrary::Arbitrary<'a>,
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
    use commonware_codec::DecodeExt as _;
    use commonware_cryptography::{
        Sha256,
        ed25519::{PrivateKey, PublicKey},
        sha256::Digest,
    };

    const NAMESPACE: &[u8] = b"_COMMONWARE_CLEARING_PAYMENT_TEST";

    /// Returns a receipt from a payment map paying two receivers.
    fn receipt() -> (Receipt<PublicKey, PublicKey, Digest>, PublicKey) {
        let namespace = Namespace::new(NAMESPACE);
        let sender = PrivateKey::from_seed(0);
        let operator = PrivateKey::from_seed(1);
        let receivers = [PrivateKey::from_seed(2), PrivateKey::from_seed(3)];
        let payments = Amounts::new(
            receivers
                .iter()
                .zip([4, 5])
                .map(|(receiver, amount)| (receiver.public_key(), amount)),
        )
        .unwrap();
        let state = State {
            epoch: 2,
            account: sender.public_key(),
            payments: payments.root::<Sha256>(),
            previous: Amounts::<PublicKey>::empty().root::<Sha256>(),
        };
        let receiver = receivers[1].public_key();
        let position = payments.position(&receiver).unwrap() as u32;
        let receipt = Receipt {
            signature: state.sign(&sender, &namespace),
            acknowledgement: state.acknowledge(&operator, &namespace),
            amount: payments.get(&receiver),
            receiver,
            position,
            proof: payments.tree::<Sha256>().proof(position).unwrap(),
            state,
        };
        (receipt, operator.public_key())
    }

    #[test]
    fn test_receipt_verifies() {
        let namespace = Namespace::new(NAMESPACE);
        let (receipt, operator) = receipt();
        receipt.verify::<Sha256>(&namespace, &operator).unwrap();
        assert_eq!(
            Receipt::<PublicKey, PublicKey, Digest>::decode(receipt.encode()).unwrap(),
            receipt
        );
    }

    #[test]
    fn test_receipt_rejects_tampering() {
        let namespace = Namespace::new(NAMESPACE);
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
        let namespace = Namespace::new(NAMESPACE);
        let (mut receipt, operator) = receipt();
        receipt.signature = receipt.state.sign(&PrivateKey::from_seed(9), &namespace);
        receipt
            .state
            .verify_acknowledgement(&namespace, &operator, &receipt.acknowledgement)
            .then_some(())
            .unwrap();
        assert!(matches!(
            receipt.verify::<Sha256>(&namespace, &operator),
            Err(Error::InvalidReceipt)
        ));
    }

    #[test]
    fn test_signatures_are_domain_separated() {
        // The operator's countersignature never verifies as the sender's signature, even when the
        // operator signs with the sender's key.
        let namespace = Namespace::new(NAMESPACE);
        let (receipt, _) = receipt();
        let sender = PrivateKey::from_seed(0);
        let countersignature = receipt.state.acknowledge(&sender, &namespace);
        assert!(!receipt.state.verify(&namespace, &countersignature));
        assert!(receipt.state.verify(&namespace, &receipt.signature));
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<State<PublicKey, Digest>>,
            CodecConformance<Request<PublicKey>>,
            CodecConformance<Acknowledgement<PublicKey>>,
            CodecConformance<Receipt<PublicKey, PublicKey, Digest>>,
            CodecConformance<Challenge<PublicKey, PublicKey, Digest>>,
        }
    }
}
