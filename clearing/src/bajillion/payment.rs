//! Payer-signed vector endpoints and operator acknowledgment countersignatures.
//!
//! A payer authorizes one batch by signing its epoch-local sequence number, lifetime cumulative
//! debit endpoint, and the root of its strictly recipient-sorted, epoch-cumulative per-recipient
//! vector. The operator accepts by countersigning the identical body. Per-edge evidence is the
//! dual-signed body plus one membership opening of the vector root at the credited recipient.

use crate::bajillion::{
    commitment::{self, VectorKind, VectorRoot},
    vector::OutEntry,
};
use ahash::RandomState;
use alloc::vec::Vec;
use bytes::{Buf, BufMut};
use commonware_codec::{
    Encode, EncodeSize, Error as CodecError, FixedSize, Read, ReadExt as _, Write,
};
use commonware_cryptography::{BatchVerifier, Digest, Hasher, PublicKey, Signer};
use commonware_parallel::Strategy;
use hashbrown::HashSet;
use rand_core::CryptoRng;
use thiserror::Error;

/// Signature namespace for payer-authorized vector endpoints.
pub const VECTOR_SEND_SIGNATURE_NAMESPACE: &[u8] = b"_COMMONWARE_CLEARING_VECTOR_SEND";
/// Signature namespace for operator acknowledgment countersignatures.
pub const VECTOR_ACK_SIGNATURE_NAMESPACE: &[u8] = b"_COMMONWARE_CLEARING_VECTOR_ACK";
/// Signature namespace for the operator's aggregable close countersignatures.
pub const VECTOR_ACK_AGGREGATE_NAMESPACE: &[u8] = b"_COMMONWARE_CLEARING_VECTOR_ACK_AGG";

/// Monotonically increasing clearing epoch number.
pub type Epoch = u64;
/// Payment or cumulative amount value.
pub type Amount = u64;
/// Monotone per-payer batch sequence number local to one epoch.
pub type Sequence = u64;

/// Authenticated context shared by every payment in one epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentContext<P: PublicKey, D: Digest> {
    anchor: D,
    epoch: Epoch,
    operator: P,
}

impl<P: PublicKey, D: Digest> PaymentContext<P, D> {
    /// Creates a payment context from its chain-recognized anchor and operator key.
    ///
    /// The anchor must uniquely identify one immutable, one-shot epoch registration. Linear
    /// settlement ancestry may bind the exact predecessor root later, but the anchor must never be
    /// reused after that ancestry is invalidated. The embedding must not release an
    /// operator-signed acknowledgment until settlement has registered this exact anchor.
    pub const fn new(anchor: D, epoch: Epoch, operator: P) -> Self {
        Self {
            anchor,
            epoch,
            operator,
        }
    }

    /// Returns the anchored epoch identifier.
    pub const fn anchor(&self) -> &D {
        &self.anchor
    }

    /// Returns the clearing epoch number.
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the operator key authorized to issue acknowledgments.
    pub const fn operator(&self) -> &P {
        &self.operator
    }
}

impl<P: PublicKey, D: Digest> Write for PaymentContext<P, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.anchor.write(buf);
        self.epoch.write(buf);
        self.operator.write(buf);
    }
}

impl<P: PublicKey, D: Digest> FixedSize for PaymentContext<P, D> {
    const SIZE: usize = D::SIZE + u64::SIZE + P::SIZE;
}

impl<P: PublicKey, D: Digest> Read for PaymentContext<P, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            anchor: D::read(buf)?,
            epoch: u64::read(buf)?,
            operator: P::read(buf)?,
        })
    }
}

/// Canonical payer-authorized vector endpoint.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct VectorSendBody<P: PublicKey, D: Digest> {
    anchor: D,
    epoch: Epoch,
    payer: P,
    seq: Sequence,
    cumulative_debit: Amount,
    send_root: VectorRoot<D>,
}

impl<P: PublicKey, D: Digest> VectorSendBody<P, D> {
    /// Constructs an endpoint body bound to one epoch context.
    pub const fn new(
        context: &PaymentContext<P, D>,
        payer: P,
        seq: Sequence,
        cumulative_debit: Amount,
        send_root: VectorRoot<D>,
    ) -> Self {
        Self {
            anchor: *context.anchor(),
            epoch: context.epoch(),
            payer,
            seq,
            cumulative_debit,
            send_root,
        }
    }

    /// Constructs an arbitrary raw body without checking protocol invariants.
    pub const fn from_raw_unchecked(
        anchor: D,
        epoch: Epoch,
        payer: P,
        seq: Sequence,
        cumulative_debit: Amount,
        send_root: VectorRoot<D>,
    ) -> Self {
        Self {
            anchor,
            epoch,
            payer,
            seq,
            cumulative_debit,
            send_root,
        }
    }

    /// Returns the anchored epoch identifier the body binds.
    pub const fn anchor(&self) -> &D {
        &self.anchor
    }

    /// Returns the clearing epoch number the body binds.
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the payer key.
    pub const fn payer(&self) -> &P {
        &self.payer
    }

    /// Returns the epoch-local batch sequence number.
    pub const fn seq(&self) -> Sequence {
        self.seq
    }

    /// Returns the payer's lifetime cumulative debit endpoint.
    pub const fn cumulative_debit(&self) -> Amount {
        self.cumulative_debit
    }

    /// Returns the committed per-recipient vector root.
    pub const fn send_root(&self) -> VectorRoot<D> {
        self.send_root
    }

    /// Requires the body to bind this exact anchor and epoch.
    pub(crate) fn validate_context(&self, context: &PaymentContext<P, D>) -> Result<(), AckError> {
        if self.anchor != *context.anchor() || self.epoch != context.epoch() {
            return Err(AckError::WrongContext);
        }
        Ok(())
    }
}

impl<P: PublicKey, D: Digest> Write for VectorSendBody<P, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.anchor.write(buf);
        self.epoch.write(buf);
        self.payer.write(buf);
        self.seq.write(buf);
        self.cumulative_debit.write(buf);
        self.send_root.write(buf);
    }
}

impl<P: PublicKey, D: Digest> FixedSize for VectorSendBody<P, D> {
    const SIZE: usize = D::SIZE + u64::SIZE + P::SIZE + u64::SIZE * 2 + VectorRoot::<D>::SIZE;
}

impl<P: PublicKey, D: Digest> Read for VectorSendBody<P, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            anchor: D::read(buf)?,
            epoch: u64::read(buf)?,
            payer: P::read(buf)?,
            seq: u64::read(buf)?,
            cumulative_debit: u64::read(buf)?,
            send_root: VectorRoot::read(buf)?,
        })
    }
}

/// Payer-signed vector endpoint carried by a close row.
///
/// The operator's acceptance reaches the close as one aggregable countersignature per proof
/// slice, so rows carry only the payer half. Receipts keep the dual-signed [VectorAck]: the
/// operator signs each accepted body twice, once for the receipt and once, under
/// [VECTOR_ACK_AGGREGATE_NAMESPACE], for the slice aggregate.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SendAuthorization<P: PublicKey, D: Digest> {
    body: VectorSendBody<P, D>,
    payer_signature: P::Signature,
}

impl<P: PublicKey, D: Digest> SendAuthorization<P, D> {
    /// Signs an endpoint body with an explicit payer authority.
    pub fn sign<S: Signer<PublicKey = P, Signature = P::Signature>>(
        body: VectorSendBody<P, D>,
        payer: &S,
    ) -> Self {
        let encoded = body.encode();
        Self {
            payer_signature: payer.sign(VECTOR_SEND_SIGNATURE_NAMESPACE, &encoded),
            body,
        }
    }

    /// Constructs a raw envelope without checking the signature.
    pub const fn from_raw_unchecked(
        body: VectorSendBody<P, D>,
        payer_signature: P::Signature,
    ) -> Self {
        Self {
            body,
            payer_signature,
        }
    }

    /// Returns the payer-signed body.
    pub const fn body(&self) -> &VectorSendBody<P, D> {
        &self.body
    }

    /// Returns the payer signature.
    pub const fn payer_signature(&self) -> &P::Signature {
        &self.payer_signature
    }

    /// Verifies intrinsic fields, epoch context, and the payer signature.
    pub fn verify(&self, context: &PaymentContext<P, D>) -> Result<(), AckError> {
        self.body.validate_context(context)?;
        let encoded = self.body.encode();
        if !self.body.payer.verify(
            VECTOR_SEND_SIGNATURE_NAMESPACE,
            &encoded,
            &self.payer_signature,
        ) {
            return Err(AckError::InvalidPayerSignature);
        }
        Ok(())
    }
}

impl<P: PublicKey, D: Digest> Write for SendAuthorization<P, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.body.write(buf);
        self.payer_signature.write(buf);
    }
}

impl<P: PublicKey, D: Digest> FixedSize for SendAuthorization<P, D> {
    const SIZE: usize = VectorSendBody::<P, D>::SIZE + P::Signature::SIZE;
}

impl<P: PublicKey, D: Digest> Read for SendAuthorization<P, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            body: VectorSendBody::read(buf)?,
            payer_signature: P::Signature::read(buf)?,
        })
    }
}

/// Dual-signed acceptance of one payer vector endpoint.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct VectorAck<P: PublicKey, D: Digest> {
    body: VectorSendBody<P, D>,
    payer_signature: P::Signature,
    operator_signature: P::Signature,
}

impl<P: PublicKey, D: Digest> VectorAck<P, D> {
    /// Signs and countersigns an endpoint body with explicit key authorities.
    ///
    /// This intentionally permits malformed bodies and keys different from the named parties,
    /// modeling everything faulty authorities can sign for challenge tests. Callers must verify
    /// the result before treating it as acceptance evidence.
    pub fn sign_by_authorities<S: Signer<PublicKey = P, Signature = P::Signature>>(
        body: VectorSendBody<P, D>,
        payer: &S,
        operator: &S,
    ) -> Self {
        let encoded = body.encode();
        Self {
            payer_signature: payer.sign(VECTOR_SEND_SIGNATURE_NAMESPACE, &encoded),
            operator_signature: operator.sign(VECTOR_ACK_SIGNATURE_NAMESPACE, &encoded),
            body,
        }
    }

    /// Constructs a raw envelope without checking signatures.
    pub const fn from_raw_unchecked(
        body: VectorSendBody<P, D>,
        payer_signature: P::Signature,
        operator_signature: P::Signature,
    ) -> Self {
        Self {
            body,
            payer_signature,
            operator_signature,
        }
    }

    /// Returns the dual-signed body.
    pub const fn body(&self) -> &VectorSendBody<P, D> {
        &self.body
    }

    /// Returns the payer signature.
    pub const fn payer_signature(&self) -> &P::Signature {
        &self.payer_signature
    }

    /// Returns the operator countersignature.
    pub const fn operator_signature(&self) -> &P::Signature {
        &self.operator_signature
    }

    /// Verifies intrinsic fields, epoch context, and both signatures.
    pub fn verify(&self, context: &PaymentContext<P, D>) -> Result<(), AckError> {
        self.body.validate_context(context)?;
        let encoded = self.body.encode();
        if !self.body.payer.verify(
            VECTOR_SEND_SIGNATURE_NAMESPACE,
            &encoded,
            &self.payer_signature,
        ) {
            return Err(AckError::InvalidPayerSignature);
        }
        if !context.operator().verify(
            VECTOR_ACK_SIGNATURE_NAMESPACE,
            &encoded,
            &self.operator_signature,
        ) {
            return Err(AckError::InvalidOperatorSignature);
        }
        Ok(())
    }
}

impl<P: PublicKey, D: Digest> Write for VectorAck<P, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.body.write(buf);
        self.payer_signature.write(buf);
        self.operator_signature.write(buf);
    }
}

impl<P: PublicKey, D: Digest> FixedSize for VectorAck<P, D> {
    const SIZE: usize = VectorSendBody::<P, D>::SIZE + P::Signature::SIZE * 2;
}

impl<P: PublicKey, D: Digest> Read for VectorAck<P, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            body: VectorSendBody::read(buf)?,
            payer_signature: P::Signature::read(buf)?,
            operator_signature: P::Signature::read(buf)?,
        })
    }
}

/// Transferable per-edge acceptance evidence.
///
/// The opening authenticates the credited recipient's cumulative entry under the dual-signed
/// vector root, so any holder can compare a retained entry against the close's public terminal
/// entry for the same edge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntryReceipt<P: PublicKey, D: Digest> {
    /// Dual-signed vector endpoint acknowledging the batch.
    pub ack: VectorAck<P, D>,
    /// Credited recipient named by the opened entry.
    pub recipient: P,
    /// Epoch-cumulative credit from this payer to the recipient after the batch.
    pub cumulative: Amount,
    /// Number of payments from this payer to the recipient this epoch after the batch.
    pub count: u64,
    /// Membership opening of the entry under the acknowledged vector root.
    pub opening: commitment::Opening<D>,
}

impl<P: PublicKey, D: Digest> EntryReceipt<P, D> {
    /// Verifies both signatures and the entry's membership under the acknowledged root.
    pub fn verify<H: Hasher<Digest = D>>(
        &self,
        context: &PaymentContext<P, D>,
    ) -> Result<(), AckError> {
        self.ack.verify(context)?;
        if self.cumulative == 0 || self.count == 0 || self.cumulative < self.count {
            return Err(AckError::InfeasibleEntry);
        }
        let entry = OutEntry {
            recipient: self.recipient.clone(),
            cumulative: self.cumulative,
            count: self.count,
        };
        self.opening
            .verify::<H>(
                VectorKind::OutEntry,
                &self.ack.body.send_root,
                entry.encode().as_ref(),
            )
            .map_err(|_| AckError::InvalidEntryOpening)
    }
}

impl<P: PublicKey, D: Digest> Write for EntryReceipt<P, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.ack.write(buf);
        self.recipient.write(buf);
        self.cumulative.write(buf);
        self.count.write(buf);
        self.opening.write(buf);
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for EntryReceipt<P, D> {
    fn encode_size(&self) -> usize {
        VectorAck::<P, D>::SIZE + P::SIZE + u64::SIZE * 2 + self.opening.encode_size()
    }
}

impl<P: PublicKey, D: Digest> Read for EntryReceipt<P, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            ack: VectorAck::read(buf)?,
            recipient: P::read(buf)?,
            cumulative: u64::read(buf)?,
            count: u64::read(buf)?,
            opening: commitment::Opening::read(buf)?,
        })
    }
}

/// Verifies every distinct acknowledgment's payer signature in one randomized aggregate batch.
///
/// Callers must validate ack structure separately and treat a `false` return as one or more
/// invalid signatures without attribution.
pub(crate) fn verify_ack_signatures<'a, P, D, B, R, I>(
    authorizations: I,
    capacity: usize,
    rng: &mut R,
    strategy: &impl Strategy,
) -> bool
where
    P: PublicKey + 'a,
    D: Digest + 'a,
    B: BatchVerifier<PublicKey = P>,
    R: CryptoRng,
    I: IntoIterator<Item = &'a SendAuthorization<P, D>>,
{
    let mut authorizations = authorizations.into_iter().peekable();
    if authorizations.peek().is_none() {
        return true;
    }

    // Randomized hashing bounds collision amplification from adversarial envelopes. The
    // operator's acceptance verifies separately through one aggregable countersignature per
    // proof slice.
    let hasher = RandomState::with_seeds(
        rng.next_u64(),
        rng.next_u64(),
        rng.next_u64(),
        rng.next_u64(),
    );
    let mut unique = HashSet::with_capacity_and_hasher(capacity, hasher);
    let mut distinct = Vec::<&SendAuthorization<P, D>>::with_capacity(capacity);
    for authorization in authorizations {
        if unique.insert(authorization) {
            distinct.push(authorization);
        }
    }
    drop(unique);

    let mut batch = B::new(distinct.len());
    let messages = strategy.map_collect_vec(distinct.iter().copied(), |authorization| {
        authorization.body.encode()
    });
    let mut queued = true;
    for (authorization, message) in distinct.into_iter().zip(messages) {
        queued &= B::add(
            &mut batch,
            VECTOR_SEND_SIGNATURE_NAMESPACE,
            &message,
            authorization.body.payer(),
            &authorization.payer_signature,
        );
    }
    queued && batch.verify(rng, strategy)
}

/// Acknowledgment construction or verification failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AckError {
    /// A body binds another anchor or epoch.
    #[error("acknowledgment binds another anchor or epoch")]
    WrongContext,
    /// The payer signature does not authenticate the endpoint body.
    #[error("payer signature is invalid")]
    InvalidPayerSignature,
    /// The operator countersignature does not authenticate the endpoint body.
    #[error("operator countersignature is invalid")]
    InvalidOperatorSignature,
    /// An entry's cumulative credit or count is not reachable by positive payments.
    #[error("entry endpoint has no positive-payment completion")]
    InfeasibleEntry,
    /// The entry opening does not authenticate under the acknowledged vector root.
    #[error("entry opening does not authenticate under the acknowledged root")]
    InvalidEntryOpening,
}

#[cfg(feature = "arbitrary")]
mod arbitrary_impls {
    use super::*;

    impl<'a, P, D> arbitrary::Arbitrary<'a> for PaymentContext<P, D>
    where
        P: PublicKey + arbitrary::Arbitrary<'a>,
        D: Digest + for<'b> arbitrary::Arbitrary<'b>,
    {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self {
                anchor: u.arbitrary()?,
                epoch: u.arbitrary()?,
                operator: u.arbitrary()?,
            })
        }
    }

    impl<'a, P, D> arbitrary::Arbitrary<'a> for VectorSendBody<P, D>
    where
        P: PublicKey + arbitrary::Arbitrary<'a>,
        D: Digest + for<'b> arbitrary::Arbitrary<'b>,
    {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self {
                anchor: u.arbitrary()?,
                epoch: u.arbitrary()?,
                payer: u.arbitrary()?,
                seq: u.arbitrary()?,
                cumulative_debit: u.arbitrary()?,
                send_root: u.arbitrary()?,
            })
        }
    }

    impl<'a, P, D> arbitrary::Arbitrary<'a> for SendAuthorization<P, D>
    where
        P: PublicKey + arbitrary::Arbitrary<'a>,
        P::Signature: arbitrary::Arbitrary<'a>,
        D: Digest + for<'b> arbitrary::Arbitrary<'b>,
    {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self {
                body: u.arbitrary()?,
                payer_signature: u.arbitrary()?,
            })
        }
    }

    impl<'a, P, D> arbitrary::Arbitrary<'a> for VectorAck<P, D>
    where
        P: PublicKey + arbitrary::Arbitrary<'a>,
        P::Signature: arbitrary::Arbitrary<'a>,
        D: Digest + for<'b> arbitrary::Arbitrary<'b>,
    {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self {
                body: u.arbitrary()?,
                payer_signature: u.arbitrary()?,
                operator_signature: u.arbitrary()?,
            })
        }
    }

    impl<'a, P, D> arbitrary::Arbitrary<'a> for EntryReceipt<P, D>
    where
        P: PublicKey + arbitrary::Arbitrary<'a>,
        P::Signature: arbitrary::Arbitrary<'a>,
        D: Digest + for<'b> arbitrary::Arbitrary<'b>,
        commitment::Opening<D>: arbitrary::Arbitrary<'a>,
    {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self {
                ack: u.arbitrary()?,
                recipient: u.arbitrary()?,
                cumulative: u.arbitrary()?,
                count: u.arbitrary()?,
                opening: u.arbitrary()?,
            })
        }
    }
}
