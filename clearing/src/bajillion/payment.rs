//! Payer-authorized debits and individually signed operator receipts.

use super::wire::{PublicKeyReader, ReadWithPublicKeys};
use bytes::{Buf, BufMut};
use commonware_codec::{Encode, Error as CodecError, FixedSize, Read, ReadExt as _, Write};
use commonware_cryptography::{Digest, Hasher, PublicKey, Signer};
use commonware_parallel::{Sequential, Strategy};
use thiserror::Error;

/// Signature namespace for payer-authorized sends.
pub const SEND_SIGNATURE_NAMESPACE: &[u8] = b"_COMMONWARE_CLEARING_PAYMENT_SEND";
/// Signature namespace for operator receipts.
pub const RECEIPT_SIGNATURE_NAMESPACE: &[u8] = b"_COMMONWARE_CLEARING_PAYMENT_RECEIPT";
/// Hash namespace for transaction identifiers.
pub const TX_ID_HASH_NAMESPACE: &[u8] = b"_COMMONWARE_CLEARING_PAYMENT_TX_ID";

/// Monotonically increasing clearing epoch number.
pub type Epoch = u64;
/// Receive-shard identifier local to a recipient and epoch.
pub type Shard = u64;
/// Cumulative amount value.
pub type Amount = u64;
/// Monotonically increasing receipt index local to a receive shard.
pub type ReceiptIndex = u64;

/// Authenticated context shared by every payment in one epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentContext<P: PublicKey, D: Digest> {
    anchor: D,
    epoch: Epoch,
    operator: P,
}

impl<P: PublicKey, D: Digest> PaymentContext<P, D> {
    /// Creates an epoch context from its chain-registered anchor and operator key.
    ///
    /// The anchor must uniquely identify the exact opening state, sealed deposit and withdrawal
    /// boundaries, validator committee, deadlines, deployment, and operator authorization for
    /// this epoch. Reusing an anchor across different registrations invalidates payment replay
    /// protection.
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

    /// Returns the operator key authorized to issue receipts.
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
        let mut public_keys = PublicKeyReader::new();
        Self::read_with_public_keys(buf, &mut public_keys)
    }
}

impl<P: PublicKey, D: Digest> ReadWithPublicKeys<P> for PaymentContext<P, D> {
    fn read_with_public_keys(
        buf: &mut impl Buf,
        public_keys: &mut PublicKeyReader<P>,
    ) -> Result<Self, CodecError> {
        Ok(Self {
            anchor: D::read(buf)?,
            epoch: u64::read(buf)?,
            operator: public_keys.read(buf)?,
        })
    }
}

/// Hash of the canonical unsigned send body.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct TxId<D: Digest>(D);

impl<D: Digest> TxId<D> {
    /// Wraps a digest as a transaction identifier.
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

impl<D: Digest> Write for TxId<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl<D: Digest> FixedSize for TxId<D> {
    const SIZE: usize = D::SIZE;
}

impl<D: Digest> Read for TxId<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self(D::read(buf)?))
    }
}

/// Canonical payer-authorized send payload.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SendBody<P: PublicKey, D: Digest> {
    anchor: D,
    epoch: Epoch,
    payer: P,
    recipient: P,
    amount: Amount,
    cumulative_debit: Amount,
}

impl<P: PublicKey, D: Digest> SendBody<P, D> {
    /// Creates the exact successor debit body from a prior cumulative debit.
    pub fn next(
        context: &PaymentContext<P, D>,
        payer: P,
        recipient: P,
        amount: Amount,
        previous_debit: Amount,
    ) -> Result<Self, PaymentError> {
        if amount == 0 {
            return Err(PaymentError::ZeroAmount);
        }
        let cumulative_debit = previous_debit
            .checked_add(amount)
            .ok_or(PaymentError::ArithmeticOverflow)?;
        Ok(Self {
            anchor: *context.anchor(),
            epoch: context.epoch(),
            payer,
            recipient,
            amount,
            cumulative_debit,
        })
    }

    /// Constructs an arbitrary raw body without checking protocol invariants.
    ///
    /// This constructor exists for decoding adversarial evidence and for tests that model a
    /// faulty signing authority. Applications should normally use [`Self::next`].
    #[allow(clippy::too_many_arguments)]
    pub const fn from_raw_unchecked(
        anchor: D,
        epoch: Epoch,
        payer: P,
        recipient: P,
        amount: Amount,
        cumulative_debit: Amount,
    ) -> Self {
        Self {
            anchor,
            epoch,
            payer,
            recipient,
            amount,
            cumulative_debit,
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

    /// Returns the payer key.
    pub const fn payer(&self) -> &P {
        &self.payer
    }

    /// Returns the recipient key.
    pub const fn recipient(&self) -> &P {
        &self.recipient
    }

    /// Returns the positive payment amount.
    pub const fn amount(&self) -> Amount {
        self.amount
    }

    /// Returns the payer's authorized cumulative debit endpoint.
    pub const fn cumulative_debit(&self) -> Amount {
        self.cumulative_debit
    }

    /// Derives the transaction identifier from this unsigned body.
    ///
    /// Signature bytes are deliberately excluded, so re-signing the same authorization cannot
    /// change receipt linkage or idempotency.
    pub fn tx_id<H: Hasher<Digest = D>>(&self) -> TxId<D> {
        let body = self.encode();
        TxId(H::hash(&[TX_ID_HASH_NAMESPACE, body.as_ref()]))
    }

    fn validate_context(&self, context: &PaymentContext<P, D>) -> Result<(), PaymentError> {
        if self.anchor != *context.anchor() || self.epoch != context.epoch() {
            return Err(PaymentError::WrongContext);
        }
        if self.amount == 0 {
            return Err(PaymentError::ZeroAmount);
        }
        if self.cumulative_debit < self.amount {
            return Err(PaymentError::MalformedDebitEndpoint);
        }
        Ok(())
    }

    fn validate_next(&self, previous_debit: Amount) -> Result<(), PaymentError> {
        let expected = previous_debit
            .checked_add(self.amount)
            .ok_or(PaymentError::ArithmeticOverflow)?;
        if self.cumulative_debit != expected {
            return Err(PaymentError::NonConsecutiveDebit);
        }
        Ok(())
    }
}

impl<P: PublicKey, D: Digest> Write for SendBody<P, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.anchor.write(buf);
        self.epoch.write(buf);
        self.payer.write(buf);
        self.recipient.write(buf);
        self.amount.write(buf);
        self.cumulative_debit.write(buf);
    }
}

impl<P: PublicKey, D: Digest> FixedSize for SendBody<P, D> {
    const SIZE: usize = D::SIZE + u64::SIZE + P::SIZE * 2 + u64::SIZE * 2;
}

impl<P: PublicKey, D: Digest> Read for SendBody<P, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        let mut public_keys = PublicKeyReader::new();
        Self::read_with_public_keys(buf, &mut public_keys)
    }
}

impl<P: PublicKey, D: Digest> ReadWithPublicKeys<P> for SendBody<P, D> {
    fn read_with_public_keys(
        buf: &mut impl Buf,
        public_keys: &mut PublicKeyReader<P>,
    ) -> Result<Self, CodecError> {
        Ok(Self {
            anchor: D::read(buf)?,
            epoch: u64::read(buf)?,
            payer: public_keys.read(buf)?,
            recipient: public_keys.read(buf)?,
            amount: u64::read(buf)?,
            cumulative_debit: u64::read(buf)?,
        })
    }
}

/// A payer signature over one exact cumulative debit endpoint.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SignedSend<P: PublicKey, D: Digest> {
    body: SendBody<P, D>,
    payer_signature: P::Signature,
}

impl<P: PublicKey, D: Digest> SignedSend<P, D> {
    /// Signs the exact successor of `previous_debit`.
    pub fn sign_next<S: Signer<PublicKey = P, Signature = P::Signature>>(
        context: &PaymentContext<P, D>,
        payer: &S,
        recipient: P,
        amount: Amount,
        previous_debit: Amount,
    ) -> Result<Self, PaymentError> {
        let body = SendBody::next(
            context,
            payer.public_key(),
            recipient,
            amount,
            previous_debit,
        )?;
        Ok(Self::sign_body_by_authority(body, payer))
    }

    /// Signs an explicit body with the supplied key authority.
    ///
    /// This intentionally permits malformed fields and a payer field different from the signer.
    /// It models everything a faulty key holder can sign for bounded challenge tests. Callers must
    /// use [`Self::verify`] or [`Self::verify_next`] before treating the result as a valid send.
    pub fn sign_body_by_authority<S: Signer<PublicKey = P, Signature = P::Signature>>(
        body: SendBody<P, D>,
        payer: &S,
    ) -> Self {
        let payer_signature = payer.sign(SEND_SIGNATURE_NAMESPACE, &body.encode());
        Self {
            body,
            payer_signature,
        }
    }

    /// Constructs a raw signed envelope without checking its signature or body.
    ///
    /// This is intended for adversarial decoding fixtures. Normal construction should use
    /// [`Self::sign_next`] or [`Self::sign_body_by_authority`].
    pub const fn from_raw_unchecked(body: SendBody<P, D>, payer_signature: P::Signature) -> Self {
        Self {
            body,
            payer_signature,
        }
    }

    /// Returns the signed body.
    pub const fn body(&self) -> &SendBody<P, D> {
        &self.body
    }

    /// Returns the payer signature.
    pub const fn signature(&self) -> &P::Signature {
        &self.payer_signature
    }

    /// Consumes the envelope into its raw parts.
    pub fn into_parts(self) -> (SendBody<P, D>, P::Signature) {
        (self.body, self.payer_signature)
    }

    /// Returns the transaction identifier derived from the unsigned body.
    pub fn tx_id<H: Hasher<Digest = D>>(&self) -> TxId<D> {
        self.body.tx_id::<H>()
    }

    /// Verifies intrinsic fields, epoch context, and the payer signature.
    pub fn verify(&self, context: &PaymentContext<P, D>) -> Result<(), PaymentError> {
        self.body.validate_context(context)?;
        if !self.body.payer.verify(
            SEND_SIGNATURE_NAMESPACE,
            &self.body.encode(),
            &self.payer_signature,
        ) {
            return Err(PaymentError::InvalidPayerSignature);
        }
        Ok(())
    }

    /// Verifies the send and proves it is the exact successor of `previous_debit`.
    pub fn verify_next(
        &self,
        context: &PaymentContext<P, D>,
        previous_debit: Amount,
    ) -> Result<(), PaymentError> {
        self.verify(context)?;
        self.body.validate_next(previous_debit)
    }
}

impl<P: PublicKey, D: Digest> Write for SignedSend<P, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.body.write(buf);
        self.payer_signature.write(buf);
    }
}

impl<P: PublicKey, D: Digest> FixedSize for SignedSend<P, D> {
    const SIZE: usize = SendBody::<P, D>::SIZE + P::Signature::SIZE;
}

impl<P: PublicKey, D: Digest> Read for SignedSend<P, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        let mut public_keys = PublicKeyReader::new();
        Self::read_with_public_keys(buf, &mut public_keys)
    }
}

impl<P: PublicKey, D: Digest> ReadWithPublicKeys<P> for SignedSend<P, D> {
    fn read_with_public_keys(
        buf: &mut impl Buf,
        public_keys: &mut PublicKeyReader<P>,
    ) -> Result<Self, CodecError> {
        Ok(Self {
            body: SendBody::read_with_public_keys(buf, public_keys)?,
            payer_signature: P::Signature::read(buf)?,
        })
    }
}

/// Canonical operator receipt payload.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ReceiptBody<P: PublicKey, D: Digest> {
    anchor: D,
    epoch: Epoch,
    recipient: P,
    shard: Shard,
    amount: Amount,
    tx_id: TxId<D>,
    cumulative_shard_credit: Amount,
    index: ReceiptIndex,
}

impl<P: PublicKey, D: Digest> ReceiptBody<P, D> {
    /// Constructs an arbitrary raw body without checking protocol invariants.
    ///
    /// This constructor models the body a faulty operator may sign. Applications should normally
    /// obtain receipt bodies through [`SignedReceipt::issue_next`].
    #[allow(clippy::too_many_arguments)]
    pub const fn from_raw_unchecked(
        anchor: D,
        epoch: Epoch,
        recipient: P,
        shard: Shard,
        amount: Amount,
        tx_id: TxId<D>,
        cumulative_shard_credit: Amount,
        index: ReceiptIndex,
    ) -> Self {
        Self {
            anchor,
            epoch,
            recipient,
            shard,
            amount,
            tx_id,
            cumulative_shard_credit,
            index,
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

    /// Returns the credited recipient.
    pub const fn recipient(&self) -> &P {
        &self.recipient
    }

    /// Returns the recipient-local receive shard.
    pub const fn shard(&self) -> Shard {
        self.shard
    }

    /// Returns the credited payment amount.
    pub const fn amount(&self) -> Amount {
        self.amount
    }

    /// Returns the linked transaction identifier.
    pub const fn tx_id(&self) -> &TxId<D> {
        &self.tx_id
    }

    /// Returns the cumulative credit endpoint for this shard.
    pub const fn cumulative_shard_credit(&self) -> Amount {
        self.cumulative_shard_credit
    }

    /// Returns the receipt index within this shard.
    pub const fn index(&self) -> ReceiptIndex {
        self.index
    }

    fn validate_context(&self, context: &PaymentContext<P, D>) -> Result<(), PaymentError> {
        if self.anchor != *context.anchor() || self.epoch != context.epoch() {
            return Err(PaymentError::WrongContext);
        }
        if self.amount == 0 {
            return Err(PaymentError::ZeroAmount);
        }
        Ok(())
    }
}

impl<P: PublicKey, D: Digest> Write for ReceiptBody<P, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.anchor.write(buf);
        self.epoch.write(buf);
        self.recipient.write(buf);
        self.shard.write(buf);
        self.amount.write(buf);
        self.tx_id.write(buf);
        self.cumulative_shard_credit.write(buf);
        self.index.write(buf);
    }
}

impl<P: PublicKey, D: Digest> FixedSize for ReceiptBody<P, D> {
    const SIZE: usize = D::SIZE * 2 + P::SIZE + u64::SIZE * 5;
}

impl<P: PublicKey, D: Digest> Read for ReceiptBody<P, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        let mut public_keys = PublicKeyReader::new();
        Self::read_with_public_keys(buf, &mut public_keys)
    }
}

impl<P: PublicKey, D: Digest> ReadWithPublicKeys<P> for ReceiptBody<P, D> {
    fn read_with_public_keys(
        buf: &mut impl Buf,
        public_keys: &mut PublicKeyReader<P>,
    ) -> Result<Self, CodecError> {
        Ok(Self {
            anchor: D::read(buf)?,
            epoch: u64::read(buf)?,
            recipient: public_keys.read(buf)?,
            shard: u64::read(buf)?,
            amount: u64::read(buf)?,
            tx_id: TxId::read(buf)?,
            cumulative_shard_credit: u64::read(buf)?,
            index: u64::read(buf)?,
        })
    }
}

/// An individually signed operator promise for one accepted payment.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SignedReceipt<P: PublicKey, D: Digest> {
    body: ReceiptBody<P, D>,
    operator_signature: P::Signature,
}

impl<P: PublicKey, D: Digest> SignedReceipt<P, D> {
    /// Issues the exact successor of a receive-shard endpoint.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_next<H: Hasher<Digest = D>, S: Signer<PublicKey = P, Signature = P::Signature>>(
        context: &PaymentContext<P, D>,
        send: &SignedSend<P, D>,
        shard: Shard,
        previous_credit: Amount,
        previous_index: ReceiptIndex,
        operator: &S,
    ) -> Result<Self, PaymentError> {
        if operator.public_key() != *context.operator() {
            return Err(PaymentError::WrongOperator);
        }
        send.verify(context)?;
        let cumulative_shard_credit = previous_credit
            .checked_add(send.body.amount)
            .ok_or(PaymentError::ArithmeticOverflow)?;
        let index = previous_index
            .checked_add(1)
            .ok_or(PaymentError::ArithmeticOverflow)?;
        let body = ReceiptBody {
            anchor: *context.anchor(),
            epoch: context.epoch(),
            recipient: send.body.recipient.clone(),
            shard,
            amount: send.body.amount,
            tx_id: send.tx_id::<H>(),
            cumulative_shard_credit,
            index,
        };
        Ok(Self::sign_body_by_authority(body, operator))
    }

    /// Signs an explicit receipt body with the supplied key authority.
    ///
    /// This intentionally permits malformed endpoints and a key different from the epoch
    /// operator. It models everything a faulty authority can sign for challenge tests. Callers
    /// must verify the resulting envelope before treating it as a receipt.
    pub fn sign_body_by_authority<S: Signer<PublicKey = P, Signature = P::Signature>>(
        body: ReceiptBody<P, D>,
        operator: &S,
    ) -> Self {
        let operator_signature = operator.sign(RECEIPT_SIGNATURE_NAMESPACE, &body.encode());
        Self {
            body,
            operator_signature,
        }
    }

    /// Constructs a raw receipt envelope without checking its signature or body.
    ///
    /// This is intended for adversarial decoding fixtures. Normal construction should use
    /// [`Self::issue_next`] or [`Self::sign_body_by_authority`].
    pub const fn from_raw_unchecked(
        body: ReceiptBody<P, D>,
        operator_signature: P::Signature,
    ) -> Self {
        Self {
            body,
            operator_signature,
        }
    }

    /// Returns the signed receipt body.
    pub const fn body(&self) -> &ReceiptBody<P, D> {
        &self.body
    }

    /// Returns the operator signature.
    pub const fn signature(&self) -> &P::Signature {
        &self.operator_signature
    }

    /// Consumes the receipt into its raw parts.
    pub fn into_parts(self) -> (ReceiptBody<P, D>, P::Signature) {
        (self.body, self.operator_signature)
    }

    /// Verifies intrinsic fields, epoch context, and the registered operator signature.
    pub fn verify(&self, context: &PaymentContext<P, D>) -> Result<(), PaymentError> {
        self.body.validate_context(context)?;
        if !context.operator.verify(
            RECEIPT_SIGNATURE_NAMESPACE,
            &self.body.encode(),
            &self.operator_signature,
        ) {
            return Err(PaymentError::InvalidOperatorSignature);
        }
        Ok(())
    }
}

impl<P: PublicKey, D: Digest> Write for SignedReceipt<P, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.body.write(buf);
        self.operator_signature.write(buf);
    }
}

impl<P: PublicKey, D: Digest> FixedSize for SignedReceipt<P, D> {
    const SIZE: usize = ReceiptBody::<P, D>::SIZE + P::Signature::SIZE;
}

impl<P: PublicKey, D: Digest> Read for SignedReceipt<P, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        let mut public_keys = PublicKeyReader::new();
        Self::read_with_public_keys(buf, &mut public_keys)
    }
}

impl<P: PublicKey, D: Digest> ReadWithPublicKeys<P> for SignedReceipt<P, D> {
    fn read_with_public_keys(
        buf: &mut impl Buf,
        public_keys: &mut PublicKeyReader<P>,
    ) -> Result<Self, CodecError> {
        Ok(Self {
            body: ReceiptBody::read_with_public_keys(buf, public_keys)?,
            operator_signature: P::Signature::read(buf)?,
        })
    }
}

/// Transferable acceptance evidence containing both required signatures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Payment<P: PublicKey, D: Digest> {
    send: SignedSend<P, D>,
    receipt: SignedReceipt<P, D>,
}

impl<P: PublicKey, D: Digest> Payment<P, D> {
    /// Constructs and verifies linked payment evidence.
    pub fn new<H: Hasher<Digest = D>>(
        context: &PaymentContext<P, D>,
        send: SignedSend<P, D>,
        receipt: SignedReceipt<P, D>,
    ) -> Result<Self, PaymentError> {
        let payment = Self { send, receipt };
        payment.verify_linked::<H>(context)?;
        Ok(payment)
    }

    /// Constructs raw evidence without checking signatures or linkage.
    ///
    /// This constructor exists so challenge tests and decoders can represent adversarial evidence.
    /// Call [`Self::verify_linked`] or [`Self::verify_terminal`] before relying on the value.
    pub const fn from_parts_unchecked(
        send: SignedSend<P, D>,
        receipt: SignedReceipt<P, D>,
    ) -> Self {
        Self { send, receipt }
    }

    /// Returns the payer-signed send.
    pub const fn send(&self) -> &SignedSend<P, D> {
        &self.send
    }

    /// Returns the operator-signed receipt.
    pub const fn receipt(&self) -> &SignedReceipt<P, D> {
        &self.receipt
    }

    /// Returns the payer key.
    pub const fn payer(&self) -> &P {
        self.send.body.payer()
    }

    /// Returns the credited recipient.
    pub const fn recipient(&self) -> &P {
        self.send.body.recipient()
    }

    /// Returns the payment amount.
    pub const fn amount(&self) -> Amount {
        self.send.body.amount()
    }

    /// Consumes the evidence into its signed parts.
    pub fn into_parts(self) -> (SignedSend<P, D>, SignedReceipt<P, D>) {
        (self.send, self.receipt)
    }

    fn validate_linkage<H: Hasher<Digest = D>>(&self) -> Result<(), PaymentError> {
        if self.receipt.body.recipient != self.send.body.recipient
            || self.receipt.body.amount != self.send.body.amount
            || self.receipt.body.tx_id != self.send.tx_id::<H>()
        {
            return Err(PaymentError::ReceiptMismatch);
        }
        Ok(())
    }

    pub(crate) fn validate_terminal_structure<H: Hasher<Digest = D>>(
        &self,
        context: &PaymentContext<P, D>,
    ) -> Result<(), PaymentError> {
        self.send.body.validate_context(context)?;
        self.receipt.body.validate_context(context)?;
        self.validate_linkage::<H>()?;
        if !receipt_range_is_feasible(
            0,
            0,
            self.amount(),
            self.receipt.body.cumulative_shard_credit,
            self.receipt.body.index,
        ) {
            return Err(PaymentError::InfeasibleReceiptRange);
        }
        Ok(())
    }

    /// Verifies both signatures and exact send-to-receipt linkage.
    ///
    /// This deliberately does not require the receipt endpoint to be reachable from the zero
    /// shard opening. A correctly linked but inconsistent operator-signed endpoint is admissible
    /// evidence for a receipt-range challenge.
    pub fn verify_linked<H: Hasher<Digest = D>>(
        &self,
        context: &PaymentContext<P, D>,
    ) -> Result<(), PaymentError> {
        self.verify_linked_with_strategy::<H>(context, &Sequential)
    }

    /// Verifies both signatures and exact linkage using the supplied execution strategy.
    pub fn verify_linked_with_strategy<H: Hasher<Digest = D>>(
        &self,
        context: &PaymentContext<P, D>,
        strategy: &impl Strategy,
    ) -> Result<(), PaymentError> {
        strategy.try_run(
            2,
            || {
                self.send.verify(context)?;
                self.receipt.verify(context)
            },
            || {
                let (send, receipt) = strategy.join(
                    || self.send.verify(context),
                    || self.receipt.verify(context),
                );
                send?;
                receipt
            },
        )?;
        self.validate_linkage::<H>()
    }

    /// Verifies linked evidence and the payer's exact next debit endpoint.
    pub fn verify_linked_next<H: Hasher<Digest = D>>(
        &self,
        context: &PaymentContext<P, D>,
        previous_debit: Amount,
    ) -> Result<(), PaymentError> {
        self.verify_linked::<H>(context)?;
        self.send.body.validate_next(previous_debit)
    }

    /// Verifies a public terminal receipt endpoint from the canonical zero opening.
    pub fn verify_terminal<H: Hasher<Digest = D>>(
        &self,
        context: &PaymentContext<P, D>,
    ) -> Result<(), PaymentError> {
        self.verify_linked::<H>(context)?;
        if !receipt_range_is_feasible(
            0,
            0,
            self.amount(),
            self.receipt.body.cumulative_shard_credit,
            self.receipt.body.index,
        ) {
            return Err(PaymentError::InfeasibleReceiptRange);
        }
        Ok(())
    }
}

impl<P: PublicKey, D: Digest> Write for Payment<P, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.send.write(buf);
        self.receipt.write(buf);
    }
}

impl<P: PublicKey, D: Digest> FixedSize for Payment<P, D> {
    const SIZE: usize = SignedSend::<P, D>::SIZE + SignedReceipt::<P, D>::SIZE;
}

impl<P: PublicKey, D: Digest> Read for Payment<P, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        let mut public_keys = PublicKeyReader::new();
        Self::read_with_public_keys(buf, &mut public_keys)
    }
}

impl<P: PublicKey, D: Digest> ReadWithPublicKeys<P> for Payment<P, D> {
    fn read_with_public_keys(
        buf: &mut impl Buf,
        public_keys: &mut PublicKeyReader<P>,
    ) -> Result<Self, CodecError> {
        Ok(Self {
            send: SignedSend::read_with_public_keys(buf, public_keys)?,
            receipt: SignedReceipt::read_with_public_keys(buf, public_keys)?,
        })
    }
}

/// Returns whether two shard endpoints admit positive omitted payments between them.
///
/// The upper receipt's payment is explicit. Every earlier omitted receipt must contribute at
/// least one unit, so an index gap constrains the minimum possible credit increase. This function
/// checks arithmetic feasibility only; it does not claim the omitted signatures exist.
#[must_use]
pub fn receipt_range_is_feasible(
    lower_credit: Amount,
    lower_index: ReceiptIndex,
    upper_amount: Amount,
    upper_credit: Amount,
    upper_index: ReceiptIndex,
) -> bool {
    if upper_amount == 0 {
        return false;
    }
    let Some(distance) = upper_index.checked_sub(lower_index) else {
        return false;
    };
    if distance == 0 {
        return false;
    }
    let Some(explicit_credit) = lower_credit.checked_add(upper_amount) else {
        return false;
    };
    if distance == 1 {
        return upper_credit == explicit_credit;
    }
    explicit_credit
        .checked_add(distance - 1)
        .is_some_and(|minimum| upper_credit >= minimum)
}

/// Checks one exact consecutive shard transition without verifying signatures.
pub fn verify_receipt_step<P: PublicKey, D: Digest>(
    predecessor_credit: Amount,
    predecessor_index: ReceiptIndex,
    successor: &Payment<P, D>,
) -> Result<(), PaymentError> {
    let expected_index = predecessor_index
        .checked_add(1)
        .ok_or(PaymentError::ArithmeticOverflow)?;
    if successor.receipt.body.index != expected_index {
        return Err(PaymentError::NonConsecutiveReceipt);
    }
    let expected_credit = predecessor_credit
        .checked_add(successor.amount())
        .ok_or(PaymentError::ArithmeticOverflow)?;
    if successor.receipt.body.cumulative_shard_credit != expected_credit {
        return Err(PaymentError::InvalidReceiptCredit);
    }
    Ok(())
}

fn verify_same_shard<P: PublicKey, D: Digest>(
    lower: &Payment<P, D>,
    upper: &Payment<P, D>,
) -> Result<(), PaymentError> {
    if lower.receipt.body.recipient != upper.receipt.body.recipient
        || lower.receipt.body.shard != upper.receipt.body.shard
    {
        return Err(PaymentError::DifferentReceiptRange);
    }
    Ok(())
}

/// Verifies two linked endpoints and their positive-credit range feasibility.
pub fn verify_receipt_range<H: Hasher<Digest = D>, P: PublicKey, D: Digest>(
    context: &PaymentContext<P, D>,
    lower: &Payment<P, D>,
    upper: &Payment<P, D>,
) -> Result<(), PaymentError> {
    lower.verify_linked::<H>(context)?;
    upper.verify_linked::<H>(context)?;
    verify_same_shard(lower, upper)?;
    if lower.receipt.body.tx_id == upper.receipt.body.tx_id {
        return Err(PaymentError::ReusedTransaction);
    }
    if !receipt_range_is_feasible(
        lower.receipt.body.cumulative_shard_credit,
        lower.receipt.body.index,
        upper.amount(),
        upper.receipt.body.cumulative_shard_credit,
        upper.receipt.body.index,
    ) {
        return Err(PaymentError::InfeasibleReceiptRange);
    }
    Ok(())
}

/// Verifies two linked receipts as one exact consecutive shard step.
pub fn verify_consecutive_receipts<H: Hasher<Digest = D>, P: PublicKey, D: Digest>(
    context: &PaymentContext<P, D>,
    predecessor: &Payment<P, D>,
    successor: &Payment<P, D>,
) -> Result<(), PaymentError> {
    predecessor.verify_linked::<H>(context)?;
    successor.verify_linked::<H>(context)?;
    verify_same_shard(predecessor, successor)?;
    if predecessor.receipt.body.tx_id == successor.receipt.body.tx_id {
        return Err(PaymentError::ReusedTransaction);
    }
    verify_receipt_step(
        predecessor.receipt.body.cumulative_shard_credit,
        predecessor.receipt.body.index,
        successor,
    )
}

/// Payment construction or verification failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PaymentError {
    /// A payment amount was zero.
    #[error("payment amount must be positive")]
    ZeroAmount,
    /// Checked debit, credit, or index arithmetic failed.
    #[error("checked payment arithmetic overflowed")]
    ArithmeticOverflow,
    /// A body binds another anchor or epoch.
    #[error("payment binds another anchor or epoch")]
    WrongContext,
    /// A cumulative debit cannot be reached from a nonnegative predecessor.
    #[error("cumulative debit is smaller than the payment amount")]
    MalformedDebitEndpoint,
    /// A cumulative debit is not the exact successor supplied by the caller.
    #[error("payer debit is not the exact next debit")]
    NonConsecutiveDebit,
    /// The payer signature does not authenticate the send body.
    #[error("payer signature is invalid")]
    InvalidPayerSignature,
    /// The supplied receipt signer is not the context operator.
    #[error("receipt signer is not the context operator")]
    WrongOperator,
    /// The context operator signature does not authenticate the receipt body.
    #[error("operator signature is invalid")]
    InvalidOperatorSignature,
    /// Receipt recipient, amount, or transaction identifier does not match the send.
    #[error("receipt does not match its payer-authorized send")]
    ReceiptMismatch,
    /// Two endpoints do not belong to the same recipient-local shard.
    #[error("receipt endpoints belong to different recipient shards")]
    DifferentReceiptRange,
    /// A transaction identifier was acknowledged at two receipt endpoints.
    #[error("one payer transaction appears at multiple receipt endpoints")]
    ReusedTransaction,
    /// The endpoint range cannot be completed by positive payment amounts.
    #[error("receipt range has no positive-credit completion")]
    InfeasibleReceiptRange,
    /// A purported successor index is not exactly one greater than its predecessor.
    #[error("receipt index is not the immediate successor")]
    NonConsecutiveReceipt,
    /// A consecutive receipt's cumulative credit is not predecessor credit plus amount.
    #[error("receipt cumulative credit is not predecessor credit plus amount")]
    InvalidReceiptCredit,
}

#[cfg(feature = "arbitrary")]
mod arbitrary_impls {
    use super::*;

    impl<'a, P, D> arbitrary::Arbitrary<'a> for PaymentContext<P, D>
    where
        P: PublicKey + arbitrary::Arbitrary<'a>,
        D: Digest + arbitrary::Arbitrary<'a>,
    {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self {
                anchor: u.arbitrary()?,
                epoch: u.arbitrary()?,
                operator: u.arbitrary()?,
            })
        }
    }

    impl<'a, D> arbitrary::Arbitrary<'a> for TxId<D>
    where
        D: Digest + arbitrary::Arbitrary<'a>,
    {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self(u.arbitrary()?))
        }
    }

    impl<'a, P, D> arbitrary::Arbitrary<'a> for SendBody<P, D>
    where
        P: PublicKey + arbitrary::Arbitrary<'a>,
        D: Digest + arbitrary::Arbitrary<'a>,
    {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self {
                anchor: u.arbitrary()?,
                epoch: u.arbitrary()?,
                payer: u.arbitrary()?,
                recipient: u.arbitrary()?,
                amount: u.arbitrary()?,
                cumulative_debit: u.arbitrary()?,
            })
        }
    }

    impl<'a, P, D> arbitrary::Arbitrary<'a> for SignedSend<P, D>
    where
        P: PublicKey + arbitrary::Arbitrary<'a>,
        P::Signature: arbitrary::Arbitrary<'a>,
        D: Digest + arbitrary::Arbitrary<'a>,
    {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self {
                body: u.arbitrary()?,
                payer_signature: u.arbitrary()?,
            })
        }
    }

    impl<'a, P, D> arbitrary::Arbitrary<'a> for ReceiptBody<P, D>
    where
        P: PublicKey + arbitrary::Arbitrary<'a>,
        D: Digest + arbitrary::Arbitrary<'a>,
    {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self {
                anchor: u.arbitrary()?,
                epoch: u.arbitrary()?,
                recipient: u.arbitrary()?,
                shard: u.arbitrary()?,
                amount: u.arbitrary()?,
                tx_id: u.arbitrary()?,
                cumulative_shard_credit: u.arbitrary()?,
                index: u.arbitrary()?,
            })
        }
    }

    impl<'a, P, D> arbitrary::Arbitrary<'a> for SignedReceipt<P, D>
    where
        P: PublicKey + arbitrary::Arbitrary<'a>,
        P::Signature: arbitrary::Arbitrary<'a>,
        D: Digest + arbitrary::Arbitrary<'a>,
    {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self {
                body: u.arbitrary()?,
                operator_signature: u.arbitrary()?,
            })
        }
    }

    impl<'a, P, D> arbitrary::Arbitrary<'a> for Payment<P, D>
    where
        P: PublicKey + arbitrary::Arbitrary<'a>,
        P::Signature: arbitrary::Arbitrary<'a>,
        D: Digest + arbitrary::Arbitrary<'a>,
    {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self {
                send: u.arbitrary()?,
                receipt: u.arbitrary()?,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};
    use commonware_cryptography::{
        Sha256,
        curve25519::{SigningKey, VerifyingKey},
        sha256::Digest as ShaDigest,
    };
    use commonware_parallel::{Rayon, Sequential};
    use std::num::NonZeroUsize;

    type TestContext = PaymentContext<VerifyingKey, ShaDigest>;
    type TestPayment = Payment<VerifyingKey, ShaDigest>;

    fn context() -> (TestContext, SigningKey, SigningKey, SigningKey) {
        let operator = SigningKey::from_seed(1);
        let payer = SigningKey::from_seed(2);
        let recipient = SigningKey::from_seed(3);
        (
            PaymentContext::new(Sha256::hash(&[b"anchor"]), 7, operator.public_key()),
            operator,
            payer,
            recipient,
        )
    }

    #[test]
    fn context_decode_rejects_a_low_order_operator_identity() {
        let (context, _, _, _) = context();
        let mut encoded = context.encode().to_vec();
        let operator = encoded.len() - VerifyingKey::SIZE;
        encoded[operator..].fill(0);
        encoded[operator] = 1;
        assert!(TestContext::decode(encoded.as_slice()).is_err());
    }

    #[allow(clippy::too_many_arguments)]
    fn payment(
        context: &TestContext,
        operator: &SigningKey,
        payer: &SigningKey,
        recipient: &SigningKey,
        amount: u64,
        previous_debit: u64,
        shard: u64,
        previous_credit: u64,
        previous_index: u64,
    ) -> TestPayment {
        let send = SignedSend::sign_next(
            context,
            payer,
            recipient.public_key(),
            amount,
            previous_debit,
        )
        .unwrap();
        let receipt = SignedReceipt::issue_next::<Sha256, _>(
            context,
            &send,
            shard,
            previous_credit,
            previous_index,
            operator,
        )
        .unwrap();
        Payment::new::<Sha256>(context, send, receipt).unwrap()
    }

    #[test]
    fn checked_send_is_exact_next_debit() {
        let (context, _, payer, recipient) = context();
        let send = SignedSend::sign_next(&context, &payer, recipient.public_key(), 9, 12).unwrap();
        assert_eq!(send.body().cumulative_debit(), 21);
        assert_eq!(send.verify_next(&context, 12), Ok(()));
        assert_eq!(
            send.verify_next(&context, 11),
            Err(PaymentError::NonConsecutiveDebit)
        );
        assert_eq!(
            SignedSend::sign_next(&context, &payer, recipient.public_key(), 0, 0),
            Err(PaymentError::ZeroAmount)
        );
        assert_eq!(
            SignedSend::sign_next(&context, &payer, recipient.public_key(), 1, u64::MAX),
            Err(PaymentError::ArithmeticOverflow)
        );
    }

    #[test]
    fn tx_id_excludes_signature_bytes() {
        let (context, _, payer, recipient) = context();
        let other = SigningKey::from_seed(99);
        let send = SignedSend::sign_next(&context, &payer, recipient.public_key(), 4, 5).unwrap();
        let different_envelope = SignedSend::sign_body_by_authority(send.body().clone(), &other);
        assert_ne!(send.signature(), different_envelope.signature());
        assert_eq!(send.tx_id::<Sha256>(), different_envelope.tx_id::<Sha256>());
        assert_eq!(
            different_envelope.verify(&context),
            Err(PaymentError::InvalidPayerSignature)
        );

        let changed_body =
            SendBody::next(&context, payer.public_key(), recipient.public_key(), 5, 5).unwrap();
        assert_ne!(send.tx_id::<Sha256>(), changed_body.tx_id::<Sha256>());
    }

    #[test]
    fn payment_verifies_both_signatures_and_linkage() {
        let (context, operator, payer, recipient) = context();
        let payment = payment(&context, &operator, &payer, &recipient, 7, 0, 4, 0, 0);
        assert_eq!(payment.verify_linked::<Sha256>(&context), Ok(()));
        assert_eq!(payment.verify_terminal::<Sha256>(&context), Ok(()));

        let other_recipient = SigningKey::from_seed(10).public_key();
        let mismatched = ReceiptBody::from_raw_unchecked(
            *context.anchor(),
            context.epoch(),
            other_recipient,
            4,
            payment.amount(),
            *payment.receipt().body().tx_id(),
            7,
            1,
        );
        let mismatched = SignedReceipt::sign_body_by_authority(mismatched, &operator);
        let mismatched = Payment::from_parts_unchecked(payment.send().clone(), mismatched);
        assert_eq!(
            mismatched.verify_linked::<Sha256>(&context),
            Err(PaymentError::ReceiptMismatch)
        );
    }

    #[test]
    fn linked_strategy_results_preserve_signature_error_precedence() {
        let (context, operator, payer, recipient) = context();
        let payment = payment(&context, &operator, &payer, &recipient, 7, 0, 4, 0, 0);
        let rayon = Rayon::new(NonZeroUsize::new(8).unwrap()).unwrap();
        let assert_all = |payment: &TestPayment, expected: Result<(), PaymentError>| {
            assert_eq!(payment.verify_linked::<Sha256>(&context), expected);
            assert_eq!(
                payment.verify_linked_with_strategy::<Sha256>(&context, &Sequential),
                expected
            );
            assert_eq!(
                payment.verify_linked_with_strategy::<Sha256>(&context, &rayon),
                expected
            );
        };
        assert_all(&payment, Ok(()));

        let wrong = SigningKey::from_seed(99);
        let invalid_send =
            SignedSend::sign_body_by_authority(payment.send().body().clone(), &wrong);
        let invalid_receipt =
            SignedReceipt::sign_body_by_authority(payment.receipt().body().clone(), &wrong);
        let both_invalid = Payment::from_parts_unchecked(invalid_send, invalid_receipt);
        assert_all(&both_invalid, Err(PaymentError::InvalidPayerSignature));
    }

    #[test]
    fn linked_evidence_and_terminal_endpoint_have_distinct_predicates() {
        let (context, operator, payer, recipient) = context();
        let send = SignedSend::sign_next(&context, &payer, recipient.public_key(), 1, 0).unwrap();
        let body = ReceiptBody::from_raw_unchecked(
            *context.anchor(),
            context.epoch(),
            recipient.public_key(),
            8,
            1,
            send.tx_id::<Sha256>(),
            1,
            2,
        );
        let receipt = SignedReceipt::sign_body_by_authority(body, &operator);
        let payment = Payment::from_parts_unchecked(send, receipt);
        assert_eq!(payment.verify_linked::<Sha256>(&context), Ok(()));
        assert_eq!(
            payment.verify_terminal::<Sha256>(&context),
            Err(PaymentError::InfeasibleReceiptRange)
        );
    }

    #[test]
    fn receipt_range_accounts_for_every_positive_omitted_payment() {
        assert!(receipt_range_is_feasible(0, 0, 5, 5, 1));
        assert!(!receipt_range_is_feasible(0, 0, 5, 6, 1));
        assert!(!receipt_range_is_feasible(0, 0, 0, 0, 1));
        assert!(!receipt_range_is_feasible(10, 5, 1, 11, 5));
        assert!(!receipt_range_is_feasible(10, 5, 1, 11, 4));
        assert!(!receipt_range_is_feasible(10, 5, 4, 14, 7));
        assert!(receipt_range_is_feasible(10, 5, 4, 15, 7));
        assert!(!receipt_range_is_feasible(u64::MAX, 0, 1, u64::MAX, 1));
        assert!(!receipt_range_is_feasible(1, 0, 1, u64::MAX, u64::MAX));
    }

    #[test]
    fn consecutive_receipts_check_identity_index_and_credit() {
        let (context, operator, payer, recipient) = context();
        let first = payment(&context, &operator, &payer, &recipient, 5, 0, 3, 0, 0);
        let second_payer = SigningKey::from_seed(4);
        let second = payment(
            &context,
            &operator,
            &second_payer,
            &recipient,
            2,
            0,
            3,
            5,
            1,
        );
        assert_eq!(
            verify_consecutive_receipts::<Sha256, _, _>(&context, &first, &second),
            Ok(())
        );
        assert_eq!(
            verify_receipt_range::<Sha256, _, _>(&context, &first, &second),
            Ok(())
        );

        let skipped = payment(
            &context,
            &operator,
            &SigningKey::from_seed(5),
            &recipient,
            2,
            0,
            3,
            6,
            2,
        );
        assert_eq!(
            verify_consecutive_receipts::<Sha256, _, _>(&context, &first, &skipped),
            Err(PaymentError::NonConsecutiveReceipt)
        );
        assert_eq!(
            verify_receipt_range::<Sha256, _, _>(&context, &first, &skipped),
            Ok(())
        );
    }

    #[test]
    fn payment_codec_is_fixed_and_round_trips() {
        let (context, operator, payer, recipient) = context();
        let payment = payment(&context, &operator, &payer, &recipient, 17, 4, 2, 9, 3);
        let encoded = payment.encode();
        assert_eq!(encoded.len(), TestPayment::SIZE);
        assert_eq!(TestPayment::decode(encoded).unwrap(), payment);
    }

    #[test]
    fn wrong_context_and_operator_are_rejected() {
        let (context, operator, payer, recipient) = context();
        let send = SignedSend::sign_next(&context, &payer, recipient.public_key(), 2, 0).unwrap();
        let wrong_operator = SigningKey::from_seed(22);
        assert_eq!(
            SignedReceipt::issue_next::<Sha256, _>(&context, &send, 0, 0, 0, &wrong_operator,),
            Err(PaymentError::WrongOperator)
        );

        let wrong_context = PaymentContext::new(
            Sha256::hash(&[b"other-anchor"]),
            context.epoch(),
            operator.public_key(),
        );
        assert_eq!(send.verify(&wrong_context), Err(PaymentError::WrongContext));
    }
}
