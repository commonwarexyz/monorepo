//! Paying through the operator.

use super::{Acknowledgement, Amounts, Epoch, Error, Namespace, Opening, Receipt, Request, State};
use commonware_cryptography::{Digest, Hasher, PublicKey, Signer};
use std::{collections::BTreeMap, marker::PhantomData};

/// One state of the pending request, with the payment map it commits to.
struct Proposed<P: PublicKey, D: Digest> {
    state: State<P, D>,
    payments: Amounts<P>,
    signature: P::Signature,
}

/// The request awaiting the operator's answer.
struct Pending<P: PublicKey, D: Digest> {
    request: Request<P>,
    /// The request's states, in epoch order. A pipelined request has two.
    states: Vec<Proposed<P, D>>,
}

/// What a posted close means for the pending request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The close settled the request, and the sender holds no pending request.
    Settled,
    /// No open epoch can settle the request, so the sender dropped it.
    Dropped,
    /// A later epoch may still settle the request, so it stays pending.
    Pending,
}

/// An account paying other accounts through the operator.
///
/// For every epoch, a sender keeps the payment map the operator has countersigned, and at most one
/// request awaiting the operator's answer. It never signs for an epoch before one it has paid in,
/// so every state it signs for an epoch extends its countersigned map of that epoch.
pub struct Sender<P: PublicKey, S: Signer, O: PublicKey, H: Hasher> {
    signer: S,
    account: P,
    operator: O,
    namespace: Namespace,
    /// Countersigned payment maps by epoch. Epochs without payments are absent.
    payments: BTreeMap<Epoch, Amounts<P>>,
    pending: Option<Pending<P, H::Digest>>,
    _hasher: PhantomData<H>,
}

impl<P, S, O, H> Sender<P, S, O, H>
where
    P: PublicKey,
    S: Signer<PublicKey = P, Signature = P::Signature>,
    O: PublicKey,
    H: Hasher,
{
    /// Creates a sender that signs with `signer` and accepts countersignatures from `operator`.
    pub fn new(signer: S, operator: O, namespace: Namespace) -> Self {
        Self {
            account: signer.public_key(),
            signer,
            operator,
            namespace,
            payments: BTreeMap::new(),
            pending: None,
            _hasher: PhantomData,
        }
    }

    /// Resumes a sender from the countersigned payment map of each epoch it paid in, and the
    /// request it was awaiting an answer to.
    ///
    /// The application must persist each payment map and clear the pending request that produced
    /// it in one write, since a request still pending on top of the map it already paid does not
    /// resume.
    ///
    /// Returns an error if a payment map is empty, or the request is not this sender's request
    /// on top of `payments`.
    pub fn resume(
        signer: S,
        operator: O,
        namespace: Namespace,
        payments: impl IntoIterator<Item = (Epoch, Amounts<P>)>,
        pending: Option<Request<P>>,
    ) -> Result<Self, Error> {
        let mut sender = Self::new(signer, operator, namespace);
        for (epoch, payments) in payments {
            if payments.is_empty() {
                return Err(Error::NoReceivers);
            }
            sender.payments.insert(epoch, payments);
        }
        if let Some(request) = pending {
            let states =
                sender.states(request.epoch, &request.batch, request.pipelined.is_some())?;
            let signatures = core::iter::once(&request.signature).chain(request.pipelined.as_ref());
            let states = states
                .into_iter()
                .zip(signatures)
                .map(|((state, payments), signature)| {
                    state
                        .verify(&sender.namespace, signature)
                        .then(|| Proposed {
                            state,
                            payments,
                            signature: signature.clone(),
                        })
                        .ok_or(Error::InvalidSignature)
                })
                .collect::<Result<_, _>>()?;
            sender.pending = Some(Pending { request, states });
        }
        Ok(sender)
    }

    /// Returns the account paying.
    pub const fn account(&self) -> &P {
        &self.account
    }

    /// Returns the payment map countersigned in `epoch`, if the sender paid in it.
    pub fn payments(&self, epoch: Epoch) -> Option<&Amounts<P>> {
        self.payments.get(&epoch)
    }

    /// Returns the request awaiting the operator's answer, to send again if it was lost.
    pub fn pending(&self) -> Option<&Request<P>> {
        self.pending.as_ref().map(|pending| &pending.request)
    }

    /// Returns the states paying `batch` in `epoch` or, if `pipelined`, also in the next epoch,
    /// each with the payment map it commits to.
    ///
    /// The state for `epoch` extends that epoch's countersigned map. The state for the next epoch
    /// pays only the batch, on top of the current map of `epoch`. That map settles unchanged if the
    /// batch settles in the next epoch.
    #[allow(clippy::type_complexity)]
    fn states(
        &self,
        epoch: Epoch,
        batch: &Amounts<P>,
        pipelined: bool,
    ) -> Result<Vec<(State<P, H::Digest>, Amounts<P>)>, Error> {
        if epoch == 0 {
            return Err(Error::ZeroEpoch);
        }
        if batch.is_empty() {
            return Err(Error::NoReceivers);
        }
        let next = epoch.checked_add(1).ok_or(Error::Overflow)?;
        if self.payments.range(next..).next().is_some() {
            return Err(Error::LaterEpoch);
        }
        let empty = Amounts::empty();
        let current = self.payments.get(&epoch).unwrap_or(&empty);
        let previous = self.payments.get(&(epoch - 1)).unwrap_or(&empty);
        let mut states = vec![self.state(epoch, current.combine(batch)?, previous)];
        if pipelined {
            states.push(self.state(next, batch.clone(), current));
        }
        Ok(states)
    }

    /// Returns the state paying `payments` in `epoch` on top of `previous`.
    fn state(
        &self,
        epoch: Epoch,
        payments: Amounts<P>,
        previous: &Amounts<P>,
    ) -> (State<P, H::Digest>, Amounts<P>) {
        let state = State {
            epoch,
            account: self.account.clone(),
            payments: payments.root::<H>(),
            previous: previous.root::<H>(),
        };
        (state, payments)
    }

    /// Signs a request to pay `batch` in `epoch` or, if `pipelined`, in `epoch` or the next one.
    ///
    /// The request stays pending until the operator acknowledges it, the operator refuses it, or a
    /// posted close resolves it.
    ///
    /// Returns an error if a request is pending, `epoch` is zero, the batch is empty, or the
    /// sender has paid in a later epoch.
    pub fn send(
        &mut self,
        epoch: Epoch,
        batch: Amounts<P>,
        pipelined: bool,
    ) -> Result<Request<P>, Error> {
        if self.pending.is_some() {
            return Err(Error::Pending);
        }
        let states: Vec<_> = self
            .states(epoch, &batch, pipelined)?
            .into_iter()
            .map(|(state, payments)| Proposed {
                signature: state.sign(&self.signer, &self.namespace),
                state,
                payments,
            })
            .collect();
        let request = Request {
            account: self.account.clone(),
            epoch,
            batch,
            signature: states[0].signature.clone(),
            pipelined: states.get(1).map(|proposed| proposed.signature.clone()),
        };
        self.pending = Some(Pending {
            request: request.clone(),
            states,
        });
        Ok(request)
    }

    /// Records the operator's acknowledgement of the pending request and returns a receipt for
    /// each receiver in its batch.
    ///
    /// Returns an error if no request is pending or the acknowledgement does not countersign one of
    /// its states.
    #[allow(clippy::type_complexity)]
    pub fn acknowledged(
        &mut self,
        acknowledgement: &Acknowledgement<O>,
    ) -> Result<Vec<Receipt<P, O, H::Digest>>, Error> {
        let pending = self.pending.as_ref().ok_or(Error::NotPending)?;
        let index = pending
            .states
            .iter()
            .position(|proposed| {
                proposed.state.epoch == acknowledgement.epoch
                    && proposed.state.verify_acknowledgement(
                        &self.namespace,
                        &self.operator,
                        &acknowledgement.signature,
                    )
            })
            .ok_or(Error::InvalidAcknowledgement)?;
        let Pending {
            request,
            mut states,
        } = self.pending.take().expect("request must be pending");
        let Proposed {
            state,
            payments,
            signature,
        } = states.swap_remove(index);

        let tree = payments.tree::<H>();
        let receipts = request
            .batch
            .iter()
            .map(|(receiver, _)| {
                let position = payments
                    .position(receiver)
                    .expect("payment map must include the batch");
                Receipt {
                    state: state.clone(),
                    signature: signature.clone(),
                    acknowledgement: acknowledgement.signature.clone(),
                    receiver: receiver.clone(),
                    amount: payments.get(receiver),
                    position: position as u32,
                    proof: tree
                        .proof(position as u32)
                        .expect("position must be in the payment map"),
                }
            })
            .collect();
        self.payments.insert(state.epoch, payments);
        Ok(receipts)
    }

    /// Drops the pending request because the operator refused every state of it.
    ///
    /// An operator that already accepted a request acknowledges it again when it is resent,
    /// unless it has since closed that epoch. A refusal of a resent request is therefore
    /// ambiguous, and the sender should keep such a request pending until a posted close resolves
    /// it. A malicious operator can still settle a request it refused, within what the sender
    /// authorized for the epoch.
    ///
    /// Returns an error if no request is pending.
    pub fn refused(&mut self) -> Result<(), Error> {
        self.pending.take().map(|_| ()).ok_or(Error::NotPending)
    }

    /// Resolves the pending request against the posted close of `epoch` with matrix root `root`.
    ///
    /// `opening` opens this sender's row in the close's matrix, for any receiver. The request
    /// settled if it has a state in `epoch` and the close settled exactly that state's payment
    /// map. Otherwise it is dropped once no epoch it may settle in remains open.
    ///
    /// Returns an error if no request is pending or the opening does not verify.
    pub fn posted(
        &mut self,
        epoch: Epoch,
        root: &H::Digest,
        opening: &Opening<P, H::Digest>,
    ) -> Result<Outcome, Error> {
        let pending = self.pending.as_ref().ok_or(Error::NotPending)?;
        let settled = opening.verify_row::<H>(root, &self.account)?;
        if let Some(index) = pending.states.iter().position(|proposed| {
            proposed.state.epoch == epoch && Some(proposed.state.payments) == settled
        }) {
            let Pending { mut states, .. } = self.pending.take().expect("request must be pending");
            let proposed = states.swap_remove(index);
            self.payments.insert(epoch, proposed.payments);
            return Ok(Outcome::Settled);
        }
        if pending
            .states
            .iter()
            .all(|proposed| proposed.state.epoch <= epoch)
        {
            self.pending = None;
            return Ok(Outcome::Dropped);
        }
        Ok(Outcome::Pending)
    }

    /// Forgets the payment maps of epochs before `epoch`.
    ///
    /// The sender must keep the map of the epoch before any epoch it may still pay in.
    pub fn prune(&mut self, epoch: Epoch) {
        self.payments = self.payments.split_off(&epoch);
    }
}
