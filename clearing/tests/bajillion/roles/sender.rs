//! A reference sender that pays through the operator and resolves its requests against posted
//! closes.

use commonware_clearing::bajillion::{
    Amount, Amounts, Epoch, InvalidOpening, InvalidReceipt, Namespace, Opening, Receipt, Request,
    RequestError, State, States,
};
use commonware_codec::Encode as _;
use commonware_cryptography::{Digest, Hasher, PublicKey, Signer};
use core::hash::Hash;
use std::collections::BTreeMap;

/// Why the sender refused to act.
#[derive(Debug, thiserror::Error)]
pub enum Refusal {
    /// A request is still pending.
    #[error("a request is still pending")]
    Pending,
    /// No request is pending.
    #[error("no request is pending")]
    NotPending,
    /// The sender holds a countersigned map of a later epoch.
    #[error("the sender holds a countersigned map of a later epoch")]
    LaterEpoch,
    /// The acknowledgement countersigns none of the pending request's states.
    #[error("the acknowledgement countersigns none of the pending request's states")]
    InvalidAcknowledgement,
    /// The sender holds no acknowledged state of the epoch.
    #[error("the sender holds no acknowledged state of the epoch")]
    NotAcknowledged,
    /// The request's states do not derive.
    #[error(transparent)]
    Request(#[from] RequestError),
    /// The receipts do not issue.
    #[error(transparent)]
    Receipt(#[from] InvalidReceipt),
    /// The opening does not verify.
    #[error(transparent)]
    Opening(#[from] InvalidOpening),
}

/// What a posted close did with the pending request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Outcome {
    /// The close settled one of its states.
    Settled,
    /// The close settled none of its states, and none is for a later epoch.
    Dropped,
    /// Its state for a later epoch may still settle.
    Pending,
}

/// A countersigned state with the sender's signature, the operator's acknowledgement if the
/// sender received it, and the payment map the state commits to (S2, S3).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Countersigned<P: PublicKey, O: PublicKey, D: Digest, A: Amount> {
    /// The countersigned state.
    pub state: State<P, D>,
    /// The sender's signature over the state.
    pub signature: P::Signature,
    /// The operator's countersignature, if the sender received it.
    pub acknowledgement: Option<O::Signature>,
    /// The payment map the state commits to.
    pub payments: Amounts<P, A>,
}

/// A request awaiting an answer, with its states.
pub type Pending<P, D, A> = (Request<P, D, A>, States<P, D, A>);

/// What the sender persists. A restart resumes from it alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Persisted<P: PublicKey, O: PublicKey, D: Digest, A: Amount> {
    /// The latest countersigned state of each epoch the sender paid in.
    pub countersigned: BTreeMap<Epoch, Countersigned<P, O, D, A>>,
    /// The sender's row root in each posted close (S5).
    pub posted: BTreeMap<Epoch, D>,
    /// The request awaiting an answer with its states, persisted before it is sent (S3).
    pub pending: Option<Pending<P, D, A>>,
}

impl<P: PublicKey, O: PublicKey, D: Digest, A: Amount> Hash for Persisted<P, O, D, A> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        let Self {
            countersigned,
            posted,
            pending,
        } = self;
        countersigned.hash(state);
        posted.hash(state);
        if let Some((request, states)) = pending {
            let States {
                batch,
                current,
                payments,
                next,
            } = states;
            request.encode().hash(state);
            batch.hash(state);
            current.hash(state);
            payments.hash(state);
            next.hash(state);
        }
    }
}

/// A sender keeping its countersigned states, the row roots of posted closes, and at most one
/// pending request with its states. Two senders are equal when they persisted the same records.
pub struct Sender<S: Signer, O: PublicKey, H: Hasher, A: Amount> {
    signer: S,
    account: S::PublicKey,
    namespace: Namespace,
    operator: O,
    persisted: Persisted<S::PublicKey, O, H::Digest, A>,
}

// The hasher is a type parameter only, so the derived impl would bound it.
impl<S: Signer, O: PublicKey, H: Hasher, A: Amount> Clone for Sender<S, O, H, A> {
    fn clone(&self) -> Self {
        Self {
            signer: self.signer.clone(),
            account: self.account.clone(),
            namespace: self.namespace.clone(),
            operator: self.operator.clone(),
            persisted: self.persisted.clone(),
        }
    }
}

impl<S: Signer, O: PublicKey, H: Hasher, A: Amount> PartialEq for Sender<S, O, H, A> {
    fn eq(&self, other: &Self) -> bool {
        self.persisted == other.persisted
    }
}

impl<S: Signer, O: PublicKey, H: Hasher, A: Amount> Eq for Sender<S, O, H, A> {}

impl<S: Signer, O: PublicKey, H: Hasher, A: Amount> Hash for Sender<S, O, H, A> {
    fn hash<T: core::hash::Hasher>(&self, state: &mut T) {
        self.persisted.hash(state);
    }
}

impl<S: Signer, O: PublicKey, H: Hasher, A: Amount> Sender<S, O, H, A> {
    /// Returns a sender with no countersigned state and no pending request.
    pub fn new(signer: S, namespace: Namespace, operator: O) -> Self {
        let persisted = Persisted {
            countersigned: BTreeMap::new(),
            posted: BTreeMap::new(),
            pending: None,
        };
        Self::restart(signer, namespace, operator, persisted)
    }

    /// Returns a sender resuming from what it persisted.
    pub fn restart(
        signer: S,
        namespace: Namespace,
        operator: O,
        persisted: Persisted<S::PublicKey, O, H::Digest, A>,
    ) -> Self {
        Self {
            account: signer.public_key(),
            signer,
            namespace,
            operator,
            persisted,
        }
    }

    /// Returns what the sender persisted.
    pub const fn persisted(&self) -> &Persisted<S::PublicKey, O, H::Digest, A> {
        &self.persisted
    }

    /// Returns the countersigned payment map of `epoch`.
    pub fn payments(&self, epoch: Epoch) -> Option<&Amounts<S::PublicKey, A>> {
        self.persisted
            .countersigned
            .get(&epoch)
            .map(|countersigned| &countersigned.payments)
    }

    /// Returns the pending request, if any.
    pub fn pending(&self) -> Option<&Request<S::PublicKey, H::Digest, A>> {
        self.persisted.pending.as_ref().map(|(request, _)| request)
    }

    /// Returns the root a request in `epoch` builds on (S1). An existing countersigned map keeps
    /// its predecessor. A new map uses the posted row root of the epoch before if recorded, else
    /// its countersigned map's root, else the empty map's root.
    fn previous(&self, epoch: Epoch) -> H::Digest {
        if let Some(countersigned) = self.persisted.countersigned.get(&epoch) {
            return countersigned.state.previous;
        }
        let before = epoch.checked_sub(1);
        before
            .and_then(|before| self.persisted.posted.get(&before).copied())
            .or_else(|| {
                before
                    .and_then(|before| self.persisted.countersigned.get(&before))
                    .map(|countersigned| countersigned.state.payments)
            })
            .unwrap_or_else(|| Amounts::<S::PublicKey, A>::empty().root::<H>())
    }

    /// Returns both states of the pending request as a [Countersigned] without an acknowledgement.
    fn proposed(&self) -> Vec<Countersigned<S::PublicKey, O, H::Digest, A>> {
        let Some((request, states)) = &self.persisted.pending else {
            return Vec::new();
        };
        let countersigned =
            |state: &State<_, _>, signature: &S::Signature, payments: &Amounts<_, _>| {
                Countersigned {
                    state: state.clone(),
                    signature: signature.clone(),
                    acknowledgement: None,
                    payments: payments.clone(),
                }
            };
        vec![
            countersigned(
                &states.current,
                &request.signatures.current,
                &states.payments,
            ),
            countersigned(&states.next, &request.signatures.next, &states.batch),
        ]
    }

    /// Signs a request paying `batch` in `epoch` on top of the countersigned map of that epoch,
    /// or on top of it in the next. The request is persisted before it is returned for sending.
    pub fn send(
        &mut self,
        epoch: Epoch,
        batch: Amounts<S::PublicKey, A>,
    ) -> Result<Request<S::PublicKey, H::Digest, A>, Refusal> {
        // One request at a time, and none for an epoch before one with a countersigned map (S1).
        if self.persisted.pending.is_some() {
            return Err(Refusal::Pending);
        }
        if self
            .persisted
            .countersigned
            .keys()
            .next_back()
            .is_some_and(|latest| *latest > epoch)
        {
            return Err(Refusal::LaterEpoch);
        }

        // The states extend the epoch's latest countersigned map on top of the root S1 names, and
        // the request is persisted before it is returned for sending (S3).
        let empty = Amounts::empty();
        let payments = self.payments(epoch).unwrap_or(&empty);
        let states = Request::states::<H>(
            epoch,
            self.account.clone(),
            batch,
            payments,
            &self.previous(epoch),
        )?;
        let request = states.sign(&self.signer, &self.namespace);
        self.persisted.pending = Some((request.clone(), states));
        Ok(request)
    }

    /// Records the pending state the operator countersigned, with both signatures and its map, in
    /// one write that also clears the request (S2, S3). Only then returns a receipt for each
    /// receiver of its batch.
    #[allow(clippy::type_complexity)]
    pub fn acknowledged(
        &mut self,
        acknowledgement: &O::Signature,
    ) -> Result<Vec<Receipt<S::PublicKey, O, H::Digest, A>>, Refusal> {
        let (_, states) = self.persisted.pending.as_ref().ok_or(Refusal::NotPending)?;
        let receivers: Vec<_> = states
            .batch
            .iter()
            .map(|(receiver, _)| receiver.clone())
            .collect();

        // The acknowledgement must countersign one of the pending request's states (S2).
        let countersigned = self
            .proposed()
            .into_iter()
            .find(|proposed| {
                proposed.state.verify_acknowledgement(
                    &self.namespace,
                    &self.operator,
                    acknowledgement,
                )
            })
            .map(|proposed| Countersigned {
                acknowledgement: Some(acknowledgement.clone()),
                ..proposed
            })
            .ok_or(Refusal::InvalidAcknowledgement)?;

        // One write records the state and clears the request before any receipt is issued (S3).
        let epoch = countersigned.state.epoch;
        self.persisted.countersigned.insert(epoch, countersigned);
        self.persisted.pending = None;
        self.receipts(epoch, receivers)
    }

    /// Issues receipts for `receivers` from the acknowledged state of `epoch` the sender
    /// persisted.
    #[allow(clippy::type_complexity)]
    pub fn receipts(
        &self,
        epoch: Epoch,
        receivers: impl IntoIterator<Item = S::PublicKey>,
    ) -> Result<Vec<Receipt<S::PublicKey, O, H::Digest, A>>, Refusal> {
        let countersigned = self
            .persisted
            .countersigned
            .get(&epoch)
            .ok_or(Refusal::NotAcknowledged)?;
        let acknowledgement = countersigned
            .acknowledgement
            .as_ref()
            .ok_or(Refusal::NotAcknowledged)?;
        Ok(Receipt::issue::<H>(
            &countersigned.state,
            &countersigned.signature,
            acknowledgement,
            &countersigned.payments,
            receivers,
        )?)
    }

    /// Drops the pending request after a refusal of its only delivery (S4).
    pub fn refused(&mut self) -> Result<(), Refusal> {
        self.persisted
            .pending
            .take()
            .map(drop)
            .ok_or(Refusal::NotPending)
    }

    /// Records the final post of `epoch` with matrix root `root` from an opening of this sender's
    /// row, and resolves the pending request against it (S5). Posts must arrive in epoch order.
    /// Returns `None` if no request is pending.
    pub fn posted(
        &mut self,
        epoch: Epoch,
        root: &H::Digest,
        opening: &Opening<S::PublicKey, H::Digest, A>,
    ) -> Result<Option<Outcome>, Refusal> {
        // The opening proves this sender's row root, and the empty map's root stands for a close
        // without its row.
        let row = opening.verify_row::<H>(root, &self.account)?;
        let posted = row.unwrap_or_else(|| Amounts::<S::PublicKey, A>::empty().root::<H>());
        self.persisted.posted.insert(epoch, posted);
        if self.persisted.pending.is_none() {
            return Ok(None);
        }

        // A state of this epoch with the posted row root settles the request, and it is dropped
        // once none of its states is for a later epoch (S5).
        let proposed = self.proposed();
        let settled = proposed
            .iter()
            .find(|proposed| proposed.state.epoch == epoch && Some(proposed.state.payments) == row)
            .cloned();
        let resolved = proposed
            .iter()
            .all(|proposed| proposed.state.epoch <= epoch);
        if let Some(countersigned) = settled {
            self.persisted.countersigned.insert(epoch, countersigned);
            self.persisted.pending = None;
            return Ok(Some(Outcome::Settled));
        }
        if resolved {
            self.persisted.pending = None;
            return Ok(Some(Outcome::Dropped));
        }
        Ok(Some(Outcome::Pending))
    }

    /// Forgets the countersigned states and posted roots of epochs before `epoch`. The next request
    /// builds on what the sender recorded for the epoch before its own, so `epoch` must be at most
    /// that epoch. The pending request keeps the maps it extends in its states.
    pub fn prune(&mut self, epoch: Epoch) {
        self.persisted.countersigned = self.persisted.countersigned.split_off(&epoch);
        self.persisted.posted = self.persisted.posted.split_off(&epoch);
    }
}
