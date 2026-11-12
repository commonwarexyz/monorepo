//! A reference sender that pays through the operator and resolves its requests and its recorded
//! maps against posted closes.

use commonware_clearing::bajillion::{
    Amount, Amounts, Epoch, InvalidOpening, Namespace, Opening, Receipt, Request, RequestError,
    State, States,
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
    /// The sender already resolved the post of the acknowledged state's epoch.
    #[error("the sender already resolved the post of the acknowledged state's epoch")]
    Closed,
    /// The sender holds no acknowledged state of the epoch.
    #[error("the sender holds no acknowledged state of the epoch")]
    NotAcknowledged,
    /// The request's states do not derive.
    #[error(transparent)]
    Request(#[from] RequestError),
    /// The recorded state and map issue no receipt for a receiver.
    #[error("invalid receipt")]
    InvalidReceipt,
    /// The opening does not verify.
    #[error("invalid opening")]
    InvalidOpening,
}

impl From<InvalidOpening> for Refusal {
    fn from(InvalidOpening: InvalidOpening) -> Self {
        Self::InvalidOpening
    }
}

/// What a posted close settled for the sender (S5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Outcome {
    /// The close settled the map the sender recorded for the epoch, or it has no row of the sender
    /// and the sender recorded no map.
    Match,
    /// The close settled a state of the pending request. The sender records that state's map and
    /// clears the request.
    Settled,
    /// The close settled another map, or it has no row of the sender where the sender recorded a
    /// map. Openings of the row show its payments.
    Conflict,
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
    /// The latest countersigned state of each epoch the sender paid in, or the state the post of
    /// that epoch settled.
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
        let latest = self
            .persisted
            .countersigned
            .get(&epoch)
            .map(|countersigned| (&countersigned.state, &countersigned.payments));
        let states = Request::states::<H>(
            epoch,
            self.account.clone(),
            batch,
            latest,
            &self.previous(epoch),
        )?;
        let request = states.sign(&self.signer, &self.namespace);
        self.persisted.pending = Some((request.clone(), states));
        Ok(request)
    }

    /// Records the pending state the operator countersigned, with both signatures and its map, in
    /// one write that also clears the request (S2, S3). Only then does it return a receipt for each
    /// receiver of its batch. A state of an epoch whose post the sender resolved is refused, and
    /// the request stays pending.
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

        // A post is final for its epoch, so a state of an epoch whose post the sender resolved is
        // not recorded, and the request stays pending (S2).
        let epoch = countersigned.state.epoch;
        let resolved = self.persisted.posted.keys().next_back();
        if resolved.is_some_and(|resolved| epoch <= *resolved) {
            return Err(Refusal::Closed);
        }

        // One write records the state and clears the request before any receipt is issued (S3).
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
        Receipt::issue::<H>(
            &countersigned.state,
            &countersigned.signature,
            acknowledgement,
            &countersigned.payments,
            receivers,
        )
        .ok_or(Refusal::InvalidReceipt)
    }

    /// Drops the pending request after a refusal of its only delivery (S4). Its states can still
    /// settle, so S6 limits when a new request may pay its batch again.
    pub fn refused(&mut self) -> Result<(), Refusal> {
        self.persisted
            .pending
            .take()
            .map(drop)
            .ok_or(Refusal::NotPending)
    }

    /// Records the final post of `epoch` with matrix root `root` from an opening of this sender's
    /// row, resolves the pending request against it, and returns what the close settled (S5). A
    /// request the close did not settle stays pending while one of its states can still settle in a
    /// later epoch. Otherwise it is dropped. [Self::pending] shows which. Posts must arrive in
    /// epoch order.
    pub fn posted(
        &mut self,
        epoch: Epoch,
        root: &H::Digest,
        opening: &Opening<S::PublicKey, H::Digest, A>,
    ) -> Result<Outcome, Refusal> {
        // The opening proves this sender's row root, and the empty map's root stands for a close
        // without its row.
        let row = opening.verify_row::<H>(root, &self.account)?;
        let empty = Amounts::<S::PublicKey, A>::empty().root::<H>();
        let posted = row.unwrap_or(empty);
        self.persisted.posted.insert(epoch, posted);

        // A state of this epoch with the posted row root settles the request. A state of the next
        // epoch can still settle only if it builds on that root, and the request is dropped once
        // none of its states can settle (S5). No state is proposed when no request is pending.
        let proposed = self.proposed();
        let settled = proposed
            .iter()
            .find(|proposed| proposed.state.epoch == epoch && Some(proposed.state.payments) == row)
            .cloned();
        let live = proposed.iter().any(|proposed| {
            let state = &proposed.state;
            state.epoch > epoch && (state.epoch - 1 > epoch || state.previous == posted)
        });
        if let Some(countersigned) = settled {
            self.persisted.countersigned.insert(epoch, countersigned);
            self.persisted.pending = None;
            return Ok(Outcome::Settled);
        }
        if !live {
            self.persisted.pending = None;
        }

        // The post matches the sender's record when the row root is the root of its countersigned
        // map, or the empty map's root when it holds none. Any other row root is a conflict (S5).
        let record = self
            .persisted
            .countersigned
            .get(&epoch)
            .map_or(empty, |countersigned| countersigned.state.payments);
        Ok(if record == posted {
            Outcome::Match
        } else {
            Outcome::Conflict
        })
    }

    /// Forgets the countersigned states and posted roots of epochs before `epoch`. The next request
    /// builds on what the sender recorded for the epoch before its own, so `epoch` must be at most
    /// that epoch. The pending request keeps the maps it extends in its states. The last post
    /// resolved tells [Self::acknowledged] which states are closed, so `epoch` must also be at most
    /// that post's epoch.
    pub fn prune(&mut self, epoch: Epoch) {
        self.persisted.countersigned = self.persisted.countersigned.split_off(&epoch);
        self.persisted.posted = self.persisted.posted.split_off(&epoch);
    }
}
