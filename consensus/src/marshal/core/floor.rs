use crate::{
    marshal::resolver::handler::{Annotation, Key, Request},
    simplex::types::Finalization,
    types::{Height, Round},
};
use commonware_cryptography::{certificate::Scheme as CertificateScheme, Digest};
use commonware_resolver::Resolver;
use commonware_utils::vec::NonEmptyVec;

/// Durable processed floor used to admit or reject resolver fetches.
#[derive(Clone, Copy)]
struct ProcessedFloor {
    height: Height,
    round: Round,
}

impl ProcessedFloor {
    /// Returns true when the resolver request is above all processed floors.
    fn permits<C: Digest>(&self, fetch: &Request<C>) -> bool {
        if !fetch.above_height_floor(self.height) {
            return false;
        }

        fetch.above_round_floor(self.round)
    }
}

#[must_use = "fetch admission must be handled explicitly"]
pub(super) enum FetchAdmission {
    Issued,
    Denied,
}

impl FetchAdmission {
    pub(super) const fn denied(self) -> bool {
        matches!(self, Self::Denied)
    }

    pub(super) const fn ignore(self) {}
}

/// The processed floor plus any pending floor update awaiting its anchor block.
pub(super) struct Floor<S: CertificateScheme, C: Digest> {
    processed: ProcessedFloor,
    pending: Option<Finalization<S, C>>,
}

impl<S: CertificateScheme, C: Digest> Floor<S, C> {
    pub(super) const fn resolved(height: Height, round: Round) -> Self {
        Self {
            processed: ProcessedFloor { height, round },
            pending: None,
        }
    }

    pub(super) const fn awaiting_anchor(
        height: Height,
        round: Round,
        finalization: Finalization<S, C>,
    ) -> Self {
        Self {
            processed: ProcessedFloor { height, round },
            pending: Some(finalization),
        }
    }

    pub(super) const fn processed_height(&self) -> Height {
        self.processed.height
    }

    pub(super) const fn processed_round(&self) -> Round {
        self.processed.round
    }

    pub(super) const fn set_processed_height(&mut self, height: Height) {
        self.processed.height = height;
    }

    pub(super) const fn set_processed_round(&mut self, round: Round) {
        self.processed.round = round;
    }

    /// Returns true while repair and application dispatch must wait for the floor anchor.
    pub(super) const fn blocks_progress(&self) -> bool {
        self.pending.is_some()
    }

    /// Returns true if a pending floor already supersedes the candidate floor round.
    pub(super) fn has_pending_anchor_at_or_after(&self, round: Round) -> bool {
        matches!(&self.pending, Some(pending) if pending.round() >= round)
    }

    /// Returns true when `commitment` is the awaited anchor.
    pub(super) fn matches_pending_anchor(&self, commitment: C) -> bool {
        matches!(&self.pending, Some(pending) if pending.proposal.payload == commitment)
    }

    /// Records a verified floor finalization whose block anchor still needs to arrive.
    pub(super) fn await_anchor(&mut self, finalization: Finalization<S, C>) {
        self.pending = Some(finalization);
    }

    /// Takes the pending anchor finalization, if any.
    #[must_use]
    pub(super) const fn take_pending_anchor(&mut self) -> Option<Finalization<S, C>> {
        self.pending.take()
    }

    pub(super) fn fetch_if_permitted<R>(
        &self,
        resolver: &mut R,
        fetch: Request<C>,
    ) -> FetchAdmission
    where
        R: Resolver<Key = Key<C>, Subscriber = Annotation>,
    {
        if !self.processed.permits(&fetch) {
            return FetchAdmission::Denied;
        }
        resolver.fetch(fetch);
        FetchAdmission::Issued
    }

    pub(super) fn fetch_targeted_if_permitted<R>(
        &self,
        resolver: &mut R,
        fetch: Request<C>,
        targets: NonEmptyVec<R::PublicKey>,
    ) -> FetchAdmission
    where
        R: Resolver<Key = Key<C>, Subscriber = Annotation>,
    {
        if !self.processed.permits(&fetch) {
            return FetchAdmission::Denied;
        }
        resolver.fetch_targeted(fetch, targets);
        FetchAdmission::Issued
    }

    pub(super) fn fetch_all_if_permitted<R>(
        &self,
        resolver: &mut R,
        fetches: Vec<Request<C>>,
    ) -> FetchAdmission
    where
        R: Resolver<Key = Key<C>, Subscriber = Annotation>,
    {
        let fetches = fetches
            .into_iter()
            .filter(|fetch| self.processed.permits(fetch))
            .collect::<Vec<_>>();
        if fetches.is_empty() {
            return FetchAdmission::Denied;
        }
        resolver.fetch_all(fetches);
        FetchAdmission::Issued
    }
}
