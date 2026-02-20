use crate::{
    marshal::{
        ancestry::AncestorStream,
        application::validation::{
            is_block_in_expected_epoch, is_valid_reproposal_at_verify,
            validate_standard_block_for_verification,
        },
        core::Mailbox,
        standard::Standard,
    },
    simplex::types::Context,
    types::{Epocher, Round},
    Application, Block, Epochable, VerifyingApplication,
};
use commonware_cryptography::certificate::Scheme;
use commonware_macros::select;
use commonware_runtime::{Clock, Metrics, Spawner};
use commonware_utils::channel::oneshot::{self, error::RecvError};
use futures::future::{ready, Either, Ready};
use rand::Rng;
use tracing::debug;

pub(super) enum VerificationDecision<B> {
    Complete(bool),
    Continue(B),
}

#[inline]
pub(super) async fn precheck_epoch_and_reproposal<ES, S, B>(
    epocher: &ES,
    marshal: &mut Mailbox<S, Standard<B>>,
    context: &Context<B::Digest, S::PublicKey>,
    digest: B::Digest,
    block: B,
) -> VerificationDecision<B>
where
    ES: Epocher,
    S: Scheme,
    B: Block + Clone,
{
    if !is_block_in_expected_epoch(epocher, block.height(), context.epoch()) {
        debug!(
            height = %block.height(),
            "block height not in expected epoch"
        );
        return VerificationDecision::Complete(false);
    }

    if digest == context.parent.1 {
        if !is_valid_reproposal_at_verify(epocher, block.height(), context.epoch()) {
            debug!(
                height = %block.height(),
                "re-proposal is not at epoch boundary"
            );
            return VerificationDecision::Complete(false);
        }

        marshal.verified(context.round, block).await;
        return VerificationDecision::Complete(true);
    }

    VerificationDecision::Continue(block)
}

#[inline]
pub(super) async fn verify_with_parent<E, S, A, B>(
    runtime_context: E,
    context: Context<B::Digest, S::PublicKey>,
    block: B,
    application: &mut A,
    marshal: &mut Mailbox<S, Standard<B>>,
    tx: &mut oneshot::Sender<bool>,
) -> Option<bool>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: VerifyingApplication<
        E,
        Block = B,
        SigningScheme = S,
        Context = Context<B::Digest, S::PublicKey>,
    >,
    B: Block + Clone,
{
    let (parent_view, parent_digest) = context.parent;
    let parent_request = fetch_parent(
        parent_digest,
        Some(Round::new(context.epoch(), parent_view)),
        application,
        marshal,
    )
    .await;
    let parent = select! {
        _ = tx.closed() => {
            debug!(
                reason = "consensus dropped receiver",
                "skipping verification"
            );
            return None;
        },
        result = parent_request => match result {
            Ok(parent) => parent,
            Err(_) => {
                debug!(
                    ?parent_digest,
                    reason = "failed to fetch parent block",
                    "skipping verification"
                );
                return None;
            }
        },
    };

    if let Err(err) = validate_standard_block_for_verification(&block, &parent, parent_digest) {
        debug!(
            ?err,
            expected_parent = %parent.digest(),
            block_parent = %block.parent(),
            parent_height = %parent.height(),
            block_height = %block.height(),
            "block failed standard invariant validation"
        );
        return Some(false);
    }

    let ancestry_stream = AncestorStream::new(marshal.clone(), [block.clone(), parent]);
    let validity_request = application.verify(
        (runtime_context.with_label("app_verify"), context.clone()),
        ancestry_stream,
    );
    let application_valid = select! {
        _ = tx.closed() => {
            debug!(
                reason = "consensus dropped receiver",
                "skipping verification"
            );
            return None;
        },
        valid = validity_request => valid,
    };

    if application_valid {
        marshal.verified(context.round, block).await;
    }
    Some(application_valid)
}

#[inline]
pub(super) async fn fetch_parent<E, S, A, B>(
    parent_digest: B::Digest,
    parent_round: Option<Round>,
    application: &mut A,
    marshal: &mut Mailbox<S, Standard<B>>,
) -> Either<Ready<Result<B, RecvError>>, oneshot::Receiver<B>>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: Application<E, Block = B, Context = Context<B::Digest, S::PublicKey>>,
    B: Block + Clone,
{
    let genesis = application.genesis().await;
    if parent_digest == genesis.digest() {
        Either::Left(ready(Ok(genesis)))
    } else {
        Either::Right(
            marshal
                .subscribe_by_digest(parent_round, parent_digest)
                .await,
        )
    }
}
