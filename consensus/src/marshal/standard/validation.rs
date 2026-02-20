use crate::{
    marshal::{
        ancestry::AncestorStream,
        application::validation::{
            has_contiguous_height, is_block_in_expected_epoch, is_valid_reproposal_at_verify,
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

/// Validation failures for standard deferred verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StandardBlockVerificationError {
    ParentDigest,
    ExpectedParentDigest,
    Height,
}

/// Consolidated validation for standard deferred verification.
#[inline]
pub(crate) fn validate_standard_block_for_verification<B>(
    block: &B,
    parent: &B,
    parent_digest: B::Digest,
) -> Result<(), StandardBlockVerificationError>
where
    B: Block,
{
    if block.parent() != parent.digest() {
        return Err(StandardBlockVerificationError::ParentDigest);
    }
    if parent.digest() != parent_digest {
        return Err(StandardBlockVerificationError::ExpectedParentDigest);
    }
    if !has_contiguous_height(parent.height(), block.height()) {
        return Err(StandardBlockVerificationError::Height);
    }
    Ok(())
}

/// Result of the shared epoch / re-proposal pre-check step.
///
/// `Complete(valid)` indicates verification can terminate immediately with `valid`.
/// `Continue(block)` indicates full parent + application verification should continue.
pub(super) enum Decision<B> {
    Complete(bool),
    Continue(B),
}

/// Performs shared pre-checks used by both inline and deferred verification paths.
///
/// This enforces:
/// - Block height belongs to the expected epoch.
/// - Re-proposal validation when `digest == context.parent.1`.
///
/// Valid re-proposals are immediately marked verified in marshal and return `Complete(true)`.
#[inline]
pub(super) async fn precheck_epoch_and_reproposal<ES, S, B>(
    epocher: &ES,
    marshal: &mut Mailbox<S, Standard<B>>,
    context: &Context<B::Digest, S::PublicKey>,
    digest: B::Digest,
    block: B,
) -> Decision<B>
where
    ES: Epocher,
    S: Scheme,
    B: Block + Clone,
{
    // Block heights must map to the expected epoch.
    if !is_block_in_expected_epoch(epocher, block.height(), context.epoch()) {
        debug!(
            height = %block.height(),
            "block height not in expected epoch"
        );
        return Decision::Complete(false);
    }

    // Re-proposals are signaled by `digest == context.parent.1`.
    // They skip normal parent/height checks because:
    // 1. The block was already verified when originally proposed.
    // 2. Parent-child checks would fail by construction when parent == block.
    if digest == context.parent.1 {
        if !is_valid_reproposal_at_verify(epocher, block.height(), context.epoch()) {
            debug!(
                height = %block.height(),
                "re-proposal is not at epoch boundary"
            );
            return Decision::Complete(false);
        }

        marshal.verified(context.round, block).await;
        return Decision::Complete(true);
    }

    Decision::Continue(block)
}

/// Runs the shared non-reproposal verification flow.
///
/// This fetches the expected parent, validates standard ancestry invariants, then
/// calls application verification over the ancestry stream.
///
/// Returns:
/// - `Some(valid)` when a verification verdict is available.
/// - `None` when work should stop early (e.g., receiver dropped or parent unavailable).
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
        // We are guaranteed that the parent round for any `context` is
        // in the same epoch (recall, the boundary block of the previous epoch
        // is the genesis block of the current epoch).
        Some(Round::new(context.epoch(), parent_view)),
        application,
        marshal,
    )
    .await;
    // If consensus drops the receiver, we can stop work early.
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

    // Validate parent digest and contiguous child height before application logic.
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

    // Request verification from the application over the two-block ancestry prefix.
    let ancestry_stream = AncestorStream::new(marshal.clone(), [block.clone(), parent]);
    let validity_request = application.verify(
        (runtime_context.with_label("app_verify"), context.clone()),
        ancestry_stream,
    );
    // If consensus drops the receiver, we can stop work early.
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

/// Fetches the parent block given its digest and optional round hint.
///
/// If the digest matches genesis, returns genesis directly. Otherwise, subscribes
/// to marshal for parent availability.
///
/// `parent_round` is a resolver hint. Callers should only provide a hint when the
/// source context is trusted/validated. Untrusted paths should pass `None`.
///
/// The returned subscription receiver may resolve with `RecvError` if marshal
/// cancels the request.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Height;
    use bytes::{Buf, BufMut};
    use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt, Write};
    use commonware_cryptography::{sha256::Digest as Sha256Digest, Digestible, Hasher, Sha256};

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct TestBlock {
        digest: Sha256Digest,
        parent: Sha256Digest,
        height: Height,
    }

    impl Write for TestBlock {
        fn write(&self, buf: &mut impl BufMut) {
            self.digest.write(buf);
            self.parent.write(buf);
            self.height.write(buf);
        }
    }

    impl EncodeSize for TestBlock {
        fn encode_size(&self) -> usize {
            self.digest.encode_size() + self.parent.encode_size() + self.height.encode_size()
        }
    }

    impl Read for TestBlock {
        type Cfg = ();

        fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
            let digest = Sha256Digest::read(buf)?;
            let parent = Sha256Digest::read(buf)?;
            let height = Height::read(buf)?;
            Ok(Self {
                digest,
                parent,
                height,
            })
        }
    }

    impl Digestible for TestBlock {
        type Digest = Sha256Digest;

        fn digest(&self) -> Self::Digest {
            self.digest
        }
    }

    impl crate::Heightable for TestBlock {
        fn height(&self) -> Height {
            self.height
        }
    }

    impl crate::Block for TestBlock {
        fn parent(&self) -> Self::Digest {
            self.parent
        }
    }

    fn baseline_blocks() -> (TestBlock, TestBlock) {
        let parent_digest = Sha256::hash(b"parent");
        let parent = TestBlock {
            digest: parent_digest,
            parent: Sha256::hash(b"grandparent"),
            height: Height::new(6),
        };
        let block = TestBlock {
            digest: Sha256::hash(b"block"),
            parent: parent_digest,
            height: Height::new(7),
        };
        (parent, block)
    }

    #[test]
    fn test_validate_standard_block_for_verification_ok() {
        let (parent, block) = baseline_blocks();
        assert_eq!(
            validate_standard_block_for_verification(&block, &parent, parent.digest()),
            Ok(())
        );
    }

    #[test]
    fn test_validate_standard_block_for_verification_parent_digest_error() {
        let (parent, mut block) = baseline_blocks();
        block.parent = Sha256::hash(b"wrong_parent");
        assert_eq!(
            validate_standard_block_for_verification(&block, &parent, parent.digest()),
            Err(StandardBlockVerificationError::ParentDigest)
        );
    }

    #[test]
    fn test_validate_standard_block_for_verification_expected_parent_digest_error() {
        let (parent, block) = baseline_blocks();
        assert_eq!(
            validate_standard_block_for_verification(
                &block,
                &parent,
                Sha256::hash(b"wrong_expected_parent"),
            ),
            Err(StandardBlockVerificationError::ExpectedParentDigest)
        );
    }

    #[test]
    fn test_validate_standard_block_for_verification_height_error() {
        let (parent, mut block) = baseline_blocks();
        block.height = Height::new(9);
        assert_eq!(
            validate_standard_block_for_verification(&block, &parent, parent.digest()),
            Err(StandardBlockVerificationError::Height)
        );
    }
}
