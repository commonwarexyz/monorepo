use crate::stateful::{
    actor::{
        core::{
            mailbox::{ErasedAncestorStream, Message},
            processing::Processing,
        },
        processor::{FinalizeStatus, Processor, ProcessorMetrics},
        syncer::{self, SyncResult},
    },
    db::{Anchor, AttachableResolverSet},
    Application,
};
use commonware_actor::mailbox as actor_mailbox;
use commonware_consensus::{
    marshal::{
        ancestry::BlockProvider,
        core::{Mailbox as MarshalMailbox, Variant},
    },
    Epochable, Heightable, Viewable,
};
use commonware_cryptography::{certificate::Scheme, Digestible};
use commonware_macros::select_loop;
use commonware_runtime::{Clock, ContextCell, Metrics, Spawner, Storage};
use commonware_utils::{
    acknowledgement::Exact,
    channel::{fallible::OneshotExt, oneshot},
    Acknowledgement,
};
use rand::Rng;
use tracing::{debug, error};

/// Verify request buffered while startup sync is still in progress.
pub(super) struct HeldVerify<C, B> {
    context: C,
    ancestry: ErasedAncestorStream<B>,
    response: oneshot::Sender<bool>,
}

type HeldVerifyRequest<E, A> =
    HeldVerify<(E, <A as Application<E>>::Context), <A as Application<E>>::Block>;

enum FinalizedAction<B> {
    Continue,
    Transition(Option<(B, Exact)>),
}

pub(super) struct Syncing<E, A, S, V, R>
where
    E: Rng + Spawner + Metrics + Clock + Storage,
    A: Application<E>,
    S: Scheme,
    V: Variant<ApplicationBlock = A::Block>,
    R: AttachableResolverSet<A::Databases>,
{
    /// Runtime context.
    pub(super) context: ContextCell<E>,

    /// Actor ingress.
    pub(super) mailbox: actor_mailbox::Receiver<Message<E, A>>,

    /// Inner application.
    pub(super) application: A,

    /// Source of input (e.g. transactions) passed to the application on propose.
    pub(super) input_provider: A::InputProvider,

    /// Marshal actor mailbox.
    pub(super) marshal: MarshalMailbox<S, V>,

    /// Prefix for durable state-sync metadata.
    pub(super) partition_prefix: String,

    /// Syncer actor mailbox.
    pub(super) syncer: syncer::Mailbox<E, A>,

    /// Verify requests held while syncing.
    pub(super) held_verify_requests: Vec<HeldVerifyRequest<E, A>>,

    /// Open subscriptions to the synced databases.
    pub(super) database_subscribers: Vec<oneshot::Sender<A::Databases>>,

    /// The cached [`SyncResult`], populated when sync completes.
    pub(super) artifact: Option<SyncResult<E, A>>,

    /// The state sync resolvers used for startup sync fetching and post-bootstrap
    /// serving.
    pub(super) resolvers: R,

    /// Signals that the syncer has produced a usable artifact.
    pub(super) sync_completed: oneshot::Receiver<SyncResult<E, A>>,
}

impl<E, A, S, V, R> Syncing<E, A, S, V, R>
where
    E: Rng + Spawner + Metrics + Clock + Storage,
    A: Application<E>,
    S: Scheme,
    V: Variant<ApplicationBlock = A::Block>,
    R: AttachableResolverSet<A::Databases>,
    MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
{
    pub async fn start(mut self) {
        select_loop! {
            self.context,
            on_start => {
                self.held_verify_requests
                    .retain(|request| !request.response.is_closed());
                self.database_subscribers
                    .retain(|subscriber| !subscriber.is_closed());
            },
            on_stopped => {
                debug!("processor received shutdown signal");
            },
            Ok(artifact) = &mut self.sync_completed else {
                error!("syncer stopped before publishing state sync artifact");
                break;
            } => {
                self.artifact = Some(artifact);
                self.transition(None).await;
                return;
            },
            Some(message) = self.mailbox.recv() else {
                debug!("mailbox closed, shutting down processor");
                break;
            } => match message {
                Message::Propose {
                    context: (_, context),
                    response,
                    ..
                } => {
                    debug!(epoch = %context.epoch(), view = %context.view(), "proposal rejected: state sync in progress");
                    response.send_lossy(None);
                }
                Message::Verify {
                    context,
                    ancestry,
                    response,
                } => {
                    self.held_verify_requests
                        .retain(|request| !request.response.is_closed());
                    self.held_verify_requests.push(HeldVerify {
                        context,
                        ancestry,
                        response,
                    });
                    debug!(
                        held_verify_requests = self.held_verify_requests.len(),
                        "verify held: state sync in progress"
                    );
                }
                Message::Finalized {
                    block,
                    acknowledgement,
                } => match self.process_finalized(block, acknowledgement).await {
                    FinalizedAction::Continue => {}
                    FinalizedAction::Transition(handoff) => {
                        self.transition(handoff).await;
                        return;
                    }
                },
                Message::SubscribeDatabases { response } => {
                    self.database_subscribers
                        .retain(|subscriber| !subscriber.is_closed());
                    if !response.is_closed() {
                        self.database_subscribers.push(response);
                    }
                }
            },
        }
    }

    /// Processes a finalized block during state sync.
    async fn process_finalized(
        &mut self,
        block: A::Block,
        acknowledgement: Exact,
    ) -> FinalizedAction<A::Block> {
        if self.artifact.is_none() {
            let anchor = Anchor::from(&block);
            let targets = A::sync_targets(&block);

            // Do not acknowledge marshal until the live sync session has recorded this
            // block's tip update. If we ack after merely enqueueing it, sync can still
            // complete on the previous anchor and handoff would observe marshal ahead of
            // `artifact.anchor.height.next()`.
            match self.syncer.update_targets(anchor, targets).await {
                Some(artifact) => {
                    self.artifact = Some(artifact);
                }
                None => {
                    acknowledgement.acknowledge();
                    return FinalizedAction::Continue;
                }
            }
        }

        let artifact = self
            .artifact
            .as_ref()
            .expect("sync artifact must exist after sync handoff");

        finalized_action_for_anchor(artifact.anchor, block, acknowledgement)
    }

    /// Transitions to [`Processing`] state following the alignment of marshal's processed height
    /// on the converged database [`Anchor`].
    async fn transition(mut self, handoff: Option<(A::Block, Exact)>) {
        let artifact = self.artifact.take().expect("transition must have artifact");
        let synced_height = artifact.anchor.height;

        let metrics = ProcessorMetrics::new(self.context.child("processor_metrics"));
        let mut processor = Processor::new(
            self.application,
            artifact.databases,
            artifact.anchor,
            metrics,
        );

        if let Some((handoff_finalized, acknowledgement)) = handoff {
            if let FinalizeStatus::Persisted { height } = processor
                .finalize(self.context.as_present(), handoff_finalized)
                .await
            {
                debug!(
                    height = height.get(),
                    "persisted finalized database batch during sync handoff"
                );
            }
            acknowledgement.acknowledge();
        }

        let marshal = self.marshal.clone();
        let partition_prefix = self.partition_prefix.clone();
        self.context
            .as_present()
            .child("state_sync_complete")
            .spawn(move |context| async move {
                if marshal.wait_processed_height(synced_height).await {
                    syncer::set_sync_complete(&context, partition_prefix.as_str()).await;
                }
            });

        // Attach the resolvers to the initialized databases before starting the processor,
        // so that this instance can serve peers database operations and proofs.
        self.resolvers
            .attach_databases(processor.databases().clone())
            .await;

        // `subscribe_databases` promises a database set that is already attached to the
        // serving actor, so keep subscribers waiting until the resolver handoff is complete.
        for subscriber in self.database_subscribers.drain(..) {
            subscriber.send_lossy(processor.databases().clone());
        }

        for request in self.held_verify_requests.drain(..) {
            processor
                .verify(
                    self.context.as_present(),
                    self.marshal.clone(),
                    request.context,
                    request.ancestry,
                    request.response,
                )
                .await;
        }

        Processing {
            context: self.context,
            mailbox: self.mailbox,
            input_provider: self.input_provider,
            marshal: self.marshal,
            resolvers: self.resolvers,
            processor,
        }
        .start()
        .await
    }
}

fn finalized_action_for_anchor<B>(
    anchor: Anchor<B::Digest>,
    block: B,
    acknowledgement: Exact,
) -> FinalizedAction<B>
where
    B: Heightable + Digestible,
{
    if block.height() == anchor.height {
        assert!(
            block.digest() == anchor.digest,
            "marshal delivered a conflicting finalized block at the sync anchor height",
        );
        acknowledgement.acknowledge();
        return FinalizedAction::Transition(None);
    }

    // The sync anchor can only advance from finalized blocks that this actor already
    // forwarded through the observation barrier, and marshal reports finalized blocks
    // in strict height order. By the time sync completes, any non-anchor finalized block
    // we see must therefore be the first post-sync block.
    assert_eq!(
        block.height(),
        anchor.height.next(),
        "marshal must deliver the first post-sync finalized block immediately after the sync anchor",
    );

    FinalizedAction::Transition(Some((block, acknowledgement)))
}

#[cfg(test)]
mod tests {
    use super::{finalized_action_for_anchor, FinalizedAction};
    use crate::stateful::db::Anchor;
    use commonware_consensus::{
        types::{Epoch, Height, Round, View},
        Heightable,
    };
    use commonware_cryptography::{sha256, Digestible};
    use commonware_utils::{acknowledgement::Exact, Acknowledgement};
    use futures::FutureExt as _;

    #[derive(Clone)]
    struct TestBlock {
        height: Height,
        digest: sha256::Digest,
    }

    impl Digestible for TestBlock {
        type Digest = sha256::Digest;

        fn digest(&self) -> Self::Digest {
            self.digest
        }
    }

    impl Heightable for TestBlock {
        fn height(&self) -> Height {
            self.height
        }
    }

    fn test_anchor(height: Height, digest: sha256::Digest) -> Anchor<sha256::Digest> {
        Anchor {
            height,
            round: Round::new(Epoch::zero(), View::zero()),
            digest,
        }
    }

    #[test]
    fn finalized_anchor_block_acknowledges_without_handoff() {
        let digest = sha256::Digest::from([1; 32]);
        let anchor = test_anchor(Height::new(7), digest);
        let block = TestBlock {
            height: anchor.height,
            digest,
        };
        let (acknowledgement, waiter) = <Exact as Acknowledgement>::handle();

        match finalized_action_for_anchor(anchor, block, acknowledgement) {
            FinalizedAction::Transition(None) => {}
            FinalizedAction::Transition(Some(_)) => panic!("anchor block should not be handed off"),
            FinalizedAction::Continue => panic!("anchor block should transition"),
        }
        assert!(matches!(waiter.now_or_never(), Some(Ok(()))));
    }

    #[test]
    fn finalized_next_block_is_handed_off() {
        let digest = sha256::Digest::from([1; 32]);
        let next_digest = sha256::Digest::from([2; 32]);
        let anchor = test_anchor(Height::new(7), digest);
        let block = TestBlock {
            height: anchor.height.next(),
            digest: next_digest,
        };
        let (acknowledgement, waiter) = <Exact as Acknowledgement>::handle();

        match finalized_action_for_anchor(anchor, block, acknowledgement) {
            FinalizedAction::Transition(Some((block, acknowledgement))) => {
                assert_eq!(block.height(), Height::new(8));
                assert!(waiter.now_or_never().is_none());
                acknowledgement.acknowledge();
            }
            FinalizedAction::Transition(None) => panic!("post-anchor block should be handed off"),
            FinalizedAction::Continue => panic!("post-anchor block should transition"),
        }
    }
}
