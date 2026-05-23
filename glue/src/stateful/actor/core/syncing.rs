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
use commonware_cryptography::certificate::Scheme;
use commonware_macros::select_loop;
use commonware_runtime::{Clock, ContextCell, Metrics, Spawner};
use commonware_utils::{
    acknowledgement::Exact,
    channel::{fallible::OneshotExt, oneshot},
    Acknowledgement,
};
use rand::Rng;
use tracing::debug;

/// Verify request buffered while startup sync is still in progress.
pub(super) struct HeldVerify<C, B> {
    context: C,
    ancestry: ErasedAncestorStream<B>,
    response: oneshot::Sender<bool>,
}

pub(super) struct Syncing<E, A, S, V, R>
where
    E: Rng + Spawner + Metrics + Clock,
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

    /// Syncer actor mailbox.
    pub(super) syncer: syncer::Mailbox<E, A>,

    /// Verify requests held while syncing.
    pub(super) held_verify_requests: Vec<HeldVerify<(E, A::Context), A::Block>>,

    /// Open subscriptions to the synced databases.
    pub(super) database_subscribers: Vec<oneshot::Sender<A::Databases>>,

    /// The cached [`SyncResult`], populated when sync completes.
    pub(super) artifact: Option<SyncResult<E, A>>,

    /// The state sync resolvers used for startup sync fetching and post-bootstrap
    /// serving.
    pub(super) resolvers: R,
}

impl<E, A, S, V, R> Syncing<E, A, S, V, R>
where
    E: Rng + Spawner + Metrics + Clock,
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
                } => {
                    if let Some((block, acknowledgement)) =
                        self.process_finalized(block, acknowledgement).await
                    {
                        self.transition(block, acknowledgement).await;
                        return;
                    }
                }
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
    ) -> Option<(A::Block, Exact)> {
        if self.artifact.is_none() {
            self.artifact = self.syncer.try_finish().await;
        }

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
                    return None;
                }
            }
        }

        let artifact = self
            .artifact
            .as_ref()
            .expect("sync artifact must exist after sync handoff");

        // The sync anchor can only advance from finalized blocks that this actor already
        // forwarded through the observation barrier, and marshal reports finalized blocks
        // in strict height order. By the time sync completes, the next finalized block we
        // see must therefore be the first post-sync block.
        assert_eq!(
            block.height(),
            artifact.anchor.height.next(),
            "marshal must deliver the first post-sync finalized block immediately after the sync anchor",
        );

        Some((block, acknowledgement))
    }

    /// Transitions to [`Processing`] state following the alignment of marshal's processed height
    /// on the converged database [`Anchor`].
    async fn transition(mut self, handoff_finalized: A::Block, acknowledgement: Exact) {
        let artifact = self.artifact.take().expect("transition must have artifact");

        let metrics = ProcessorMetrics::new(self.context.child("processor_metrics"));
        let mut processor = Processor::new(
            self.application,
            artifact.databases,
            artifact.anchor,
            metrics,
        );

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
