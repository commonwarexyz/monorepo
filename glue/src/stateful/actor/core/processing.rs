use crate::stateful::{
    actor::{
        core::mailbox::Message,
        processor::{FinalizeStatus, Processor},
    },
    Application,
};
use commonware_actor::mailbox as actor_mailbox;
use commonware_consensus::marshal::{
    ancestry::BlockProvider,
    core::{Mailbox as MarshalMailbox, Variant},
};
use commonware_cryptography::certificate::Scheme;
use commonware_macros::select_loop;
use commonware_runtime::{Clock, ContextCell, Metrics, Spawner};
use commonware_utils::{channel::fallible::OneshotExt, Acknowledgement};
use rand::Rng;
use tracing::debug;

pub(super) struct Processing<E, A, S, V, R>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    S: Scheme,
    V: Variant<ApplicationBlock = A::Block>,
{
    /// Runtime context.
    pub(super) context: ContextCell<E>,

    /// Actor ingress.
    pub(super) mailbox: actor_mailbox::Receiver<Message<E, A>>,

    /// Source of input (e.g. transactions) passed to the application on propose.
    pub(super) input_provider: A::InputProvider,

    /// Marshal mailbox used for lazy block lookup.
    pub(super) marshal: MarshalMailbox<S, V>,

    /// State sync resolvers stay alive here so peers can keep syncing from us.
    #[expect(
        dead_code,
        reason = "processing keeps resolver handles alive for peer state sync"
    )]
    pub(super) resolvers: R,

    /// The processing state of the actor.
    pub(super) processor: Processor<E, A>,
}

impl<E, A, S, V, R> Processing<E, A, S, V, R>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    S: Scheme,
    V: Variant<ApplicationBlock = A::Block>,
    MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
{
    pub async fn start(mut self) {
        select_loop! {
            self.context,
            on_stopped => {
                debug!("processor received shutdown signal");
            },
            Some(message) = self.mailbox.recv() else {
                debug!("mailbox closed, shutting down processor");
                break;
            } => match message {
                Message::Propose {
                    context,
                    ancestry,
                    response,
                } => {
                    self.processor
                        .propose(
                            self.context.as_present(),
                            self.marshal.clone(),
                            context,
                            ancestry,
                            &mut self.input_provider,
                            response,
                        )
                        .await;
                }
                Message::Verify {
                    context,
                    ancestry,
                    response,
                } => {
                    self.processor
                        .verify(
                            self.context.as_present(),
                            self.marshal.clone(),
                            context,
                            ancestry,
                            response,
                        )
                        .await;
                }
                Message::Finalized {
                    block,
                    acknowledgement,
                } => {
                    if let FinalizeStatus::Persisted { height } =
                        self.processor.finalize(&self.context, block).await
                    {
                        debug!(height = height.get(), "persisted finalized database batch");
                    }
                    acknowledgement.acknowledge();
                }
                Message::SubscribeDatabases { response } => {
                    response.send_lossy(self.processor.databases().clone());
                }
            },
        }
    }
}
