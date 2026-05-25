//! [`Syncer`](super::Syncer) actor ingress.

use super::SyncResult;
use crate::stateful::{
    db::{Anchor, DatabaseSet, TipUpdate},
    Application,
};
use commonware_actor::mailbox::{Overflow, Policy, Sender};
use commonware_cryptography::Digestible;
use commonware_runtime::{Clock, Metrics, Spawner};
use commonware_utils::channel::oneshot;
use rand::Rng;

type SyncTargets<E, A> = <<A as Application<E>>::Databases as DatabaseSet<E>>::SyncTargets;
type BlockDigest<E, A> = <<A as Application<E>>::Block as Digestible>::Digest;

pub(crate) enum Message<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    UpdateTargets {
        update: TipUpdate<BlockDigest<E, A>, SyncTargets<E, A>>,
        response: oneshot::Sender<Option<SyncResult<E, A>>>,
    },
}

impl<E, A> Overflow<Message<E, A>> for Option<Message<E, A>>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    fn is_empty(&self) -> bool {
        self.is_none()
    }

    fn drain<F>(&mut self, mut push: F)
    where
        F: FnMut(Message<E, A>) -> Self,
    {
        if let Some(message) = self.take() {
            if let Some(message) = push(message) {
                *self = Some(message);
            }
        }
    }
}

impl<E, A> Policy for Message<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    type Overflow = Option<Self>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        *overflow = Some(message);
    }
}

/// Ingress mailbox for the [`Syncer`](super::Syncer) actor.
pub struct Mailbox<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    sender: Sender<Message<E, A>>,
}

impl<E, A> Mailbox<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    pub const fn new(sender: Sender<Message<E, A>>) -> Self {
        Self { sender }
    }

    /// Sends a target update and waits until the live sync coordinator records it.
    ///
    /// If sync already completed before the update could be observed, returns the
    /// completed artifact instead.
    pub async fn update_targets(
        &self,
        anchor: Anchor<BlockDigest<E, A>>,
        targets: SyncTargets<E, A>,
    ) -> Option<SyncResult<E, A>> {
        loop {
            let (update, observed) = TipUpdate::with_observation(anchor, targets.clone());
            let (response, receiver) = oneshot::channel();
            let _ = self
                .sender
                .enqueue(Message::UpdateTargets { update, response });

            match receiver
                .await
                .expect("Syncer should respond to update_targets")
            {
                Some(artifact) => return Some(artifact),
                None => {
                    // The caller acknowledges marshal after this returns. Wait until the
                    // live sync coordinator has actually recorded the new tip update;
                    // enqueueing it into Syncer is not enough to prove the eventual sync
                    // artifact includes this finalized block. If the update was accepted
                    // but the coordinator completed before recording it, retry so Syncer
                    // can return the completed artifact instead.
                    if observed.await.is_ok() {
                        return None;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Mailbox, Message, SyncResult};
    use crate::stateful::{
        db::{Anchor, ManagedDb, Merkleized, Unmerkleized},
        Application, Proposed,
    };
    use commonware_actor::mailbox as actor_mailbox;
    use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
    use commonware_consensus::{
        simplex::types::Context as ConsensusContext,
        types::{Epoch, Height, Round, View},
        CertifiableBlock, Heightable,
    };
    use commonware_cryptography::{
        ed25519,
        sha256::Digest,
        Digest as _, Digestible, Hasher as _, Sha256,
    };
    use commonware_runtime::{deterministic, Runner as _, Supervisor as _};
    use commonware_utils::{
        channel::fallible::OneshotExt,
        sync::AsyncRwLock,
        NZUsize,
    };
    use futures::{join, Stream};
    use std::{convert::Infallible, sync::Arc};

    type TestContext = ConsensusContext<Digest, ed25519::PublicKey>;
    type TestDbSet = Arc<AsyncRwLock<TestDb>>;

    struct TestUnmerkleized;

    struct TestMerkleized;

    impl Unmerkleized for TestUnmerkleized {
        type Merkleized = TestMerkleized;
        type Error = Infallible;

        async fn merkleize(self) -> Result<Self::Merkleized, Self::Error> {
            Ok(TestMerkleized)
        }
    }

    impl Merkleized for TestMerkleized {
        type Digest = Digest;
        type Unmerkleized = TestUnmerkleized;

        fn root(&self) -> Self::Digest {
            Digest::EMPTY
        }

        fn new_batch(&self) -> Self::Unmerkleized {
            TestUnmerkleized
        }
    }

    struct TestDb;

    impl ManagedDb<deterministic::Context> for TestDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = ();
        type SyncTarget = u64;

        async fn init(
            _context: deterministic::Context,
            _config: Self::Config,
        ) -> Result<Self, Self::Error> {
            Ok(Self)
        }

        async fn new_batch(_db: &Arc<AsyncRwLock<Self>>) -> Self::Unmerkleized {
            TestUnmerkleized
        }

        fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
            true
        }

        async fn finalize(&mut self, _batch: Self::Merkleized) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn sync_target(&self) -> Self::SyncTarget {
            0
        }

        async fn rewind_to_target(
            &mut self,
            _target: Self::SyncTarget,
        ) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[derive(Clone)]
    struct TestBlock {
        context: TestContext,
        parent: Digest,
        height: Height,
        digest: Digest,
    }

    impl Write for TestBlock {
        fn write(&self, buf: &mut impl commonware_runtime::BufMut) {
            self.context.write(buf);
            self.parent.write(buf);
            self.height.write(buf);
            self.digest.write(buf);
        }
    }

    impl EncodeSize for TestBlock {
        fn encode_size(&self) -> usize {
            self.context.encode_size()
                + self.parent.encode_size()
                + self.height.encode_size()
                + self.digest.encode_size()
        }
    }

    impl Read for TestBlock {
        type Cfg = ();

        fn read_cfg(
            buf: &mut impl commonware_runtime::Buf,
            _cfg: &Self::Cfg,
        ) -> Result<Self, CodecError> {
            Ok(Self {
                context: TestContext::read(buf)?,
                parent: Digest::read(buf)?,
                height: Height::read(buf)?,
                digest: Digest::read(buf)?,
            })
        }
    }

    impl Digestible for TestBlock {
        type Digest = Digest;

        fn digest(&self) -> Self::Digest {
            self.digest
        }
    }

    impl Heightable for TestBlock {
        fn height(&self) -> Height {
            self.height
        }
    }

    impl commonware_consensus::Block for TestBlock {
        fn parent(&self) -> Self::Digest {
            self.parent
        }
    }

    impl CertifiableBlock for TestBlock {
        type Context = TestContext;

        fn context(&self) -> Self::Context {
            self.context.clone()
        }
    }

    #[derive(Clone)]
    struct TestApp;

    impl Application<deterministic::Context> for TestApp {
        type SigningScheme = commonware_consensus::simplex::mocks::scheme::Scheme<ed25519::PublicKey>;
        type Context = TestContext;
        type Block = TestBlock;
        type Databases = TestDbSet;
        type InputProvider = ();

        async fn genesis(&mut self) -> Self::Block {
            unreachable!("mailbox retry test does not execute the application")
        }

        async fn propose(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _ancestry: impl Stream<Item = Self::Block> + Send,
            _batches: <Self::Databases as crate::stateful::db::DatabaseSet<
                deterministic::Context,
            >>::Unmerkleized,
            _input: &mut Self::InputProvider,
        ) -> Option<Proposed<Self, deterministic::Context>> {
            unreachable!("mailbox retry test does not execute the application")
        }

        async fn verify(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _ancestry: impl Stream<Item = Self::Block> + Send,
            _batches: <Self::Databases as crate::stateful::db::DatabaseSet<
                deterministic::Context,
            >>::Unmerkleized,
        ) -> Option<
            <Self::Databases as crate::stateful::db::DatabaseSet<
                deterministic::Context,
            >>::Merkleized,
        > {
            unreachable!("mailbox retry test does not execute the application")
        }

        async fn apply(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _block: &Self::Block,
            _batches: <Self::Databases as crate::stateful::db::DatabaseSet<
                deterministic::Context,
            >>::Unmerkleized,
        ) -> <Self::Databases as crate::stateful::db::DatabaseSet<deterministic::Context>>::Merkleized
        {
            unreachable!("mailbox retry test does not execute the application")
        }

        fn sync_targets(
            _block: &Self::Block,
        ) -> <Self::Databases as crate::stateful::db::DatabaseSet<
            deterministic::Context,
        >>::SyncTargets {
            0
        }
    }

    fn test_anchor(height: Height, digest: Digest) -> Anchor<Digest> {
        Anchor {
            height,
            round: Round::new(Epoch::zero(), View::zero()),
            digest,
        }
    }

    #[test]
    fn update_targets_retries_when_observation_is_dropped() {
        deterministic::Runner::default().start(|context| async move {
            let (sender, mut receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(1));
            let mailbox = Mailbox::<deterministic::Context, TestApp>::new(sender);
            let anchor = test_anchor(Height::new(3), Sha256::hash(b"anchor"));

            let update_targets = mailbox.update_targets(anchor, 11);
            let drive_syncer = async {
                let Some(Message::UpdateTargets { update, response }) = receiver.recv().await else {
                    panic!("first update should arrive");
                };
                response.send_lossy(None);
                drop(update);

                let Some(Message::UpdateTargets { response, .. }) = receiver.recv().await else {
                    panic!("retry update should arrive");
                };
                response.send_lossy(Some(SyncResult {
                    databases: Arc::new(AsyncRwLock::new(TestDb)),
                    anchor,
                }));
            };

            let (artifact, ()) = join!(update_targets, drive_syncer);
            assert_eq!(
                artifact.expect("retry should return completed artifact").anchor,
                anchor
            );
        });
    }
}
