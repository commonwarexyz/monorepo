use crate::{
    types::{Epoch, Round},
    Automaton, CertifiableAutomaton, Monitor, Relay, Reporter,
};
use commonware_cryptography::{Digest, PublicKey};
use commonware_utils::{
    channel::{mpsc, oneshot},
    sync::AsyncMutex,
};
use std::sync::Arc;

pub struct Shared<T>(Arc<AsyncMutex<T>>);

impl<T> Shared<T> {
    pub fn new(value: T) -> Self {
        Self(Arc::new(AsyncMutex::new(value)))
    }
}

impl<T> Clone for Shared<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> Automaton for Shared<T>
where
    T: Automaton,
    T::Context: Send,
    T::Digest: Send,
{
    type Context = T::Context;
    type Digest = T::Digest;

    async fn genesis(&mut self, epoch: Epoch) -> Self::Digest {
        self.0.lock().await.genesis(epoch).await
    }

    async fn propose(&mut self, context: Self::Context) -> oneshot::Receiver<Self::Digest> {
        self.0.lock().await.propose(context).await
    }

    async fn verify(
        &mut self,
        context: Self::Context,
        payload: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        self.0.lock().await.verify(context, payload).await
    }
}

impl<T> CertifiableAutomaton for Shared<T>
where
    T: CertifiableAutomaton,
    T::Context: Send,
    T::Digest: Send,
{
    async fn certify(&mut self, round: Round, payload: Self::Digest) -> oneshot::Receiver<bool> {
        self.0.lock().await.certify(round, payload).await
    }
}

impl<T> Relay for Shared<T>
where
    T: Relay,
    T::Digest: Digest + Send,
    T::PublicKey: PublicKey + Send,
    T::Plan: Send,
{
    type Digest = T::Digest;
    type PublicKey = T::PublicKey;
    type Plan = T::Plan;

    async fn broadcast(&mut self, payload: Self::Digest, plan: Self::Plan) {
        self.0.lock().await.broadcast(payload, plan).await
    }
}

impl<T> Reporter for Shared<T>
where
    T: Reporter,
    T::Activity: Send,
{
    type Activity = T::Activity;

    async fn report(&mut self, activity: Self::Activity) {
        self.0.lock().await.report(activity).await
    }
}

impl<T> Monitor for Shared<T>
where
    T: Monitor,
    T::Index: Send,
{
    type Index = T::Index;

    async fn subscribe(&mut self) -> (Self::Index, mpsc::Receiver<Self::Index>) {
        self.0.lock().await.subscribe().await
    }
}
