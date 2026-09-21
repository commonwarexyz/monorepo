//! Route a whole delivery to an actor through its response channels.

use crate::{Consumer, Delivery, Outcome};
use commonware_utils::{Span, channel::oneshot, vec::NonEmptyVec};
use std::{future::Future, marker::PhantomData};

/// One candidate and the verdict for its complete demand snapshot.
///
/// Every route in the snapshot must be consumed by the same logical actor.
/// The actor validates this response once for all of its subscribers.
pub struct Response<K, S, V, O = Outcome> {
    /// Key and exact response routes included in this delivery.
    pub delivery: Delivery<K, S, Self>,
    /// Data returned for the key.
    pub value: V,
    /// Aggregate validity and completion verdict for this delivery.
    pub verdict: oneshot::Sender<O>,
}

/// Routes one delivery batch through one of its open response channels.
///
/// All channels must belong to one logical consumer of the complete snapshot.
/// Independent callers requiring individual responses should implement [Consumer]
/// with their own fanout instead.
pub struct ChannelConsumer<K, S, V, O = Outcome>(
    // This stateless consumer does not inherit auto-trait bounds from response data.
    #[allow(clippy::type_complexity)] PhantomData<fn() -> Response<K, S, V, O>>,
);

impl<K, S, V, O> Default for ChannelConsumer<K, S, V, O> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<K, S, V, O> Clone for ChannelConsumer<K, S, V, O> {
    fn clone(&self) -> Self {
        Self::default()
    }
}

impl<K, S, V, O> Consumer for ChannelConsumer<K, S, V, O>
where
    K: Span,
    S: Clone + Eq + Send + 'static,
    V: Clone + Send + 'static,
    O: Into<Outcome> + Send + 'static,
{
    type Key = K;
    type Subscriber = S;
    type Value = V;
    type Response = Response<K, S, V, O>;
    type Outcome = O;

    fn deliver(
        &mut self,
        delivery: Delivery<K, S, Self::Response>,
        value: V,
    ) -> impl Future<Output = Option<O>> + Send + 'static {
        let mut subscribers = delivery.subscribers.into_vec();
        async move {
            loop {
                subscribers.retain(|subscriber| !subscriber.response.is_closed());
                let pending = NonEmptyVec::try_from(subscribers.clone()).ok()?;
                let route = pending.first().response.clone();
                let (verdict, receiver) = oneshot::channel();
                let response = Response {
                    delivery: Delivery {
                        key: delivery.key.clone(),
                        subscribers: pending,
                    },
                    value: value.clone(),
                    verdict,
                };
                if route.send(response).await.is_err() {
                    continue;
                }

                // Once dequeued, the batch owns its verdict even if its selected route closes.
                // Dropping a still-queued batch drops this verdict and permits another route.
                match receiver.await {
                    Ok(outcome) => return Some(outcome),
                    Err(_) if route.is_closed() => {}
                    Err(_) => return None,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Subscriber, p2p::mocks::Key};
    use commonware_runtime::{Runner as _, deterministic::Runner};
    use commonware_utils::{channel::mpsc, non_empty_vec};
    use futures::FutureExt as _;

    type Candidate = Response<Key, u8, u8>;

    fn route(subscriber: u8) -> (Subscriber<u8, Candidate>, mpsc::Receiver<Candidate>) {
        let (response, receiver) = mpsc::channel(1);
        (
            Subscriber {
                subscriber,
                response,
                span: tracing::Span::none(),
            },
            receiver,
        )
    }

    #[test]
    fn closed_queued_route_hands_batch_to_survivor() {
        Runner::default().start(|_| async move {
            let (first, first_receiver) = route(1);
            let (second, mut second_receiver) = route(2);
            let mut consumer = ChannelConsumer::<Key, u8, u8>::default();
            let delivery = Delivery {
                key: Key(7),
                subscribers: non_empty_vec![first, second],
            };
            let mut future = Box::pin(consumer.deliver(delivery, 9));
            assert!(future.as_mut().now_or_never().is_none());
            assert!(second_receiver.try_recv().is_err());

            drop(first_receiver);
            assert!(future.as_mut().now_or_never().is_none());
            let response = second_receiver.try_recv().expect("surviving route");
            assert_eq!(response.value, 9);
            assert_eq!(response.delivery.subscribers.len().get(), 1);
            assert_eq!(response.delivery.subscribers.first().subscriber, 2);
            response.verdict.send(Outcome::Complete).unwrap();
            assert_eq!(future.await, Some(Outcome::Complete));
        });
    }

    #[test]
    fn closing_dequeued_route_does_not_replay_pending_validation() {
        Runner::default().start(|_| async move {
            let (first, mut first_receiver) = route(1);
            let (second, mut second_receiver) = route(2);
            let mut consumer = ChannelConsumer::<Key, u8, u8>::default();
            let delivery = Delivery {
                key: Key(7),
                subscribers: non_empty_vec![first, second],
            };
            let mut future = Box::pin(consumer.deliver(delivery, 9));
            assert!(future.as_mut().now_or_never().is_none());
            let response = first_receiver.try_recv().expect("selected route");
            assert_eq!(response.delivery.subscribers.len().get(), 2);

            drop(first_receiver);
            assert!(future.as_mut().now_or_never().is_none());
            assert!(second_receiver.try_recv().is_err());
            response.verdict.send(Outcome::Ambiguous).unwrap();
            assert_eq!(future.await, Some(Outcome::Ambiguous));
            assert!(second_receiver.try_recv().is_err());
        });
    }

    #[test]
    fn dropped_verdict_on_open_route_abstains_without_replay() {
        Runner::default().start(|_| async move {
            let (first, mut first_receiver) = route(1);
            let (second, mut second_receiver) = route(2);
            let mut consumer = ChannelConsumer::<Key, u8, u8>::default();
            let delivery = Delivery {
                key: Key(7),
                subscribers: non_empty_vec![first, second],
            };
            let mut future = Box::pin(consumer.deliver(delivery, 9));
            assert!(future.as_mut().now_or_never().is_none());
            drop(first_receiver.try_recv().expect("selected route"));
            assert_eq!(future.await, None);
            assert!(second_receiver.try_recv().is_err());
        });
    }

    #[test]
    fn all_closed_routes_abstain() {
        Runner::default().start(|_| async move {
            let (first, first_receiver) = route(1);
            let (second, second_receiver) = route(2);
            let mut consumer = ChannelConsumer::<Key, u8, u8>::default();
            let delivery = Delivery {
                key: Key(7),
                subscribers: non_empty_vec![first, second],
            };
            let mut future = Box::pin(consumer.deliver(delivery, 9));
            assert!(future.as_mut().now_or_never().is_none());
            drop(first_receiver);
            drop(second_receiver);
            assert_eq!(future.await, None);
        });
    }
}
