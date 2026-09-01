//! Bounded history of marshal's total order for the terminal UI.

use crate::application::Block;
use commonware_actor::Feedback;
use commonware_consensus::{Reporter, multimmit::marshal::Update};
use commonware_cryptography::sha256::Digest as Sha256Digest;
use commonware_utils::{Acknowledgement as _, channel::mpsc, sync::Mutex};
use std::{collections::VecDeque, sync::Arc};

/// Most recent ordered blocks kept for the total-order pane.
const ORDERING_CAPACITY: usize = 10_000;

/// Compact coordinates of one block in the total order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct OrderedBlock {
    /// Marshal-local output index.
    pub(super) index: u64,
    pub(super) chain: u32,
    pub(super) height: u64,
    pub(super) digest: Sha256Digest,
}

/// Bounded observer for marshal's total order that acknowledges every block.
#[derive(Clone)]
pub struct OrderedReporter {
    ordering: Arc<Mutex<VecDeque<OrderedBlock>>>,
    redraws: mpsc::Sender<()>,
}

impl OrderedReporter {
    /// Creates a reporter and the receiver it signals after each delivery.
    pub(super) fn channel() -> (Self, mpsc::Receiver<()>) {
        let (redraws, receiver) = mpsc::channel(1);
        (
            Self {
                ordering: Arc::default(),
                redraws,
            },
            receiver,
        )
    }

    /// Returns the retained history, oldest first.
    pub(super) fn snapshot(&self) -> Vec<OrderedBlock> {
        self.ordering.lock().iter().copied().collect()
    }
}

impl Reporter for OrderedReporter {
    type Activity = Update<Block>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        let Update {
            index,
            block,
            acknowledgement,
        } = activity;
        let reference = block.reference();
        let ordered = OrderedBlock {
            index: index.get(),
            chain: reference.chain().get(),
            height: reference.height().get(),
            digest: reference.digest(),
        };
        let mut ordering = self.ordering.lock();
        if ordering.len() == ORDERING_CAPACITY {
            ordering.pop_front();
        }
        ordering.push_back(ordered);
        drop(ordering);
        let _ = self.redraws.try_send(());
        acknowledgement.acknowledge();
        Feedback::Ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::Body;
    use bytes::Bytes;
    use commonware_codec::{Encode as _, Read as _};
    use commonware_consensus::{
        multimmit::{
            marshal::OutputIndex,
            types::{ChainId, Context as BlockContext},
        },
        types::{Epoch, Height},
    };
    use commonware_cryptography::{Hasher as _, Sha256};
    use commonware_utils::acknowledgement::Exact;
    use std::{future::Future as _, pin::Pin, task::Poll};

    #[test]
    fn ordered_reporter_acknowledges_and_bounds_history() {
        let context = BlockContext::new(
            Epoch::new(7),
            ChainId::new(2),
            Height::new(11),
            Sha256::hash(&[b"parent"]),
        )
        .unwrap();
        let mut encoded = Bytes::from_static(b"body").encode();
        let body = Body::read_cfg(&mut encoded, &Body::codec_config(4)).unwrap();
        let block = Arc::new(Block::from_context(context, body));
        let reference = block.reference();
        let (mut reporter, mut redraws) = OrderedReporter::channel();

        for index in 0..=ORDERING_CAPACITY {
            let (acknowledgement, mut waiter) = Exact::handle();
            assert_eq!(
                reporter.report(Update {
                    index: OutputIndex::new(index as u64),
                    block: Arc::clone(&block),
                    acknowledgement,
                }),
                Feedback::Ok
            );
            assert!(matches!(
                Pin::new(&mut waiter)
                    .poll(&mut std::task::Context::from_waker(std::task::Waker::noop())),
                Poll::Ready(Ok(()))
            ));
        }

        let ordering = reporter.snapshot();
        assert_eq!(redraws.try_recv(), Ok(()));
        assert!(redraws.try_recv().is_err());
        assert_eq!(ordering.len(), ORDERING_CAPACITY);
        assert_eq!(ordering.first().unwrap().index, 1);
        assert_eq!(ordering.last().unwrap().index, ORDERING_CAPACITY as u64);
        assert!(ordering.iter().all(|ordered| {
            ordered.chain == reference.chain().get()
                && ordered.height == reference.height().get()
                && ordered.digest == reference.digest()
        }));
    }
}
