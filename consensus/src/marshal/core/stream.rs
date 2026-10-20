use crate::types::{Epoch, Height, Round, View};
use commonware_codec::varint::UInt;
use commonware_storage::{
    Context,
    metadata::{self, Metadata},
};
use commonware_utils::sequence::U64;

/// The key used to store the last processed height in the metadata store.
const LATEST_KEY: U64 = U64::new(0xFF);
/// The keys used to store the epoch and view of the processed round floor.
const ROUND_EPOCH_KEY: U64 = U64::new(0xFE);
const ROUND_VIEW_KEY: U64 = U64::new(0xFD);

/// Last block acknowledged by the application.
#[derive(Clone, Copy)]
enum State {
    Unprocessed,
    Processed(Height),
}

impl State {
    const fn new(processed_height: Option<Height>) -> Self {
        match processed_height {
            Some(height) => Self::Processed(height),
            None => Self::Unprocessed,
        }
    }

    const fn processed_height(self) -> Option<Height> {
        match self {
            Self::Unprocessed => None,
            Self::Processed(height) => Some(height),
        }
    }

    const fn next_height(self) -> Height {
        match self {
            Self::Unprocessed => Height::zero(),
            Self::Processed(height) => height.next(),
        }
    }

    const fn acknowledge(&mut self, height: Height) {
        *self = Self::Processed(height);
    }
}

/// Application delivery stream progress, the processed round floor, and their durable metadata.
///
/// Entries are varint integers under fixed keys, so the processed height and the round floor
/// share one store and one sync.
pub(super) struct Stream<E: Context> {
    metadata: Metadata<E, U64, UInt<u64>>,
    state: State,
}

impl<E: Context> Stream<E> {
    pub(super) async fn new(context: E, application_metadata_partition: &str) -> Self {
        let metadata: Metadata<E, U64, UInt<u64>> = Metadata::init(
            context,
            metadata::Config {
                partition: application_metadata_partition.to_string(),
                codec_config: (),
            },
        )
        .await
        .expect("failed to initialize application metadata");
        let state = State::new(
            metadata
                .get(&LATEST_KEY)
                .map(|height| Height::new(height.0)),
        );
        Self { metadata, state }
    }

    pub(super) const fn processed_height(&self) -> Option<Height> {
        self.state.processed_height()
    }

    pub(super) const fn next_height(&self) -> Height {
        self.state.next_height()
    }

    /// Returns the durable processed round floor, or zero if none was recorded.
    pub(super) fn round(&self) -> Round {
        match (
            self.metadata.get(&ROUND_EPOCH_KEY),
            self.metadata.get(&ROUND_VIEW_KEY),
        ) {
            (Some(epoch), Some(view)) => Round::new(Epoch::new(epoch.0), View::new(view.0)),
            _ => Round::zero(),
        }
    }

    pub(super) fn acknowledge(&mut self, height: Height) {
        self.state.acknowledge(height);
        self.metadata.put(LATEST_KEY, UInt(height.get()));
    }

    /// Buffers the processed round floor. The next [Self::sync] makes it durable.
    pub(super) fn set_round(&mut self, round: Round) {
        self.metadata
            .put(ROUND_EPOCH_KEY, UInt(round.epoch().get()));
        self.metadata.put(ROUND_VIEW_KEY, UInt(round.view().get()));
    }

    pub(super) async fn sync(mut self) -> Result<Self, metadata::Error> {
        self.metadata = self.metadata.sync().await?;
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};

    const PARTITION: &str = "stream-metadata";

    /// Opens the partition with the processed height as its only entry, which is the layout
    /// written before the round floor was recorded.
    async fn seed_processed_height(context: deterministic::Context, height: Height) {
        let mut metadata: Metadata<deterministic::Context, U64, Height> = Metadata::init(
            context,
            metadata::Config {
                partition: PARTITION.to_string(),
                codec_config: (),
            },
        )
        .await
        .expect("failed to initialize metadata");
        metadata.put(LATEST_KEY, height);
        metadata.sync().await.expect("failed to sync metadata");
    }

    #[test]
    fn test_round_floor_round_trips_beside_processed_height() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            seed_processed_height(context.child("seed"), Height::new(7)).await;

            let mut stream = Stream::new(context.child("first"), PARTITION).await;
            assert_eq!(stream.processed_height(), Some(Height::new(7)));
            assert_eq!(stream.round(), Round::zero());

            let round = Round::new(Epoch::new(2), View::new(40));
            stream.set_round(round);
            stream.acknowledge(Height::new(8));
            let stream = stream.sync().await.expect("failed to sync stream");
            drop(stream);

            let stream = Stream::new(context.child("second"), PARTITION).await;
            assert_eq!(stream.processed_height(), Some(Height::new(8)));
            assert_eq!(stream.round(), round);
        });
    }
}
