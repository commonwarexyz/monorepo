use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::{adb::any::Any, index::Translator};
use commonware_utils::Array;

enum ClientEvent {
    GotTip(u64),
}

enum ClientState<E: Storage + Clock + Metrics, K: Array, V: Array, H: Hasher, T: Translator> {
    Init {
        db: Any<E, K, V, H, T>,
        target_index: u64,
        target_hash: H::Digest,
    },
    /// The client sent its max index to the server.
    /// It's waiting for the server to respond.
    FetchingTip {
        db: Any<E, K, V, H, T>,
        target_index: u64,
    },
    Done {
        db: Any<E, K, V, H, T>,
        target_index: u64,
        root_hash: Vec<u8>,
    },
    Errored {
        db: Any<E, K, V, H, T>,
        target_index: u64,
        error: Error,
    },
}

async fn sync<E, K, V, H, T>(db: Any<E, K, V, H, T>, target_index: u64, target_hash: H::Digest)
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
{
    let state = ClientState::Init {
        db,
        target_index,
        target_hash,
    };

    // The actual sync logic would go here, handling the different states.
    // This is a placeholder for the sake of example.
}

#[derive(Debug)]
enum Error {}
