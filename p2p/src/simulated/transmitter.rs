//! Deterministic scheduler for simulated message delivery with bandwidth limits.
//!
//! This module re-exports the generic transmitter from `commonware_runtime::simulated`
//! with peer type parameterized to `PublicKey` and channel type set to `Channel`.

use crate::Channel;

/// Completion with p2p-specific types.
pub type Completion<P> = commonware_runtime::simulated::Completion<P, Channel>;

/// Transmitter state with p2p-specific types.
pub type State<P> = commonware_runtime::simulated::State<P, Channel>;

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use commonware_cryptography::ed25519;
    use std::time::{Duration, SystemTime};

    type TestState = State<ed25519::PublicKey>;

    const CHANNEL: Channel = 0;

    fn make_pk(seed: u64) -> ed25519::PublicKey {
        use commonware_cryptography::{PrivateKeyExt, Signer};
        ed25519::PrivateKey::from_seed(seed).public_key()
    }

    #[test]
    fn queue_immediate_completion_with_unlimited_capacity() {
        let mut state = TestState::new();
        let now = SystemTime::UNIX_EPOCH;
        let origin = make_pk(1);
        let recipient = make_pk(2);

        let completions = state.enqueue(
            now,
            origin,
            recipient,
            CHANNEL,
            Bytes::from_static(b"hello"),
            Duration::ZERO,
            true,
        );

        assert_eq!(completions.len(), 1);
        let completion = &completions[0];
        assert_eq!(completion.deliver_at, Some(now));
    }

    #[test]
    fn queue_dropped_message_records_outcome() {
        let mut state = TestState::new();
        let now = SystemTime::UNIX_EPOCH;
        let origin = make_pk(3);
        let recipient = make_pk(4);

        let completions = state.enqueue(
            now,
            origin,
            recipient,
            CHANNEL,
            Bytes::from_static(b"drop"),
            Duration::ZERO,
            false,
        );

        assert_eq!(completions.len(), 1);
        assert!(completions[0].deliver_at.is_none());
    }

    #[test]
    fn bandwidth_limited_delivery() {
        let mut state = TestState::new();
        let now = SystemTime::UNIX_EPOCH;
        let origin = make_pk(10);
        let recipient = make_pk(11);
        let make_bytes = |value: u8| Bytes::from(vec![value; 1_000]);

        // Set bandwidth limit: 1KB/s egress
        let completions = state.limit(now, &origin, Some(1_000), None);
        assert!(completions.is_empty());

        // Enqueue 1KB message - should take 1 second to transmit
        let completions = state.enqueue(
            now,
            origin.clone(),
            recipient,
            CHANNEL,
            make_bytes(1),
            Duration::from_secs(1), // 1s latency
            true,
        );
        assert!(completions.is_empty());

        // Check next event is 1 second in the future
        let first_finish = state.next().expect("first completion scheduled");
        assert_eq!(first_finish, now + Duration::from_secs(1));

        // Advance to completion
        let completions = state.advance(first_finish);
        assert_eq!(completions.len(), 1);
        let completion = &completions[0];
        // Message completes at first_finish, arrives 1s later due to latency
        assert_eq!(
            completion.deliver_at,
            Some(first_finish + Duration::from_secs(1))
        );
    }
}
