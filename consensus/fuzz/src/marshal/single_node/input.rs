//! Libfuzzer-facing scenario: a byte tape (consumed by `FuzzRng`) plus a
//! length-bounded list of events the driver replays against marshal.

use arbitrary::Arbitrary;

const MIN_EVENTS: usize = 1;
const MAX_EVENTS: usize = 128;

#[derive(Debug, Clone, Copy, Arbitrary)]
pub enum MarshalEvent {
    /// Notify marshal that a block was locally proposed.
    Propose { block_idx: u8 },
    /// Notify marshal that a block was verified.
    Verify { block_idx: u8 },
    /// Notify marshal that a block was certified.
    Certify { block_idx: u8 },
    /// Report a finalization for a block.
    ReportFinalization { block_idx: u8 },
    /// Report a notarization for a block.
    ReportNotarization { block_idx: u8 },
    /// Publish a block through the variant's local buffer (buffered
    /// broadcast engine for Standard, shards engine for Coding) without
    /// going through marshal's mailbox.
    PublishViaVariant { block_idx: u8 },
    /// Release one pending application ack, recording the popped height
    /// as a delivery observation.
    AckNext,
    /// Abort the marshal actor and re-initialize from the same on-disk
    /// state. Pending acks at the moment of restart are NOT signaled,
    /// so marshal's persistent state retains them as un-processed and
    /// the new instance must redeliver them (at-least-once).
    Restart,
    /// Yield without dispatching a marshal-facing event.
    Idle,
}

#[derive(Debug, Clone)]
pub struct MarshalFuzzInput {
    pub raw_bytes: Vec<u8>,
    pub events: Vec<MarshalEvent>,
}

impl Arbitrary<'_> for MarshalFuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let event_count = u.int_in_range(MIN_EVENTS..=MAX_EVENTS)?;
        let mut events = Vec::with_capacity(event_count);
        for _ in 0..event_count {
            events.push(MarshalEvent::arbitrary(u)?);
        }
        let remaining = u.len().min(crate::MAX_RAW_BYTES);
        let raw_bytes = if remaining == 0 {
            vec![0]
        } else {
            u.bytes(remaining)?.to_vec()
        };
        Ok(Self { raw_bytes, events })
    }
}
