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
    /// Best-effort local read of a finalized block by height (pure query).
    GetBlock { block_idx: u8 },
    /// Subscribe to a block by digest or commitment with a fetch fallback,
    /// exercising the missing-block subscription path.
    Subscribe { block_idx: u8, by_commitment: bool },
    /// Set marshal's durable floor to the next processable finalized block.
    SetFloor { block_idx: u8 },
    /// Request pruning finalized archives below a height (only effective at
    /// or below the current floor).
    Prune { block_idx: u8 },
    /// Publish a block through the variant's local buffer (buffered
    /// broadcast engine for Standard, shards engine for Coding) without
    /// going through marshal's mailbox.
    PublishViaVariant { block_idx: u8 },
    /// Release one pending application ack. The popped height is recorded as a
    /// delivery observation unless it is a stale pre-restart entry or the
    /// height-0 genesis floor block, which are skipped.
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
        if events.len() < event_count && !u.is_empty() && u.arbitrary::<bool>()? {
            events.push(MarshalEvent::Subscribe {
                block_idx: 0,
                by_commitment: true,
            });
        }
        if event_count - events.len() >= 2 && u.len() >= 2 && u.arbitrary::<bool>()? {
            if u.arbitrary::<bool>()? {
                events.push(MarshalEvent::Propose { block_idx: 0 });
                events.push(MarshalEvent::SetFloor { block_idx: 0 });
            } else {
                events.push(MarshalEvent::SetFloor { block_idx: 0 });
                events.push(MarshalEvent::Propose { block_idx: 0 });
            }
            if events.len() < event_count {
                events.push(MarshalEvent::AckNext);
            }
            if events.len() < event_count {
                events.push(MarshalEvent::AckNext);
            }
            if events.len() < event_count {
                events.push(MarshalEvent::Subscribe {
                    block_idx: 0,
                    by_commitment: false,
                });
            }
            if events.len() < event_count {
                events.push(MarshalEvent::Subscribe {
                    block_idx: 0,
                    by_commitment: true,
                });
            }
        }
        if events.len() < event_count && u.len() >= 2 && u.arbitrary::<bool>()? {
            events.push(MarshalEvent::PublishViaVariant {
                block_idx: u.arbitrary()?,
            });
        }
        for _ in events.len()..event_count {
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
