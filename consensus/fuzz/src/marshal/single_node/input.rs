//! Libfuzzer-facing scenario: a byte tape (consumed by `FuzzRng`) plus a
//! length-bounded list of events the driver replays against marshal.

use super::NUM_BLOCKS;
use arbitrary::Arbitrary;

const MIN_EVENTS: usize = 1;
const MAX_EVENTS: usize = 128;

fn block_idx(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<u8> {
    u.int_in_range(0..=((NUM_BLOCKS - 1) as u8))
}

#[derive(Debug, Clone, Copy)]
pub enum QueryKind {
    /// Query via `Height::into()`.
    Height,
    /// Query via `(&Digest)::into()`.
    Digest,
    /// Query via `archive::Identifier::Index`.
    ArchiveIndex,
    /// Query via `archive::Identifier::Key`.
    ArchiveKey,
    /// Query the latest finalized block.
    Latest,
}

impl Arbitrary<'_> for QueryKind {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(match u.int_in_range(0..=4)? {
            0 => Self::Height,
            1 => Self::Digest,
            2 => Self::ArchiveIndex,
            3 => Self::ArchiveKey,
            _ => Self::Latest,
        })
    }
}

#[derive(Debug, Clone, Copy)]
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
    GetBlock { block_idx: u8, query: QueryKind },
    /// Best-effort local read of finalized block info by height, digest, archive
    /// identifier, or latest tip.
    GetInfo { block_idx: u8, query: QueryKind },
    /// Walk ancestry from a locally available block.
    Ancestry { block_idx: u8, max_items: u8 },
    /// Exercise the bounded ancestry stream produced from caller-provided blocks.
    BoundedAncestry {
        block_idx: u8,
        len: u8,
        reverse: bool,
        max_items: u8,
    },
    /// Subscribe to a block by digest or commitment with a fetch fallback,
    /// exercising the missing-block subscription path.
    Subscribe { block_idx: u8, by_commitment: bool },
    /// Submit a synchronous burst of mailbox traffic to exercise bounded
    /// mailbox overflow, coalescing, pruning, and dropped subscribers.
    MailboxBurst { block_idx: u8 },
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
    /// a later instance must redeliver them (at-least-once).
    Restart,
    /// Yield without dispatching a marshal-facing event.
    Idle,
}

impl Arbitrary<'_> for MarshalEvent {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(match u.int_in_range(0..=127)? {
            0..=11 => Self::Propose {
                block_idx: block_idx(u)?,
            },
            12..=21 => Self::Verify {
                block_idx: block_idx(u)?,
            },
            22..=31 => Self::Certify {
                block_idx: block_idx(u)?,
            },
            32..=47 => Self::ReportFinalization {
                block_idx: block_idx(u)?,
            },
            48..=57 => Self::ReportNotarization {
                block_idx: block_idx(u)?,
            },
            58..=62 => Self::GetBlock {
                block_idx: block_idx(u)?,
                query: QueryKind::arbitrary(u)?,
            },
            63..=67 => Self::GetInfo {
                block_idx: block_idx(u)?,
                query: QueryKind::arbitrary(u)?,
            },
            68..=73 => Self::Ancestry {
                block_idx: block_idx(u)?,
                max_items: u.arbitrary()?,
            },
            74..=79 => Self::BoundedAncestry {
                block_idx: block_idx(u)?,
                len: u.arbitrary()?,
                reverse: u.arbitrary()?,
                max_items: u.arbitrary()?,
            },
            80..=87 => Self::Subscribe {
                block_idx: block_idx(u)?,
                by_commitment: u.arbitrary()?,
            },
            88..=95 => Self::MailboxBurst {
                block_idx: block_idx(u)?,
            },
            96..=101 => Self::SetFloor {
                block_idx: block_idx(u)?,
            },
            102..=105 => Self::Prune {
                block_idx: block_idx(u)?,
            },
            106..=113 => Self::PublishViaVariant {
                block_idx: block_idx(u)?,
            },
            114..=121 => Self::AckNext,
            122..=125 => Self::Restart,
            _ => Self::Idle,
        })
    }
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
        events.extend([
            MarshalEvent::MailboxBurst { block_idx: 0 },
            MarshalEvent::Subscribe {
                block_idx: 0,
                by_commitment: true,
            },
            MarshalEvent::Verify { block_idx: 0 },
            MarshalEvent::Verify { block_idx: 1 },
            MarshalEvent::GetBlock {
                block_idx: 0,
                query: QueryKind::ArchiveIndex,
            },
            MarshalEvent::GetBlock {
                block_idx: 0,
                query: QueryKind::ArchiveKey,
            },
            MarshalEvent::GetInfo {
                block_idx: 0,
                query: QueryKind::ArchiveIndex,
            },
            MarshalEvent::GetInfo {
                block_idx: 0,
                query: QueryKind::ArchiveKey,
            },
            MarshalEvent::Ancestry {
                block_idx: 1,
                max_items: 4,
            },
            MarshalEvent::BoundedAncestry {
                block_idx: 1,
                len: 4,
                reverse: true,
                max_items: 4,
            },
            MarshalEvent::PublishViaVariant { block_idx: 0 },
            MarshalEvent::Propose { block_idx: 0 },
            MarshalEvent::SetFloor { block_idx: 0 },
            MarshalEvent::AckNext,
            MarshalEvent::AckNext,
            MarshalEvent::Prune { block_idx: 0 },
            MarshalEvent::Subscribe {
                block_idx: 0,
                by_commitment: false,
            },
        ]);
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
