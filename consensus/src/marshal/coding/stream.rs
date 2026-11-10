//! Erasure coding of a block's body while the application is still building the block.
//!
//! The application pushes its block's body to a [`crate::BodySink`] as the bytes become final. A
//! task codes completed segments and hands their chunks to the shards engine, allowing
//! dissemination while the application is still building the block. Once the application returns
//! the block, the rest of the coded layout is pushed through the same encoder and the block is
//! sealed from the streamed segments, without coding it a second time.
//!
//! ```text
//! application   select ........ push(txs) ... push(txs) ... settle, merkleize, return block
//! encoder                       seg 0        seg 1 .. seg k                tail segment
//! shards engine                 chunks out   chunks out                    chunks out, then roots
//!                               ^ dissemination starts with the first completed segment
//!
//! pushed length != sealed body length  -->  code the whole block in one go (fallback)
//! ```

use crate::{
    BodySink, CertifiableBlock,
    marshal::coding::{
        shards,
        types::{CodedBlock, CodedLayout, write_coded_trailer},
    },
    types::Round,
};
use commonware_coding::{Config as CodingConfig, EncodedSegment, Scheme, Segmentable};
use commonware_cryptography::{Digested, Hasher, PublicKey};
use commonware_macros::select;
use commonware_parallel::Strategy;
use commonware_runtime::{Handle, Spawner};
use commonware_utils::channel::{fallible::OneshotExt, mpsc, oneshot};
use tracing::{debug, warn};

/// One coded segment: its root and the chunk of every shard index, in index order.
pub(crate) type StreamedSegment<C> =
    EncodedSegment<<C as Scheme>::Commitment, <C as Segmentable>::Chunk>;

/// What the streaming task hands back when the block is sealed.
struct Streamed<C: Segmentable> {
    /// The encoder that coded `segments`, ready for the rest of the coded layout.
    encoder: C::Encoder,
    /// Every segment already sent, in segment order.
    segments: Vec<StreamedSegment<C>>,
    /// The number of body bytes coded.
    pushed: usize,
}

/// A body stream started for one build, consumed when its block is sealed.
pub(crate) struct BodyStream<C: Segmentable> {
    config: CodingConfig,
    finish: oneshot::Sender<()>,
    streamed: Handle<Option<Streamed<C>>>,
}

impl<C: Segmentable> BodyStream<C> {
    /// Starts coding the body pushed to the returned sink for a block proposed in `round`,
    /// handing every completed segment to `shards`.
    pub(crate) fn start<B, H, P, S>(
        context: &impl Spawner,
        strategy: S,
        shards: shards::Mailbox<B, C, H, P>,
        round: Round,
        config: CodingConfig,
    ) -> (BodySink, Self)
    where
        B: CertifiableBlock,
        H: Hasher,
        P: PublicKey,
        S: Strategy,
    {
        let encoder = C::encoder(config);
        let (sink, bytes) = BodySink::channel();
        let (finish, finish_rx) = oneshot::channel();
        let streamed = context
            .child("body_stream")
            .with_attribute("round", round)
            .spawn(move |_| {
                stream::<B, C, H, P, S>(strategy, shards, round, encoder, bytes, finish_rx)
            });
        (
            sink,
            Self {
                config,
                finish,
                streamed,
            },
        )
    }

    /// Seals `block` into its [`CodedBlock`].
    ///
    /// When the pushed bytes are as long as the block's body, the rest of the coded layout is coded
    /// through the same encoder, the remaining segments go to `shards`, and the shards are
    /// assembled from the streamed segments. Otherwise (nothing pushed, pushes whose length differs
    /// from the body's, or an encoder failure), the block is coded whole, and the shards engine
    /// sends its chunks when the block is proposed.
    pub(crate) async fn seal<B, H, P>(
        self,
        block: Digested<B>,
        strategy: &impl Strategy,
        shards: &shards::Mailbox<B, C, H, P>,
        round: Round,
    ) -> CodedBlock<B, C, H>
    where
        B: CertifiableBlock + CodedLayout,
        H: Hasher,
        P: PublicKey,
    {
        let Self {
            config,
            finish,
            streamed,
        } = self;
        finish.send_lossy(());
        let Some(Streamed {
            mut encoder,
            mut segments,
            pushed,
        }) = streamed
            .await
            .ok()
            .flatten()
            .filter(|streamed| streamed.pushed > 0)
        else {
            return CodedBlock::encode(block, config, strategy).await;
        };

        let sealing = block.clone();
        let sealed = strategy
            .spawn(pushed, move |strategy| {
                let mut rest = Vec::new();
                sealing.inner().write_tail(&mut rest);
                let body = sealing.inner().encode_size().checked_sub(rest.len());
                if body != Some(pushed) {
                    return Err(format!(
                        "pushed {pushed} body bytes but the block's body is {body:?} bytes"
                    ));
                }
                write_coded_trailer(pushed, config, &mut rest);
                let mut completed = C::push(&mut encoder, &rest, &strategy)
                    .map_err(|err| format!("failed to code the block's tail: {err:?}"))?;
                let (root, roots, last) = C::finish(encoder, &strategy)
                    .map_err(|err| format!("failed to finish the block's coding: {err:?}"))?;
                completed.extend(last);
                Ok((root, roots, completed))
            })
            .await;
        let (root, roots, completed) = match sealed {
            Ok(sealed) => sealed,
            Err(reason) => {
                warn!(%round, reason, "coding the whole block instead of its streamed body");
                return CodedBlock::encode(block, config, strategy).await;
            }
        };
        for segment in completed {
            shards.stream_segment(round, segment.clone());
            segments.push(segment);
        }
        let shards = C::assemble_shards(roots, segments);
        CodedBlock::from_shards(block, config, root, shards)
    }
}

/// Codes pushed bytes until the block is sealed, sending each completed segment to `shards`.
///
/// Returns `None` when the build is abandoned or the encoder fails. A block sealed after either
/// is coded whole.
async fn stream<B, C, H, P, S>(
    strategy: S,
    shards: shards::Mailbox<B, C, H, P>,
    round: Round,
    encoder: C::Encoder,
    mut bytes: mpsc::UnboundedReceiver<bytes::Bytes>,
    mut finish: oneshot::Receiver<()>,
) -> Option<Streamed<C>>
where
    B: CertifiableBlock,
    C: Segmentable,
    H: Hasher,
    P: PublicKey,
    S: Strategy,
{
    let mut streamed = Streamed {
        encoder,
        segments: Vec::new(),
        pushed: 0,
    };
    let mut open = true;
    loop {
        // Pushes happen before the application returns its block, so once sealing begins
        // every pushed piece is already queued.
        let batch = if open {
            select! {
                result = &mut finish => {
                    result.ok()?;
                    break;
                },
                piece = bytes.recv() => match piece {
                    Some(piece) => {
                        let mut batch = vec![piece];
                        batch.extend(std::iter::from_fn(|| bytes.try_recv().ok()));
                        batch
                    }
                    None => {
                        open = false;
                        continue;
                    }
                },
            }
        } else {
            (&mut finish).await.ok()?;
            break;
        };
        streamed = code(&strategy, &shards, round, streamed, batch).await?;
    }

    // Code the pieces still queued when sealing began.
    let batch: Vec<_> = std::iter::from_fn(|| bytes.try_recv().ok()).collect();
    if batch.is_empty() {
        return Some(streamed);
    }
    code(&strategy, &shards, round, streamed, batch).await
}

/// Pushes `batch` through the encoder on `strategy` and sends every completed segment.
async fn code<B, C, H, P, S>(
    strategy: &S,
    shards: &shards::Mailbox<B, C, H, P>,
    round: Round,
    streamed: Streamed<C>,
    batch: Vec<bytes::Bytes>,
) -> Option<Streamed<C>>
where
    B: CertifiableBlock,
    C: Segmentable,
    H: Hasher,
    P: PublicKey,
    S: Strategy,
{
    let len = batch.iter().map(|piece| piece.len()).sum();
    let (streamed, result) = strategy
        .spawn(len, move |strategy| {
            let mut streamed = streamed;
            let mut completed = Vec::new();
            for piece in &batch {
                match C::push(&mut streamed.encoder, piece, &strategy) {
                    Ok(segments) => completed.extend(segments),
                    Err(err) => return (streamed, Err(err)),
                }
                streamed.pushed += piece.len();
            }
            (streamed, Ok(completed))
        })
        .await;
    let mut streamed = streamed;
    match result {
        Ok(completed) => {
            for segment in completed {
                shards.stream_segment(round, segment.clone());
                streamed.segments.push(segment);
            }
            Some(streamed)
        }
        Err(err) => {
            debug!(%round, ?err, "failed to code the pushed body");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        marshal::{
            coding::{shards::mailbox::Message, types::coding_config_for_participants},
            mocks::{
                block::{encode_block, ready},
                harness::{CodingB, CodingCtx, D, K, default_leader, genesis_commitment},
            },
        },
        types::{Epoch, Height, View},
    };
    use bytes::Bytes;
    use commonware_actor::mailbox;
    use commonware_cryptography::{Committable as _, Digestible as _, Sha256};
    use commonware_parallel::Sequential;
    use commonware_runtime::{Clock as _, Runner as _, Supervisor as _, deterministic};
    use commonware_utils::NZUsize;
    use std::time::Duration;

    type H = Sha256;
    type SC = commonware_coding::Segmented<H, 16>;

    /// Returns the test block proposed in `round`.
    fn block(round: Round) -> CodingB {
        let context = CodingCtx {
            round,
            leader: default_leader(),
            parent: (View::zero(), genesis_commitment()),
        };
        CodingB::new::<H>(context, D::from([7u8; 32]), Height::new(1), 42)
    }

    /// Splits the block's body into three pushes of uneven length.
    fn pieces(block: &CodingB) -> Vec<Bytes> {
        let mut body = Vec::new();
        block.write_body(&mut body);
        assert!(body.len() > 2 * 16, "the body must span several segments");
        vec![
            Bytes::copy_from_slice(&body[..5]),
            Bytes::copy_from_slice(&body[5..37]),
            Bytes::copy_from_slice(&body[37..]),
        ]
    }

    /// Runs one build that pushes `pushes` to the sink and seals `block`, and returns the sealed
    /// block, the segments handed to the shards engine, and how many of them it held before the
    /// block was sealed.
    #[allow(clippy::type_complexity)]
    fn build(
        block: CodingB,
        pushes: Vec<Bytes>,
    ) -> (CodedBlock<CodingB, SC, H>, Vec<StreamedSegment<SC>>, usize) {
        deterministic::Runner::default().start(|context| async move {
            // A shards mailbox whose receiver records what the build sends the engine.
            let (sender, mut receiver) = mailbox::new::<Message<CodingB, SC, H, K>>(
                context.child("mailbox"),
                NZUsize!(1024),
            );
            let shards = shards::Mailbox::new(sender);

            // The build pushes each piece to the sink and then seals the block.
            let round = Round::new(Epoch::zero(), View::new(1));
            let config = coding_config_for_participants(4);
            let (sink, stream) =
                BodyStream::<SC>::start(&context, Sequential, shards.clone(), round, config);
            for piece in pushes {
                sink.push(piece);
                context.sleep(Duration::from_millis(1)).await;
            }

            // Every message the build sends is a segment of this round.
            let mut segments = Vec::new();
            let mut drain = |segments: &mut Vec<_>| {
                while let Ok(message) = receiver.try_recv() {
                    match message {
                        Message::StreamSegment {
                            round: streamed,
                            segment,
                        } => {
                            assert_eq!(streamed, round);
                            segments.push(segment);
                        }
                        _ => panic!("only segments must be sent while building"),
                    }
                }
            };

            // Segments sent before sealing are counted apart from those the seal sends.
            drain(&mut segments);
            let early = segments.len();
            let sealed = stream.seal(ready(block), &Sequential, &shards, round).await;
            drain(&mut segments);
            (sealed, segments, early)
        })
    }

    /// Streaming the body and sealing produces the commitment and shards of a whole-block
    /// encode, and every segment reaches the shards engine in order with the chunk of each
    /// shard. The segments the pushed body completes reach it before the block is sealed.
    #[test]
    fn test_streamed_block_matches_whole_encode() {
        // Three uneven pushes seal the block that a whole-block encode produces.
        let round = Round::new(Epoch::zero(), View::new(1));
        let block = block(round);
        let expected =
            encode_block::<CodingB, SC, H>(block.clone(), coding_config_for_participants(4));
        let (sealed, segments, early) = build(block.clone(), pieces(&block));
        assert_eq!(sealed.commitment(), expected.commitment());
        assert_eq!(sealed.digest(), expected.digest());
        assert!(sealed.shards(&Sequential) == expected.shards(&Sequential));
        assert!(
            early >= 2,
            "the segments the pushes complete must be sent before sealing"
        );

        // Each segment reached the engine in order, with its root and every shard's chunk.
        let shards = expected.shards(&Sequential);
        let (roots, _) = SC::split(&shards[0]);
        assert_eq!(segments.len(), roots.len());
        for (position, segment) in segments.iter().enumerate() {
            assert_eq!(usize::from(segment.segment), position);
            assert_eq!(segment.root, roots[position]);
            for (index, shard) in shards.iter().enumerate() {
                let (_, chunks) = SC::split(shard);
                assert!(segment.chunks[index] == chunks[position]);
            }
        }
    }

    /// A build that pushes nothing codes the block whole and streams no segment.
    #[test]
    fn test_unpushed_build_codes_whole_block() {
        // A build that pushes nothing seals the whole-block encode and sends no segment.
        let round = Round::new(Epoch::zero(), View::new(1));
        let block = block(round);
        let expected =
            encode_block::<CodingB, SC, H>(block.clone(), coding_config_for_participants(4));
        let (sealed, segments, _) = build(block, Vec::new());
        assert_eq!(sealed.commitment(), expected.commitment());
        assert!(segments.is_empty());
    }

    /// Pushed bytes whose length differs from the block's body fall back to coding the block
    /// whole, so the sealed commitment is still the block's.
    #[test]
    fn test_mismatched_push_falls_back_to_whole_encode() {
        // A build that withholds its last piece still seals the whole-block encode.
        let round = Round::new(Epoch::zero(), View::new(1));
        let block = block(round);
        let expected =
            encode_block::<CodingB, SC, H>(block.clone(), coding_config_for_participants(4));
        let mut pushes = pieces(&block);
        pushes.pop();
        let (sealed, _, _) = build(block, pushes);
        assert_eq!(sealed.commitment(), expected.commitment());
        assert!(sealed.shards(&Sequential) == expected.shards(&Sequential));
    }
}
