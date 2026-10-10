//! The block this example orders: a transaction block carrying junk bytes.

use bytes::{BufMut, Bytes};
use commonware_codec::{
    Buf, BufsMut, EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, Write,
    varint::{MAX_U32_VARINT_SIZE, MAX_U64_VARINT_SIZE},
};
use commonware_consensus::{
    Epochable as _, Heightable as _,
    multimmit::types::{Context, TransactionBlock},
};
use commonware_cryptography::{Digestible, Hasher as _, Sha256, sha256::Digest as Sha256Digest};

/// Hash namespace for body digests and the junk pattern each body repeats.
const BODY_NAMESPACE: &[u8] = b"_COMMONWARE_LOG_MULTIMMIT_BODY";

/// Opaque junk data carried by one producer block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Body(Bytes);

impl Body {
    /// Returns a codec bound that accepts exactly `size` body bytes.
    pub const fn codec_config(size: usize) -> RangeCfg<usize> {
        RangeCfg::exact(size)
    }

    /// Returns the largest encoded transaction block accepted for `size` body bytes.
    pub const fn max_block_size(size: usize) -> usize {
        let header = 2 * MAX_U64_VARINT_SIZE + MAX_U32_VARINT_SIZE + 2 * Sha256Digest::SIZE;
        size.checked_add(header + MAX_U64_VARINT_SIZE)
            .expect("body size must fit in an encoded transaction block")
    }

    /// Returns `size` bytes that repeat a pattern unique to `seed` and `context`.
    pub(super) fn junk(seed: u64, context: Context<Sha256Digest>, size: usize) -> Self {
        let seed = seed.to_be_bytes();
        let epoch = context.epoch().get().to_be_bytes();
        let chain = context.chain().get().to_be_bytes();
        let height = context.height().get().to_be_bytes();
        let pattern = Sha256::hash(&[
            BODY_NAMESPACE,
            &seed,
            &epoch,
            &chain,
            &height,
            context.parent().as_ref(),
        ]);
        let mut bytes = Vec::with_capacity(size);
        while bytes.len() < size {
            let remaining = size - bytes.len();
            bytes.extend_from_slice(&pattern.as_ref()[..remaining.min(pattern.as_ref().len())]);
        }
        Self(Bytes::from(bytes))
    }
}

impl Write for Body {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }

    fn write_bufs(&self, buf: &mut impl BufsMut) {
        self.0.write_bufs(buf);
    }
}

impl Read for Body {
    type Cfg = RangeCfg<usize>;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        Bytes::read_cfg(buf, cfg).map(Self)
    }
}

impl EncodeSize for Body {
    fn encode_size(&self) -> usize {
        self.0.encode_size()
    }

    fn encode_inline_size(&self) -> usize {
        self.0.encode_inline_size()
    }
}

impl Digestible for Body {
    type Digest = Sha256Digest;

    fn digest(&self) -> Self::Digest {
        Sha256::hash(&[BODY_NAMESPACE, self.0.as_ref()])
    }
}

/// Complete block type retained and delivered by marshal.
pub type Block = TransactionBlock<Sha256, Body>;

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Buf as _;
    use commonware_codec::{Decode, Encode};
    use commonware_consensus::{
        multimmit::types::ChainId,
        types::{Epoch, Height},
    };
    use commonware_runtime::{
        BufferPooler as _, Runner as _, deterministic, iobuf::EncodeExt as _,
    };

    fn context() -> Context<Sha256Digest> {
        Context::new(
            Epoch::new(7),
            ChainId::new(2),
            Height::new(11),
            Sha256::hash(&[b"parent"]),
        )
        .unwrap()
    }

    #[test]
    fn body_codec_and_block_identities_are_canonical() {
        let context = context();
        let body = Body::junk(9, context, 4_097);
        let mut encoded = body.encode();
        let decoded = Body::read_cfg(&mut encoded, &Body::codec_config(4_097)).unwrap();
        assert_eq!(decoded, body);

        let block = TransactionBlock::<Sha256, _>::from_context(context, body);
        assert_eq!(block.header().body_digest(), block.body().digest());
        assert_ne!(block.digest(), block.header().body_digest());
        assert!(block.encode_size() <= Body::max_block_size(4_097));
    }

    #[test]
    fn block_encoding_shares_body_buffer() {
        deterministic::Runner::default().start(|runtime| async move {
            for size in [0, 1, 127, 128, 256 * 1024] {
                let block = Block::from_context(context(), Body::junk(9, context(), size));
                let payload = block.body().0.clone();
                let inline = block.header().encode_size() + size.encode_size();
                let encoded = block.encode_with_pool(runtime.network_buffer_pool());
                assert_eq!(encoded.clone().coalesce().as_ref(), block.encode().as_ref());
                assert_eq!(block.encode_inline_size(), inline);

                let decoded =
                    Block::decode_cfg(encoded.clone(), &Body::codec_config(size)).unwrap();
                assert_eq!(decoded, block);
                if size != 0 {
                    let mut body = encoded;
                    body.advance(inline);
                    assert_eq!(body.chunk().as_ptr(), payload.as_ptr());
                    assert_eq!(decoded.body().0.as_ptr(), payload.as_ptr());
                }
                drop(block);
                assert_eq!(decoded.body().0, payload);
            }
        });
    }
}
