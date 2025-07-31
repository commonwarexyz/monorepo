use crate::Block;
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_utils::Span;
use std::{
    fmt::{Debug, Display},
    hash::{Hash, Hasher},
    ops::Deref,
};

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone)]
enum Subject<B: Block> {
    Block(B::Commitment),
    Finalized { height: u64 },
    Notarized { view: u64 },
}

impl<B: Block> Write for Subject<B> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Block(commitment) => {
                0u8.write(buf);
                commitment.write(buf)
            }
            Self::Finalized { height } => {
                1u8.write(buf);
                height.write(buf)
            }
            Self::Notarized { view } => {
                2u8.write(buf);
                view.write(buf)
            }
        }
    }
}

impl<B: Block> Read for Subject<B> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let request = match u8::read(buf)? {
            0 => Self::Block(B::Commitment::read(buf)?),
            1 => Self::Finalized {
                height: u64::read(buf)?,
            },
            2 => Self::Notarized {
                view: u64::read(buf)?,
            },
            i => return Err(CodecError::InvalidEnum(i)),
        };
        Ok(request)
    }
}

impl<B: Block> EncodeSize for Subject<B> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Block(block) => block.encode_size(),
            Self::Finalized { height } => height.encode_size(),
            Self::Notarized { view } => view.encode_size(),
        }
    }
}

/// A request wrapper that holds the serialized bytes of the inner request.
#[derive(Clone)]
pub struct Request<B: Block> {
    inner: Subject<B>,
    raw: Vec<u8>,
}

impl<B: Block> Request<B> {
    /// Create a new request from an inner request.
    pub fn new(inner: Subject<B>) -> Self {
        let mut raw = Vec::with_capacity(inner.encode_size());
        inner.write(&mut raw);
        Self { inner, raw }
    }

    /// Create a request for a block.
    pub fn block(commitment: B::Commitment) -> Self {
        Self::new(Subject::Block(commitment))
    }

    /// Create a request for a finalization.
    pub fn finalized(height: u64) -> Self {
        Self::new(Subject::Finalized { height })
    }

    /// Create a request for a notarization.
    pub fn notarized(view: u64) -> Self {
        Self::new(Subject::Notarized { view })
    }

    /// Get the [Subject] of the request.
    pub fn subject(&self) -> &Subject<B> {
        &self.inner
    }
}

impl<B: Block> Span for Request<B> {}

impl<B: Block> Write for Request<B> {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(&self.raw);
    }
}

impl<B: Block> Read for Request<B> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let inner = Subject::read_cfg(buf, &())?;
        Ok(Self::new(inner))
    }
}

impl<B: Block> EncodeSize for Request<B> {
    fn encode_size(&self) -> usize {
        self.raw.len()
    }
}

impl<B: Block> PartialEq for Request<B> {
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}

impl<B: Block> Eq for Request<B> {}

impl<B: Block> Ord for Request<B> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.raw.cmp(&other.raw)
    }
}

impl<B: Block> PartialOrd for Request<B> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<B: Block> AsRef<[u8]> for Request<B> {
    fn as_ref(&self) -> &[u8] {
        &self.raw
    }
}

impl<B: Block> Deref for Request<B> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.raw
    }
}

impl<B: Block> Hash for Request<B> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.raw.hash(state);
    }
}

impl<B: Block> Display for Request<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.inner {
            Subject::Block(commitment) => write!(f, "Block({:?})", commitment),
            Subject::Finalized { height } => write!(f, "Finalized({:?})", height),
            Subject::Notarized { view } => write!(f, "Notarized({:?})", view),
        }
    }
}

impl<B: Block> Debug for Request<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
