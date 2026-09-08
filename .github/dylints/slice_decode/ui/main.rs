// Fixtures for the `slice_decode` lint, compiled against the real `bytes` and
// `commonware_codec` crates so the lint resolves `bytes::Buf` and
// `commonware_codec::FixedSize` the way it does in the workspace. `Frame`
// stands in for `IoBuf`: a local type that implements `Buf` and hands out
// refcounted views.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use commonware_codec::{
    Decode, DecodeExt, Encode, Error, FixedSize, RangeCfg, Read, ReadExt, types::lazy::Lazy,
};
use std::ops::{Deref, RangeBounds};

type Cfg = (RangeCfg<usize>, RangeCfg<usize>);

struct Frame(Bytes);

impl Frame {
    fn slice(&self, range: impl RangeBounds<usize>) -> Self {
        Self(self.0.slice(range))
    }
}

impl Buf for Frame {
    fn remaining(&self) -> usize {
        self.0.remaining()
    }

    fn chunk(&self) -> &[u8] {
        self.0.chunk()
    }

    fn advance(&mut self, cnt: usize) {
        self.0.advance(cnt)
    }

    fn copy_to_bytes(&mut self, len: usize) -> Bytes {
        self.0.copy_to_bytes(len)
    }
}

impl AsRef<[u8]> for Frame {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

struct Holder {
    vec: Vec<u8>,
    frame: Frame,
}

impl Holder {
    fn frame(&self) -> &Frame {
        &self.frame
    }

    // A `Buf` read from a field is borrowed, so the fix is a clone.
    fn decode(&self, cfg: &Cfg) -> Result<Vec<Bytes>, Error> {
        Vec::<Bytes>::decode_cfg(self.frame.as_ref(), cfg)
    }
}

struct Decoder;

impl Decoder {
    // A method whose parameter is bounded by `Buf`: calls are method calls,
    // whose receiver is the first signature input.
    fn decode(&self, buf: impl Buf, cfg: &Cfg) -> Result<Vec<Bytes>, Error> {
        Vec::<Bytes>::decode_cfg(buf, cfg)
    }
}

// A by-value `impl Buf` forwarder, like the journal's `decode_item`.
fn forward<V: Decode>(buf: impl Buf, cfg: &V::Cfg) -> Result<V, Error> {
    V::decode_cfg(buf, cfg)
}

// A forwarder bounded in a `where` clause, like the probe's `read_response`.
fn forward_where<R>(buf: R, cfg: &Cfg) -> Result<Vec<Bytes>, Error>
where
    R: Buf,
{
    Vec::<Bytes>::decode_cfg(buf, cfg)
}

// A `Buf` consumer that is not a decode at all, like `Transcript::append`.
fn absorb(mut data: impl Buf) -> usize {
    let mut n = 0;
    while data.has_remaining() {
        n += data.chunk().len();
        data.advance(data.chunk().len());
    }
    n
}

// A `Read` impl forwarding its own `&mut impl Buf` parameter stays silent.
struct Wrapper(Vec<Bytes>);

impl Read for Wrapper {
    type Cfg = Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self(Vec::<Bytes>::read_cfg(buf, cfg)?))
    }
}

// A reborrow of a `Buf` behind `&mut`, or a `Buf` moved out of a `Box`, is a
// `Buf` and stays silent.
fn reborrow(buf: &mut Bytes, cfg: &Cfg) -> Result<Vec<Bytes>, Error> {
    Vec::<Bytes>::read_cfg(&mut *buf, cfg)
}

fn unbox(buf: Box<Bytes>, cfg: &Cfg) -> Result<Vec<Bytes>, Error> {
    Vec::<Bytes>::decode_cfg(*buf, cfg)
}

// A `FixedSize` bound in the parameter environment gates the call.
fn fixed<T: FixedSize + Decode<Cfg = ()>>(bytes: &Bytes) -> Result<T, Error> {
    T::decode(bytes.as_ref())
}

fn encoded() -> Bytes {
    vec![Bytes::from_static(b"ab"), Bytes::from_static(b"cd")].encode()
}

fn make_vec() -> Vec<u8> {
    encoded().to_vec()
}

fn behind_ref(bytes: &Bytes, cfg: &Cfg) -> Result<Vec<Bytes>, Error> {
    Vec::<Bytes>::decode_cfg(bytes.as_ref(), cfg)
}

fn behind_mut(bytes: &mut Bytes, cfg: &Cfg) -> Result<Vec<Bytes>, Error> {
    Vec::<Bytes>::decode_cfg(bytes.as_ref(), cfg)
}

// Generic callers, like the journal's `decode_item<V: Codec>`: `Self` is a
// type parameter with no `FixedSize` bound.
fn generic_ref<T: Decode>(bytes: &Bytes, cfg: &T::Cfg) -> Result<T, Error> {
    T::decode_cfg(bytes.as_ref(), cfg)
}

fn generic_vec<V: Decode>(vec: Vec<u8>, cfg: &V::Cfg) -> Result<V, Error> {
    V::decode_cfg(vec.as_slice(), cfg)
}

fn borrowed_slice(data: &[u8], cfg: &Cfg) -> Result<Vec<Bytes>, Error> {
    Vec::<Bytes>::decode_cfg(data, cfg)
}

fn borrowed_vec(data: &Vec<u8>, cfg: &Cfg) -> Result<Vec<Bytes>, Error> {
    Vec::<Bytes>::decode_cfg(data.as_slice(), cfg)
}

fn generic_as_ref<T: AsRef<[u8]>>(data: T, cfg: &Cfg) -> Result<Vec<Bytes>, Error> {
    Vec::<Bytes>::decode_cfg(data.as_ref(), cfg)
}

#[rustfmt::skip]
fn main() {
    let cfg: Cfg = ((..).into(), (..).into());

    // Bad: views of a `Bytes`.
    let bytes = encoded();
    let _ = Vec::<Bytes>::decode_cfg(bytes.as_ref(), &cfg);
    let _ = Vec::<Bytes>::decode_cfg(&bytes[..], &cfg);
    let _ = Vec::<Bytes>::decode_cfg(&bytes[1..], &cfg);
    let _ = Vec::<Bytes>::decode_cfg(&*bytes, &cfg);
    let _ = Vec::<Bytes>::decode_cfg(bytes.deref(), &cfg);
    let _ = Vec::<Bytes>::decode_cfg(bytes.chunk(), &cfg);
    let _ = Vec::<Bytes>::read_cfg(&mut bytes.as_ref(), &cfg);

    // Bad: views of a `BytesMut`.
    let bytes_mut = BytesMut::from(encoded().as_ref());
    let _ = Vec::<Bytes>::decode_cfg(bytes_mut.as_ref(), &cfg);

    // Bad: views of a local `Buf` implementor standing in for `IoBuf`.
    let frame = Frame(encoded());
    let _ = Vec::<Bytes>::read_cfg(&mut frame.as_ref(), &cfg);
    let _ = Vec::<Bytes>::read_cfg(&mut frame.as_ref()[1..].as_ref(), &cfg);
    let _ = Vec::<Bytes>::decode_cfg(frame.chunk(), &cfg);

    // Bad: the view was bound one `let` earlier.
    let view = &frame.as_ref()[..frame.remaining()];
    let _ = Vec::<Bytes>::decode_cfg(view, &cfg);

    // Bad: an owned `Vec<u8>` local or temporary.
    let vec = make_vec();
    let _ = Vec::<Bytes>::decode_cfg(vec.as_slice(), &cfg);
    let _ = Vec::<Bytes>::decode_cfg(make_vec().as_ref(), &cfg);
    let _ = Lazy::<u64>::deferred(&mut vec.as_slice(), ());

    // Bad: a `Bytes` behind a reference, and views taken inside generic callers.
    let _ = behind_ref(&bytes, &cfg);
    let _ = behind_mut(&mut encoded(), &cfg);
    let _ = generic_ref::<Vec<Bytes>>(&bytes, &cfg);
    let _ = generic_vec::<Vec<Bytes>>(make_vec(), &cfg);

    // Bad: a `Buf` read from a field or returned by a method is borrowed.
    let holder = Holder { vec: make_vec(), frame: Frame(encoded()) };
    let _ = holder.decode(&cfg);
    let _ = Vec::<Bytes>::decode_cfg(holder.frame().as_ref(), &cfg);

    // Bad: by-value `Buf` forwarders and method calls, not only codec entry points.
    let _ = forward::<Vec<Bytes>>(bytes.as_ref(), &cfg);
    let _ = forward_where(bytes.as_ref(), &cfg);
    let _ = Decoder.decode(bytes.as_ref(), &cfg);
    let _ = absorb(bytes.as_ref());

    // Good: the buffer itself, a clone, a conversion, a sub-range, a reborrow, or an unboxing.
    let mut owned = encoded();
    let _ = reborrow(&mut owned, &cfg);
    let _ = unbox(Box::new(owned), &cfg);
    let _ = Vec::<Bytes>::decode_cfg(bytes.clone(), &cfg);
    let _ = Vec::<Bytes>::decode_cfg(frame.slice(1..), &cfg);
    let _ = Vec::<Bytes>::decode_cfg(Bytes::from(vec), &cfg);
    let _ = Vec::<Bytes>::decode_cfg(bytes, &cfg);

    // Good: a fixed-size target has O(1) byte fields.
    let word = Bytes::from_static(&[0u8; 8]);
    let _ = u64::decode(word.as_ref());
    let _ = u64::read(&mut word.as_ref());
    let _ = fixed::<u64>(&word);

    // Good: a consumer that copies its input outright.
    let mut sink = BytesMut::new();
    sink.put(word.as_ref());

    // Good: genuinely borrowed sources.
    let array = [0u8; 8];
    let _ = u64::decode(array.as_ref());
    let _ = absorb(array.as_slice());
    let _ = Vec::<Bytes>::decode_cfg(holder.vec.as_slice(), &cfg);
    let _ = borrowed_slice(word.as_ref(), &cfg);
    let _ = borrowed_vec(&holder.vec, &cfg);
    let _ = generic_as_ref(word.clone(), &cfg);
    let _ = Wrapper::decode_cfg(word, &cfg).map(|wrapper| wrapper.0.len());
}
