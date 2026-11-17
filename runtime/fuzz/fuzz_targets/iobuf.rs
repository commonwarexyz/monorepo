//! Fuzz `IoBufMut`, `IoBuf`, `IoBufs`, `IoBufsMut` and `IoBufsBuilder` against byte-level models.
//!
//! Up to [`MAX_OBJECTS`] buffers live at once, each paired with a model of its content and of the
//! allocation it views. After every operation the harness checks every live buffer against its
//! model, checks that no mutable region overlaps another live buffer, and judges the outcome of
//! `try_into_mut` against the other live views of the same allocation. Every generated operation
//! stays inside the documented preconditions of the method it calls, so any panic is a finding.

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use commonware_codec::BufsMut as _;
use commonware_runtime::{
    IoBuf, IoBufMut, IoBufs, IoBufsBuilder, IoBufsMut, Runner as _, deterministic,
};
use commonware_runtime_fuzz::decode;
use commonware_utils::{Entropy, FuzzRng};
use libfuzzer_sys::fuzz_target;
use std::{fmt::Display, io::IoSlice, num::NonZeroUsize};

/// Maximum number of live buffers.
const MAX_OBJECTS: usize = 8;

/// Maximum number of operations per input.
const MAX_OPS: usize = 64;

/// Maximum number of chunks an `IoBufs` or `IoBufsMut` is built from.
const MAX_CHUNKS: usize = 5;

/// Largest capacity or length of a single allocation.
const MAX_SIZE: usize = 256 * 1024;

/// Spare capacity at which a frozen buffer's tail no longer fits its 64-bit owner descriptor.
const TAIL_LIMIT: usize = 128 * 1024;

/// Largest alignment, as a power of two.
const MAX_ALIGN_LOG2: u32 = 12;

/// Length of the static slice pool.
const POOL_LEN: usize = 4096;

/// Backing bytes for `&'static [u8]` buffers.
static POOL: [u8; POOL_LEN] = {
    let mut pool = [0u8; POOL_LEN];
    let mut i = 0;
    while i < POOL_LEN {
        pool[i] = (i % 251) as u8 + 1;
        i += 1;
    }
    pool
};

/// Samples a capacity or length biased toward zero, small values and [`TAIL_LIMIT`].
fn size(u: &mut Unstructured<'_>) -> arbitrary::Result<usize> {
    Ok(match u.int_in_range(0u8..=31)? {
        0..=7 => 0,
        8..=19 => u.int_in_range(1..=64)?,
        20..=25 => u.int_in_range(65..=4096)?,
        26..=28 => TAIL_LIMIT
            .checked_add_signed(u.int_in_range(-16isize..=64)?)
            .expect("offset is smaller than the limit"),
        29 => 4096 * u.int_in_range(1..=MAX_SIZE / 4096)?,
        _ => u.int_in_range(0..=MAX_SIZE)?,
    })
}

/// Samples a power-of-two alignment.
fn alignment(u: &mut Unstructured<'_>) -> arbitrary::Result<usize> {
    Ok(1 << u.int_in_range(0..=MAX_ALIGN_LOG2)?)
}

fn buf_sources(u: &mut Unstructured<'_>) -> arbitrary::Result<Vec<BufSource>> {
    (0..u.int_in_range(1..=MAX_CHUNKS)?)
        .map(|_| u.arbitrary())
        .collect()
}

fn mut_chunks(u: &mut Unstructured<'_>) -> arbitrary::Result<Vec<MutChunk>> {
    (0..u.int_in_range(1..=MAX_CHUNKS)?)
        .map(|_| u.arbitrary())
        .collect()
}

/// A count resolved against the largest count the target accepts when the operation runs.
#[derive(Arbitrary, Clone, Copy, Debug)]
enum Amount {
    Zero,
    All,
    Few(u8),
    AllBut(u8),
    Any(u32),
}

impl Amount {
    fn resolve(self, max: usize) -> usize {
        match self {
            Self::Zero => 0,
            Self::All => max,
            Self::Few(n) => usize::from(n).min(max),
            Self::AllBut(n) => max.saturating_sub(usize::from(n)),
            Self::Any(n) => n as usize % (max + 1),
        }
    }
}

/// A `BufMut` write.
#[derive(Arbitrary, Clone, Copy, Debug)]
enum Put {
    Slice,
    Bytes(u8),
    U8(u8),
}

/// A range passed to `IoBuf::slice`.
#[derive(Arbitrary, Clone, Copy, Debug)]
enum Slice {
    Full,
    From(Amount),
    To(Amount),
    Range(Amount, Amount),
    Inclusive(Amount, Amount),
}

/// How a container is collected from its chunks.
#[derive(Arbitrary, Clone, Copy, Debug)]
enum Collect {
    Vec,
    Iter,
}

/// A way to construct an `IoBuf`.
#[derive(Arbitrary, Clone, Copy, Debug)]
enum BufSource {
    Empty,
    Copy {
        #[arbitrary(with = size)]
        len: usize,
    },
    Vec {
        #[arbitrary(with = size)]
        len: usize,
        #[arbitrary(with = size)]
        spare: usize,
    },
    Bytes {
        #[arbitrary(with = size)]
        len: usize,
    },
    BytesMut {
        #[arbitrary(with = size)]
        len: usize,
        #[arbitrary(with = size)]
        spare: usize,
    },
    Static {
        start: u16,
        len: u16,
    },
    Frozen {
        #[arbitrary(with = size)]
        cap: usize,
        fill: Amount,
        #[arbitrary(with = alignment)]
        align: usize,
    },
    Clone {
        pick: u8,
    },
}

/// A way to construct an `IoBufMut`.
#[derive(Arbitrary, Clone, Copy, Debug)]
enum MutSource {
    Default,
    WithCapacity {
        #[arbitrary(with = size)]
        cap: usize,
    },
    WithAlignment {
        #[arbitrary(with = size)]
        cap: usize,
        #[arbitrary(with = alignment)]
        align: usize,
    },
    Zeroed {
        #[arbitrary(with = size)]
        len: usize,
    },
    ZeroedWithAlignment {
        #[arbitrary(with = size)]
        len: usize,
        #[arbitrary(with = alignment)]
        align: usize,
    },
    Vec {
        #[arbitrary(with = size)]
        len: usize,
        #[arbitrary(with = size)]
        spare: usize,
    },
}

/// A chunk of a new `IoBufsMut`: a new buffer partly filled, or a live `IoBufMut`.
#[derive(Arbitrary, Clone, Copy, Debug)]
enum MutChunk {
    New { source: MutSource, fill: Amount },
    Take { pick: u8 },
}

/// One operation. `pick` selects a live object of the operation's type, and an operation with
/// no such object is skipped.
#[derive(Arbitrary, Debug)]
enum Op {
    NewMut(MutSource),
    MutPut {
        pick: u8,
        put: Put,
        amount: Amount,
    },
    MutOverwrite {
        pick: u8,
    },
    MutTruncate {
        pick: u8,
        len: Amount,
    },
    MutClear {
        pick: u8,
    },
    MutAdvance {
        pick: u8,
        cnt: Amount,
    },
    MutCopyToBytes {
        pick: u8,
        len: Amount,
    },
    MutFreeze {
        pick: u8,
    },
    NewBuf(BufSource),
    BufClone {
        pick: u8,
    },
    BufSlice {
        pick: u8,
        range: Slice,
    },
    BufSplitTo {
        pick: u8,
        at: Amount,
    },
    BufAdvance {
        pick: u8,
        cnt: Amount,
    },
    BufCopyToBytes {
        pick: u8,
        len: Amount,
    },
    BufTryIntoMut {
        pick: u8,
    },
    BufIntoVec {
        pick: u8,
    },
    BufIntoBytes {
        pick: u8,
    },
    BufIntoBufs {
        pick: u8,
    },
    NewBufs {
        #[arbitrary(with = buf_sources)]
        sources: Vec<BufSource>,
        collect: Collect,
    },
    BufsPrepend {
        pick: u8,
        source: BufSource,
    },
    BufsAppend {
        pick: u8,
        source: BufSource,
    },
    BufsSplitTo {
        pick: u8,
        at: Amount,
    },
    BufsAdvance {
        pick: u8,
        cnt: Amount,
    },
    BufsCopyToBytes {
        pick: u8,
        len: Amount,
    },
    BufsCoalesce {
        pick: u8,
    },
    BufsTryIntoSingle {
        pick: u8,
    },
    BufsClone {
        pick: u8,
    },
    NewBufsMut {
        #[arbitrary(with = mut_chunks)]
        chunks: Vec<MutChunk>,
        collect: Collect,
    },
    BufsMutCopyFromSlice {
        pick: u8,
    },
    BufsMutPut {
        pick: u8,
        put: Put,
        amount: Amount,
    },
    BufsMutAdvance {
        pick: u8,
        cnt: Amount,
    },
    BufsMutCopyToBytes {
        pick: u8,
        len: Amount,
    },
    BufsMutCopyToSlice {
        pick: u8,
        len: Amount,
    },
    BufsMutFreeze {
        pick: u8,
    },
    BufsMutCoalesce {
        pick: u8,
    },
    BufsMutTryIntoSingle {
        pick: u8,
    },
    NewBuilder {
        #[arbitrary(with = size)]
        cap: usize,
    },
    BuilderPut {
        pick: u8,
        put: Put,
        amount: Amount,
    },
    BuilderPush {
        pick: u8,
        source: BufSource,
    },
    BuilderFinish {
        pick: u8,
    },
    Drop {
        pick: u8,
    },
}

#[derive(Debug)]
struct FuzzInput {
    ops: Vec<Op>,
    entropy: Entropy,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let (session, entropy) = decode(u)?;
        let u = &mut Unstructured::new(&session);

        let ops = (0..u.int_in_range(1..=MAX_OPS)?)
            .map(|_| u.arbitrary())
            .collect::<arbitrary::Result<_>>()?;
        Ok(Self { ops, entropy })
    }
}

/// Returns `len` bytes that depend on `tag` and on each byte's position.
fn pattern(tag: u64, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut word = 0u64;
    while out.len() < len {
        // splitmix64 finalizer over the tag and the word index.
        let mut x = (tag << 32) ^ word;
        x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        x ^= x >> 31;
        let take = (len - out.len()).min(8);
        out.extend_from_slice(&x.to_le_bytes()[..take]);
        word += 1;
    }
    out
}

/// Describes where `actual` first differs from `model`.
fn describe(model: &[u8], actual: &[u8]) -> String {
    let at = model
        .iter()
        .zip(actual)
        .position(|(m, a)| m != a)
        .unwrap_or_else(|| model.len().min(actual.len()));
    let window = |bytes: &[u8]| {
        let end = (at + 12).min(bytes.len());
        format!("{:02x?}", &bytes[at.saturating_sub(4).min(end)..end])
    };
    format!(
        "model len {}, actual len {}, first difference at {at}: model {} actual {}",
        model.len(),
        actual.len(),
        window(model),
        window(actual)
    )
}

/// What backs an allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// Runtime-owned heap storage or an adopted `Vec<u8>`.
    Native,
    /// A caller-supplied `Bytes`.
    External,
    /// A `'static` slice.
    Static,
}

/// An allocation that views refer to.
#[derive(Clone, Copy, Debug)]
struct Group {
    kind: Kind,
    /// Address of the allocation's first byte.
    base: usize,
    /// Exact size, when known.
    size: Option<usize>,
    /// Lower bound on the size.
    extent: usize,
}

impl Group {
    /// Returns whether `addr` lies in the bytes known to belong to the allocation.
    const fn contains(&self, addr: usize) -> bool {
        let size = match self.size {
            Some(size) => size,
            None => self.extent,
        };
        addr >= self.base && addr < self.base + size
    }
}

/// What an `IoBuf` view holds.
#[derive(Clone, Copy, Debug)]
enum Prov {
    /// An empty view without an owner.
    Detached,
    /// A view `off` bytes into a known allocation, holding a reference to it. It is empty only
    /// after a cursor `advance`, which moves the view but keeps its owner.
    View { group: usize, off: usize },
    /// A view of a `Bytes` whose address is unknown.
    Foreign,
    /// A view whose owner the documentation leaves open.
    Unknown,
}

#[derive(Clone)]
struct BufModel {
    content: Vec<u8>,
    prov: Prov,
}

impl BufModel {
    const fn detached() -> Self {
        Self {
            content: Vec::new(),
            prov: Prov::Detached,
        }
    }

    const fn unknown() -> Self {
        Self {
            content: Vec::new(),
            prov: Prov::Unknown,
        }
    }

    /// A view `off` bytes into `group`, or an unknown owner when `content` is empty.
    fn view(content: Vec<u8>, group: usize, off: usize) -> Self {
        let prov = if content.is_empty() {
            Prov::Unknown
        } else {
            Prov::View { group, off }
        };
        Self { content, prov }
    }

    /// Drops the first `n` bytes as the cursor `advance` does, which uses only the view's
    /// pointer and length and so keeps its owner even when the view becomes empty.
    fn advance(&mut self, n: usize) {
        self.content.drain(..n);
        if let Prov::View { off, .. } = &mut self.prov {
            *off += n;
        }
    }

    /// The bytes `start..end` of this view, with an unknown owner when empty.
    fn sub(&self, start: usize, end: usize) -> Self {
        let content = self.content[start..end].to_vec();
        match self.prov {
            Prov::View { group, off } => Self::view(content, group, off + start),
            _ if content.is_empty() => Self::unknown(),
            prov => Self { content, prov },
        }
    }
}

#[derive(Clone)]
struct MutModel {
    content: Vec<u8>,
    cap: usize,
    /// The allocation group and the offset of the first readable byte. `None` for a handle that
    /// owns no storage, whose capacity is zero.
    alloc: Option<(usize, usize)>,
}

impl MutModel {
    const fn detached() -> Self {
        Self {
            content: Vec::new(),
            cap: 0,
            alloc: None,
        }
    }

    fn spare(&self) -> usize {
        self.cap - self.content.len()
    }

    fn advance(&mut self, n: usize) {
        self.content.drain(..n);
        self.cap -= n;
        if let Some((_, off)) = &mut self.alloc {
            *off += n;
        }
    }

    fn freeze(self) -> BufModel {
        match self.alloc {
            Some((group, off)) if !self.content.is_empty() => {
                BufModel::view(self.content, group, off)
            }
            _ => BufModel::detached(),
        }
    }
}

/// Non-empty chunks in order.
#[derive(Clone)]
struct BufsModel {
    chunks: Vec<BufModel>,
    /// The provenance of the empty single chunk an emptied container still holds with its owner.
    /// Set only while `chunks` is empty. Every other empty container holds the default buffer.
    retained: Option<Prov>,
}

impl BufsModel {
    fn new(chunks: impl IntoIterator<Item = BufModel>) -> Self {
        Self {
            chunks: chunks
                .into_iter()
                .filter(|chunk| !chunk.content.is_empty())
                .collect(),
            retained: None,
        }
    }

    fn content(&self) -> Vec<u8> {
        self.chunks
            .iter()
            .flat_map(|chunk| chunk.content.iter().copied())
            .collect()
    }

    fn len(&self) -> usize {
        self.chunks.iter().map(|chunk| chunk.content.len()).sum()
    }

    /// Splits off the first `at` bytes.
    fn split_to(&mut self, at: usize) -> Self {
        let mut prefix = Vec::new();
        let mut left = at;
        while left > 0 {
            let len = self.chunks[0].content.len();
            if left >= len {
                prefix.push(self.chunks.remove(0));
                left -= len;
            } else {
                prefix.push(self.chunks[0].sub(0, left));
                self.chunks[0] = self.chunks[0].sub(left, len);
                left = 0;
            }
        }
        Self {
            chunks: prefix,
            retained: None,
        }
    }
}

struct BufsMutModel {
    /// The chunks that own storage, in order, until the first read. Writes after a read are
    /// outside the `IoBufsMut` contract, and reads reshape the chunks, so only the content is
    /// tracked from then on.
    chunks: Option<Vec<MutModel>>,
    content: Vec<u8>,
    /// The allocation groups of the chunks it was built from. Those chunks were live at once,
    /// so their ranges are disjoint, and every chunk left after reads lies in exactly one of
    /// them.
    groups: Vec<usize>,
}

impl BufsMutModel {
    fn sync_content(&mut self) {
        if let Some(chunks) = &self.chunks {
            self.content = chunks
                .iter()
                .flat_map(|chunk| chunk.content.iter().copied())
                .collect();
        }
    }
}

enum Segment {
    Inline {
        start: usize,
        bytes: Vec<u8>,
    },
    /// A pushed piece and, when known, the address of its first byte. The builder holds the
    /// piece without copying, so that address stays referenced while the builder lives.
    Pushed {
        model: BufModel,
        addr: Option<usize>,
    },
}

struct BuilderModel {
    cap: usize,
    inline: usize,
    group: Option<usize>,
    segments: Vec<Segment>,
}

enum Obj {
    Mut(IoBufMut, MutModel),
    Buf(IoBuf, BufModel),
    Bufs(IoBufs, BufsModel),
    BufsMut(IoBufsMut, BufsMutModel),
    Builder(IoBufsBuilder, BuilderModel),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tag {
    Mut,
    Buf,
    Bufs,
    BufsMut,
    Builder,
}

impl Obj {
    const fn tag(&self) -> Tag {
        match self {
            Self::Mut(..) => Tag::Mut,
            Self::Buf(..) => Tag::Buf,
            Self::Bufs(..) => Tag::Bufs,
            Self::BufsMut(..) => Tag::BufsMut,
            Self::Builder(..) => Tag::Builder,
        }
    }
}

/// A byte range a live object holds. Exclusive ranges belong to mutable handles.
struct Region {
    start: usize,
    end: usize,
    exclusive: bool,
    slot: usize,
}

/// Defines one `#[cold]`, never-inlined failure function per oracle check, named after the check
/// and tagging its message with that name, so crash deduplication by top frame or by message
/// separates findings by check. The class never depends on the data.
macro_rules! checks {
    ($($variant:ident => $name:ident,)*) => {
        /// The oracle check that failed.
        #[derive(Clone, Copy)]
        enum Check {
            $($variant,)*
        }

        impl Check {
            fn fail(self, ctx: &str, msg: &dyn Display) -> ! {
                match self {
                    $(Self::$variant => oracle::$name(ctx, msg),)*
                }
            }
        }

        /// One failure function per check.
        mod oracle {
            use std::fmt::Display;

            $(
                #[cold]
                #[inline(never)]
                pub(super) fn $name(ctx: &str, msg: &dyn Display) -> ! {
                    panic!("[{}] iobuf oracle violated at {ctx}: {msg}", stringify!($name));
                }
            )*
        }
    };
}

checks! {
    ContentMismatch => content_mismatch,
    ConversionContent => conversion_content,
    LenOrCapacity => len_or_capacity,
    ChunkShape => chunk_shape,
    PointerIdentity => pointer_identity,
    Alignment => alignment,
    AliasOverlap => alias_overlap,
    TryIntoMutSuccessWithHolders => try_into_mut_success_with_holders,
    TryIntoMutSuccessNonNative => try_into_mut_success_non_native,
    TryIntoMutRefused => try_into_mut_refused,
    BufsMutFreezeUnmapped => bufsmut_freeze_unmapped,
}

struct Harness {
    slots: [Option<Obj>; MAX_OBJECTS],
    groups: Vec<Group>,
    tags: u64,
    index: usize,
    ctx: String,
}

impl Harness {
    fn new() -> Self {
        Self {
            slots: Default::default(),
            groups: Vec::new(),
            tags: 0,
            index: 0,
            ctx: String::new(),
        }
    }

    fn fail(&self, check: Check, msg: impl Display) -> ! {
        check.fail(&self.ctx, &msg)
    }

    fn pattern(&mut self, len: usize) -> Vec<u8> {
        self.tags += 1;
        pattern(self.tags, len)
    }

    fn group(
        &mut self,
        kind: Kind,
        base: *const u8,
        size: Option<usize>,
        extent: usize,
        align: usize,
    ) -> usize {
        let base = base as usize;
        if !base.is_multiple_of(align) {
            self.fail(
                Check::Alignment,
                format_args!("{kind:?} allocation at {base:#x} is not aligned to {align}"),
            );
        }
        self.groups.push(Group {
            kind,
            base,
            size,
            extent,
        });
        self.groups.len() - 1
    }

    fn find(&self, tag: Option<Tag>, pick: u8) -> Option<usize> {
        let live: Vec<usize> = self
            .slots
            .iter()
            .enumerate()
            .filter_map(|(i, slot)| {
                slot.as_ref()
                    .filter(|obj| tag.is_none_or(|tag| obj.tag() == tag))
                    .map(|_| i)
            })
            .collect();
        (!live.is_empty()).then(|| live[usize::from(pick) % live.len()])
    }

    fn take(&mut self, tag: Tag, pick: u8) -> Option<(usize, Obj)> {
        let i = self.find(Some(tag), pick)?;
        self.slots[i].take().map(|obj| (i, obj))
    }

    /// Stores `obj` in a free slot, or in place of a live object other than `avoid`.
    fn place(&mut self, obj: Obj, avoid: Option<usize>) {
        let slot = self
            .slots
            .iter()
            .position(Option::is_none)
            .unwrap_or_else(|| {
                let victim = self.index % MAX_OBJECTS;
                if Some(victim) == avoid {
                    (victim + 1) % MAX_OBJECTS
                } else {
                    victim
                }
            });
        self.slots[slot] = Some(obj);
    }

    /// Builds a model for a mutable handle whose capacity and content the model cannot predict.
    fn adopt_mut(&mut self, buf: &IoBufMut, content: Vec<u8>) -> MutModel {
        let cap = buf.capacity();
        if cap < content.len() {
            self.fail(
                Check::LenOrCapacity,
                format_args!("capacity {cap} is below the length {}", content.len()),
            );
        }
        let alloc = (cap > 0).then(|| {
            let group = self.group(Kind::Native, buf.as_ref().as_ptr(), Some(cap), cap, 1);
            (group, 0)
        });
        MutModel {
            content,
            cap,
            alloc,
        }
    }

    /// Builds a model for a freshly allocated mutable handle.
    fn fresh_mut(
        &mut self,
        buf: &IoBufMut,
        cap: usize,
        content: Vec<u8>,
        align: usize,
    ) -> MutModel {
        let alloc = (cap > 0).then(|| {
            let group = self.group(Kind::Native, buf.as_ref().as_ptr(), Some(cap), cap, align);
            (group, 0)
        });
        MutModel {
            content,
            cap,
            alloc,
        }
    }

    fn new_mut(&mut self, source: MutSource) -> (IoBufMut, MutModel) {
        match source {
            MutSource::Default => (IoBufMut::default(), MutModel::detached()),
            MutSource::WithCapacity { cap } => {
                let buf = IoBufMut::with_capacity(cap);
                let model = self.fresh_mut(&buf, cap, Vec::new(), 1);
                (buf, model)
            }
            MutSource::WithAlignment { cap, align } => {
                let buf = IoBufMut::with_alignment(cap, NonZeroUsize::new(align).unwrap());
                let model = self.fresh_mut(&buf, cap, Vec::new(), align);
                (buf, model)
            }
            MutSource::Zeroed { len } => {
                let buf = IoBufMut::zeroed(len);
                let model = self.fresh_mut(&buf, len, vec![0; len], 1);
                (buf, model)
            }
            MutSource::ZeroedWithAlignment { len, align } => {
                let buf = IoBufMut::zeroed_with_alignment(len, NonZeroUsize::new(align).unwrap());
                let model = self.fresh_mut(&buf, len, vec![0; len], align);
                (buf, model)
            }
            MutSource::Vec { len, spare } => {
                let mut vec = Vec::with_capacity(len + spare.min(MAX_SIZE - len));
                vec.extend_from_slice(&self.pattern(len));
                let (base, cap, content) = (vec.as_ptr(), vec.capacity(), vec.clone());
                let buf = IoBufMut::from(vec);
                if cap > 0 && buf.as_ref().as_ptr() != base {
                    self.fail(
                        Check::PointerIdentity,
                        "IoBufMut::from(Vec<u8>) copied instead of adopting the vec",
                    );
                }
                let model = self.fresh_mut(&buf, cap, content, 1);
                (buf, model)
            }
        }
    }

    fn new_buf(&mut self, source: BufSource) -> (IoBuf, BufModel) {
        match source {
            BufSource::Empty => (IoBuf::default(), BufModel::detached()),
            BufSource::Copy { len } => {
                let data = self.pattern(len);
                let buf = IoBuf::copy_from_slice(&data);
                // An empty copy freezes an empty buffer, which holds no owner.
                let model = if data.is_empty() {
                    BufModel::detached()
                } else {
                    let group = self.group(Kind::Native, buf.as_ptr(), None, len, 1);
                    BufModel::view(data, group, 0)
                };
                (buf, model)
            }
            BufSource::Vec { len, spare } => {
                let mut vec = Vec::with_capacity(len + spare.min(MAX_SIZE - len));
                vec.extend_from_slice(&self.pattern(len));
                let (base, cap, content) = (vec.as_ptr(), vec.capacity(), vec.clone());
                let buf = IoBuf::from(vec);
                // An empty vec freezes an empty buffer, which holds no owner.
                let model = if content.is_empty() {
                    BufModel::detached()
                } else {
                    let group = self.group(Kind::Native, base, Some(cap), cap, 1);
                    BufModel::view(content, group, 0)
                };
                (buf, model)
            }
            BufSource::Bytes { len } => {
                let bytes = Bytes::from(self.pattern(len));
                let (base, content) = (bytes.as_ptr(), bytes.to_vec());
                let buf = IoBuf::from(bytes);
                // Empty `Bytes` convert to the default buffer, which holds no owner.
                let model = if content.is_empty() {
                    BufModel::detached()
                } else {
                    let group = self.group(Kind::External, base, Some(len), len, 1);
                    BufModel::view(content, group, 0)
                };
                (buf, model)
            }
            BufSource::BytesMut { len, spare } => {
                let mut bytes = BytesMut::with_capacity(len + spare.min(MAX_SIZE - len));
                bytes.extend_from_slice(&self.pattern(len));
                let (base, content) = (bytes.as_ptr(), bytes.to_vec());
                let buf = IoBuf::from(bytes);
                // Empty `Bytes` convert to the default buffer, which holds no owner.
                let model = if content.is_empty() {
                    BufModel::detached()
                } else {
                    let group = self.group(Kind::External, base, Some(len), len, 1);
                    BufModel::view(content, group, 0)
                };
                (buf, model)
            }
            BufSource::Static { start, len } => {
                let slice = static_slice(start, len);
                let buf = IoBuf::from(slice);
                // A static view holds no owner, so an empty one is detached.
                let model = if slice.is_empty() {
                    BufModel::detached()
                } else {
                    let group = self.group(
                        Kind::Static,
                        slice.as_ptr(),
                        Some(slice.len()),
                        slice.len(),
                        1,
                    );
                    BufModel::view(slice.to_vec(), group, 0)
                };
                (buf, model)
            }
            BufSource::Frozen { cap, fill, align } => {
                let mut staged = IoBufMut::with_alignment(cap, NonZeroUsize::new(align).unwrap());
                let data = self.pattern(fill.resolve(cap));
                staged.put_slice(&data);
                let base = staged.as_ref().as_ptr();
                let buf = staged.freeze();
                // Freezing an empty buffer releases its allocation.
                let model = if data.is_empty() {
                    BufModel::detached()
                } else {
                    let group = self.group(Kind::Native, base, Some(cap), cap, align);
                    BufModel::view(data, group, 0)
                };
                (buf, model)
            }
            BufSource::Clone { pick } => match self.find(Some(Tag::Buf), pick) {
                Some(i) => match &self.slots[i] {
                    Some(Obj::Buf(buf, model)) => (buf.clone(), model.clone()),
                    _ => unreachable!("find returned a slot of another type"),
                },
                None => (IoBuf::default(), BufModel::detached()),
            },
        }
    }

    /// Writes into `dst`, which accepts at most `max` more bytes, and returns the bytes written.
    fn put(&mut self, dst: &mut impl BufMut, put: Put, amount: Amount, max: usize) -> Vec<u8> {
        match put {
            Put::Slice => {
                let data = self.pattern(amount.resolve(max));
                dst.put_slice(&data);
                data
            }
            Put::Bytes(val) => {
                let n = amount.resolve(max);
                dst.put_bytes(val, n);
                vec![val; n]
            }
            Put::U8(val) => {
                if max == 0 {
                    return Vec::new();
                }
                dst.put_u8(val);
                vec![val]
            }
        }
    }

    /// Returns the slots, other than `except`, that certainly hold a reference to the native
    /// allocation `group`: non-empty views whose bytes lie in it, and pieces pushed into a builder.
    fn holders(&self, group: usize, except: usize) -> Vec<usize> {
        let g = self.groups[group];
        let mut holders = Vec::new();
        for (i, slot) in self.slots.iter().enumerate() {
            if i == except {
                continue;
            }
            let holds = match slot {
                // An empty view in the group still holds its owner after an advance.
                Some(Obj::Buf(buf, model)) => {
                    (!buf.is_empty() && g.contains(buf.as_ptr() as usize))
                        || matches!(model.prov, Prov::View { group: g2, .. } if g2 == group)
                }
                Some(Obj::Bufs(bufs, model)) => {
                    matches!(model.retained, Some(Prov::View { group: g2, .. }) if g2 == group)
                        || (0..bufs.chunk_count()).any(|k| {
                            bufs.chunk_at(k)
                                .is_some_and(|c| !c.is_empty() && g.contains(c.as_ptr() as usize))
                        })
                }
                Some(Obj::Builder(_, model)) => {
                    model.segments.iter().any(|segment| match segment {
                        Segment::Pushed { model, addr } => {
                            matches!(model.prov, Prov::View { group: g2, .. } if g2 == group)
                                || addr.is_some_and(|addr| g.contains(addr))
                        }
                        Segment::Inline { .. } => false,
                    })
                }
                _ => false,
            };
            if holds {
                holders.push(i);
            }
        }
        holders
    }

    fn apply(&mut self, op: &Op) {
        match *op {
            Op::NewMut(source) => {
                let (buf, model) = self.new_mut(source);
                self.place(Obj::Mut(buf, model), None);
            }
            Op::MutPut { pick, put, amount } => {
                let Some((i, Obj::Mut(mut buf, mut model))) = self.take(Tag::Mut, pick) else {
                    return;
                };
                let written = self.put(&mut buf, put, amount, model.spare());
                model.content.extend_from_slice(&written);
                self.slots[i] = Some(Obj::Mut(buf, model));
            }
            Op::MutOverwrite { pick } => {
                let Some((i, Obj::Mut(mut buf, mut model))) = self.take(Tag::Mut, pick) else {
                    return;
                };
                let data = self.pattern(model.content.len());
                buf.as_mut().copy_from_slice(&data);
                model.content = data;
                self.slots[i] = Some(Obj::Mut(buf, model));
            }
            Op::MutTruncate { pick, len } => {
                let Some((i, Obj::Mut(mut buf, mut model))) = self.take(Tag::Mut, pick) else {
                    return;
                };
                // Lengths past the current length have no effect.
                let len = len.resolve(model.content.len() + 2);
                buf.truncate(len);
                model.content.truncate(len);
                self.slots[i] = Some(Obj::Mut(buf, model));
            }
            Op::MutClear { pick } => {
                let Some((i, Obj::Mut(mut buf, mut model))) = self.take(Tag::Mut, pick) else {
                    return;
                };
                buf.clear();
                model.content.clear();
                self.slots[i] = Some(Obj::Mut(buf, model));
            }
            Op::MutAdvance { pick, cnt } => {
                let Some((i, Obj::Mut(mut buf, mut model))) = self.take(Tag::Mut, pick) else {
                    return;
                };
                let cnt = cnt.resolve(model.content.len());
                buf.advance(cnt);
                model.advance(cnt);
                self.slots[i] = Some(Obj::Mut(buf, model));
            }
            Op::MutCopyToBytes { pick, len } => {
                let Some((i, Obj::Mut(mut buf, mut model))) = self.take(Tag::Mut, pick) else {
                    return;
                };
                let len = len.resolve(model.content.len());
                let ptr = buf.as_ref().as_ptr();
                let bytes = buf.copy_to_bytes(len);
                self.check_bytes(
                    Check::ConversionContent,
                    "IoBufMut::copy_to_bytes result",
                    &model.content[..len],
                    &bytes,
                );
                if len > 0 && len == model.content.len() {
                    // A full drain moves the whole buffer out and leaves an empty handle with
                    // zero capacity.
                    if bytes.as_ptr() != ptr {
                        self.fail(
                            Check::PointerIdentity,
                            "IoBufMut::copy_to_bytes copied a full drain",
                        );
                    }
                    model = MutModel::detached();
                } else {
                    model.advance(len);
                }
                self.slots[i] = Some(Obj::Mut(buf, model));
            }
            Op::MutFreeze { pick } => {
                let Some((i, Obj::Mut(buf, model))) = self.take(Tag::Mut, pick) else {
                    return;
                };
                self.slots[i] = Some(Obj::Buf(buf.freeze(), model.freeze()));
            }
            Op::NewBuf(source) => {
                let (buf, model) = self.new_buf(source);
                self.place(Obj::Buf(buf, model), None);
            }
            Op::BufClone { pick } => {
                let Some(i) = self.find(Some(Tag::Buf), pick) else {
                    return;
                };
                let Some(Obj::Buf(buf, model)) = &self.slots[i] else {
                    unreachable!("find returned a slot of another type");
                };
                let obj = Obj::Buf(buf.clone(), model.clone());
                self.place(obj, Some(i));
            }
            Op::BufSlice { pick, range } => {
                let Some(i) = self.find(Some(Tag::Buf), pick) else {
                    return;
                };
                let Some(Obj::Buf(buf, model)) = &self.slots[i] else {
                    unreachable!("find returned a slot of another type");
                };
                let len = model.content.len();
                let (start, end, sliced) = match range {
                    Slice::Full => (0, len, buf.slice(..)),
                    Slice::From(a) => {
                        let start = a.resolve(len);
                        (start, len, buf.slice(start..))
                    }
                    Slice::To(b) => {
                        let end = b.resolve(len);
                        (0, end, buf.slice(..end))
                    }
                    Slice::Range(a, b) => {
                        let start = a.resolve(len);
                        let end = start + b.resolve(len - start);
                        (start, end, buf.slice(start..end))
                    }
                    Slice::Inclusive(a, b) => {
                        let start = a.resolve(len);
                        let end = start + b.resolve(len - start);
                        if end > start {
                            (start, end, buf.slice(start..=end - 1))
                        } else {
                            (start, end, buf.slice(start..end))
                        }
                    }
                };
                // An empty range returns a detached buffer.
                let sliced_model = if start == end {
                    BufModel::detached()
                } else {
                    model.sub(start, end)
                };
                self.place(Obj::Buf(sliced, sliced_model), Some(i));
            }
            Op::BufSplitTo { pick, at } => {
                let Some((i, Obj::Buf(mut buf, mut model))) = self.take(Tag::Buf, pick) else {
                    return;
                };
                let len = model.content.len();
                let at = at.resolve(len);
                let prefix = buf.split_to(at);
                // A split at 0 returns the default buffer, which holds no owner, and leaves `self`
                // unchanged. The empty half of a split at either end is detached.
                let prefix_model = if at == 0 {
                    BufModel::detached()
                } else if at == len {
                    std::mem::replace(&mut model, BufModel::detached())
                } else {
                    let prefix_model = model.sub(0, at);
                    model = model.sub(at, len);
                    prefix_model
                };
                self.slots[i] = Some(Obj::Buf(buf, model));
                self.place(Obj::Buf(prefix, prefix_model), Some(i));
            }
            Op::BufAdvance { pick, cnt } => {
                let Some((i, Obj::Buf(mut buf, mut model))) = self.take(Tag::Buf, pick) else {
                    return;
                };
                let cnt = cnt.resolve(model.content.len());
                buf.advance(cnt);
                model.advance(cnt);
                self.slots[i] = Some(Obj::Buf(buf, model));
            }
            Op::BufCopyToBytes { pick, len } => {
                let Some((i, Obj::Buf(mut buf, mut model))) = self.take(Tag::Buf, pick) else {
                    return;
                };
                let total = model.content.len();
                let len = len.resolve(total);
                let ptr = buf.as_ptr();
                let bytes = buf.copy_to_bytes(len);
                self.check_bytes(
                    Check::ConversionContent,
                    "IoBuf::copy_to_bytes result",
                    &model.content[..len],
                    &bytes,
                );
                // The drained prefix is a view, not a copy.
                if len > 0 && bytes.as_ptr() != ptr {
                    self.fail(
                        Check::PointerIdentity,
                        "IoBuf::copy_to_bytes copied its prefix",
                    );
                }
                // A full drain moves the view out and leaves the default buffer behind.
                if len == total && len > 0 {
                    model = BufModel::detached();
                } else if len > 0 {
                    model = model.sub(len, total);
                }
                self.slots[i] = Some(Obj::Buf(buf, model));
            }
            Op::BufTryIntoMut { pick } => self.buf_try_into_mut(pick),
            Op::BufIntoVec { pick } => {
                let Some((_, Obj::Buf(buf, model))) = self.take(Tag::Buf, pick) else {
                    return;
                };
                let vec: Vec<u8> = buf.into();
                self.check_bytes(
                    Check::ConversionContent,
                    "Vec::from(IoBuf)",
                    &model.content,
                    &vec,
                );
            }
            Op::BufIntoBytes { pick } => {
                let Some((_, Obj::Buf(buf, model))) = self.take(Tag::Buf, pick) else {
                    return;
                };
                let ptr = buf.as_ptr();
                let bytes: Bytes = buf.into();
                self.check_bytes(
                    Check::ConversionContent,
                    "Bytes::from(IoBuf)",
                    &model.content,
                    &bytes,
                );
                if !bytes.is_empty() && bytes.as_ptr() != ptr {
                    self.fail(
                        Check::PointerIdentity,
                        "Bytes::from(IoBuf) copied the readable bytes",
                    );
                }
            }
            Op::BufIntoBufs { pick } => {
                let Some((i, Obj::Buf(buf, model))) = self.take(Tag::Buf, pick) else {
                    return;
                };
                // The buffer becomes the single chunk as is, so an empty view keeps its owner.
                let retained = match model.prov {
                    Prov::Detached => None,
                    prov => model.content.is_empty().then_some(prov),
                };
                let mut bufs_model = BufsModel::new([model]);
                bufs_model.retained = retained;
                self.slots[i] = Some(Obj::Bufs(IoBufs::from(buf), bufs_model));
            }
            Op::NewBufs {
                ref sources,
                collect,
            } => {
                let (bufs, models): (Vec<IoBuf>, Vec<BufModel>) =
                    sources.iter().map(|source| self.new_buf(*source)).unzip();
                let bufs = match collect {
                    Collect::Vec => IoBufs::from(bufs),
                    Collect::Iter => bufs.into_iter().collect(),
                };
                self.place(Obj::Bufs(bufs, BufsModel::new(models)), None);
            }
            Op::BufsPrepend { pick, source } => {
                let Some((i, Obj::Bufs(mut bufs, mut model))) = self.take(Tag::Bufs, pick) else {
                    return;
                };
                let (buf, buf_model) = self.new_buf(source);
                bufs.prepend(buf);
                // A non-empty buffer replaces an empty single chunk, and an empty one is ignored.
                if !buf_model.content.is_empty() {
                    model.chunks.insert(0, buf_model);
                    model.retained = None;
                }
                self.slots[i] = Some(Obj::Bufs(bufs, model));
            }
            Op::BufsAppend { pick, source } => {
                let Some((i, Obj::Bufs(mut bufs, mut model))) = self.take(Tag::Bufs, pick) else {
                    return;
                };
                let (buf, buf_model) = self.new_buf(source);
                bufs.append(buf);
                // A non-empty buffer replaces an empty single chunk, and an empty one is ignored.
                if !buf_model.content.is_empty() {
                    model.chunks.push(buf_model);
                    model.retained = None;
                }
                self.slots[i] = Some(Obj::Bufs(bufs, model));
            }
            Op::BufsSplitTo { pick, at } => {
                let Some((i, Obj::Bufs(mut bufs, mut model))) = self.take(Tag::Bufs, pick) else {
                    return;
                };
                let at = at.resolve(model.len());
                let prefix = bufs.split_to(at);
                let prefix_model = model.split_to(at);
                self.slots[i] = Some(Obj::Bufs(bufs, model));
                self.place(Obj::Bufs(prefix, prefix_model), Some(i));
            }
            Op::BufsAdvance { pick, cnt } => {
                let Some((i, Obj::Bufs(mut bufs, mut model))) = self.take(Tag::Bufs, pick) else {
                    return;
                };
                let len = model.len();
                let cnt = cnt.resolve(len);
                bufs.advance(cnt);
                let single = (model.chunks.len() == 1 && cnt == len).then(|| model.chunks[0].prov);
                model.split_to(cnt);
                // Mirrors the `Single` arm of `IoBufs::advance`, which advances the chunk in place
                // without canonicalizing, so a fully drained single chunk keeps its owner. This is
                // implementation behaviour that the docs do not state, so a runtime change that
                // detaches the chunk here shows up as a harness failure.
                if let Some(prov) = single {
                    model.retained = Some(match prov {
                        Prov::View { group, off } => Prov::View {
                            group,
                            off: off + cnt,
                        },
                        prov => prov,
                    });
                }
                self.slots[i] = Some(Obj::Bufs(bufs, model));
            }
            Op::BufsCopyToBytes { pick, len } => {
                let Some((i, Obj::Bufs(mut bufs, mut model))) = self.take(Tag::Bufs, pick) else {
                    return;
                };
                let len = len.resolve(model.len());
                let bytes = bufs.copy_to_bytes(len);
                let prefix = model.split_to(len);
                self.check_bytes(
                    Check::ConversionContent,
                    "IoBufs::copy_to_bytes result",
                    &prefix.content(),
                    &bytes,
                );
                self.slots[i] = Some(Obj::Bufs(bufs, model));
            }
            Op::BufsCoalesce { pick } => {
                let Some((i, Obj::Bufs(bufs, model))) = self.take(Tag::Bufs, pick) else {
                    return;
                };
                let front = bufs.chunk_at(0).map(<[u8]>::as_ptr);
                let buf = bufs.coalesce();
                let buf_model = self.single(model, front, &buf, "IoBufs::coalesce");
                self.slots[i] = Some(Obj::Buf(buf, buf_model));
            }
            Op::BufsTryIntoSingle { pick } => {
                let Some((i, Obj::Bufs(bufs, model))) = self.take(Tag::Bufs, pick) else {
                    return;
                };
                let front = bufs.chunk_at(0).map(<[u8]>::as_ptr);
                match bufs.try_into_single() {
                    Ok(buf) => {
                        if model.chunks.len() > 1 {
                            self.fail(
                                Check::ChunkShape,
                                format_args!(
                                    "IoBufs::try_into_single succeeded with {} chunks",
                                    model.chunks.len()
                                ),
                            );
                        }
                        let buf_model = self.single(model, front, &buf, "IoBufs::try_into_single");
                        self.slots[i] = Some(Obj::Buf(buf, buf_model));
                    }
                    Err(bufs) => {
                        if model.chunks.len() <= 1 {
                            self.fail(
                                Check::ChunkShape,
                                format_args!(
                                    "IoBufs::try_into_single failed with {} chunks",
                                    model.chunks.len()
                                ),
                            );
                        }
                        self.slots[i] = Some(Obj::Bufs(bufs, model));
                    }
                }
            }
            Op::BufsClone { pick } => {
                let Some(i) = self.find(Some(Tag::Bufs), pick) else {
                    return;
                };
                let Some(Obj::Bufs(bufs, model)) = &self.slots[i] else {
                    unreachable!("find returned a slot of another type");
                };
                let obj = Obj::Bufs(bufs.clone(), model.clone());
                self.place(obj, Some(i));
            }
            Op::NewBufsMut {
                ref chunks,
                collect,
            } => {
                let mut bufs = Vec::new();
                let mut models = Vec::new();
                for chunk in chunks {
                    let (buf, model) = match *chunk {
                        MutChunk::New { source, fill } => {
                            let (mut buf, mut model) = self.new_mut(source);
                            let data = self.pattern(fill.resolve(model.spare()));
                            buf.put_slice(&data);
                            model.content.extend_from_slice(&data);
                            (buf, model)
                        }
                        MutChunk::Take { pick } => match self.take(Tag::Mut, pick) {
                            Some((_, Obj::Mut(buf, model))) => (buf, model),
                            _ => continue,
                        },
                    };
                    bufs.push(buf);
                    models.push(model);
                }
                let bufs = match collect {
                    Collect::Vec => IoBufsMut::from(bufs),
                    Collect::Iter => bufs.into_iter().collect(),
                };
                // Collecting drops the chunks without storage.
                let chunks: Vec<MutModel> = models.into_iter().filter(|m| m.cap > 0).collect();
                let groups = chunks
                    .iter()
                    .filter_map(|chunk| chunk.alloc.map(|(group, _)| group))
                    .collect();
                let mut model = BufsMutModel {
                    chunks: Some(chunks),
                    content: Vec::new(),
                    groups,
                };
                model.sync_content();
                self.place(Obj::BufsMut(bufs, model), None);
            }
            Op::BufsMutCopyFromSlice { pick } => {
                let Some((i, Obj::BufsMut(mut bufs, mut model))) = self.take(Tag::BufsMut, pick)
                else {
                    return;
                };
                if let Some(chunks) = &mut model.chunks {
                    let data = self.pattern(model.content.len());
                    bufs.copy_from_slice(&data);
                    let mut pos = 0;
                    for chunk in chunks.iter_mut() {
                        let len = chunk.content.len();
                        chunk.content.copy_from_slice(&data[pos..pos + len]);
                        pos += len;
                    }
                    model.sync_content();
                }
                self.slots[i] = Some(Obj::BufsMut(bufs, model));
            }
            Op::BufsMutPut { pick, put, amount } => {
                let Some((i, Obj::BufsMut(mut bufs, mut model))) = self.take(Tag::BufsMut, pick)
                else {
                    return;
                };
                if let Some(mut chunks) = model.chunks.take() {
                    let max = chunks.iter().map(MutModel::spare).sum();
                    let written = self.put(&mut bufs, put, amount, max);
                    // Writes fill the first chunk with spare capacity, then the next.
                    let mut pos = 0;
                    for chunk in chunks.iter_mut() {
                        let n = chunk.spare().min(written.len() - pos);
                        chunk.content.extend_from_slice(&written[pos..pos + n]);
                        pos += n;
                    }
                    model.chunks = Some(chunks);
                    model.sync_content();
                }
                self.slots[i] = Some(Obj::BufsMut(bufs, model));
            }
            Op::BufsMutAdvance { pick, cnt } => {
                let Some((i, Obj::BufsMut(mut bufs, mut model))) = self.take(Tag::BufsMut, pick)
                else {
                    return;
                };
                let cnt = cnt.resolve(model.content.len());
                bufs.advance(cnt);
                model.chunks = None;
                model.content.drain(..cnt);
                self.slots[i] = Some(Obj::BufsMut(bufs, model));
            }
            Op::BufsMutCopyToBytes { pick, len } => {
                let Some((i, Obj::BufsMut(mut bufs, mut model))) = self.take(Tag::BufsMut, pick)
                else {
                    return;
                };
                let len = len.resolve(model.content.len());
                let bytes = bufs.copy_to_bytes(len);
                model.chunks = None;
                let prefix: Vec<u8> = model.content.drain(..len).collect();
                self.check_bytes(
                    Check::ConversionContent,
                    "IoBufsMut::copy_to_bytes result",
                    &prefix,
                    &bytes,
                );
                self.slots[i] = Some(Obj::BufsMut(bufs, model));
            }
            Op::BufsMutCopyToSlice { pick, len } => {
                let Some((i, Obj::BufsMut(mut bufs, mut model))) = self.take(Tag::BufsMut, pick)
                else {
                    return;
                };
                let mut dst = vec![0; len.resolve(model.content.len())];
                bufs.copy_to_slice(&mut dst);
                model.chunks = None;
                let prefix: Vec<u8> = model.content.drain(..dst.len()).collect();
                self.check_bytes(
                    Check::ConversionContent,
                    "IoBufsMut::copy_to_slice result",
                    &prefix,
                    &dst,
                );
                self.slots[i] = Some(Obj::BufsMut(bufs, model));
            }
            Op::BufsMutFreeze { pick } => {
                let Some((i, Obj::BufsMut(bufs, model))) = self.take(Tag::BufsMut, pick) else {
                    return;
                };
                let frozen = bufs.freeze();
                let frozen_model = match model.chunks {
                    Some(chunks) => BufsModel::new(chunks.into_iter().map(MutModel::freeze)),
                    None => {
                        self.check_bytes(
                            Check::ConversionContent,
                            "IoBufsMut::freeze result",
                            &model.content,
                            &chunks_of(&frozen).concat(),
                        );
                        // Reads reshape the chunks but never copy them, so each frozen chunk
                        // views the allocation of the original chunk whose range holds it.
                        let chunks = (0..frozen.chunk_count())
                            .filter_map(|k| frozen.chunk_at(k))
                            .map(|chunk| {
                                let addr = chunk.as_ptr() as usize;
                                let end = addr + chunk.len();
                                let owner = model.groups.iter().copied().find(|&group| {
                                    let g = self.groups[group];
                                    g.contains(addr) && g.size.is_some_and(|s| end <= g.base + s)
                                });
                                match owner {
                                    Some(group) => {
                                        let off = addr - self.groups[group].base;
                                        BufModel::view(chunk.to_vec(), group, off)
                                    }
                                    // Every chunk is an `IoBufMut` with storage in a known group.
                                    None if !chunk.is_empty() => self.fail(Check::BufsMutFreezeUnmapped, format_args!(
                                        "IoBufsMut::freeze chunk {addr:#x}..{end:#x} lies outside \
                                         the allocations it was built from"
                                    )),
                                    None => BufModel::unknown(),
                                }
                            })
                            .collect::<Vec<_>>();
                        BufsModel::new(chunks)
                    }
                };
                self.slots[i] = Some(Obj::Bufs(frozen, frozen_model));
            }
            Op::BufsMutCoalesce { pick } => {
                let Some((i, Obj::BufsMut(bufs, model))) = self.take(Tag::BufsMut, pick) else {
                    return;
                };
                let buf = bufs.coalesce();
                self.check_bytes(
                    Check::ConversionContent,
                    "IoBufsMut::coalesce result",
                    &model.content,
                    buf.as_ref(),
                );
                let buf_model = match model.chunks {
                    // A single chunk returns as is.
                    Some(mut chunks) if chunks.len() <= 1 => {
                        chunks.pop().unwrap_or_else(MutModel::detached)
                    }
                    // Several chunks copy into one allocation of exactly the readable length.
                    Some(_) => {
                        if buf.capacity() != model.content.len() {
                            self.fail(Check::LenOrCapacity, format_args!(
                                "IoBufsMut::coalesce of several chunks has capacity {}, expected {}",
                                buf.capacity(),
                                model.content.len()
                            ));
                        }
                        self.adopt_mut(&buf, model.content)
                    }
                    None => self.adopt_mut(&buf, model.content),
                };
                self.slots[i] = Some(Obj::Mut(buf, buf_model));
            }
            Op::BufsMutTryIntoSingle { pick } => {
                let Some((i, Obj::BufsMut(bufs, model))) = self.take(Tag::BufsMut, pick) else {
                    return;
                };
                let chunk_count = model.chunks.as_ref().map(Vec::len);
                match bufs.try_into_single() {
                    Ok(buf) => {
                        self.check_bytes(
                            Check::ConversionContent,
                            "IoBufsMut::try_into_single result",
                            &model.content,
                            buf.as_ref(),
                        );
                        let buf_model = match model.chunks {
                            Some(mut chunks) if chunks.len() <= 1 => {
                                chunks.pop().unwrap_or_else(MutModel::detached)
                            }
                            Some(chunks) => self.fail(
                                Check::ChunkShape,
                                format_args!(
                                    "IoBufsMut::try_into_single succeeded with {} chunks",
                                    chunks.len()
                                ),
                            ),
                            None => self.adopt_mut(&buf, model.content),
                        };
                        self.slots[i] = Some(Obj::Mut(buf, buf_model));
                    }
                    Err(bufs) => {
                        if let Some(count @ 0..=1) = chunk_count {
                            self.fail(
                                Check::ChunkShape,
                                format_args!(
                                    "IoBufsMut::try_into_single failed with {count} chunks"
                                ),
                            );
                        }
                        self.slots[i] = Some(Obj::BufsMut(bufs, model));
                    }
                }
            }
            Op::NewBuilder { cap } => {
                let mut builder = IoBufsBuilder::new(cap);
                let base = builder.chunk_mut().as_mut_ptr();
                let group = (cap > 0).then(|| self.group(Kind::Native, base, Some(cap), cap, 1));
                let model = BuilderModel {
                    cap,
                    inline: 0,
                    group,
                    segments: Vec::new(),
                };
                self.place(Obj::Builder(builder, model), None);
            }
            Op::BuilderPut { pick, put, amount } => {
                let Some((i, Obj::Builder(mut builder, mut model))) = self.take(Tag::Builder, pick)
                else {
                    return;
                };
                let written = self.put(&mut builder, put, amount, model.cap - model.inline);
                if !written.is_empty() {
                    let start = model.inline;
                    model.inline += written.len();
                    match model.segments.last_mut() {
                        Some(Segment::Inline { bytes, .. }) => bytes.extend_from_slice(&written),
                        _ => model.segments.push(Segment::Inline {
                            start,
                            bytes: written,
                        }),
                    }
                }
                self.slots[i] = Some(Obj::Builder(builder, model));
            }
            Op::BuilderPush { pick, source } => {
                let Some((i, Obj::Builder(mut builder, mut model))) = self.take(Tag::Builder, pick)
                else {
                    return;
                };
                let (pushed, addr) = match source {
                    // Non-`IoBuf` pieces become `Bytes`, held without copying.
                    BufSource::Bytes { len } => {
                        let bytes = Bytes::from(self.pattern(len));
                        let (base, content) = (bytes.as_ptr(), bytes.to_vec());
                        builder.push(bytes);
                        if content.is_empty() {
                            (BufModel::unknown(), None)
                        } else {
                            let group = self.group(Kind::External, base, Some(len), len, 1);
                            (BufModel::view(content, group, 0), Some(base as usize))
                        }
                    }
                    BufSource::Static { start, len } => {
                        let slice = static_slice(start, len);
                        builder.push(slice);
                        if slice.is_empty() {
                            (BufModel::unknown(), None)
                        } else {
                            let group = self.group(
                                Kind::External,
                                slice.as_ptr(),
                                Some(slice.len()),
                                slice.len(),
                                1,
                            );
                            let addr = slice.as_ptr() as usize;
                            (BufModel::view(slice.to_vec(), group, 0), Some(addr))
                        }
                    }
                    BufSource::Vec { len, spare } => {
                        let mut vec = Vec::with_capacity(len + spare.min(MAX_SIZE - len));
                        vec.extend_from_slice(&self.pattern(len));
                        let content = vec.clone();
                        builder.push(vec);
                        let model = BufModel {
                            content,
                            prov: Prov::Foreign,
                        };
                        (model, None)
                    }
                    // A pushed `IoBuf` becomes a chunk as is.
                    source => {
                        let (buf, model) = self.new_buf(source);
                        let addr = buf.as_ptr() as usize;
                        builder.push(buf);
                        (model, Some(addr))
                    }
                };
                // Empty pieces are ignored.
                if !pushed.content.is_empty() {
                    model.segments.push(Segment::Pushed {
                        model: pushed,
                        addr,
                    });
                }
                self.slots[i] = Some(Obj::Builder(builder, model));
            }
            Op::BuilderFinish { pick } => {
                let Some((i, Obj::Builder(builder, model))) = self.take(Tag::Builder, pick) else {
                    return;
                };
                let bufs = builder.finish();
                let group = model.group;
                let bufs_model =
                    BufsModel::new(model.segments.into_iter().map(|segment| match segment {
                        Segment::Inline { start, bytes } => BufModel::view(
                            bytes,
                            group.expect("inline bytes need an inline buffer"),
                            start,
                        ),
                        Segment::Pushed { model, .. } => model,
                    }));
                self.slots[i] = Some(Obj::Bufs(bufs, bufs_model));
            }
            Op::Drop { pick } => {
                if let Some(i) = self.find(None, pick) {
                    self.slots[i] = None;
                }
            }
        }
    }

    /// Model of the `IoBuf` that `IoBufs::coalesce` or a successful `try_into_single` returned.
    /// `front` is the address of the container's first chunk.
    fn single(
        &mut self,
        model: BufsModel,
        front: Option<*const u8>,
        buf: &IoBuf,
        what: &str,
    ) -> BufModel {
        let content = model.content();
        self.check_bytes(Check::ConversionContent, what, &content, buf.as_ref());
        match model.chunks.len() {
            // An emptied single chunk returns as is, with its owner. Any other empty container
            // holds the default buffer: canonicalizing, `take`, `split_to(0)` and empty
            // construction all leave `Single(IoBuf::default())`.
            0 => match model.retained {
                Some(prov) => BufModel {
                    content: Vec::new(),
                    prov,
                },
                None => BufModel::detached(),
            },
            // A single chunk returns as is.
            1 => {
                if front != Some(buf.as_ptr()) {
                    self.fail(
                        Check::PointerIdentity,
                        format_args!("{what} copied its only chunk"),
                    );
                }
                model.chunks.into_iter().next().unwrap()
            }
            // Several chunks copy into one native allocation.
            _ => {
                let group = self.group(Kind::Native, buf.as_ptr(), None, content.len(), 1);
                BufModel::view(content, group, 0)
            }
        }
    }

    fn buf_try_into_mut(&mut self, pick: u8) {
        let Some((i, Obj::Buf(buf, model))) = self.take(Tag::Buf, pick) else {
            return;
        };
        let holders = match model.prov {
            Prov::View { group, .. } if self.groups[group].kind == Kind::Native => {
                self.holders(group, i)
            }
            _ => Vec::new(),
        };
        match buf.try_into_mut() {
            Ok(recovered) => {
                self.check_bytes(
                    Check::ConversionContent,
                    "IoBuf::try_into_mut result",
                    &model.content,
                    recovered.as_ref(),
                );
                let mut_model = match model.prov {
                    Prov::Detached | Prov::Unknown => self.adopt_mut(&recovered, model.content),
                    // A static view holds no owner, so an empty one converts.
                    Prov::View { group, .. }
                        if self.groups[group].kind == Kind::Static && model.content.is_empty() =>
                    {
                        self.adopt_mut(&recovered, model.content)
                    }
                    Prov::Foreign => self.fail(
                        Check::TryIntoMutSuccessNonNative,
                        "IoBuf::try_into_mut succeeded on a view of Bytes",
                    ),
                    Prov::View { group, off } => {
                        let g = self.groups[group];
                        match g.kind {
                            Kind::External => self.fail(
                                Check::TryIntoMutSuccessNonNative,
                                "IoBuf::try_into_mut succeeded on a view of Bytes",
                            ),
                            Kind::Static => self.fail(
                                Check::TryIntoMutSuccessNonNative,
                                "IoBuf::try_into_mut succeeded on a non-empty static view",
                            ),
                            Kind::Native => {}
                        }
                        if !holders.is_empty() {
                            self.fail(Check::TryIntoMutSuccessWithHolders, format_args!(
                                "IoBuf::try_into_mut succeeded while slots {holders:?} view the same allocation"
                            ));
                        }
                        let ptr = recovered.as_ref().as_ptr() as usize;
                        if ptr != g.base + off {
                            self.fail(
                                Check::PointerIdentity,
                                format_args!(
                                    "IoBuf::try_into_mut moved the view from {:#x} to {ptr:#x}",
                                    g.base + off
                                ),
                            );
                        }
                        // The recovered capacity runs to the end of the allocation.
                        let cap = recovered.capacity();
                        match g.size {
                            Some(size) if cap != size - off => self.fail(
                                Check::LenOrCapacity,
                                format_args!(
                                    "IoBuf::try_into_mut recovered capacity {cap}, expected {}",
                                    size - off
                                ),
                            ),
                            Some(_) => {}
                            None if off + cap < g.extent => self.fail(
                                Check::LenOrCapacity,
                                format_args!(
                                    "IoBuf::try_into_mut recovered capacity {cap}, below the known \
                                 allocation end {}",
                                    g.extent - off
                                ),
                            ),
                            None => self.groups[group].size = Some(off + cap),
                        }
                        MutModel {
                            content: model.content,
                            cap,
                            alloc: Some((group, off)),
                        }
                    }
                };
                self.slots[i] = Some(Obj::Mut(recovered, mut_model));
            }
            Err(buf) => {
                // An empty view without an owner always converts, and so does the only handle to
                // a native allocation. `holders` sees every live handle the harness keeps.
                let ownerless = match model.prov {
                    Prov::Detached => true,
                    Prov::View { group, .. } => {
                        self.groups[group].kind == Kind::Static && model.content.is_empty()
                    }
                    _ => false,
                };
                if ownerless {
                    self.fail(
                        Check::TryIntoMutRefused,
                        "IoBuf::try_into_mut failed on an empty view without an owner",
                    );
                }
                if let Prov::View { group, off } = model.prov
                    && self.groups[group].kind == Kind::Native
                    && holders.is_empty()
                {
                    self.fail(
                        Check::TryIntoMutRefused,
                        format_args!(
                            "IoBuf::try_into_mut failed on the only handle to a native allocation \
                         ({:?}, offset {off}, len {})",
                            self.groups[group],
                            model.content.len()
                        ),
                    );
                }
                self.slots[i] = Some(Obj::Buf(buf, model));
            }
        }
    }

    fn check_bytes(&self, check: Check, what: &str, model: &[u8], actual: &[u8]) {
        if model != actual {
            self.fail(
                check,
                format_args!("{what} differs from the model: {}", describe(model, actual)),
            );
        }
    }

    fn check_len(&self, check: Check, what: &str, name: &str, model: usize, actual: usize) {
        if model != actual {
            self.fail(
                check,
                format_args!("{what}: {name} is {actual}, model {model}"),
            );
        }
    }

    fn check_ptr(&self, what: &str, prov: Prov, actual: *const u8) {
        if let Prov::View { group, off } = prov {
            let expected = self.groups[group].base + off;
            if actual as usize != expected {
                self.fail(
                    Check::PointerIdentity,
                    format_args!(
                        "{what}: view starts at {:#x}, model {expected:#x} ({:?})",
                        actual as usize, self.groups[group]
                    ),
                );
            }
        }
    }

    fn check_buf(&self, what: &str, buf: &IoBuf, model: &BufModel) {
        let len = model.content.len();
        self.check_len(Check::LenOrCapacity, what, "len", len, buf.len());
        self.check_len(
            Check::LenOrCapacity,
            what,
            "remaining",
            len,
            buf.remaining(),
        );
        self.check_len(
            Check::LenOrCapacity,
            what,
            "is_empty",
            usize::from(len == 0),
            usize::from(buf.is_empty()),
        );
        self.check_bytes(Check::ContentMismatch, what, &model.content, buf.as_ref());
        self.check_bytes(Check::ContentMismatch, what, &model.content, buf.chunk());
        self.check_ptr(what, model.prov, buf.as_ptr());
    }

    fn check_mut(&self, what: &str, buf: &IoBufMut, model: &MutModel) {
        let len = model.content.len();
        self.check_len(Check::LenOrCapacity, what, "len", len, buf.len());
        self.check_len(
            Check::LenOrCapacity,
            what,
            "remaining",
            len,
            buf.remaining(),
        );
        self.check_len(
            Check::LenOrCapacity,
            what,
            "is_empty",
            usize::from(len == 0),
            usize::from(buf.is_empty()),
        );
        self.check_len(
            Check::LenOrCapacity,
            what,
            "capacity",
            model.cap,
            buf.capacity(),
        );
        self.check_len(
            Check::LenOrCapacity,
            what,
            "remaining_mut",
            model.spare(),
            buf.remaining_mut(),
        );
        self.check_bytes(Check::ContentMismatch, what, &model.content, buf.as_ref());
        self.check_bytes(Check::ContentMismatch, what, &model.content, buf.chunk());
        if let Some((group, off)) = model.alloc {
            self.check_ptr(what, Prov::View { group, off }, buf.as_ref().as_ptr());
        }
    }

    fn check_bufs(&self, what: &str, bufs: &IoBufs, model: &BufsModel) {
        let len = model.len();
        self.check_len(Check::LenOrCapacity, what, "len", len, bufs.len());
        self.check_len(
            Check::LenOrCapacity,
            what,
            "remaining",
            len,
            bufs.remaining(),
        );
        self.check_len(
            Check::LenOrCapacity,
            what,
            "is_empty",
            usize::from(len == 0),
            usize::from(bufs.is_empty()),
        );

        // `chunk_count` counts the non-empty readable chunks, which `chunk_at` returns in order.
        let count = bufs.chunk_count();
        self.check_len(
            Check::ChunkShape,
            what,
            "chunk_count",
            model.chunks.len(),
            count,
        );
        for (k, chunk_model) in model.chunks.iter().enumerate() {
            let Some(chunk) = bufs.chunk_at(k) else {
                self.fail(
                    Check::ChunkShape,
                    format_args!("{what}: chunk_at({k}) is None below chunk_count"),
                );
            };
            let name = format!("{what} chunk {k}");
            self.check_bytes(Check::ContentMismatch, &name, &chunk_model.content, chunk);
            self.check_ptr(&name, chunk_model.prov, chunk.as_ptr());
        }
        if bufs.chunk_at(count).is_some() {
            self.fail(
                Check::ChunkShape,
                format_args!("{what}: chunk_at({count}) is Some at chunk_count"),
            );
        }

        let mut visits = 0;
        let mut differs = None;
        bufs.for_each_chunk(|chunk| {
            let expected = model.chunks.get(visits).map(|c| &c.content[..]);
            if differs.is_none() && expected != Some(chunk) {
                differs = Some(visits);
            }
            visits += 1;
        });
        if let Some(k) = differs {
            self.fail(
                Check::ChunkShape,
                format_args!("{what}: for_each_chunk visit {k} differs from the model"),
            );
        }
        self.check_len(
            Check::ChunkShape,
            what,
            "for_each_chunk visits",
            count,
            visits,
        );

        let mut slices = [IoSlice::new(&[]); MAX_CHUNKS + 3];
        let filled = bufs.chunks_vectored(&mut slices);
        self.check_len(
            Check::ChunkShape,
            what,
            "chunks_vectored",
            count.min(slices.len()),
            filled,
        );
        for (k, slice) in slices[..filled].iter().enumerate() {
            self.check_bytes(
                Check::ContentMismatch,
                &format!("{what} chunks_vectored {k}"),
                &model.chunks[k].content,
                slice,
            );
        }

        let first = model.chunks.first().map_or(&[][..], |c| &c.content[..]);
        self.check_bytes(
            Check::ContentMismatch,
            &format!("{what} chunk"),
            first,
            bufs.chunk(),
        );
        if bufs.is_single() != bufs.as_single().is_some() {
            self.fail(
                Check::ChunkShape,
                format_args!("{what}: is_single disagrees with as_single"),
            );
        }
        // A single buffer holds every remaining byte.
        if bufs.is_single() && bufs.chunk().len() != len {
            self.fail(
                Check::ChunkShape,
                format_args!(
                    "{what}: is_single holds {} of {len} bytes",
                    bufs.chunk().len()
                ),
            );
        }
    }

    fn check_bufs_mut(&self, what: &str, bufs: &IoBufsMut, model: &BufsMutModel) {
        let len = model.content.len();
        self.check_len(Check::LenOrCapacity, what, "len", len, bufs.len());
        self.check_len(
            Check::LenOrCapacity,
            what,
            "remaining",
            len,
            bufs.remaining(),
        );
        self.check_len(
            Check::LenOrCapacity,
            what,
            "is_empty",
            usize::from(len == 0),
            usize::from(bufs.is_empty()),
        );
        if bufs.capacity() < len {
            self.fail(
                Check::LenOrCapacity,
                format_args!(
                    "{what}: capacity {} is below the length {len}",
                    bufs.capacity()
                ),
            );
        }

        let mut slices = [IoSlice::new(&[]); MAX_CHUNKS + 3];
        let filled = bufs.chunks_vectored(&mut slices);
        let mut pos = 0;
        for (k, slice) in slices[..filled].iter().enumerate() {
            let end = pos + slice.len();
            let expected = model.content.get(pos..end).unwrap_or(&[]);
            self.check_bytes(
                Check::ContentMismatch,
                &format!("{what} chunks_vectored {k} at {pos}"),
                expected,
                slice,
            );
            pos = end;
        }
        self.check_len(
            Check::LenOrCapacity,
            what,
            "chunks_vectored bytes",
            len,
            pos,
        );
        let first = slices[..filled].first().map_or(&[][..], |s| &s[..]);
        self.check_bytes(
            Check::ContentMismatch,
            &format!("{what} chunk"),
            first,
            bufs.chunk(),
        );
        if bufs.is_single() != bufs.as_single().is_some() {
            self.fail(
                Check::ChunkShape,
                format_args!("{what}: is_single disagrees with as_single"),
            );
        }
        if bufs.is_single() && bufs.chunk().len() != len {
            self.fail(
                Check::ChunkShape,
                format_args!(
                    "{what}: is_single holds {} of {len} bytes",
                    bufs.chunk().len()
                ),
            );
        }

        let Some(chunks) = &model.chunks else {
            return;
        };
        let cap = chunks.iter().map(|c| c.cap).sum();
        self.check_len(Check::LenOrCapacity, what, "capacity", cap, bufs.capacity());
        let spare = chunks.iter().map(MutModel::spare).sum();
        self.check_len(
            Check::LenOrCapacity,
            what,
            "remaining_mut",
            spare,
            bufs.remaining_mut(),
        );
        self.check_len(
            Check::ChunkShape,
            what,
            "is_single",
            usize::from(chunks.len() <= 1),
            usize::from(bufs.is_single()),
        );
        let readable: Vec<&MutModel> = chunks.iter().filter(|c| !c.content.is_empty()).collect();
        self.check_len(
            Check::ChunkShape,
            what,
            "readable chunks",
            readable.len(),
            filled,
        );
        for (k, (chunk, slice)) in readable.iter().zip(&slices[..filled]).enumerate() {
            let name = format!("{what} readable chunk {k}");
            self.check_bytes(Check::ContentMismatch, &name, &chunk.content, slice);
            if let Some((group, off)) = chunk.alloc {
                self.check_ptr(&name, Prov::View { group, off }, slice.as_ptr());
            }
        }
    }

    fn check_builder(&self, what: &str, builder: &IoBufsBuilder, model: &BuilderModel) {
        self.check_len(
            Check::LenOrCapacity,
            what,
            "remaining_mut",
            model.cap - model.inline,
            builder.remaining_mut(),
        );
    }

    /// Checks that no mutable handle's storage overlaps another live buffer.
    fn check_regions(&self) {
        let mut regions = Vec::new();
        for (slot, obj) in self.slots.iter().enumerate() {
            let mut add = |start: usize, len: usize, exclusive: bool| {
                if len > 0 {
                    regions.push(Region {
                        start,
                        end: start + len,
                        exclusive,
                        slot,
                    });
                }
            };
            match obj {
                None => {}
                Some(Obj::Mut(buf, _)) => add(buf.as_ref().as_ptr() as usize, buf.capacity(), true),
                Some(Obj::Buf(buf, _)) => add(buf.as_ptr() as usize, buf.len(), false),
                Some(Obj::Bufs(bufs, _)) => {
                    for k in 0..bufs.chunk_count() {
                        if let Some(chunk) = bufs.chunk_at(k) {
                            add(chunk.as_ptr() as usize, chunk.len(), false);
                        }
                    }
                }
                Some(Obj::BufsMut(bufs, model)) => match &model.chunks {
                    Some(chunks) => {
                        for chunk in chunks {
                            if let Some((group, off)) = chunk.alloc {
                                add(self.groups[group].base + off, chunk.cap, true);
                            }
                        }
                    }
                    None => {
                        let mut slices = [IoSlice::new(&[]); MAX_CHUNKS + 3];
                        let filled = bufs.chunks_vectored(&mut slices);
                        for slice in &slices[..filled] {
                            add(slice.as_ptr() as usize, slice.len(), true);
                        }
                    }
                },
                Some(Obj::Builder(_, model)) => {
                    // The inline buffer is an `IoBufMut` the builder owns until `finish`.
                    if let Some(group) = model.group {
                        add(self.groups[group].base, model.cap, true);
                    }
                    for segment in &model.segments {
                        if let Segment::Pushed {
                            model,
                            addr: Some(addr),
                        } = segment
                        {
                            add(*addr, model.content.len(), false);
                        }
                    }
                }
            }
        }
        for (a, ra) in regions.iter().enumerate() {
            for rb in &regions[a + 1..] {
                if (ra.exclusive || rb.exclusive) && ra.start < rb.end && rb.start < ra.end {
                    self.fail(
                        Check::AliasOverlap,
                        format_args!(
                            "slot {} range {:#x}..{:#x} (exclusive: {}) overlaps slot {} range \
                         {:#x}..{:#x} (exclusive: {})",
                            ra.slot,
                            ra.start,
                            ra.end,
                            ra.exclusive,
                            rb.slot,
                            rb.start,
                            rb.end,
                            rb.exclusive
                        ),
                    );
                }
            }
        }
    }

    fn check_all(&self) {
        for (i, slot) in self.slots.iter().enumerate() {
            match slot {
                None => {}
                Some(Obj::Mut(buf, model)) => {
                    self.check_mut(&format!("slot {i} IoBufMut"), buf, model)
                }
                Some(Obj::Buf(buf, model)) => {
                    self.check_buf(&format!("slot {i} IoBuf"), buf, model)
                }
                Some(Obj::Bufs(bufs, model)) => {
                    self.check_bufs(&format!("slot {i} IoBufs"), bufs, model)
                }
                Some(Obj::BufsMut(bufs, model)) => {
                    self.check_bufs_mut(&format!("slot {i} IoBufsMut"), bufs, model)
                }
                Some(Obj::Builder(builder, model)) => {
                    self.check_builder(&format!("slot {i} IoBufsBuilder"), builder, model)
                }
            }
        }
        self.check_regions();
    }
}

/// A slice of [`POOL`] from `start`, at most `len` bytes long.
fn static_slice(start: u16, len: u16) -> &'static [u8] {
    let start = usize::from(start) % POOL_LEN;
    let len = usize::from(len) % (POOL_LEN - start + 1);
    &POOL[start..start + len]
}

/// The readable chunks of `bufs`, in order.
fn chunks_of(bufs: &IoBufs) -> Vec<Vec<u8>> {
    (0..bufs.chunk_count())
        .filter_map(|k| bufs.chunk_at(k).map(<[u8]>::to_vec))
        .collect()
}

fn fuzz(input: FuzzInput) {
    let cfg = deterministic::Config::new().with_rng(FuzzRng::from(input.entropy));
    let ops = input.ops;
    deterministic::Runner::new(cfg).start(|_context| async move {
        let mut harness = Harness::new();
        for (index, op) in ops.iter().enumerate() {
            harness.index = index;
            harness.ctx = format!("op {index} {op:?}");
            harness.apply(op);
            harness.check_all();
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
