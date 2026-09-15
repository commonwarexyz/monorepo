//! Derive macros for structural codecs.

/// Derives both [`Write`] and [`EncodeSize`].
///
/// The codec's blanket implementation then supplies `Encode`. This accepts
/// the same attributes as the independent derives. Do not combine it with
/// `Write`, `EncodeSize`, or `FixedSize` derives on the same type.
///
/// # Examples
///
/// ```
/// use commonware_codec::Encode;
/// #[derive(Encode)]
/// struct Raw(
///     #[codec(
///         encode_with = {
///             buf.put_slice(value);
///         },
///         encode_size = value.len()
///     )]
///     Vec<u8>,
/// );
/// assert_eq!(Raw(vec![3, 7]).encode().as_ref(), &[3, 7]);
/// ```
pub use commonware_codec_macros::Encode;
/// Derives `commonware_codec::EncodeSize` independently of writing.
///
/// Field sizes are summed, including a one-byte tag for enums. Ordinary fields
/// delegate `encode_inline_size` separately from `encode_size`. Explicit size
/// overrides instruct derived [`Write`] to use ordinary writes for the overridden
/// field or whole container so their bytes are all inline. A handwritten `Write`
/// implementation must uphold the same inline-size contract.
///
/// `#[codec(encode_size = expression)]` on a field overrides its size, with
/// `value` bound to a reference to that field. A container can override the
/// entire size using `#[codec(encode_size = expression)]` or
/// `#[encode_size(expression)]`, with `self` available. Overrides also supply
/// the inline size, so container overrides should budget the entire encoding.
/// A field with custom `encode_with` must have a field or container size
/// override: its Rust type does not determine its custom encoded size.
/// `#[codec(encode_size_bounds(T: Trait, ...))]` replaces inferred field bounds
/// for this implementation; see [`Write`] for the shared bound-override rules.
/// Use the parenthesized form for expressions such as
/// `#[encode_size(1 + self.field.encode_size())]`; Rust's outer name-value
/// attributes only accept literal values.
///
/// Do not combine this derive with [`FixedSize`], which already supplies
/// `EncodeSize` through a blanket implementation.
///
/// ```compile_fail
/// use commonware_codec::EncodeSize;
/// #[derive(EncodeSize)]
/// struct Invalid(#[codec(encode_with = { let _ = value; })] u8);
/// ```
///
/// # Examples
///
/// ```
/// use commonware_codec::EncodeSize;
/// #[derive(EncodeSize)]
/// struct Payload(
///     #[codec(encode_size = value.len())]
///     Vec<u8>,
/// );
/// assert_eq!(Payload(vec![3, 7]).encode_size(), 2);
/// ```
///
/// A container override can refer to `self` and calculate the whole encoding:
///
/// ```
/// use commonware_codec::{Encode, EncodeSize, Write};
/// #[derive(Write, EncodeSize)]
/// #[encode_size(1 + self.payload.len())]
/// struct Raw {
///     tag: u8,
///     #[codec(encode_with = { buf.put_slice(value); })]
///     payload: Vec<u8>,
/// }
/// assert_eq!(Raw { tag: 7, payload: vec![8, 9] }.encode().as_ref(), &[7, 8, 9]);
/// ```
pub use commonware_codec_macros::EncodeSize;
/// Derives byte-array conversion impls for a fixed-size type.
///
/// Generates:
/// - `TryFrom<[u8; SIZE]>` and `TryFrom<&[u8; SIZE]>`, or `From<[u8; SIZE]>` and
///   `From<&[u8; SIZE]>` when `infallible` (decoding via `DecodeFixed`).
/// - `TryFrom<&[u8]>`
/// - `From<T> for [u8; SIZE]`
/// - `From<&T> for [u8; SIZE]`
///
/// The type must implement `Read<Cfg = ()>` and `EncodeFixed`.
///
/// # Attributes
///
/// - `#[fixed_array(infallible)]`: emit `From<[u8; SIZE]>` instead of `TryFrom<[u8; SIZE]>`.
///   The type's decode must never fail (any `[u8; SIZE]` is a valid value), since the generated
///   `From` unwraps the `DecodeFixed` result.
/// - `#[fixed_array(bytes([u8; N]))]`: required for any generic type (lifetime, type, or
///   const). Stable Rust forbids a generic parameter inside the const expression
///   `[u8; <T as FixedSize>::SIZE]`, so the byte array type must be named.
///
/// # Examples
///
/// ```
/// use commonware_codec::{FixedArray, FixedSize, Read, Write};
/// #[derive(Debug, PartialEq, FixedArray, FixedSize, Read, Write)]
/// struct Word(u32);
/// let bytes: [u8; 4] = Word(7).into();
/// assert_eq!(Word::try_from(bytes).unwrap(), Word(7));
/// ```
pub use commonware_codec_macros::FixedArray;
/// Derives `commonware_codec::FixedSize` by summing field `SIZE` constants.
///
/// Enum sizes include the one-byte tag. An associated-constant assertion
/// requires all variants to have the same total size when `SIZE` is evaluated.
/// Empty enums and unions are rejected. Custom `encode_with` and `encode_size`
/// attributes are rejected because field constants cannot describe their wire
/// representation.
/// `#[codec(fixed_size_bounds(T: Trait, ...))]` replaces inferred field bounds
/// for this implementation; see [`Write`] for the shared bound-override rules.
///
/// Combine this derive with [`Write`] and optionally [`Read`]. The codec's
/// blanket implementation already provides `EncodeSize`; deriving [`Encode`]
/// or [`EncodeSize`] as well produces conflicting implementations.
///
/// # Examples
///
/// ```
/// use commonware_codec::FixedSize;
/// #[derive(FixedSize)]
/// enum Word { Number(u16), Bytes([u8; 2]) }
/// assert_eq!(Word::SIZE, 3);
/// ```
///
/// Unequal variant lengths cannot satisfy the fixed-size contract:
///
/// ```compile_fail
/// use commonware_codec::FixedSize;
/// #[derive(FixedSize)]
/// enum Unequal { Byte(u8), Word(u16) }
/// const SIZE: usize = Unequal::SIZE;
/// ```
///
/// Bound overrides accept associated types as well as generic parameters:
///
/// ```
/// use commonware_codec::FixedSize;
/// trait Format { type Word; }
/// #[derive(FixedSize)]
/// #[codec(fixed_size_bounds(F::Word: FixedSize))]
/// struct Header<F: Format>(F::Word);
/// struct Short;
/// impl Format for Short { type Word = u16; }
/// assert_eq!(Header::<Short>::SIZE, 2);
/// ```
pub use commonware_codec_macros::FixedSize;
/// Derives `commonware_codec::Read` for a struct or nonempty enum.
///
/// Fields are read in declaration order. Enum tags follow [`Write`]; an unknown
/// tag returns `Error::InvalidEnum` by default. An enum can customize that error
/// with `#[codec(invalid_tag = function_or_closure)]`, called with the unknown
/// `u8` tag, or a block with `tag` in scope. The expression returns a codec
/// [`Error`](crate::Error). Errors reading the tag or variant fields propagate
/// unchanged.
///
/// `#[codec(read_cfg = Type)]` or `#[read_cfg(Type)]` sets the associated `Cfg`
/// type (default `()`). Each field receives `cfg` directly, unless it supplies
/// `#[codec(cfg = expression)]`. That expression must evaluate to a reference
/// to the field's configuration; for example, `#[codec(cfg = &cfg.0)]`.
/// Field expressions can refer to the method's `cfg` parameter.
/// Parenthesized attributes accept Rust types and expressions directly, including
/// tuple types, blocks, and function calls.
///
/// `#[codec(read_with = function_or_closure)]` reads a field by calling
/// `(buf, field_cfg)`. A block instead has `buf` and `cfg` in scope, where `cfg`
/// is the field's configuration after applying its `codec(cfg = ...)` expression.
/// Custom readers return `Result<FieldType, Error>` and use the codec's [`Buf`](crate::Buf).
/// The derive does not infer a `Read` bound for a custom-read field. Readers
/// consume only that field's bytes; errors propagate to the caller.
///
/// Structural decoding preserves errors from field readers. Types that validate
/// relationships between fields or use a layout spanning multiple fields should
/// implement `Read` manually; writing and sizing can still be derived.
///
/// Bounds are inferred from field types. For explicitly configured fields,
/// bounds apply to their generic arguments so the field's concrete `Cfg` remains
/// available. This inference does not resolve type aliases or discover domain
/// bounds such as `PublicKey`. A configured wrapper whose parameter does not
/// itself implement `Read`, or whose reader requires additional bounds, can use
/// `#[codec(read_bounds(T: Trait, ...))]` to replace inferred field bounds.
/// See [`Write`] for the shared bound-override rules.
///
/// ```compile_fail
/// use commonware_codec::Read;
/// #[derive(Read)]
/// #[codec(cfg = &())] // Field configuration belongs on a field.
/// struct Invalid(u8);
/// ```
///
/// # Examples
///
/// ```
/// use commonware_codec::Read;
/// #[derive(Debug, PartialEq, Read)]
/// enum Message { Empty, #[codec(tag = 9)] Value(u8) }
/// let mut bytes = commonware_codec::Copying(&[9u8, 42]);
/// assert_eq!(Message::read_cfg(&mut bytes, &()).unwrap(), Message::Value(42));
/// ```
///
/// A container configuration can be projected into each field's configuration:
///
/// ```
/// use commonware_codec::{Copying, Encode, RangeCfg, Read};
/// #[derive(Debug, PartialEq, Read)]
/// #[read_cfg(RangeCfg<usize>)]
/// struct Payload {
///     #[codec(cfg = &(*cfg, ()))]
///     bytes: Vec<u8>,
/// }
/// let encoded = vec![3u8, 7].encode();
/// let mut input = Copying(encoded.as_ref());
/// let decoded = Payload::read_cfg(&mut input, &(0..=8).into()).unwrap();
/// assert_eq!(decoded.bytes, [3, 7]);
/// ```
///
/// A custom reader can construct a field without a `Read` implementation. The
/// configuration expression is evaluated before the reader's `cfg` is bound:
///
/// ```
/// use commonware_codec::{Copying, Error, Read};
/// struct Count(u16);
/// #[derive(Read)]
/// #[read_cfg((u16,))]
/// struct Message {
///     #[codec(cfg = &cfg.0, read_with = {
///         let count = u16::read_cfg(buf, &())?;
///         if count > *cfg {
///             Err(Error::Invalid("Message", "count exceeds limit"))
///         } else {
///             Ok(Count(count))
///         }
///     })]
///     count: Count,
/// }
/// let mut input = Copying(&[0u8, 7]);
/// assert_eq!(Message::read_cfg(&mut input, &(10,)).unwrap().count.0, 7);
/// ```
///
/// An explicit empty bound list lets a configured wrapper supply its own bounds:
///
/// ```
/// use commonware_codec::{Buf, Copying, Error, Read};
/// use core::marker::PhantomData;
/// struct Marker<T>(PhantomData<T>);
/// impl<T> Read for Marker<T> {
///     type Cfg = u8;
///     fn read_cfg(_: &mut impl Buf, _: &u8) -> Result<Self, Error> {
///         Ok(Self(PhantomData))
///     }
/// }
/// #[derive(Read)]
/// #[read_cfg((u8,))]
/// #[codec(read_bounds())]
/// struct Message<T>(#[codec(cfg = &cfg.0)] Marker<T>);
/// struct Domain;
/// let mut input = Copying(&[] as &[u8]);
/// let _ = Message::<Domain>::read_cfg(&mut input, &(3,)).unwrap();
/// ```
///
/// Enum errors can identify their protocol:
///
/// ```
/// use commonware_codec::{Copying, Error, Read};
/// #[derive(Read)]
/// #[codec(invalid_tag = { Error::Invalid("Message", "unknown tag") })]
/// enum Message { Empty }
/// let mut input = Copying(&[9u8]);
/// assert!(matches!(Message::read_cfg(&mut input, &()),
///     Err(Error::Invalid("Message", "unknown tag"))));
/// ```
pub use commonware_codec_macros::Read;
/// Derives `commonware_codec::Write` without deriving size calculation.
///
/// Struct fields are written in declaration order. Enums start with a one-byte tag:
/// the variant's zero-based declaration index, or its `#[codec(tag = N)]` value.
/// Tags must be unique integers from 0 through 255, and enums must have 1 through
/// 256 variants. Rust discriminants do not determine codec tags.
///
/// A field may use `#[codec(encode_with = function_or_closure)]`, called with
/// `(&field, buf)`, or `#[codec(encode_with = { ... })]`, whose block has `value`
/// (a reference to the field) and `buf` in scope. Custom writers must write all
/// bytes inline. Ordinary fields delegate both `write` and `write_bufs`.
/// The derive cannot infer bounds required by arbitrary function bodies.
///
/// Container attributes `write_bounds(...)`, `read_bounds(...)`,
/// `encode_size_bounds(...)`, and `fixed_size_bounds(...)` inside `#[codec(...)]`
/// accept comma-separated Rust where predicates. Each replaces all inferred
/// field bounds for its corresponding implementation. An empty list suppresses
/// field-bound inference. Declared type bounds and the requirements on `Read::Cfg`
/// remain in effect. The generated body must still type-check under these bounds.
/// [`Encode`] uses the independent write and encode-size overrides. Overrides can
/// add implementation-only constraints without restricting the type itself.
///
/// When a handwritten `FixedSize` implementation wraps a field that can share
/// buffers, use `#[encode_size(Self::SIZE)]` to keep the entire write inline.
/// This matches the inline size supplied by the `FixedSize` blanket implementation.
///
/// The shared `codec`, `read_cfg`, and `encode_size` attributes are validated
/// even when they configure another derive. See [`Read`] and [`EncodeSize`].
///
/// For recursive fields, name the enclosing type with `Self` or its unqualified
/// name. Derives cannot resolve module paths to distinguish a recursive type
/// from another type with the same name. This applies to all codec derives.
///
/// # Examples
///
/// ```
/// use commonware_codec::{Encode, Read};
/// use std::sync::Arc;
/// #[derive(Encode, Read)]
/// struct Node {
///     value: u8,
///     next: Option<Arc<Self>>,
/// }
/// assert_eq!(Node { value: 7, next: None }.encode().as_ref(), &[7, 0]);
/// ```
///
/// ```
/// use commonware_codec::{FixedSize, Write};
/// #[derive(Write, FixedSize)]
/// struct Pair { first: u8, second: u8 }
/// let mut bytes = Vec::new();
/// Pair { first: 3, second: 7 }.write(&mut bytes);
/// assert_eq!(bytes, [3, 7]);
/// ```
///
/// A function can encode a field whose type does not implement `Write`:
///
/// ```
/// use commonware_codec::{Encode, Write};
///
/// fn write_text(text: &str, buf: &mut impl bytes::BufMut) {
///     text.as_bytes().write(buf);
/// }
///
/// #[derive(Write)]
/// struct Label(#[codec(encode_with = write_text)] String);
/// let mut bytes = Vec::new();
/// Label(String::from("hi")).write(&mut bytes);
/// assert_eq!(bytes, b"hi".as_slice().encode().as_ref());
/// ```
///
/// Custom encoding can require bounds only on the codec implementations:
///
/// ```
/// use commonware_codec::Encode;
/// #[derive(Encode)]
/// #[codec(write_bounds(T: AsRef<[u8]>), encode_size_bounds(T: AsRef<[u8]>))]
/// struct Raw<T>(#[codec(
///     encode_with = { buf.put_slice(value.as_ref()); },
///     encode_size = value.as_ref().len()
/// )] T);
/// assert_eq!(Raw([3u8, 7]).encode().as_ref(), &[3, 7]);
/// ```
///
/// Suppressing inference does not remove requirements of the generated writer:
///
/// ```compile_fail
/// use commonware_codec::Write;
/// #[derive(Write)]
/// #[codec(write_bounds())]
/// struct MissingBound<T>(T);
/// ```
pub use commonware_codec_macros::Write;
