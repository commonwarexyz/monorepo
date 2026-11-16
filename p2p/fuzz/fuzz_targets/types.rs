#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_codec::{
    Copying, DecodeExt as _, Encode, EncodeSize as _, Error, MaxEncodeSize, Read, ReadExt as _,
};
use commonware_p2p::{Address, Ingress};
use commonware_runtime::{Error as RuntimeError, Runner, deterministic};
use commonware_utils::{
    Entropy, FuzzRng, Hostname,
    hostname::{MAX_HOSTNAME_LABEL_LEN, MAX_HOSTNAME_LEN},
};
use libfuzzer_sys::fuzz_target;
use rand::{Rng as _, RngExt as _};
use std::{
    cmp::Ordering,
    collections::BTreeMap,
    fmt::Debug,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

/// Most operations a plan applies. Every value is compared with each one checked before it, and a
/// few dozen registrations and lookups already move every hostname through each record state.
const MAX_OPS: usize = 32;

/// Most hostnames a plan registers and dials. Lookups draw from this pool so they often find a
/// record, and four names already hold records in different states at once.
const MAX_HOSTS: usize = 4;

/// Most addresses a DNS record holds. Resolution keeps their order and filtering judges each one
/// alone, which a few addresses already show.
const MAX_IPS: usize = 4;

/// Most bytes appended after an encoding. Decoding counts them without reading them, so a few
/// show the count.
const MAX_TRAILING: usize = 8;

/// Most raw bytes decoded as both types, more than the widest symmetric address and the head of
/// any other value. Corrupted encodings reach the deeper fields.
const MAX_RAW: usize = 32;

/// Bytes of the stream a plan is sampled from, more than the largest plan draws, of the input's
/// head that seeds the stream, and of the stream's tail that seeds the runtime.
const STREAM_BYTES: usize = 1 << 13;
const SEED_BYTES: usize = 8;
const ENTROPY_BYTES: usize = 32;

/// Special-purpose IPv4 ranges of the IANA registry as `(prefix, length, global)`. The most
/// specific range holding an address decides whether it is global, and an address in none is.
const V4_RANGES: [(u128, u8, bool); 16] = [
    // This network.
    (0x0000_0000, 8, false),
    // Private use.
    (0x0a00_0000, 8, false),
    // Shared address space.
    (0x6440_0000, 10, false),
    // Loopback.
    (0x7f00_0000, 8, false),
    // Link local.
    (0xa9fe_0000, 16, false),
    // Private use.
    (0xac10_0000, 12, false),
    // IETF protocol assignments, except two globally reachable anycast addresses.
    (0xc000_0000, 24, false),
    (0xc000_0009, 32, true),
    (0xc000_000a, 32, true),
    // Documentation (TEST-NET-1).
    (0xc000_0200, 24, false),
    // 6a44-relay anycast.
    (0xc058_6302, 32, false),
    // Private use.
    (0xc0a8_0000, 16, false),
    // Benchmarking.
    (0xc612_0000, 15, false),
    // Documentation (TEST-NET-2 and TEST-NET-3).
    (0xc633_6400, 24, false),
    (0xcb00_7100, 24, false),
    // Reserved, including the limited broadcast address.
    (0xf000_0000, 4, false),
];

/// Special-purpose IPv6 ranges of the IANA registry, as in [`V4_RANGES`].
const V6_RANGES: [(u128, u8, bool); 20] = [
    // Unspecified and loopback.
    (0, 128, false),
    (1, 128, false),
    // IPv4-mapped.
    (0xffff_0000_0000, 96, false),
    // IPv4-IPv6 translation.
    (0x0064_ff9b_0001_u128 << 80, 48, false),
    // Discard-only and dummy prefixes.
    (0x0100_u128 << 112, 64, false),
    (0x0100_0000_0000_0001_u128 << 64, 64, false),
    // IETF protocol assignments, except the globally reachable anycast addresses and blocks.
    (0x2001_u128 << 112, 23, false),
    ((0x2001_0001_u128 << 96) | 1, 128, true),
    ((0x2001_0001_u128 << 96) | 2, 128, true),
    ((0x2001_0001_u128 << 96) | 3, 128, true),
    (0x2001_0003_u128 << 96, 32, true),
    (0x2001_0004_0112_u128 << 80, 48, true),
    (0x2001_0020_u128 << 96, 28, true),
    (0x2001_0030_u128 << 96, 28, true),
    // Documentation.
    (0x2001_0db8_u128 << 96, 32, false),
    (0x3fff_u128 << 112, 20, false),
    // 6to4.
    (0x2002_u128 << 112, 16, false),
    // Segment routing SIDs.
    (0x5f00_u128 << 112, 16, false),
    // Unique local.
    (0xfc00_u128 << 112, 7, false),
    // Link-local unicast.
    (0xfe80_u128 << 112, 10, false),
];

/// Characters that may start and end a hostname label, and those that may sit inside one.
const LABEL_EDGE: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const LABEL_INSIDE: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-";

/// Uniform addresses are almost all global, so many are drawn at or next to the edges of a
/// special-purpose range instead.
#[derive(Arbitrary, Clone, Copy, Debug)]
enum Ip {
    V4(u32),
    V6(u128),
    /// An address of range `range`, counting the IPv4 ranges and then the IPv6 ones, at `edge`.
    Range {
        range: u8,
        edge: Edge,
    },
}

#[derive(Arbitrary, Clone, Copy, Debug)]
enum Edge {
    First,
    Last,
    /// The address just below the range.
    Below,
    /// The address just above the range.
    Above,
    /// Any address of the range.
    Inside(u128),
}

#[derive(Arbitrary, Debug)]
struct Socket {
    ip: Ip,
    port: u16,
    /// IPv6 flow information and scope identifier, which the codec drops.
    extra: Option<(u32, u32)>,
}

#[derive(Arbitrary, Debug)]
enum IngressOperand {
    Socket(Socket),
    /// A hostname of the plan's pool.
    Dns {
        host: u8,
        port: u16,
    },
    /// Through the ingress's own `Arbitrary` impl.
    Sampled(Ingress),
}

#[derive(Arbitrary, Debug)]
enum AddressOperand {
    Symmetric(Socket),
    Asymmetric {
        ingress: IngressOperand,
        egress: Socket,
    },
    /// Through the address's own `Arbitrary` impl.
    Sampled(Address),
}

#[derive(Arbitrary, Debug)]
enum Value {
    Ingress(IngressOperand),
    Address(AddressOperand),
}

/// How an encoding is corrupted before it is decoded.
#[derive(Arbitrary, Debug)]
enum Mutation {
    /// Keeps `len` bytes, reduced below the encoded length.
    Truncate(u16),
    /// Appends bytes after the encoding.
    Append(#[arbitrary(with = trailing)] Vec<u8>),
    /// Replaces the leading prefix with one no variant uses.
    Prefix(u8),
    /// Replaces the second byte, the prefix of an asymmetric address's ingress, with one no
    /// variant uses.
    NestedPrefix(u8),
    /// Overwrites the byte at `index`, reduced to the encoded length.
    Byte { index: u16, value: u8 },
}

/// What a hostname's DNS record becomes.
#[derive(Arbitrary, Debug)]
enum Record {
    Remove,
    /// A record without addresses, which resolution refuses.
    Empty,
    Ips(#[arbitrary(with = ips)] Vec<Ip>),
}

#[derive(Arbitrary, Debug)]
enum Op {
    Ingress(IngressOperand),
    Address(AddressOperand),
    Corrupt { value: Value, mutation: Mutation },
    Raw(#[arbitrary(with = raw)] Vec<u8>),
    Register { host: u8, record: Record },
    Resolve(IngressOperand),
}

fn trailing(u: &mut Unstructured<'_>) -> arbitrary::Result<Vec<u8>> {
    (0..u.int_in_range(1..=MAX_TRAILING)?)
        .map(|_| u.arbitrary())
        .collect()
}

fn ips(u: &mut Unstructured<'_>) -> arbitrary::Result<Vec<Ip>> {
    (0..u.int_in_range(1..=MAX_IPS)?)
        .map(|_| u.arbitrary())
        .collect()
}

fn raw(u: &mut Unstructured<'_>) -> arbitrary::Result<Vec<u8>> {
    (0..u.int_in_range(0..=MAX_RAW)?)
        .map(|_| u.arbitrary())
        .collect()
}

/// Draws a hostname through its own `Arbitrary` impl, whose labels are short, or at a length
/// bound: the widest hostname, a single label of one to 63 characters, or labels of any length.
fn hostname(u: &mut Unstructured<'_>) -> arbitrary::Result<Hostname> {
    let lens = match u.choose_index(4)? {
        0 => return u.arbitrary(),
        // Full labels and a last one that reaches the length bound exactly.
        1 => {
            let mut lens = vec![MAX_HOSTNAME_LABEL_LEN; 3];
            lens.push(MAX_HOSTNAME_LEN - 3 * (MAX_HOSTNAME_LABEL_LEN + 1));
            lens
        }
        2 => {
            let len = u.int_in_range(1..=MAX_HOSTNAME_LABEL_LEN)?;
            vec![*u.choose(&[1, len, MAX_HOSTNAME_LABEL_LEN])?]
        }
        _ => {
            let (mut lens, mut width) = (Vec::new(), 0);
            loop {
                let len = u.int_in_range(1..=MAX_HOSTNAME_LABEL_LEN)?;
                let next = width + usize::from(width > 0) + len;
                if next > MAX_HOSTNAME_LEN {
                    break;
                }
                lens.push(len);
                width = next;
                if u.ratio(1, 4)? {
                    break;
                }
            }
            lens
        }
    };
    let mut host = String::with_capacity(MAX_HOSTNAME_LEN);
    for (i, len) in lens.into_iter().enumerate() {
        if i > 0 {
            host.push('.');
        }
        for j in 0..len {
            let chars = if j == 0 || j == len - 1 {
                LABEL_EDGE
            } else {
                LABEL_INSIDE
            };
            host.push(char::from(*u.choose(chars)?));
        }
    }
    Ok(Hostname::new(host).expect("labels within the bounds must form a hostname"))
}

#[derive(Debug)]
struct Plan {
    hosts: Vec<Hostname>,
    ops: Vec<Op>,
    entropy: Entropy,
}

impl<'a> Arbitrary<'a> for Plan {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // libFuzzer starts from inputs of a few bytes and lengthens them slowly, and a plan
        // sampled from so few bytes would hold one IPv4 socket ingress of zeros. The input's head
        // therefore seeds a fixed-size stream of [`FuzzRng`] output that the rest of the input
        // overwrites from its start, so every input, even an empty one, samples a whole plan, and
        // a byte mutated past the head changes only what is sampled from it.
        let seed = u.bytes(u.len().min(SEED_BYTES))?.to_vec();
        let mut stream = vec![0; STREAM_BYTES.max(u.len())];
        FuzzRng::new(seed).fill_bytes(&mut stream);
        let literal = u.bytes(u.len())?;
        stream[..literal.len()].copy_from_slice(literal);
        let (plan, entropy) = stream.split_at(stream.len() - ENTROPY_BYTES);
        let u = &mut Unstructured::new(plan);

        Ok(Self {
            hosts: (0..u.int_in_range(1..=MAX_HOSTS)?)
                .map(|_| hostname(u))
                .collect::<arbitrary::Result<_>>()?,
            ops: (0..u.int_in_range(1..=MAX_OPS)?)
                .map(|_| u.arbitrary())
                .collect::<arbitrary::Result<_>>()?,
            entropy: Unstructured::new(entropy).arbitrary()?,
        })
    }
}

impl Ip {
    fn addr(self) -> IpAddr {
        match self {
            Self::V4(bits) => IpAddr::V4(bits.into()),
            Self::V6(bits) => IpAddr::V6(bits.into()),
            Self::Range { range, edge } => {
                let range = usize::from(range) % (V4_RANGES.len() + V6_RANGES.len());
                let ((prefix, len, _), width) = match V4_RANGES.get(range) {
                    Some(&range) => (range, 32),
                    None => (V6_RANGES[range - V4_RANGES.len()], 128),
                };
                let all = u128::MAX >> (128 - width);
                let host = all.checked_shr(len.into()).unwrap_or(0);
                let bits = match edge {
                    Edge::First => prefix,
                    Edge::Last => prefix | host,
                    Edge::Below => prefix.wrapping_sub(1) & all,
                    Edge::Above => (prefix | host).wrapping_add(1) & all,
                    Edge::Inside(offset) => prefix | (offset & host),
                };
                match width {
                    32 => IpAddr::V4(Ipv4Addr::from(bits as u32)),
                    _ => IpAddr::V6(Ipv6Addr::from(bits)),
                }
            }
        }
    }
}

impl Socket {
    fn build(self) -> SocketAddr {
        let (flowinfo, scope_id) = self.extra.unwrap_or_default();
        match self.ip.addr() {
            IpAddr::V4(ip) => SocketAddr::V4(SocketAddrV4::new(ip, self.port)),
            IpAddr::V6(ip) => SocketAddr::V6(SocketAddrV6::new(ip, self.port, flowinfo, scope_id)),
        }
    }
}

impl IngressOperand {
    fn build(self, hosts: &[Hostname]) -> Ingress {
        match self {
            Self::Socket(socket) => Ingress::Socket(socket.build()),
            Self::Dns { host, port } => Ingress::Dns {
                host: pool(hosts, host).clone(),
                port,
            },
            Self::Sampled(ingress) => ingress,
        }
    }
}

impl AddressOperand {
    fn build(self, hosts: &[Hostname]) -> Address {
        match self {
            Self::Symmetric(socket) => Address::Symmetric(socket.build()),
            Self::Asymmetric { ingress, egress } => Address::Asymmetric {
                ingress: ingress.build(hosts),
                egress: egress.build(),
            },
            Self::Sampled(address) => address,
        }
    }
}

fn pool(hosts: &[Hostname], index: u8) -> &Hostname {
    &hosts[usize::from(index) % hosts.len()]
}

/// Returns whether `ip` is global: the most specific special-purpose range holding it decides, and
/// an address in none of them is.
fn global(ip: IpAddr) -> bool {
    let (bits, width, ranges) = match ip {
        IpAddr::V4(ip) => (u32::from(ip).into(), 32, &V4_RANGES[..]),
        IpAddr::V6(ip) => (u128::from(ip), 128, &V6_RANGES[..]),
    };
    ranges
        .iter()
        .copied()
        .filter(|&(prefix, len, _)| bits >> (width - len) == prefix >> (width - len))
        .max_by_key(|&(_, len, _)| len)
        .is_none_or(|(_, _, global)| global)
}

/// Returns whether `host` follows RFC 1035 and RFC 1123: at most 253 characters in labels of one
/// to 63 letters, digits and hyphens, none starting or ending with a hyphen.
fn valid_hostname(host: &str) -> bool {
    host.len() <= MAX_HOSTNAME_LEN
        && host.split('.').all(|label| {
            let label = label.as_bytes();
            (1..=MAX_HOSTNAME_LABEL_LEN).contains(&label.len())
                && label
                    .iter()
                    .all(|c| c.is_ascii_alphanumeric() || *c == b'-')
                && label.first() != Some(&b'-')
                && label.last() != Some(&b'-')
        })
}

/// Why a decode fails.
#[derive(Debug, PartialEq, Eq)]
enum Refusal {
    End,
    Extra(usize),
    Prefix(u8),
    Family,
    Varint,
    Length(usize),
    Utf8,
    Hostname,
}

impl Refusal {
    fn of(error: Error) -> Self {
        match error {
            Error::EndOfBuffer => Self::End,
            Error::ExtraData(extra) => Self::Extra(extra),
            Error::InvalidEnum(prefix) => Self::Prefix(prefix),
            Error::Invalid("IpAddr", "Invalid version") => Self::Family,
            Error::InvalidVarint(4) => Self::Varint,
            Error::InvalidLength(len) => Self::Length(len),
            Error::Invalid("Hostname", "invalid UTF-8") => Self::Utf8,
            Error::Invalid("Hostname", "invalid hostname") => Self::Hostname,
            error => panic!("unexpected decode error: {error:?}"),
        }
    }
}

/// A cursor the model decoder reads from.
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], Refusal> {
        let taken = self.bytes[self.pos..].get(..len).ok_or(Refusal::End)?;
        self.pos += len;
        Ok(taken)
    }

    fn byte(&mut self) -> Result<u8, Refusal> {
        Ok(self.take(1)?[0])
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Refusal> {
        Ok(self.take(N)?.try_into().expect("took N bytes"))
    }

    /// Reads a length: groups of seven bits, least significant first, each flagged in its high bit
    /// when another follows. Only the shortest form of a value within `u32` is accepted.
    fn length(&mut self) -> Result<usize, Refusal> {
        let mut value = 0u64;
        for group in 0..5 {
            let byte = self.byte()?;
            if (group > 0 && byte == 0) || (group == 4 && byte >= 0x10) {
                return Err(Refusal::Varint);
            }
            value |= u64::from(byte & 0x7f) << (7 * group);
            if byte & 0x80 == 0 {
                return Ok(value as usize);
            }
        }
        unreachable!("the fifth group carries no continuation flag");
    }

    fn hostname(&mut self) -> Result<String, Refusal> {
        let len = self.length()?;
        if len > MAX_HOSTNAME_LEN {
            return Err(Refusal::Length(len));
        }
        let host = std::str::from_utf8(self.take(len)?).map_err(|_| Refusal::Utf8)?;
        if !valid_hostname(host) {
            return Err(Refusal::Hostname);
        }
        Ok(host.to_owned())
    }
}

/// The model of a type of `types.rs`: its fields as plain values.
trait Model: Clone + Debug + Eq {
    type Value: Encode + Read<Cfg = ()> + MaxEncodeSize + Ord + Debug;

    /// Whether a leading prefix of one selects a nested ingress.
    const NESTED: bool;

    fn of(value: &Self::Value) -> Self;

    /// Returns the model without the IPv6 flow information and scope identifiers the codec drops.
    fn canonical(&self) -> Self;

    fn write(&self, out: &mut Vec<u8>);

    fn read(reader: &mut Reader<'_>) -> Result<Self, Refusal>;

    /// Orders models as the derived order of their values should.
    fn order(&self, other: &Self) -> Ordering;

    fn encoding(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write(&mut out);
        out
    }
}

/// `SocketAddr` orders by family, then address, port, flow information and scope identifier.
type SocketKey = (bool, u128, u16, u32, u32);
type IngressKey<'a> = (u8, SocketKey, &'a [u8], u16);
type AddressKey<'a> = (u8, SocketKey, IngressKey<'a>, SocketKey);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SocketModel {
    v6: bool,
    bits: u128,
    port: u16,
    flowinfo: u32,
    scope_id: u32,
}

impl SocketModel {
    fn of(addr: &SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(addr) => Self::at(IpAddr::V4(*addr.ip()), addr.port()),
            SocketAddr::V6(addr) => Self {
                flowinfo: addr.flowinfo(),
                scope_id: addr.scope_id(),
                ..Self::at(IpAddr::V6(*addr.ip()), addr.port())
            },
        }
    }

    fn at(ip: IpAddr, port: u16) -> Self {
        let (v6, bits) = match ip {
            IpAddr::V4(ip) => (false, u32::from(ip).into()),
            IpAddr::V6(ip) => (true, u128::from(ip)),
        };
        Self {
            v6,
            bits,
            port,
            flowinfo: 0,
            scope_id: 0,
        }
    }

    fn ip(self) -> IpAddr {
        if self.v6 {
            IpAddr::V6(self.bits.into())
        } else {
            IpAddr::V4((self.bits as u32).into())
        }
    }

    const fn canonical(self) -> Self {
        Self {
            flowinfo: 0,
            scope_id: 0,
            ..self
        }
    }

    /// Writes the family's tag, then the address and the port, big-endian.
    fn write(self, out: &mut Vec<u8>) {
        if self.v6 {
            out.push(6);
            out.extend_from_slice(&self.bits.to_be_bytes());
        } else {
            out.push(4);
            out.extend_from_slice(&(self.bits as u32).to_be_bytes());
        }
        out.extend_from_slice(&self.port.to_be_bytes());
    }

    fn read(reader: &mut Reader<'_>) -> Result<Self, Refusal> {
        let (v6, bits) = match reader.byte()? {
            4 => (false, u32::from_be_bytes(reader.array()?).into()),
            6 => (true, u128::from_be_bytes(reader.array()?)),
            _ => return Err(Refusal::Family),
        };
        let port = u16::from_be_bytes(reader.array()?);
        Ok(Self {
            v6,
            bits,
            port,
            flowinfo: 0,
            scope_id: 0,
        })
    }

    const fn key(self) -> SocketKey {
        (self.v6, self.bits, self.port, self.flowinfo, self.scope_id)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum IngressModel {
    Socket(SocketModel),
    Dns { host: String, port: u16 },
}

impl IngressModel {
    const fn port(&self) -> u16 {
        match self {
            Self::Socket(socket) => socket.port,
            Self::Dns { port, .. } => *port,
        }
    }

    fn ip(&self) -> Option<IpAddr> {
        match self {
            Self::Socket(socket) => Some(socket.ip()),
            Self::Dns { .. } => None,
        }
    }

    /// A socket must be global unless private addresses are allowed, and a hostname is checked
    /// only after resolution, so it needs DNS allowed.
    fn valid(&self, allow_private_ips: bool, allow_dns: bool) -> bool {
        match self {
            Self::Socket(socket) => allow_private_ips || global(socket.ip()),
            Self::Dns { .. } => allow_dns,
        }
    }

    /// Variants order by declaration, then by their fields in declaration order.
    fn key(&self) -> IngressKey<'_> {
        match self {
            Self::Socket(socket) => (0, socket.key(), &[], 0),
            Self::Dns { host, port } => (1, Default::default(), host.as_bytes(), *port),
        }
    }
}

impl Model for IngressModel {
    type Value = Ingress;

    const NESTED: bool = false;

    fn of(ingress: &Ingress) -> Self {
        match ingress {
            Ingress::Socket(addr) => Self::Socket(SocketModel::of(addr)),
            Ingress::Dns { host, port } => Self::Dns {
                host: host.as_str().to_owned(),
                port: *port,
            },
        }
    }

    fn canonical(&self) -> Self {
        match self {
            Self::Socket(socket) => Self::Socket(socket.canonical()),
            Self::Dns { .. } => self.clone(),
        }
    }

    /// Writes a prefix of zero and the socket address, or a prefix of one, the hostname's length
    /// as a varint and its characters, and the port.
    fn write(&self, out: &mut Vec<u8>) {
        match self {
            Self::Socket(socket) => {
                out.push(0);
                socket.write(out);
            }
            Self::Dns { host, port } => {
                out.push(1);
                let mut len = host.len();
                while len >= 0x80 {
                    out.push(0x80 | (len & 0x7f) as u8);
                    len >>= 7;
                }
                out.push(len as u8);
                out.extend_from_slice(host.as_bytes());
                out.extend_from_slice(&port.to_be_bytes());
            }
        }
    }

    fn read(reader: &mut Reader<'_>) -> Result<Self, Refusal> {
        match reader.byte()? {
            0 => Ok(Self::Socket(SocketModel::read(reader)?)),
            1 => {
                let host = reader.hostname()?;
                let port = u16::from_be_bytes(reader.array()?);
                Ok(Self::Dns { host, port })
            }
            prefix => Err(Refusal::Prefix(prefix)),
        }
    }

    fn order(&self, other: &Self) -> Ordering {
        self.key().cmp(&other.key())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum AddressModel {
    Symmetric(SocketModel),
    Asymmetric {
        ingress: IngressModel,
        egress: SocketModel,
    },
}

impl AddressModel {
    fn ingress(&self) -> IngressModel {
        match self {
            Self::Symmetric(socket) => IngressModel::Socket(*socket),
            Self::Asymmetric { ingress, .. } => ingress.clone(),
        }
    }

    const fn egress(&self) -> SocketModel {
        match self {
            Self::Symmetric(socket) => *socket,
            Self::Asymmetric { egress, .. } => *egress,
        }
    }

    /// Variants order by declaration, then by their fields in declaration order.
    fn key(&self) -> AddressKey<'_> {
        match self {
            Self::Symmetric(socket) => (0, socket.key(), Default::default(), Default::default()),
            Self::Asymmetric { ingress, egress } => {
                (1, Default::default(), ingress.key(), egress.key())
            }
        }
    }
}

impl Model for AddressModel {
    type Value = Address;

    const NESTED: bool = true;

    fn of(address: &Address) -> Self {
        match address {
            Address::Symmetric(addr) => Self::Symmetric(SocketModel::of(addr)),
            Address::Asymmetric { ingress, egress } => Self::Asymmetric {
                ingress: IngressModel::of(ingress),
                egress: SocketModel::of(egress),
            },
        }
    }

    fn canonical(&self) -> Self {
        match self {
            Self::Symmetric(socket) => Self::Symmetric(socket.canonical()),
            Self::Asymmetric { ingress, egress } => Self::Asymmetric {
                ingress: ingress.canonical(),
                egress: egress.canonical(),
            },
        }
    }

    /// Writes a prefix of zero and the socket address, or a prefix of one, the ingress and the
    /// egress socket address.
    fn write(&self, out: &mut Vec<u8>) {
        match self {
            Self::Symmetric(socket) => {
                out.push(0);
                socket.write(out);
            }
            Self::Asymmetric { ingress, egress } => {
                out.push(1);
                ingress.write(out);
                egress.write(out);
            }
        }
    }

    fn read(reader: &mut Reader<'_>) -> Result<Self, Refusal> {
        match reader.byte()? {
            0 => Ok(Self::Symmetric(SocketModel::read(reader)?)),
            1 => {
                let ingress = IngressModel::read(reader)?;
                let egress = SocketModel::read(reader)?;
                Ok(Self::Asymmetric { ingress, egress })
            }
            prefix => Err(Refusal::Prefix(prefix)),
        }
    }

    fn order(&self, other: &Self) -> Ordering {
        self.key().cmp(&other.key())
    }
}

/// Values checked so far, with their models and encodings.
type Seen<M> = Vec<(<M as Model>::Value, M, Vec<u8>)>;

/// Decodes `bytes` and checks both `read` and `decode` against the model decoder. Returns what
/// `decode` yields.
fn check_decode<M: Model>(bytes: &[u8]) -> Result<M, Refusal> {
    let mut reader = Reader { bytes, pos: 0 };
    let expected = M::read(&mut reader).map(|model| (model, reader.pos));

    // Reading stops exactly where the model does, and what it reads re-encodes to the bytes it
    // consumed.
    let mut buf = Copying(bytes);
    match (M::Value::read(&mut buf), &expected) {
        (Ok(value), Ok((model, end))) => {
            assert_eq!(M::of(&value), *model);
            assert_eq!(bytes.len() - buf.0.len(), *end);
            assert_eq!(value.encode().as_ref(), &bytes[..*end]);
        }
        (Err(error), Err(refusal)) => assert_eq!(Refusal::of(error), *refusal),
        (read, expected) => panic!("{bytes:?} read as {read:?}, expected {expected:?}"),
    }

    // Decoding also refuses any bytes after the value.
    let expected = expected.and_then(|(model, end)| match bytes.len() - end {
        0 => Ok(model),
        extra => Err(Refusal::Extra(extra)),
    });
    let decoded = M::Value::decode(Copying(bytes))
        .map(|value| M::of(&value))
        .map_err(Refusal::of);
    assert_eq!(decoded, expected);
    decoded
}

/// Checks the encoding of `value` against the model and returns it.
fn check_codec<M: Model>(
    value: &M::Value,
    model: &M,
    context: &mut deterministic::Context,
) -> Vec<u8> {
    let encoded = value.encode().to_vec();
    assert_eq!(encoded, model.encoding());
    assert_eq!(value.encode_size(), encoded.len());
    assert!(encoded.len() <= M::Value::MAX_ENCODE_SIZE);

    // Decoding drops IPv6 flow information and scope identifiers, and otherwise returns the value.
    let decoded = M::Value::decode(Copying(&encoded)).expect("an encoding must decode");
    assert_eq!(M::of(&decoded), model.canonical());
    if model.canonical() == *model {
        assert_eq!(decoded, *value);
    }
    assert_eq!(check_decode::<M>(&encoded), Ok(model.canonical()));

    // Every strict prefix ends early, and decoding refuses bytes after the encoding.
    let cut = context.random_range(0..encoded.len());
    assert!(matches!(
        M::Value::decode(Copying(&encoded[..cut])),
        Err(Error::EndOfBuffer)
    ));
    let mut longer = encoded.clone();
    longer.resize(encoded.len() + context.random_range(1..=MAX_TRAILING), 0);
    context.fill_bytes(&mut longer[encoded.len()..]);
    assert_eq!(
        check_decode::<M>(&longer),
        Err(Refusal::Extra(longer.len() - encoded.len()))
    );
    encoded
}

/// Checks `value` against every value checked before: the derived order and equality follow the
/// model, and values share an encoding exactly when they agree on everything the codec keeps.
fn check_order<M: Model>(seen: &mut Seen<M>, value: M::Value, model: M, encoded: Vec<u8>) {
    for (other, other_model, other_encoded) in seen.iter() {
        let order = model.order(other_model);
        assert_eq!(value.cmp(other), order);
        assert_eq!(value.partial_cmp(other), Some(order));
        assert_eq!(value == *other, model == *other_model);
        assert_eq!(
            encoded == *other_encoded,
            model.canonical() == other_model.canonical()
        );
    }
    seen.push((value, model, encoded));
}

/// Checks both `From<SocketAddr>` impls: an ingress dials the address, and an address dials and
/// filters by it.
fn check_from(addr: SocketAddr) {
    let socket = SocketModel::of(&addr);
    assert_eq!(
        IngressModel::of(&Ingress::from(addr)),
        IngressModel::Socket(socket)
    );
    assert_eq!(
        AddressModel::of(&Address::from(addr)),
        AddressModel::Symmetric(socket)
    );
}

fn check_ingress(
    ingress: Ingress,
    seen: &mut Seen<IngressModel>,
    context: &mut deterministic::Context,
) {
    let model = IngressModel::of(&ingress);
    assert_eq!(ingress.port(), model.port());
    assert_eq!(ingress.ip(), model.ip());
    for allow_private_ips in [false, true] {
        for allow_dns in [false, true] {
            assert_eq!(
                ingress.is_valid(allow_private_ips, allow_dns),
                model.valid(allow_private_ips, allow_dns)
            );
        }
    }
    if let Ingress::Socket(addr) = &ingress {
        check_from(*addr);
    }
    let encoded = check_codec(&ingress, &model, context);
    check_order(seen, ingress, model, encoded);
}

fn check_address(
    address: Address,
    ingresses: &mut Seen<IngressModel>,
    addresses: &mut Seen<AddressModel>,
    context: &mut deterministic::Context,
) {
    let model = AddressModel::of(&address);
    let ingress = address.ingress();
    assert_eq!(IngressModel::of(&ingress), model.ingress());
    assert_eq!(SocketModel::of(&address.egress()), model.egress());
    assert_eq!(address.egress_ip(), model.egress().ip());
    check_from(address.egress());
    check_ingress(ingress, ingresses, context);
    let encoded = check_codec(&address, &model, context);
    check_order(addresses, address, model, encoded);
}

/// Corrupts the encoding of `value` and checks its decoding against the model decoder.
fn corrupt<M: Model>(value: &M::Value, mutation: Mutation) {
    // Maps a byte to a prefix no variant uses.
    let unknown = |byte: u8| 2 + byte % 254;

    let mut bytes = value.encode().to_vec();
    match mutation {
        Mutation::Truncate(len) => {
            bytes.truncate(usize::from(len) % bytes.len());
            assert_eq!(check_decode::<M>(&bytes), Err(Refusal::End));
        }
        Mutation::Append(trailing) => {
            bytes.extend_from_slice(&trailing);
            assert_eq!(
                check_decode::<M>(&bytes),
                Err(Refusal::Extra(trailing.len()))
            );
        }
        Mutation::Prefix(prefix) => {
            let prefix = unknown(prefix);
            bytes[0] = prefix;
            assert_eq!(check_decode::<M>(&bytes), Err(Refusal::Prefix(prefix)));
        }
        Mutation::NestedPrefix(prefix) => {
            // Elsewhere the second byte starts an IP address or a hostname's length, which the
            // model decoder judges.
            let prefix = unknown(prefix);
            bytes[1] = prefix;
            let decoded = check_decode::<M>(&bytes);
            if M::NESTED && bytes[0] == 1 {
                assert_eq!(decoded, Err(Refusal::Prefix(prefix)));
            }
        }
        Mutation::Byte { index, value } => {
            let index = usize::from(index) % bytes.len();
            bytes[index] = value;
            let _ = check_decode::<M>(&bytes);
        }
    }
}

/// Checks the resolution of `ingress` against the records registered so far.
async fn check_resolve(
    context: &deterministic::Context,
    records: &BTreeMap<String, Vec<IpAddr>>,
    ingress: &Ingress,
) {
    // A socket resolves to itself, and a hostname to every address of its record, in order, at
    // its port. A hostname without a record or with an empty one fails.
    let model = IngressModel::of(ingress);
    let expected: Option<Vec<SocketModel>> = match &model {
        IngressModel::Socket(socket) => Some(vec![*socket]),
        IngressModel::Dns { host, port } => records
            .get(host)
            .filter(|ips| !ips.is_empty())
            .map(|ips| ips.iter().map(|ip| SocketModel::at(*ip, *port)).collect()),
    };
    let resolved = ingress
        .resolve(context)
        .await
        .map(|addrs| addrs.map(|addr| SocketModel::of(&addr)).collect::<Vec<_>>());
    match (resolved, &expected) {
        (Ok(resolved), Some(expected)) => assert_eq!(resolved, *expected),
        (Err(RuntimeError::ResolveFailed(failed)), None) => {
            let IngressModel::Dns { host, .. } = &model else {
                panic!("socket ingress {ingress:?} failed to resolve");
            };
            assert_eq!(failed, *host);
        }
        (resolved, expected) => {
            panic!("{ingress:?} resolved to {resolved:?}, expected {expected:?}")
        }
    }

    // Filtering keeps exactly the global addresses unless private ones are allowed.
    for allow_private_ips in [false, true] {
        let filtered = ingress
            .resolve_filtered(context, allow_private_ips)
            .await
            .map(|addrs| addrs.map(|addr| SocketModel::of(&addr)).collect::<Vec<_>>());
        let kept = expected.as_ref().map(|addrs| {
            addrs
                .iter()
                .copied()
                .filter(|addr| allow_private_ips || global(addr.ip()))
                .collect()
        });
        assert_eq!(filtered, kept);
    }
}

fn run(plan: Plan) {
    let Plan {
        hosts,
        ops,
        entropy,
    } = plan;
    let cfg = deterministic::Config::new().with_rng(FuzzRng::from(entropy));
    let runner = deterministic::Runner::new(cfg);
    runner.start(|mut context| async move {
        // The bounds count a hostname's length at the widest varint of a `u32`, five bytes, and an
        // address's egress as an IPv6 socket address.
        assert_eq!(Ingress::MAX_ENCODE_SIZE, 1 + 5 + MAX_HOSTNAME_LEN + 2);
        assert_eq!(
            Address::MAX_ENCODE_SIZE,
            1 + Ingress::MAX_ENCODE_SIZE + 1 + 16 + 2
        );

        // Oracle: the record the runtime's resolver holds for each hostname.
        let mut records = BTreeMap::new();
        let mut ingresses = Seen::<IngressModel>::new();
        let mut addresses = Seen::<AddressModel>::new();

        for op in ops {
            match op {
                Op::Ingress(ingress) => {
                    check_ingress(ingress.build(&hosts), &mut ingresses, &mut context);
                }
                Op::Address(address) => {
                    let address = address.build(&hosts);
                    check_address(address, &mut ingresses, &mut addresses, &mut context);
                }
                Op::Corrupt { value, mutation } => match value {
                    Value::Ingress(ingress) => {
                        corrupt::<IngressModel>(&ingress.build(&hosts), mutation);
                    }
                    Value::Address(address) => {
                        corrupt::<AddressModel>(&address.build(&hosts), mutation);
                    }
                },
                Op::Raw(bytes) => {
                    let _ = check_decode::<IngressModel>(&bytes);
                    let _ = check_decode::<AddressModel>(&bytes);
                }
                Op::Register { host, record } => {
                    let host = pool(&hosts, host).as_str();
                    let ips = match record {
                        Record::Remove => None,
                        Record::Empty => Some(Vec::new()),
                        Record::Ips(ips) => Some(ips.into_iter().map(Ip::addr).collect()),
                    };
                    match &ips {
                        Some(ips) => {
                            records.insert(host.to_owned(), ips.clone());
                        }
                        None => {
                            records.remove(host);
                        }
                    }
                    context.resolver_register(host, ips);
                }
                Op::Resolve(ingress) => {
                    check_resolve(&context, &records, &ingress.build(&hosts)).await;
                }
            }
        }
    });
}

fuzz_target!(|plan: Plan| {
    run(plan);
});
