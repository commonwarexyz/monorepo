//! Transport-neutral peer reachability.

#[stability(ALPHA)]
use crate::Provider;
#[stability(ALPHA)]
use commonware_actor::Feedback;
use commonware_codec::{
    EncodeSize, Error as CodecError, FixedSize, Read, ReadExt, Write, config::RangeCfg,
};
use commonware_cryptography::PublicKey;
use commonware_macros::stability;
use commonware_runtime::{Buf, BufMut};
use commonware_utils::{
    PlatformSend, PlatformSync,
    ordered::Map,
};
use std::{collections::HashSet, fmt::Debug, hash::Hash};

const DIALABLE_PREFIX: u8 = 0;
const OUTBOUND_ONLY_PREFIX: u8 = 1;

/// An endpoint that can be advertised to and dialed by peers.
///
/// Endpoint codecs are intentionally not part of this trait. Protocols that exchange endpoints
/// add the codec bounds required by their wire format.
pub trait PeerEndpoint: Clone + Debug + Eq + Hash + PlatformSend + PlatformSync + 'static {}

/// An ordered, non-empty list of unique endpoints.
///
/// Earlier entries are preferred when attempting to reach a peer. At most
/// [`MAX_ENDPOINTS`](Self::MAX_ENDPOINTS) endpoints may be advertised.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Advertisement<E: PeerEndpoint> {
    endpoints: Vec<E>,
}

impl<E: PeerEndpoint> Advertisement<E> {
    /// Maximum number of endpoints in an advertisement.
    pub const MAX_ENDPOINTS: usize = 8;

    /// Maximum encoded size of one endpoint.
    pub const MAX_ENDPOINT_SIZE: usize = 2_048;

    /// Maximum encoded size of an advertisement, including its length prefix.
    pub const MAX_SIZE: usize = 8_192;

    /// Creates an advertisement, preserving the order of `endpoints`.
    ///
    /// Returns an error if no endpoints are supplied, the maximum is exceeded, or an endpoint
    /// occurs more than once.
    pub fn new(endpoints: Vec<E>) -> Result<Self, CodecError> {
        if endpoints.is_empty() || endpoints.len() > Self::MAX_ENDPOINTS {
            return Err(CodecError::InvalidLength(endpoints.len()));
        }

        let mut unique = HashSet::with_capacity(endpoints.len());
        if endpoints.iter().any(|endpoint| !unique.insert(endpoint)) {
            return Err(CodecError::Invalid("Advertisement", "duplicate endpoint"));
        }

        Ok(Self { endpoints })
    }

    /// Returns endpoints in dialing preference order.
    pub fn endpoints(&self) -> &[E] {
        &self.endpoints
    }

    /// Consumes the advertisement and returns endpoints in dialing preference order.
    #[stability(ALPHA)]
    pub fn into_endpoints(self) -> Vec<E> {
        self.endpoints
    }
}

#[stability(ALPHA)]
impl<E: PeerEndpoint + EncodeSize> Advertisement<E> {
    /// Creates an advertisement and validates its encoded size.
    ///
    /// In addition to the identity checks performed by [`new`](Self::new), this rejects endpoints
    /// and advertisements that exceed their encoded-size limits.
    pub fn new_encoded(endpoints: Vec<E>) -> Result<Self, CodecError> {
        let advertisement = Self::new(endpoints)?;
        advertisement.validate_encoded()?;
        Ok(advertisement)
    }

    /// Validates the encoded size of this advertisement and each of its endpoints.
    pub fn validate_encoded(&self) -> Result<(), CodecError> {
        if self
            .endpoints
            .iter()
            .any(|endpoint| endpoint.encode_size() > Self::MAX_ENDPOINT_SIZE)
        {
            return Err(CodecError::Invalid(
                "Advertisement",
                "endpoint exceeds maximum encoded size",
            ));
        }

        if self.encode_size() > Self::MAX_SIZE {
            return Err(CodecError::Invalid(
                "Advertisement",
                "advertisement exceeds maximum encoded size",
            ));
        }

        Ok(())
    }
}

impl<E: PeerEndpoint + Write> Write for Advertisement<E> {
    fn write(&self, buf: &mut impl BufMut) {
        self.endpoints.write(buf);
    }
}

impl<E: PeerEndpoint + EncodeSize> EncodeSize for Advertisement<E> {
    fn encode_size(&self) -> usize {
        self.endpoints.encode_size()
    }
}

impl<E: PeerEndpoint + Read<Cfg = ()>> Read for Advertisement<E> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let advertisement_start = buf.remaining();
        let len = usize::read_cfg(buf, &RangeCfg::new(1..=Self::MAX_ENDPOINTS))?;
        let mut endpoints = Vec::with_capacity(len);

        for _ in 0..len {
            let endpoint_start = buf.remaining();
            let endpoint = E::read(&mut (&mut *buf).take(Self::MAX_ENDPOINT_SIZE))?;
            let endpoint_size = endpoint_start - buf.remaining();
            if endpoint_size > Self::MAX_ENDPOINT_SIZE {
                return Err(CodecError::Invalid(
                    "Advertisement",
                    "endpoint exceeds maximum encoded size",
                ));
            }

            if advertisement_start - buf.remaining() > Self::MAX_SIZE {
                return Err(CodecError::Invalid(
                    "Advertisement",
                    "advertisement exceeds maximum encoded size",
                ));
            }

            endpoints.push(endpoint);
        }

        Self::new(endpoints)
    }
}

/// Whether and how a peer can be reached.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Reachability<E: PeerEndpoint> {
    /// The peer can be dialed using the advertised endpoints.
    Dialable(Advertisement<E>),
    /// The peer cannot be dialed and must establish outbound connections to participate.
    OutboundOnly,
}

impl<E: PeerEndpoint + Write> Write for Reachability<E> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Dialable(advertisement) => {
                DIALABLE_PREFIX.write(buf);
                advertisement.write(buf);
            }
            Self::OutboundOnly => OUTBOUND_ONLY_PREFIX.write(buf),
        }
    }
}

impl<E: PeerEndpoint + EncodeSize> EncodeSize for Reachability<E> {
    fn encode_size(&self) -> usize {
        u8::SIZE
            + match self {
                Self::Dialable(advertisement) => advertisement.encode_size(),
                Self::OutboundOnly => 0,
            }
    }
}

impl<E: PeerEndpoint + Read<Cfg = ()>> Read for Reachability<E> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            DIALABLE_PREFIX => Ok(Self::Dialable(Advertisement::<E>::read(buf)?)),
            OUTBOUND_ONLY_PREFIX => Ok(Self::OutboundOnly),
            other => Err(CodecError::InvalidEnum(other)),
        }
    }
}

/// Primary and secondary peers with transport-neutral reachability information.
///
/// The same public key may appear in both maps. Tracking deduplicates overlapping keys, storing
/// them as primary only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReachableTrackedPeers<P: PublicKey, E: PeerEndpoint> {
    /// Reachability for peers eligible for primary-only policies.
    pub primary: Map<P, Reachability<E>>,
    /// Reachability for peers eligible for secondary-only policies.
    pub secondary: Map<P, Reachability<E>>,
}

impl<P: PublicKey, E: PeerEndpoint> ReachableTrackedPeers<P, E> {
    /// Creates a tracked peer set with primary and secondary peers.
    pub const fn new(
        primary: Map<P, Reachability<E>>,
        secondary: Map<P, Reachability<E>>,
    ) -> Self {
        Self { primary, secondary }
    }

    /// Creates a tracked peer set containing only primary peers.
    pub fn primary(primary: Map<P, Reachability<E>>) -> Self {
        Self::new(primary, Map::default())
    }
}

impl<P: PublicKey, E: PeerEndpoint> From<Map<P, Reachability<E>>>
    for ReachableTrackedPeers<P, E>
{
    fn from(primary: Map<P, Reachability<E>>) -> Self {
        Self::primary(primary)
    }
}

/// Interface for managing peers with transport-neutral reachability information.
///
/// Implementations use [`Reachability::Dialable`] advertisements to connect to peers and retain
/// [`Reachability::OutboundOnly`] peers without attempting to dial them.
#[stability(ALPHA)]
pub trait ReachabilityManager: Provider {
    /// Endpoint type understood by the network transport.
    type Endpoint: PeerEndpoint;

    /// Tracks primary and secondary peers with the given ID.
    ///
    /// IDs must increase monotonically. The highest ID is the active peer set, which implementations
    /// use to decide which connections to maintain. Peers present in both maps are stored as primary
    /// only.
    fn track<R>(&mut self, id: u64, peers: R) -> Feedback
    where
        R: Into<ReachableTrackedPeers<Self::PublicKey, Self::Endpoint>> + PlatformSend;

    /// Updates reachability for tracked peers without creating a new peer set.
    ///
    /// Implementations should discard connections made using stale reachability information and
    /// apply the new information to future connection attempts.
    fn overwrite(
        &mut self,
        peers: Map<Self::PublicKey, Reachability<Self::Endpoint>>,
    ) -> Feedback;
}

#[cfg(feature = "arbitrary")]
impl<'a, E> arbitrary::Arbitrary<'a> for Advertisement<E>
where
    E: PeerEndpoint + arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let len = u.int_in_range(1..=Self::MAX_ENDPOINTS)?;
        let mut endpoints = Vec::with_capacity(len);

        for _ in 0..len {
            endpoints.push(E::arbitrary(u)?);
        }

        Self::new(endpoints).map_err(|_| arbitrary::Error::IncorrectFormat)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a, E> arbitrary::Arbitrary<'a> for Reachability<E>
where
    E: PeerEndpoint + arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        if u.arbitrary::<bool>()? {
            return Ok(Self::OutboundOnly);
        }

        Ok(Self::Dialable(u.arbitrary::<Advertisement<E>>()?))
    }
}
