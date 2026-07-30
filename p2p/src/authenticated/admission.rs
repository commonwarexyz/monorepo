//! Admission policies for inbound authenticated connections.

use commonware_cryptography::PublicKey;
use commonware_macros::stability;
use commonware_runtime::{
    Clock, ConnectionInfo, KeyedRateLimiter, Metrics, Quota, TcpOrigin,
    telemetry::metrics::{Counter, MetricsExt as _},
};
use commonware_utils::{
    IpAddrExt, PlatformSend, PlatformSync,
    net::{Subnet, SubnetMask},
    sync::RwLock,
};
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};
use thiserror::Error;

/// Subnet mask used to rate limit inbound TCP handshakes.
const SUBNET_MASK: SubnetMask = SubnetMask::new(24, 48);

/// Number of admitted origins between rate-limiter cleanup attempts.
const CLEANUP_INTERVAL: u32 = 16_384;

/// Authorizes an inbound connection before and after peer authentication.
///
/// The pre-authentication permit carries policy state across the encrypted handshake. It is
/// dropped without calling [`InboundAdmission::post_auth`] if the handshake fails.
pub trait InboundAdmission<P: PublicKey, O>: PlatformSend + PlatformSync + 'static {
    /// State retained while the encrypted handshake is in progress.
    type Permit: PlatformSend + 'static;

    /// Decides whether authentication should begin.
    fn pre_auth(&self, info: &ConnectionInfo<O>) -> Result<Self::Permit, Rejection>;

    /// Checks the claimed peer before performing the cryptographic handshake.
    ///
    /// Policies that bind transport origins to peer identities should reject mismatches here and
    /// repeat the check in [`InboundAdmission::post_auth`] to guard against concurrent policy
    /// updates.
    fn accept_peer(
        &self,
        _peer: &P,
        _info: &ConnectionInfo<O>,
    ) -> bool {
        true
    }

    /// Decides whether the authenticated peer may use the connection.
    fn post_auth(
        &self,
        permit: Self::Permit,
        peer: &P,
        info: &ConnectionInfo<O>,
    ) -> impl Future<Output = Result<(), Rejection>> + PlatformSend;
}

/// Admits only one expected authenticated peer, independent of transport origin.
#[stability(ALPHA)]
#[derive(Clone, Debug)]
pub struct ExactPeerAdmission<P> {
    expected: P,
}

#[stability(ALPHA)]
impl<P> ExactPeerAdmission<P> {
    /// Creates an admission policy for `expected`.
    pub const fn new(expected: P) -> Self {
        Self { expected }
    }
}

#[stability(ALPHA)]
impl<P, O> InboundAdmission<P, O> for ExactPeerAdmission<P>
where
    P: PublicKey,
    O: PlatformSend + PlatformSync + 'static,
{
    type Permit = ();

    fn pre_auth(&self, _info: &ConnectionInfo<O>) -> Result<Self::Permit, Rejection> {
        Ok(())
    }

    fn accept_peer(
        &self,
        peer: &P,
        _info: &ConnectionInfo<O>,
    ) -> bool {
        peer == &self.expected
    }

    async fn post_auth(
        &self,
        _permit: Self::Permit,
        peer: &P,
        _info: &ConnectionInfo<O>,
    ) -> Result<(), Rejection> {
        if peer == &self.expected {
            return Ok(());
        }
        Err(Rejection::Application)
    }
}

/// Configuration for TCP inbound admission.
#[derive(Clone)]
pub struct TcpAdmissionConfig {
    /// Whether non-global source IP addresses are allowed.
    pub allow_private_ips: bool,

    /// Whether a source IP must be present in the registered IP set.
    pub require_registered_ip: bool,

    /// Quota for handshake attempts from one IP address.
    pub allowed_handshake_rate_per_ip: Quota,

    /// Quota for handshake attempts from one `/24` IPv4 or `/48` IPv6 subnet.
    pub allowed_handshake_rate_per_subnet: Quota,
}

/// Reason an inbound TCP connection was rejected before authentication.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum Rejection {
    /// The transport did not provide the remote TCP socket.
    #[error("TCP connection is missing its remote origin")]
    MissingOrigin,

    /// The remote IP is not globally routable.
    #[error("private IP is not allowed")]
    PrivateIp,

    /// The remote IP is not registered by an authorized peer.
    #[error("IP is not registered")]
    UnregisteredIp,

    /// The remote IP exceeded its handshake quota.
    #[error("IP exceeded its handshake quota")]
    IpRateLimited,

    /// The remote subnet exceeded its handshake quota.
    #[error("subnet exceeded its handshake quota")]
    SubnetRateLimited,

    /// An application-specific admission rule rejected the connection.
    #[cfg(not(any(
        commonware_stability_BETA,
        commonware_stability_GAMMA,
        commonware_stability_DELTA,
        commonware_stability_EPSILON,
        commonware_stability_RESERVED
    )))] // ALPHA
    #[error("application admission policy rejected the connection")]
    Application,
}

/// Permit retained across a TCP handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpPermit {
    source: SocketAddr,
}

/// Applies private-IP, registered-IP, exact-IP, and subnet admission rules to TCP connections.
pub struct TcpAdmission<E: Clock + Metrics, P: PublicKey> {
    allow_private_ips: bool,
    require_registered_ip: bool,
    address_book: Arc<RwLock<TcpAddressBook<P>>>,
    eligibility: Option<PeerEligibility<P>>,
    ip_rate_limiter: KeyedRateLimiter<IpAddr, E>,
    subnet_rate_limiter: KeyedRateLimiter<Subnet, E>,
    admitted: AtomicU32,
    handshakes_blocked: Counter,
    handshakes_ip_rate_limited: Counter,
    handshakes_subnet_rate_limited: Counter,
}

/// Handle used to atomically replace TCP peer-origin associations.
#[derive(Clone)]
pub struct TcpAdmissionUpdates<P: PublicKey> {
    address_book: Arc<RwLock<TcpAddressBook<P>>>,
}

struct TcpAddressBook<P> {
    registered_ips: HashSet<IpAddr>,
    peers_by_ip: HashMap<IpAddr, HashSet<P>>,
    peer_ips: HashMap<P, HashSet<IpAddr>>,
}

impl<P> Default for TcpAddressBook<P> {
    fn default() -> Self {
        Self {
            registered_ips: HashSet::new(),
            peers_by_ip: HashMap::new(),
            peer_ips: HashMap::new(),
        }
    }
}

/// Shared snapshot of peers currently eligible for inbound authentication.
#[derive(Clone)]
pub(crate) struct PeerEligibility<P> {
    peers: Arc<RwLock<HashSet<P>>>,
}

impl<P> Default for PeerEligibility<P> {
    fn default() -> Self {
        Self {
            peers: Arc::new(RwLock::new(HashSet::new())),
        }
    }
}

impl<P: Eq + std::hash::Hash> PeerEligibility<P> {
    pub(crate) fn set(&self, peers: HashSet<P>) {
        *self.peers.write() = peers;
    }

    fn allows_any(&self, peers: &HashSet<P>) -> bool {
        let eligible = self.peers.read();
        peers.iter().any(|peer| eligible.contains(peer))
    }
}

impl<P: PublicKey> TcpAdmissionUpdates<P> {
    /// Replaces the registered union and exact peer-to-origin associations together.
    pub fn set(&self, peer_ips: HashMap<P, HashSet<IpAddr>>) {
        let registered_ips = peer_ips.values().flatten().copied().collect();
        let mut peers_by_ip: HashMap<IpAddr, HashSet<P>> = HashMap::new();
        for (peer, ips) in &peer_ips {
            for ip in ips {
                peers_by_ip.entry(*ip).or_default().insert(peer.clone());
            }
        }
        *self.address_book.write() = TcpAddressBook {
            registered_ips,
            peers_by_ip,
            peer_ips,
        };
    }
}

impl<E: Clock + Metrics, P: PublicKey> TcpAdmission<E, P> {
    /// Creates a policy and a handle for updating its registered peer origins.
    #[cfg(test)]
    pub fn with_updates(context: E, cfg: TcpAdmissionConfig) -> (Self, TcpAdmissionUpdates<P>) {
        Self::new(context, cfg, None)
    }

    pub(crate) fn with_eligibility(
        context: E,
        cfg: TcpAdmissionConfig,
        eligibility: PeerEligibility<P>,
    ) -> (Self, TcpAdmissionUpdates<P>) {
        Self::new(context, cfg, Some(eligibility))
    }

    fn new(
        context: E,
        cfg: TcpAdmissionConfig,
        eligibility: Option<PeerEligibility<P>>,
    ) -> (Self, TcpAdmissionUpdates<P>) {
        let ip_rate_limiter = KeyedRateLimiter::hashmap_with_clock(
            cfg.allowed_handshake_rate_per_ip,
            context.child("ip_rate_limiter"),
        );
        let subnet_rate_limiter = KeyedRateLimiter::hashmap_with_clock(
            cfg.allowed_handshake_rate_per_subnet,
            context.child("subnet_rate_limiter"),
        );
        let handshakes_blocked = context.counter(
            "handshakes_blocked",
            "number of handshake attempts blocked by TCP origin policy",
        );
        let handshakes_ip_rate_limited = context.counter(
            "handshake_ip_rate_limited",
            "number of handshake attempts dropped because an IP exceeded its rate limit",
        );
        let handshakes_subnet_rate_limited = context.counter(
            "handshake_subnet_rate_limited",
            "number of handshake attempts dropped because a subnet exceeded its rate limit",
        );

        let address_book = Arc::new(RwLock::new(TcpAddressBook::default()));
        let updates = TcpAdmissionUpdates {
            address_book: address_book.clone(),
        };
        let admission = Self {
            allow_private_ips: cfg.allow_private_ips,
            require_registered_ip: cfg.require_registered_ip,
            address_book,
            eligibility,
            ip_rate_limiter,
            subnet_rate_limiter,
            admitted: AtomicU32::new(0),
            handshakes_blocked,
            handshakes_ip_rate_limited,
            handshakes_subnet_rate_limited,
        };
        (admission, updates)
    }

    fn registered(&self, ip: &IpAddr) -> bool {
        let address_book = self.address_book.read();
        let Some(eligibility) = &self.eligibility else {
            return address_book.registered_ips.contains(ip);
        };
        address_book
            .peers_by_ip
            .get(ip)
            .is_some_and(|peers| eligibility.allows_any(peers))
    }

    fn peer_registered(&self, source: IpAddr, peer: &P) -> bool {
        !self.require_registered_ip
            || self
                .address_book
                .read()
                .peer_ips
                .get(peer)
                .is_some_and(|ips| ips.contains(&source))
    }

    fn pre_auth(&self, info: &ConnectionInfo<TcpOrigin>) -> Result<TcpPermit, Rejection> {
        let Some(origin) = &info.origin else {
            self.handshakes_blocked.inc();
            return Err(Rejection::MissingOrigin);
        };
        let source = origin.remote;
        let ip = source.ip();

        if !self.allow_private_ips && !IpAddrExt::is_global(&ip) {
            self.handshakes_blocked.inc();
            return Err(Rejection::PrivateIp);
        }
        if self.require_registered_ip && !self.registered(&ip) {
            self.handshakes_blocked.inc();
            return Err(Rejection::UnregisteredIp);
        }

        if self.admitted.fetch_add(1, Ordering::Relaxed) >= CLEANUP_INTERVAL {
            self.ip_rate_limiter.retain_recent();
            self.subnet_rate_limiter.retain_recent();
            self.admitted.store(0, Ordering::Relaxed);
        }

        // Charge both buckets even when the first is exhausted. This prevents an attacker from
        // avoiding the subnet quota by first exhausting its exact-IP quota.
        let ip_limited = self.ip_rate_limiter.check_key(&ip).is_err();
        let subnet = ip.subnet(&SUBNET_MASK);
        let subnet_limited = self.subnet_rate_limiter.check_key(&subnet).is_err();

        if ip_limited {
            self.handshakes_ip_rate_limited.inc();
        }
        if subnet_limited {
            self.handshakes_subnet_rate_limited.inc();
        }
        if ip_limited {
            return Err(Rejection::IpRateLimited);
        }
        if subnet_limited {
            return Err(Rejection::SubnetRateLimited);
        }

        Ok(TcpPermit { source })
    }
}

impl<E, P> InboundAdmission<P, TcpOrigin> for TcpAdmission<E, P>
where
    E: Clock + Metrics,
    P: PublicKey,
{
    type Permit = TcpPermit;
    fn pre_auth(&self, info: &ConnectionInfo<TcpOrigin>) -> Result<Self::Permit, Rejection> {
        Self::pre_auth(self, info)
    }

    fn accept_peer(
        &self,
        peer: &P,
        info: &ConnectionInfo<TcpOrigin>,
    ) -> bool {
        let Some(origin) = &info.origin else {
            return false;
        };
        if self.peer_registered(origin.remote.ip(), peer) {
            return true;
        }
        self.handshakes_blocked.inc();
        false
    }

    async fn post_auth(
        &self,
        permit: Self::Permit,
        peer: &P,
        _info: &ConnectionInfo<TcpOrigin>,
    ) -> Result<(), Rejection> {
        if !self.peer_registered(permit.source.ip(), peer) {
            self.handshakes_blocked.inc();
            return Err(Rejection::UnregisteredIp);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{
        Signer as _,
        ed25519::{PrivateKey, PublicKey},
    };
    use commonware_runtime::{Quota, Runner as _, Supervisor as _, deterministic};
    use commonware_utils::NZU32;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn info(ip: IpAddr) -> ConnectionInfo<TcpOrigin> {
        ConnectionInfo {
            origin: Some(TcpOrigin {
                remote: SocketAddr::new(ip, 1234),
            }),
            transport: "tcp",
        }
    }

    fn config(ip: Quota, subnet: Quota) -> TcpAdmissionConfig {
        TcpAdmissionConfig {
            allow_private_ips: true,
            require_registered_ip: true,
            allowed_handshake_rate_per_ip: ip,
            allowed_handshake_rate_per_subnet: subnet,
        }
    }

    #[test]
    fn enforces_origin_and_registered_ip() {
        deterministic::Runner::default().start(|context| async move {
            let (admission, updates) = TcpAdmission::with_updates(
                context.child("admission"),
                config(Quota::per_second(NZU32!(10)), Quota::per_second(NZU32!(10))),
            );
            let peer = PrivateKey::from_seed(1).public_key();
            let missing = ConnectionInfo {
                origin: None,
                transport: "tcp",
            };
            assert_eq!(
                <TcpAdmission<_, PublicKey> as InboundAdmission<PublicKey, TcpOrigin>>::pre_auth(
                    &admission, &missing
                ),
                Err(Rejection::MissingOrigin)
            );

            let source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
            assert_eq!(
                <TcpAdmission<_, PublicKey> as InboundAdmission<PublicKey, TcpOrigin>>::pre_auth(
                    &admission,
                    &info(source),
                ),
                Err(Rejection::UnregisteredIp)
            );
            updates.set(HashMap::from([(peer, HashSet::from([source]))]));
            assert!(
                <TcpAdmission<_, PublicKey> as InboundAdmission<PublicKey, TcpOrigin>>::pre_auth(
                    &admission,
                    &info(source),
                )
                .is_ok()
            );

            let private_admission = TcpAdmission::with_updates(
                context.child("private"),
                TcpAdmissionConfig {
                    allow_private_ips: false,
                    require_registered_ip: false,
                    allowed_handshake_rate_per_ip: Quota::per_second(NZU32!(10)),
                    allowed_handshake_rate_per_subnet: Quota::per_second(NZU32!(10)),
                },
            )
            .0;
            assert_eq!(
                <TcpAdmission<_, PublicKey> as InboundAdmission<PublicKey, TcpOrigin>>::pre_auth(
                    &private_admission,
                    &info(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                ),
                Err(Rejection::PrivateIp)
            );
        });
    }

    #[test]
    fn charges_exact_ip_and_subnet_limits() {
        deterministic::Runner::default().start(|context| async move {
            let (admission, updates) = TcpAdmission::with_updates(
                context.child("admission"),
                config(Quota::per_second(NZU32!(1)), Quota::per_second(NZU32!(2))),
            );
            let first = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1));
            let second = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 2));
            let peer = PrivateKey::from_seed(1).public_key();
            updates.set(HashMap::from([(peer, HashSet::from([first, second]))]));

            let admit = |source| {
                <TcpAdmission<_, PublicKey> as InboundAdmission<PublicKey, TcpOrigin>>::pre_auth(
                    &admission,
                    &info(source),
                )
            };
            assert!(admit(first).is_ok());
            assert_eq!(admit(first), Err(Rejection::IpRateLimited));
            assert_eq!(admit(second), Err(Rejection::SubnetRateLimited));

            let metrics = context.encode();
            assert!(metrics.contains("handshake_ip_rate_limited_total 1"));
            assert!(metrics.contains("handshake_subnet_rate_limited_total 1"));
        });
    }

    #[test]
    fn revalidates_peer_origin_after_authentication() {
        deterministic::Runner::default().start(|context| async move {
            let (admission, updates) = TcpAdmission::with_updates(
                context.child("admission"),
                config(Quota::per_second(NZU32!(10)), Quota::per_second(NZU32!(10))),
            );
            let peer = PrivateKey::from_seed(1).public_key();
            let other = PrivateKey::from_seed(2).public_key();
            let source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
            let replacement = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
            updates.set(HashMap::from([(peer.clone(), HashSet::from([source]))]));

            let permit =
                <TcpAdmission<_, PublicKey> as InboundAdmission<PublicKey, TcpOrigin>>::pre_auth(
                    &admission,
                    &info(source),
                )
                .expect("registered source should begin authentication");
            assert_eq!(
                admission.post_auth(permit, &other, &info(source)).await,
                Err(Rejection::UnregisteredIp),
                "an origin registered to another peer must be rejected"
            );

            let permit =
                <TcpAdmission<_, PublicKey> as InboundAdmission<PublicKey, TcpOrigin>>::pre_auth(
                    &admission,
                    &info(source),
                )
                .expect("registered source should begin authentication");
            updates.set(HashMap::from([(
                peer.clone(),
                HashSet::from([replacement]),
            )]));
            assert_eq!(
                admission.post_auth(permit, &peer, &info(source)).await,
                Err(Rejection::UnregisteredIp),
                "address-book changes during authentication must be revalidated"
            );
        });
    }
}
