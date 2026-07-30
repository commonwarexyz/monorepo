#![allow(
    clippy::disallowed_types,
    reason = "this standalone native crate does not depend on commonware-utils"
)]

use ctutils::CtEq as _;
use std::{
    collections::HashMap,
    error::Error,
    fmt::{self, Debug, Formatter},
    sync::{Arc, Mutex, MutexGuard},
};

const CAPABILITY_LENGTH: usize = 32;
const SESSION_ID_LENGTH: usize = 16;
const PUBLIC_KEY_LENGTH: usize = 32;
const SESSION_ID_GENERATION_ATTEMPTS: usize = 8;

/// A bearer secret authorizing one pairing handshake.
#[derive(Clone)]
pub struct Capability([u8; CAPABILITY_LENGTH]);

impl Capability {
    /// Construct a capability from exactly 256 bits supplied by the caller.
    pub const fn from_bytes(bytes: [u8; CAPABILITY_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Generate a capability from the operating system's cryptographic random source.
    pub fn generate() -> Result<Self, getrandom::Error> {
        let mut bytes = [0; CAPABILITY_LENGTH];
        getrandom::fill(&mut bytes)?;
        Ok(Self(bytes))
    }

    /// Expose the capability only for the duration of a serialization callback.
    pub fn expose<R>(&self, use_capability: impl FnOnce(&[u8; CAPABILITY_LENGTH]) -> R) -> R {
        use_capability(&self.0)
    }
}

impl Debug for Capability {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("Capability([REDACTED])")
    }
}

impl PartialEq for Capability {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for Capability {}

/// Public identifier for a pairing session.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SessionId([u8; SESSION_ID_LENGTH]);

impl SessionId {
    /// Construct a session ID from exactly 128 bits supplied by the caller.
    pub const fn from_bytes(bytes: [u8; SESSION_ID_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Return the wire representation.
    pub const fn as_bytes(&self) -> &[u8; SESSION_ID_LENGTH] {
        &self.0
    }

    fn generate() -> Result<Self, getrandom::Error> {
        let mut bytes = [0; SESSION_ID_LENGTH];
        getrandom::fill(&mut bytes)?;
        Ok(Self(bytes))
    }
}

/// Raw authenticated Ed25519 public-key bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PublicKeyBytes([u8; PUBLIC_KEY_LENGTH]);

impl PublicKeyBytes {
    /// Construct a key representation from the 32 bytes authenticated by the handshake.
    pub const fn new(bytes: [u8; PUBLIC_KEY_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Return the authenticated key bytes.
    pub const fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        &self.0
    }
}

/// Values serialized into a pairing invitation.
#[derive(Clone, Debug)]
pub struct PairingInvite {
    session_id: SessionId,
    capability: Capability,
    expires_at: u64,
}

impl PairingInvite {
    /// Return the public session identifier.
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Expose the capability for invite serialization.
    pub const fn capability(&self) -> &Capability {
        &self.capability
    }

    /// Return the Unix-seconds deadline. The invite is invalid at this second and later.
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

/// Proof that a session was consumed by an authenticated peer.
///
/// Pass this value across the application's lookup attachment seam. It does not itself attach a
/// connection or represent a network transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerAdmission {
    session_id: SessionId,
    public_key: PublicKeyBytes,
}

impl PeerAdmission {
    /// Return the pairing session that authorized the peer.
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Return the key authenticated by the handshake.
    pub const fn public_key(&self) -> PublicKeyBytes {
        self.public_key
    }
}

/// Pairing state transition failure.
#[derive(Debug, Eq, PartialEq)]
pub enum PairingError {
    /// No session exists for the supplied identifier.
    UnknownSession,
    /// A caller attempted to insert an existing session identifier.
    SessionAlreadyExists,
    /// A generated identifier collided too many times.
    SessionIdGenerationExhausted,
    /// The invite deadline is not in the future.
    InvalidExpiry,
    /// The session has reached its Unix-seconds deadline.
    Expired,
    /// The presented capability does not match.
    CapabilityMismatch,
    /// A handshake already owns the active reservation.
    AlreadyReserved,
    /// The capability has already been consumed.
    AlreadyConsumed,
    /// This reservation no longer owns the session.
    ReservationLost,
    /// Reconnect was not enabled when the store was created.
    ReconnectDisabled,
    /// The requested reconnect lease is zero or exceeds the configured maximum.
    InvalidReconnectLease,
    /// The reconnect lease has elapsed or was not requested.
    ReconnectExpired,
    /// The reconnecting peer did not authenticate the bound key.
    ReconnectKeyMismatch,
    /// A Unix-seconds lease deadline overflowed.
    TimestampOverflow,
    /// The operating system could not provide cryptographic randomness.
    EntropyUnavailable,
}

impl fmt::Display for PairingError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for PairingError {}

/// Concurrent pairing session store.
#[derive(Clone)]
pub struct PairingStore {
    inner: Arc<Inner>,
}

struct Inner {
    sessions: Mutex<HashMap<SessionId, Session>>,
    max_reconnect_lease_seconds: Option<u64>,
}

struct Session {
    capability: Option<Capability>,
    expires_at: u64,
    state: SessionState,
}

enum SessionState {
    Available,
    Reserved {
        reservation_id: u64,
    },
    Bound {
        public_key: PublicKeyBytes,
        reconnect_until: Option<u64>,
    },
}

impl PairingStore {
    /// Create a store with an optional upper bound on reconnect leases.
    pub fn new(max_reconnect_lease_seconds: Option<u64>) -> Self {
        Self {
            inner: Arc::new(Inner {
                sessions: Mutex::new(HashMap::new()),
                max_reconnect_lease_seconds,
            }),
        }
    }

    /// Mint and store a fresh invite using operating-system randomness.
    pub fn create(&self, expires_at: u64, now: u64) -> Result<PairingInvite, PairingError> {
        if expires_at <= now {
            return Err(PairingError::InvalidExpiry);
        }

        for _ in 0..SESSION_ID_GENERATION_ATTEMPTS {
            let session_id = SessionId::generate().map_err(|_| PairingError::EntropyUnavailable)?;
            let capability =
                Capability::generate().map_err(|_| PairingError::EntropyUnavailable)?;
            let mut sessions = self.sessions();
            if sessions.contains_key(&session_id) {
                continue;
            }
            sessions.insert(
                session_id,
                Session {
                    capability: Some(capability.clone()),
                    expires_at,
                    state: SessionState::Available,
                },
            );
            return Ok(PairingInvite {
                session_id,
                capability,
                expires_at,
            });
        }

        Err(PairingError::SessionIdGenerationExhausted)
    }

    /// Insert caller-supplied invite material.
    ///
    /// This is useful when invitation generation is owned by a higher-level secure component.
    pub fn insert(
        &self,
        session_id: SessionId,
        capability: Capability,
        expires_at: u64,
        now: u64,
    ) -> Result<(), PairingError> {
        if expires_at <= now {
            return Err(PairingError::InvalidExpiry);
        }

        let mut sessions = self.sessions();
        if sessions.contains_key(&session_id) {
            return Err(PairingError::SessionAlreadyExists);
        }
        sessions.insert(
            session_id,
            Session {
                capability: Some(capability),
                expires_at,
                state: SessionState::Available,
            },
        );
        Ok(())
    }

    /// Reserve a capability for one in-progress authenticated handshake.
    pub fn reserve(
        &self,
        session_id: SessionId,
        capability: &Capability,
        now: u64,
    ) -> Result<PairingReservation, PairingError> {
        let mut sessions = self.sessions();
        let session = sessions
            .get_mut(&session_id)
            .ok_or(PairingError::UnknownSession)?;
        if now >= session.expires_at {
            return Err(PairingError::Expired);
        }

        match session.state {
            SessionState::Available => {}
            SessionState::Reserved { .. } => return Err(PairingError::AlreadyReserved),
            SessionState::Bound { .. } => return Err(PairingError::AlreadyConsumed),
        }

        let expected = session
            .capability
            .as_ref()
            .expect("unconsumed session must retain its capability");
        if expected != capability {
            return Err(PairingError::CapabilityMismatch);
        }

        let reservation_id = next_reservation_id();
        session.state = SessionState::Reserved { reservation_id };
        Ok(PairingReservation {
            inner: Arc::clone(&self.inner),
            session_id,
            reservation_id,
            active: true,
        })
    }

    /// Re-admit a previously bound key while its optional reconnect lease remains active.
    pub fn reconnect(
        &self,
        session_id: SessionId,
        public_key: PublicKeyBytes,
        now: u64,
    ) -> Result<PeerAdmission, PairingError> {
        let sessions = self.sessions();
        let session = sessions
            .get(&session_id)
            .ok_or(PairingError::UnknownSession)?;
        let SessionState::Bound {
            public_key: bound_key,
            reconnect_until,
        } = session.state
        else {
            return Err(PairingError::ReconnectExpired);
        };
        let reconnect_until = reconnect_until.ok_or(PairingError::ReconnectExpired)?;
        if now >= reconnect_until {
            return Err(PairingError::ReconnectExpired);
        }
        if public_key != bound_key {
            return Err(PairingError::ReconnectKeyMismatch);
        }

        Ok(PeerAdmission {
            session_id,
            public_key,
        })
    }

    fn sessions(&self) -> MutexGuard<'_, HashMap<SessionId, Session>> {
        lock_sessions(&self.inner)
    }
}

impl Default for PairingStore {
    fn default() -> Self {
        Self::new(None)
    }
}

/// Exclusive ownership of one in-progress pairing handshake.
///
/// Dropping this value before successful consumption releases the session. This includes task
/// cancellation, early handshake failure, and admission metadata being discarded.
pub struct PairingReservation {
    inner: Arc<Inner>,
    session_id: SessionId,
    reservation_id: u64,
    active: bool,
}

impl PairingReservation {
    /// Atomically consume the capability and bind the authenticated Ed25519 key.
    ///
    /// `reconnect_lease_seconds` is accepted only when the store has a configured maximum. A
    /// failed call leaves this reservation active, so dropping it safely releases the session.
    pub fn consume_and_bind(
        mut self,
        public_key: PublicKeyBytes,
        now: u64,
        reconnect_lease_seconds: Option<u64>,
    ) -> Result<PeerAdmission, PairingError> {
        let reconnect_until = reconnect_deadline(
            self.inner.max_reconnect_lease_seconds,
            reconnect_lease_seconds,
            now,
        )?;

        let mut sessions = lock_sessions(&self.inner);
        let session = sessions
            .get_mut(&self.session_id)
            .ok_or(PairingError::UnknownSession)?;
        if now >= session.expires_at {
            return Err(PairingError::Expired);
        }
        let SessionState::Reserved { reservation_id } = session.state else {
            return Err(PairingError::ReservationLost);
        };
        if reservation_id != self.reservation_id {
            return Err(PairingError::ReservationLost);
        }

        session.capability = None;
        session.state = SessionState::Bound {
            public_key,
            reconnect_until,
        };
        self.active = false;
        Ok(PeerAdmission {
            session_id: self.session_id,
            public_key,
        })
    }
}

impl Debug for PairingReservation {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingReservation")
            .field("session_id", &self.session_id)
            .field("reservation", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl Drop for PairingReservation {
    fn drop(&mut self) {
        if !self.active {
            return;
        }

        let mut sessions = lock_sessions(&self.inner);
        let Some(session) = sessions.get_mut(&self.session_id) else {
            return;
        };
        let SessionState::Reserved { reservation_id } = session.state else {
            return;
        };
        if reservation_id != self.reservation_id {
            return;
        }
        session.state = SessionState::Available;
    }
}

fn reconnect_deadline(
    maximum: Option<u64>,
    requested: Option<u64>,
    now: u64,
) -> Result<Option<u64>, PairingError> {
    let Some(requested) = requested else {
        return Ok(None);
    };
    let maximum = maximum.ok_or(PairingError::ReconnectDisabled)?;
    if requested == 0 || requested > maximum {
        return Err(PairingError::InvalidReconnectLease);
    }
    now.checked_add(requested)
        .map(Some)
        .ok_or(PairingError::TimestampOverflow)
}

fn lock_sessions(inner: &Inner) -> MutexGuard<'_, HashMap<SessionId, Session>> {
    inner
        .sessions
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn next_reservation_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_ID: AtomicU64 = AtomicU64::new(1);
    NEXT_ID.fetch_add(1, Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{Arc, Barrier},
        thread,
    };

    const NOW: u64 = 1_900_000_000;

    fn session(value: u8) -> SessionId {
        SessionId::from_bytes([value; SESSION_ID_LENGTH])
    }

    fn capability(value: u8) -> Capability {
        Capability::from_bytes([value; CAPABILITY_LENGTH])
    }

    fn key(value: u8) -> PublicKeyBytes {
        PublicKeyBytes::new([value; PUBLIC_KEY_LENGTH])
    }

    fn store_with_session(maximum_lease: Option<u64>) -> PairingStore {
        let store = PairingStore::new(maximum_lease);
        store
            .insert(session(1), capability(2), NOW + 60, NOW)
            .unwrap();
        store
    }

    #[test]
    fn capability_debug_is_redacted() {
        assert_eq!(format!("{:?}", capability(7)), "Capability([REDACTED])");
        let invite = PairingInvite {
            session_id: session(1),
            capability: capability(7),
            expires_at: NOW + 1,
        };
        assert!(!format!("{invite:?}").contains("7, 7"));
    }

    #[test]
    fn rejects_expired_capability_at_exact_deadline() {
        let store = store_with_session(None);
        assert!(matches!(
            store.reserve(session(1), &capability(2), NOW + 60),
            Err(PairingError::Expired)
        ));
    }

    #[test]
    fn consumed_capability_cannot_be_replayed() {
        let store = store_with_session(None);
        store
            .reserve(session(1), &capability(2), NOW)
            .unwrap()
            .consume_and_bind(key(3), NOW, None)
            .unwrap();

        assert!(matches!(
            store.reserve(session(1), &capability(2), NOW + 1),
            Err(PairingError::AlreadyConsumed)
        ));
    }

    #[test]
    fn only_one_concurrent_reservation_succeeds() {
        let store = store_with_session(None);
        let barrier = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();

        for _ in 0..2 {
            let store = store.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                let reservation = store.reserve(session(1), &capability(2), NOW);
                barrier.wait();
                reservation
            }));
        }

        barrier.wait();
        barrier.wait();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(PairingError::AlreadyReserved)))
                .count(),
            1
        );
    }

    #[test]
    fn dropping_reservation_releases_session() {
        let store = store_with_session(None);
        let reservation = store.reserve(session(1), &capability(2), NOW).unwrap();
        drop(reservation);

        assert!(store.reserve(session(1), &capability(2), NOW).is_ok());
    }

    #[test]
    fn wrong_reservation_cannot_consume_or_release_owner() {
        let store = store_with_session(None);
        let stale = store.reserve(session(1), &capability(2), NOW).unwrap();
        let owner_id = stale.reservation_id + 1;
        {
            let mut sessions = store.sessions();
            sessions.get_mut(&session(1)).unwrap().state = SessionState::Reserved {
                reservation_id: owner_id,
            };
        }

        assert_eq!(
            stale.consume_and_bind(key(3), NOW, None),
            Err(PairingError::ReservationLost)
        );
        let sessions = store.sessions();
        assert!(matches!(
            sessions.get(&session(1)).unwrap().state,
            SessionState::Reserved { reservation_id } if reservation_id == owner_id
        ));
    }

    #[test]
    fn reconnect_requires_the_bound_key() {
        let store = store_with_session(Some(30));
        store
            .reserve(session(1), &capability(2), NOW)
            .unwrap()
            .consume_and_bind(key(3), NOW, Some(30))
            .unwrap();

        assert_eq!(
            store.reconnect(session(1), key(4), NOW + 1),
            Err(PairingError::ReconnectKeyMismatch)
        );
        assert_eq!(
            store
                .reconnect(session(1), key(3), NOW + 1)
                .unwrap()
                .public_key(),
            key(3)
        );
        assert_eq!(
            store.reconnect(session(1), key(3), NOW + 30),
            Err(PairingError::ReconnectExpired)
        );
    }

    #[test]
    fn reconnect_lease_is_bounded() {
        let store = store_with_session(Some(30));
        let reservation = store.reserve(session(1), &capability(2), NOW).unwrap();
        assert_eq!(
            reservation.consume_and_bind(key(3), NOW, Some(31)),
            Err(PairingError::InvalidReconnectLease)
        );
        assert!(store.reserve(session(1), &capability(2), NOW).is_ok());
    }
}
