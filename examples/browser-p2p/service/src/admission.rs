use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use commonware_browser_p2p_service::{
    Capability, PairingReservation, PairingStore, PublicKeyBytes, SessionId,
};
use commonware_cryptography::ed25519;
use commonware_p2p::authenticated::lookup::{PeerAdmission, Rejected};
use commonware_runtime::ConnectionInfo;
use commonware_utils::sync::Mutex;
use commonware_websocket::{
    Admission, UpgradeErrorResponse, UpgradeRequest, UpgradeResponse, WebSocketOrigin,
};
use http::{Response, StatusCode};
use std::{
    fmt::{self, Debug, Formatter},
    net::SocketAddr,
    sync::Arc,
};

/// Cloneable, redacted transport metadata around a uniquely takeable reservation.
#[derive(Clone)]
pub struct UpgradeOrigin {
    reservation: Arc<Mutex<Option<PairingReservation>>>,
}

impl UpgradeOrigin {
    fn new(reservation: PairingReservation) -> Self {
        Self {
            reservation: Arc::new(Mutex::new(Some(reservation))),
        }
    }

    fn take(&self) -> Option<PairingReservation> {
        self.reservation.lock().take()
    }
}

impl Debug for UpgradeOrigin {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UpgradeOrigin")
            .field("reservation", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone)]
pub(crate) struct UpgradeAdmission {
    store: PairingStore,
}

impl UpgradeAdmission {
    pub(crate) const fn new(store: PairingStore) -> Self {
        Self { store }
    }
}

impl Admission for UpgradeAdmission {
    type Permit = UpgradeOrigin;

    fn admit(
        &self,
        _remote: SocketAddr,
        request: &UpgradeRequest,
        _response: &mut UpgradeResponse,
    ) -> Result<Self::Permit, UpgradeErrorResponse> {
        if request.uri().path() != "/pair" {
            return Err(reject(StatusCode::NOT_FOUND));
        }

        let Some((session, capability)) = credentials(request.uri().query()) else {
            return Err(reject(StatusCode::BAD_REQUEST));
        };
        let reservation = self
            .store
            .reserve(session, &capability, unix_seconds())
            .map_err(|_| reject(StatusCode::UNAUTHORIZED))?;
        Ok(UpgradeOrigin::new(reservation))
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PairingPolicy {
    admitted: tokio::sync::mpsc::Sender<ed25519::PublicKey>,
}

impl PairingPolicy {
    pub(crate) const fn new(admitted: tokio::sync::mpsc::Sender<ed25519::PublicKey>) -> Self {
        Self { admitted }
    }
}

impl PeerAdmission<ed25519::PublicKey, WebSocketOrigin<UpgradeOrigin>> for PairingPolicy {
    type Permit = PairingReservation;

    fn pre_auth(
        &self,
        info: &ConnectionInfo<WebSocketOrigin<UpgradeOrigin>>,
    ) -> Result<Self::Permit, Rejected> {
        info.origin
            .as_ref()
            .and_then(|origin| origin.permit().take())
            .ok_or(Rejected)
    }

    async fn post_auth(
        &self,
        permit: Self::Permit,
        peer: &ed25519::PublicKey,
        _info: &ConnectionInfo<WebSocketOrigin<UpgradeOrigin>>,
    ) -> Result<(), Rejected> {
        let public_key = peer.as_ref().try_into().map_err(|_| Rejected)?;
        permit
            .consume_and_bind(PublicKeyBytes::new(public_key), unix_seconds(), None)
            .map_err(|_| Rejected)?;
        let _ = self.admitted.send(peer.clone()).await;
        Ok(())
    }
}

fn credentials(query: Option<&str>) -> Option<(SessionId, Capability)> {
    let mut session = None;
    let mut capability = None;
    for pair in query?.split('&') {
        let (name, value) = pair.split_once('=')?;
        match name {
            "sid" if session.is_none() => session = decode_session(value),
            "cap" if capability.is_none() => capability = decode_capability(value),
            _ => return None,
        }
    }
    Some((session?, capability?))
}

fn decode_session(value: &str) -> Option<SessionId> {
    let bytes: [u8; 16] = URL_SAFE_NO_PAD.decode(value).ok()?.try_into().ok()?;
    Some(SessionId::from_bytes(bytes))
}

fn decode_capability(value: &str) -> Option<Capability> {
    let bytes: [u8; 32] = URL_SAFE_NO_PAD.decode(value).ok()?.try_into().ok()?;
    Some(Capability::from_bytes(bytes))
}

fn reject(status: StatusCode) -> UpgradeErrorResponse {
    Box::new(
        Response::builder()
            .status(status)
            .body(Some(
                status.canonical_reason().unwrap_or("rejected").to_string(),
            ))
            .expect("static rejection response must be valid"),
    )
}

pub(crate) fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock must be after Unix epoch")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    #[test]
    fn parses_exact_pairing_credentials() {
        let sid = URL_SAFE_NO_PAD.encode([1_u8; 16]);
        let cap = URL_SAFE_NO_PAD.encode([2_u8; 32]);
        let (session, capability) = credentials(Some(&format!("sid={sid}&cap={cap}"))).unwrap();

        assert_eq!(session, SessionId::from_bytes([1; 16]));
        assert_eq!(capability, Capability::from_bytes([2; 32]));
    }

    #[test]
    fn rejects_ambiguous_pairing_credentials() {
        let sid = URL_SAFE_NO_PAD.encode([1_u8; 16]);
        let cap = URL_SAFE_NO_PAD.encode([2_u8; 32]);

        assert!(credentials(Some(&format!("sid={sid}&sid={sid}&cap={cap}"))).is_none());
        assert!(credentials(Some(&format!("sid={sid}&cap={cap}&extra=1"))).is_none());
    }

    #[test]
    fn origin_clones_share_one_take() {
        let store = PairingStore::default();
        store
            .insert(
                SessionId::from_bytes([1; 16]),
                Capability::from_bytes([2; 32]),
                20,
                10,
            )
            .unwrap();
        let reservation = store
            .reserve(
                SessionId::from_bytes([1; 16]),
                &Capability::from_bytes([2; 32]),
                10,
            )
            .unwrap();
        let origin = UpgradeOrigin::new(reservation);
        let clone = origin.clone();

        assert!(origin.take().is_some());
        assert!(clone.take().is_none());
        assert!(!format!("{clone:?}").contains(&URL_SAFE_NO_PAD.encode([2_u8; 32])));
    }
}
