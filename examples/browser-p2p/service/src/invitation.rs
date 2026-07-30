use crate::PairingInvite;
#[cfg(test)]
use crate::{Capability, SessionId};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

/// Pairing payload understood by the browser frontend and WASM bridge.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PairingPayload {
    /// Payload format version.
    pub version: u8,
    /// Ephemeral desktop Ed25519 public key as lowercase hex.
    pub desktop_public_key: String,
    /// WebSocket endpoint without bearer credentials.
    pub websocket_url: String,
    /// One-time 256-bit bearer capability as unpadded base64url.
    pub capability: String,
    /// Pairing session identifier as unpadded base64url.
    pub session_id: String,
    /// Unix-seconds expiry.
    pub expires_at: u64,
}

impl PairingPayload {
    /// Construct the canonical version-one payload.
    pub fn new(desktop_public_key: &[u8], websocket_url: String, invite: &PairingInvite) -> Self {
        Self {
            version: 1,
            desktop_public_key: encode_hex(desktop_public_key),
            websocket_url,
            capability: invite
                .capability()
                .expose(|value| URL_SAFE_NO_PAD.encode(value)),
            session_id: URL_SAFE_NO_PAD.encode(invite.session_id().as_bytes()),
            expires_at: invite.expires_at(),
        }
    }

    /// Serialize compact canonical JSON.
    pub fn compact_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Serialize JSON and encode it as unpadded base64url.
    pub fn encoded(&self) -> Result<String, serde_json::Error> {
        Ok(URL_SAFE_NO_PAD.encode(self.compact_json()?))
    }
}

#[cfg(test)]
fn decode_session(value: &str) -> Option<SessionId> {
    let bytes: [u8; 16] = URL_SAFE_NO_PAD.decode(value).ok()?.try_into().ok()?;
    Some(SessionId::from_bytes(bytes))
}

#[cfg(test)]
fn decode_capability(value: &str) -> Option<Capability> {
    let bytes: [u8; 32] = URL_SAFE_NO_PAD.decode(value).ok()?.try_into().ok()?;
    Some(Capability::from_bytes(bytes))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PairingStore;

    #[test]
    fn payload_matches_browser_contract() {
        let store = PairingStore::default();
        let invite = store.create(1_900_000_060, 1_900_000_000).unwrap();
        let payload = PairingPayload::new(
            &[0xab; 32],
            "ws://192.168.1.20:41000/pair".to_string(),
            &invite,
        );
        let json = payload.compact_json().unwrap();
        let decoded: PairingPayload = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded, payload);
        assert_eq!(payload.version, 1);
        assert_eq!(payload.desktop_public_key, "ab".repeat(32));
        assert_eq!(payload.capability.len(), 43);
        assert_eq!(payload.session_id.len(), 22);
        assert_eq!(
            decode_session(&payload.session_id),
            Some(invite.session_id())
        );
        assert_eq!(
            decode_capability(&payload.capability),
            Some(invite.capability().clone())
        );
    }
}
