//! JSON node and network configuration shared by all subcommands.

use commonware_codec::{DecodeExt as _, Encode};
use commonware_cryptography::{
    Signer,
    ed25519::{PrivateKey, PublicKey},
};
use commonware_formatting::{from_hex, hex};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use std::{
    ffi::OsString,
    fs::{self, File},
    io::Write as _,
    net::SocketAddr,
    path::{Path, PathBuf},
};

/// Per-node config stored in `node.json`: signer and listen/dial addresses.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeConfig {
    #[serde(with = "hex_private_key")]
    pub signer: PrivateKey,
    pub listen: SocketAddr,
    pub dial: SocketAddr,
}

impl NodeConfig {
    /// Read the node config from `node.json` in `node_dir`.
    pub fn load(node_dir: &Path) -> anyhow::Result<Self> {
        read_json(&node_dir.join("node.json"))
    }

    /// Public key of the node's signer.
    pub fn public_key(&self) -> PublicKey {
        self.signer.public_key()
    }

    /// Node config with listen and dial both on localhost at `port`.
    #[cfg(test)]
    pub const fn localhost(signer: PrivateKey, port: u16) -> Self {
        use std::net::{IpAddr, Ipv4Addr};

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        Self {
            signer,
            listen: addr,
            dial: addr,
        }
    }
}

/// Shared network config stored in `network.json`: ordered participants,
/// committee size, and peer dial addresses.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkConfig {
    #[serde(with = "hex_public_keys")]
    pub participants: Vec<PublicKey>,
    pub committee_size: usize,
    pub peers: Vec<PeerConfig>,
}

impl NetworkConfig {
    /// Read the network config from `network.json` in `node_dir`.
    pub fn load(node_dir: &Path) -> anyhow::Result<Self> {
        read_json(&node_dir.join("network.json"))
    }

    /// Check participant and committee size invariants.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.participants.is_empty() {
            anyhow::bail!("participants must not be empty");
        }
        if self.committee_size == 0 {
            anyhow::bail!("committee size must not be zero");
        }
        if self.committee_size > self.participants.len() {
            anyhow::bail!("committee size exceeds participant count");
        }
        Ok(())
    }

    /// Dial addresses for every peer except `local`.
    pub fn bootstrappers(&self, local: &PublicKey) -> Vec<(PublicKey, commonware_p2p::Ingress)> {
        self.peers
            .iter()
            .filter(|peer| &peer.public_key != local)
            .map(|peer| (peer.public_key.clone(), peer.dial.into()))
            .collect()
    }
}

/// Dial address for one participant.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerConfig {
    #[serde(with = "hex_public_key")]
    pub public_key: PublicKey,
    pub dial: SocketAddr,
}

/// Read a JSON value from `path`.
pub fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> anyhow::Result<T> {
    let contents = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&contents)?)
}

/// Write `value` to `path` as pretty-printed JSON, atomically and durably (see [`persist`]).
pub fn write_json<T: Serialize>(path: &Path, value: &T) -> anyhow::Result<()> {
    let contents = serde_json::to_string_pretty(value)?;
    persist(path, contents.as_bytes())
}

/// Path of the sibling file that [`persist`] stages `path`'s new contents in.
///
/// The name carries the process id, so processes writing the same `path` never
/// share a staged file.
pub fn staged(path: &Path) -> PathBuf {
    let mut staged = OsString::from(path.as_os_str());
    staged.push(format!(".{}.tmp", std::process::id()));
    staged.into()
}

/// Replace `path` with `contents` so that a crash leaves either the previous or
/// the new contents, durable once this returns.
///
/// `path`'s parent directory must already exist. The contents are written to
/// [`staged`], synced, and renamed over `path`, and then the parent directory is
/// synced so the rename survives a crash. Callers in one process must not
/// persist the same `path` concurrently.
pub fn persist(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let staged = staged(path);
    let mut file = File::create(&staged)?;

    // Keep the replaced file's permissions, which a rename would otherwise reset.
    if let Ok(metadata) = fs::metadata(path) {
        file.set_permissions(metadata.permissions())?;
    }
    file.write_all(contents)?;
    file.sync_all()?;
    fs::rename(&staged, path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

/// Serde codec for a hex-encoded [`PrivateKey`].
mod hex_private_key {
    use super::*;

    pub fn serialize<S: Serializer>(value: &PrivateKey, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex(&value.encode()))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<PrivateKey, D::Error> {
        let raw = String::deserialize(deserializer)?;
        let bytes = from_hex(&raw).ok_or_else(|| D::Error::custom("invalid hex"))?;
        PrivateKey::decode(bytes).map_err(D::Error::custom)
    }
}

/// Serde codec for a hex-encoded [`PublicKey`].
mod hex_public_key {
    use super::*;

    pub fn serialize<S: Serializer>(value: &PublicKey, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex(&value.encode()))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<PublicKey, D::Error> {
        let raw = String::deserialize(deserializer)?;
        let bytes = from_hex(&raw).ok_or_else(|| D::Error::custom("invalid hex"))?;
        PublicKey::decode(bytes).map_err(D::Error::custom)
    }
}

/// Serde codec for a list of hex-encoded [`PublicKey`]s.
mod hex_public_keys {
    use super::*;

    pub fn serialize<S: Serializer>(value: &[PublicKey], serializer: S) -> Result<S::Ok, S::Error> {
        let values = value
            .iter()
            .map(|key| hex(&key.encode()))
            .collect::<Vec<_>>();
        values.serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<PublicKey>, D::Error> {
        let values = Vec::<String>::deserialize(deserializer)?;
        values
            .into_iter()
            .map(|raw| {
                let bytes = from_hex(&raw).ok_or_else(|| D::Error::custom("invalid hex"))?;
                PublicKey::decode(bytes).map_err(D::Error::custom)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_math::algebra::Random;
    use commonware_utils::test_rng;

    #[test]
    fn config_roundtrip() {
        let mut rng = test_rng();
        let signer = PrivateKey::random(&mut rng);
        let public_key = signer.public_key();
        let node = NodeConfig::localhost(signer, 3000);
        let network = NetworkConfig {
            participants: vec![public_key.clone()],
            committee_size: 1,
            peers: vec![PeerConfig {
                public_key,
                dial: node.dial,
            }],
        };

        let node_encoded = serde_json::to_string(&node).unwrap();
        let node_decoded = serde_json::from_str::<NodeConfig>(&node_encoded).unwrap();
        assert_eq!(node.public_key(), node_decoded.public_key());

        let network_encoded = serde_json::to_string(&network).unwrap();
        let network_decoded = serde_json::from_str::<NetworkConfig>(&network_encoded).unwrap();
        assert_eq!(network.participants, network_decoded.participants);
        assert_eq!(network.committee_size, network_decoded.committee_size);
    }
}
