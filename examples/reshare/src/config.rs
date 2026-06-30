use commonware_codec::{DecodeExt as _, Encode};
use commonware_cryptography::{
    ed25519::{PrivateKey, PublicKey},
    Signer,
};
use commonware_formatting::{from_hex, hex};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use std::{fs, net::SocketAddr, path::Path};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeConfig {
    #[serde(with = "hex_private_key")]
    pub signing_key: PrivateKey,
    pub listen: SocketAddr,
    pub dial: SocketAddr,
}

impl NodeConfig {
    pub fn load(node_dir: &Path) -> anyhow::Result<Self> {
        read_json(&node_dir.join("node.json"))
    }

    pub fn public_key(&self) -> PublicKey {
        self.signing_key.public_key()
    }

    #[cfg(test)]
    pub const fn localhost(signing_key: PrivateKey, port: u16) -> Self {
        use std::net::{IpAddr, Ipv4Addr};

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        Self {
            signing_key,
            listen: addr,
            dial: addr,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkConfig {
    #[serde(with = "hex_public_keys")]
    pub participants: Vec<PublicKey>,
    pub committee_size: usize,
    pub peers: Vec<PeerConfig>,
}

impl NetworkConfig {
    pub fn load(node_dir: &Path) -> anyhow::Result<Self> {
        read_json(&node_dir.join("network.json"))
    }

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

    pub fn bootstrappers(&self, local: &PublicKey) -> Vec<(PublicKey, commonware_p2p::Ingress)> {
        self.peers
            .iter()
            .filter(|peer| &peer.public_key != local)
            .map(|peer| (peer.public_key.clone(), peer.dial.into()))
            .collect()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerConfig {
    #[serde(with = "hex_public_key")]
    pub public_key: PublicKey,
    pub dial: SocketAddr,
}

pub fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> anyhow::Result<T> {
    let contents = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&contents)?)
}

pub fn write_json<T: Serialize>(path: &Path, value: &T) -> anyhow::Result<()> {
    let contents = serde_json::to_string_pretty(value)?;
    fs::write(path, contents)?;
    Ok(())
}

mod hex_private_key {
    use super::*;

    pub fn serialize<S: Serializer>(value: &PrivateKey, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex(&value.encode()))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<PrivateKey, D::Error> {
        let raw = String::deserialize(deserializer)?;
        let bytes = from_hex(&raw).ok_or_else(|| D::Error::custom("invalid hex"))?;
        PrivateKey::decode(bytes.as_slice()).map_err(D::Error::custom)
    }
}

mod hex_public_key {
    use super::*;

    pub fn serialize<S: Serializer>(value: &PublicKey, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex(&value.encode()))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<PublicKey, D::Error> {
        let raw = String::deserialize(deserializer)?;
        let bytes = from_hex(&raw).ok_or_else(|| D::Error::custom("invalid hex"))?;
        PublicKey::decode(bytes.as_slice()).map_err(D::Error::custom)
    }
}

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
                PublicKey::decode(bytes.as_slice()).map_err(D::Error::custom)
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
