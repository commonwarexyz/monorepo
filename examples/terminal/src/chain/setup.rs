//! `setup` subcommand: generate validator directories for the settlement
//! chain.
//!
//! Setup writes one directory per validator holding `node.json` (signing key,
//! addresses, the validator's consensus threshold share, and its dealt
//! clearing committee key), the shared `network.json` (participants, dial
//! addresses, and the operators' network identities), and the shared
//! `genesis.json` (the trusted-dealer threshold output plus the deployment
//! list). The committee is fixed for the life of the chain: this is the
//! reshare example's trusted-bootstrap path without continuous resharing,
//! which remains a drop-in replacement (swap the fixed scheme provider for
//! the reshare orchestrator and dkg actors).
//!
//! Setup also writes one node directory per operator (`operator-0/`,
//! `operator-1/`, ...): its own `node.json` with a fresh ed25519 NETWORK key
//! and its curve25519 CLEARING key, plus the shared network and genesis
//! files. The network key authenticates the operator as a p2p secondary,
//! while the clearing key is the payment-signing identity whose digest names
//! the deployment the operator runs. Genesis carries one deployment per
//! operator, in operator order, each opening with the compiled demo account
//! set, and one chain-wide epoch timing policy applied to every deployment.
//!
//! The clearing committee is the same machines as the consensus committee
//! under separate key material: each validator's consensus identity is its
//! dealt threshold share, while its clearing identity is the fixed seeded
//! BLS key setup distributes as `clearing` (key `i` to directory `i`).

use crate::{
    chain::validator::{MAX_PARTICIPANTS, MAX_SUPPORTED_MODE, SHARING_MODE},
    protocol::{
        Account, Deployment, Key, Timing, accounts, clearing_private, committee, operator_signer,
    },
};
use anyhow::Context as _;
use clap::Args;
use commonware_codec::{Decode as _, Encode as _};
use commonware_cryptography::{
    Signer as _,
    bls12381::{
        dkg::feldman_desmedt::{Output, deal},
        primitives::{
            group::{Private as ClearingKey, Share},
            sharing::Sharing,
            variant::MinSig,
        },
    },
    ed25519::{PrivateKey, PublicKey},
};
use commonware_cryptography_curve25519::signing::SigningKey as ClearingSigner;
use commonware_formatting::{from_hex, hex};
use commonware_math::algebra::Random as _;
use commonware_utils::{N3f1, ordered::Set};
use rand::rngs::StdRng;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
};

/// The trusted-dealer threshold output shared by every validator.
pub(crate) type Identity = Output<MinSig, PublicKey>;

/// The shared chain genesis: the trusted-dealer threshold identity, the
/// chain-fixed metadata setup chooses once, and the configured deployment
/// list, stored together in `genesis.json`.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Genesis {
    /// The committee threshold identity every certified read verifies against.
    identity: Identity,
    /// Chain creation time in milliseconds since the Unix epoch.
    ///
    /// Display/recency-grade only: block timestamps descend from it and serve
    /// query recency and display. Block heights remain the only deadline
    /// clock.
    pub(crate) timestamp: u64,
    /// Maximum blocks from a registration's inclusion height to its admission
    /// deadline.
    ///
    /// Genesis-fixed with `challenge_duration`, one chain-wide policy applied
    /// to every deployment: a per-epoch or per-operator choice would let an
    /// operator squeeze the enforcement window shut. Forced withdrawal
    /// remains the escape from a badly configured chain, not a substitute
    /// for a sane window.
    pub(crate) admission_offset: u64,
    /// Exact blocks between a registration's admission deadline and its
    /// challenge deadline (the same genesis-fixed rule).
    pub(crate) challenge_duration: u64,
    /// The configured deployments sharing this chain: each an operator
    /// clearing identity plus the accounts and initial balances its genesis
    /// machine opens with.
    pub(crate) deployments: Vec<Deployment>,
}

impl Genesis {
    pub(crate) const fn new(
        identity: Identity,
        timestamp: u64,
        timing: Timing,
        deployments: Vec<Deployment>,
    ) -> Self {
        Self {
            identity,
            timestamp,
            admission_offset: timing.admission_offset,
            challenge_duration: timing.challenge_duration,
            deployments,
        }
    }

    /// The committee players holding dealt shares.
    pub(crate) const fn players(&self) -> &Set<PublicKey> {
        self.identity.players()
    }

    /// The committee's threshold public sharing.
    pub(crate) const fn public(&self) -> &Sharing<MinSig> {
        self.identity.public()
    }

    /// The chain-wide epoch timing policy applied to every deployment.
    pub(crate) const fn timing(&self) -> Timing {
        Timing {
            admission_offset: self.admission_offset,
            challenge_duration: self.challenge_duration,
        }
    }
}

/// Per-node config stored in `node.json`.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct NodeConfig {
    #[serde(with = "hex_private_key")]
    pub(crate) signing_key: PrivateKey,
    pub(crate) listen: SocketAddr,
    pub(crate) dial: SocketAddr,
    /// Query server listen address.
    pub(crate) query: SocketAddr,
    /// Threshold share for the fixed committee.
    #[serde(with = "hex_share")]
    pub(crate) share: Share,
    /// Dealt clearing committee BLS key: the validator's sealing identity,
    /// separate material from the consensus threshold share above.
    #[serde(with = "hex_clearing")]
    pub(crate) clearing: ClearingKey,
}

impl NodeConfig {
    pub(crate) fn load(node_dir: &Path) -> anyhow::Result<Self> {
        read_json(&node_dir.join("node.json"))
    }

    pub(crate) fn public_key(&self) -> PublicKey {
        self.signing_key.public_key()
    }
}

/// One operator node's config stored in `operator-<index>/node.json`: its
/// ed25519 network identity and addresses plus its curve25519 clearing key.
/// The network key authenticates the operator as a p2p secondary, while the
/// clearing key signs payments and registrations and names the deployment
/// the operator runs (the deployment digest derives from it).
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct OperatorConfig {
    #[serde(with = "hex_private_key")]
    pub(crate) signing_key: PrivateKey,
    pub(crate) listen: SocketAddr,
    pub(crate) dial: SocketAddr,
    /// The operator's clearing signing key (a demo protocol constant).
    #[serde(with = "hex_clearing_signer")]
    pub(crate) clearing: ClearingSigner,
}

impl OperatorConfig {
    pub(crate) fn load(node_dir: &Path) -> anyhow::Result<Self> {
        read_json(&node_dir.join("node.json"))
    }

    pub(crate) fn public_key(&self) -> PublicKey {
        self.signing_key.public_key()
    }
}

/// Shared network config stored in `network.json`.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct NetworkConfig {
    #[serde(with = "hex_public_keys")]
    pub(crate) participants: Vec<PublicKey>,
    pub(crate) peers: Vec<PeerConfig>,
    /// The operators' network identities, in the same order as the genesis
    /// deployment list (operator `i` runs deployment `i`): every validator's
    /// extra bootstrappers and tracked secondaries.
    pub(crate) operators: Vec<PeerConfig>,
}

impl NetworkConfig {
    pub(crate) fn load(node_dir: &Path) -> anyhow::Result<Self> {
        read_json(&node_dir.join("network.json"))
    }

    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        if self.participants.is_empty() {
            anyhow::bail!("participants must not be empty");
        }
        if self.participants.len() != self.peers.len() {
            anyhow::bail!("every participant needs a dial address");
        }
        if self.operators.is_empty() {
            anyhow::bail!("at least one operator is required");
        }
        let mut operators = std::collections::BTreeSet::new();
        for operator in &self.operators {
            if self
                .participants
                .iter()
                .any(|participant| participant == &operator.public_key)
            {
                anyhow::bail!("an operator network identity must not be a participant");
            }
            if !operators.insert(operator.public_key.clone()) {
                anyhow::bail!("operator network identities must be distinct");
            }
        }
        Ok(())
    }

    /// Dial addresses for every peer except `local`.
    pub(crate) fn bootstrappers(
        &self,
        local: &PublicKey,
    ) -> Vec<(PublicKey, commonware_p2p::Ingress)> {
        self.peers
            .iter()
            .filter(|peer| &peer.public_key != local)
            .map(|peer| (peer.public_key.clone(), peer.dial.into()))
            .collect()
    }
}

/// Dial address for one participant.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct PeerConfig {
    #[serde(with = "hex_public_key")]
    pub(crate) public_key: PublicKey,
    pub(crate) dial: SocketAddr,
}

#[derive(Serialize, Deserialize)]
struct EncodedGenesis {
    #[serde(with = "hex_genesis")]
    output: Identity,
    /// Chain creation time in milliseconds since the Unix epoch
    /// (display/recency-grade only).
    timestamp: u64,
    /// Genesis-fixed maximum blocks from registration inclusion to the
    /// admission deadline, applied to every deployment.
    admission_offset: u64,
    /// Genesis-fixed exact challenge window duration in blocks, applied to
    /// every deployment.
    challenge_duration: u64,
    /// The configured deployments sharing this chain, in operator order.
    deployments: Vec<EncodedDeployment>,
}

/// One configured deployment in `genesis.json`.
#[derive(Serialize, Deserialize)]
struct EncodedDeployment {
    /// Hex curve25519 operator clearing public key.
    #[serde(with = "hex_clearing_public")]
    operator: Key,
    /// The accounts and initial balances the deployment's genesis machine
    /// opens with.
    accounts: Vec<EncodedAccount>,
}

/// One configured account in `genesis.json`.
#[derive(Serialize, Deserialize)]
struct EncodedAccount {
    #[serde(with = "hex_clearing_public")]
    key: Key,
    balance: u64,
}

impl From<&Deployment> for EncodedDeployment {
    fn from(deployment: &Deployment) -> Self {
        Self {
            operator: deployment.operator.clone(),
            accounts: deployment
                .accounts
                .iter()
                .map(|account| EncodedAccount {
                    key: account.key.clone(),
                    balance: account.balance,
                })
                .collect(),
        }
    }
}

impl From<EncodedDeployment> for Deployment {
    fn from(encoded: EncodedDeployment) -> Self {
        Self::new(
            encoded.operator,
            encoded
                .accounts
                .into_iter()
                .map(|account| Account {
                    key: account.key,
                    balance: account.balance,
                })
                .collect(),
        )
    }
}

/// Reads the shared chain genesis from `node_dir`.
pub(crate) fn read_genesis(node_dir: &Path) -> anyhow::Result<Genesis> {
    read_genesis_file(&node_dir.join("genesis.json"))
}

/// Reads a chain genesis from an exact file path (the wallet and operator
/// clients take the file directly).
pub(crate) fn read_genesis_file(path: &Path) -> anyhow::Result<Genesis> {
    let encoded = read_json::<EncodedGenesis>(path)?;
    anyhow::ensure!(
        encoded.admission_offset >= 1,
        "the genesis admission offset must be at least one block"
    );
    anyhow::ensure!(
        encoded.challenge_duration >= 1,
        "the genesis challenge duration must be at least one block"
    );
    anyhow::ensure!(
        !encoded.deployments.is_empty(),
        "the genesis must configure at least one deployment"
    );
    let deployments = encoded
        .deployments
        .into_iter()
        .map(Deployment::from)
        .collect::<Vec<_>>();
    let mut digests = std::collections::BTreeSet::new();
    for deployment in &deployments {
        anyhow::ensure!(
            !deployment.accounts.is_empty(),
            "every genesis deployment must configure at least one account"
        );
        let mut keys = std::collections::BTreeSet::new();
        anyhow::ensure!(
            deployment
                .accounts
                .iter()
                .all(|account| keys.insert(account.key.clone())),
            "a genesis deployment configures a duplicate account"
        );
        anyhow::ensure!(
            digests.insert(*deployment.digest()),
            "genesis deployment operators must be distinct"
        );
    }
    Ok(Genesis::new(
        encoded.output,
        encoded.timestamp,
        Timing {
            admission_offset: encoded.admission_offset,
            challenge_duration: encoded.challenge_duration,
        },
        deployments,
    ))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> anyhow::Result<T> {
    let contents = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&contents)?)
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> anyhow::Result<()> {
    let contents = serde_json::to_string_pretty(value)?;
    fs::write(path, contents)?;
    Ok(())
}

/// Generate every validator directory with node, network, and genesis config.
#[derive(Args)]
pub struct Setup {
    /// Directory where validator subdirectories will be generated.
    #[arg(long, default_value = "./data")]
    pub node_dir: PathBuf,

    /// Total number of validators to generate (all form the fixed committee).
    #[arg(long, default_value_t = 4)]
    pub(crate) peers: usize,

    /// First local P2P port assigned to validator-0.
    #[arg(long, default_value_t = 3000)]
    pub(crate) base_port: u16,

    /// First local query server port assigned to validator-0.
    #[arg(long, default_value_t = 3200)]
    pub(crate) base_query_port: u16,

    /// Number of operators (one deployment each) to generate.
    #[arg(long, default_value_t = 2)]
    pub(crate) operators: usize,

    /// First local P2P port assigned to operator-0.
    #[arg(long, default_value_t = 3400)]
    pub(crate) operator_port: u16,

    /// IP address used for generated listen and dial addresses.
    #[arg(long, default_value_t = IpAddr::V4(Ipv4Addr::LOCALHOST))]
    pub(crate) host: IpAddr,
}

/// Generate the validator directories and print the commands to run next.
pub fn run(args: Setup) {
    run_inner(args).expect("setup failed");
}

fn run_inner(args: Setup) -> anyhow::Result<()> {
    validate(&args)?;
    if args.node_dir.exists() && args.node_dir.read_dir()?.next().is_some() {
        anyhow::bail!(
            "refusing to write into non-empty directory: {}",
            args.node_dir.display()
        );
    }
    fs::create_dir_all(&args.node_dir)?;

    let mut rng = rand::make_rng::<StdRng>();
    let signers = (0..args.peers)
        .map(|_| PrivateKey::random(&mut rng))
        .collect::<Vec<_>>();

    // One fresh network identity, one clearing identity, and therefore one
    // deployment per operator. Operator `index` runs deployment `index` in
    // both the network config and the genesis deployment list.
    let operator_signers = (0..args.operators)
        .map(|_| PrivateKey::random(&mut rng))
        .collect::<Vec<_>>();
    let operator_addresses = (0..args.operators)
        .map(|index| Ok(SocketAddr::new(args.host, port(args.operator_port, index)?)))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let deployments = (0..args.operators)
        .map(|index| {
            let index = u64::try_from(index).expect("the operator count fits u64");
            Deployment::new(operator_signer(index).public_key(), accounts())
        })
        .collect::<Vec<_>>();
    let peers = signers
        .iter()
        .enumerate()
        .map(|(index, signer)| {
            Ok(PeerConfig {
                public_key: signer.public_key(),
                dial: SocketAddr::new(args.host, port(args.base_port, index)?),
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let network = NetworkConfig {
        participants: signers.iter().map(|signer| signer.public_key()).collect(),
        peers,
        operators: operator_signers
            .iter()
            .zip(&operator_addresses)
            .map(|(signer, address)| PeerConfig {
                public_key: signer.public_key(),
                dial: *address,
            })
            .collect(),
    };

    // The fixed committee is every participant, dealt once by setup.
    let players = Set::from_iter_dedup(network.participants.iter().cloned());
    let (output, shares) = deal::<MinSig, _, N3f1>(&mut rng, SHARING_MODE, players)?;

    // The chain metadata fixed at creation: the display/recency-grade
    // creation timestamp, the epoch timing policy populated from the
    // compiled defaults (see [`Timing::DEFAULT`]) and applied to every
    // deployment, and the deployment list itself.
    let timestamp = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("the system clock is before the Unix epoch")?
            .as_millis(),
    )
    .context("the system clock exceeds u64 milliseconds")?;
    let encoded = |output: Identity| EncodedGenesis {
        output,
        timestamp,
        admission_offset: Timing::DEFAULT.admission_offset,
        challenge_duration: Timing::DEFAULT.challenge_duration,
        deployments: deployments.iter().map(EncodedDeployment::from).collect(),
    };

    for (index, signer) in signers.into_iter().enumerate() {
        let node_dir = args.node_dir.join(format!("validator-{index}"));
        fs::create_dir_all(&node_dir)?;
        let public_key = signer.public_key();
        let share = shares
            .get_value(&public_key)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("dealer omitted a participant share"))?;
        let address = SocketAddr::new(args.host, port(args.base_port, index)?);
        let node = NodeConfig {
            signing_key: signer,
            listen: address,
            dial: address,
            query: SocketAddr::new(args.host, port(args.base_query_port, index)?),
            share,
            clearing: clearing_private(index)?,
        };
        write_json(&node_dir.join("node.json"), &node)?;
        write_json(&node_dir.join("network.json"), &network)?;
        write_json(&node_dir.join("genesis.json"), &encoded(output.clone()))?;
    }

    // Each operator's node directory: its fresh network identity and its
    // clearing key, plus the shared network and genesis files.
    for (index, signer) in operator_signers.into_iter().enumerate() {
        let operator_dir = args.node_dir.join(format!("operator-{index}"));
        fs::create_dir_all(&operator_dir)?;
        let clearing = operator_signer(u64::try_from(index).expect("operator index fits u64"));
        write_json(
            &operator_dir.join("node.json"),
            &OperatorConfig {
                signing_key: signer,
                listen: operator_addresses[index],
                dial: operator_addresses[index],
                clearing,
            },
        )?;
        write_json(&operator_dir.join("network.json"), &network)?;
        write_json(&operator_dir.join("genesis.json"), &encoded(output.clone()))?;
    }

    println!("Run the cluster with:");
    println!(
        "mprocs {}",
        (0..args.peers)
            .map(|index| {
                format!(
                    "\"cargo run --bin terminal-chain -- validator --node-dir {}\"",
                    args.node_dir.join(format!("validator-{index}")).display()
                )
            })
            .collect::<Vec<_>>()
            .join(" ")
    );
    for index in 0..args.operators {
        println!(
            "Run operator {index} with: --node-dir {}",
            args.node_dir.join(format!("operator-{index}")).display()
        );
    }

    // The wallet agents verify certified reads against the shared genesis
    // identity and query the validators' certified query servers, each bound
    // to one operator's deployment.
    let queries = (0..args.peers)
        .map(|index| {
            port(args.base_query_port, index)
                .map(|port| format!("--query {}", SocketAddr::new(args.host, port)))
        })
        .collect::<anyhow::Result<Vec<_>>>()?
        .join(" ");
    let genesis = args.node_dir.join("validator-0").join("genesis.json");
    println!(
        "Point the agents at the chain with: --genesis {} {queries} --deployment <operator index>",
        genesis.display()
    );
    Ok(())
}

fn validate(args: &Setup) -> anyhow::Result<()> {
    // Every validator holds one dealt clearing committee key, so the
    // consensus committee must be exactly the clearing committee.
    let clearing = committee()
        .map_err(|error| anyhow::anyhow!("clearing committee is unavailable: {error:#}"))?
        .members()
        .len();
    if args.peers != clearing {
        anyhow::bail!("peers must equal the clearing committee size ({clearing})");
    }
    if args.peers > MAX_PARTICIPANTS.get() as usize {
        anyhow::bail!("peers exceeds max supported participants");
    }
    if args.operators == 0 {
        anyhow::bail!("at least one operator is required");
    }
    port(args.base_port, args.peers - 1)?;
    port(args.base_query_port, args.peers - 1)?;
    port(args.operator_port, args.operators - 1)?;
    Ok(())
}

fn port(base: u16, index: usize) -> anyhow::Result<u16> {
    let offset = u16::try_from(index)?;
    base.checked_add(offset)
        .ok_or_else(|| anyhow::anyhow!("base port plus peer index overflows u16"))
}

/// Serde codec for a hex-encoded [`PrivateKey`].
mod hex_private_key {
    use super::*;

    pub(crate) fn serialize<S: Serializer>(
        value: &PrivateKey,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex(&value.encode()))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<PrivateKey, D::Error> {
        let raw = String::deserialize(deserializer)?;
        let bytes = from_hex(&raw).ok_or_else(|| D::Error::custom("invalid hex"))?;
        PrivateKey::decode_cfg(bytes.as_slice(), &()).map_err(D::Error::custom)
    }
}

/// Serde codec for a hex-encoded [`PublicKey`].
mod hex_public_key {
    use super::*;

    pub(crate) fn serialize<S: Serializer>(
        value: &PublicKey,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex(&value.encode()))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<PublicKey, D::Error> {
        let raw = String::deserialize(deserializer)?;
        let bytes = from_hex(&raw).ok_or_else(|| D::Error::custom("invalid hex"))?;
        PublicKey::decode_cfg(bytes.as_slice(), &()).map_err(D::Error::custom)
    }
}

/// Serde codec for a list of hex-encoded [`PublicKey`]s.
mod hex_public_keys {
    use super::*;

    pub(crate) fn serialize<S: Serializer>(
        value: &[PublicKey],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value
            .iter()
            .map(|key| hex(&key.encode()))
            .collect::<Vec<_>>()
            .serialize(serializer)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<PublicKey>, D::Error> {
        Vec::<String>::deserialize(deserializer)?
            .into_iter()
            .map(|raw| {
                let bytes = from_hex(&raw).ok_or_else(|| D::Error::custom("invalid hex"))?;
                PublicKey::decode_cfg(bytes.as_slice(), &()).map_err(D::Error::custom)
            })
            .collect()
    }
}

/// Serde codec for a hex-encoded [`Share`].
mod hex_share {
    use super::*;

    pub(crate) fn serialize<S: Serializer>(
        value: &Share,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex(&value.encode()))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Share, D::Error> {
        let raw = String::deserialize(deserializer)?;
        let bytes = from_hex(&raw).ok_or_else(|| D::Error::custom("invalid hex"))?;
        Share::decode_cfg(bytes.as_slice(), &()).map_err(D::Error::custom)
    }
}

/// Serde codec for a hex-encoded clearing committee key.
mod hex_clearing {
    use super::*;

    pub(crate) fn serialize<S: Serializer>(
        value: &ClearingKey,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex(&value.encode()))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<ClearingKey, D::Error> {
        let raw = String::deserialize(deserializer)?;
        let bytes = from_hex(&raw).ok_or_else(|| D::Error::custom("invalid hex"))?;
        ClearingKey::decode_cfg(bytes.as_slice(), &()).map_err(D::Error::custom)
    }
}

/// Serde codec for a hex-encoded curve25519 clearing signing key.
mod hex_clearing_signer {
    use super::*;

    pub(crate) fn serialize<S: Serializer>(
        value: &ClearingSigner,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex(&value.encode()))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<ClearingSigner, D::Error> {
        let raw = String::deserialize(deserializer)?;
        let bytes = from_hex(&raw).ok_or_else(|| D::Error::custom("invalid hex"))?;
        ClearingSigner::decode_cfg(bytes.as_slice(), &()).map_err(D::Error::custom)
    }
}

/// Serde codec for a hex-encoded curve25519 clearing public key.
mod hex_clearing_public {
    use super::*;

    pub(crate) fn serialize<S: Serializer>(value: &Key, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex(&value.encode()))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Key, D::Error> {
        let raw = String::deserialize(deserializer)?;
        let bytes = from_hex(&raw).ok_or_else(|| D::Error::custom("invalid hex"))?;
        Key::decode_cfg(bytes.as_slice(), &()).map_err(D::Error::custom)
    }
}

/// Serde codec for the hex-encoded threshold [`Identity`].
mod hex_genesis {
    use super::*;

    pub(crate) fn serialize<S: Serializer>(
        value: &Identity,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex(&value.encode()))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Identity, D::Error> {
        let raw = String::deserialize(deserializer)?;
        let bytes = from_hex(&raw).ok_or_else(|| D::Error::custom("invalid hex"))?;
        Identity::decode_cfg(bytes.as_slice(), &(MAX_PARTICIPANTS, MAX_SUPPORTED_MODE))
            .map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::bls12381::primitives::ops::compute_public;

    #[test]
    fn setup_writes_node_network_operator_and_genesis() {
        let node_dir =
            std::env::temp_dir().join(format!("terminal-chain-setup-{}", std::process::id()));
        let _ = fs::remove_dir_all(&node_dir);
        run_inner(Setup {
            node_dir: node_dir.clone(),
            peers: 4,
            base_port: 4300,
            base_query_port: 4400,
            operators: 2,
            operator_port: 4500,
            host: IpAddr::V4(Ipv4Addr::LOCALHOST),
        })
        .unwrap();

        let first = node_dir.join("validator-0");
        let node = NodeConfig::load(&first).unwrap();
        let network = NetworkConfig::load(&first).unwrap();
        network.validate().unwrap();
        assert_eq!(network.participants.len(), 4);
        assert_eq!(node.listen.port(), 4300);
        assert_eq!(node.query.port(), 4400);
        assert_eq!(network.bootstrappers(&node.public_key()).len(), 3);

        // Each operator directory holds its own network identity and its
        // clearing key, listed in the shared network config as the extra
        // bootstrappers in genesis deployment order.
        assert_eq!(network.operators.len(), 2);
        for index in 0..2u16 {
            let operator_dir = node_dir.join(format!("operator-{index}"));
            let operator = OperatorConfig::load(&operator_dir).unwrap();
            assert_eq!(operator.listen.port(), 4500 + index);
            let listed = &network.operators[usize::from(index)];
            assert_eq!(listed.public_key, operator.public_key());
            assert_eq!(listed.dial, operator.dial);
            assert_eq!(
                operator.clearing.public_key(),
                crate::protocol::operator_signer(u64::from(index)).public_key()
            );
            let genesis = read_genesis(&operator_dir).unwrap();
            assert_eq!(genesis.players().len(), 4);
            assert_eq!(
                genesis.deployments[usize::from(index)].operator,
                operator.clearing.public_key()
            );
        }

        // The genesis output covers every participant and matches each
        // node's share, and every validator holds a distinct dealt clearing
        // committee key.
        let clearing = committee().unwrap();
        let genesis = read_genesis(&first).unwrap();
        assert_eq!(genesis.players().len(), 4);

        // The chain metadata is fixed at creation: the epoch timing policy
        // carries the compiled defaults, the creation timestamp is a real
        // wall-clock instant, and every deployment configures the compiled
        // demo accounts under a distinct operator.
        assert_eq!(genesis.timing(), Timing::DEFAULT);
        assert!(genesis.timestamp > 0);
        assert_eq!(genesis.deployments.len(), 2);
        assert_ne!(
            genesis.deployments[0].digest(),
            genesis.deployments[1].digest()
        );
        for deployment in &genesis.deployments {
            assert_eq!(deployment.accounts.len(), accounts().len());
        }
        let mut dealt = Vec::new();
        for index in 0..4 {
            let dir = node_dir.join(format!("validator-{index}"));
            let node = NodeConfig::load(&dir).unwrap();
            assert!(
                genesis
                    .players()
                    .iter()
                    .any(|player| player == &node.public_key())
            );
            assert_eq!(read_genesis(&dir).unwrap(), genesis);
            let public = compute_public::<MinSig>(&node.clearing);
            let participant = clearing
                .index_of(&public)
                .expect("the dealt clearing key is in the committee");
            assert!(!dealt.contains(&participant));
            dealt.push(participant);
        }
        let _ = fs::remove_dir_all(node_dir);
    }

    #[test]
    fn setup_rejects_non_empty_directory() {
        let node_dir = std::env::temp_dir().join(format!(
            "terminal-chain-setup-non-empty-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&node_dir);
        fs::create_dir_all(&node_dir).unwrap();
        fs::write(node_dir.join("sentinel"), b"keep").unwrap();
        assert!(
            run_inner(Setup {
                node_dir: node_dir.clone(),
                peers: 4,
                base_port: 4500,
                base_query_port: 4600,
                operators: 2,
                operator_port: 4700,
                host: IpAddr::V4(Ipv4Addr::LOCALHOST),
            })
            .is_err()
        );
        let _ = fs::remove_dir_all(node_dir);
    }

    #[test]
    fn setup_requires_the_exact_clearing_committee() {
        let node_dir = std::env::temp_dir().join(format!(
            "terminal-chain-setup-committee-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&node_dir);
        let error = run_inner(Setup {
            node_dir: node_dir.clone(),
            peers: 1,
            base_port: 4800,
            base_query_port: 4900,
            operators: 2,
            operator_port: 5000,
            host: IpAddr::V4(Ipv4Addr::LOCALHOST),
        })
        .unwrap_err();
        assert!(format!("{error:#}").contains("clearing committee size"));
        let _ = fs::remove_dir_all(node_dir);
    }
}
