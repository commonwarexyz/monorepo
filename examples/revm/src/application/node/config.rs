use crate::{
    domain::{BlockCfg, TxCfg},
    PublicKey,
};
use anyhow::Context as _;
use commonware_consensus::simplex::scheme::bls12381_threshold::vrf;
use commonware_cryptography::{
    bls12381::{
        dkg,
        primitives::{sharing::Mode, variant::MinSig},
    },
    ed25519, Signer as _,
};
use commonware_p2p::simulated;
use commonware_runtime::{buffer::paged::CacheRef, tokio};
use commonware_utils::{ordered::Set, N3f1, NZUsize, TryCollect as _, NZU16, NZU32};
use governor::Quota;
use rand::{rngs::StdRng, SeedableRng as _};

pub(crate) type ThresholdScheme = vrf::Scheme<PublicKey, MinSig>;

/// Namespace used by simplex votes in this example.
pub(crate) const SIMPLEX_NAMESPACE: &[u8] = b"_COMMONWARE_REVM_SIMPLEX";

/// Mailbox depth for each simulated transport channel.
pub(crate) const MAILBOX_SIZE: usize = 1024;
/// Channel id used for voting traffic.
pub(crate) const CHANNEL_VOTES: u64 = 0;
/// Channel id used for certificate gossip delivery.
pub(crate) const CHANNEL_CERTS: u64 = 1;
/// Channel id used for resolver/backfill requests.
pub(crate) const CHANNEL_RESOLVER: u64 = 2;
/// Channel id used for full block broadcast traffic.
pub(crate) const CHANNEL_BLOCKS: u64 = 3;
// Marshal backfill requests/responses use a resolver protocol and are kept separate from the
// best-effort broadcast channel used for full blocks.
/// Channel id used for marshal backfill replies.
pub(crate) const CHANNEL_BACKFILL: u64 = 4;
/// Maximum transactions per block encoded by the REVM codec.
const BLOCK_CODEC_MAX_TXS: usize = 64;
/// Maximum calldata bytes per transaction admitted by the block codec.
const BLOCK_CODEC_MAX_CALLDATA: usize = 1024;

pub(crate) type Peer = PublicKey;
pub(crate) type ChannelSender = simulated::Sender<Peer, tokio::Context>;
pub(crate) type ChannelReceiver = simulated::Receiver<Peer>;

// This example keeps everything in a single epoch for simplicity. The `Marshaled` wrapper also
// supports epoch boundaries, but exercising that logic is out-of-scope for this demo.
pub(crate) const EPOCH_LENGTH: u64 = u64::MAX;
/// Partition prefix used for node-local storage.
pub(crate) const PARTITION_PREFIX: &str = "revm";

/// Default rate limit applied to simulated transport channels.
pub(crate) const fn default_quota() -> Quota {
    Quota::per_second(NZU32!(1_000))
}

/// Default page cache used by node-local storage.
pub(crate) fn default_page_cache() -> CacheRef {
    CacheRef::new(NZU16!(16_384), NZUsize!(10_000))
}

/// Default block codec configuration for REVM transactions.
pub(crate) const fn block_codec_cfg() -> BlockCfg {
    BlockCfg {
        max_txs: BLOCK_CODEC_MAX_TXS,
        tx: TxCfg {
            max_calldata_bytes: BLOCK_CODEC_MAX_CALLDATA,
        },
    }
}

/// Derive deterministic participants and threshold-simplex signing schemes.
pub(crate) fn threshold_schemes(
    seed: u64,
    n: usize,
) -> anyhow::Result<(Vec<PublicKey>, Vec<ThresholdScheme>)> {
    let participants: Set<PublicKey> = (0..n)
        .map(|i| ed25519::PrivateKey::from_seed(seed.wrapping_add(i as u64)).public_key())
        .try_collect()
        .expect("participant public keys are unique");

    let mut rng = StdRng::seed_from_u64(seed);
    let (output, shares) =
        dkg::deal::<MinSig, _, N3f1>(&mut rng, Mode::default(), participants.clone())
            .context("dkg deal failed")?;

    let mut schemes = Vec::with_capacity(n);
    for pk in participants.iter() {
        let share = shares.get_value(pk).expect("share exists").clone();
        let scheme = vrf::Scheme::signer(
            SIMPLEX_NAMESPACE,
            participants.clone(),
            output.public().clone(),
            share,
        )
        .context("signer should exist")?;
        schemes.push(scheme);
    }

    Ok((participants.into(), schemes))
}
