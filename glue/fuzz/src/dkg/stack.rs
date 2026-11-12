//! Construction of one bootstrap engine.

use super::{
    BOOTSTRAP_NAMESPACE, EPOCH_LENGTH, MockGroup, PublicKey, context::EngineContext,
    invariants::Ending, store::Secrets,
};
use crate::stateful::{
    IO_BUFFER_SIZE, MAILBOX_SIZE, PAGE_CACHE_SIZE, PAGE_SIZE, stack::TEST_QUOTA,
};
use commonware_cryptography::{
    Signer as _,
    bls12381::{
        dkg::feldman_desmedt::Reveal,
        primitives::sharing::{Mode, ModeVersion},
    },
    ed25519,
};
use commonware_glue::dkg::bootstrap;
use commonware_p2p::{
    Receiver as ReceiverTrait, Sender as SenderTrait,
    simulated::{Oracle, Receiver, Sender},
};
use commonware_parallel::Sequential;
use commonware_runtime::{Handle, buffer::paged::CacheRef, deterministic};
use commonware_utils::{NZDuration, NZU64, channel::oneshot, ordered::Set, sequence::Unit};
use std::{num::NonZeroU64, time::Duration};

/// Channel identifiers of the bootstrap chain.
const CHANNEL_VOTES: u64 = 0;
const CHANNEL_CERTIFICATES: u64 = 1;
const CHANNEL_RESOLVER: u64 = 2;
const CHANNEL_BACKFILL: u64 = 3;
const CHANNEL_BROADCAST: u64 = 4;
const CHANNEL_DKG: u64 = 5;

/// How long a fetch of an engine waits for a peer, and how long before a
/// fetch is retried.
pub(super) const FETCH_TIMEOUT: Duration = Duration::from_secs(2);
pub(super) const FETCH_RETRY_DELAY: Duration = Duration::from_millis(100);

/// Items per section in a chain's archives.
pub(super) const SECTION_ITEMS: NonZeroU64 = NZU64!(10);

/// The newest sharing mode version, so a block of either mode decodes.
pub(super) const MAX_SUPPORTED_MODE: ModeVersion = ModeVersion::v1();

/// One unsplit channel of an identity.
pub(super) type Endpoint = (
    Sender<PublicKey, deterministic::Context>,
    Receiver<PublicKey>,
);

/// One identity's unsplit channels.
pub(super) struct Channels {
    pub(super) votes: Endpoint,
    pub(super) certificates: Endpoint,
    pub(super) resolver: Endpoint,
    pub(super) backfill: Endpoint,
    pub(super) broadcast: Endpoint,
    pub(super) dkg: Endpoint,
}

/// Register one identity's six channels.
pub(super) async fn register(
    oracle: &Oracle<PublicKey, deterministic::Context>,
    identity: &PublicKey,
) -> Channels {
    let control = oracle.control(identity.clone());
    let register = async |channel| {
        control
            .register(channel, TEST_QUOTA)
            .await
            .expect("channel registration failed")
    };
    Channels {
        votes: register(CHANNEL_VOTES).await,
        certificates: register(CHANNEL_CERTIFICATES).await,
        resolver: register(CHANNEL_RESOLVER).await,
        backfill: register(CHANNEL_BACKFILL).await,
        broadcast: register(CHANNEL_BROADCAST).await,
        dkg: register(CHANNEL_DKG).await,
    }
}

/// What one bootstrap engine runs with.
pub(super) struct Config {
    /// The identity's key.
    pub(super) signer: ed25519::PrivateKey,
    /// The ceremony's participants.
    pub(super) participants: Set<PublicKey>,
    /// Storage partition prefix, distinct per engine.
    pub(super) partition: String,
    /// The engine's secret store.
    pub(super) secrets: Secrets,
    /// How the ceremony assigns evaluation points.
    pub(super) sharing_mode: Mode,
}

/// The completion a bootstrap engine reports.
pub(super) type Completion = bootstrap::Completion<MockGroup>;

/// How the ceremony ended at the engine that reports `completion`.
pub(super) fn ending(completion: Completion) -> Ending {
    completion
        .info
        .map_or(Ending::Failure, |info| Ending::Success(Box::new(info)))
}

/// Start one real bootstrap engine over the given channels.
///
/// The engine is assembled by the task that calls this, which is the
/// driver's: the engine's own tasks run nothing but the DKG module. A panic
/// while the engine is assembled is therefore never taken for the engine's.
#[allow(clippy::too_many_arguments)]
pub(super) fn spawn(
    context: EngineContext,
    oracle: &Oracle<PublicKey, deterministic::Context>,
    config: Config,
    votes: (
        impl SenderTrait<PublicKey = PublicKey>,
        impl ReceiverTrait<PublicKey = PublicKey>,
    ),
    certificates: (
        impl SenderTrait<PublicKey = PublicKey>,
        impl ReceiverTrait<PublicKey = PublicKey>,
    ),
    resolver: (
        impl SenderTrait<PublicKey = PublicKey>,
        impl ReceiverTrait<PublicKey = PublicKey>,
    ),
    backfill: (
        impl SenderTrait<PublicKey = PublicKey>,
        impl ReceiverTrait<PublicKey = PublicKey>,
    ),
    broadcast: (
        impl SenderTrait<PublicKey = PublicKey>,
        impl ReceiverTrait<PublicKey = PublicKey>,
    ),
    dkg: (
        impl SenderTrait<PublicKey = PublicKey>,
        impl ReceiverTrait<PublicKey = PublicKey>,
    ),
) -> (Handle<()>, oneshot::Receiver<Completion>) {
    let identity = config.signer.public_key();

    // The engine's storage is paced like its secret store.
    let context = context.paced(config.secrets.pacing());
    bootstrap::Engine::<_, MockGroup, _, _, _, _, Unit>::new(
        context,
        bootstrap::Config {
            signer: config.signer,
            manager: oracle.manager(),
            blocker: oracle.control(identity),
            secret_store: config.secrets,
            strategy: Sequential,
            namespace: BOOTSTRAP_NAMESPACE,
            sharing_mode: config.sharing_mode,
            reveal: Reveal::V1,
            max_supported_mode: MAX_SUPPORTED_MODE,
            partition_prefix: config.partition,
            page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            write_buffer: IO_BUFFER_SIZE,
            replay_buffer: IO_BUFFER_SIZE,
            mailbox_size: MAILBOX_SIZE,
            fetch_timeout: NZDuration!(FETCH_TIMEOUT),
            fetch_retry_delay: FETCH_RETRY_DELAY,
            items_per_section: SECTION_ITEMS,
            participants: config.participants,
            directory: Unit,
            blocks_per_epoch: EPOCH_LENGTH,
        },
    )
    .start(votes, certificates, resolver, backfill, broadcast, dkg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dkg::{
            fixtures::{committee, raised},
            identities,
        },
        stateful::runner::{network, tolerating},
    };
    use commonware_runtime::{Clock as _, Runner as _, Spawner as _, Supervisor as _};

    /// The panics of a run in which a task of the harness assembles the
    /// engine `engine`, as a driver does, and then panics if `planted`, each
    /// with the engine it is attributed to and what it said.
    fn assembled(engine: usize, planted: bool) -> Vec<(Option<usize>, String)> {
        let config = deterministic::Config::new().with_catch_panics(true);
        let (result, panics) = tolerating(|| {
            deterministic::Runner::new(config).start(|context| async move {
                let participants = committee();
                let oracle = network(&context, &participants).await;
                let assembly = context.child("assembly").spawn(move |context| async move {
                    let channels = register(&oracle, &participants[engine]).await;
                    let (handle, _) = spawn(
                        EngineContext::new(context.child("engine"), engine),
                        &oracle,
                        Config {
                            signer: identities()[engine].clone(),
                            participants: Set::from_iter_dedup(participants),
                            partition: format!("engine-{engine}"),
                            secrets: Secrets::default(),
                            sharing_mode: Mode::NonZeroCounter,
                        },
                        channels.votes,
                        channels.certificates,
                        channels.resolver,
                        channels.backfill,
                        channels.broadcast,
                        channels.dkg,
                    );
                    assert!(!planted, "planted in the assembly");
                    let _ = handle.await;
                });
                context.sleep(Duration::from_millis(100)).await;
                assembly.abort();
            })
        });
        result.expect("the root task returns");
        raised(panics)
    }

    /// The harness assembles a bootstrap engine on a task of its own, on the
    /// context of the engine it assembles. A panic in that assembly belongs
    /// to no engine, so no half would be excused it.
    #[test]
    fn harness_panic_in_assembly_belongs_to_no_engine() {
        assert_eq!(
            assembled(2, true),
            vec![(None, "planted in the assembly".to_string())]
        );
        assert_eq!(assembled(2, false), Vec::new());
    }
}
