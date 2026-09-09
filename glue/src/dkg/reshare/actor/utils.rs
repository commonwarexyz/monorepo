//! Shared deterministic fixtures for reshare actor unit tests.

use super::{Config, Mailbox};
use crate::dkg::{
    fence::Fence,
    state_sync::Plan as StateSyncPlan,
    tests::mocks::{self, MemorySecretStore},
};
use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    Signer,
    bls12381::{dkg::feldman_desmedt::Reveal, primitives::sharing::Mode},
    ed25519,
};
use commonware_p2p::simulated::Oracle;
use commonware_parallel::Sequential;
use commonware_runtime::{Supervisor as _, deterministic};
use commonware_utils::{NZU32, NZUsize, ordered::Set};
use std::{marker::PhantomData, num::NonZeroU64};

/// Mailbox paired with [`mocks::TestReshareActor`].
pub(super) type TestMailbox = Mailbox<mocks::TestBlock, mocks::TestBlsVariant, mocks::TestSigner>;

/// Builds an unstarted actor with deterministic storage, networking, and marshal fixtures.
pub(super) async fn new_actor(
    mut context: deterministic::Context,
    signer: mocks::TestSigner,
    participants: Set<mocks::TestPublicKey>,
    oracle: &Oracle<mocks::TestPublicKey, deterministic::Context>,
    namespace: &'static [u8],
    partition_prefix: &str,
    blocks_per_epoch: NonZeroU64,
) -> (mocks::TestReshareActor, TestMailbox) {
    let fixture = mocks::scheme_fixture_n(&mut context, 1);
    let marshal = mocks::closed_marshal_mailbox(
        context.child("marshal"),
        &signer,
        fixture.schemes[0].clone(),
        partition_prefix,
        blocks_per_epoch,
    )
    .await;
    let (fence, _gate) = Fence::new(Epoch::zero());
    mocks::TestReshareActor::new(
        context.child("actor"),
        Config {
            signer: signer.clone(),
            manager: oracle.manager(),
            blocker: oracle.control(signer.public_key()),
            participants_provider: mocks::StaticParticipants(participants),
            secret_store: MemorySecretStore::default(),
            strategy: Sequential,
            registrar: mocks::MockConsumer::default(),
            marshal,
            state_sync: StateSyncPlan::disabled(),
            fence,
            namespace,
            sharing_mode: Mode::NonZeroCounter,
            reveal: Reveal::V1,
            mailbox_size: NZUsize!(16),
            partition_prefix: format!("{partition_prefix}-actor"),
            max_participants: NZU32!(16),
            blocks_per_epoch,
            batch_verifier: PhantomData::<ed25519::Batch>,
        },
    )
}
