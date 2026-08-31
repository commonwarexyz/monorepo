//! Settlement DA channel: dealing dissemination and vote return.
//!
//! Distributed certification runs over one muxed-free p2p channel modeled on
//! the dkg dealing exchange: the operator sends each committee validator its
//! exact assigned proof slices with [`Message::Dealing`] (`Recipients::One`),
//! and the validator answers with [`Message::Vote`] on the same channel.
//! Dealings and votes are off-chain traffic, recoverable by resend: only the
//! finalized admission is durable protocol state.
//!
//! The validator side is the [`Sealer`]: it accepts dealings from any
//! configured operator's network identity, routes each dealing to the
//! deployment that operator runs, seals it with clearing `seal` against THAT
//! deployment's chain-registered close from its own applied state (never
//! against operator-supplied context material), persists the sealed dealing
//! durably BEFORE releasing its vote back to the sending operator, and
//! retains it through the close's challenge deadline. Each deployment's
//! sealed dealings live in their own archive (the partition folds the
//! deployment digest), so two deployments' closes never contend for one
//! deadline slot. Within one archive the record key is the batch id, which
//! is already deployment-unique by construction: the close header commits
//! the payment anchor, which folds the deployment digest.

use crate::{
    chain::{
        state::{Machine, Record, machine_key, status_key},
        types::Database,
        validator::{IO_BUFFER_SIZE, PAGE_CACHE_SIZE, PAGE_SIZE},
    },
    protocol::{Key, MAX_SLICES, limits, short_digest},
};
use bytes::{Buf, BufMut};
use commonware_clearing::bajillion::{
    admission::{Vote, bls12381, seal},
    transition::{Header, ProofSlice, RootBundle, SliceCodecConfig},
};
use commonware_codec::{
    DecodeExt as _, Encode as _, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt as _,
    Write,
};
use commonware_cryptography::{Sha256, ed25519, sha256::Digest};
use commonware_cryptography_curve25519::signing::BatchVerifier as PaymentBatchVerifier;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_parallel::Sequential;
use commonware_runtime::{
    ContextCell, Handle, Metrics, Spawner, buffer::paged::CacheRef, spawn_cell,
};
use commonware_storage::{
    Context as StorageContext,
    archive::{Archive as _, Identifier, prunable},
    translator::TwoCap,
};
use commonware_utils::NZU64;
use rand_core::CryptoRng;
use tracing::{debug, error, info, warn};

/// Maximum Merkle proof hashes accepted per decoded slice frontier.
const MAX_PROOF_HASHES: usize = 4_096;

/// Adversarial decode limits for one disseminated proof slice: the
/// anchor-bound close limits every epoch context commits.
const fn slice_codec() -> SliceCodecConfig {
    SliceCodecConfig::new(limits(), MAX_PROOF_HASHES)
}

/// One validator's dealing for the registered close: the close header and
/// roots with exactly that validator's assigned proof slices.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Dealing {
    pub(crate) epoch: u64,
    pub(crate) header: Header<Digest>,
    pub(crate) roots: RootBundle<Digest>,
    pub(crate) slices: Vec<ProofSlice<Key, Digest>>,
}

impl Write for Dealing {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch.write(buf);
        self.header.write(buf);
        self.roots.write(buf);
        self.slices.write(buf);
    }
}

impl EncodeSize for Dealing {
    fn encode_size(&self) -> usize {
        self.epoch.encode_size()
            + self.header.encode_size()
            + self.roots.encode_size()
            + self.slices.encode_size()
    }
}

impl Read for Dealing {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            epoch: u64::read(buf)?,
            header: Header::read(buf)?,
            roots: RootBundle::read(buf)?,
            slices: Vec::<ProofSlice<Key, Digest>>::read_cfg(
                buf,
                &(RangeCfg::new(1..=MAX_SLICES), slice_codec()),
            )?,
        })
    }
}

/// One validator's attestation over a sealed close header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Ballot {
    pub(crate) epoch: u64,
    pub(crate) header: Header<Digest>,
    pub(crate) vote: Vote,
}

impl Write for Ballot {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch.write(buf);
        self.header.write(buf);
        self.vote.write(buf);
    }
}

impl EncodeSize for Ballot {
    fn encode_size(&self) -> usize {
        self.epoch.encode_size() + self.header.encode_size() + self.vote.encode_size()
    }
}

impl Read for Ballot {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            epoch: u64::read(buf)?,
            header: Header::read(buf)?,
            vote: Vote::read(buf)?,
        })
    }
}

/// One settlement DA channel message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Message {
    Dealing(Dealing),
    Vote(Ballot),
}

impl Write for Message {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Dealing(dealing) => {
                0_u8.write(buf);
                dealing.write(buf);
            }
            Self::Vote(ballot) => {
                1_u8.write(buf);
                ballot.write(buf);
            }
        }
    }
}

impl EncodeSize for Message {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Dealing(dealing) => dealing.encode_size(),
            Self::Vote(ballot) => ballot.encode_size(),
        }
    }
}

impl Read for Message {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::Dealing(Dealing::read(buf)?)),
            1 => Ok(Self::Vote(Ballot::read(buf)?)),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

/// One sealed dealing retained durably through its challenge deadline.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Sealed {
    pub(crate) epoch: u64,
    /// Challenge deadline (an absolute block height) through which the
    /// dealing must stay retained.
    pub(crate) deadline: u64,
    pub(crate) header: Header<Digest>,
    pub(crate) roots: RootBundle<Digest>,
    pub(crate) slices: Vec<ProofSlice<Key, Digest>>,
}

impl Write for Sealed {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch.write(buf);
        self.deadline.write(buf);
        self.header.write(buf);
        self.roots.write(buf);
        self.slices.write(buf);
    }
}

impl EncodeSize for Sealed {
    fn encode_size(&self) -> usize {
        self.epoch.encode_size()
            + self.deadline.encode_size()
            + self.header.encode_size()
            + self.roots.encode_size()
            + self.slices.encode_size()
    }
}

impl Read for Sealed {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            epoch: u64::read(buf)?,
            deadline: u64::read(buf)?,
            header: Header::read(buf)?,
            roots: RootBundle::read(buf)?,
            slices: Vec::<ProofSlice<Key, Digest>>::read_cfg(
                buf,
                &(RangeCfg::new(1..=MAX_SLICES), slice_codec()),
            )?,
        })
    }
}

/// Durable store of sealed dealings: a prunable archive indexed by the
/// close's challenge deadline height and keyed by the close's batch id.
///
/// Height-based retention is exactly what prunable archives are for
/// (marshal's finalizations-by-height archive is the model), and every
/// record syncs incrementally instead of rewriting the whole store, which
/// matters at real dealing sizes.
///
/// The record contract at this store:
/// - a sealed dealing is put and synced here BEFORE its vote is sent (the
///   clearing admission contract: the vote attests to availability this
///   validator must be able to honor), and a failed sync stops the actor,
/// - retention is pruning: a record lives at its challenge deadline, and
///   sections strictly below the certified finalized height are released
///   (a deadline below that height means the window is closed), never on
///   wall clock,
/// - restart reloads the archive whole, so a validator killed between seal
///   and vote still holds its sealed dealing,
/// - one record per batch id, never overwritten: an identical
///   re-dissemination re-votes from the stored bytes, and because the
///   archive silently ignores a put at an occupied index, a DIFFERING
///   dealing for a stored deadline is refused loudly before any put.
pub(crate) type Store<E> = prunable::Archive<TwoCap, E, Digest, Sealed>;

/// Opens one deployment's durable dealing store under the `partition`
/// family: the partition folds the deployment digest, so every configured
/// deployment retains its sealed dealings in its own archive.
pub(crate) async fn store<E: StorageContext>(
    context: E,
    partition: &str,
    deployment: &Digest,
) -> Store<E> {
    let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
    let scoped = format!("{partition}-{}", short_digest(deployment));
    Store::init(
        context,
        prunable::Config {
            translator: TwoCap,
            key_partition: format!("{scoped}-key"),
            key_page_cache: page_cache,
            value_partition: format!("{scoped}-value"),
            compression: None,
            codec_config: (),
            items_per_section: NZU64!(1_024),
            key_write_buffer: IO_BUFFER_SIZE,
            value_write_buffer: IO_BUFFER_SIZE,
            replay_buffer: IO_BUFFER_SIZE,
        },
    )
    .await
    .expect("failed to initialize the sealed dealing store")
}

/// Sealer configuration.
pub(crate) struct Config<E>
where
    E: Spawner + StorageContext,
{
    /// The validator's dealt clearing committee signing scheme.
    pub(crate) scheme: bls12381::Scheme,
    /// The accepted dealers: each configured operator's network identity
    /// paired with the digest of the deployment it runs, in genesis order.
    pub(crate) operators: Vec<(ed25519::PublicKey, Digest)>,
    /// The applied settlement database holding the registered closes.
    pub(crate) db: Database<E>,
    /// Storage partition family retaining sealed dealings.
    pub(crate) partition: String,
}

/// One configured operator's sealing lane: its deployment and the durable
/// store retaining that deployment's sealed dealings.
struct Lane<E>
where
    E: StorageContext,
{
    peer: ed25519::PublicKey,
    deployment: Digest,
    /// Taken while one dealing is processed and always restored: archive
    /// operations consume and return the store.
    store: Option<Store<E>>,
}

/// The validator's sealing actor on the settlement DA channel.
pub(crate) struct Sealer<E>
where
    E: Spawner + Metrics + StorageContext + CryptoRng,
{
    context: ContextCell<E>,
    scheme: bls12381::Scheme,
    operators: Vec<(ed25519::PublicKey, Digest)>,
    db: Database<E>,
    partition: String,
}

impl<E> Sealer<E>
where
    E: Spawner + Metrics + StorageContext + CryptoRng,
{
    pub(crate) fn new(context: E, config: Config<E>) -> Self {
        assert!(
            config.scheme.me().is_some(),
            "the sealer requires a signing clearing scheme"
        );
        assert!(
            !config.operators.is_empty(),
            "the sealer requires at least one configured operator"
        );
        Self {
            context: ContextCell::new(context),
            scheme: config.scheme,
            operators: config.operators,
            db: config.db,
            partition: config.partition,
        }
    }

    /// Starts the sealer on the settlement DA channel.
    pub(crate) fn start<Se, Re>(mut self, chan: (Se, Re)) -> Handle<()>
    where
        Se: Sender<PublicKey = ed25519::PublicKey>,
        Re: Receiver<PublicKey = ed25519::PublicKey>,
    {
        spawn_cell!(self.context, self.run(chan))
    }

    async fn run<Se, Re>(mut self, (mut sender, mut receiver): (Se, Re))
    where
        Se: Sender<PublicKey = ed25519::PublicKey>,
        Re: Receiver<PublicKey = ed25519::PublicKey>,
    {
        let mut lanes = Vec::with_capacity(self.operators.len());
        for (index, (peer, deployment)) in self.operators.iter().enumerate() {
            // Context labels are 'static: one bounded allocation per
            // configured operator at actor start.
            let label: &'static str = format!("dealings_{index}").leak();
            lanes.push(Lane {
                peer: peer.clone(),
                deployment: *deployment,
                store: Some(store(self.context.child(label), &self.partition, deployment).await),
            });
        }
        while let Ok((peer, bytes)) = receiver.recv().await {
            // The configured operators are the only dealers, and the sender
            // identity routes the dealing to the deployment that operator
            // runs. Anything else on this channel is dropped without
            // decoding past the bounds.
            let Some(lane) = lanes.iter_mut().find(|lane| lane.peer == peer) else {
                debug!(?peer, "dropping DA message from a non-operator peer");
                continue;
            };
            let deployment = lane.deployment;
            let mut store = lane
                .store
                .take()
                .expect("the lane store is always restored");
            let Ok(Message::Dealing(dealing)) = Message::decode(bytes) else {
                debug!("dropping undecodable or unexpected DA message");
                lane.store = Some(store);
                continue;
            };

            // A replayed dealing for a batch this validator already sealed
            // re-votes from the durable record (dissemination and votes are
            // recoverable off-chain traffic), and never re-seals: the vote
            // attested to exactly the retained bytes.
            let batch = dealing.header.batch_id::<Sha256>().into_digest();
            match store.get(Identifier::Key(&batch)).await {
                Ok(Some(sealed)) => {
                    self.vote(&mut sender, &peer, sealed.epoch, sealed.header);
                    lane.store = Some(store);
                    continue;
                }
                Ok(None) => {}
                Err(error) => {
                    error!(?error, "sealer failed to read the dealing store");
                    return;
                }
            }

            // The sending operator's deployment's chain-registered close from
            // this validator's own applied state is the only sealing context:
            // the dealing carries no context material to trust.
            let (machine, height) = {
                let guard = self.db.read().await;
                let machine = match guard.get(&machine_key(&deployment)).await {
                    Ok(Some(Record::Machine(encoded))) => {
                        Machine::decode(encoded).expect("the persisted machine decodes")
                    }
                    Ok(_) => {
                        debug!("no settlement machine is applied yet");
                        lane.store = Some(store);
                        continue;
                    }
                    Err(error) => {
                        error!(?error, "sealer failed to read applied state");
                        return;
                    }
                };
                let height = match guard.get(&status_key(&deployment)).await {
                    Ok(Some(Record::Status(status))) => status.height,
                    Ok(_) => 0,
                    Err(error) => {
                        error!(?error, "sealer failed to read applied status");
                        return;
                    }
                };
                (machine, height)
            };
            let Some(registered) = machine.registered() else {
                debug!(
                    epoch = dealing.epoch,
                    "no registered close to seal against yet"
                );
                lane.store = Some(store);
                continue;
            };
            if registered.context.payment().epoch() != dealing.epoch {
                debug!(
                    epoch = dealing.epoch,
                    registered = registered.context.payment().epoch(),
                    "dealing is not for the registered epoch"
                );
                lane.store = Some(store);
                continue;
            }

            // The archive satisfies a put below its prune floor without
            // storing, so a dealing whose challenge window already closed at
            // the certified finalized height is refused instead of earning a
            // vote its bytes could not back.
            let deadline = registered.context.challenge_deadline();
            if deadline < height {
                debug!(
                    epoch = dealing.epoch,
                    deadline, height, "dealing challenge window already closed"
                );
                lane.store = Some(store);
                continue;
            }

            // One close per challenge deadline: the archive silently ignores
            // a put at an occupied index, so a differing dealing that would
            // collide there is refused loudly before any seal work. An
            // identical close was already answered from the store above.
            match store.get(Identifier::Index(deadline)).await {
                Ok(Some(_)) => {
                    warn!(
                        epoch = dealing.epoch,
                        deadline, "refusing a second close for a sealed challenge deadline"
                    );
                    lane.store = Some(store);
                    continue;
                }
                Ok(None) => {}
                Err(error) => {
                    error!(?error, "sealer failed to read the dealing store");
                    return;
                }
            }

            // Clearing seal re-derives and enforces this validator's exact
            // assignment, validates every slice against the registered
            // context, and batch-verifies the payment signatures.
            let sealed = match seal::<Sha256, _, _, PaymentBatchVerifier, _>(
                &self.scheme,
                registered.context,
                registered.deposits,
                registered.withdrawals,
                &dealing.header,
                &dealing.roots,
                dealing.slices,
                self.context.as_mut(),
                &Sequential,
            ) {
                Ok((_, sealed)) => sealed,
                Err(error) => {
                    warn!(?error, epoch = dealing.epoch, "dealing failed to seal");
                    lane.store = Some(store);
                    continue;
                }
            };

            // Pruning is the retention rule: sections strictly below the
            // certified finalized height (the applied status) are released,
            // never on wall clock, because a deadline below that height
            // means the challenge window is closed.
            store = match store.prune(height).await {
                Ok(store) => store,
                Err(error) => {
                    error!(?error, "sealed dealing store could not prune");
                    return;
                }
            };

            // Durable before vote: the sealed dealing is put at its
            // challenge deadline and synced to disk before the attestation
            // leaves this validator.
            store = match store
                .put_sync(
                    deadline,
                    batch,
                    Sealed {
                        epoch: dealing.epoch,
                        deadline,
                        header: *sealed.header(),
                        roots: *sealed.roots(),
                        slices: sealed.into_slices(),
                    },
                )
                .await
            {
                Ok(store) => store,
                Err(error) => {
                    error!(?error, "sealed dealing could not be made durable");
                    return;
                }
            };
            info!(epoch = dealing.epoch, "sealed dealing");
            lane.store = Some(store);
            self.vote(&mut sender, &peer, dealing.epoch, dealing.header);
        }
    }

    /// Signs and returns one vote over a durably sealed header, addressed to
    /// the operator that disseminated the dealing.
    fn vote<Se>(
        &self,
        sender: &mut Se,
        operator: &ed25519::PublicKey,
        epoch: u64,
        header: Header<Digest>,
    ) where
        Se: Sender<PublicKey = ed25519::PublicKey>,
    {
        let vote = self
            .scheme
            .sign(&header)
            .expect("the sealer scheme was constructed as a signer");
        let message = Message::Vote(Ballot {
            epoch,
            header,
            vote,
        });
        let sent = sender.send(Recipients::One(operator.clone()), message.encode(), true);
        if sent.is_empty() {
            debug!(epoch, "failed to send vote; the operator will resend");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chain::{
            state::execute,
            tx::{RegisterEpochRequest, SettlementTx},
            types::Database,
        },
        protocol::{
            DepositEvent, INITIAL_BALANCE, PreparedEpoch, Protocol, clearing_private, committee,
            dealt_participant, deployment, deployments, identities,
        },
    };
    use commonware_clearing::bajillion::{
        boundary::{DepositBatch, DepositRecord, WithdrawalBatch},
        credit::ShardSet,
        state::{AccountRow, AccountState, Prefix, SettlementOutput, StateLeaf},
    };
    use commonware_consensus::types::Height;
    use commonware_cryptography::{Hasher as _, Signer as _, ed25519::PrivateKey};
    use commonware_glue::stateful::db::DatabaseSet;
    use commonware_p2p::simulated::{Config as NetConfig, Link, Network};
    use commonware_runtime::{
        Clock as _, Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
    };
    use commonware_storage::{
        journal::contiguous::variable::Config as VariableJournalConfig,
        merkle::full::Config as MerkleConfig, qmdb::current::VariableConfig,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize, probability};
    use std::{num::NonZeroUsize, time::Duration};

    /// Opens a fresh settlement database with partitions under `prefix`.
    async fn open(
        context: deterministic::Context,
        prefix: &str,
    ) -> Database<deterministic::Context> {
        let page_cache = CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(16));
        let config: VariableConfig<TwoCap, ((), ()), commonware_parallel::Sequential> =
            VariableConfig {
                merkle_config: MerkleConfig {
                    journal_partition: format!("{prefix}-mmr-journal"),
                    metadata_partition: format!("{prefix}-mmr-metadata"),
                    items_per_blob: NZU64!(64),
                    write_buffer: NZUsize!(2048),
                    strategy: Sequential,
                    page_cache: page_cache.clone(),
                },
                journal_config: VariableJournalConfig {
                    partition: format!("{prefix}-log-journal"),
                    items_per_section: NZU64!(64),
                    compression: None,
                    codec_config: ((), ()),
                    page_cache,
                    write_buffer: NZUsize!(2048),
                },
                grafted_metadata_partition: format!("{prefix}-grafted-metadata"),
                translator: TwoCap,
                init_cache_size: Some(NZUsize!(1024)),
                init_buffer: NZUsize!(1 << 21),
                init_concurrency: (),
            };
        <Database<deterministic::Context> as DatabaseSet<_>>::init(context, config).await
    }

    /// Executes one block against `db` under `configured` and applies it,
    /// with the height doubling as the timestamp.
    async fn apply_with(
        db: &Database<deterministic::Context>,
        height: u64,
        configured: &[crate::protocol::Deployment],
        txs: &[SettlementTx],
    ) {
        let batch = db.new_batches().await;
        let sealed = execute(
            batch,
            Height::new(height),
            height,
            &crate::protocol::Timing::DEFAULT,
            configured,
            txs,
        )
        .await
        .expect("block execution succeeds");
        db.apply(sealed).await;
    }

    /// Executes one block against `db` under the compiled default deployment
    /// and applies it.
    async fn apply(db: &Database<deterministic::Context>, height: u64, txs: &[SettlementTx]) {
        apply_with(db, height, &deployments(), txs).await;
    }

    /// One epoch-0 close over genesis with a unit deposit, prepared for
    /// dissemination, and its chain transactions.
    fn fixture(
        protocol: &Protocol,
        admission_deadline: u64,
        challenge_deadline: u64,
    ) -> (SettlementTx, SettlementTx, PreparedEpoch) {
        let mut predecessor = identities()
            .into_iter()
            .map(|identity| StateLeaf {
                account: identity.key,
                state: AccountState {
                    balance: INITIAL_BALANCE,
                    active: true,
                    ..AccountState::default()
                },
            })
            .collect::<Vec<_>>();
        predecessor.sort_unstable_by(|left, right| left.account.cmp(&right.account));
        let account = predecessor[0].account.clone();
        let liability = predecessor
            .iter()
            .map(|leaf| leaf.state.balance)
            .sum::<u64>();
        let deposit = DepositEvent {
            id: Sha256::hash(&[b"da-fixture-deposit"]),
            account: account.clone(),
            amount: 1,
        };
        let deposits =
            DepositBatch::new(vec![DepositRecord::new(account.clone(), 1).unwrap()]).unwrap();
        let deposits_root = deposits.root::<Sha256>().unwrap();
        let withdrawals = WithdrawalBatch::empty();
        let signature = protocol.sign_chain_registration(
            0,
            liability,
            &deposits_root,
            &deposits_root,
            &withdrawals,
        );
        let register = SettlementTx::RegisterEpoch(RegisterEpochRequest {
            deployment: protocol.deployment(),
            epoch: 0,
            predecessor_liability: liability,
            deposits_root,
            staged_root: deposits_root,
            withdrawals: withdrawals.clone(),
            openings: Vec::new(),
            signature,
        });

        let predecessor_state = predecessor[0].state;
        let successor_state = AccountState {
            balance: predecessor_state.balance + 1,
            ..predecessor_state
        };
        let row = AccountRow {
            account: account.clone(),
            predecessor: predecessor_state,
            successor: successor_state,
            outgoing: None,
            output: SettlementOutput::None,
            prefix: Prefix {
                deposit: 1,
                ..Prefix::default()
            },
        };
        let mut successor = predecessor.clone();
        successor[0].state = successor_state;
        let registration = protocol
            .registration_at(
                0,
                deposits,
                withdrawals,
                liability,
                admission_deadline,
                challenge_deadline,
            )
            .unwrap();
        let prepared = protocol
            .prepare(
                registration,
                vec![deposit.clone()],
                predecessor,
                vec![row],
                vec![ShardSet::empty(0, account)],
                successor,
            )
            .unwrap();
        (
            SettlementTx::Deposit(crate::chain::tx::DepositRequest {
                deployment: protocol.deployment(),
                event: deposit,
            }),
            register,
            prepared,
        )
    }

    /// One two-peer simulated network: the operator's DA channel endpoints
    /// and the validator's, with links per `to_validator`/`to_operator`.
    async fn network(
        context: &deterministic::Context,
        operator: &ed25519::PublicKey,
        validator: &ed25519::PublicKey,
        to_validator: bool,
        to_operator: bool,
    ) -> (
        (
            impl Sender<PublicKey = ed25519::PublicKey>,
            impl Receiver<PublicKey = ed25519::PublicKey>,
        ),
        (
            impl Sender<PublicKey = ed25519::PublicKey>,
            impl Receiver<PublicKey = ed25519::PublicKey>,
        ),
    ) {
        let (net, oracle) = Network::new_with_peers(
            context.child("network"),
            NetConfig {
                max_size: 4 * 1024 * 1024,
                max_peers_per_set: NZUsize!(2),
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(1),
            },
            [operator.clone(), validator.clone()],
        )
        .await;
        net.start();
        let quota = commonware_runtime::Quota::per_second(commonware_utils::NZU32!(128));
        let operator_chan = oracle
            .control(operator.clone())
            .register(0, quota)
            .await
            .unwrap();
        let validator_chan = oracle
            .control(validator.clone())
            .register(0, quota)
            .await
            .unwrap();
        let link = Link {
            latency: Duration::from_millis(1),
            jitter: Duration::from_millis(0),
            success_rate: probability!(1.0),
        };
        if to_validator {
            oracle
                .add_link(operator.clone(), validator.clone(), link.clone())
                .await
                .unwrap();
        }
        if to_operator {
            oracle
                .add_link(validator.clone(), operator.clone(), link)
                .await
                .unwrap();
        }
        (operator_chan, validator_chan)
    }

    /// A sealer for validator directory `index` over `db`, accepting
    /// dealings from the configured `operators`.
    fn sealer(
        context: &deterministic::Context,
        index: usize,
        operators: Vec<(ed25519::PublicKey, Digest)>,
        db: Database<deterministic::Context>,
        partition: &str,
    ) -> Sealer<deterministic::Context> {
        Sealer::new(
            context.child("sealer"),
            Config {
                scheme: bls12381::Scheme::signer(
                    committee().unwrap(),
                    clearing_private(index).unwrap(),
                )
                .unwrap(),
                operators,
                db,
                partition: partition.to_string(),
            },
        )
    }

    #[test]
    fn sealer_seals_persists_and_revotes() {
        deterministic::Runner::default().start(|context| async move {
            let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
            let (deposit_tx, register_tx, prepared) = fixture(&protocol, 11, 12);
            let db = open(context.child("db"), "sealer-happy").await;
            apply(&db, 1, &[deposit_tx, register_tx]).await;

            let operator_key = PrivateKey::from_seed(9_000).public_key();
            let validator_key = PrivateKey::from_seed(9_001).public_key();
            let (mut operator_chan, validator_chan) =
                network(&context, &operator_key, &validator_key, true, true).await;
            sealer(
                &context,
                0,
                vec![(operator_key.clone(), deployment())],
                db.clone(),
                "sealer-happy",
            )
            .start(validator_chan);

            // The validator's exact dealing seals and earns a verified vote.
            let slices = protocol.slices(&prepared).unwrap();
            let dealings = protocol.dealings(&prepared, &slices).unwrap();
            let participant = dealt_participant(0).unwrap();
            let header = prepared.close().header;
            let roots = prepared.close().roots;
            let dealing = Message::Dealing(Dealing {
                epoch: 0,
                header,
                roots,
                slices: dealings[usize::from(participant)].clone(),
            });
            let sent = operator_chan.0.send(
                Recipients::One(validator_key.clone()),
                dealing.encode(),
                true,
            );
            assert_eq!(sent, vec![validator_key.clone()]);
            let (from, bytes) = operator_chan.1.recv().await.unwrap();
            assert_eq!(from, validator_key);
            let Ok(Message::Vote(ballot)) = Message::decode(bytes) else {
                panic!("the sealer answered with a non-vote");
            };
            assert_eq!(ballot.epoch, 0);
            assert_eq!(ballot.header, header);
            assert_eq!(ballot.vote.signer, participant);
            let verifier = protocol.verifier();
            assert!(verifier.verify_vote(&header, &ballot.vote));

            // The sealed dealing is durably retained under the batch id, at
            // its challenge deadline.
            let store = store(context.child("probe"), "sealer-happy", &deployment()).await;
            let batch = header.batch_id::<Sha256>().into_digest();
            let sealed = store
                .get(Identifier::Key(&batch))
                .await
                .unwrap()
                .expect("the sealed dealing is durable");
            assert_eq!(sealed.epoch, 0);
            assert_eq!(sealed.deadline, 12);
            assert_eq!(sealed.header, header);
            assert_eq!(sealed.roots, roots);
            assert_eq!(sealed.slices, dealings[usize::from(participant)]);
            assert_eq!(store.first_index(), Some(12));

            // A replayed dealing re-votes from the durable record.
            let sent = operator_chan.0.send(
                Recipients::One(validator_key.clone()),
                dealing.encode(),
                true,
            );
            assert!(!sent.is_empty());
            let (_, bytes) = operator_chan.1.recv().await.unwrap();
            let Ok(Message::Vote(replayed)) = Message::decode(bytes) else {
                panic!("the sealer answered the replay with a non-vote");
            };
            assert_eq!(replayed.header, header);
            assert!(verifier.verify_vote(&header, &replayed.vote));
        });
    }

    #[test]
    fn sealer_refuses_tampered_dealings() {
        deterministic::Runner::default().start(|context| async move {
            let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
            let (deposit_tx, register_tx, prepared) = fixture(&protocol, 11, 12);
            let db = open(context.child("db"), "sealer-tampered").await;
            apply(&db, 1, &[deposit_tx, register_tx]).await;

            let operator_key = PrivateKey::from_seed(9_100).public_key();
            let validator_key = PrivateKey::from_seed(9_101).public_key();
            let (mut operator_chan, validator_chan) =
                network(&context, &operator_key, &validator_key, true, true).await;
            sealer(
                &context,
                0,
                vec![(operator_key.clone(), deployment())],
                db.clone(),
                "sealer-tampered",
            )
            .start(validator_chan);

            let slices = protocol.slices(&prepared).unwrap();
            let dealings = protocol.dealings(&prepared, &slices).unwrap();
            let participant = dealt_participant(0).unwrap();
            let header = prepared.close().header;
            let roots = prepared.close().roots;
            let mine = dealings[usize::from(participant)].clone();

            // Another validator's assignment fails seal's exact-assignment
            // check, and a corrupted slice fails structural validation:
            // neither earns a vote or a durable record.
            let foreign = usize::from(participant) ^ 1;
            let wrong = Message::Dealing(Dealing {
                epoch: 0,
                header,
                roots,
                slices: dealings[foreign].clone(),
            });
            let mut corrupt_slices = mine.clone();
            corrupt_slices[0].coverage.end.predecessor =
                corrupt_slices[0].coverage.end.predecessor.saturating_add(1);
            let corrupt = Message::Dealing(Dealing {
                epoch: 0,
                header,
                roots,
                slices: corrupt_slices,
            });
            let good = Message::Dealing(Dealing {
                epoch: 0,
                header,
                roots,
                slices: mine,
            });
            for message in [&wrong, &corrupt, &good] {
                let sent = operator_chan.0.send(
                    Recipients::One(validator_key.clone()),
                    message.encode(),
                    true,
                );
                assert!(!sent.is_empty());
            }

            // The DA channel delivers in order, so the first (and only)
            // answer voting for the header proves the tampered dealings
            // produced nothing.
            let (_, bytes) = operator_chan.1.recv().await.unwrap();
            let Ok(Message::Vote(ballot)) = Message::decode(bytes) else {
                panic!("the sealer answered with a non-vote");
            };
            assert_eq!(ballot.vote.signer, participant);
            assert!(protocol.verifier().verify_vote(&header, &ballot.vote));

            // Exactly one dealing was sealed and retained: indices are
            // unique per archive entry, and the only one is the close's
            // challenge deadline holding the untampered dealing.
            let store = store(context.child("probe"), "sealer-tampered", &deployment()).await;
            assert_eq!(store.first_index(), Some(12));
            assert_eq!(store.last_index(), Some(12));
            let batch = header.batch_id::<Sha256>().into_digest();
            let sealed = store
                .get(Identifier::Key(&batch))
                .await
                .unwrap()
                .expect("the sealed dealing is durable");
            assert_eq!(sealed.slices, dealings[usize::from(participant)]);
        });
    }

    #[test]
    fn sealed_dealing_is_durable_before_the_vote() {
        deterministic::Runner::default().start(|context| async move {
            let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
            let (deposit_tx, register_tx, prepared) = fixture(&protocol, 11, 12);
            let db = open(context.child("db"), "sealer-durable").await;
            apply(&db, 1, &[deposit_tx, register_tx]).await;

            let operator_key = PrivateKey::from_seed(9_200).public_key();
            let validator_key = PrivateKey::from_seed(9_201).public_key();

            // No return link: the vote can never leave the validator, which
            // models a kill between seal and vote.
            let (mut operator_chan, validator_chan) =
                network(&context, &operator_key, &validator_key, true, false).await;
            let running = sealer(
                &context,
                0,
                vec![(operator_key.clone(), deployment())],
                db.clone(),
                "sealer-durable",
            )
            .start(validator_chan);

            let slices = protocol.slices(&prepared).unwrap();
            let dealings = protocol.dealings(&prepared, &slices).unwrap();
            let participant = dealt_participant(0).unwrap();
            let header = prepared.close().header;
            let dealing = Message::Dealing(Dealing {
                epoch: 0,
                header,
                roots: prepared.close().roots,
                slices: dealings[usize::from(participant)].clone(),
            });
            operator_chan.0.send(
                Recipients::One(validator_key.clone()),
                dealing.encode(),
                true,
            );
            context.sleep(Duration::from_secs(1)).await;
            running.abort();

            // The restarted validator still holds the sealed dealing even
            // though its vote never left, and re-votes on the resent dealing.
            let store = store(context.child("probe"), "sealer-durable", &deployment()).await;
            let batch = header.batch_id::<Sha256>().into_digest();
            let sealed = store
                .get(Identifier::Key(&batch))
                .await
                .unwrap()
                .expect("the sealed dealing survived the crash before the vote");
            assert_eq!(sealed.slices, dealings[usize::from(participant)]);
            drop(store);

            let relinked = context.child("relinked");
            let (mut operator_chan, validator_chan) =
                network(&relinked, &operator_key, &validator_key, true, true).await;
            sealer(
                &context.child("restarted"),
                0,
                vec![(operator_key.clone(), deployment())],
                db.clone(),
                "sealer-durable",
            )
            .start(validator_chan);
            operator_chan.0.send(
                Recipients::One(validator_key.clone()),
                dealing.encode(),
                true,
            );
            let (_, bytes) = operator_chan.1.recv().await.unwrap();
            let Ok(Message::Vote(ballot)) = Message::decode(bytes) else {
                panic!("the restarted sealer answered with a non-vote");
            };
            assert_eq!(ballot.header, header);
            assert!(protocol.verifier().verify_vote(&header, &ballot.vote));
        });
    }
    /// THE dealing-store cross-talk pin: two operators' closes share one
    /// challenge deadline, and the sealer seals both, retains each in its
    /// own deployment's archive, and votes back to each sender. Neither
    /// dealing collides with or displaces the other.
    #[test]
    fn dealing_stores_do_not_cross_talk() {
        deterministic::Runner::default().start(|context| async move {
            let alpha_protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
            let beta_protocol =
                Protocol::with_signer(NonZeroUsize::MIN, crate::protocol::operator_signer(1))
                    .unwrap();
            let alpha = alpha_protocol.deployment();
            let beta = beta_protocol.deployment();
            let configured = vec![
                crate::protocol::Deployment::new(
                    crate::protocol::operator_key(),
                    crate::protocol::accounts(),
                ),
                crate::protocol::Deployment::new(
                    crate::protocol::operator_signer(1).public_key(),
                    crate::protocol::accounts(),
                ),
            ];

            // Both deployments register in block 1 under the default policy,
            // so both closes carry the same assigned deadlines (11, 12).
            let (a_deposit, a_register, a_prepared) = fixture(&alpha_protocol, 11, 12);
            let (b_deposit, b_register, b_prepared) = fixture(&beta_protocol, 11, 12);
            let db = open(context.child("db"), "cross-talk").await;
            apply_with(
                &db,
                1,
                &configured,
                &[a_deposit, a_register, b_deposit, b_register],
            )
            .await;

            // One validator sealer configured for both operators, on a
            // three-peer simulated network.
            let alpha_key = PrivateKey::from_seed(9_400).public_key();
            let beta_key = PrivateKey::from_seed(9_401).public_key();
            let validator_key = PrivateKey::from_seed(9_402).public_key();
            let (net, oracle) = Network::new_with_peers(
                context.child("network"),
                NetConfig {
                    max_size: 4 * 1024 * 1024,
                    max_peers_per_set: NZUsize!(3),
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
                [alpha_key.clone(), beta_key.clone(), validator_key.clone()],
            )
            .await;
            net.start();
            let quota = commonware_runtime::Quota::per_second(commonware_utils::NZU32!(128));
            let mut alpha_chan = oracle
                .control(alpha_key.clone())
                .register(0, quota)
                .await
                .unwrap();
            let mut beta_chan = oracle
                .control(beta_key.clone())
                .register(0, quota)
                .await
                .unwrap();
            let validator_chan = oracle
                .control(validator_key.clone())
                .register(0, quota)
                .await
                .unwrap();
            let link = Link {
                latency: Duration::from_millis(1),
                jitter: Duration::from_millis(0),
                success_rate: probability!(1.0),
            };
            for operator in [&alpha_key, &beta_key] {
                oracle
                    .add_link(operator.clone(), validator_key.clone(), link.clone())
                    .await
                    .unwrap();
                oracle
                    .add_link(validator_key.clone(), operator.clone(), link.clone())
                    .await
                    .unwrap();
            }
            sealer(
                &context,
                0,
                vec![(alpha_key.clone(), alpha), (beta_key.clone(), beta)],
                db.clone(),
                "cross-talk",
            )
            .start(validator_chan);

            // Each operator disseminates its own dealing, and each vote
            // routes back to exactly the sender that earned it.
            let participant = dealt_participant(0).unwrap();
            let mut headers = Vec::new();
            for (protocol, prepared, chan) in [
                (&alpha_protocol, &a_prepared, &mut alpha_chan),
                (&beta_protocol, &b_prepared, &mut beta_chan),
            ] {
                let slices = protocol.slices(prepared).unwrap();
                let dealings = protocol.dealings(prepared, &slices).unwrap();
                let header = prepared.close().header;
                let message = Message::Dealing(Dealing {
                    epoch: 0,
                    header,
                    roots: prepared.close().roots,
                    slices: dealings[usize::from(participant)].clone(),
                });
                let sent = chan.0.send(
                    Recipients::One(validator_key.clone()),
                    message.encode(),
                    true,
                );
                assert_eq!(sent, vec![validator_key.clone()]);
                let (from, bytes) = chan.1.recv().await.unwrap();
                assert_eq!(from, validator_key);
                let Ok(Message::Vote(ballot)) = Message::decode(bytes) else {
                    panic!("the sealer answered with a non-vote");
                };
                assert_eq!(ballot.header, header);
                assert!(protocol.verifier().verify_vote(&header, &ballot.vote));
                headers.push(header);
            }

            // The batch ids are deployment-unique and each archive holds
            // exactly its own deployment's dealing at the shared deadline.
            let alpha_batch = headers[0].batch_id::<Sha256>().into_digest();
            let beta_batch = headers[1].batch_id::<Sha256>().into_digest();
            assert_ne!(alpha_batch, beta_batch);
            let alpha_store = store(context.child("alpha_probe"), "cross-talk", &alpha).await;
            let beta_store = store(context.child("beta_probe"), "cross-talk", &beta).await;
            for (own, other, store, header) in [
                (&alpha_batch, &beta_batch, &alpha_store, &headers[0]),
                (&beta_batch, &alpha_batch, &beta_store, &headers[1]),
            ] {
                assert_eq!(store.first_index(), Some(12));
                assert_eq!(store.last_index(), Some(12));
                let sealed = store
                    .get(Identifier::Key(own))
                    .await
                    .unwrap()
                    .expect("the sealed dealing is durable in its own archive");
                assert_eq!(&sealed.header, header);
                assert_eq!(sealed.deadline, 12);
                assert_eq!(store.get(Identifier::Key(other)).await.unwrap(), None);
            }
        });
    }
}
