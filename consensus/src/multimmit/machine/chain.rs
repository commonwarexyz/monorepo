//! Transaction-chain state: data availability, the local producer, DA signing reservations, and
//! the capabilities they issue.
//!
//! [`ChainState`] composes the per-chain DA state (`da.rs`), the local producer's pipeline
//! (`producer.rs`), and the DA signing choices (`signing.rs`). Vote bodies and chain proposals are
//! built in `vote_body.rs`. Verified blocks are routed to their chain plane (see
//! `eligibility.rs`) through [`ValidatorCommand::Observe`].

use super::{
    capability::{Capabilities, Capability, ChainCommand, ObservedBlock, ValidatorCommand},
    da::{DaChoice, DaState},
    durability::SignRequest,
    producer::ProducerState,
    signing::{ReservationBook, ReservationError},
    verification::Observation,
};
use crate::{
    Epochable as _,
    multimmit::{
        config::{Profile, Role},
        types::{
            Artifact, ArtifactId, ChainId, CodecConfig, Context, DaCertificate,
            SignedTransactionBlock, TransactionBlockHeader,
        },
    },
    types::{Epoch, Height, Participant},
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::sync::Arc;

/// The greatest known, DA-certified, and locally DA-voted heights on one chain.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct ChainHeights {
    /// The greatest height this node can use: its floor, a certificate, a validated offer, a DA
    /// choice, or its own production.
    pub(crate) known: Height,
    /// The greatest height holding a DA certificate, or zero when none is held.
    pub(crate) certified: Height,
    /// The greatest height this node DA-voted, or its retired frontier when it holds no choice.
    pub(crate) da_voted: Height,
}

/// Chain state owned by the deterministic machine.
///
/// The DA choices, producer headers, and DA signing reservations (see
/// [`Self::reserve_signing`] and [`Self::replay_signing`]) mirror durable state; everything else
/// is rebuildable from admitted artifacts and durable anchors.
pub(crate) struct ChainState<V: Variant, D: Digest> {
    pub(super) config: CodecConfig,
    pub(super) epoch: Epoch,
    /// This node's participant when it validates, or `None` when it observes.
    pub(super) me: Option<Participant>,
    pub(super) da_quorum: usize,
    pub(super) pipeline_depth: u64,
    pub(super) da: DaState<V, D>,
    /// The local producer's pipeline, when this node produces a chain.
    pub(super) producer: Option<ProducerState<D>>,
    /// Reserved DA signing choices, each keyed by its effect and held as its shared requests.
    pub(super) signing: ReservationBook<Arc<[SignRequest<V, D>]>>,
    /// Work issued since the reducer last took it.
    pub(super) capabilities: Capabilities<V, D>,
}

impl<V: Variant, D: Digest> ChainState<V, D> {
    /// Creates the chain state for the profile, with a producer pipeline when this validator
    /// produces a chain.
    pub(crate) fn new(profile: &Profile<D>) -> Self {
        let genesis = profile.protocol().genesis().tips().to_vec();
        let me = match profile.role() {
            Role::Validator(participant) => Some(participant),
            Role::Observer => None,
        };
        let producer = me
            .and_then(|participant| profile.protocol().producer_chain(participant))
            .and_then(|chain| {
                let tip = genesis.get(chain.index()).copied()?;
                Some(ProducerState::new(
                    chain,
                    tip,
                    profile.tuning().production_interval,
                ))
            });
        let config = profile.codec();
        Self {
            config,
            epoch: profile.protocol().epoch(),
            me,
            da_quorum: config.da_quorum(),
            pipeline_depth: config.pipeline_depth() as u64,
            da: DaState::new(genesis),
            producer,
            signing: ReservationBook::new(profile.resources().max_outbox_effects()),
            capabilities: Vec::new(),
        }
    }

    /// Prunes chain work made obsolete by a durably recorded DA certificate.
    pub(crate) fn compact_certified<H: Hasher<Digest = D>>(
        &mut self,
        certificate: &DaCertificate<V, D>,
        retired: Height,
    ) -> Result<(), ChainError> {
        let block = certificate.block_ref::<H>();
        let applied = self
            .da
            .chains
            .get(block.chain().index())
            .ok_or(ChainError::Context)?
            .data_retired_through;
        if retired < applied || retired > block.height() {
            return Err(ChainError::Context);
        }

        self.da.install_certificate(block, certificate.clone())?;
        self.da.retire(block, retired, self.pipeline_depth);
        if let Some(producer) = self
            .producer
            .as_mut()
            .filter(|producer| producer.chain == block.chain())
        {
            producer
                .headers
                .retain(|height, _| *height > block.height());
            if producer.produced.height() <= block.height() {
                self.advance_produced::<H>(block);
            }
        }
        // The block store and its validations live in the chain's chain plane: route the new
        // certified anchor so the plane settles them, and the surviving DA choices so its
        // eligibility read-copy tracks this durable retirement.
        self.capabilities.push(Capability::Validator(
            block.chain(),
            ValidatorCommand::AnchorAdvanced(block),
        ));
        self.emit_validator_chosen(block.chain());
        Ok(())
    }

    /// Routes a chain's current durable DA choices above the anchor to its chain plane so the
    /// plane's eligibility read-copy stays a lower-bound mirror of the machine's durable record.
    fn emit_validator_chosen(&mut self, chain: ChainId) {
        let choices = self.da.choices_above_floor(chain);
        self.capabilities.push(Capability::Validator(
            chain,
            ValidatorCommand::Chosen(choices),
        ));
    }

    /// Returns the greatest locally usable, DA-certified, and locally DA-voted height on every
    /// chain.
    pub(crate) fn tip_heights(&self) -> Vec<ChainHeights> {
        self.da
            .genesis
            .iter()
            .zip(&self.da.chains)
            .enumerate()
            .map(|(index, (floor, chain))| {
                let certified = chain.certified_height();

                // The chain plane owns the block store; its offered run's reach is the
                // highest locally validated height the machine still tracks for this chain.
                let locally_valid = Some(chain.ready_through);
                let da_voted = chain
                    .local_da_votes
                    .last_key_value()
                    .map(|(height, _)| *height);
                let produced = self
                    .producer
                    .as_ref()
                    .map(|producer| producer.produced)
                    .filter(|tip| tip.chain().index() == index)
                    .map(|tip| tip.height());
                let known = [
                    Some(floor.height()),
                    Some(certified),
                    locally_valid,
                    da_voted,
                    produced,
                ]
                .into_iter()
                .flatten()
                .max()
                .expect("every chain has a floor");

                // Retention drops DA votes at or below the retired frontier, so an empty vote map
                // reports that frontier rather than dipping back to the genesis floor.
                let da_voted =
                    da_voted.unwrap_or_else(|| chain.data_retired_through.max(floor.height()));

                ChainHeights {
                    known,
                    certified,
                    da_voted,
                }
            })
            .collect()
    }

    /// Records a verified producer header, DA vote, or DA certificate.
    pub(crate) fn observe<H: Hasher<Digest = D>>(
        &mut self,
        id: ArtifactId<D>,
        observation: Observation,
        artifact: &Artifact<V, D>,
    ) -> Result<(), ChainError> {
        let block_ref = match artifact {
            Artifact::TransactionBlock(block) => Some(block.header().block_ref::<H>()),
            Artifact::DaVote(vote) => Some(vote.header().block_ref::<H>()),
            Artifact::DaCertificate(certificate) => Some(certificate.block_ref::<H>()),
            _ => None,
        };
        if block_ref.is_some_and(|block| {
            self.da
                .genesis
                .get(block.chain().index())
                .is_some_and(|genesis| block.height() <= genesis.height())
        }) {
            return Ok(());
        }
        match artifact {
            Artifact::TransactionBlock(block) => {
                // The machine records producer ancestry before the block leaves for its chain's
                // chain plane, so observation identity and order stay with the machine. The block
                // store and application validation live in the plane. Competing blocks at one
                // height are all routed; accountability, not this check, handles the equivocation.
                if !self.da.record_header::<H>(block.header())? {
                    return Err(ChainError::ProducerConflict);
                }
                let custodied = self.is_producer_header(block.header());
                self.capabilities.push(Capability::Validator(
                    block.header().chain(),
                    ValidatorCommand::Observe(ObservedBlock {
                        id,
                        observation,
                        block: Arc::new(block.clone()),
                        custodied,
                    }),
                ));
            }
            Artifact::DaVote(vote) => {
                // Shares are only useful to the chain's producer; its DA recovery task pools them
                // and decides recovery. The machine keeps minting their observation identity.
                if self
                    .producer
                    .as_ref()
                    .is_some_and(|producer| producer.chain == vote.header().chain())
                {
                    self.capabilities
                        .push(Capability::OwnChainDa(ChainCommand::Observe(Arc::new(
                            vote.clone(),
                        ))));
                }
            }
            Artifact::DaCertificate(certificate) => {
                if !self.da.record_header::<H>(certificate.header())? {
                    return Err(ChainError::CertifiedConflict);
                }
                self.da
                    .observe_certificate::<H>(id, observation, certificate)?;
            }
            _ => return Ok(()),
        }
        Ok(())
    }

    /// Drops the state an artifact that failed verification left behind.
    pub(crate) fn reject_unverified<H: Hasher<Digest = D>>(
        &mut self,
        id: ArtifactId<D>,
        artifact: &Artifact<V, D>,
    ) -> Result<(), ChainError> {
        match artifact {
            // A block is routed to its chain plane only after producer-signature verification,
            // so a rejected-unverified block was never stored by the machine nor routed: nothing
            // to drop.
            Artifact::TransactionBlock(_) => {}
            Artifact::DaCertificate(certificate) => {
                self.da.reject_certificate::<H>(id, certificate)?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Returns every application payload whose recovered local authority requires reverification.
    pub(crate) fn recovered_payloads(&self) -> Vec<(Context<D>, D)> {
        let mut headers = self
            .producer
            .iter()
            .flat_map(|producer| producer.headers.values())
            .chain(
                self.da
                    .chains
                    .iter()
                    .flat_map(|chain| chain.local_da_votes.values())
                    .map(DaChoice::header),
            )
            .cloned()
            .collect::<Vec<_>>();
        headers.sort_by_key(|header| {
            (
                header.chain(),
                header.height(),
                header.parent(),
                header.body_digest(),
            )
        });
        headers.dedup();
        headers
            .iter()
            .map(|header| (Context::from(header), header.body_digest()))
            .collect()
    }

    /// Records one durable DA choice and routes the surviving choices to its chain plane.
    pub(crate) fn observe_da_choice<H: Hasher<Digest = D>>(
        &mut self,
        header: &TransactionBlockHeader<D>,
    ) -> Result<(), ChainError> {
        self.da.observe_choice::<H>(header)?;
        self.emit_validator_chosen(header.chain());
        Ok(())
    }

    /// Returns the eligible data-availability votes a validator may reserve; see
    /// [`DaState::ready_votes`].
    pub(crate) fn ready_da_votes(
        &self,
        limit: usize,
        run_limit: usize,
    ) -> Vec<Arc<SignedTransactionBlock<V, D>>> {
        if self.me.is_none() {
            return Vec::new();
        }
        self.da.ready_votes(limit, run_limit)
    }

    /// Returns the chain of the first offered eligible vote `select` accepts, for a validator.
    pub(crate) fn selected_da_chain(
        &self,
        select: impl FnMut(ChainId, Height) -> bool,
    ) -> Option<ChainId> {
        self.me?;
        self.da.selected_chain(select)
    }

    /// Takes the work issued since the last call.
    pub(crate) fn take_capabilities(&mut self) -> Capabilities<V, D> {
        std::mem::take(&mut self.capabilities)
    }
}

/// A malformed application completion or contradictory chain fact.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ChainError {
    #[error("chain object is outside the configured epoch context")]
    Context,
    #[error("chain job identifier exhausted")]
    IdentifierExhausted,
    #[error("chain height overflow")]
    HeightOverflow,
    #[error("application completion does not match its exact job")]
    CompletionMismatch,
    #[error("conflicting data-availability certificates were admitted")]
    CertifiedConflict,
    #[error("local producer choices conflict")]
    ProducerConflict,
    #[error("local data-availability vote choices conflict")]
    DaVoteConflict,
    #[error("signing reservation failed: {0}")]
    Reservation(ReservationError),
}
