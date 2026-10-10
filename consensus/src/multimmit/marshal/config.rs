//! Marshal configuration.

use crate::multimmit::{
    config::Parameters,
    order::Lanes,
    types::{CodecConfig, EpochGenesis},
};
use commonware_cryptography::Digest;
use commonware_runtime::buffer::paged::CacheRef;
use commonware_utils::{NZU64, NZUsize};
use std::num::{NonZeroU64, NonZeroUsize};

/// Resource bounds of one marshal instance.
///
/// Every bound is a memory, disk or bandwidth budget; none decides correctness. Defaults derive
/// from [`Limits::max_block_bytes`] where a bound must fit whole blocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Largest encoded block, header included.
    pub max_block_bytes: NonZeroUsize,
    /// Most delivered outputs awaiting the application's acknowledgement.
    pub max_pending_acks: NonZeroUsize,
    /// Most final blocks of one chain handed out at a time to report as
    /// [`Update::Final`](super::Update::Final), and the spacing of the references kept on the way
    /// to a far final tip.
    pub final_lookahead: NonZeroUsize,
    /// Most requests queued from the public mailbox.
    pub mailbox_size: NonZeroUsize,
    /// Bytes of staged blocks accepted and not yet appended to the custody stream; staging more
    /// fails with [`Error::Busy`](super::Error::Busy) until appends catch up. One block is
    /// always accepted.
    pub max_staged_bytes: NonZeroUsize,
    /// Largest value one resolver response carries.
    pub max_response_bytes: NonZeroUsize,
    /// Bytes of block bodies kept in memory ahead of delivery.
    pub max_hot_bytes: NonZeroUsize,
    /// Bytes of block fetches in flight.
    pub max_fetch_bytes: NonZeroUsize,
    /// Most peer requests served at once.
    pub max_serving: NonZeroUsize,
    /// Bytes of history records waiting in the consensus feed before marshal fails rather than
    /// lose them.
    pub max_record_backlog_bytes: NonZeroUsize,
    /// Blocks per storage segment; fixed when the namespace is created.
    pub blocks_per_segment: NonZeroU64,
    /// Proof parts per storage segment; fixed when the namespace is created.
    pub proofs_per_segment: NonZeroU64,
    /// Bytes buffered by each journal writer.
    pub write_buffer: NonZeroUsize,
    /// Bytes buffered while replaying index journals, and the read-ahead of value reads.
    pub replay_buffer: NonZeroUsize,
}

impl Default for Limits {
    fn default() -> Self {
        Self::for_block_bytes(NZUsize!(1024 * 1024))
    }
}

/// The memory a marshal holds by default: see [`Limits::within_memory`].
const DEFAULT_MEMORY_BYTES: NonZeroUsize = NZUsize!(1024 * 1024 * 1024);

/// Journal writers: the custody and bulk block streams and the proofs log.
const WRITERS: usize = 3;

impl Limits {
    /// Returns the default bounds for blocks of at most `max_block_bytes`, sized within 1 GiB of
    /// memory (see [`Self::within_memory`]).
    pub fn for_block_bytes(max_block_bytes: NonZeroUsize) -> Self {
        let block = max_block_bytes.get();
        // Segments of about 128 MiB; responses of 16 blocks.
        let blocks_per_segment = (128 * 1024 * 1024 / block).max(16) as u64;
        Self {
            max_block_bytes,
            max_pending_acks: NZUsize!(128),
            final_lookahead: NZUsize!(128),
            mailbox_size: NZUsize!(1024),
            max_staged_bytes: max_block_bytes,
            max_response_bytes: NonZeroUsize::new(16 * block + 64).expect("nonzero"),
            max_hot_bytes: max_block_bytes,
            max_fetch_bytes: max_block_bytes,
            max_serving: NZUsize!(16),
            max_record_backlog_bytes: max_block_bytes,
            blocks_per_segment: NonZeroU64::new(blocks_per_segment).expect("nonzero"),
            proofs_per_segment: NZU64!(1024),
            write_buffer: NZUsize!(1024 * 1024),
            replay_buffer: NZUsize!(1024 * 1024),
        }
        .within_memory(DEFAULT_MEMORY_BYTES)
    }

    /// Returns these bounds with the memory budgets sized so that [`Self::memory_bound`] is at
    /// most `memory_bytes`, or as close to it as one block per budget allows.
    ///
    /// The fixed parts (delivered blocks awaiting acknowledgement, responses being served, and
    /// journal buffers) are taken first. Of the rest, bodies held ahead of delivery and fetches
    /// in flight take three eighths each, and staged blocks and the record backlog one eighth
    /// each. Each budget holds at least what one block or one response needs; a budget raised to
    /// that floor takes it from the others in proportion, so the bound is exceeded only when the
    /// fixed parts and the floors alone exceed `memory_bytes`.
    pub fn within_memory(mut self, memory_bytes: NonZeroUsize) -> Self {
        let block = self.max_block_bytes.get();
        let share = memory_bytes.get().saturating_sub(self.fixed_memory());
        // Hot bodies, fetches, staged blocks and the record backlog.
        let weights = [3, 3, 1, 1];
        let floors = [block, self.max_response_bytes.get(), block, block];
        let mut sizes = floors;
        let mut floored = [false; 4];
        // Every pass that raises a budget to its floor lowers the others' level, so at most four
        // passes settle.
        loop {
            let (taken, weight) = (0..4).fold((0usize, 0usize), |(taken, weight), i| {
                if floored[i] {
                    (taken.saturating_add(floors[i]), weight)
                } else {
                    (taken, weight + weights[i])
                }
            });
            if weight == 0 {
                break;
            }
            let rest = share.saturating_sub(taken);
            let mut settled = true;
            for i in 0..4 {
                if floored[i] {
                    continue;
                }
                let size = rest / weight * weights[i];
                if size < floors[i] {
                    floored[i] = true;
                    settled = false;
                }
                sizes[i] = size.max(floors[i]);
            }
            if settled {
                break;
            }
        }
        let [hot, fetch, staged, backlog] =
            sizes.map(|size| NonZeroUsize::new(size).expect("floors are non-zero"));
        self.max_hot_bytes = hot;
        self.max_fetch_bytes = fetch;
        self.max_staged_bytes = staged;
        self.max_record_backlog_bytes = backlog;
        self
    }

    /// Returns the most bytes of blocks, responses, records and buffers these bounds let one
    /// marshal hold in memory at once.
    ///
    /// Indexes of retained blocks and records come on top and grow with what the application
    /// retains (about 130 bytes per held block).
    pub const fn memory_bound(&self) -> usize {
        self.fixed_memory()
            .saturating_add(self.max_hot_bytes.get())
            .saturating_add(self.max_fetch_bytes.get())
            .saturating_add(self.max_staged_bytes.get())
            .saturating_add(self.max_record_backlog_bytes.get())
    }

    /// Returns the memory the bounds hold regardless of the budget: delivered blocks awaiting
    /// acknowledgement, responses being served, and journal buffers.
    const fn fixed_memory(&self) -> usize {
        let delivered = self
            .max_pending_acks
            .get()
            .saturating_mul(self.max_block_bytes.get());
        let serving = self
            .max_serving
            .get()
            .saturating_mul(self.max_response_bytes.get());
        let buffers = self
            .write_buffer
            .get()
            .saturating_mul(WRITERS)
            .saturating_add(self.replay_buffer.get());
        delivered.saturating_add(serving).saturating_add(buffers)
    }
}

/// Configuration of one marshal instance (one epoch).
pub struct Config<D: Digest, C> {
    /// The epoch's genesis: its history and its synthetic height-zero tips.
    pub genesis: EpochGenesis<D>,
    /// Prefix of every partition; ASCII letters, digits and underscores. Also a metric label.
    pub partition_prefix: String,
    /// Page cache for index journals.
    pub page_cache: CacheRef,
    /// Bounds used to decode Multimmit certificates and records.
    pub codec_config: CodecConfig,
    /// Bounds used to decode block bodies.
    pub body_codec_config: C,
    /// Resource bounds.
    pub limits: Limits,
    /// Whether each chain is a payment chain, in chain order, or empty when none is.
    ///
    /// Every opening and sweep of the order visits the payment chains first, so this must match
    /// the epoch's consensus parameters on every node: set it with [`Self::with_payments`].
    pub payment_chains: Vec<bool>,
}

/// A configuration that cannot run.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// The partition prefix is empty or holds characters other than letters, digits and
    /// underscores.
    #[error("invalid partition prefix")]
    InvalidPartitionPrefix,
    /// The genesis names another number of chains than the codec configuration.
    #[error("genesis and codec configuration disagree on the chain count")]
    ChainCount,
    /// The payment chains name another number of chains than the codec configuration.
    #[error("payment chains and codec configuration disagree on the chain count")]
    PaymentChains,
    /// A response cannot carry one maximum-size block.
    #[error("responses cannot carry one maximum-size block")]
    ResponseTooSmall,
    /// Fetches cannot carry one maximum-size response.
    #[error("the fetch budget cannot carry one maximum-size response")]
    FetchTooSmall,
}

impl<D: Digest, C> Config<D, C> {
    /// Creates a configuration with default [`Limits`] and no payment chains.
    pub fn new(
        genesis: EpochGenesis<D>,
        partition_prefix: String,
        page_cache: CacheRef,
        codec_config: CodecConfig,
        body_codec_config: C,
    ) -> Self {
        Self {
            genesis,
            partition_prefix,
            page_cache,
            codec_config,
            body_codec_config,
            limits: Limits::default(),
            payment_chains: Vec::new(),
        }
    }

    /// Orders the payment chains of the epoch `parameters` configure first, as consensus does
    /// (see [`Parameters::payment_chain`]). Without payments in `parameters`, no chain is one.
    pub fn with_payments(mut self, parameters: &Parameters) -> Self {
        self.payment_chains = Lanes::from_parameters(parameters).to_mask();
        self
    }

    /// Replaces the resource bounds.
    pub const fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Checks that the configuration can run.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.partition_prefix.is_empty()
            || !self
                .partition_prefix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(ConfigError::InvalidPartitionPrefix);
        }
        if self.genesis.tips().len() != self.codec_config.chains() {
            return Err(ConfigError::ChainCount);
        }
        if !self.payment_chains.is_empty()
            && self.payment_chains.len() != self.codec_config.chains()
        {
            return Err(ConfigError::PaymentChains);
        }
        let limits = &self.limits;
        // A count prefix of at most nine bytes precedes the blocks of a response.
        if limits.max_response_bytes.get() < limits.max_block_bytes.get().saturating_add(9) {
            return Err(ConfigError::ResponseTooSmall);
        }
        if limits.max_fetch_bytes < limits.max_response_bytes {
            return Err(ConfigError::FetchTooSmall);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multimmit::{
        mocks::{Bls, Committee},
        types::PathLimits,
    };
    use commonware_cryptography::bls12381::primitives::variant::MinPk;
    use commonware_utils::NZU16;
    use std::sync::Arc;

    #[test]
    fn payment_chains_follow_the_parameters_and_name_every_chain() {
        let committee = Committee::<Bls<MinPk>>::builder(1, 6)
            .producers((0..3).map(crate::types::Participant::new).collect())
            .chain_limits(vec![
                PathLimits::new(2, 1),
                PathLimits::new(0, 0),
                PathLimits::new(0, 1),
            ])
            .build();
        let config = || {
            Config::new(
                committee.config.genesis().clone(),
                "marshal".into(),
                CacheRef::new(NZU16!(1024), NZUsize!(8)),
                committee.codec(),
                (),
            )
        };
        // Off by default, and off while the parameters run no payments.
        assert!(config().payment_chains.is_empty());
        let parameters = Arc::unwrap_or_clone(Arc::clone(committee.config.parameters()));
        assert!(
            config()
                .with_payments(&parameters)
                .payment_chains
                .is_empty()
        );

        let paying = config().with_payments(&parameters.with_payments(true));
        assert_eq!(paying.payment_chains, vec![false, true, false]);
        assert_eq!(paying.validate(), Ok(()));
        let mut short = paying;
        short.payment_chains = vec![true];
        assert_eq!(short.validate(), Err(ConfigError::PaymentChains));
    }

    #[test]
    fn budgets_fit_the_memory_they_are_sized_within() {
        for block in [64 * 1024, 300 * 1024, 1024 * 1024, 4 * 1024 * 1024] {
            let block = NonZeroUsize::new(block).unwrap();
            for memory in [512 << 20, 1 << 30, 12 << 30] {
                let limits = Limits::for_block_bytes(block)
                    .within_memory(NonZeroUsize::new(memory).unwrap());
                // A budget too small for the fixed parts and one block or response per budget
                // is exceeded by exactly those floors.
                if limits.fixed_memory() + 3 * block.get() + limits.max_response_bytes.get()
                    <= memory
                {
                    assert!(
                        limits.memory_bound() <= memory,
                        "block {block} memory {memory}"
                    );
                }
                // Every budget still fits one block, and fetches one response.
                assert!(limits.max_hot_bytes >= block && limits.max_staged_bytes >= block);
                assert!(limits.max_fetch_bytes >= limits.max_response_bytes);
            }
        }
    }

    #[test]
    fn floors_take_from_the_other_budgets_rather_than_exceed_the_memory() {
        let block = NZUsize!(1024 * 1024);
        let limits = Limits::for_block_bytes(block);
        let floors = 3 * block.get() + limits.max_response_bytes.get();
        // Just above the fixed parts the fetch floor exceeds its share: the others shrink.
        for extra in [floors, floors + 1, 20 << 20, 32 << 20, 33 << 20, 64 << 20, 200 << 20] {
            let memory = limits.fixed_memory() + extra;
            let sized = limits.within_memory(NonZeroUsize::new(memory).unwrap());
            assert!(sized.memory_bound() <= memory, "extra {extra}");
            assert!(sized.max_hot_bytes >= block && sized.max_staged_bytes >= block);
            assert!(sized.max_record_backlog_bytes >= block);
            assert!(sized.max_fetch_bytes >= sized.max_response_bytes);
        }
        // Below the floors, each budget holds exactly its floor.
        let sized = limits.within_memory(NonZeroUsize::new(limits.fixed_memory() + 1).unwrap());
        assert_eq!(sized.memory_bound(), limits.fixed_memory() + floors);
    }

    #[test]
    fn a_tiny_budget_keeps_one_block_per_budget() {
        let block = NZUsize!(1024 * 1024);
        let limits = Limits::for_block_bytes(block).within_memory(NZUsize!(1));
        assert_eq!(limits.max_hot_bytes, block);
        assert_eq!(limits.max_staged_bytes, block);
        assert_eq!(limits.max_record_backlog_bytes, block);
        assert_eq!(limits.max_fetch_bytes, limits.max_response_bytes);
    }
}
