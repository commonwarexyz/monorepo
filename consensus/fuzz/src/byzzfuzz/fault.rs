//! ByzzFuzz fault data types. Sampling lives in [`super::sampling`].

use crate::{
    byzzfuzz::{intercept::InterceptChannel, scope::MessageScope},
    utils::SetPartition,
};
use commonware_consensus::types::View;
use commonware_cryptography::PublicKey;

/// What a matching process fault does after the message-scope filter selects
/// a byzantine outbound message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessAction {
    /// Drop the targeted delivery and emit no replacement.
    Omit,
    /// Mutate a vote semantically and re-sign under the byzantine key.
    MutateVote,
}

impl ProcessAction {
    pub fn supports_channel(self, channel: InterceptChannel) -> bool {
        match self {
            ProcessAction::Omit => true,
            ProcessAction::MutateVote => matches!(channel, InterceptChannel::Vote),
        }
    }
}

/// A single ByzzFuzz process fault. When the decoded view carried by a
/// byzantine outbound message equals `view`, deliveries to anyone in
/// `receivers` whose channel/kind matches `scope` are intercepted. The
/// forwarder drops the original to those receivers only after the intercept is
/// enqueued successfully; the injector then executes `action`.
#[derive(Clone, Debug)]
pub struct ProcessFault<P: PublicKey> {
    pub view: u64,
    pub receivers: Vec<P>,
    pub action: ProcessAction,
    pub scope: MessageScope,
}

/// A single ByzzFuzz network fault. When the message sender's `rnd(m)`
/// equals `view`, all messages on every channel are dropped between blocks
/// of `partition` -- network partitions are total at their round; no
/// per-channel/kind targeting.
#[derive(Clone, Copy, Debug)]
pub struct NetworkFault {
    pub view: View,
    pub partition: SetPartition,
}
