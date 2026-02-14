use super::config::Peer;
use commonware_runtime::tokio;

/// Transport-specific controls used by node wiring.
pub(crate) trait TransportControl {
    type Control: Clone;
    type Manager;

    fn control(&self, me: Peer) -> Self::Control;
    fn manager(&self) -> Self::Manager;
}

/// Runtime-specific dependencies that the node wiring relies on.
pub(crate) trait NodeEnvironment {
    type Transport: TransportControl;

    fn context(&self) -> tokio::Context;
    fn transport(&mut self) -> &mut Self::Transport;
}
