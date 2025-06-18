/// Messages that can be sent to the peer [super::Actor].
#[derive(Clone, Debug)]
pub enum Message {
    /// Kill the peer actor.
    Kill,
}
