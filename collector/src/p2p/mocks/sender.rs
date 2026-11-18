//! Mock sender implementations for testing.

use commonware_actor::{Feedback, Unreliable};
use commonware_codec::ReadExt as _;
use commonware_cryptography::PublicKey;
use commonware_p2p::{CheckedSender, LimitedSender, Recipients};
use commonware_runtime::IoBufs;
use commonware_utils::sync::Mutex;
use std::{sync::Arc, time::SystemTime};

/// A sender that always returns [Feedback::Closed].
#[derive(Clone, Debug)]
pub struct Failing<P: PublicKey> {
    _phantom: std::marker::PhantomData<P>,
}

impl<P: PublicKey> Failing<P> {
    /// Creates a new failing sender.
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<P: PublicKey> LimitedSender for Failing<P> {
    type PublicKey = P;
    type Checked<'a> = CheckedFailing<P>;

    fn check(&mut self, _recipients: Recipients<P>) -> Result<Self::Checked<'_>, SystemTime> {
        Ok(CheckedFailing {
            _phantom: std::marker::PhantomData,
        })
    }
}

/// The [CheckedSender] of a [Failing] sender.
pub struct CheckedFailing<P: PublicKey> {
    _phantom: std::marker::PhantomData<P>,
}

impl<P: PublicKey> CheckedSender for CheckedFailing<P> {
    type PublicKey = P;

    fn recipients(&self) -> Vec<Self::PublicKey> {
        Vec::new()
    }

    fn send(self, _message: impl Into<IoBufs> + Send, _priority: bool) -> Unreliable<Feedback> {
        Unreliable::new(Feedback::Closed)
    }
}

/// Recipients, first payload byte, and priority of each send made through a [Recording] sender.
pub type Sent<P> = Arc<Mutex<Vec<(Recipients<P>, u8, bool)>>>;

/// A sender that records the recipients, first payload byte, and priority of every send and
/// reports each explicitly named recipient as sent to.
#[derive(Clone, Debug)]
pub struct Recording<P: PublicKey> {
    sent: Sent<P>,
}

impl<P: PublicKey> Recording<P> {
    /// Creates a recording sender and the log it appends to.
    pub fn new() -> (Self, Sent<P>) {
        let sent = Sent::<P>::default();
        (Self { sent: sent.clone() }, sent)
    }
}

impl<P: PublicKey> LimitedSender for Recording<P> {
    type PublicKey = P;
    type Checked<'a> = CheckedRecording<P>;

    fn check(&mut self, recipients: Recipients<P>) -> Result<Self::Checked<'_>, SystemTime> {
        Ok(CheckedRecording {
            sent: self.sent.clone(),
            recipients,
        })
    }
}

/// The [CheckedSender] of a [Recording] sender.
pub struct CheckedRecording<P: PublicKey> {
    sent: Sent<P>,
    recipients: Recipients<P>,
}

impl<P: PublicKey> CheckedSender for CheckedRecording<P> {
    type PublicKey = P;

    fn recipients(&self) -> Vec<Self::PublicKey> {
        match &self.recipients {
            Recipients::All => Vec::new(),
            Recipients::Some(peers) => peers.clone(),
            Recipients::One(peer) => vec![peer.clone()],
        }
    }

    fn send(self, message: impl Into<IoBufs> + Send, priority: bool) -> Unreliable<Feedback> {
        let mut payload: IoBufs = message.into();
        let first = u8::read(&mut payload).expect("a payload must not be empty");
        self.sent.lock().push((self.recipients, first, priority));
        Unreliable::new(Feedback::Ok)
    }
}
