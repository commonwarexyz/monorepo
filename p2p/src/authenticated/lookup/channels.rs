use super::actors::router::Messenger;
use crate::authenticated::channels as shared;

pub use shared::Error;

pub type Sender<P, C> = shared::Sender<Messenger<P>, C>;
pub type Receiver<P> = shared::Receiver<P>;
pub type Channels<P> = shared::Channels<Messenger<P>>;
