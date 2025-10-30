use bytes::Bytes;
use commonware_cryptography::PublicKey;
use commonware_p2p::{Receiver, Recipients, Sender};
use futures::{
    channel::mpsc::{self},
    future::try_join,
    select_biased, FutureExt as _, SinkExt, StreamExt as _,
};
use std::future::Future;
use thiserror::Error;

/// The possible errors that `self_channel` will produce.
#[derive(Debug, Error)]
pub enum Error {
    #[error("network error: {0}")]
    NetworkError(#[from] anyhow::Error),
    #[error("the receiver has closed")]
    ReceiverClosed,
}

/// A [Sender] allowing messages sent to yourself.
#[derive(Clone, Debug)]
pub struct SelfSender<P, S> {
    me: P,
    bypass: mpsc::Sender<Bytes>,
    inner: S,
}

impl<P: PublicKey, S: Sender<PublicKey = P>> Sender for SelfSender<P, S> {
    type Error = Error;

    type PublicKey = P;

    fn send(
        &mut self,
        recipients: Recipients<Self::PublicKey>,
        message: Bytes,
        priority: bool,
    ) -> impl Future<Output = Result<Vec<Self::PublicKey>, Self::Error>> + Send {
        async move {
            let (send_to_self, remaining) = match recipients {
                Recipients::All => (true, Recipients::All),
                Recipients::Some(mut items) => {
                    let old_len = items.len();
                    items.retain(|x| x != &self.me);
                    (items.len() < old_len, Recipients::Some(items))
                }
                Recipients::One(x) if &x == &self.me => (true, Recipients::Some(Vec::new())),
                Recipients::One(x) => (false, Recipients::One(x)),
            };
            let self_message = message.clone();
            let send_self_fut = async {
                if send_to_self {
                    self.bypass
                        .send(self_message)
                        .await
                        .map_err(|_| Error::ReceiverClosed)?;
                    Ok(true)
                } else {
                    Ok(false)
                }
            };
            let send_others_fut = async {
                self.inner
                    .send(remaining, message, priority)
                    .await
                    .map_err(|e| Error::NetworkError(e.into()))
            };
            let (sent_to_self, mut others) = try_join(send_self_fut, send_others_fut).await?;
            if sent_to_self {
                others.push(self.me.clone());
            }
            Ok(others)
        }
    }
}

/// A [Receiver] allowing messages sent to yourself.
#[derive(Debug)]
pub struct SelfReceiver<P, R> {
    me: P,
    bypass: mpsc::Receiver<Bytes>,
    inner: R,
}

impl<P: PublicKey, R: Receiver<PublicKey = P>> Receiver for SelfReceiver<P, R> {
    type Error = Error;

    type PublicKey = P;

    fn recv(
        &mut self,
    ) -> impl Future<Output = Result<commonware_p2p::Message<Self::PublicKey>, Self::Error>> + Send
    {
        async {
            select_biased! {
                msg = self.bypass.select_next_some() => Ok((self.me.clone(), msg)),
                res = self.inner.recv().fuse() => res.map_err(|e| Error::NetworkError(e.into())),
            }
        }
    }
}

/// Create a channel which allows sending messages to yourself.
///
/// `me` is your public key, identifying you.
/// `buffer_size` controls the size of the buffer for messages sent to yourself.
/// `sender` and `receiver` are the underlying channel, for messages directed
/// towards other people.
pub fn self_channel<P: PublicKey, S: Sender<PublicKey = P>, R: Receiver<PublicKey = P>>(
    me: P,
    buffer_size: usize,
    sender: S,
    receiver: R,
) -> (SelfSender<P, S>, SelfReceiver<P, R>) {
    let (bypass_in, bypass_out) = mpsc::channel(buffer_size);
    (
        SelfSender {
            me: me.clone(),
            bypass: bypass_in,
            inner: sender,
        },
        SelfReceiver {
            me: me.clone(),
            bypass: bypass_out,
            inner: receiver,
        },
    )
}
