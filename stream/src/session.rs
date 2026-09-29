//! Pair an [Exchange] with [Records].

use crate::{Exchange, Handshake, Records};
use commonware_runtime::{BufferPooler, Clock, Sink, Stream};
use rand_core::CryptoRng;
use std::future::Future;

/// Implements [Handshake] by running the key exchange `K`, then keying the records `R` with the
/// agreed ciphers.
#[derive(Clone)]
pub struct Session<K, R> {
    exchange: K,
    records: R,
}

impl<K, R> Session<K, R> {
    /// Creates a session that runs `exchange` and keys `records`.
    pub const fn new(exchange: K, records: R) -> Self {
        Self { exchange, records }
    }

    /// Returns the key exchange.
    pub const fn exchange(&self) -> &K {
        &self.exchange
    }
}

impl<K, R> Handshake for Session<K, R>
where
    K: Exchange,
    R: Records,
{
    const MAX_SIZE: u32 = R::MAX_SIZE;

    type PublicKey = K::PublicKey;
    type Error = K::Error;
    type Sender<I: Stream, O: Sink> = R::Sender<O>;
    type Receiver<I: Stream, O: Sink> = R::Receiver<I>;

    fn public_key(&self) -> Self::PublicKey {
        self.exchange.public_key()
    }

    async fn dial<E, I, O>(
        self,
        context: E,
        namespace: &[u8],
        max_message_size: u32,
        peer: Self::PublicKey,
        mut stream: I,
        mut sink: O,
    ) -> Result<(Self::Sender<I, O>, Self::Receiver<I, O>), Self::Error>
    where
        E: BufferPooler + Clock + CryptoRng,
        I: Stream,
        O: Sink,
    {
        assert!(
            max_message_size <= Self::MAX_SIZE,
            "maximum message size exceeds stream limit"
        );
        let pool = context.network_buffer_pool().clone();
        let (send, recv) = self
            .exchange
            .dial(
                context,
                namespace,
                self.records.namespace(),
                peer,
                &mut stream,
                &mut sink,
            )
            .await?;
        Ok(self
            .records
            .split(send, recv, stream, sink, max_message_size, pool))
    }

    async fn listen<E, I, O, B, F>(
        self,
        context: E,
        namespace: &[u8],
        max_message_size: u32,
        bouncer: B,
        mut stream: I,
        mut sink: O,
    ) -> Result<(Self::PublicKey, Self::Sender<I, O>, Self::Receiver<I, O>), Self::Error>
    where
        E: BufferPooler + Clock + CryptoRng,
        I: Stream,
        O: Sink,
        B: FnOnce(Self::PublicKey) -> F + Send,
        F: Future<Output = bool> + Send,
    {
        assert!(
            max_message_size <= Self::MAX_SIZE,
            "maximum message size exceeds stream limit"
        );
        let pool = context.network_buffer_pool().clone();
        let (peer, send, recv) = self
            .exchange
            .listen(
                context,
                namespace,
                self.records.namespace(),
                bouncer,
                &mut stream,
                &mut sink,
            )
            .await?;
        let (sender, receiver) =
            self.records
                .split(send, recv, stream, sink, max_message_size, pool);
        Ok((peer, sender, receiver))
    }
}
