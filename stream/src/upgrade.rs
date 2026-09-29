//! Pair an [Exchange] with a [Transport].

use crate::{Exchange, Handshake, Transport};
use commonware_runtime::{BufferPooler, Clock, Sink, Stream};
use rand_core::CryptoRng;
use std::future::Future;

/// Implements [Handshake] by running the key exchange `K`, then keying the transport `T` with the
/// agreed ciphers.
#[derive(Clone)]
pub struct Upgrade<K, T> {
    exchange: K,
    transport: T,
}

impl<K, T> Upgrade<K, T> {
    /// Creates an upgrade that runs `exchange` and keys `transport`.
    pub const fn new(exchange: K, transport: T) -> Self {
        Self {
            exchange,
            transport,
        }
    }

    /// Returns the key exchange.
    pub const fn exchange(&self) -> &K {
        &self.exchange
    }
}

impl<K, T> Handshake for Upgrade<K, T>
where
    K: Exchange,
    T: Transport,
{
    const MAX_SIZE: u32 = T::MAX_SIZE;

    type PublicKey = K::PublicKey;
    type Error = K::Error;
    type Sender<I: Stream, O: Sink> = T::Sender<O>;
    type Receiver<I: Stream, O: Sink> = T::Receiver<I>;

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

        // Agree on ciphers bound to this transport, then key it on the same connection.
        let (send, recv) = self
            .exchange
            .dial(
                context,
                namespace,
                self.transport.namespace(),
                peer,
                &mut stream,
                &mut sink,
            )
            .await?;
        Ok(self
            .transport
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

        // Agree on ciphers bound to this transport, then key it on the same connection.
        let (peer, send, recv) = self
            .exchange
            .listen(
                context,
                namespace,
                self.transport.namespace(),
                bouncer,
                &mut stream,
                &mut sink,
            )
            .await?;
        let (sender, receiver) =
            self.transport
                .split(send, recv, stream, sink, max_message_size, pool);
        Ok((peer, sender, receiver))
    }
}
