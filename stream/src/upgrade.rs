//! Pair a [Handshake] with a [Transport].

use crate::{Handshake, Transport, Upgrader};
use commonware_runtime::{BufferPooler, Clock, Sink, Stream};
use rand_core::CryptoRng;
use std::future::Future;

/// Runs the handshake `H`, then keys the transport `T` with the agreed ciphers.
impl<H, T> Upgrader for (H, T)
where
    H: Handshake,
    T: Transport,
{
    const MAX_SIZE: u32 = T::MAX_SIZE;

    type PublicKey = H::PublicKey;
    type Error = H::Error;
    type Sender<I: Stream, O: Sink> = T::Sender<O>;
    type Receiver<I: Stream, O: Sink> = T::Receiver<I>;

    fn public_key(&self) -> Self::PublicKey {
        self.0.public_key()
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
        let (handshake, transport) = self;

        // Agree on ciphers bound to this transport, then key it on the same connection.
        let (send, recv) = handshake
            .dial(
                context,
                namespace,
                transport.namespace(),
                peer,
                &mut stream,
                &mut sink,
            )
            .await?;
        Ok(transport.split(send, recv, stream, sink, max_message_size, pool))
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
        let (handshake, transport) = self;

        // Agree on ciphers bound to this transport, then key it on the same connection.
        let (peer, send, recv) = handshake
            .listen(
                context,
                namespace,
                transport.namespace(),
                bouncer,
                &mut stream,
                &mut sink,
            )
            .await?;
        let (sender, receiver) = transport.split(send, recv, stream, sink, max_message_size, pool);
        Ok((peer, sender, receiver))
    }
}
