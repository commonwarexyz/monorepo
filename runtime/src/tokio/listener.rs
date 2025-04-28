use super::{sink::Sink, stream::Stream, Context};
use crate::Error;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tracing::warn;

/// Implementation of [`crate::Listener`] for the `tokio` runtime.
pub struct Listener {
    pub(super) context: Context,
    pub(super) listener: TcpListener,
}

impl crate::Listener<Sink, Stream> for Listener {
    async fn accept(&mut self) -> Result<(SocketAddr, Sink, Stream), Error> {
        // Accept a new TCP stream
        let (stream, addr) = self.listener.accept().await.map_err(|_| Error::Closed)?;
        self.context.executor.metrics.inbound_connections.inc();

        // Set TCP_NODELAY if configured
        if let Some(tcp_nodelay) = self.context.executor.cfg.tcp_nodelay {
            if let Err(err) = stream.set_nodelay(tcp_nodelay) {
                warn!(?err, "failed to set TCP_NODELAY");
            }
        }

        // Return the sink and stream
        let context = self.context.clone();
        let (stream, sink) = stream.into_split();
        Ok((
            addr,
            Sink {
                context: context.clone(),
                sink,
            },
            Stream { context, stream },
        ))
    }
}

impl axum::serve::Listener for Listener {
    type Io = TcpStream;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        let (stream, addr) = self.listener.accept().await.unwrap();
        (stream, addr)
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}
