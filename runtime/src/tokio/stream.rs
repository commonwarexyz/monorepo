use tokio::{io::AsyncReadExt as _, net::tcp::OwnedReadHalf, time::timeout};

use crate::Error;

use super::Context;

/// Implementation of [`crate::Stream`] for the `tokio` runtime.
pub struct Stream {
    pub(super) context: Context,
    pub(super) stream: OwnedReadHalf,
}

impl crate::Stream for Stream {
    async fn recv(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        // Wait for the stream to be readable
        timeout(
            self.context.executor.cfg.read_timeout,
            self.stream.read_exact(buf),
        )
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|_| Error::RecvFailed)?;

        // Record metrics
        self.context
            .executor
            .metrics
            .inbound_bandwidth
            .inc_by(buf.len() as u64);

        Ok(())
    }
}
