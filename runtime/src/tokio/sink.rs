use tokio::{io::AsyncWriteExt as _, net::tcp::OwnedWriteHalf, time::timeout};

use crate::Error;

use super::Context;

/// Implementation of [crate::Sink] for the `tokio` runtime.
pub struct Sink {
    pub(super) context: Context,
    pub(super) sink: OwnedWriteHalf,
}

impl crate::Sink for Sink {
    async fn send(&mut self, msg: &[u8]) -> Result<(), Error> {
        let len = msg.len();
        timeout(
            self.context.executor.cfg.write_timeout,
            self.sink.write_all(msg),
        )
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|_| Error::SendFailed)?;
        self.context
            .executor
            .metrics
            .outbound_bandwidth
            .inc_by(len as u64);
        Ok(())
    }
}
