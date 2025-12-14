use super::{io, wire};
use crate::net::request_id;
use commonware_codec::{Encode, Read};
use commonware_cryptography::Digest;
use commonware_runtime::{Network, Spawner};
use commonware_storage::{mmr::Location, qmdb::sync};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};
use std::num::NonZeroU64;

/// Network resolver that works directly with generic wire messages.
#[derive(Clone)]
pub struct Resolver<Op, D>
where
    Op: Read<Cfg = ()> + Encode + Send + Sync + 'static,
    D: Digest,
{
    request_id_generator: request_id::Generator,
    request_tx: mpsc::Sender<io::Request<wire::Message<Op, D>>>,
}

impl<Op, D> Resolver<Op, D>
where
    Op: Send + Sync + Read<Cfg = ()> + Encode,
    D: Digest,
{
    /// Returns a resolver connected to the server at the given address.
    pub async fn connect<E>(
        context: E,
        server_addr: std::net::SocketAddr,
    ) -> Result<Self, commonware_runtime::Error>
    where
        E: Network + Spawner,
    {
        let (sink, stream) = context.dial(server_addr).await?;
        let (request_tx, _handle) = io::run(context, sink, stream)?;
        Ok(Self {
            request_id_generator: request_id::Generator::new(),
            request_tx,
        })
    }

    /// Returns the current sync target from the server.
    pub async fn get_sync_target(&self) -> Result<sync::Target<D>, crate::Error> {
        let request_id = self.request_id_generator.next();
        let request =
            wire::Message::GetSyncTargetRequest(wire::GetSyncTargetRequest { request_id });
        let (tx, rx) = oneshot::channel();
        self.request_tx
            .clone()
            .send(io::Request {
                request,
                response_tx: tx,
            })
            .await
            .map_err(|_| crate::Error::RequestChannelClosed)?;
        let response = rx
            .await
            .map_err(|_| crate::Error::ResponseChannelClosed { request_id })??;
        match response {
            wire::Message::GetSyncTargetResponse(r) => Ok(r.target),
            wire::Message::Error(err) => Err(crate::Error::Server {
                code: err.error_code,
                message: err.message,
            }),
            _ => Err(crate::Error::UnexpectedResponse { request_id }),
        }
    }
}

impl<Op, D> sync::resolver::Resolver for Resolver<Op, D>
where
    Op: Clone + Send + Sync + Read<Cfg = ()> + Encode,
    D: Digest,
{
    type Digest = D;
    type Op = Op;
    type Error = crate::Error;

    async fn get_operations(
        &self,
        op_count: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<sync::resolver::FetchResult<Self::Op, Self::Digest>, Self::Error> {
        let request_id = self.request_id_generator.next();
        let request = wire::Message::GetOperationsRequest(wire::GetOperationsRequest {
            request_id,
            op_count,
            start_loc,
            max_ops,
        });
        let (tx, rx) = oneshot::channel();
        self.request_tx
            .clone()
            .send(io::Request {
                request,
                response_tx: tx,
            })
            .await
            .map_err(|_| crate::Error::RequestChannelClosed)?;
        let response = rx
            .await
            .map_err(|_| crate::Error::ResponseChannelClosed { request_id })??;
        let (proof, operations) = match response {
            wire::Message::GetOperationsResponse(r) => (r.proof, r.operations),
            wire::Message::Error(err) => {
                return Err(crate::Error::Server {
                    code: err.error_code,
                    message: err.message,
                })
            }
            _ => return Err(crate::Error::UnexpectedResponse { request_id }),
        };
        let (tx, _rx) = oneshot::channel();
        Ok(sync::resolver::FetchResult {
            proof,
            operations,
            success_tx: tx,
        })
    }
}
