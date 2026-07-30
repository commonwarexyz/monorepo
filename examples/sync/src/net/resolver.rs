use super::{io, wire};
use crate::net::request_id;
use commonware_codec::{EncodeShared, IsUnit, Read};
use commonware_cryptography::Digest;
use commonware_runtime::{Network, Spawner};
use commonware_storage::{
    mmr,
    qmdb::sync::{self, compact},
};
use commonware_utils::channel::{mpsc, oneshot};

/// Network resolver that works directly with generic wire messages.
#[derive(Clone)]
pub struct Resolver<Op, D>
where
    Op: Read + EncodeShared + 'static,
    Op::Cfg: IsUnit,
    D: Digest,
{
    request_id_generator: request_id::Generator,
    request_tx: mpsc::Sender<io::Request<wire::Message<Op, D>>>,
}

impl<Op, D> Resolver<Op, D>
where
    Op: Read + EncodeShared,
    Op::Cfg: IsUnit,
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
    pub async fn get_sync_target(&self) -> Result<sync::Target<mmr::Family, D>, crate::Error> {
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

    /// Returns the compact sync target currently served by the remote.
    pub async fn get_compact_target(
        &self,
    ) -> Result<compact::Target<mmr::Family, D>, crate::Error> {
        let request_id = self.request_id_generator.next();
        let request =
            wire::Message::GetCompactTargetRequest(wire::GetCompactTargetRequest { request_id });
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
            wire::Message::GetCompactTargetResponse(r) => Ok(r.target),
            wire::Message::Error(err) => Err(crate::Error::Server {
                code: err.error_code,
                message: err.message,
            }),
            _ => Err(crate::Error::UnexpectedResponse { request_id }),
        }
    }

    /// Returns compact authenticated state for the given target.
    pub async fn get_compact_state(
        &self,
        target: compact::Target<mmr::Family, D>,
    ) -> Result<sync::Response<mmr::Family, Op, D>, crate::Error> {
        let request_id = self.request_id_generator.next();
        let request = wire::Message::GetCompactStateRequest(wire::GetCompactStateRequest {
            request_id,
            target,
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
        match response {
            wire::Message::GetCompactStateResponse(r) => Ok(r.response),
            wire::Message::Error(err) => Err(crate::Error::Server {
                code: err.error_code,
                message: err.message,
            }),
            _ => Err(crate::Error::UnexpectedResponse { request_id }),
        }
    }
}

impl<Op, D> sync::Source<sync::Request<mmr::Family>> for Resolver<Op, D>
where
    Op: Clone + Read + EncodeShared,
    Op::Cfg: IsUnit,
    D: Digest,
{
    type Family = mmr::Family;
    type Digest = D;
    type Op = Op;
    type Error = crate::Error;

    async fn serve(
        &self,
        request: sync::Request<mmr::Family>,
    ) -> Result<
        (
            sync::Response<Self::Family, Self::Op, Self::Digest>,
            sync::ValidityTx,
        ),
        Self::Error,
    > {
        let request_id = self.request_id_generator.next();
        let message = wire::Message::GetOperationsRequest(wire::GetOperationsRequest {
            request_id,
            op_count: request.size,
            start_loc: request.start,
            max_ops: request.max_ops,
            include_pinned_nodes: request.retain_from.is_some(),
        });
        let (tx, rx) = oneshot::channel();
        self.request_tx
            .clone()
            .send(io::Request {
                request: message,
                response_tx: tx,
            })
            .await
            .map_err(|_| crate::Error::RequestChannelClosed)?;
        let response = rx
            .await
            .map_err(|_| crate::Error::ResponseChannelClosed { request_id })??;
        match response {
            wire::Message::GetOperationsResponse(r) => Ok((
                sync::Response {
                    proof: r.proof,
                    operations: r.operations,
                    pinned_nodes: r.pinned_nodes,
                },
                None,
            )),
            wire::Message::Error(err) => Err(crate::Error::Server {
                code: err.error_code,
                message: err.message,
            }),
            _ => Err(crate::Error::UnexpectedResponse { request_id }),
        }
    }
}

impl<Op, D> sync::Source<compact::Target<mmr::Family, D>> for Resolver<Op, D>
where
    Op: Clone + Read + EncodeShared,
    Op::Cfg: IsUnit,
    D: Digest,
{
    type Family = mmr::Family;
    type Digest = D;
    type Op = Op;
    type Error = crate::Error;

    async fn serve(
        &self,
        target: compact::Target<mmr::Family, D>,
    ) -> Result<
        (
            sync::Response<Self::Family, Self::Op, Self::Digest>,
            sync::ValidityTx,
        ),
        Self::Error,
    > {
        Ok((self.get_compact_state(target).await?, None))
    }
}
