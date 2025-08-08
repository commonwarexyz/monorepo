use super::{io, wire};
use crate::net::request_id;
use commonware_codec::{Encode, EncodeSize, Read, ReadExt, Write};
use commonware_cryptography::Digest;
use commonware_storage::adb::sync::Target;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};
use std::marker::PhantomData;
use std::num::NonZeroU64;

/// Network resolver that works directly with generic wire messages.
#[derive(Clone)]
pub struct Resolver<E, Op, D>
where
    E: commonware_runtime::Network
        + commonware_runtime::Spawner
        + commonware_runtime::Clock
        + Clone,
    Op: Read<Cfg = ()> + Write + EncodeSize + Encode + Clone + Send + Sync + 'static,
    D: Digest,
{
    request_id_generator: request_id::Generator,
    request_tx: mpsc::Sender<io::Request<wire::Message<Op, D>>>,
    _phantom: PhantomData<E>,
}

impl<E, Op, D> Resolver<E, Op, D>
where
    E: commonware_runtime::Network
        + commonware_runtime::Spawner
        + commonware_runtime::Clock
        + Clone,
    Op: Clone + Send + Sync + 'static + ReadExt<Cfg = ()> + Write + EncodeSize,
    D: Digest,
{
    pub async fn new(context: E, server_addr: std::net::SocketAddr) -> Self {
        let (request_sender, _) = io::start_io::<E, wire::Message<Op, D>>(context, server_addr)
            .await
            .unwrap();
        Self {
            request_id_generator: request_id::Generator::new(),
            request_tx: request_sender,
            _phantom: PhantomData,
        }
    }

    pub async fn get_sync_target(&self) -> Result<Target<D>, crate::Error> {
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

impl<E, Op, D> commonware_storage::adb::sync::resolver::Resolver for Resolver<E, Op, D>
where
    E: commonware_runtime::Network
        + commonware_runtime::Spawner
        + commonware_runtime::Clock
        + Clone,
    Op: Clone + Send + Sync + 'static + ReadExt<Cfg = ()> + Write + EncodeSize,
    D: Digest,
{
    type Digest = D;
    type Op = Op;
    type Error = crate::Error;

    async fn get_operations(
        &self,
        size: u64,
        start_loc: u64,
        max_ops: NonZeroU64,
    ) -> Result<
        commonware_storage::adb::sync::resolver::FetchResult<Self::Op, Self::Digest>,
        Self::Error,
    > {
        let request_id = self.request_id_generator.next();
        let request = wire::Message::GetOperationsRequest(wire::GetOperationsRequest {
            request_id,
            size,
            start_loc,
            max_ops,
        });
        let (tx, rx) = futures::channel::oneshot::channel();
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
            other => {
                return Err(crate::Error::UnexpectedResponse {
                    request_id: other.request_id(),
                })
            }
        };
        let (tx, _rx) = futures::channel::oneshot::channel();
        Ok(commonware_storage::adb::sync::resolver::FetchResult {
            proof,
            operations,
            success_tx: tx,
        })
    }
}
