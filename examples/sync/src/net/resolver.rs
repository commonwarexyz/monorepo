use commonware_codec::{Encode, EncodeSize, Read, ReadExt, Write};
use commonware_cryptography::Digest;
use commonware_storage::adb::sync::Target;
use std::num::NonZeroU64;

use super::{client, wire};

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
    client: client::Client<E, wire::Message<Op, D>>,
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
    pub fn new(context: E, server_addr: std::net::SocketAddr) -> Self {
        let client = client::Client::<E, wire::Message<Op, D>>::new(context, server_addr);
        Self { client }
    }

    pub async fn get_sync_target(&self) -> Result<Target<D>, crate::Error> {
        let request =
            wire::Message::GetSyncTargetRequest(wire::GetSyncTargetRequest { request_id: 0 });
        let response = self.client.send(request).await?;
        match response {
            wire::Message::GetSyncTargetResponse(r) => Ok(r.target),
            wire::Message::Error(err) => Err(crate::Error::Server {
                code: err.error_code,
                message: err.message,
            }),
            other => Err(crate::Error::UnexpectedResponse {
                request_id: other.request_id(),
            }),
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
        let request = wire::Message::GetOperationsRequest(wire::GetOperationsRequest {
            request_id: 0,
            size,
            start_loc,
            max_ops,
        });
        let response = self.client.send(request).await?;
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
