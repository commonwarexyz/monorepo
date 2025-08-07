//! Network resolver for Immutable example.

use crate::immutable::{
    protocol::{GetOperationsRequest, GetSyncTargetRequest, Message},
    Operation,
};
// use crate::protocol::MAX_MESSAGE_SIZE; // unused after refactor
use crate::net::client::NetworkClient;
use crate::Error;
// use commonware_codec::{DecodeExt, Encode}; // unused after refactor
use commonware_cryptography::sha256::Digest;
// use commonware_macros::select; // unused after refactor
use commonware_storage::adb::sync::{
    resolver::{FetchResult, Resolver as ResolverTrait},
    Target,
};
use futures::channel::oneshot;
use std::{marker::PhantomData, net::SocketAddr, num::NonZeroU64};

#[derive(Clone)]
pub struct Resolver<E>
where
    E: commonware_runtime::Network
        + commonware_runtime::Spawner
        + commonware_runtime::Clock
        + Clone,
{
    client: NetworkClient<E, Message>,
    _phantom: PhantomData<E>,
}

impl<E> Resolver<E>
where
    E: commonware_runtime::Network
        + commonware_runtime::Spawner
        + commonware_runtime::Clock
        + Clone,
{
    pub fn new(context: E, server_addr: SocketAddr) -> Self {
        let client = NetworkClient::<E, Message>::new(context, server_addr);
        Self {
            client,
            _phantom: PhantomData,
        }
    }

    pub async fn get_sync_target(&self) -> Result<Target<Digest>, Error> {
        let request_id = 0u64;
        let request = GetSyncTargetRequest { request_id };
        let response = self
            .client
            .send(Message::GetSyncTargetRequest(request))
            .await?;
        match response {
            Message::GetSyncTargetResponse(response) => Ok(response.target),
            Message::Error(err) => Err(Error::Server {
                code: err.error_code,
                message: err.message,
            }),
            _ => Err(Error::UnexpectedResponse { request_id }),
        }
    }

    async fn send_request(&self, message: Message) -> Result<Message, Error> {
        self.client.send(message).await
    }
}

impl<E> ResolverTrait for Resolver<E>
where
    E: commonware_runtime::Network
        + commonware_runtime::Spawner
        + commonware_runtime::Clock
        + Clone,
{
    type Digest = Digest;
    type Op = Operation;
    type Error = Error;

    async fn get_operations(
        &self,
        size: u64,
        start_loc: u64,
        max_ops: NonZeroU64,
    ) -> Result<FetchResult<Self::Op, Self::Digest>, Self::Error> {
        let request_id = 0u64;
        let request = GetOperationsRequest {
            request_id,
            size,
            start_loc,
            max_ops,
        };
        let response = self
            .client
            .send(Message::GetOperationsRequest(request))
            .await?;
        match response {
            Message::GetOperationsResponse(response) => {
                let (success_tx, _success_rx) = oneshot::channel();
                Ok(FetchResult {
                    operations: response.operations,
                    proof: response.proof,
                    success_tx,
                })
            }
            Message::Error(err) => Err(Error::Server {
                code: err.error_code,
                message: err.message,
            }),
            _ => Err(Error::UnexpectedResponse { request_id }),
        }
    }
}
