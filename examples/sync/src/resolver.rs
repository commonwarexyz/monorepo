//! Provides a [Resolver] implementation that communicates with a remote server
//! to fetch operations and proofs.

use crate::net::{self as net, client::NetworkClient, Protocol};
use crate::{error::Error, AnyProtocol, Message};
use commonware_cryptography::sha256::Digest;
use commonware_storage::adb::sync::{
    resolver::{FetchResult, Resolver as ResolverTrait},
    Target,
};
use futures::channel::oneshot;
use std::{marker::PhantomData, net::SocketAddr, num::NonZeroU64};

/// Network resolver that fetches operations from a remote server.
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
        // NetworkClient correlates by message.request_id; use 0 for target request (no clash due to single in-flight per send())
        AnyProtocol::parse_get_target_response(
            self.client.send(AnyProtocol::make_get_target(0u64)).await?,
        )
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
    type Op = <AnyProtocol as net::Protocol>::Op;
    type Error = Error;

    async fn get_operations(
        &self,
        size: u64,
        start_loc: u64,
        max_ops: NonZeroU64,
    ) -> Result<FetchResult<Self::Op, Self::Digest>, Self::Error> {
        let (proof, operations) = AnyProtocol::parse_get_ops_response(
            self.client
                .send(AnyProtocol::make_get_ops(0u64, size, start_loc, max_ops))
                .await?,
        )?;
        let (success_tx, _rx) = oneshot::channel();
        Ok(FetchResult {
            operations,
            proof,
            success_tx,
        })
    }
}
