use alloy::{
    network::Network,
    primitives::{Address, Uint},
    providers::RootProvider,
    sol,
    transports::Transport,
};
use std::collections::HashSet;
use std::sync::Arc;

// Codegen from ABI file to interact with the OperatorStateRetriever contract.
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    SymbioticNetworkMiddleware,
    "src/abi/IBaseMiddlewareReader.sol/IBaseMiddlewareReader.json"
);

pub struct SymbioticStakingClient<T: Transport + std::clone::Clone, N: Network> {
    provider: Arc<RootProvider<T, N>>,
    network_middleware_address: Address,
}

impl<T: Transport + std::clone::Clone, N: Network> SymbioticStakingClient<T, N> {
    fn new(provider: Arc<RootProvider<T, N>>, network_middleware_address: Address) -> Option<Self> {
        return Some(Self {
            provider,
            network_middleware_address: network_middleware_address,
        });
    }

    pub async fn get_operators(&self, block_number: u64) -> HashSet<Address> {
        let network_middleware =
            SymbioticNetworkMiddleware::new(self.network_middleware_address, self.provider.clone());

        let a = Uint::<48, 1>::from(block_number);
        let addresses = network_middleware
            .activeOperatorsAt(a)
            .call()
            .await
            .unwrap()
            ._0;

        let mut set = HashSet::new();
        for address in addresses {
            set.insert(address);
        }
        set
    }
}

#[cfg(test)]
mod tests {
    use alloy::{providers::ProviderBuilder, sol};
    use alloy_node_bindings::Anvil;

    use super::*;
    use rand::Rng;
    use std::sync::Arc;

    // Codegen from ABI file to interact with the OperatorStateRetriever contract.
    sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        MockedNetworkMiddleware,
        "src/abi/mock_BaseMiddlewareReader.sol/MockedMiddlewareReader.json"
    );

    #[tokio::test]
    async fn test() {
        let anvil = Anvil::new().block_time(1_u64).spawn();
        let anvil_provider = ProviderBuilder::new().on_http(anvil.endpoint().parse().unwrap());
        let anvil_provider = Arc::new(anvil_provider);
        let mocked_network_middleware = MockedNetworkMiddleware::deploy(anvil_provider.clone())
            .await
            .unwrap();

        let address1 = generate_random_address();
        let address2 = generate_random_address();
        let _ = mocked_network_middleware
            .setActiveOperators(vec![address1.clone(), address2.clone()])
            .send()
            .await
            .unwrap()
            .watch()
            .await
            .unwrap();

        let addresses = mocked_network_middleware
            .activeOperatorsAt(Uint::<48, 1>::from(1))
            .call()
            .await
            .unwrap()
            ._0;
        assert_eq!(addresses.len(), 2);

        let symbiotic_client = SymbioticStakingClient::new(
            anvil_provider,
            mocked_network_middleware.address().clone(),
        )
        .unwrap();
        let operators_set = symbiotic_client.get_operators(1).await;
        assert!(operators_set.contains(&address1));
        assert!(operators_set.contains(&address2));
    }

    fn generate_random_address() -> Address {
        let mut rng = rand::thread_rng();
        let mut address = [0u8; 20];
        rng.fill(&mut address);
        return Address::from(address);
    }
}
