use alloy::{
    network::Network,
    primitives::{Address, FixedBytes, Uint, U256},
    providers::RootProvider,
    sol,
    transports::Transport,
};
use std::collections::HashSet;

// Codegen from ABI file to interact with the MiddlewareReader contract.
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    MiddlewareReader,
    "src/symbiotic/artifacts/IMiddlewareReader.sol/IMiddlewareReader.json"
);

// Codegen from ABI file to interact with the StateRetriever contract.
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    StateRetriever,
    "src/symbiotic/artifacts/StateRetriever.sol/StateRetriever.json"
);

pub struct SymbioticStakingClient<T: Transport + std::clone::Clone, N: Network> {
    provider: RootProvider<T, N>,
    network_middleware_address: Address,
    state_retriever_address: Address,
}

impl<T: Transport + std::clone::Clone, N: Network> SymbioticStakingClient<T, N> {
    pub fn new(
        provider: RootProvider<T, N>,
        network_middleware_address: Address,
        state_retriever_address: Address,
    ) -> Self {
        Self {
            provider,
            network_middleware_address,
            state_retriever_address,
        }
    }

    pub async fn get_operators(
        &self,
        timestamp: Option<u64>,
    ) -> Result<HashSet<Address>, alloy::contract::Error> {
        let network_middleware =
            MiddlewareReader::new(self.network_middleware_address, self.provider.clone());

        let addresses = match timestamp {
            None => network_middleware.activeOperators().call().await?._0,
            Some(timestamp) => {
                let timestamp = Uint::<48, 1>::from(timestamp);
                network_middleware
                    .activeOperatorsAt(timestamp)
                    .call()
                    .await?
                    ._0
            }
        };

        let mut set = HashSet::new();
        for address in addresses {
            set.insert(address);
        }
        Ok(set)
    }

    pub async fn get_validator_set(
        &self,
        timestamp: Option<u64>,
    ) -> Result<Vec<Validator>, alloy::contract::Error> {
        let state_retriever =
            StateRetriever::new(self.state_retriever_address, self.provider.clone());

        let validators_data = match timestamp {
            None => {
                state_retriever
                    .getValidatorSet(self.network_middleware_address)
                    .call()
                    .await?
                    .validatorSet
            }
            Some(timestamp) => {
                let timestamp = Uint::<48, 1>::from(timestamp);
                state_retriever
                    .getValidatorSetAt(self.network_middleware_address, timestamp)
                    .call()
                    .await?
                    .validatorSet
            }
        };

        let mut validators = Vec::with_capacity(validators_data.len());
        for data in validators_data {
            validators.push(Validator {
                operator: data.operator,
                key: data.key,
                power: data.power,
            });
        }
        Ok(validators)
    }
}

pub struct Validator {
    pub operator: Address,
    pub key: FixedBytes<32>,
    pub power: U256,
}

#[cfg(test)]
mod tests {
    use alloy::{primitives::FixedBytes, primitives::U256, providers::ProviderBuilder, sol};
    use alloy_node_bindings::Anvil;

    use super::*;
    use rand::Rng;

    // Codegen from compiled MockedMiddlewareReader contract.
    sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        MockedNetworkMiddleware,
        "src/symbiotic/artifacts/MockedMiddlewareReader.sol/MockedMiddlewareReader.json"
    );

    // Codegen from compiled MockedStateRetriever contract.
    sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        MockedStateRetriever,
        "src/symbiotic/artifacts/MockedStateRetriever.sol/MockedStateRetriever.json"
    );

    #[tokio::test]
    async fn get_operators() {
        // This test initializes a mocked contract to verify we are able to get the operators set.
        let anvil = Anvil::new().block_time(1_u64).spawn();
        let anvil_provider = ProviderBuilder::new().on_http(anvil.endpoint().parse().unwrap());

        let mocked_network_middleware = MockedNetworkMiddleware::deploy(anvil_provider.clone())
            .await
            .unwrap();

        let mocked_state_retriever = MockedStateRetriever::deploy(anvil_provider.clone())
            .await
            .unwrap();

        let address1 = generate_random_address();
        let address2 = generate_random_address();
        let _ = mocked_network_middleware
            .setActiveOperators(vec![address1, address2])
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
            *mocked_network_middleware.address(),
            *mocked_state_retriever.address(),
        );
        let operators_set = symbiotic_client.get_operators(Some(1)).await.unwrap();
        assert_eq!(operators_set.len(), 2);
        assert!(operators_set.contains(&address1));
        assert!(operators_set.contains(&address2));
    }

    #[tokio::test]
    async fn get_valitors_set() {
        let anvil = Anvil::new().block_time(1_u64).spawn();
        let anvil_provider = ProviderBuilder::new().on_http(anvil.endpoint().parse().unwrap());

        let mocked_network_middleware = MockedNetworkMiddleware::deploy(anvil_provider.clone())
            .await
            .unwrap();

        let mocked_state_retriever = MockedStateRetriever::deploy(anvil_provider.clone())
            .await
            .unwrap();

        let address1 = generate_random_address();
        let address2 = generate_random_address();

        let validator1 = StateRetriever::ValidatorData {
            operator: address1,
            key: FixedBytes::new([1; 32]),
            power: U256::from(200),
        };
        let validator2 = StateRetriever::ValidatorData {
            operator: address2,
            key: FixedBytes::new([2; 32]),
            power: U256::from(400),
        };
        mocked_state_retriever
            .setActiveValidators(vec![validator1.clone(), validator2.clone()])
            .send()
            .await
            .unwrap()
            .watch()
            .await
            .unwrap();

        let validators_set = mocked_state_retriever
            .getValidatorSet(*mocked_network_middleware.address())
            .call()
            .await
            .unwrap()
            .validatorSet;

        assert_eq!(validators_set.len(), 2);

        let symbiotic_client = SymbioticStakingClient::new(
            anvil_provider,
            *mocked_network_middleware.address(),
            *mocked_state_retriever.address(),
        );

        let validators = symbiotic_client.get_validator_set(Some(4)).await.unwrap();
        assert_eq!(validators.len(), 2);
        let validator1_from_set = validators.first().unwrap();
        let validator2_from_set = validators.get(1).unwrap();
        assert_eq!(validator1_from_set.operator, validator1.operator);
        assert_eq!(validator1_from_set.key, validator1.key);
        assert_eq!(validator1_from_set.power, validator1.power);
        assert_eq!(validator2_from_set.operator, validator2.operator);
        assert_eq!(validator2_from_set.key, validator2.key);
        assert_eq!(validator2_from_set.power, validator2.power);
    }

    fn generate_random_address() -> Address {
        let mut rng = rand::thread_rng();
        let mut address = [0u8; 20];
        rng.fill(&mut address);
        Address::from(address)
    }
}
