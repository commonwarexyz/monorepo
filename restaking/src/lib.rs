use alloy::{
    eips::BlockNumberOrTag,
    hex::FromHex,
    network::Network,
    primitives::{address, Address, FixedBytes, Uint, U256},
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
    OperationStateRetriever,
    "src/abi/operator_state_retriever.json"
);

// Codegen from ABI file to interact with the RegistryCoordinator contract.
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    RegistryCoordinator,
    "src/abi/registry_coordinator.json"
);

/// source: https://github.com/Layr-Labs/eigenlayer-middleware
/// Contracts from middleware are supposed to be deployed for each AVS but
/// OperatorStateRetriever looks generic for everyone.
const OPERATOR_STATE_RETRIEVER_ADDRESS: Address =
    address!("0xd5d7fb4647ce79740e6e83819efdf43fa74f8c31");

pub struct EigenStakingClient<T: Transport + std::clone::Clone, N: Network> {
    provider: Arc<RootProvider<T, N>>,
    operator_state_retriever_address: Address,
    registry_coordinator_address: Address,
}

impl<T: Transport + std::clone::Clone, N: Network> EigenStakingClient<T, N> {
    fn new(
        provider: Arc<RootProvider<T, N>>,
        registry_coordinator_address: Address,
        operator_state_retriever_address: Option<Address>,
    ) -> Option<Self> {
        let operator_state_retriever_address = match operator_state_retriever_address {
            Some(address) => address,
            None => Address::from_hex(OPERATOR_STATE_RETRIEVER_ADDRESS).unwrap(),
        };
        return Some(Self {
            provider,
            registry_coordinator_address: registry_coordinator_address,
            operator_state_retriever_address: operator_state_retriever_address,
        });
    }

    pub async fn get_avs_operators(&self, block_number: u32) -> Option<OperatorState> {
        let registry_coordinator =
            RegistryCoordinator::new(self.registry_coordinator_address, self.provider.clone());
        let operation_state_retriever = OperationStateRetriever::new(
            self.operator_state_retriever_address,
            self.provider.clone(),
        );

        let builder = registry_coordinator.quorumCount();
        let b = BlockNumberOrTag::from(block_number as u64);
        let quorum_count = match builder.call().await {
            Ok(count) => count._0,
            Err(_) => return None,
        };
        let quorum_numbers: Vec<u8> = Vec::from_iter(1..=quorum_count);
        let call_builder = operation_state_retriever.getOperatorState_0(
            self.registry_coordinator_address,
            quorum_numbers.into(),
            block_number,
        );
        let operators_state = match call_builder.call().await {
            Ok(result) => result._0,
            Err(_) => return None,
        };
        Some(OperatorState::new(block_number, operators_state))
    }
}

pub struct OperatorState {
    block_number: u32,
    quorums_operators: Vec<Vec<OperatorStateRetriever::Operator>>,
}

#[derive(PartialEq, Eq, Hash)]
pub struct Operator {
    address: Address,
    id: FixedBytes<32>,
}

impl OperatorState {
    fn new(
        block_number: u32,
        quorums_operators: Vec<Vec<OperatorStateRetriever::Operator>>,
    ) -> Self {
        Self {
            block_number: block_number,
            quorums_operators: quorums_operators,
        }
    }

    pub fn get_block_number(&self) -> u32 {
        return self.block_number;
    }

    pub fn get_quorum_count(&self) -> usize {
        return self.quorums_operators.len();
    }

    pub fn get_operator_set(&self) -> HashSet<Operator> {
        let mut set = HashSet::new();
        for quorum_operator_list in &self.quorums_operators {
            for operator in quorum_operator_list {
                set.insert(Operator {
                    address: operator.operator,
                    id: operator.operatorId,
                });
            }
        }
        set
    }

    /// Returns the (OperatorStake,TotalStake) of the provided quorum number.
    pub fn get_operator_weight(
        &self,
        operator_id: FixedBytes<32>,
        quorum_number: usize,
    ) -> Option<(U256, U256)> {
        let Some(quorum_operators) = self.quorums_operators.get(quorum_number - 1) else {
            return None;
        };
        let mut operator_staked: Option<U256> = None;
        let mut total_staked: U256 = Uint::from(0);
        for operator in quorum_operators {
            let stake = operator.stake;
            total_staked = total_staked.saturating_add(U256::from(stake));
            if operator_id == operator.operatorId {
                operator_staked = Some(U256::from(stake));
            }
        }
        if operator_staked.is_some() {
            return Some((operator_staked.unwrap(), total_staked));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use alloy::providers::Provider;
    use alloy::sol_types::private;
    use alloy::{providers::ProviderBuilder, sol};
    use alloy_node_bindings::Anvil;

    use super::*;
    use rand::Rng;
    use std::sync::Arc;

    sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        MockedRegistryCoordinator,
        "testutils/out/registry_coordinator.sol/RegistryCoordinator.json"
    );
    sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        MockedOperatorStateRetriever,
        "testutils/out/operator_state_retriever.sol/OperatorStateRetriever.json"
    );

    #[tokio::test]
    async fn test_mocked_registry_coordinator() {
        let anvil = Anvil::new().block_time(1_u64).spawn();
        let anvil_provider = ProviderBuilder::new().on_http(anvil.endpoint().parse().unwrap());
        let anvil_provider = Arc::new(anvil_provider);
        let coordinator = MockedRegistryCoordinator::deploy(anvil_provider)
            .await
            .unwrap();
        coordinator
            .setQuorumCount(3)
            .send()
            .await
            .unwrap()
            .watch()
            .await
            .unwrap();
        let count = coordinator.quorumCount().call().await.unwrap()._0;
        assert_eq!(count, 3);
    }

    #[tokio::test]
    async fn test_mocked_operator_state_retriever() {
        let anvil = Anvil::new().block_time(1_u64).spawn();

        let anvil_provider = ProviderBuilder::new().on_http(anvil.endpoint().parse().unwrap());
        let anvil_provider = Arc::new(anvil_provider);

        let coordinator = MockedRegistryCoordinator::deploy(anvil_provider.clone())
            .await
            .unwrap();

        let retriever = MockedOperatorStateRetriever::deploy(anvil_provider)
            .await
            .unwrap();
        retriever
            .setRegistryCoordinator(*coordinator.address())
            .send()
            .await
            .unwrap()
            .watch()
            .await
            .unwrap();

        let registry_coordinator_address =
            retriever._registryCoordinator().call().await.unwrap()._0;
        assert_eq!(&registry_coordinator_address, coordinator.address());
    }

    #[tokio::test]
    async fn test_eigen_layer_client() {
        let anvil = Anvil::new().block_time(1_u64).spawn();

        let anvil_provider = ProviderBuilder::new().on_http(anvil.endpoint().parse().unwrap());
        let anvil_provider = Arc::new(anvil_provider);

        let coordinator = MockedRegistryCoordinator::deploy(anvil_provider.clone())
            .await
            .unwrap();

        let retriever = MockedOperatorStateRetriever::deploy(anvil_provider.clone())
            .await
            .unwrap();

        let _ = coordinator.setQuorumCount(3).send().await.unwrap();

        let operator_1_quorum_1 = generate_operator();
        let operator_2_quorum_1 = generate_operator();
        let operator_1_quorum_3 = update_operator_stake(&operator_1_quorum_1);
        let operator_2_quorum_3 = update_operator_stake(&operator_2_quorum_1);

        let operators_quorum_1: private::Vec<OperatorStateRetriever::Operator> =
            vec![operator_1_quorum_1.clone(), operator_2_quorum_1.clone()];
        let operators_quorum_2: private::Vec<OperatorStateRetriever::Operator> = vec![];
        let operators_quorum_3: private::Vec<OperatorStateRetriever::Operator> =
            vec![operator_1_quorum_3, operator_2_quorum_3];

        retriever
            .setOperators(1, operators_quorum_1)
            .send()
            .await
            .unwrap()
            .watch()
            .await
            .unwrap();
        retriever
            .setOperators(2, operators_quorum_2)
            .send()
            .await
            .unwrap()
            .watch()
            .await
            .unwrap();
        retriever
            .setOperators(3, operators_quorum_3)
            .send()
            .await
            .unwrap()
            .watch()
            .await
            .unwrap();

        let quorum_numbers: Vec<u8> = Vec::from_iter(1..=3);
        let quorums_operators = retriever
            .getOperatorState(*coordinator.address(), quorum_numbers.into(), 1)
            .call()
            .await
            .unwrap()
            ._0;
        assert_eq!(quorums_operators.len(), 3);

        let eigen_client = EigenStakingClient::new(
            anvil_provider,
            coordinator.address().clone(),
            Some(retriever.address().clone()),
        )
        .unwrap();
        let avs_operators = eigen_client.get_avs_operators(1).await.unwrap();
        let count = avs_operators.get_quorum_count();
        assert_eq!(count, 3);
        let operator_set = avs_operators.get_operator_set();
        assert_eq!(operator_set.len(), 2);
        assert!(operator_set.contains(&Operator {
            address: operator_1_quorum_1.operator,
            id: operator_1_quorum_1.operatorId,
        }));
        assert!(operator_set.contains(&Operator {
            address: operator_2_quorum_1.operator,
            id: operator_2_quorum_1.operatorId,
        }));
    }

    fn generate_operator() -> OperatorStateRetriever::Operator {
        let mut rng = rand::thread_rng();
        let stake = Uint::<96, 2>::from(rng.gen::<u64>());
        let mut id = [0u8; 32];
        let mut address = [0u8; 20];
        rng.fill(&mut id);
        rng.fill(&mut address);
        OperatorStateRetriever::Operator {
            operator: Address::from(address),
            operatorId: FixedBytes::from(id),
            stake: stake,
        }
    }

    fn update_operator_stake(
        operator: &OperatorStateRetriever::Operator,
    ) -> OperatorStateRetriever::Operator {
        let mut rng = rand::thread_rng();
        let stake = Uint::<96, 2>::from(rng.gen::<u64>());
        OperatorStateRetriever::Operator {
            operator: operator.operator.clone(),
            operatorId: operator.operatorId.clone(),
            stake: stake,
        }
    }
}
