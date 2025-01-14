use alloy::{
    eips::BlockNumberOrTag,
    hex::FromHex,
    primitives::{address, Address, FixedBytes, Uint, U256},
    providers::{ProviderBuilder, RootProvider},
    sol,
    transports::http::{reqwest::Url, Client, Http},
};
use std::{collections::HashSet, str::FromStr};

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

pub struct EigenStakingClient {
    provider: RootProvider<Http<Client>>,
    registry_coordinator_address: Address,
}

impl EigenStakingClient {
    pub fn new(rpc_url: &str, registry_coordinator_pk: &str) -> Option<Self> {
        let rpc_url = match Url::from_str(rpc_url) {
            Ok(rpc_url) => rpc_url,
            Err(_) => return None,
        };
        let provider = ProviderBuilder::new().on_http(rpc_url);
        let address = match Address::from_hex(registry_coordinator_pk) {
            Ok(address) => address,
            Err(_) => return None,
        };
        return Some(Self {
            provider,
            registry_coordinator_address: address,
        });
    }

    pub async fn get_avs_operators(&self, block_number: u32) -> Option<OperatorState> {
        let registry_coordinator =
            RegistryCoordinator::new(self.registry_coordinator_address, self.provider.clone());
        let operation_state_retriever =
            OperationStateRetriever::new(OPERATOR_STATE_RETRIEVER_ADDRESS, self.provider.clone());

        let builder = registry_coordinator.quorumCount();
        let b = BlockNumberOrTag::from(block_number as u64);
        let quorum_count = match builder.block(b.into()).call().await {
            Ok(count) => count._0,
            Err(_) => return None,
        };
        let quorum_numbers: Vec<u8> = Vec::from_iter(1..=quorum_count);
        let call_builder = operation_state_retriever.getOperatorState_0(
            self.registry_coordinator_address,
            quorum_numbers.into(),
            block_number,
        );
        //let eth_call = call_builder.call();
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
