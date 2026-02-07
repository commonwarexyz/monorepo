use super::*;
use alloy_evm::revm::primitives::{keccak256, Address, Bytes, B256, U256};
use commonware_codec::{Decode as _, Encode as _};

fn cfg() -> BlockCfg {
    BlockCfg {
        max_txs: 64,
        tx: TxCfg {
            max_calldata_bytes: 1024,
        },
    }
}

#[test]
fn test_tx_roundtrip_and_id_stable() {
    let tx = Tx {
        from: Address::from([0x11u8; 20]),
        to: Address::from([0x22u8; 20]),
        value: U256::from(1234u64),
        gas_limit: 50_000,
        data: Bytes::from(vec![1, 2, 3]),
    };
    let encoded = tx.encode();
    let decoded = Tx::decode_cfg(
        encoded.clone(),
        &TxCfg {
            max_calldata_bytes: 1024,
        },
    )
    .expect("decode tx");
    assert_eq!(tx, decoded);
    assert_eq!(tx.id(), decoded.id());
    assert_eq!(tx.id(), TxId(keccak256(encoded)));
}

#[test]
fn test_block_roundtrip_and_id_stable() {
    let txs = vec![
        Tx {
            from: Address::from([0x11u8; 20]),
            to: Address::from([0x22u8; 20]),
            value: U256::from(1u64),
            gas_limit: 21_000,
            data: Bytes::new(),
        },
        Tx {
            from: Address::from([0x33u8; 20]),
            to: Address::from([0x44u8; 20]),
            value: U256::from(2u64),
            gas_limit: 50_000,
            data: Bytes::from(vec![9, 9, 9]),
        },
    ];
    let parent = BlockId(B256::from([0xAAu8; 32]));
    let block = Block {
        context: super::genesis_context(parent),
        parent,
        height: 7,
        prevrandao: B256::from([0x55u8; 32]),
        state_root: StateRoot(B256::from([0xBBu8; 32])),
        txs,
    };
    let encoded = block.encode();
    let decoded = Block::decode_cfg(encoded.clone(), &cfg()).expect("decode block");
    assert_eq!(block, decoded);
    assert_eq!(block.id(), decoded.id());
    assert_eq!(block.id(), BlockId(keccak256(encoded)));
}
