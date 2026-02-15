use super::ids::TxId;
use alloy_evm::revm::primitives::{keccak256, Address, Bytes, U256};
use bytes::{Buf, BufMut};
use commonware_codec::{Encode, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt, Write};

#[derive(Clone, Copy, Debug)]
/// Configuration used when decoding transactions from bytes.
pub struct TxCfg {
    /// Maximum calldata size accepted by the codec.
    pub max_calldata_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Minimal transaction type for the example.
///
/// This is not a signed Ethereum transaction. It is just enough information to build a `TxEnv`
/// for REVM execution in the simulation.
pub struct Tx {
    /// Sender address.
    pub from: Address,
    /// Recipient address.
    pub to: Address,
    /// Amount transferred (Wei).
    pub value: U256,
    /// Gas limit supplied for execution.
    pub gas_limit: u64,
    /// Calldata passed to the contract.
    pub data: Bytes,
}

impl Tx {
    pub fn id(&self) -> TxId {
        TxId(keccak256(self.encode()))
    }
}

impl Write for Tx {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(self.from.as_slice());
        buf.put_slice(self.to.as_slice());
        buf.put_slice(&self.value.to_be_bytes::<32>());
        self.gas_limit.write(buf);
        self.data.as_ref().write(buf);
    }
}

impl EncodeSize for Tx {
    fn encode_size(&self) -> usize {
        20 + 20 + 32 + self.gas_limit.encode_size() + self.data.as_ref().encode_size()
    }
}

impl Read for Tx {
    type Cfg = TxCfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        if buf.remaining() < 20 + 20 + 32 {
            return Err(CodecError::EndOfBuffer);
        }
        let mut from = [0u8; 20];
        buf.copy_to_slice(&mut from);
        let mut to = [0u8; 20];
        buf.copy_to_slice(&mut to);
        let mut value = [0u8; 32];
        buf.copy_to_slice(&mut value);
        let gas_limit = u64::read(buf)?;
        let data = Vec::<u8>::read_cfg(buf, &(RangeCfg::new(0..=cfg.max_calldata_bytes), ()))?;
        Ok(Self {
            from: Address::from(from),
            to: Address::from(to),
            value: U256::from_be_bytes(value),
            gas_limit,
            data: Bytes::from(data),
        })
    }
}
