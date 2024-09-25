pub struct Block {
    Timestamp: u64,

    Height: u64,
    Parent: BlockHash,
    Epoch: u64,
    View: u64,
    // TODO: add partial signatures
    Payload: Bytes, // TODO: use function that returns hash for constructing block header
}

impl Block {
    pub fn hash(&self) -> BlockHash {
        // H(timestamp, H(parent, epoch, view, height), payload_hash)
    }
}
