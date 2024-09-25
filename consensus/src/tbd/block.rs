use bytes::Bytes;

type Hash = [u8; 32];

pub struct Signer {
    pub public_key: Bytes,
    pub signature: Bytes,
}

pub struct Block {
    pub timestamp: u64, // in ms

    pub height: u64,
    pub parent: Hash,

    pub epoch: u64,
    pub view: u64,
    pub partials: Vec<Signer>, // TODO: sorted by public key, included to provide voting rewards/track uptime

    pub payload: Bytes, // TODO: use function that returns hash for constructing block header (most wont want to just hash)
}

impl Block {
    pub fn hash(&self) -> Hash {
        // H(timestamp, H(parent, epoch, view, height), payload_hash)
    }
}
