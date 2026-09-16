use commonware_codec::{FixedSize, Read, Write};
use commonware_cryptography::{Committable, Digestible, Hasher, Sha256, sha256::Digest};

/// A mock request for testing
#[derive(Clone, Debug, PartialEq, Eq, Hash, Write, Read, FixedSize)]
pub struct Request {
    pub id: u64,
    pub data: u32,
}

impl Committable for Request {
    type Commitment = Digest;

    fn commitment(&self) -> Self::Commitment {
        Sha256::hash(&[&self.id.to_be_bytes()])
    }
}

impl Digestible for Request {
    type Digest = Digest;
    fn digest(&self) -> Self::Digest {
        Sha256::hash(&[&self.id.to_be_bytes(), &self.data.to_be_bytes()])
    }
}

/// A mock response for testing
#[derive(Clone, Debug, PartialEq, Eq, Hash, Write, Read, FixedSize)]
pub struct Response {
    pub id: u64,
    // Use a different size to ensure we don't accidentally parse with `Request`.
    pub result: u64,
}

impl Committable for Response {
    type Commitment = Digest;
    fn commitment(&self) -> Self::Commitment {
        Sha256::hash(&[&self.id.to_be_bytes()])
    }
}

impl Digestible for Response {
    type Digest = <Sha256 as Hasher>::Digest;

    fn digest(&self) -> Self::Digest {
        Sha256::hash(&[&self.id.to_be_bytes(), &self.result.to_be_bytes()])
    }
}
