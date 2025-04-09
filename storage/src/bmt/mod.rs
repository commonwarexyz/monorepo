//! Stateless Binary Merkle Tree (BMT).
//!
//! The Binary Merkle Tree is constructed level-by-level. The first level consists of position-hashed leaf digests.
//! On each additional level, pairs of nodes are hashed from the previous level (if a level contains an odd
//! number of nodes, the last node is duplicated). The root of the tree is the digest of the node in the top level.
//!
//! For example, given three leaves A, B, and C, the tree is constructed as follows:
//!
//! ```text
//!     Level 2 (root):       [hash(hash(hash(0,A),hash(1,B)),hash(hash(2,C),hash(2,C)))]
//!     Level 1:              [hash(hash(0,A),hash(1,B)),hash(hash(2,C),hash(2,C))]
//!     Level 0 (leaves):     [hash(0,A),hash(1,B),hash(2,C)]
//! ```
//!
//! A proof for a given leaf is generated by collecting the sibling at each level (from the leaf up to the root).
//! An external process can then use this proof (with some trusted root) to verify that the leaf (at a fixed position)
//! is part of the tree.
//!
//! # Example
//!
//! ```rust
//! use commonware_storage::bmt::{Builder, Tree};
//! use commonware_cryptography::{hash, Sha256, sha256::Digest};
//!
//! // Create transactions and compute their digests
//! let txs = [b"tx1", b"tx2", b"tx3", b"tx4"];
//! let digests: Vec<Digest> = txs.iter().map(|tx| hash(*tx)).collect();
//!
//! // Build a Merkle Tree from the digests
//! let mut builder = Builder::<Sha256>::new(digests.len());
//! for digest in &digests {
//!    builder.add(digest);
//! }
//! let tree = builder.build();
//! let root = tree.root();
//!
//! // Generate a proof for leaf at index 1
//! let mut hasher = Sha256::default();
//! let proof = tree.proof(1).unwrap();
//! assert!(proof.verify(&mut hasher, &digests[1], 1, &root).is_ok());
//! ```

use bytes::Buf;
use commonware_codec::FixedSize;
use commonware_cryptography::Hasher;
use commonware_utils::Array;
use thiserror::Error;

/// Errors that can occur when working with a Binary Merkle Tree (BMT).
#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid position: {0}")]
    InvalidPosition(u32),
    #[error("invalid proof: {0} != {1}")]
    InvalidProof(String, String),
    #[error("no leaves")]
    NoLeaves,
    #[error("unaligned proof")]
    UnalignedProof,
    #[error("too many siblings: {0}")]
    TooManySiblings(usize),
    #[error("invalid digest")]
    InvalidDigest,
}

/// Constructor for a Binary Merkle Tree (BMT).
pub struct Builder<H: Hasher> {
    hasher: H,
    leaves: Vec<H::Digest>,
}

impl<H: Hasher> Builder<H> {
    /// Creates a new Binary Merkle Tree builder.
    pub fn new(leaves: usize) -> Self {
        Self {
            hasher: H::new(),
            leaves: Vec::with_capacity(leaves),
        }
    }

    /// Adds a leaf to the Binary Merkle Tree.
    ///
    /// When added, the leaf is hashed with its position.
    pub fn add(&mut self, leaf: &H::Digest) -> u32 {
        let position: u32 = self.leaves.len().try_into().expect("too many leaves");
        self.hasher.update(&position.to_be_bytes());
        self.hasher.update(leaf);
        self.leaves.push(self.hasher.finalize());
        position
    }

    /// Builds the Binary Merkle Tree.
    ///
    /// It is valid to build a tree with no leaves, in which case
    /// just an "empty" node is included (no leaves will be provable).
    pub fn build(self) -> Tree<H> {
        Tree::new(self.hasher, self.leaves)
    }
}

/// Constructed Binary Merkle Tree (BMT).
#[derive(Clone, Debug)]
pub struct Tree<H: Hasher> {
    /// Records whether the tree is empty.
    empty: bool,

    /// The digests at each level of the tree (from leaves to root).
    levels: Vec<Vec<H::Digest>>,
}

impl<H: Hasher> Tree<H> {
    /// Builds a Merkle Tree from a slice of position-hashed leaf digests.
    fn new(mut hasher: H, mut leaves: Vec<H::Digest>) -> Self {
        // If no leaves, add an empty node.
        //
        // Because this node only includes a position, there is no way a valid proof
        // can be generated that references it.
        let mut empty = false;
        if leaves.is_empty() {
            leaves.push(hasher.finalize());
            empty = true;
        }

        // Create the first level
        let mut levels = Vec::new();
        levels.push(leaves);

        // Construct the tree level-by-level
        let mut current_level = levels.last().unwrap();
        while current_level.len() > 1 {
            let mut next_level = Vec::with_capacity(current_level.len().div_ceil(2));
            for chunk in current_level.chunks(2) {
                // Hash the left child
                hasher.update(&chunk[0]);

                // Hash the right child
                if chunk.len() == 2 {
                    hasher.update(&chunk[1])
                } else {
                    // If no right child exists, duplicate left child.
                    hasher.update(&chunk[0]);
                };

                // Compute the parent digest
                next_level.push(hasher.finalize());
            }

            // Add the computed level to the tree
            levels.push(next_level);
            current_level = levels.last().unwrap();
        }
        Self { empty, levels }
    }

    /// Returns the root of the tree.
    pub fn root(&self) -> H::Digest {
        *self.levels.last().unwrap().first().unwrap()
    }

    /// Generates a Merkle proof for the leaf at `position`.
    ///
    /// The proof contains the sibling digest at each level needed to reconstruct
    /// the root.
    pub fn proof(&self, position: u32) -> Result<Proof<H>, Error> {
        // Ensure the position is within bounds
        if self.empty || position >= self.levels.first().unwrap().len() as u32 {
            return Err(Error::InvalidPosition(position));
        }

        // For each level (except the root level) record the sibling
        let mut siblings = Vec::with_capacity(self.levels.len() - 1);
        let mut index = position as usize;
        for level in &self.levels {
            if level.len() == 1 {
                break;
            }
            let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
            let sibling = if sibling_index < level.len() {
                level[sibling_index]
            } else {
                // If no right child exists, use a duplicate of the current node.
                //
                // This doesn't affect the robustness of the proof (allow a non-existent position
                // to be proven or enable multiple proofs to be generated from a single leaf).
                level[index]
            };
            siblings.push(sibling);
            index /= 2;
        }
        Ok(Proof { siblings })
    }
}

/// A Merkle proof for a leaf in a Binary Merkle Tree.
#[derive(Clone, Debug, Eq)]
pub struct Proof<H: Hasher> {
    /// The sibling hashes from the leaf up to the root.
    pub siblings: Vec<H::Digest>,
}

impl<H: Hasher> PartialEq for Proof<H>
where
    H::Digest: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.siblings == other.siblings
    }
}

impl<H: Hasher> Proof<H> {
    /// Verifies that a given `leaf` at `position` is included in a Binary Merkle Tree
    /// with `root` using the provided `hasher`.
    ///
    /// The proof consists of sibling hashes stored from the leaf up to the root. At each level, if the current
    /// node is a left child (even index), the sibling is combined to the right; if it is a right child (odd index),
    /// the sibling is combined to the left.
    pub fn verify(
        &self,
        hasher: &mut H,
        leaf: &H::Digest,
        mut position: u32,
        root: &H::Digest,
    ) -> Result<(), Error> {
        // Compute the position-hashed leaf
        hasher.update(&position.to_be_bytes());
        hasher.update(leaf);
        let mut computed = hasher.finalize();
        for sibling in self.siblings.iter() {
            // Determine the position of the sibling
            let (left_node, right_node) = if position % 2 == 0 {
                (&computed, sibling)
            } else {
                (sibling, &computed)
            };

            // Compute the parent digest
            hasher.update(left_node);
            hasher.update(right_node);
            computed = hasher.finalize();

            // Move up the tree
            position /= 2;
        }
        let result = computed == *root;
        if result {
            Ok(())
        } else {
            Err(Error::InvalidProof(computed.to_string(), root.to_string()))
        }
    }

    /// Serializes the proof as the concatenation of each hash.
    pub fn serialize(&self) -> Vec<u8> {
        // There should never be more than 255 siblings in a proof (would mean the Binary Merkle Tree
        // has more than 2^255 leaves).
        assert!(
            self.siblings.len() <= u8::MAX as usize,
            "too many siblings in proof"
        );

        // Serialize the proof as the concatenation of each hash.
        let bytes_len = self.siblings.len() * H::Digest::LEN_ENCODED;
        let mut bytes = Vec::with_capacity(bytes_len);
        for hash in &self.siblings {
            bytes.extend_from_slice(hash.as_ref());
        }
        bytes
    }

    /// Deserializes a proof from its canonical serialized representation.
    pub fn deserialize(mut buf: &[u8]) -> Result<Self, Error> {
        // It is ok to have an empty proof (just means the provided leaf is the root).

        // If the remaining buffer is not a multiple of the hash size, it's invalid.
        if buf.remaining() % H::Digest::LEN_ENCODED != 0 {
            return Err(Error::UnalignedProof);
        }

        // If the number of siblings is too large, it's invalid.
        let num_siblings = buf.len() / H::Digest::LEN_ENCODED;
        if num_siblings > u8::MAX as usize {
            return Err(Error::TooManySiblings(num_siblings));
        }

        // Deserialize the siblings
        let mut siblings = Vec::with_capacity(num_siblings);
        for _ in 0..num_siblings {
            let hash = H::Digest::read_from(&mut buf).map_err(|_| Error::InvalidDigest)?;
            siblings.push(hash);
        }
        Ok(Self { siblings })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{
        hash,
        sha256::{Digest, Sha256},
    };
    use commonware_utils::hex;

    fn test_merkle_tree(n: usize) -> Digest {
        // Build tree
        let mut digests = Vec::with_capacity(n);
        let mut builder = Builder::new(n);
        for i in 0..n {
            let digest = hash(&i.to_be_bytes());
            builder.add(&digest);
            digests.push(digest);
        }
        let tree = builder.build();
        let root = tree.root();

        // For each leaf, generate and verify its proof
        let mut hasher = Sha256::default();
        for (i, leaf) in digests.iter().enumerate() {
            // Generate proof
            let proof = tree.proof(i as u32).unwrap();
            assert!(
                proof.verify(&mut hasher, leaf, i as u32, &root).is_ok(),
                "correct fail for size={} leaf={}",
                n,
                i
            );

            // Serialize and deserialize the proof
            let serialized = proof.serialize();
            let deserialized = Proof::<Sha256>::deserialize(&serialized).unwrap();
            assert!(
                deserialized
                    .verify(&mut hasher, leaf, i as u32, &root)
                    .is_ok(),
                "deserialize fail for size={} leaf={}",
                n,
                i
            );

            // Modify a sibling hash and ensure the proof fails
            if !proof.siblings.is_empty() {
                let mut update_tamper = proof.clone();
                update_tamper.siblings[0] = hash(b"tampered");
                assert!(
                    update_tamper
                        .verify(&mut hasher, leaf, i as u32, &root)
                        .is_err(),
                    "modify fail for size={} leaf={}",
                    n,
                    i
                );
            }

            // Add a sibling hash and ensure the proof fails
            let mut add_tamper = proof.clone();
            add_tamper.siblings.push(hash(b"tampered"));
            assert!(
                add_tamper
                    .verify(&mut hasher, leaf, i as u32, &root)
                    .is_err(),
                "add fail for size={} leaf={}",
                n,
                i
            );

            // Remove a sibling hash and ensure the proof fails
            if !proof.siblings.is_empty() {
                let mut remove_tamper = proof.clone();
                remove_tamper.siblings.pop();
                assert!(
                    remove_tamper
                        .verify(&mut hasher, leaf, i as u32, &root)
                        .is_err(),
                    "remove fail for size={} leaf={}",
                    n,
                    i
                );
            }
        }

        // Test proof for larger than size
        assert!(tree.proof(n as u32).is_err());

        // Return the root so we can ensure we don't silently change.
        root
    }

    /// Roots for all trees with 1..201 leaves.
    ///
    /// We use these pre-generated roots to ensure that we don't silently change
    /// the tree hashing algorithm.
    const ROOTS: [&str; 200] = [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "50ae5b142a0f31db537ba060ba07e46fafe1ec960ebec7b6f08f03dafe774f52",
        "fce6b9d873d5a92d828695fbddb93d0cecc76747e311035cf7b2a80532f65ea2",
        "33635879d11892586d0735076c9d1b9d661344861d46aa96c36450b71a32300c",
        "e5e67dc697801aea53044bc042a0e8724abf1f96512c0b4a4dd9027697fbb160",
        "4fe4f8ada41e7d98d2344a7faec0360cf4c718318c6cce2bbfdad544288ab746",
        "1a80d0ad0413511f1a56490d9527a5dd2f4686884c4fdc4e912221b7a67462c3",
        "924aeecd88420edaf033e055f276823ffea95eb965f8a24bedd3b71ff7a4e00e",
        "48b65ee4de800d7ab900781dc0257bf22675e5d921395e4392e1f1ca81095d06",
        "846ab5f09531e4176aa66a6bd03d83f7503c16dfc494aa7cf600825bb11df9c3",
        "bd491c9ca0678c29f61ad2affcfb313edbbd5f59c58a7c0d5ce1f0dbb7baf282",
        "422aab7074448c8d5563ba5636f18fb46ccab9de0a12c997d82d12f0273a9477",
        "4ee0c261ba4eb3902ac003b6789675f7a2ccb09ffd23249fdc457f436e675b18",
        "e303776cd1f6f708659765f938dcb79ffe7878f03b67d97947ee8320c2377480",
        "787847b8cfd106d7264ed6280c72d4e5e62294c8c4f786f486b16217b993fcbb",
        "2d7cb674b223d2b3bf82a3d76d53b58eb542b5f9cec672f075c2cd3056a869f8",
        "9888bb342b33693d7885e1a84fa9cd803bdbb3fdb5593f6cabdd68511fc34e3a",
        "d491440069227e34868e75ea9c4c0946bc3084651798946916100de64b1ee2c7",
        "b3f496525d3b4b9db0d409a954a0f29078b1c9f7b4fbc5d32e4615bfbf657ab3",
        "3ad08b0ce43aea793560e5b093398abfdfb37310e86c8bf0cfa91e7573f80100",
        "86229048316a1c894883a9e3a8d3c3d3e95f0b843d1f648f9e58462aff9f3148",
        "143f71172df1ea73e59c795d0b3a7ccaff6cb9d934200ddb7fe485a02bbcb25d",
        "688a6084995fb4d5b65592f8fac5b5347d46252ff08059d825884ed7b46a92a9",
        "1152caa5f17fd92aa0f86b4ec07a442b176b62961e525bfe84d5b82913ab5269",
        "71e367ea9deacf960f80370f169accf59345b77e02e780bf916e9daab0be060b",
        "05bcda0901af59dd91b74c3f34edc6f7ba9e4b6e61b77888053a02c65f7b75a3",
        "6c8e49673a96942fa83ff46c4f82511806d7185e7025d8b39df159b98b1394fa",
        "a38f666a29ea9c6d084eebce18a31422234db99be0e947205e5b6fb05dc344a4",
        "b9325d2e47b15e451928b96feadaf29ae57107e15f28f04a59f54e44b3e152a0",
        "5e35af451db9a82e17a904e477aa48ebf678abd3527c5a7a6c1e0d0cae033196",
        "eb1e3e7c34f35cee920cae35d779675f8f0e4a226d513ff72e67a61f1cb07bed",
        "dfffa428315478482fb39b6cabd19b82c4abe0fdfe28a2d8b637b00934694d26",
        "e8af2e8391e3fcec5a1a4acd0df713dd56abea1949234aeec4f999c57adc6886",
        "9ffeaf6d1802438062656b7a8ac052287b349172abb1cd0c6102de8d782c773b",
        "637127e22c8c5505c95637436a8c7872523bb1e05000ce3b026b2c60335a9ec6",
        "3a5ae08c9837b67941f2096b4e806b8bf54e1d11836e3b54c2d1ddd8be81d339",
        "b9e868d4441e850c8989ab140cb7e7107fa916a7cc9f10532460669b5d185fb9",
        "ca4e9513943517c7756ecb1fdfcf941f8b296eb59ca344960ddf447fc811b3fe",
        "e889aa56a848a2b283fd3fd6e134fc83450c0d6c1d01f576c2bb5eb72a87f409",
        "7f37830b35e2eaf1c22658508a2cf8cf2c4ad138ee96bbb4dca6d466699ab09d",
        "5f30c90f31b8a32a117579c89ef258d3621e3c4ffd0051b50fe7032e7d16024c",
        "022e9efb9c643379420118e4553d2355eec5e3bcb3502778bc4b2e85d57b4795",
        "daa5d97c2202a64210ec877a9075dd17fb9f6178ad6b0905809a4d79df13e3c8",
        "5d2873958ea245ac1e8ece124ae9fe1b5cecb36034a0fa644f447026728bcabd",
        "7744dc3b7505d01edc098edb6873e8e923d371ec777b0abe2d7fc0f5e5abfcff",
        "52fe4af553d4bb631cc42ceabb7395fd2a234ee1431b8720571d2878e4676e4b",
        "c46c4647b7464f67c19ec8a66815b87487070fd0aad02dd51c537af08e7036b2",
        "004828da3fd62ee55449394a54882573d2ce5f323e45cf021e99ca0c3f4b12fd",
        "aea7466b24c3537178dfb0e2b23254162230c36613664f546923edda8f4a9cb9",
        "12b52d15244e3e4f01f2b69dff8b18e4d30cda39e3d87b09875fba0918c0f3c4",
        "cb774e0aba6a497ebeefdac5237ea4b91cf02d8df761e4d5931bca06f92ba7e7",
        "730fd826be4ae1482b88affb6e74ff3461409903a499f86170168f4634a3e36b",
        "12ac285defa63afcc7a47541993837d2da3f81def14004a058d0b82c340f3f28",
        "e661d6c753cf32fa26eefa5d2c1e4602386df79e96b1e0bd3a54454de6fadc1c",
        "608587b5ae578e310be49be55fee4d950bf85cda31af2ecd0306bfc34fab61d1",
        "a41205347e79e7b2a688422cb620caef3862c06be97c3cceb0cc6cef39fbafe8",
        "d332d4863654ba825c0e1ddb63b9a0c1bf35aea89a28f0c7234ec104e4e9e8e8",
        "d21f7cbce3ba334611617b73f5abf283d17ca7a7a0e460f4e4c559bb6175cadb",
        "ec13e53573f637e38ce6f45b55e8a9967f3121ee30b52fd2b8b680512b175ee0",
        "b137cc53ae95e87de14667d94bfc77015d29ae978c09ada78ce00061b03f7d56",
        "f41819163d7e13359c09c50776f0da810dc39d6e15ea67f2b047dbd2a609933f",
        "f128a3ee5cb5b6d687aaf6908445256de0099d976346ef6e5496bd51a2b7400c",
        "94141d70b9b61b86ec050753f11a9f2d275f3d28a07d044c7f0d8736128252a9",
        "80acd071567fcca9e8740fe47d29c1197b2df093e22197c53e6176d9b1565045",
        "55871c3b57591746d7febac3e386dd838cf13276572daf484332811f1a62e8f4",
        "7674ec07655fb1f00bc1c46f9f7b3847674815b4c8a05327ac6a40ac031c7616",
        "253794e58aab5d5ad517c2e1d007566e25c8be42033c1255f4139dc014914c2f",
        "ad0ad5f5c95c2e5ad0f78354bafb7563f0c6573a74253145373ffc24eb13debb",
        "c322c8902b4a4c10879856222f820d8f92ffd15d25d5d461a1ac126954580626",
        "1e1be47b4c0b321f3ac638039ff9e47ca6ebadf15a6230699c6405a3ed7044dc",
        "225a9d06465ac4b1cf65528c799966c5a8344e484d31289c8cfd9d29202bd02f",
        "17382a91ee6946f78cb712e53a9e58d6c0e07a26be2b47463ecbfcada335dd6e",
        "4635742a72a250016f3c92d510d3aa64b2f7f2d8f739cace99b49ae20bfda981",
        "0b49ac169f476f95c84e376ca86c7ac66a82df44bd6783edf238be23bffaad5e",
        "f18d45122b929ae17a7233f60414b5626577eb00b00e106a1eb852a6c4cf7f57",
        "3ab2fb11c3d06ca1d8228402b7f6f3ebebc2072305e015fd142c51675cfddbec",
        "c9dcb27313895d2f7c67af4d6ae6734a22aecc49cec0b9f3cdb27eed7e4d8f03",
        "ed4397b2d47b98848253e66d79aba7bfa2beb2a44ffc3aa6d9b4056fcfd099cb",
        "b35074c978d512800e700adfddf0a73fbf4de49215cfdb69430aa51525ce507e",
        "58093e52dc8e10fed83fd8f60a6ebd5980cde59667044d3eaf6dd942c3dc110a",
        "b23225934ef6cfbfc2fd95da072a030d8a4815502bf15d14f90a64b6b6bd1a83",
        "e66ec3aff80f8224a1012ef0fd137e685ab294c4a3d47b976553d13afcc130cf",
        "b06ec0ecaa3d9fba83a25bb25b44ef88ba66748c7dd6ca4692fa6c3efccfb44e",
        "0a9e7cbb5b1697e45245329a5a4bff4b2ca1a93a7f1ed1cf8a552ac6493131ce",
        "f9f3a65472790ca66b908e0e8bddd2040aa0db36557f453df8a8d6b4604a12c5",
        "0650349d871b9efc044110657c49eaa2dcbb27257a320d6e59a18178c237ec38",
        "49c04edb1576b51db9fe0bd990dbf16b90418837be51c7983b32d76bbf2f9f30",
        "1b2ece1a345f9e762235b01c8f644277408281545f063732183386bab2a09dce",
        "182b36c2af475f3ca465b409f8a110ec6a23e0e5388730ed7920628bbe15268e",
        "a8aecf727c29a84d4e15be02399f78b4fd0f1b45a48d30062a8c871de684b612",
        "9e0bc42a02db1b41d4ed9a7c6fcab527085c469b37471bc20f89fbeedd5e03ce",
        "3b89297f5235f95c35dabe6235dd89958af0b15b1868e5151cde112fa3039773",
        "15e7c5ef9b6c731b075322897799f54ec8622a00ca90cceac3411f83b49ea237",
        "79e2533ad3eebb44325eb5a5b93e7cbb67278b564eeeff4a029c802935527a01",
        "3a691d7163b2ff4bf566c0bee7ccef767a5303d3a9319729d799ae12e19f4c1a",
        "5799066961c8ca5c5b3d62e90e407fa51429488fd14c80ba8ba28529a2071c84",
        "ae530275bf76e94083b2c8de75ad44fe7ab4d45c46fd461ca796a7a2803e7608",
        "3f8eec5de2cc57152c9d58caa5fd4d2a3ddf22d666eae9a6ae0aee433127f9f6",
        "00f16a9bde34a6d3c1b0c21486165cc32dfa840e3a07da864625d7a2b1d493bf",
        "e57b868d21768ac786eca4889030c7517af93102198b0cdf15879bb12e434985",
        "48a705b3265d0696a69c7870d05052ed0d24c9c094727408be4429f6b236db62",
        "14e0743518594de85852563962db3b63688dda7034f86f86b903c9bec21860f2",
        "9d1b3b67045dc6b85b3a2c5cd4c2ed14c6ad2d1f17740a6fe29387865e433c71",
        "ca5afe197a9aeb4020a6110ac693e84b174800e4de4bd92d9a15cacf7d77f598",
        "7f833e5072a4c8c3802613626b5afa42a69790614f4fd84ee269ce2cc8de08fb",
        "d4f5f4d6b6c185e1d68dcac5d4e7d55828cd94c1eb6170e75d0ca474e21a14d8",
        "eaf15269b6f147771746cf2cd7f8b6f2eab92287a8468f03127eab68b78fcfa1",
        "f84c317503d500c03b32e2d14360a6d1877e791f5cccaccc9c0e15c71ed85705",
        "e0e6d90287b23f7065a13537ed8353d43bcc14b80e6902938db6cf5ac43e79fb",
        "2e244362779d657581f0a9879daba8acbe1c7234a2e27eef91c8a0a1be6c6efb",
        "7086f9c9e40a5f576235d41dac2187001ff1c315cc94dd3a0feaf3e905be7f7a",
        "4b9e14b2834ab37608e3ec4b85db30a4b45d0caf78dd6363e02d8802a2d51a41",
        "e3e44f53cf473636859fc6d6eb05dc505e5a56c612216636a44c8eac8efad382",
        "99d4638fb24b7aca63e936a60abb74abb70d7797643879be80735605a7e2a2ed",
        "1e8401b6c65c67dc544e9a1ce21c6ce9903702ac30c93d0caa0df64b6c0e1e36",
        "1bf14f3f0372956833770f87e9145cfc0a5b0dc985b1b694353e705961e94738",
        "ed9b69ad2d779f82b2d1a97a5bd1e2f941b2edfdfd82db99f121561964345128",
        "035c58d5ac8a38fc0e6dec6472f3459f47c17f76bb04eef929064482f5bfb2a9",
        "706ff9580c8869ab68edb9e801b5c631377a10ac07617fb34d9250616231ad52",
        "f9b815729a5cdfe9f1ebcaaca36a658464a5d49c2dad1dcae7aed2688c2209a7",
        "8c1e7468650b0f8309c23b7fb453ce59ab989fcaa80fa32bd82d02c25fc19b68",
        "557a00a4e6d55c60a033b23ca20975f5c774ed0fef3bc316f68fb4a6df66137e",
        "06516e2e9e5fa3583c643209666758483e38c642757e7a452ed29d716229370b",
        "f708b4d19acfadd56e1e4275ed1191d285c656ee045efd2b7049539a39caf5a2",
        "00a126e14b8ec6f7e7e31d0d4b551a24fcbcad62045490feb532b0b78d15a411",
        "c47d49034a6a7ce59fae50d10153fdd619783c39265789a7858b420cbc32b56e",
        "c7d67122fc2b83e565ee0108e16753936f2bb62128d38237454053e60ac918a8",
        "18db7a4c3694b83c2258a4bafdd062cf20d80d356d9d899bc429be9d732dac0e",
        "e3e55212157e06d8745eb23eb4a391611abf0d9e98efe19b482d0d0fdd66a053",
        "70d1830363a58704b037f018a417b7e8682f7a2bad6ed5eaefacf335b9f2de13",
        "559e34d21bf90025d69c0401e3bfb70abfd470fcd4a64f739728f41c0fed4075",
        "73828339c42835cd9f48291c11322d905a35e4d0cccca4095a93a1e4bb778664",
        "7f4cba2e2e584eae771dc328099a098819a6625ea5b2c9382120a1504964841b",
        "a1f44690445ccd1b9930f615e416aeda750601a49631b4eb536f6fd709293f0e",
        "5de9674bc7412231cdb526dc17bfd2e0ed0635be4224d9f72c16378bba7ad8dd",
        "7b217e77ea4175029928ba4839f6d350df9e41b67cff183b1a43ab52925193ca",
        "53bea1bad7659ccd0feb50136fc5093878888fe0cb16dee5ed7503b01d96e4ba",
        "084e489bf686d41db4e8f0ff1bce15a40ac24b948ddcc377a8095d99751673ea",
        "bf67b177d3000a2ac7df34d422486cec6606c6ee82ee50aa91dd98b567957f6d",
        "2f5777d29dcb3c78730c52fedff7d57270125f9a8a570c9d30cf0ad141803118",
        "3c06f61c8b538beb4a557bbdde61a379a631972b3d0698fbb98c68c874744698",
        "12d7d4f4c868b645681dc988d3a170b2f6e425c067ef89ee7a7f07c801ba226e",
        "6f0a289c5c41336a1b5d32aecaec5aa57d1352e319820b80e84d38979ce1ea2c",
        "a8e2f08c46aeadcf56bb10d427418174269e679af7a53c7a1fe92c3fe13f133b",
        "e7e04233a526c7b513eb02d65b8c81b48edf95782d0fbacd0ece7d391f3a7598",
        "d0c677a7b01abb943f00ab1dfa2d4097c4b2309566d6a9ada3cd0f0d1041b449",
        "2cc6597dfd2903bb9e8549f2d1f6842f0e136b0aab9872bbf4b86f49b59c3678",
        "0f230a73d7922eae8290b989014806fb9e6e3c042fa87a8adc742b31e99c4dcc",
        "ec0ab16c9228a1671d6501189cc53dedaafe17cb3aea8119f77fd78d035ec740",
        "f80b66f4f25c4995b19cb973dfd5be34cda67e47e359e944d7fb6ee63e4a64b4",
        "791066ca90c59ab7729bc242be45e26f8f1343656ed63e7c597eb3618ac34036",
        "5efea2b25d7407a8c14a9d0f232e7280a9b13b14e48635925be0703547060f3c",
        "5bb18cd0630e2cefec9817220b3561157f893570cf8f7374eb5d4d374be7d3fc",
        "97d1a186229ef63fd0616c3dc36777065ad201b11109b8a8b43a7326c868cd72",
        "d715dfb79b1bca2e5464e3c2c1f7b9cd3b3962fb7a9b42ddc629efd76a5b9b0d",
        "bb9960745bfd91f49aedda17a5151d3f2105523d637e8df3c4a19e201688e3ab",
        "4d694f1b092b6c514f50b832d483d14cbf2d22435c1d64b0a0143b1b91a7db0e",
        "f4aec328caed1748906126cd72f9dc032dc529e3cabc9a55f96ff7f08e136630",
        "65d7ca2883222a70edb0acadb0d969fb3824224e3de365ca98b8d41124955640",
        "5a7c37a041319dbc68a2aebb98d18dcf971bdd26f7679fb4c8d71023dd62e763",
        "45c7c8a9c1a6d073df038a63c8fb3585750f2186020fc42e67388ed90d687334",
        "76ceb2ed736c577275c47a270f13fc3f829db8f677fe52117a7916913f8e9f07",
        "83616f52af18dfb6bca88c39905c24d1d7443b8fafcb408ba92e3357bf64826d",
        "6184a19e674eb02c014ffd52ccfae8451d78bdd371d7f3c5d9c0b034ea75f34b",
        "73cbf19495785c2a8822229e71ae5246cb0572f5bfc31ab0c95a6f9bdbe42880",
        "ad417fcc01c49775fedc526cac80ed9751799f50db513d7107da4b5539e25025",
        "fcf56dcdb68b31aa8c71404585a886cfcc978e08be8f64c6c3ce8438044013ca",
        "f4c9a1a92630aa75afd8b8dbcaafdc212ffb2f34b69a7bdb2f40609aa332236d",
        "b932d9bc11b9f21ab792e3b5dff181a56cc9eeab2f3ee7afe4d3c82317fe3b9e",
        "f78f6c3055d0c1c49fe4303a4e97de9e85107d084a542e15d3a1f59d068d48cf",
        "aed078316e0c3c4624d12b253adc31114011bdc8550b3cf9aa7a3ae3528478ae",
        "67879ad6b94d3e536c41abcd2719df496d990e360e3cd1bf6168ad34681c9b7e",
        "3d9c7c5590c129b3ac13384367c823d2bf4fe8b681d617b3b5d627494897753a",
        "c5b437bb860c077c0a42eaf4574418da19681dcd8bae66f39d64c28488d73715",
        "c3a56646dde6bef7edbd352447a84d11887f90e6c701ba3f416657c2266e7dc0",
        "8d2540362789502dfb5a288bc65ac890265a214a0cda02f5ceaccb469b0cc137",
        "2e45352b458f89889bada37cf933852d182a7824113b025b88b6a85cb269c6aa",
        "6fc01506749124063a43a2120245bf3b1c5aea36f3d59bc39dc51e057e75f71f",
        "588efc61ec42e19f898bd5d958a7365c4c3baf8038a64a1460806f3cdc21948f",
        "808d865fc016720e9bf61a0d5eaa015f6f187d41d7633845c92c6cacdfe613c9",
        "e6a1d190049b0c050e189d26c00f96e2235eb8bcb196aca24fdc62fd0ecb9eae",
        "1a306d0a919c071c844e7bba1c052090637ede6b61cc4683f0f4b2c461eecdb8",
        "4e45867c281c31ee45c7fca4a8360deba83194d8e564ee67f3bf93ed3957bec7",
        "bf6327fddf29b861a04f968dc5774cfef7b3e10eb1f245e5efa8fd83fafa2bf1",
        "3e45cc36fbaf609569d86d61b35149cdb76ad98f89ece8346f3a37a3c1719cf4",
        "880158cad3643cf9a0edb91393c32054ddbc1f246e033ce487c8eb4d107c1194",
        "bb0df4b7018c0263acab38f3b17f39b275825c0f68d4433309723398933b8da7",
        "d7e391633d0961dd8a570346483012a0b6f63e00d246111fa34f2ccc47fb8703",
        "8200353a6675b2cf6f8d582522f4b5a3631c7d63e1c2241f11663349e76462f3",
        "fac2e4190f279be818ea9aa3480dc4a1e3cbcf7f0882f8e31c2157ef0508e90f",
        "17749a05e9cae5177d8e0faba46da779823d3e8d86ef5ed79b54d78135bb7223",
        "87028314fdab0aa49907b7ce8b8f3908907295d7e0c0b6bae2fe9b5ba5c0ceb4",
        "167183adfd0b5e5969f45cfc8ff6540e15ead0fdcd6c9dfc298d630759d189be",
        "537a57b808d97bd0bd43c44ed409c104453422052e55d6b5ff6c2f0e094e8be7",
        "91f9ca4ece65c41449b62d0bfc3b3394bd748bb084b8821e4c022a7eece1c612",
        "bbe7726fdfcf0ff06ec19af865ca1f63aa04c17ed76b61048d146a35790ad9bf",
        "e80cd26d4b358842e76d45a4e5560ec8998fcff4675a526d940739338bf427a7",
        "165b46546b409202ee4b213ee9cc36b4e401d90a726a9976c45b9c448df4b8ea",
        "fdd9b0055a0d85ae21f227a875ac22cef20592fba24cebc306cf401ab8d61fab",
        "a7df94accafd8e8cfc78996cb98b25dc2cf28b3eb4983106b50e359b81040eb5",
    ];

    #[test]
    fn test_merkle_trees() {
        for (n, previous) in ROOTS.into_iter().enumerate() {
            let root = test_merkle_tree(n);
            assert_eq!(hex(&root), previous);
        }
    }

    #[test]
    fn test_tampered_proof_no_siblings() {
        // Create transactions and digests
        let txs = [b"tx1", b"tx2", b"tx3", b"tx4"];
        let digests: Vec<Digest> = txs.iter().map(|tx| hash(*tx)).collect();
        let element = &digests[0];

        // Build tree
        let mut builder = Builder::new(txs.len());
        for digest in &digests {
            builder.add(digest);
        }
        let tree = builder.build();
        let root = tree.root();

        // Build proof
        let mut proof = tree.proof(0).unwrap();

        // Tamper with proof
        proof.siblings = Vec::new();

        // Fail verification with an empty proof.
        let mut hasher = Sha256::default();
        assert!(proof.verify(&mut hasher, element, 0, &root).is_err());
    }

    #[test]
    fn test_tampered_proof_extra_sibling() {
        // Create transactions and digests
        let txs = [b"tx1", b"tx2", b"tx3", b"tx4"];
        let digests: Vec<Digest> = txs.iter().map(|tx| hash(*tx)).collect();
        let element = &digests[0];

        // Build tree
        let mut builder = Builder::new(txs.len());
        for digest in &digests {
            builder.add(digest);
        }
        let tree = builder.build();
        let root = tree.root();

        // Build proof
        let mut proof = tree.proof(0).unwrap();

        // Tamper with proof
        proof.siblings.push(*element);

        // Fail verification with an empty proof.
        let mut hasher = Sha256::default();
        assert!(proof.verify(&mut hasher, element, 0, &root).is_err());
    }

    #[test]
    fn test_invalid_proof_wrong_element() {
        // Create transactions and digests
        let txs = [b"tx1", b"tx2", b"tx3", b"tx4"];
        let digests: Vec<Digest> = txs.iter().map(|tx| hash(*tx)).collect();

        // Build tree
        let mut builder = Builder::new(txs.len());
        for digest in &digests {
            builder.add(digest);
        }
        let tree = builder.build();
        let root = tree.root();

        // Generate a valid proof for leaf at index 2.
        let proof = tree.proof(2).unwrap();

        // Use a wrong element (e.g. hash of a different transaction).
        let mut hasher = Sha256::default();
        let wrong_leaf = hash(b"wrong_tx");
        assert!(proof.verify(&mut hasher, &wrong_leaf, 2, &root).is_err());
    }

    #[test]
    fn test_invalid_proof_wrong_index() {
        // Create transactions and digests
        let txs = [b"tx1", b"tx2", b"tx3", b"tx4"];
        let digests: Vec<Digest> = txs.iter().map(|tx| hash(*tx)).collect();

        // Build tree
        let mut builder = Builder::new(txs.len());
        for digest in &digests {
            builder.add(digest);
        }
        let tree = builder.build();
        let root = tree.root();

        // Generate a valid proof for leaf at index 1.
        let proof = tree.proof(1).unwrap();

        // Use an incorrect index (e.g. 2 instead of 1).
        let mut hasher = Sha256::default();
        assert!(proof.verify(&mut hasher, &digests[1], 2, &root).is_err());
    }

    #[test]
    fn test_invalid_proof_wrong_root() {
        // Create transactions and digests
        let txs = [b"tx1", b"tx2", b"tx3", b"tx4"];
        let digests: Vec<Digest> = txs.iter().map(|tx| hash(*tx)).collect();

        // Build tree
        let mut builder = Builder::new(txs.len());
        for digest in &digests {
            builder.add(digest);
        }
        let tree = builder.build();

        // Generate a valid proof for leaf at index 0.
        let proof = tree.proof(0).unwrap();

        // Use a wrong root (hash of a different input).
        let mut hasher = Sha256::default();
        let wrong_root = hash(b"wrong_root");
        assert!(proof
            .verify(&mut hasher, &digests[0], 0, &wrong_root)
            .is_err());
    }

    #[test]
    fn test_invalid_proof_serialization_truncated() {
        // Create transactions and digests
        let txs = [b"tx1", b"tx2", b"tx3"];
        let digests: Vec<Digest> = txs.iter().map(|tx| hash(*tx)).collect();

        // Build tree
        let mut builder = Builder::<Sha256>::new(txs.len());
        for digest in &digests {
            builder.add(digest);
        }
        let tree = builder.build();

        // Generate a valid proof for leaf at index 1.
        let proof = tree.proof(1).unwrap();
        let mut serialized = proof.serialize();

        // Truncate one byte.
        serialized.pop();
        assert!(Proof::<Sha256>::deserialize(&serialized).is_err());
    }

    #[test]
    fn test_invalid_proof_serialization_extra() {
        // Create transactions and digests
        let txs = [b"tx1", b"tx2", b"tx3"];
        let digests: Vec<Digest> = txs.iter().map(|tx| hash(*tx)).collect();

        // Build tree
        let mut builder = Builder::<Sha256>::new(txs.len());
        for digest in &digests {
            builder.add(digest);
        }
        let tree = builder.build();

        // Generate a valid proof for leaf at index 1.
        let proof = tree.proof(1).unwrap();
        let mut serialized = proof.serialize();

        // Append an extra byte.
        serialized.push(0u8);
        assert!(Proof::<Sha256>::deserialize(&serialized).is_err());
    }

    #[test]
    fn test_invalid_proof_modified_hash() {
        // Create transactions and digests
        let txs = [b"tx1", b"tx2", b"tx3", b"tx4"];
        let digests: Vec<Digest> = txs.iter().map(|tx| hash(*tx)).collect();

        // Build tree
        let mut builder = Builder::new(txs.len());
        for digest in &digests {
            builder.add(digest);
        }
        let tree = builder.build();
        let root = tree.root();

        // Generate a valid proof for leaf at index 2.
        let mut proof = tree.proof(2).unwrap();

        // Modify the first hash in the proof.
        let mut hasher = Sha256::default();
        proof.siblings[0] = hash(b"modified");
        assert!(proof.verify(&mut hasher, &digests[2], 2, &root).is_err());
    }

    #[test]
    fn test_odd_tree_duplicate_index_proof() {
        // Create transactions and digests
        let txs = [b"tx1", b"tx2", b"tx3"];
        let digests: Vec<Digest> = txs.iter().map(|tx| hash(*tx)).collect();

        // Build tree
        let mut builder = Builder::new(txs.len());
        for digest in &digests {
            builder.add(digest);
        }
        let tree = builder.build();
        let root = tree.root();

        // The tree was built with 3 leaves; index 2 is the last valid index.
        let proof = tree.proof(2).unwrap();

        // Verification should succeed for the proper index 2.
        let mut hasher = Sha256::default();
        assert!(proof.verify(&mut hasher, &digests[2], 2, &root).is_ok());

        // Should not be able to generate a proof for an out-of-range index (e.g. 3).
        assert!(tree.proof(3).is_err());

        // Attempting to verify using an out-of-range index (e.g. 3, which would correspond
        // to a duplicate leaf that doesn't actually exist) should fail.
        assert!(proof.verify(&mut hasher, &digests[2], 3, &root).is_err());
    }
}
