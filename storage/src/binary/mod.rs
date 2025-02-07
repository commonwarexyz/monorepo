//! A stateless Binary Merkle Tree.
//!
//! The tree is constructed level-by-level. Level 0 consists of the leaf nodes. At each higher
//! level, pairs of nodes are hashed with their positions in the tree (if a level contains an odd number
//! of nodes, the last node is duplicated). The root of the tree is the hash of the top level and
//! the number of leaves in the tree.
//!
//! For example, given three leaves A, B, and C, the tree is constructed as follows:
//!
//! ```text
//!     Root:                 [hash(3, hash(4,hash(0,A,1,B),5,hash(2,C,3,C)))]
//!     Level 2:              [hash(4,hash(0,A,1,B),5,hash(2,C,3,C))]
//!     Level 1:              [hash(0,A,1,B),hash(2,C,3,C)]
//!     Level 0 (leaves):     [A,B,C]
//! ```
//!
//! A Merkle proof for a given leaf is generated by collecting the sibling at each level (from the leaf
//! up to the root). The proof can then be used to verify that the leaf is part of the tree.
//!
//! This data structure is often used to generate a root for a block digest (over included transactions).
//!
//! # Example
//!
//! ```rust
//! use commonware_storage::binary::Tree;
//! use commonware_cryptography::{hash, Sha256, sha256::Digest};
//!
//! // Build tree
//! let txs = [b"tx1", b"tx2", b"tx3", b"tx4"];
//! let digests: Vec<Digest> = txs.iter().map(|tx| hash(*tx)).collect();
//! let mut hasher = Sha256::default();
//! let tree = Tree::new(&mut hasher, digests.clone()).unwrap();
//! let root = tree.root();
//!
//! // Generate a proof for leaf at index 1.
//! let proof = tree.proof(0).unwrap();
//! assert!(proof.verify(&mut hasher, &digests[0], 0, &root));
//! ```

use bytes::{Buf, BufMut};
use commonware_cryptography::{Digest, Hasher};
use std::mem::size_of;

/// A stateless Binary Merkle Tree that computes a root over an arbitrary set
/// of [commonware_cryptography::Digest].
#[derive(Clone, Debug)]
pub struct Tree<H: Hasher> {
    /// Number of leaves in the tree.
    leaves: u32,

    /// The digests at each level of the tree (from leaves to root).
    levels: Vec<Vec<H::Digest>>,

    /// The root of the tree (computed by hashing the top level with the number
    /// of leaves).
    root: H::Digest,
}

impl<H: Hasher> Tree<H> {
    /// Builds a Merkle Tree from a slice of leaf digests.
    ///
    /// If `leaves` is empty, returns `None`.
    pub fn new(hasher: &mut H, leaves: Vec<H::Digest>) -> Option<Self> {
        // Ensure there are non-zero leaves
        if leaves.is_empty() {
            return None;
        }

        // Initialize the tree with the levels
        let mut levels = Vec::new();

        // Store the leaves in the first level
        let leaves_len: u32 = leaves.len().try_into().ok()?;
        levels.push(leaves);

        // Build the tree
        let mut pos = 0u32;
        while levels.last().unwrap().len() > 1 {
            let current_level = levels.last().unwrap();
            let next_level_len = (current_level.len() + 1) / 2;
            let mut next_level = Vec::with_capacity(next_level_len);
            for chunk in current_level.chunks(2) {
                // Hash the left child
                let left = &chunk[0];
                hasher.update(&pos.to_be_bytes());
                hasher.update(left);
                pos += 1;

                // Hash the right child
                let right = if chunk.len() == 2 {
                    &chunk[1]
                } else {
                    // If the chunk has an odd number of nodes, use a duplicate of the left child.
                    &chunk[0]
                };
                hasher.update(&pos.to_be_bytes());
                hasher.update(right);
                pos += 1;

                // Reset the hasher for the next iteration.
                next_level.push(hasher.finalize());
            }

            // Add the computed level to the tree
            levels.push(next_level);
        }

        // Hash the top level with the number of leaves in the tree
        //
        // We don't do this in the loop because we'd have to special case the handling of
        // single-node trees.
        let last = levels.last().unwrap().first().unwrap();
        hasher.update(&leaves_len.to_be_bytes());
        hasher.update(last);
        let root = hasher.finalize();
        Some(Self {
            leaves: leaves_len,
            root,
            levels,
        })
    }

    /// Returns the root of the tree.
    pub fn root(&self) -> H::Digest {
        // Note, this is NOT the item in the last level.
        self.root.clone()
    }

    /// Generates a Merkle proof for the leaf at `position`.
    ///
    /// The proof contains the total number of leaves and the sibling hash at each level
    /// needed to reconstruct the root.
    pub fn proof(&self, position: u32) -> Option<Proof<H>> {
        // Ensure the position is within bounds.
        if position >= self.leaves {
            return None;
        }

        // For each level (except the root level) record the sibling.
        let mut siblings = Vec::new();
        let mut index = position as usize;
        for level in &self.levels {
            if level.len() == 1 {
                break;
            }
            let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
            let sibling = if sibling_index < level.len() {
                level[sibling_index].clone()
            } else {
                // If no right child exists, use a duplicate of the current node.
                level[index].clone()
            };
            siblings.push(sibling);
            index /= 2;
        }
        Some(Proof {
            leaves: self.leaves,
            siblings,
        })
    }
}

/// A Merkle proof for a leaf in a Binary Merkle Tree.
#[derive(Clone, Debug)]
pub struct Proof<H: Hasher> {
    /// The total number of leaves in the tree.
    pub leaves: u32,

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

impl<H: Hasher> Eq for Proof<H> where H::Digest: Eq {}

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
    ) -> bool {
        // Ensure element isn't past allowed
        if position >= self.leaves {
            return false;
        }

        // Compute the root by combining the leaf with each sibling hash
        let mut computed = leaf.clone();
        let mut level_nodes = self.leaves;
        let mut cumulative_offset = 0;
        for sibling in self.siblings.iter() {
            // Determine the position of the sibling
            let parent_position = position / 2;
            let left_position = cumulative_offset + 2 * parent_position;
            let right_position = left_position + 1;
            let (left_node, right_node) = if position % 2 == 0 {
                (&computed, sibling)
            } else {
                (sibling, &computed)
            };

            // Compute the parent digest
            hasher.update(&left_position.to_be_bytes());
            hasher.update(left_node);
            hasher.update(&right_position.to_be_bytes());
            hasher.update(right_node);
            computed = hasher.finalize();

            // Update the cursors
            level_nodes = (level_nodes + 1) / 2;
            cumulative_offset += level_nodes * 2;
            position = parent_position;
        }

        // Hash the number of leaves in the tree with the computed root
        hasher.update(&(self.leaves).to_be_bytes());
        hasher.update(&computed);
        hasher.finalize() == *root
    }

    /// Returns the maximum number of bytes any serialized proof can occupy.
    pub fn max_serialization_size() -> usize {
        size_of::<u32>() + u8::MAX as usize * size_of::<H::Digest>()
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
        let bytes_len = size_of::<u32>() + self.siblings.len() * size_of::<H::Digest>();
        let mut bytes = Vec::with_capacity(bytes_len);
        bytes.put_u32(self.leaves);
        for hash in &self.siblings {
            bytes.extend_from_slice(hash.as_ref());
        }
        bytes
    }

    /// Deserializes a proof from its canonical serialized representation.
    pub fn deserialize(mut buf: &[u8]) -> Option<Self> {
        // Get leaves
        if buf.len() < size_of::<u32>() {
            return None;
        }
        let leaves = buf.get_u32();

        // If no leaves, nothing to prove
        if leaves == 0 {
            return None;
        }

        // If the remaining buffer is not a multiple of the hash size, it's invalid.
        if buf.remaining() % size_of::<H::Digest>() != 0 {
            return None;
        }

        // If the number of siblings is too large, it's invalid.
        let num_siblings = buf.len() / size_of::<H::Digest>();
        if num_siblings > u8::MAX as usize {
            return None;
        }

        // Deserialize the siblings
        let mut siblings = Vec::with_capacity(num_siblings);
        for _ in 0..num_siblings {
            let hash = H::Digest::read_from(&mut buf).ok()?;
            siblings.push(hash);
        }
        Some(Self { leaves, siblings })
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

    #[test]
    fn test_merkle_tree_empty() {
        let mut hasher = Sha256::default();
        let tree = Tree::new(&mut hasher, Vec::new());
        assert!(tree.is_none());
    }

    fn test_merkle_tree(n: usize) -> Digest {
        // Build tree
        let digests: Vec<Digest> = (0..n).map(|i| hash(&i.to_be_bytes())).collect();
        let tree = Tree::new(&mut Sha256::default(), digests.clone()).unwrap();
        let root = tree.root();

        // For each leaf, generate and verify its proof.
        for (i, leaf) in digests.iter().enumerate() {
            let proof = tree.proof(i as u32).unwrap();
            let mut hasher = Sha256::default();
            assert!(proof.verify(&mut hasher, leaf, i as u32, &root),);

            // Tamper with hash in proof
            let mut hash_tamper = proof.clone();
            if !proof.siblings.is_empty() {
                hash_tamper.siblings[0] = hash(b"tampered");
            } else {
                hash_tamper.siblings.push(hash(b"tampered"));
            }
            assert!(!hash_tamper.verify(&mut hasher, leaf, i as u32, &root));

            // Tamper with leaf index in proof
            let mut leaves_low_tamper = proof.clone();
            leaves_low_tamper.leaves += 1;
            assert!(!leaves_low_tamper.verify(&mut hasher, leaf, i as u32, &root));

            // Tamper with leaf index again
            let mut leaves_high_tamper = proof.clone();
            leaves_high_tamper.leaves -= 1;
            assert!(!leaves_high_tamper.verify(&mut hasher, leaf, i as u32, &root));
        }

        // Return the root so we can ensure we don't silently change.
        root
    }

    /// Roots for all trees with 1..201 leaves.
    ///
    /// We use these pre-generated roots to ensure that we don't silently change
    /// the tree hashing algorithm.
    const ROOTS: [&str; 200] = [
        "74897d1add1a13c26a0b9335a8fec97d73e39a098912ed035ad0d66b98a960c1",
        "28bc783481526a7b0437f787154d7fbfc83ce56d1b376f1fd4b96ddfd38393a3",
        "11b2f9bfb1302d563a8a25622615eeeb57541aeec68beb759cad13cee80721c5",
        "fe8095e16d33b630495ef7b59ecc0987d4a04ff8af16c601b53992fec61305dd",
        "c373403f6ffa39f5f72d9cc5a3488dddbda3e188f11ff583fcce06cca2370148",
        "693eca7150af0f16fca412bb446e4eb7beaea44a92e41b4cc81b83728d9f242f",
        "6b78768170df834d8334ea3cc0c88a407994d815f6db403ec1cd302e8bfffd7b",
        "736064eb62350e0c156da1b04b3d45f84b0889b23c1393520123e6d947ed1b27",
        "a26c2cea5f21defea3e9aaed0214c31885e4a85351cdb378981771dbebd4d9d4",
        "519550ab8572efc667cc8f6401d1c6b2b8f551a361e22acf2921d317774f29ba",
        "13d24d70eecbbc0bf484ab671ae9d10ca93562e0644b45536a8bcc958c94b6de",
        "7f197ee1f5b65e2ec63f519fe4591d74cc816edfc847c8abbc357c85987b3663",
        "82d3085ff8ae294bfb4ed24702b52f3e8fc66031e140445103a5bd4372311051",
        "0c4324e8db323619095e51e1926daa4f0c0cd9d173f6ee8c2f2df45134ce66ee",
        "f1f0e63059ac6fcf236d26ef22df2973b39df3e3037a89ee27d8f5ebaa3fb39f",
        "a3567c356be0ec59696fc7a99d0348a13619791297043b0d85062528980e74c8",
        "8dfb26bb4765fd6223466e5b138e924e23c6867f7ee4d1a8ea4f77686a022a0c",
        "eff6bada2181dbfb3f94c7e87dd7cc4fac1dbf7557d25e815ab53b72442c2fe1",
        "6e8286d8fe454bafbd99121010f63aa12abbe661d7495247af2eed6d8cfcebff",
        "3a00c52ab74df335ce7561c93c0a4535d40863ffd45026194d72144746b3864d",
        "e73f765f15be78e122bd8b64cce509eb0b3c33ccc5a512764c0265edc95acb29",
        "40001cc213246a3c6e2fbe6fe02f3f8af4006833a90e3b0214f0eb00a6f107d9",
        "460a64eb9a5d82989cd08dd6fc6cd821ce1b192d1adf5a24c86588cf2614d8c0",
        "131b71fec9b93cbe40849fc154cb59da880d091c40daac3564432d12211da866",
        "b262f76f92a4c3cd1bbf6f8bad716f32e2c8fc40dc1e584293a578692a313e78",
        "9e6e1249cec5369559133175576b0873da94161ac9bceaf0cb6b657d7c936596",
        "61c59b3c44c74cca0a1b5f5b77e3134f74b12bd90955538745974777f0cd45cc",
        "05bb4584e6632fcc66cf7b3fbae5fb9374b7dc962fb3feb3d0c1ecf016952e8c",
        "0946721073bb5d7df7bb77871b2f119e47a9fea4ef51f89633b8d7bd34c5fd9d",
        "a184368e1078f9f4c32249739395741f0d3a0f33e633344e6136da848ca12158",
        "519e897718f69d1447865bdda7825cd7ae17e2e024282f8df967c9864c9cf119",
        "e101061441311ae54c4a40368553d584593c18b04504f26a82071fb932417782",
        "fe551be82e92ae47fc5b575782544022e174b89acb08721983c1a8278fc465da",
        "976ce6a7fd3f771af4703d4fbc0ba0f5b0083905e1659a07b61f16bdd49d48de",
        "fe1dc7566fef3baa91b6f0de76d2ef12dbc24051275e4d330999dd8ab8281270",
        "1f781a79a253678fd8ec02f57306f912e0b91c1233d92076cffd87e3eb99251b",
        "8218265c9034e726fffc81e60cac0318d11a09bf00b0dc821b5b43c3e7af1a63",
        "6a3404adc810f27d27ab554cc2d24becb6d693cd27cde9f3b49626f7c9c80187",
        "4301ed15021968c8fda0474cebe351f423c01eb0879cd7c532ceecf1cee158b0",
        "671295fae78bf742e7e5d569763334c81ba66b09ae4862360a29eb9fb40006b6",
        "d2082416d561c7c4b6024d3a28ead1c45d90fcf0317ff9a15294d614aea7e0fb",
        "a08b0cb0bab1e5b031c601d52fc7bc6c69bfbe88768b7f65c8c3abe90a963c17",
        "a33c18882da40656b199dd92586fae43da0e0f57da39bab8dd4853271ce6f869",
        "07dd46d289405d5c4ffcbf88b74bfa1284c0804ecbb0afd71cd573926c6a99ed",
        "9142a5b9ed5de1f3e778520a4235a9b5098658dde708fa3039d65f60a9d0eee7",
        "830dfe5b0f7344da9d6dad3b5bba167c0dbc01ff0b6638243df0c7c1522bfa63",
        "be9407eb3b262c95a8da80a46461959d9369b00cb94e2f7f34d9bad2ba403965",
        "5e58a8de3e36d69da43fb64abef29ea92bb203fd7e6deb22e4e73fac3381b7c6",
        "f8de29f494bc40b9b503145900b8909edc4037847470a4eee8c382da2345ef24",
        "8254927a346d4ae4fa5a8a5dee675639b66a38854ce672c5bbec76a95768bea3",
        "855f24e757b2e04f7f8c4019c2037fbc512bb0bb42131e69ae6577bc03c1b208",
        "2e23653b40cd04d1056be5a796818aa9a85c88e2fbb68a56fe0c0abf580a4c38",
        "67a7393d7d6426deafb7419ba5aff5f89a35084bec038fe7d7fa95b68decb78d",
        "26d4ebeb70da4911330a5bb95887b737e90d0d8afbc68dcd1e63d10a93e9bd46",
        "6c7630d3e6164b3d6a5b2f9ca40f53e4a74efcaffdbeff5a16e66d7e53b8aafb",
        "2f6a717a47bb25e669ec52036c6a23cb0f0a4ab30f6c804c4407f8de47a2d281",
        "ca0b29fdf966aee2d7e0d9c88058e257421c0f46a63a54003f9c3cb371c44614",
        "7a1d000364ef26fa561fe87d57142425c9d9b9c2a4fec7c231fb3948a54c12fb",
        "bb11cf0ca09ade72d404500d88d7a14ed8ea0b7e2855f24817299bb69d417ca1",
        "d467c37559a7c360a8e4b80f00b9b37ae99de1a9badb1c5d86aa2164fe1c5f58",
        "98bfcf418141d1923a2213da79946632f41ca95ec6bb60c251c8a13e1607fd42",
        "932465068b1c55c311b621417b5b39abedd76701c3ebb5caf2058b0347b3716b",
        "24096d979fb2fb371a04a10a0116a3ccfa3985288d3e43c5e99becfbdb608c9e",
        "cef459f32e102d4aa8015c0482de5b79b1be813db0b699a0b35a763b9943c3de",
        "e136be9136b2b60237a9c561e5abc289f7d5c2b04cd18043600148aae5d200b0",
        "ba59495ea8088270fb04cb5ff32a6d61df831b48d4dadb9e53470e46003b74ad",
        "67b1fd042270a2833fd16cd8de1afc576a8d708e654a2091307a89a3d085ba01",
        "905ae1dd388228cd08eb98380220d0bbecf5b5f6d119ec7282154251ecb5f248",
        "2ea19483d1af47872f416f751d28c61d4cba8e8b8c08bdbb078e55e3fdec530b",
        "c5c38e16eb16a6426bb24d426ffa020b2b67631a0a3f76a086272bb4621ed0ed",
        "a75bbd39199ef391cc6892804bbf99d7284bb3c5636ae87412f285341a3e4119",
        "f9ecc7379ab44ab3ffd2a5e4806f3261be231503e0aafb1e6a47faf4fc67f624",
        "863dc05948bd3b1dcab7882fd9f4e406666524cc675efb569f4983f2bce70f90",
        "88584a2d0b5f1172231d640e1fc084b5f97f1f8fa182bd4e03a4284c03d79fea",
        "46496b3761d1b2313760d05410ec24cb43e7ff6ebbd2d88cb431feeb1f302ac4",
        "542fdc19add3eadab2dcd7edb14350e7c8818de6f3b3d64a65b068414f0e54fd",
        "f1ea337eebc3ba6d8a67242de6cb7eee38bc0a945313df5b41c9755f9710dad4",
        "a6b454b7747a0211248c9ce2e3f656d8632f8570854d71d2ec6666fe9ac2554a",
        "b45e917aa317fafb8cdc443719fac4c2f7e8b8e80c2dd27e211acbf818c48be0",
        "f6ce271b146f56564d7b72770d73548a0ecef02d7314449246ae887c58697caa",
        "8d4a449e879cf6f380ef792503ebecf69b912d3028475c185ad70099fcbfc0a5",
        "963230b13299b8b86b482bb0eaa40311ba0460effb51e1a8aecd7c06fd4da049",
        "a4f66d770441fe31d99108e35c4fe865c534d988c7dc8a52b3d3530fbf38d278",
        "a66ab879621afdc73a587684133ada904c90a45f3e5e9ded3363f8ba657a9d74",
        "094c2b0b59f03afda1daf6a3d91ad45e5e5c87d03464ff7eec9a2f588d3e67e9",
        "4b598b9d4f385041586e2db17e854530f596c3cd9c73696242b925c012d48350",
        "626601ffd266c9c514fdd53f224fb3a58d0a0ae033c8f7c6930fdd4bd96b9483",
        "5f079d5bcecafcae1bfee68bf0b4e05834fa91245eb2103750d11296edf10356",
        "15588f575cacc48b869d88034ccd49ed2216401fbb2f1f9da3b8fbaa0d5aa816",
        "15c07f596a86ab8d1a54d07b196876a7b0ba8fbe56b4bc362ef69813dd3d4424",
        "ba6265c0d9466943fb84f7255f21fd5f3874b746b680e7ef8cc099d9d613890a",
        "3fab7a758a1c2e9bae0b9b59b7ab8ed3cd71430481aa2474a5b308448265fd7b",
        "41234e9ecd3c58ee037d7d501c56d2fd55205a5c4063d140d7af5099465c420f",
        "c78e195889fd7912c3d6952176e46e5a50d83200c14e58b9476f879d3dadc9e2",
        "0e32c5f9325d0b6494e6de1615757da933b0539e0adc852d3ef85f3e1218c46a",
        "c9fb762dc2477ea8519ad78568195740a1789ed5d606cd1f8862b5532226236d",
        "48572eddfe156b6651b8406bee604823e8c41a87f8636043d3b43f2034a1cc84",
        "8aa8cb3c3d3bd76486682b368897dd817b3afd91406e6d4949523d4de8cd5763",
        "53dcc370906cec32900f0f3f6f6ee46d1e8b74e2e898188ed6e506a077d2c275",
        "ff1bab2e5d9722836767699c9dbba369a080618b5b8cddcc3fea8a20f48eb635",
        "aafdd67f76e1592d785f3d4ffa9193a5e568e93034d6dbbc1089bd707a1b1215",
        "2d09e492e428afc6c23fbf18f5926405e1106792c25f07134bd41fad9a14b81a",
        "73e71925d52378696432f3f1619fd8010a44881863460d31d3f39fcef9b7985d",
        "d42c1cccb4073770107ffb38b046f8626ead143f82b2949148fb70c374c3ec1a",
        "b4d3f389c3b46a9de0bb5f256382483daa1327481bfdf2ee19e5bc084ecc4836",
        "dfef8c0afcce1c2d0f2808c6e36fb8dd9fe426a7569f53cb4bc89813d40d533a",
        "a49672e3534939567e4920b80d952baecb0b1196d55b10a7bd4176cd7bd287ff",
        "a935e2f1dc9e899edb2f5447f8ad0e9b42ee2b2fd3cf23acb4308e605a86b353",
        "d7938f0275302d85435bf6be1d6cf39235b31c0997bfec9c5bf45fdd2eea54bd",
        "0ff0bae01496010ada7d68b47f9bc6a9ea8e2710e995f8dd9a48cb58d7b3727e",
        "d13492935dd0cd450568e447f11f709e8b74b14f78f2bfb7be49374d1f2643c6",
        "9cf470b7c53b76a51770599de96ff94ef1d621656de15d2fc28f0554a4f68c30",
        "2d3aeee89db30ac1bcb4e89e853a263dec796e4383655c54b853c75a3d1fe1a0",
        "be710c6dc53d01de94b89e9e9e51056fa59ad68cbd89b3acab966d687254f21b",
        "788d8cf076c7cf24b0b15b3a4a0dbe642d369b2e2c9ea12c3117cb9abe639bf7",
        "481110b8e243fd3494ca951b78c2dcb158a71dbd469351996572a0720d2fbbd4",
        "cbb108316f9cae36f29cc95ee07d3e037b9031f01765725103be23379f1914f6",
        "f2df1319ecfd6f5f024b8f3e8317bf589fa45c4467e5a4a5cedae92285b079a1",
        "7d951e2bedbe1747209e8f40dd3b04589f5b9a46af34c45ec7a21f355479823a",
        "0d60f50f8beb5aeb95eaa179f73b1d28e99688c77af08da0af4487b3102240cd",
        "4eba5ddeb5245e24dbe0016bef08c0a9c2b701fc8031c95dcdee25512889e7d7",
        "1afbbac78c478e0a6cbadfe70fd01942f0d0cf74323b04e003d2dbf66a175b04",
        "533c2bb3008ff103e694e6e89a2ed6c65000d087d429e6da9857969a7a6f916b",
        "46ba730a1ec7f292be1ae5c915534570da0fc871ebfdeb8a550817e09b3d8d18",
        "bc54c8f128a1ea110547aac6bfbead8b9ba85acad6cc716287ee2cc9e0ae9c68",
        "3ff9a06959f23f1c49f7b0fd16352727b5b251b50e89be57ba5c4623f554b8c3",
        "156995f129fe41af1472162f498eec38612bb3f2fe0ca168c845d5da556e7ce0",
        "c90f1c06e5768dc0d6993c74284448bbb37bd66fac18aac1a3b268db4d8502b1",
        "cfbbb0eeddcb0f6b435129bb4c60f1754d63d8e01924dc07cd883ed1b31036bb",
        "aa5b7bfe2358ad71031fe80c1421df3f29a79e63c64e77a33e4defa0eb22b8c6",
        "287c73236a283b6462676d8561e8093eace377cfc30dd5f437ffff078f42c989",
        "1c206b352851354ba4c0e35b7990bab4e93e91cd9c255aa3a99c1915c2a94353",
        "79c72b66506a009f9a8bfd40c4724b608f846a67adb23d75d02c3be6b1e3c017",
        "1fa35d4932f7bc251ed3b29d92e36c4f6efe3fffc57cc8a6f4b87c175154678a",
        "845ab5f5fdd8b15dacc65e41b8bba6b944b2d879407a91717c00d9912860d0bb",
        "ecc3a55a11e900352b57ff093a09d85ea4c22ac591b8d5bc8734132f0a623fc5",
        "007017831c54e1ce2ce7dcc00764f4f7f2adde579261d39ad1215b5dbdf2e5a7",
        "de59cc95c1827f846533a1bee76da7a183b1f23f48a0a75a38575d0eb8b3d4d4",
        "0af0bec17963d93119b475e26f9bd61757e440a0ac5b6e2bd6e07f0865ea7a82",
        "a691e56d49c0f14187bcf7dad11621cf1ca1bb7544b59e65bff524e0ed0b31ca",
        "26aff5ce5255138befdcef15c55e0b87cd9dee85eaea14912fb9889d2610f9cb",
        "995d70ff56bcd5af6fe100e2dddec1fbb2997f9faa05d60eff4eee091721dcea",
        "c7304721c1d5c45ad3af78092e4884e7c9b2e1650042b2200a3091e6593616f2",
        "5618f523d8104787eab0c5e17aa4cb193750bb5d8ea56ea6dca42e9091e3df06",
        "62d00036c40045435cc7ac29475b7b781f8c761dfe6c6aeebaabf1762da0615a",
        "3b14f0cd347d7fd6aa6e41f65ef6926dc8207790533769fa6fcbed3c870b9707",
        "453fc8d1d110ab4d332f42881f124d1d36ccd6d5338ade6bb8304206f07a9cdb",
        "ad4d7f103bd811c512e5ddf7aeb911140c55b9d3b53b2607d6389f313e80f37a",
        "b1636dc64c8c02cb020e62cd8dd40cfdc429382f25d9c76a7677b36e1f6451ef",
        "9fd52d5e5ba45d6d6bb5de062df6a11725d7cad721dbf36bdb3a4d093ab4919c",
        "3ceba44473b1afa063ae6ff552a82f2e6af07816aa5c7672f8673da01981cb09",
        "80073556c925cddbc09a22eaf0207c8a13bf730f4c4bd41b1e7537f692ab9205",
        "fbb6f36e5fc5482745fde1fc3ac7dc8592b1125b02c1331f9c2764bd526b94ba",
        "c4fcb8d00c6391d3cefc4d813e124251503c054c0c1969557830b65897554e3d",
        "a90fabeec20432166fb77581cc2f1f20ae7922c5c5d7786109d66c3a958dcf54",
        "dcae11ba4e66806a20fa3a87d41790241d99a289c67f67be55df75b6239336e5",
        "27ace663238e241a92b493863223b9b0b7e597d3324d099b41527015070d41af",
        "a4760dc32860e8f0757aeff2fb35b72f1fcf6420a7a5ed442eb8dda144b49de4",
        "173eae54c313aa726c253e368ac53f865956bcaaf1378c88c3fb40671e250257",
        "d121d16ef727d3c5591d271244b4221d7a3244550f5cb608253ce3ecd7e270c2",
        "a714c358ce17886c34d3efbf7ba0abb83292dce3c54bb09ad37d5709e0f6029d",
        "3457f4c1bcb55456a657c16ce9cacbf3f73349b16b7e62a909e9b427912ecb2d",
        "67957f7e6a2c7076cf9bc050e5abf4afe3fd830850e5563da083b242cc1bdbce",
        "ec2ce4e197bcf0fd8e0867fc7f545691b83e87b81ad5ade7c668c41b4e5506fa",
        "fab8cae9795d6f0f63dfb7be2c6bbd4d5266261b891992a4a7e721fba8d30b37",
        "9827fd1ae70f52997e81ac0f5cbaed058fe03e8b003ee8289de5c8a37c052c71",
        "951d261a7d35c9b7e82436d8f60b1c470a59311056181154b211a1b79c3dabee",
        "1b3fabe599024efd46e83172c5ea914721fca0364b05f7784992a07ab62d3b2e",
        "07d53917c5848b9488201c4772a966246d2cc1e464c3450b5d5772c98df55753",
        "4294390aafec576f98a5905477f8d83c8e0861edb11874528cb240ace93379c8",
        "1135d6742289593dc4e39661a947cfce7c83c126fb6de64eb92d90d3c4877b25",
        "bc8bbfb3730e6c6b814991f7c1c848e7cf82298dc034bdc38df9165586d03a9a",
        "f96e740723a8b1619f25f1d5876adee03bf3a269aa958772aaa7abdbefb9033b",
        "49d713a47c4f83538ab996296deb44ed625a5c8bb75d1600ec1ea698cb271742",
        "c4824c34946e6953d35e6aadd995503046b66c3f7d09620da1d77a168c658bc3",
        "a93725dbe33e08633ab5a1b5e5df2cf97481d4270cdf1c174411e7e09e454d29",
        "4aaa6c370560ba77112faa95cce9a6676aea4d8a24e47ce42207437367828075",
        "67919b2ce96c55eb6452c0eebe6143183882eb853f0d713e80d98b7272ca816c",
        "0b32659c5a44838d3752a8c9f577d5b7665a3373aba198b1b1d48697ec501459",
        "65ece4450b570029ba9db851ed8b97bbb5166683c11b39b0d01654f8d369558c",
        "c45fca3d41b129b2c80db267bec41c59cde5345f425ab89b41c18c02edbe2405",
        "b28fcdf315fb223603c9cf3160eb6de2f4ea7234e2cc153648453f90c9c4f4ac",
        "7fc1b4821fd12e474e7d0444d833459e41588fef97cb7a807cf2d5c737990381",
        "98ca5e4b2dc65cf9ffa9e498951e48af527da087b024216eac022c42932e7c9d",
        "50cdddf5a25090662c4964a9f929dbd35a161720d48ee275e31ba0e4b729b688",
        "ec63e4ee06161d2076677a1eb61c16f66fd206bd443d07c0c4addd31df4ea39c",
        "50cb46db1e3e240d1a64679367d13fc8fe6ff81c3afb4a489cdb5510e042af95",
        "5502be46a306665dbba10ca4c1ef46cc5838ed8ba7eab1185f8dc8d143b3a770",
        "b90b697e42e111ccd6a8339cb30da19227998e0ddbd11edf3ba273893ed78cf1",
        "a4244baa8de02702cef1630134dae87658e38eba560d83ec26145468423cc3be",
        "2436de19ae00d3cbb74aad2d4b02bf54984c068b5a899abc7e368452e4bca98f",
        "0d4313b1bff6374e20c43e44312f97b4a2b4562c8a2187c3d4f6cd80aab7eddf",
        "35d390910408adb9c182c57acf68408daa142a1288ac9457f99576d503367efa",
        "f452cf0a37c2f882eca8a008ecf7323380de96f44c0353f7fb592dfa405fc8d8",
        "e30bab11075c5f740f2f38630ba85c5c5777ea91c56324ffb974d91d1241bc1c",
        "6971b3055e2337a283790e1a36d2a3a4cb7e5f9c3aaedd6f7b90835a1195993f",
        "3afe2eb34b776a0f720ab556de9909dd79e1d65f4b54bfc6ec97831bdedd7c3e",
        "1deeeacec5adf873301fcf1fd77a9dc7a7bb9527f65da86518101782bc96b8e4",
        "590e313cfaf568f2e23e1e6c425b6b1079435dba3276d4f6ad8b938f53068a84",
        "75ecc296819b85907e6b7452c90bb604a6f6044de5661361596e1b5814bcd05a",
    ];

    #[test]
    fn test_merkle_trees() {
        for n in 1..201 {
            let root = test_merkle_tree(n);
            let previous_root = ROOTS[n - 1];
            assert_eq!(hex(&root), previous_root);
        }
    }

    #[test]
    fn test_tampered_proof_no_siblings() {
        // Build tree
        let txs = [b"tx1", b"tx2", b"tx3", b"tx4"];
        let digests: Vec<Digest> = txs.iter().map(|tx| hash(*tx)).collect();
        let leaf = digests[0].clone();
        let mut hasher = Sha256::default();
        let tree = Tree::new(&mut hasher, digests).unwrap();
        let root = tree.root();

        // Build proof
        let mut proof = tree.proof(0).unwrap();

        // Tamper with proof
        proof.siblings = Vec::new();

        // Fail verification with an empty proof.
        assert!(!proof.verify(&mut hasher, &leaf, 0, &root));
    }

    #[test]
    fn test_tampered_proof_no_leaves() {
        // Build tree
        let txs = [b"tx1", b"tx2", b"tx3", b"tx4"];
        let digests: Vec<Digest> = txs.iter().map(|tx| hash(*tx)).collect();
        let leaf = digests[0].clone();
        let mut hasher = Sha256::default();
        let tree = Tree::new(&mut hasher, digests).unwrap();
        let root = tree.root();

        // Build proof
        let mut proof = tree.proof(0).unwrap();

        // Tamper with proof
        proof.leaves = 0;

        // Fail verification with an empty proof.
        assert!(!proof.verify(&mut hasher, &leaf, 0, &root));
    }

    #[test]
    fn test_proof_serialization() {
        // Build tree
        let txs = [b"tx1", b"tx2", b"tx3"];
        let digests: Vec<Digest> = txs.iter().map(|tx| hash(*tx)).collect();
        let mut hasher = Sha256::default();
        let tree = Tree::new(&mut hasher, digests.clone()).unwrap();
        let root = tree.root();

        // Generate a proof for leaf at index 1.
        let proof = tree.proof(1).unwrap();
        let serialized = proof.serialize();
        let deserialized = Proof::<Sha256>::deserialize(&serialized).unwrap();
        assert_eq!(proof, deserialized);

        // Verify the deserialized proof.
        deserialized.verify(&mut hasher, &digests[1], 1, &root);
    }

    #[test]
    fn test_invalid_proof_wrong_element() {
        // Build tree
        let txs = [b"tx1", b"tx2", b"tx3", b"tx4"];
        let digests: Vec<Digest> = txs.iter().map(|tx| hash(*tx)).collect();
        let mut hasher = Sha256::default();
        let tree = Tree::new(&mut hasher, digests.clone()).unwrap();
        let root = tree.root();

        // Generate a valid proof for leaf at index 2.
        let proof = tree.proof(2).unwrap();

        // Use a wrong element (e.g. hash of a different transaction).
        let wrong_leaf = hash(b"wrong_tx");
        let valid = proof.verify(&mut hasher, &wrong_leaf, 2, &root);
        assert!(!valid, "Verification should fail with a wrong leaf element");
    }

    #[test]
    fn test_invalid_proof_wrong_index() {
        // Build tree
        let txs = [b"tx1", b"tx2", b"tx3", b"tx4"];
        let digests: Vec<Digest> = txs.iter().map(|tx| hash(*tx)).collect();
        let mut hasher = Sha256::default();
        let tree = Tree::new(&mut hasher, digests.clone()).unwrap();
        let root = tree.root();

        // Generate a valid proof for leaf at index 1.
        let proof = tree.proof(1).unwrap();

        // Use an incorrect index (e.g. 2 instead of 1).
        let valid = proof.verify(&mut hasher, &digests[1], 2, &root);
        assert!(
            !valid,
            "Verification should fail with an incorrect element index"
        );
    }

    #[test]
    fn test_invalid_proof_wrong_root() {
        // Build tree
        let txs = [b"tx1", b"tx2", b"tx3", b"tx4"];
        let digests: Vec<Digest> = txs.iter().map(|tx| hash(*tx)).collect();
        let mut hasher = Sha256::default();
        let tree = Tree::new(&mut hasher, digests.clone()).unwrap();

        // Generate a valid proof for leaf at index 0.
        let proof = tree.proof(0).unwrap();

        // Use a wrong root (hash of a different input).
        let wrong_root = hash(b"wrong_root");
        let valid = proof.verify(&mut hasher, &digests[0], 0, &wrong_root);
        assert!(
            !valid,
            "Verification should fail with an incorrect root hash"
        );
    }

    #[test]
    fn test_invalid_proof_serialization_truncated() {
        // Build tree
        let txs = [b"tx1", b"tx2", b"tx3"];
        let digests: Vec<Digest> = txs.iter().map(|tx| hash(*tx)).collect();
        let mut hasher = Sha256::default();
        let tree = Tree::new(&mut hasher, digests.clone()).unwrap();

        // Generate a valid proof for leaf at index 1.
        let proof = tree.proof(1).unwrap();
        let mut serialized = proof.serialize();

        // Truncate one byte.
        serialized.pop();
        let deserialized = Proof::<Sha256>::deserialize(&serialized);
        assert!(
            deserialized.is_none(),
            "Deserialization should fail with truncated data"
        );
    }

    #[test]
    fn test_invalid_proof_serialization_extra() {
        // Build tree
        let txs = [b"tx1", b"tx2", b"tx3"];
        let digests: Vec<Digest> = txs.iter().map(|tx| hash(*tx)).collect();
        let mut hasher = Sha256::default();
        let tree = Tree::new(&mut hasher, digests.clone()).unwrap();

        // Generate a valid proof for leaf at index 1.
        let proof = tree.proof(1).unwrap();
        let mut serialized = proof.serialize();

        // Append an extra byte.
        serialized.push(0u8);
        let deserialized = Proof::<Sha256>::deserialize(&serialized);
        assert!(
            deserialized.is_none(),
            "Deserialization should fail with extra data"
        );
    }

    #[test]
    fn test_invalid_proof_modified_hash() {
        // Build tree
        let txs = [b"tx1", b"tx2", b"tx3", b"tx4"];
        let digests: Vec<Digest> = txs.iter().map(|tx| hash(*tx)).collect();
        let mut hasher = Sha256::default();
        let tree = Tree::new(&mut hasher, digests.clone()).unwrap();
        let root = tree.root();

        // Generate a valid proof for leaf at index 2.
        let mut proof = tree.proof(2).unwrap();

        // Modify the first hash in the proof.
        proof.siblings[0] = hash(b"modified");
        let valid = proof.verify(&mut hasher, &digests[2], 2, &root);
        assert!(
            !valid,
            "Verification should fail if a proof hash is tampered with"
        );
    }

    #[test]
    fn test_odd_tree_duplicate_index_proof() {
        // Build a tree with an odd number of leaves.
        let txs = [b"tx1", b"tx2", b"tx3"];
        let digests: Vec<Digest> = txs.iter().map(|tx| hash(*tx)).collect();
        let mut hasher = Sha256::default();
        let tree = Tree::new(&mut hasher, digests.clone()).unwrap();
        let root = tree.root();

        // The tree was built with 3 leaves; index 2 is the last valid index.
        let proof = tree.proof(2).unwrap();

        // Verification should succeed for the proper index 2.
        assert!(proof.verify(&mut hasher, &digests[2], 2, &root));

        // Should not be able to generate a proof for an out-of-range index (e.g. 3).
        assert!(tree.proof(3).is_none());

        // Attempting to verify using an out-of-range index (e.g. 3, which would correspond
        // to a duplicate leaf that doesn't actually exist) should fail.
        assert!(
            !proof.verify(&mut hasher, &digests[2], 3, &root),
            "Verification should fail for an invalid duplicate leaf index"
        );
    }
}
