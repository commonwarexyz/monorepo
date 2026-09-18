// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { Common } from "../merkle/Common.sol";
import { LibMerkle } from "../merkle/LibMerkle.sol";
import { Common as QMDBCommon } from "./Common.sol";

/// @notice Verify active operations and key exclusion in a current QMDB with 32-byte bitmap chunks.
/// @dev Uses QMDB's backward peak fold and big-endian position and count encodings.
/// The caller supplies an authenticated root and a trusted hash target.
/// Hash targets receive raw bytes and must return exactly 32 bytes.
/// A failed call or any other return length reverts with `Common.HashFailed()`.
library LibQMDBCurrent {
    /// @dev Absent pending and partial digests are zero. Their presence follows from
    /// `leaves` and the tree family. MMR proofs never have a pending digest.
    struct Proof {
        uint256 leaves;
        uint256 location;
        uint256 inactivePeaks;
        bytes32 chunk;
        bytes32 opsRoot;
        bytes32 pending;
        bytes32 partialDigest;
        bytes32[] digests;
    }

    /// @notice Verify an encoded operation and its active bit against a trusted current MMB root.
    /// @param root Authenticated QMDB root.
    /// @param operation Exact Commonware operation encoding, without a length prefix.
    /// @param proof Single-operation membership proof with a 256-bit activity chunk.
    /// @param hasher Trusted raw hash target, or `address(0)` for native Keccak256.
    /// @return True when the active operation reconstructs `root` and consumes every digest.
    function verify(bytes32 root, bytes memory operation, Proof calldata proof, address hasher)
        internal
        view
        returns (bool)
    {
        return _verify(root, operation, proof, true, hasher);
    }

    /// @notice Verify an encoded operation and its active bit against a trusted current MMR root.
    /// @param root Authenticated QMDB root.
    /// @param operation Exact Commonware operation encoding, without a length prefix.
    /// @param proof Single-operation membership proof with a 256-bit activity chunk.
    /// @param hasher Trusted raw hash target, or `address(0)` for native Keccak256.
    /// @return True when the active operation reconstructs `root` and consumes every digest.
    function verifyMMR(bytes32 root, bytes memory operation, Proof calldata proof, address hasher)
        internal
        view
        returns (bool)
    {
        return _verify(root, operation, proof, false, hasher);
    }

    /// @notice Verify key exclusion against a trusted ordered current MMB root.
    /// @dev The database must use 32-byte keys and fixed value encoding. For value size `V`,
    /// operations have `65 + V` bytes. Updates encode tag, key, value, then next key.
    /// Commits encode tag, metadata flag, `V` metadata bytes, big-endian `uint64` floor,
    /// then 55 zero bytes. The authenticated database's schema determines `V`.
    /// @param root Authenticated root of a database with this fixed ordered schema.
    /// @param key Key whose absence is being proven.
    /// @param operation Exact encoded adjacent-key update or empty-database commit.
    /// @param proof Single-operation membership proof with a 256-bit activity chunk.
    /// @param hasher Trusted raw hash target, or `address(0)` for native Keccak256.
    /// @return True when the active operation proves that `key` is absent under `root`.
    function verifyExclusion(bytes32 root, bytes32 key, bytes memory operation, Proof calldata proof, address hasher)
        internal
        view
        returns (bool)
    {
        return _excludes(key, operation, proof.location) && _verify(root, operation, proof, true, hasher);
    }

    /// @notice Verify key exclusion against a trusted ordered current MMR root.
    /// @dev Requires the same fixed ordered database schema as `verifyExclusion`.
    /// @param root Authenticated root of a database with 32-byte keys and fixed value encoding.
    /// @param key Key whose absence is being proven.
    /// @param operation Exact encoded adjacent-key update or empty-database commit.
    /// @param proof Single-operation membership proof with a 256-bit activity chunk.
    /// @param hasher Trusted raw hash target, or `address(0)` for native Keccak256.
    /// @return True when the active operation proves that `key` is absent under `root`.
    function verifyExclusionMMR(bytes32 root, bytes32 key, bytes memory operation, Proof calldata proof, address hasher)
        internal
        view
        returns (bool)
    {
        return _excludes(key, operation, proof.location) && _verify(root, operation, proof, false, hasher);
    }

    /// @dev An active update excludes the open cyclic interval between its keys, including
    /// every other key when both endpoints match. An empty database's commit floor is its location.
    function _excludes(bytes32 key, bytes memory operation, uint256 location) private pure returns (bool) {
        uint256 length = operation.length;
        if (length < 65) return false;
        if (operation[0] == 0xd2) {
            bytes32 start;
            bytes32 end;
            assembly ("memory-safe") {
                start := mload(add(operation, 33))
                end := mload(add(operation, length))
            }
            return start < end ? key > start && key < end : key > start || key < end;
        }
        if (operation[0] != 0xd3 || uint8(operation[1]) > 1) return false;
        uint256 floor;
        uint256 padding;
        assembly ("memory-safe") {
            let data := add(operation, 32)
            floor := shr(192, mload(add(data, sub(length, 63))))
            padding := or(mload(add(data, sub(length, 55))), mload(add(data, sub(length, 32))))
        }
        if (floor != location || padding != 0) return false;
        if (operation[1] == 0) {
            for (uint256 i = 2; i < length - 63; ++i) {
                if (operation[i] != 0) return false;
            }
        }
        return true;
    }

    /// @dev The tree family determines the leaf bound, physical positions, and graftable chunks.
    function _verify(bytes32 root, bytes memory operation, Proof calldata proof, bool mmb, address hasher)
        private
        view
        returns (bool)
    {
        uint256 n = proof.leaves;
        uint256 loc = proof.location;
        if (n > (uint256(1) << 62) + (mmb ? 30 : 0) || loc >= n) return false;
        if (uint8(proof.chunk[(loc & 255) >> 3]) & (uint256(1) << (loc & 7)) == 0) return false;

        uint256 complete = n >> 8;
        uint256 graftable = mmb ? Common.graftableMMBChunks(n, 8) : complete;
        bool pending = complete != graftable;
        uint256 nextBit = n & 255;
        if ((!pending && proof.pending != 0) || (nextBit == 0 && proof.partialDigest != 0)) return false;
        uint256 chunkIndex = loc >> 8;
        if (chunkIndex >= graftable) {
            bytes32 digest = Common.hash(proof.chunk, 0, 0, 32, hasher);
            if (chunkIndex == complete) {
                if (digest != proof.partialDigest) return false;
            } else if (digest != proof.pending) {
                return false;
            }
        }

        (bytes32 merkleRoot, bool valid) = QMDBCommon.reconstruct(
            n, loc, operation, proof.digests, proof.inactivePeaks, LibMerkle.Graft(proof.chunk, 256), mmb, hasher
        );
        if (!valid) return false;
        return _root(proof, merkleRoot, pending, nextBit, hasher) == root;
    }

    /// @dev Pending precedes partial when both chunks are outside the grafted tree.
    function _root(Proof calldata proof, bytes32 merkleRoot, bool pending, uint256 nextBit, address hasher)
        private
        view
        returns (bytes32)
    {
        bytes memory input = new bytes(64 + (pending ? 32 : 0) + (nextBit != 0 ? 40 : 0));
        bytes32 opsRoot = proof.opsRoot;
        bytes32 pendingDigest = proof.pending;
        bytes32 partialDigest = proof.partialDigest;
        assembly ("memory-safe") {
            let p := add(input, 0x20)
            mstore(p, opsRoot)
            mstore(add(p, 0x20), merkleRoot)
            p := add(p, 0x40)
            if pending {
                mstore(p, pendingDigest)
                p := add(p, 0x20)
            }
            if nextBit {
                mstore(p, shl(192, nextBit))
                mstore(add(p, 8), partialDigest)
            }
        }
        return Common.hash(input, hasher);
    }
}
