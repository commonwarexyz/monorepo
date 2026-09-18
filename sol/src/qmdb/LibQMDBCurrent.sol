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

    /// @dev A range authenticates operation bytes and their activity chunks, including inactive bits.
    /// Absent pending and partial digests are zero and their presence follows from `leaves`.
    struct RangeProof {
        uint256 start;
        uint256 leaves;
        uint256 inactivePeaks;
        bytes32[] chunks;
        bytes32 opsRoot;
        bytes32 pending;
        bytes32 partialDigest;
        bytes32[] digests;
    }

    /// @dev Commitments authenticating an operation root under a canonical Current root.
    /// Absent pending and partial digests are zero and their presence follows from the operation proof's leaf count.
    struct OpsRootWitness {
        bytes32 opsRoot;
        bytes32 graftedRoot;
        bytes32 pending;
        bytes32 partialDigest;
    }

    /// @notice Verify operation bytes and activity status for a Current MMB range.
    /// @dev Inactive operations are valid and every touched 256-bit activity chunk is authenticated.
    function verifyRange(bytes32 root, bytes[] memory operations, RangeProof calldata proof, address hasher)
        internal
        view
        returns (bool)
    {
        return _verifyRange(root, operations, proof, true, hasher);
    }

    /// @notice Verify operation bytes and activity status for a Current MMR range.
    /// @dev Inactive operations are valid and every touched 256-bit activity chunk is authenticated.
    function verifyRangeMMR(bytes32 root, bytes[] memory operations, RangeProof calldata proof, address hasher)
        internal
        view
        returns (bool)
    {
        return _verifyRange(root, operations, proof, false, hasher);
    }

    /// @notice Verify historical operation inclusion under a canonical Current MMB root.
    /// @dev The witness authenticates the operation root and does not establish activity of selected operations.
    function verifyOpsMulti(
        bytes32 root,
        bytes[] memory operations,
        QMDBCommon.MultiProof calldata proof,
        OpsRootWitness calldata witness,
        address hasher
    ) internal view returns (bool) {
        return _verifyOpsMulti(root, operations, proof, witness, true, hasher);
    }

    /// @notice Verify historical operation inclusion under a canonical Current MMR root.
    /// @dev The witness authenticates the operation root and does not establish activity of selected operations.
    function verifyOpsMultiMMR(
        bytes32 root,
        bytes[] memory operations,
        QMDBCommon.MultiProof calldata proof,
        OpsRootWitness calldata witness,
        address hasher
    ) internal view returns (bool) {
        return _verifyOpsMulti(root, operations, proof, witness, false, hasher);
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

    /// @dev Validate touched chunks before reconstructing their grafted operation range.
    function _verifyRange(bytes32 root, bytes[] memory operations, RangeProof calldata proof, bool mmb, address hasher)
        private
        view
        returns (bool)
    {
        uint256 n = proof.leaves;
        uint256 start = proof.start;
        uint256 count = operations.length;
        if (n > (uint256(1) << 62) + (mmb ? 30 : 0) || start >= n || count == 0 || count > n - start) {
            return false;
        }
        uint256 firstChunk = start >> 8;
        uint256 lastChunk = (start + count - 1) >> 8;
        if (proof.chunks.length != lastChunk - firstChunk + 1) return false;
        uint256 complete = n >> 8;
        uint256 graftable = mmb ? Common.graftableMMBChunks(n, 8) : complete;
        bool pending = complete != graftable;
        uint256 nextBit = n & 255;
        if ((!pending && proof.pending != 0) || (nextBit == 0 && proof.partialDigest != 0)) return false;
        if (pending && firstChunk <= graftable && graftable <= lastChunk) {
            if (Common.hash(proof.chunks[graftable - firstChunk], 0, 0, 32, hasher) != proof.pending) return false;
        }
        if (nextBit != 0 && lastChunk == complete) {
            if (Common.hash(proof.chunks[lastChunk - firstChunk], 0, 0, 32, hasher) != proof.partialDigest) {
                return false;
            }
        }
        (bytes32 merkleRoot, bool valid) = QMDBCommon.reconstructRange(
            operations,
            n,
            start,
            proof.digests,
            proof.inactivePeaks,
            LibMerkle.RangeGraft(proof.chunks, firstChunk, graftable),
            mmb,
            hasher
        );
        return
            valid
                && _root(proof.opsRoot, merkleRoot, proof.pending, proof.partialDigest, pending, nextBit, hasher)
                    == root;
    }

    /// @dev Authenticate an operation root from the same snapshot before verifying its sparse inclusion proof.
    function _verifyOpsMulti(
        bytes32 root,
        bytes[] memory operations,
        QMDBCommon.MultiProof calldata proof,
        OpsRootWitness calldata witness,
        bool mmb,
        address hasher
    ) private view returns (bool) {
        uint256 n = proof.leaves;
        if (n > (uint256(1) << 62) + (mmb ? 30 : 0)) return false;
        uint256 complete = n >> 8;
        uint256 graftable = mmb ? Common.graftableMMBChunks(n, 8) : complete;
        bool pending = complete != graftable;
        uint256 nextBit = n & 255;
        if ((!pending && witness.pending != 0) || (nextBit == 0 && witness.partialDigest != 0)) return false;
        if (
            _root(
                    witness.opsRoot,
                    witness.graftedRoot,
                    witness.pending,
                    witness.partialDigest,
                    pending,
                    nextBit,
                    hasher
                ) != root
        ) return false;
        return QMDBCommon.verifyMulti(witness.opsRoot, operations, proof, mmb, hasher);
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
        return _root(proof.opsRoot, merkleRoot, proof.pending, proof.partialDigest, pending, nextBit, hasher) == root;
    }

    /// @dev Pending precedes partial when both chunks are outside the grafted tree.
    function _root(
        bytes32 opsRoot,
        bytes32 merkleRoot,
        bytes32 pendingDigest,
        bytes32 partialDigest,
        bool pending,
        uint256 nextBit,
        address hasher
    ) private view returns (bytes32) {
        bytes memory input = new bytes(64 + (pending ? 32 : 0) + (nextBit != 0 ? 40 : 0));
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
