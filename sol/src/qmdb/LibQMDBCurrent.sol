// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { LibMerkle } from "../merkle/LibMerkle.sol";
import { LibQMDBCommon } from "./LibQMDBCommon.sol";

/// @notice Verify active operations and key exclusion in a current QMDB with configurable bitmap chunks.
/// @dev Uses QMDB's backward peak fold and big-endian position and count encodings.
/// The caller supplies an authenticated root and a trusted hash target and chunk byte size.
/// Chunk bytes must be a nonzero power of two below `2^60`, matching the authenticated database.
/// Nonzero hash targets receive raw bytes via `STATICCALL` and must return exactly 32 bytes.
/// A failed call or any other return length reverts with `LibMerkle.HashFailed()`.
library LibQMDBCurrent {
    /// @dev Absent pending and partial digests are zero. Their presence follows from
    /// `leaves` and the tree family. MMR proofs never have a pending digest.
    /// `chunk` contains exactly the configured number of bitmap bytes.
    struct Proof {
        uint256 leaves;
        uint256 location;
        uint256 inactivePeaks;
        bytes chunk;
        bytes32 opsRoot;
        bytes32 pending;
        bytes32 partialDigest;
        bytes32[] digests;
    }

    /// @dev A range authenticates operation bytes and their activity chunks, including inactive bits.
    /// Chunks are packed in increasing chunk order, each with the configured byte size.
    /// Absent pending and partial digests are zero and their presence follows from `leaves`.
    struct RangeProof {
        uint256 start;
        uint256 leaves;
        uint256 inactivePeaks;
        bytes chunks;
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

    /// @dev Field byte sizes with `VARIABLE_SIZE` selecting length-prefixed byte vectors.
    /// Lengths use Commonware's canonical unsigned 32-bit varint. Keys use raw byte lexicographic ordering.
    struct ExclusionEncoding {
        uint256 keySize;
        uint256 valueSize;
    }

    /// @dev Select a length-prefixed byte vector in `ExclusionEncoding`.
    uint256 internal constant VARIABLE_SIZE = type(uint256).max;

    /// @notice Verify key exclusion in an ordered current QMDB with fixed operation encoding.
    /// @dev The authenticated database uses 32-byte keys and fixed values of size `V`.
    /// Updates encode tag, key, value, and next key in `65 + V` bytes. Commits encode tag,
    /// metadata flag, `V` metadata bytes, big-endian `uint64` floor, and 55 zero bytes.
    /// Exclusion framing is checked before the operation and its active bit are authenticated.
    /// @param root Authenticated root of a database with this fixed ordered schema.
    /// @param key Key whose absence is being proven.
    /// @param operation Exact encoded adjacent-key update or empty-database commit.
    /// @param proof Single-operation proof with an activity chunk.
    /// @param mmb True for MMB and false for MMR.
    /// @param chunkBytes Trusted bitmap chunk byte size of the authenticated database.
    /// @param hasher Trusted raw hash target, or `address(0)` for native Keccak256.
    /// @return True when the active operation proves that `key` is absent under `root`.
    function verifyExclusion(
        bytes32 root,
        bytes32 key,
        bytes memory operation,
        Proof calldata proof,
        bool mmb,
        uint256 chunkBytes,
        address hasher
    ) internal view returns (bool) {
        return _excludes(key, operation, proof.location) && verify(root, operation, proof, mmb, chunkBytes, hasher);
    }

    /// @notice Verify ordered key exclusion in a current QMDB with variable operation encoding.
    /// @dev Keys use raw byte lexicographic ordering. The trusted schema selects fixed-width
    /// fields or byte vectors with canonical unsigned 32-bit varint lengths.
    /// Exclusion framing is checked before the operation and its active bit are authenticated.
    /// @param root Authenticated root of an ordered current QMDB using variable operation encoding.
    /// @param key Raw key whose absence is being proven.
    /// @param operation Exact encoded adjacent-key update or empty-database commit.
    /// @param proof Active operation membership proof.
    /// @param encoding Trusted key and value encoding configuration bound to `root`.
    /// @param mmb True for MMB and false for MMR.
    /// @param chunkBytes Trusted bitmap chunk byte size of the authenticated database.
    /// @param hasher Trusted raw hash target, or `address(0)` for native Keccak256.
    /// @return True when the active operation proves that `key` is absent under `root`.
    function verifyExclusionVariable(
        bytes32 root,
        bytes memory key,
        bytes memory operation,
        Proof calldata proof,
        ExclusionEncoding memory encoding,
        bool mmb,
        uint256 chunkBytes,
        address hasher
    ) internal view returns (bool) {
        return _excludesVariable(key, operation, proof.location, encoding)
            && verify(root, operation, proof, mmb, chunkBytes, hasher);
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

    /// @dev Authenticate operation bytes and every touched activity chunk. Inactive operations are valid.
    /// Chunks are validated before reconstructing their grafted range. `mmb` selects MMB when true and MMR otherwise.
    function verifyRange(
        bytes32 root,
        bytes[] memory operations,
        RangeProof calldata proof,
        bool mmb,
        uint256 chunkBytes,
        address hasher
    ) internal view returns (bool) {
        if (!_validChunkBytes(chunkBytes)) return false;
        uint256 height = LibMerkle.log2(chunkBytes) + 3;
        uint256 n = proof.leaves;
        uint256 start = proof.start;
        uint256 count = operations.length;
        if (n > (uint256(1) << 62) + (mmb ? 30 : 0) || start >= n || count == 0 || count > n - start) {
            return false;
        }
        uint256 firstChunk = start >> height;
        uint256 lastChunk = (start + count - 1) >> height;
        bytes calldata chunks = proof.chunks;
        if (chunks.length != (lastChunk - firstChunk + 1) * chunkBytes) return false;
        uint256 complete = n >> height;
        uint256 graftable = mmb ? LibMerkle.graftableMMBChunks(n, height) : complete;
        bool pending = complete != graftable;
        uint256 nextBit = n & ((chunkBytes << 3) - 1);
        if ((!pending && proof.pending != 0) || (nextBit == 0 && proof.partialDigest != 0)) return false;
        if (pending && firstChunk <= graftable && graftable <= lastChunk) {
            if (
                LibMerkle.hash(
                        chunks[(graftable - firstChunk) * chunkBytes:(graftable - firstChunk + 1) * chunkBytes], hasher
                    ) != proof.pending
            ) return false;
        }
        if (nextBit != 0 && lastChunk == complete) {
            if (
                LibMerkle.hash(
                        chunks[(lastChunk - firstChunk) * chunkBytes:(lastChunk - firstChunk + 1) * chunkBytes], hasher
                    ) != proof.partialDigest
            ) {
                return false;
            }
        }
        uint256 chunkData;
        assembly ("memory-safe") { chunkData := chunks.offset }
        (bytes32 merkleRoot, bool valid) = LibQMDBCommon.reconstructRange(
            operations,
            n,
            start,
            proof.digests,
            proof.inactivePeaks,
            LibMerkle.RangeGraft(chunkData, firstChunk, graftable, chunkBytes << 3),
            mmb,
            hasher
        );
        return
            valid
                && _root(proof.opsRoot, merkleRoot, proof.pending, proof.partialDigest, pending, nextBit, hasher)
                    == root;
    }

    /// @dev Authenticate an operation root from the same snapshot before verifying its sparse inclusion proof.
    /// This proves historical inclusion without establishing activity. `mmb` selects MMB when true and MMR otherwise.
    function verifyOpsMulti(
        bytes32 root,
        bytes[] memory operations,
        LibQMDBCommon.MultiProof calldata proof,
        OpsRootWitness calldata witness,
        bool mmb,
        uint256 chunkBytes,
        address hasher
    ) internal view returns (bool) {
        if (!_validChunkBytes(chunkBytes)) return false;
        uint256 height = LibMerkle.log2(chunkBytes) + 3;
        uint256 n = proof.leaves;
        if (n > (uint256(1) << 62) + (mmb ? 30 : 0)) return false;
        uint256 complete = n >> height;
        uint256 graftable = mmb ? LibMerkle.graftableMMBChunks(n, height) : complete;
        bool pending = complete != graftable;
        uint256 nextBit = n & ((chunkBytes << 3) - 1);
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
        return LibQMDBCommon.verifyMulti(witness.opsRoot, operations, proof, mmb, hasher);
    }

    /// @dev Authenticate an encoded operation and its active bit against the supplied current root.
    /// `mmb` selects MMB when true and MMR otherwise, determining leaf bounds, physical positions, and graftable chunks.
    function verify(
        bytes32 root,
        bytes memory operation,
        Proof calldata proof,
        bool mmb,
        uint256 chunkBytes,
        address hasher
    ) internal view returns (bool) {
        if (!_validChunkBytes(chunkBytes)) return false;
        uint256 height = LibMerkle.log2(chunkBytes) + 3;
        uint256 n = proof.leaves;
        uint256 loc = proof.location;
        if (n > (uint256(1) << 62) + (mmb ? 30 : 0) || loc >= n) return false;
        bytes calldata chunk = proof.chunk;
        if (chunk.length != chunkBytes) return false;
        if (uint8(chunk[(loc & ((chunkBytes << 3) - 1)) >> 3]) & (uint256(1) << (loc & 7)) == 0) return false;

        uint256 complete = n >> height;
        uint256 graftable = mmb ? LibMerkle.graftableMMBChunks(n, height) : complete;
        bool pending = complete != graftable;
        uint256 nextBit = n & ((chunkBytes << 3) - 1);
        if ((!pending && proof.pending != 0) || (nextBit == 0 && proof.partialDigest != 0)) return false;
        uint256 chunkIndex = loc >> height;
        if (chunkIndex >= graftable) {
            bytes32 digest = LibMerkle.hash(chunk, hasher);
            if (chunkIndex == complete) {
                if (digest != proof.partialDigest) return false;
            } else if (digest != proof.pending) {
                return false;
            }
        }

        uint256 chunkData;
        assembly ("memory-safe") { chunkData := chunk.offset }
        (bytes32 merkleRoot, bool valid) = LibQMDBCommon.reconstruct(
            n,
            loc,
            operation,
            proof.digests,
            proof.inactivePeaks,
            LibMerkle.Graft(chunkData, chunkBytes << 3),
            mmb,
            hasher
        );
        if (!valid) return false;
        return _root(proof.opsRoot, merkleRoot, proof.pending, proof.partialDigest, pending, nextBit, hasher) == root;
    }

    /// @dev Rust bitmap chunks have a power-of-two byte length and a bit width below `2^63`.
    function _validChunkBytes(uint256 chunkBytes) private pure returns (bool) {
        return chunkBytes != 0 && chunkBytes < (uint256(1) << 60) && (chunkBytes & (chunkBytes - 1)) == 0;
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
        return LibMerkle.hash(input, hasher);
    }

    /// @dev Parse variable operation framing before interpreting an authenticated cyclic key interval.
    function _excludesVariable(
        bytes memory key,
        bytes memory operation,
        uint256 location,
        ExclusionEncoding memory encoding
    ) private pure returns (bool) {
        if (operation.length == 0) return false;
        if (encoding.keySize == VARIABLE_SIZE) {
            if (key.length > type(uint32).max) return false;
        } else if (key.length != encoding.keySize) {
            return false;
        }
        if (operation[0] == 0xd2) {
            (uint256 left, uint256 leftEnd, bool valid) = _field(operation, 1, encoding.keySize);
            if (!valid) return false;
            (, uint256 valueEnd, bool valueValid) = _field(operation, leftEnd, encoding.valueSize);
            if (!valueValid) return false;
            (uint256 right, uint256 rightEnd, bool rightValid) = _field(operation, valueEnd, encoding.keySize);
            if (!rightValid || rightEnd != operation.length) return false;
            int256 afterLeft = _compare(key, 0, key.length, operation, left, leftEnd);
            int256 beforeRight = _compare(key, 0, key.length, operation, right, rightEnd);
            // Equal nonzero comparisons require a wrapping interval. Opposite signs determine inclusion directly.
            return afterLeft != beforeRight
                ? afterLeft > 0 && beforeRight < 0
                : afterLeft != 0 && _compare(operation, left, leftEnd, operation, right, rightEnd) >= 0;
        }
        if (operation[0] != 0xd3 || operation.length < 2 || uint8(operation[1]) > 1) return false;
        uint256 cursor = 2;
        if (operation[1] == 0x01) {
            bool valid;
            (, cursor, valid) = _field(operation, cursor, encoding.valueSize);
            if (!valid) return false;
        }
        (uint256 floor, uint256 end, bool validFloor) = _varint(operation, cursor, 64);
        return validFloor && end == operation.length && floor == location;
    }

    /// @dev Return a bounded raw field slice, consuming its length prefix when present.
    function _field(bytes memory input, uint256 cursor, uint256 size)
        private
        pure
        returns (uint256 start, uint256 end, bool valid)
    {
        if (size == VARIABLE_SIZE) {
            (size, cursor, valid) = _varint(input, cursor, 32);
            // forge-lint: disable-next-line(boolean-cst)
            if (!valid) return (0, 0, false);
        }
        // forge-lint: disable-next-line(boolean-cst)
        if (cursor > input.length || size > input.length - cursor) return (0, 0, false);
        // forge-lint: disable-next-line(boolean-cst)
        return (cursor, cursor + size, true);
    }

    /// @dev Decode a minimal unsigned varint with a bounded width and no truncation.
    function _varint(bytes memory input, uint256 cursor, uint256 bits)
        private
        pure
        returns (uint256 value, uint256 end, bool valid)
    {
        for (uint256 shift = 0; shift < bits; shift += 7) {
            // forge-lint: disable-next-line(boolean-cst)
            if (cursor >= input.length) return (0, 0, false);
            uint256 octet = uint8(input[cursor++]);
            value |= (octet & 127) << shift;
            if (octet < 128) {
                // forge-lint: disable-next-line(boolean-cst)
                if ((shift != 0 && octet == 0) || value >> bits != 0) return (0, 0, false);
                // forge-lint: disable-next-line(boolean-cst)
                return (value, cursor, true);
            }
        }
        // forge-lint: disable-next-line(boolean-cst)
        return (0, 0, false);
    }

    /// @dev Compare bounded raw byte slices lexicographically, ordering a proper prefix first.
    /// End-aligned words keep short reads within the byte array allocation.
    function _compare(bytes memory a, uint256 aStart, uint256 aEnd, bytes memory b, uint256 bStart, uint256 bEnd)
        private
        pure
        returns (int256)
    {
        uint256 aLength = aEnd - aStart;
        uint256 bLength = bEnd - bStart;
        uint256 length = aLength < bLength ? aLength : bLength;
        for (uint256 i = 0; i < length; i += 32) {
            uint256 remaining = length - i;
            uint256 width = remaining < 32 ? remaining : 32;
            uint256 left;
            uint256 right;
            assembly ("memory-safe") {
                let mask := shr(shl(3, sub(32, width)), not(0))
                left := and(mask, mload(add(add(add(a, aStart), i), width)))
                right := and(mask, mload(add(add(add(b, bStart), i), width)))
            }
            if (left != right) return left < right ? int256(-1) : int256(1);
        }
        return aLength == bLength ? int256(0) : aLength < bLength ? int256(-1) : int256(1);
    }
}
