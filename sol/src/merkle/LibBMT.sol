// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { LibMerkleCommon } from "./LibMerkleCommon.sol";

/// @title Commonware Binary Merkle Tree inclusion verification
/// @notice Verify inclusion proofs for raw 32-byte elements in trees of at most `2^32 - 1` leaves.
/// @dev Leaves hash `uint32_be(index) || element`. Parents hash `left || right`.
/// The final root hashes `uint32_be(leaves) || treeRoot`. An empty tree's tree root is `H(empty)`.
/// Witnesses ascend by level, left to right. A last unpaired node duplicates itself without a witness.
/// Every verifier requires exact proof consumption and leaves its input arrays unchanged.
/// Address `0` selects native Keccak256. Other hashers receive raw bytes through `STATICCALL`
/// and must return exactly `32` bytes, matching the SHA256 precompile at address `2`.
/// Failed calls and invalid return lengths revert with `LibMerkleCommon.HashFailed()`.
library LibBMT {
    /// @notice Verify one raw element.
    /// @dev Invalid bounds, malformed proofs and root mismatches return `false`.
    /// @param root Trusted root commitment.
    /// @param leaves Total leaf count, at most `2^32 - 1`.
    /// @param index Zero-based leaf index.
    /// @param element Raw 32-byte leaf value.
    /// @param proof Exact Commonware sibling digests in ascending level and index order.
    /// @param hasher Hash implementation address, or `address(0)` for native Keccak256.
    /// @return True exactly when the complete proof authenticates the supplied elements.
    function verify(
        bytes32 root,
        uint256 leaves,
        uint256 index,
        bytes32 element,
        bytes32[] memory proof,
        address hasher
    ) internal view returns (bool) {
        uint256 witnesses;
        assembly ("memory-safe") {
            witnesses := add(proof, 0x20)
        }
        return _single(root, leaves, index, element, witnesses, proof.length, false, hasher);
    }

    /// @notice Verify one raw element.
    /// @dev Invalid bounds, malformed proofs and root mismatches return `false`.
    /// @param root Trusted root commitment.
    /// @param leaves Total leaf count, at most `2^32 - 1`.
    /// @param index Zero-based leaf index.
    /// @param element Raw 32-byte leaf value.
    /// @param proof Exact Commonware sibling digests in ascending level and index order.
    /// @param hasher Hash implementation address, or `address(0)` for native Keccak256.
    /// @return True exactly when the complete proof authenticates the supplied elements.
    function verifyCalldata(
        bytes32 root,
        uint256 leaves,
        uint256 index,
        bytes32 element,
        bytes32[] calldata proof,
        address hasher
    ) internal view returns (bool) {
        uint256 witnesses;
        assembly ("memory-safe") {
            witnesses := proof.offset
        }
        return _single(root, leaves, index, element, witnesses, proof.length, true, hasher);
    }

    /// @notice Verify consecutive raw elements beginning at `start`.
    /// @dev Invalid bounds, malformed proofs and root mismatches return `false`.
    /// Empty inputs require an empty tree and proof with `start == 0`.
    /// @param root Trusted root commitment.
    /// @param leaves Total leaf count, at most `2^32 - 1`.
    /// @param start Zero-based first leaf index.
    /// @param elements Raw 32-byte leaf values.
    /// @param proof Exact Commonware sibling digests in ascending level and index order.
    /// @param hasher Hash implementation address, or `address(0)` for native Keccak256.
    /// @return True exactly when the complete proof authenticates the supplied elements.
    function verifyRange(
        bytes32 root,
        uint256 leaves,
        uint256 start,
        bytes32[] memory elements,
        bytes32[] memory proof,
        address hasher
    ) internal view returns (bool) {
        uint256 witnesses;
        uint256 data;
        assembly ("memory-safe") {
            witnesses := add(proof, 0x20)
            data := add(elements, 0x20)
        }
        return _range(root, leaves, start, data, elements.length, witnesses, proof.length, false, hasher);
    }

    /// @notice Verify consecutive raw elements beginning at `start`.
    /// @dev Invalid bounds, malformed proofs and root mismatches return `false`.
    /// Empty inputs require an empty tree and proof with `start == 0`.
    /// @param root Trusted root commitment.
    /// @param leaves Total leaf count, at most `2^32 - 1`.
    /// @param start Zero-based first leaf index.
    /// @param elements Raw 32-byte leaf values.
    /// @param proof Exact Commonware sibling digests in ascending level and index order.
    /// @param hasher Hash implementation address, or `address(0)` for native Keccak256.
    /// @return True exactly when the complete proof authenticates the supplied elements.
    function verifyRangeCalldata(
        bytes32 root,
        uint256 leaves,
        uint256 start,
        bytes32[] calldata elements,
        bytes32[] calldata proof,
        address hasher
    ) internal view returns (bool) {
        uint256 witnesses;
        uint256 data;
        assembly ("memory-safe") {
            witnesses := proof.offset
            data := elements.offset
        }
        return _range(root, leaves, start, data, elements.length, witnesses, proof.length, true, hasher);
    }

    /// @notice Verify raw elements at arbitrary, distinct indices.
    /// @dev Invalid bounds, malformed proofs and root mismatches return `false`.
    /// Empty inputs require an empty tree and proof.
    /// @param root Trusted root commitment.
    /// @param leaves Total leaf count, at most `2^32 - 1`.
    /// @param indices Distinct zero-based leaf indices in the same order as `elements`.
    /// @param elements Raw 32-byte leaf values.
    /// @param proof Exact Commonware sibling digests in ascending level and index order.
    /// @param hasher Hash implementation address, or `address(0)` for native Keccak256.
    /// @return True exactly when the complete proof authenticates the supplied elements.
    function verifyMulti(
        bytes32 root,
        uint256 leaves,
        uint256[] memory indices,
        bytes32[] memory elements,
        bytes32[] memory proof,
        address hasher
    ) internal view returns (bool) {
        uint256 witnesses;
        uint256 data;
        if (indices.length != elements.length) return false;
        uint256 positions;
        assembly ("memory-safe") {
            witnesses := add(proof, 0x20)
            data := add(elements, 0x20)
            positions := add(indices, 0x20)
        }
        return _multi(root, leaves, positions, data, elements.length, witnesses, proof.length, false, hasher);
    }

    /// @notice Verify raw elements at arbitrary, distinct indices.
    /// @dev Invalid bounds, malformed proofs and root mismatches return `false`.
    /// Empty inputs require an empty tree and proof.
    /// @param root Trusted root commitment.
    /// @param leaves Total leaf count, at most `2^32 - 1`.
    /// @param indices Distinct zero-based leaf indices in the same order as `elements`.
    /// @param elements Raw 32-byte leaf values.
    /// @param proof Exact Commonware sibling digests in ascending level and index order.
    /// @param hasher Hash implementation address, or `address(0)` for native Keccak256.
    /// @return True exactly when the complete proof authenticates the supplied elements.
    function verifyMultiCalldata(
        bytes32 root,
        uint256 leaves,
        uint256[] calldata indices,
        bytes32[] calldata elements,
        bytes32[] calldata proof,
        address hasher
    ) internal view returns (bool) {
        uint256 witnesses;
        uint256 data;
        if (indices.length != elements.length) return false;
        uint256 positions;
        assembly ("memory-safe") {
            witnesses := proof.offset
            data := elements.offset
            positions := indices.offset
        }
        return _multi(root, leaves, positions, data, elements.length, witnesses, proof.length, true, hasher);
    }

    /// @dev Hash a single branch without allocating memory.
    function _single(
        bytes32 root,
        uint256 leaves,
        uint256 index,
        bytes32 element,
        uint256 proof,
        uint256 proofLength,
        bool cd,
        address hasher
    ) private view returns (bool valid) {
        assembly ("memory-safe") {
            hasher := and(hasher, 0xffffffffffffffffffffffffffffffffffffffff)
            /// @dev Hash raw bytes through an external target and require exactly one digest.
            function externalHash(pointer, length, targetHasher) -> digest {
                let success := staticcall(gas(), targetHasher, pointer, length, 0, 0x20)
                if iszero(and(success, eq(returndatasize(), 0x20))) {
                    mstore(0, 0x832d9905) // `LibMerkleCommon.HashFailed()`.
                    // Each external hash result must be checked before traversal continues.
                    // forge-lint: disable-next-line(require-revert-in-loop)
                    revert(0x1c, 4)
                }
                digest := mload(0)
            }
            /// @dev Read one word from the selected input address space.
            function load(p, calldataInput) -> v {
                switch calldataInput
                case 0 { v := mload(p) }
                default { v := calldataload(p) }
            }
            if and(iszero(gt(leaves, 0xffffffff)), lt(index, leaves)) {
                mstore(0, index)
                mstore(0x20, element)
                let digest
                switch hasher
                case 0 { digest := keccak256(0x1c, 0x24) }
                default { digest := externalHash(0x1c, 0x24, hasher) }
                let cursor := proof
                let end := add(proof, shl(5, proofLength))
                let size := leaves
                valid := 1
                for { } gt(size, 1) { } {
                    let sibling := digest
                    if lt(xor(index, 1), size) {
                        if eq(cursor, end) {
                            valid := 0
                            break
                        }
                        sibling := load(cursor, cd)
                        cursor := add(cursor, 0x20)
                    }
                    let slot := shl(5, and(index, 1))
                    mstore(slot, digest)
                    mstore(xor(slot, 0x20), sibling)
                    switch hasher
                    case 0 { digest := keccak256(0, 0x40) }
                    default { digest := externalHash(0, 0x40, hasher) }
                    index := shr(1, index)
                    size := shr(1, add(size, 1))
                }
                mstore(0, leaves)
                mstore(0x20, digest)
                {
                    let hashed
                    switch hasher
                    case 0 { hashed := keccak256(0x1c, 0x24) }
                    default { hashed := externalHash(0x1c, 0x24, hasher) }
                    valid := and(valid, and(eq(cursor, end), eq(root, hashed)))
                }
            }
        }
    }

    /// @dev Compact each contiguous level in place. Only its two boundaries can require witnesses.
    function _range(
        bytes32 root,
        uint256 leaves,
        uint256 start,
        uint256 data,
        uint256 count,
        uint256 proof,
        uint256 proofLength,
        bool cd,
        address hasher
    ) private view returns (bool valid) {
        if (leaves > type(uint32).max || start > leaves || count > leaves - start) return false;
        if (count == 0) return start == 0 && _empty(root, leaves, proofLength, hasher);
        assembly ("memory-safe") {
            hasher := and(hasher, 0xffffffffffffffffffffffffffffffffffffffff)
            /// @dev Hash raw bytes through an external target and require exactly one digest.
            function externalHash(pointer, length, targetHasher) -> digest {
                let success := staticcall(gas(), targetHasher, pointer, length, 0, 0x20)
                if iszero(and(success, eq(returndatasize(), 0x20))) {
                    mstore(0, 0x832d9905) // `LibMerkleCommon.HashFailed()`.
                    // Each external hash result must be checked before traversal continues.
                    // forge-lint: disable-next-line(require-revert-in-loop)
                    revert(0x1c, 4)
                }
                digest := mload(0)
            }
            /// @dev Read one word from the selected input address space.
            function load(p, calldataInput) -> v {
                switch calldataInput
                case 0 { v := mload(p) }
                default { v := calldataload(p) }
            }

            // The working level is temporary memory confined to this assembly block.
            let base := mload(0x40)
            let limit := add(base, shl(5, count))
            for { let i := 0 } lt(i, count) { i := add(i, 1) } {
                mstore(0, add(start, i))
                mstore(0x20, load(add(data, shl(5, i)), cd))
                {
                    let hashed
                    switch hasher
                    case 0 { hashed := keccak256(0x1c, 0x24) }
                    default { hashed := externalHash(0x1c, 0x24, hasher) }
                    mstore(add(base, shl(5, i)), hashed)
                }
            }
            let cursor := proof
            let end := add(proof, shl(5, proofLength))
            let size := leaves
            valid := 1
            for { } and(gt(size, 1), valid) { } {
                let output := base
                let input := base
                let inputEnd := add(base, shl(5, count))
                let position := start
                for { } lt(input, inputEnd) { position := add(position, 2) } {
                    let left := mload(input)
                    let right := left
                    input := add(input, 0x20)
                    switch and(position, 1)
                    case 1 {
                        if eq(cursor, end) {
                            valid := 0
                            break
                        }
                        right := left
                        left := load(cursor, cd)
                        cursor := add(cursor, 0x20)
                        position := sub(position, 1)
                    }
                    default {
                        switch lt(input, inputEnd)
                        case 1 {
                            right := mload(input)
                            input := add(input, 0x20)
                        }
                        default {
                            if lt(add(position, 1), size) {
                                if eq(cursor, end) {
                                    valid := 0
                                    break
                                }
                                right := load(cursor, cd)
                                cursor := add(cursor, 0x20)
                            }
                        }
                    }
                    mstore(0, left)
                    mstore(0x20, right)
                    {
                        let hashed
                        switch hasher
                        case 0 { hashed := keccak256(0, 0x40) }
                        default { hashed := externalHash(0, 0x40, hasher) }
                        mstore(output, hashed)
                    }
                    output := add(output, 0x20)
                }
                count := shr(5, sub(output, base))
                start := shr(1, start)
                size := shr(1, add(size, 1))
            }
            mstore(0, leaves)
            mstore(0x20, mload(base))
            {
                let hashed
                switch hasher
                case 0 { hashed := keccak256(0x1c, 0x24) }
                default { hashed := externalHash(0x1c, 0x24, hasher) }
                valid := and(valid, and(eq(cursor, end), eq(root, hashed)))
            }
            for { let p := base } lt(p, limit) { p := add(p, 0x20) } { mstore(p, 0) }
        }
    }

    /// @dev Sort private index/digest pairs, reject duplicates, and compact each level in place.
    function _multi(
        bytes32 root,
        uint256 leaves,
        uint256 indices,
        uint256 data,
        uint256 count,
        uint256 proof,
        uint256 proofLength,
        bool cd,
        address hasher
    ) private view returns (bool valid) {
        if (leaves > type(uint32).max || count > leaves) return false;
        if (count == 0) return _empty(root, leaves, proofLength, hasher);
        uint256 base;
        bool sorted = true;
        assembly ("memory-safe") {
            hasher := and(hasher, 0xffffffffffffffffffffffffffffffffffffffff)
            /// @dev Hash raw bytes through an external target and require exactly one digest.
            function externalHash(pointer, length, targetHasher) -> digest {
                let success := staticcall(gas(), targetHasher, pointer, length, 0, 0x20)
                if iszero(and(success, eq(returndatasize(), 0x20))) {
                    mstore(0, 0x832d9905) // `LibMerkleCommon.HashFailed()`.
                    // Each external hash result must be checked before traversal continues.
                    // forge-lint: disable-next-line(require-revert-in-loop)
                    revert(0x1c, 4)
                }
                digest := mload(0)
            }
            /// @dev Read one word from the selected input address space.
            function load(p, calldataInput) -> v {
                switch calldataInput
                case 0 { v := mload(p) }
                default { v := calldataload(p) }
            }
            base := mload(0x40)
            mstore(0x40, add(base, shl(6, count)))
            valid := 1
            let previous := 0
            for { let i := 0 } lt(i, count) { i := add(i, 1) } {
                let index := load(add(indices, shl(5, i)), cd)
                if iszero(lt(index, leaves)) { valid := 0 }
                if lt(index, previous) { sorted := 0 }
                previous := index
                let target := add(base, shl(6, i))
                mstore(target, index)
                mstore(0, index)
                mstore(0x20, load(add(data, shl(5, i)), cd))
                {
                    let hashed
                    switch hasher
                    case 0 { hashed := keccak256(0x1c, 0x24) }
                    default { hashed := externalHash(0x1c, 0x24, hasher) }
                    mstore(add(target, 0x20), hashed)
                }
            }
        }
        if (valid && !sorted) LibMerkleCommon.sortPairs(base, count);
        assembly ("memory-safe") {
            hasher := and(hasher, 0xffffffffffffffffffffffffffffffffffffffff)
            /// @dev Hash raw bytes through an external target and require exactly one digest.
            function externalHash(pointer, length, targetHasher) -> digest {
                let success := staticcall(gas(), targetHasher, pointer, length, 0, 0x20)
                if iszero(and(success, eq(returndatasize(), 0x20))) {
                    mstore(0, 0x832d9905) // `LibMerkleCommon.HashFailed()`.
                    // Each external hash result must be checked before traversal continues.
                    // forge-lint: disable-next-line(require-revert-in-loop)
                    revert(0x1c, 4)
                }
                digest := mload(0)
            }
            /// @dev Read one word from the selected input address space.
            function load(p, calldataInput) -> v {
                switch calldataInput
                case 0 { v := mload(p) }
                default { v := calldataload(p) }
            }
            let limit := add(base, shl(6, count))
            for { let p := add(base, 0x40) } and(lt(p, limit), valid) { p := add(p, 0x40) } {
                if eq(mload(p), mload(sub(p, 0x40))) { valid := 0 }
            }
            let cursor := proof
            let end := add(proof, shl(5, proofLength))
            let size := leaves
            for { } and(gt(size, 1), valid) { } {
                let output := base
                let input := base
                let inputEnd := add(base, shl(6, count))
                for { } lt(input, inputEnd) { } {
                    let index := mload(input)
                    let left := mload(add(input, 0x20))
                    let right := left
                    input := add(input, 0x40)
                    switch and(index, 1)
                    case 1 {
                        if eq(cursor, end) {
                            valid := 0
                            break
                        }
                        right := left
                        left := load(cursor, cd)
                        cursor := add(cursor, 0x20)
                    }
                    default {
                        let paired := 0
                        if lt(input, inputEnd) { paired := eq(mload(input), add(index, 1)) }
                        switch paired
                        case 1 {
                            right := mload(add(input, 0x20))
                            input := add(input, 0x40)
                        }
                        default {
                            if lt(add(index, 1), size) {
                                if eq(cursor, end) {
                                    valid := 0
                                    break
                                }
                                right := load(cursor, cd)
                                cursor := add(cursor, 0x20)
                            }
                        }
                    }
                    mstore(0, left)
                    mstore(0x20, right)
                    mstore(output, shr(1, index))
                    {
                        let hashed
                        switch hasher
                        case 0 { hashed := keccak256(0, 0x40) }
                        default { hashed := externalHash(0, 0x40, hasher) }
                        mstore(add(output, 0x20), hashed)
                    }
                    output := add(output, 0x40)
                }
                count := shr(6, sub(output, base))
                size := shr(1, add(size, 1))
            }
            mstore(0, leaves)
            mstore(0x20, mload(add(base, 0x20)))
            {
                let hashed
                switch hasher
                case 0 { hashed := keccak256(0x1c, 0x24) }
                default { hashed := externalHash(0x1c, 0x24, hasher) }
                valid := and(valid, and(eq(cursor, end), eq(root, hashed)))
            }
            for { let p := base } lt(p, limit) { p := add(p, 0x20) } { mstore(p, 0) }
        }
    }

    /// @dev Authenticate the unique finalized empty tree without allocating memory.
    function _empty(bytes32 root, uint256 leaves, uint256 proofLength, address hasher) private view returns (bool) {
        bytes32 digest = LibMerkleCommon.hash(0, 0, 0, 0, hasher);
        digest = LibMerkleCommon.hash(0, digest, 0x1c, 0x24, hasher);
        return leaves == 0 && proofLength == 0 && root == digest;
    }
}
