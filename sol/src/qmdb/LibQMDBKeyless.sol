// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { Common } from "./Common.sol";

/// @notice Verify inclusion of encoded operations in a keyless QMDB.
/// @dev Operations include their append or commit tag and the database's fixed or variable encoding.
/// Locations count all operations, including commits. The caller supplies an authenticated
/// root and a trusted hash target. Targets receive raw bytes and must return exactly 32 bytes.
/// A failed call or any other return length reverts with `HashFailed()`.
library LibQMDBKeyless {
    /// @dev A single-operation proof with the inactive peak boundary committed by the root.
    struct Proof {
        uint256 leaves;
        uint256 location;
        uint256 inactivePeaks;
        bytes32[] digests;
    }

    /// @notice Verify an encoded operation against a trusted keyless MMB root.
    /// @param root Authenticated QMDB root.
    /// @param operation Exact Commonware operation encoding, including any codec padding or length prefixes.
    /// @param proof Single-operation membership proof.
    /// @param hasher Trusted raw hash target, or `address(0)` for native Keccak256.
    /// @return True when the operation reconstructs `root` and consumes every digest.
    function verify(bytes32 root, bytes memory operation, Proof calldata proof, address hasher)
        internal
        view
        returns (bool)
    {
        return Common.verify(
            root, operation, proof.leaves, proof.location, proof.digests, proof.inactivePeaks, true, hasher
        );
    }

    /// @notice Verify an encoded operation against a trusted keyless MMR root.
    /// @param root Authenticated QMDB root.
    /// @param operation Exact Commonware operation encoding, including any codec padding or length prefixes.
    /// @param proof Single-operation membership proof.
    /// @param hasher Trusted raw hash target, or `address(0)` for native Keccak256.
    /// @return True when the operation reconstructs `root` and consumes every digest.
    function verifyMMR(bytes32 root, bytes memory operation, Proof calldata proof, address hasher)
        internal
        view
        returns (bool)
    {
        return Common.verify(
            root, operation, proof.leaves, proof.location, proof.digests, proof.inactivePeaks, false, hasher
        );
    }

    /// @notice Verify a contiguous range of encoded operations against a trusted keyless MMB root.
    /// @dev Each operation includes its exact codec tags, padding and length prefixes.
    function verifyRange(bytes32 root, bytes[] memory operations, Common.RangeProof calldata proof, address hasher)
        internal
        view
        returns (bool)
    {
        return Common.verifyRange(root, operations, proof, true, hasher);
    }

    /// @notice Verify a contiguous range of encoded operations against a trusted keyless MMR root.
    /// @dev Each operation includes its exact codec tags, padding and length prefixes.
    function verifyRangeMMR(bytes32 root, bytes[] memory operations, Common.RangeProof calldata proof, address hasher)
        internal
        view
        returns (bool)
    {
        return Common.verifyRange(root, operations, proof, false, hasher);
    }

    /// @notice Verify a sparse selection of encoded operations against a trusted keyless MMB root.
    /// @dev Each operation includes its exact codec tags, padding and length prefixes.
    function verifyMulti(bytes32 root, bytes[] memory operations, Common.MultiProof calldata proof, address hasher)
        internal
        view
        returns (bool)
    {
        return Common.verifyMulti(root, operations, proof, true, hasher);
    }

    /// @notice Verify a sparse selection of encoded operations against a trusted keyless MMR root.
    /// @dev Each operation includes its exact codec tags, padding and length prefixes.
    function verifyMultiMMR(bytes32 root, bytes[] memory operations, Common.MultiProof calldata proof, address hasher)
        internal
        view
        returns (bool)
    {
        return Common.verifyMulti(root, operations, proof, false, hasher);
    }
}
