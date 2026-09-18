// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { Common } from "./Common.sol";

/// @notice Verify inclusion of encoded operations in an immutable QMDB.
/// @dev Operations include the `Set` or `Commit` tag and the database's fixed or variable encoding.
/// Verification binds the key, value, metadata, floor, length prefixes, and padding as opaque bytes.
/// Locations count sets and commits. Inclusion does not establish key uniqueness or current activity.
/// The caller supplies an authenticated root and a trusted hash target that returns exactly 32 bytes.
/// A failed hash call or any other return length reverts with `HashFailed()`.
library LibQMDBImmutable {
    /// @dev A single-operation proof with the inactive peak boundary committed by the root.
    struct Proof {
        uint256 leaves;
        uint256 location;
        uint256 inactivePeaks;
        bytes32[] digests;
    }

    /// @notice Verify an encoded operation against a trusted immutable MMB root.
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

    /// @notice Verify an encoded operation against a trusted immutable MMR root.
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
}
