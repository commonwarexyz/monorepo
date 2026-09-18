// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { Common } from "./Common.sol";

/// @notice Verify inclusion of encoded operations in an ordered or unordered any QMDB.
/// @dev Inclusion authenticates operation bytes at a location, not their current activity or key exclusion.
/// Uses QMDB's backward peak fold and big-endian position and count encodings.
/// The caller supplies an authenticated root and a trusted hash target.
/// Hash targets receive raw bytes and must return exactly 32 bytes.
/// A failed call or any other return length reverts with `HashFailed()`.
library LibQMDBAny {
    /// @dev A single-operation proof with the inactive peak boundary committed by the root.
    struct Proof {
        uint256 leaves;
        uint256 location;
        uint256 inactivePeaks;
        bytes32[] digests;
    }

    /// @notice Verify an encoded operation against a trusted any MMB root.
    /// @param root Authenticated QMDB root.
    /// @param operation Exact Commonware operation encoding, without a length prefix.
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

    /// @notice Verify an encoded operation against a trusted any MMR root.
    /// @param root Authenticated QMDB root.
    /// @param operation Exact Commonware operation encoding, without a length prefix.
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
