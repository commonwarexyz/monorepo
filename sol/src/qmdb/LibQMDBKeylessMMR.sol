// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { LibMerkle } from "../merkle/LibMerkle.sol";
import { LibQMDBCommon } from "./LibQMDBCommon.sol";

/// @notice Verify inclusion of encoded operations in a keyless QMDB.
/// @dev Operations include their append or commit tag and the database's fixed or variable encoding.
/// Locations count all operations, including commits. The caller supplies an authenticated
/// root and a trusted hash target.
/// Inclusion authenticates operation bytes at their locations without establishing current activity.
/// Nonzero hash targets receive raw bytes via `STATICCALL` and must return exactly 32 bytes.
/// A failed call or another return length reverts with `HashFailed()`.
library LibQMDBKeylessMMR {
    /// @notice Verify an encoded operation against a trusted keyless MMR root.
    /// @param root Authenticated keyless QMDB MMR root.
    /// @param operation Exact Commonware operation encoding, including codec tags, padding and length prefixes.
    /// @param proof Single-operation proof with its location and inactive peak boundary.
    /// @param hasher Trusted raw hash target, or `address(0)` for native Keccak256.
    /// @return True when the operation reconstructs `root` and consumes every digest.
    function verify(bytes32 root, bytes memory operation, LibQMDBCommon.Proof calldata proof, address hasher)
        internal
        view
        returns (bool)
    {
        return LibQMDBCommon.verify(
            root,
            operation,
            proof.leaves,
            proof.location,
            proof.digests,
            proof.inactivePeaks,
            LibMerkle.Family.MMR,
            hasher
        );
    }

    /// @notice Verify a contiguous range of encoded operations against a trusted keyless MMR root.
    /// @param root Authenticated keyless QMDB MMR root.
    /// @param operations Exact Commonware operation encodings in consecutive location order.
    /// @param proof Range proof with its start location and backward-folded witnesses.
    /// @param hasher Trusted raw hash target, or `address(0)` for native Keccak256.
    /// @return True when the range reconstructs `root` and consumes every digest.
    function verifyRange(
        bytes32 root,
        bytes[] memory operations,
        LibQMDBCommon.RangeProof calldata proof,
        address hasher
    ) internal view returns (bool) {
        return LibQMDBCommon.verifyRange(root, operations, proof, LibMerkle.Family.MMR, hasher);
    }

    /// @notice Verify a sparse selection of encoded operations against a trusted keyless MMR root.
    /// @param root Authenticated keyless QMDB MMR root.
    /// @param operations Exact Commonware operation encodings corresponding to `proof.locations`.
    /// @param proof Sparse proof with witnesses in increasing physical position order.
    /// @param hasher Trusted raw hash target, or `address(0)` for native Keccak256.
    /// @return True when the selected operations reconstruct `root` and consume every witness.
    function verifyMulti(
        bytes32 root,
        bytes[] memory operations,
        LibQMDBCommon.MultiProof calldata proof,
        address hasher
    ) internal view returns (bool) {
        return LibQMDBCommon.verifyMulti(root, operations, proof, LibMerkle.Family.MMR, hasher);
    }
}
