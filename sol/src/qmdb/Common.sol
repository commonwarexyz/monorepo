// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { Common as MerkleCommon } from "../merkle/Common.sol";
import { LibMerkle } from "../merkle/LibMerkle.sol";

/// @dev Shared QMDB operation proof reconstruction.
library Common {
    /// @dev Authenticate an operation root without activity bitmap grafting.
    function verify(
        bytes32 root,
        bytes memory operation,
        uint256 leaves,
        uint256 location,
        bytes32[] calldata digests,
        uint256 inactivePeaks,
        bool mmb,
        address hasher
    ) internal view returns (bool) {
        if (leaves > (uint256(1) << 62) + (mmb ? 30 : 0) || location >= leaves) {
            return false;
        }
        (bytes32 reconstructed, bool valid) =
            reconstruct(leaves, location, operation, digests, inactivePeaks, LibMerkle.Graft(0, 0), mmb, hasher);
        return valid && reconstructed == root;
    }

    /// @dev Reconstruct a backward-folded root from an encoded operation at its physical position.
    /// A zero graft width keeps the positioned leaf digest and binds no ancestor prefix.
    /// Callers validate the family's leaf bound and require `location < leaves` before hashing.
    /// Callers authenticate the returned root, including any surrounding current-state commitment.
    function reconstruct(
        uint256 leaves,
        uint256 location,
        bytes memory operation,
        bytes32[] calldata digests,
        uint256 inactivePeaks,
        LibMerkle.Graft memory graft,
        bool mmb,
        address hasher
    ) internal view returns (bytes32 root, bool valid) {
        uint256 position = MerkleCommon.position(MerkleCommon.peak(location, 1, mmb), 1, mmb);
        // The leaf bound keeps every physical position below `2^64`.
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes32 leaf = MerkleCommon.hash(abi.encodePacked(uint64(position), operation), hasher);
        return LibMerkle.reconstructGrafted(leaves, location, leaf, digests, inactivePeaks, graft, mmb, hasher);
    }
}
