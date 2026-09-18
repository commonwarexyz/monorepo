// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { Common as MerkleCommon } from "../merkle/Common.sol";
import { LibMerkle } from "../merkle/LibMerkle.sol";
import { LibMerkleSparse } from "../merkle/LibMerkleSparse.sol";

/// @dev Shared QMDB operation proof reconstruction.
library Common {
    /// @dev A contiguous operation range with backward-folded Merkle witnesses.
    struct RangeProof {
        uint256 leaves;
        uint256 start;
        uint256 inactivePeaks;
        bytes32[] digests;
    }

    /// @dev Sparse operations with witnesses in increasing physical position order.
    struct MultiProof {
        uint256 leaves;
        uint256[] locations;
        uint256 inactivePeaks;
        uint256[] positions;
        bytes32[] digests;
    }

    /// @dev Authenticate exact encoded operations at consecutive locations.
    function verifyRange(bytes32 root, bytes[] memory operations, RangeProof calldata proof, bool mmb, address hasher)
        internal
        view
        returns (bool)
    {
        (bytes32 reconstructed, bool valid) = reconstructRange(
            operations,
            proof.leaves,
            proof.start,
            proof.digests,
            proof.inactivePeaks,
            LibMerkle.RangeGraft(0, 0, 0, 0),
            mmb,
            hasher
        );
        return valid && reconstructed == root;
    }

    /// @dev Reconstruct a range after hashing exact operation encodings at their physical positions.
    /// Callers authenticate the returned root and any Current bitmap commitments.
    function reconstructRange(
        bytes[] memory operations,
        uint256 leaves,
        uint256 start,
        bytes32[] calldata digests,
        uint256 inactivePeaks,
        LibMerkle.RangeGraft memory graft,
        bool mmb,
        address hasher
    ) internal view returns (bytes32 root, bool valid) {
        // forge-lint: disable-next-line(boolean-cst)
        if (leaves > (uint256(1) << 62) + (mmb ? 30 : 0)) return (0, false);
        // forge-lint: disable-next-line(boolean-cst)
        if (start > leaves || operations.length > leaves - start) return (0, false);
        bytes32[] memory elements = new bytes32[](operations.length);
        for (uint256 i; i < operations.length; ++i) {
            uint256 position = MerkleCommon.position(MerkleCommon.peak(start + i, 1, mmb), 1, mmb);
            // forge-lint: disable-next-line(unsafe-typecast)
            elements[i] = MerkleCommon.hash(abi.encodePacked(uint64(position), operations[i]), hasher);
        }
        return LibMerkle.reconstructPrehashed(leaves, start, elements, digests, inactivePeaks, graft, mmb, hasher);
    }

    /// @dev Authenticate exact encoded operations at the supplied locations.
    /// Every location is checked before hashing and duplicate locations require equal operations.
    function verifyMulti(bytes32 root, bytes[] memory operations, MultiProof calldata proof, bool mmb, address hasher)
        internal
        view
        returns (bool)
    {
        uint256 leaves = proof.leaves;
        if (leaves > (uint256(1) << 62) + (mmb ? 30 : 0)) return false;
        if (operations.length != proof.locations.length || proof.positions.length != proof.digests.length) {
            return false;
        }
        for (uint256 i; i < operations.length; ++i) {
            if (proof.locations[i] >= leaves) return false;
        }
        bytes32[] memory elements = new bytes32[](operations.length);
        for (uint256 i; i < operations.length; ++i) {
            uint256 position = MerkleCommon.position(MerkleCommon.peak(proof.locations[i], 1, mmb), 1, mmb);
            // forge-lint: disable-next-line(unsafe-typecast)
            elements[i] = MerkleCommon.hash(abi.encodePacked(uint64(position), operations[i]), hasher);
        }
        return LibMerkleSparse.verifyPrehashed(
            root, leaves, proof.locations, elements, proof.positions, proof.digests, proof.inactivePeaks, mmb, hasher
        );
    }

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
