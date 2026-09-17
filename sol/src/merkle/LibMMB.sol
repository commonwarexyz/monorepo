// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import { LibMerkle } from "./LibMerkle.sol";
import { LibMerkleSparse } from "./LibMerkleSparse.sol";

/// @title Commonware Merkle Mountain Belt inclusion verification
/// @notice Verify Keccak256 inclusion proofs for raw 32-byte elements.
/// @dev Supports at most `2^62 + 30` leaves.
/// Entry points without policy arguments use `ForwardFold` and zero inactive peaks.
/// Policy overloads select the fold direction and the inactive prefix committed by the root.
/// `LibMerkle` documents shared hashing and the policy-dependent range proof layout.
///
/// Peaks follow Commonware's delayed-merge schedule in leaf order.
/// For example, 10 leaves form peaks containing 4, 4 and 2 leaves.
/// Delayed parents can appear after leaves belonging to a later peak, so
/// physical node positions do not determine peak order.
///
/// Eight leaves form three peaks. Labels are physical node positions and the
/// bottom leaves in logical order are 0, 1, 3, 4, 6, 8, 10 and 11.
/// ```text
///            7                  9        12
///        +---+---+             / \      / \
///        2       5            6   8    10  11
///       / \     / \
///      0   1   3   4
/// ```
/// Peak order is 7, 9, 12. With `ForwardFold` and zero inactive peaks the root is
/// `H(uint64_be(8) || H(H(digest_at_7 || digest_at_9) || digest_at_12))`.
library LibMMB {
    /// @notice Verify the raw element at leaf index `index`.
    /// @dev Uses `ForwardFold` with zero inactive peaks.
    /// @param root Trusted root commitment supplied by the caller.
    /// @param leaves Total leaf count, at most `2^62 + 30`.
    /// @param index Zero-based index of the leaf.
    /// @param element Raw 32-byte value to hash with its physical node position.
    /// @param proof Exact Commonware range proof digests for `ForwardFold` with zero inactive peaks.
    /// @return True if the proof matches `root` and consumes every digest.
    /// Invalid bounds, missing digests or extra digests return false.
    function verify(bytes32 root, uint256 leaves, uint256 index, bytes32 element, bytes32[] memory proof)
        internal
        pure
        returns (bool)
    {
        uint256 proofData;
        assembly ("memory-safe") { proofData := add(proof, 0x20) }
        return LibMerkle.verify(root, leaves, index, uint256(element), 1, proofData, proof.length, true, false, true);
    }

    /// @notice Verify consecutive raw elements beginning at `start`.
    /// @dev Uses `ForwardFold` with zero inactive peaks.
    /// An empty range requires `leaves == start == 0`, an empty proof and
    /// `root == keccak256(bytes8(0))`.
    /// @param root Trusted root commitment supplied by the caller.
    /// @param leaves Total leaf count, at most `2^62 + 30`.
    /// @param start Zero-based index of the first leaf.
    /// @param elements Raw 32-byte values in consecutive leaf-index order.
    /// @param proof Exact Commonware range proof digests for `ForwardFold` with zero inactive peaks.
    /// @return True if the proof matches `root` and consumes every digest.
    /// Invalid bounds, missing digests or extra digests return false.
    function verifyRange(bytes32 root, uint256 leaves, uint256 start, bytes32[] memory elements, bytes32[] memory proof)
        internal
        pure
        returns (bool)
    {
        uint256 data;
        uint256 proofData;
        assembly ("memory-safe") {
            data := add(elements, 0x20)
            proofData := add(proof, 0x20)
        }
        return LibMerkle.verify(root, leaves, start, data, elements.length, proofData, proof.length, false, false, true);
    }

    /// @notice Verify the raw element at leaf index `index`.
    /// @dev Uses `ForwardFold` with zero inactive peaks.
    /// Input arrays are read directly from calldata without copying.
    /// @param root Trusted root commitment supplied by the caller.
    /// @param leaves Total leaf count, at most `2^62 + 30`.
    /// @param index Zero-based index of the leaf.
    /// @param element Raw 32-byte value to hash with its physical node position.
    /// @param proof Exact Commonware range proof digests for `ForwardFold` with zero inactive peaks.
    /// @return True if the proof matches `root` and consumes every digest.
    /// Invalid bounds, missing digests or extra digests return false.
    function verifyCalldata(bytes32 root, uint256 leaves, uint256 index, bytes32 element, bytes32[] calldata proof)
        internal
        pure
        returns (bool)
    {
        uint256 proofData;
        assembly ("memory-safe") { proofData := proof.offset }
        return LibMerkle.verify(root, leaves, index, uint256(element), 1, proofData, proof.length, true, true, true);
    }

    /// @notice Verify consecutive raw elements beginning at `start`.
    /// @dev Uses `ForwardFold` with zero inactive peaks.
    /// Input arrays are read directly from calldata without copying.
    /// An empty range requires `leaves == start == 0`, an empty proof and
    /// `root == keccak256(bytes8(0))`.
    /// @param root Trusted root commitment supplied by the caller.
    /// @param leaves Total leaf count, at most `2^62 + 30`.
    /// @param start Zero-based index of the first leaf.
    /// @param elements Raw 32-byte values in consecutive leaf-index order.
    /// @param proof Exact Commonware range proof digests for `ForwardFold` with zero inactive peaks.
    /// @return True if the proof matches `root` and consumes every digest.
    /// Invalid bounds, missing digests or extra digests return false.
    function verifyRangeCalldata(
        bytes32 root,
        uint256 leaves,
        uint256 start,
        bytes32[] calldata elements,
        bytes32[] calldata proof
    ) internal pure returns (bool) {
        uint256 data;
        uint256 proofData;
        assembly ("memory-safe") {
            data := elements.offset
            proofData := proof.offset
        }
        return LibMerkle.verify(root, leaves, start, data, elements.length, proofData, proof.length, false, true, true);
    }

    /// @notice Verify the raw element at leaf index `index`.
    /// @dev The proof layout and trusted root must use the supplied bagging and inactive boundary.
    /// @param root Trusted root commitment supplied by the caller.
    /// @param leaves Total leaf count, at most `2^62 + 30`.
    /// @param index Zero-based index of the leaf.
    /// @param element Raw 32-byte value to hash with its physical node position.
    /// @param proof Exact Commonware range proof digests for the selected root policy.
    /// @param bagging Fold direction for the peak list after the inactive prefix is folded forward.
    /// @param inactivePeaks Leading inactive peak count committed by `root`, from zero through the total peak count.
    /// @return True if the proof matches `root` and consumes every digest.
    /// Invalid bounds, an invalid inactive count, missing digests or extra digests return false.
    function verify(
        bytes32 root,
        uint256 leaves,
        uint256 index,
        bytes32 element,
        bytes32[] memory proof,
        LibMerkle.Bagging bagging,
        uint256 inactivePeaks
    ) internal pure returns (bool) {
        uint256 proofData;
        assembly ("memory-safe") { proofData := add(proof, 0x20) }
        return LibMerkle.verify(
            root, leaves, index, uint256(element), 1, proofData, proof.length, true, false, true, bagging, inactivePeaks
        );
    }

    /// @notice Verify consecutive raw elements beginning at `start`.
    /// @dev An empty range requires `leaves == start == 0`, an empty proof and
    /// `root == keccak256(bytes8(0))` with zero inactive peaks.
    /// @param root Trusted root commitment supplied by the caller.
    /// @param leaves Total leaf count, at most `2^62 + 30`.
    /// @param start Zero-based index of the first leaf.
    /// @param elements Raw 32-byte values in consecutive leaf-index order.
    /// @param proof Exact Commonware range proof digests for the selected root policy.
    /// @param bagging Fold direction for the peak list after the inactive prefix is folded forward.
    /// @param inactivePeaks Leading inactive peak count committed by `root`, from zero through the total peak count.
    /// @return True if the proof matches `root` and consumes every digest.
    /// Invalid bounds, an invalid inactive count, missing digests or extra digests return false.
    function verifyRange(
        bytes32 root,
        uint256 leaves,
        uint256 start,
        bytes32[] memory elements,
        bytes32[] memory proof,
        LibMerkle.Bagging bagging,
        uint256 inactivePeaks
    ) internal pure returns (bool) {
        uint256 data;
        uint256 proofData;
        assembly ("memory-safe") {
            data := add(elements, 0x20)
            proofData := add(proof, 0x20)
        }
        return LibMerkle.verify(
            root,
            leaves,
            start,
            data,
            elements.length,
            proofData,
            proof.length,
            false,
            false,
            true,
            bagging,
            inactivePeaks
        );
    }

    /// @notice Verify the raw element at leaf index `index`.
    /// @dev Input arrays are read directly from calldata without copying.
    /// The proof layout and trusted root must use the supplied bagging and inactive boundary.
    /// @param root Trusted root commitment supplied by the caller.
    /// @param leaves Total leaf count, at most `2^62 + 30`.
    /// @param index Zero-based index of the leaf.
    /// @param element Raw 32-byte value to hash with its physical node position.
    /// @param proof Exact Commonware range proof digests for the selected root policy.
    /// @param bagging Fold direction for the peak list after the inactive prefix is folded forward.
    /// @param inactivePeaks Leading inactive peak count committed by `root`, from zero through the total peak count.
    /// @return True if the proof matches `root` and consumes every digest.
    /// Invalid bounds, an invalid inactive count, missing digests or extra digests return false.
    function verifyCalldata(
        bytes32 root,
        uint256 leaves,
        uint256 index,
        bytes32 element,
        bytes32[] calldata proof,
        LibMerkle.Bagging bagging,
        uint256 inactivePeaks
    ) internal pure returns (bool) {
        uint256 proofData;
        assembly ("memory-safe") { proofData := proof.offset }
        return LibMerkle.verify(
            root, leaves, index, uint256(element), 1, proofData, proof.length, true, true, true, bagging, inactivePeaks
        );
    }

    /// @notice Verify consecutive raw elements beginning at `start`.
    /// @dev Input arrays are read directly from calldata without copying.
    /// An empty range requires `leaves == start == 0`, an empty proof and
    /// `root == keccak256(bytes8(0))` with zero inactive peaks.
    /// @param root Trusted root commitment supplied by the caller.
    /// @param leaves Total leaf count, at most `2^62 + 30`.
    /// @param start Zero-based index of the first leaf.
    /// @param elements Raw 32-byte values in consecutive leaf-index order.
    /// @param proof Exact Commonware range proof digests for the selected root policy.
    /// @param bagging Fold direction for the peak list after the inactive prefix is folded forward.
    /// @param inactivePeaks Leading inactive peak count committed by `root`, from zero through the total peak count.
    /// @return True if the proof matches `root` and consumes every digest.
    /// Invalid bounds, an invalid inactive count, missing digests or extra digests return false.
    function verifyRangeCalldata(
        bytes32 root,
        uint256 leaves,
        uint256 start,
        bytes32[] calldata elements,
        bytes32[] calldata proof,
        LibMerkle.Bagging bagging,
        uint256 inactivePeaks
    ) internal pure returns (bool) {
        uint256 data;
        uint256 proofData;
        assembly ("memory-safe") {
            data := elements.offset
            proofData := proof.offset
        }
        return LibMerkle.verify(
            root,
            leaves,
            start,
            data,
            elements.length,
            proofData,
            proof.length,
            false,
            true,
            true,
            bagging,
            inactivePeaks
        );
    }

    /// @notice Verify sparse raw elements under the selected root policy.
    /// @dev Witnesses must be the exact union required by Commonware single-leaf proofs.
    /// This union includes witnesses that could be derived from other supplied elements.
    /// Empty inputs require an empty tree, no witnesses, zero inactive peaks and
    /// `root == keccak256(bytes8(0))`.
    /// @param root Trusted root commitment supplied by the caller.
    /// @param leaves Total leaf count, at most `2^62 + 30`.
    /// @param indices Zero-based leaf indices, which may be unordered or repeated.
    /// @param elements Raw values paired with `indices`. Repeated indices require identical values.
    /// @param proofPositions Strictly increasing physical node positions paired with proof digests.
    /// @param proof Canonical Commonware multiproof digests in `proofPositions` order.
    /// @param bagging Fold direction for the peak list after the inactive prefix is folded forward.
    /// @param inactivePeaks Leading inactive peak count committed by `root`, from zero through the total peak count.
    /// @return True if every element matches `root` and the witness union is exact.
    /// Invalid bounds, unequal paired array lengths or malformed witnesses return false.
    function verifyMulti(
        bytes32 root,
        uint256 leaves,
        uint256[] memory indices,
        bytes32[] memory elements,
        uint256[] memory proofPositions,
        bytes32[] memory proof,
        LibMerkle.Bagging bagging,
        uint256 inactivePeaks
    ) internal pure returns (bool) {
        if (indices.length != elements.length || proofPositions.length != proof.length) {
            return false;
        }
        uint256 data;
        uint256 proofData;
        uint256 indexData;
        uint256 positionData;
        assembly ("memory-safe") {
            data := add(elements, 0x20)
            proofData := add(proof, 0x20)
            indexData := add(indices, 0x20)
            positionData := add(proofPositions, 0x20)
        }
        return LibMerkleSparse.verify(
            root,
            leaves,
            indexData,
            data,
            elements.length,
            positionData,
            proofData,
            proof.length,
            bagging == LibMerkle.Bagging.BackwardFold,
            inactivePeaks,
            false,
            true
        );
    }

    /// @notice Verify sparse raw elements under the selected root policy.
    /// @dev Proof arrays are read directly from calldata. Selected elements use temporary working memory.
    /// Witnesses must be the exact union required by Commonware single-leaf proofs.
    /// This union includes witnesses that could be derived from other supplied elements.
    /// Empty inputs require an empty tree, no witnesses, zero inactive peaks and
    /// `root == keccak256(bytes8(0))`.
    /// @param root Trusted root commitment supplied by the caller.
    /// @param leaves Total leaf count, at most `2^62 + 30`.
    /// @param indices Zero-based leaf indices, which may be unordered or repeated.
    /// @param elements Raw values paired with `indices`. Repeated indices require identical values.
    /// @param proofPositions Strictly increasing physical node positions paired with proof digests.
    /// @param proof Canonical Commonware multiproof digests in `proofPositions` order.
    /// @param bagging Fold direction for the peak list after the inactive prefix is folded forward.
    /// @param inactivePeaks Leading inactive peak count committed by `root`, from zero through the total peak count.
    /// @return True if every element matches `root` and the witness union is exact.
    /// Invalid bounds, unequal paired array lengths or malformed witnesses return false.
    function verifyMultiCalldata(
        bytes32 root,
        uint256 leaves,
        uint256[] calldata indices,
        bytes32[] calldata elements,
        uint256[] calldata proofPositions,
        bytes32[] calldata proof,
        LibMerkle.Bagging bagging,
        uint256 inactivePeaks
    ) internal pure returns (bool) {
        if (indices.length != elements.length || proofPositions.length != proof.length) {
            return false;
        }
        uint256 data;
        uint256 proofData;
        uint256 indexData;
        uint256 positionData;
        assembly ("memory-safe") {
            data := elements.offset
            proofData := proof.offset
            indexData := indices.offset
            positionData := proofPositions.offset
        }
        return LibMerkleSparse.verify(
            root,
            leaves,
            indexData,
            data,
            elements.length,
            positionData,
            proofData,
            proof.length,
            bagging == LibMerkle.Bagging.BackwardFold,
            inactivePeaks,
            true,
            true
        );
    }
}
