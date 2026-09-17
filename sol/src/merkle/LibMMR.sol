// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { LibMerkle } from "./LibMerkle.sol";
import { LibMerkleSparse } from "./LibMerkleSparse.sol";

/// @title Commonware Merkle Mountain Range inclusion verification
/// @notice Verify inclusion proofs with a caller-selected hash for raw 32-byte elements.
/// @dev Supports at most `2^62` leaves.
/// `H` is native Keccak256 for `address(0)`. Other addresses receive raw hash input via
/// `STATICCALL` and must return exactly 32 bytes. The caller must trust the selected hasher.
/// A failed call or any other return length reverts with `Common.HashFailed()`.
/// Entry points without policy arguments use `ForwardFold` and zero inactive peaks.
/// Policy overloads select the fold direction and the inactive prefix committed by the root.
/// `LibMerkle` documents shared hashing and the policy-dependent range proof layout.
///
/// Peaks correspond to set bits of the leaf count, from largest to smallest.
/// For example, 13 leaves form peaks containing 8, 4 and 1 leaves.
/// Nodes use postorder positions. A parent covering `w` leaves has children at
/// `parent - w` and `parent - 1`.
///
/// Eight leaves form one peak. Labels are physical node positions and the
/// bottom row follows leaf-index order.
/// ```text
///                     14
///              +-------+-------+
///              6              13
///          +---+---+      +----+---+
///          2       5      9       12
///         / \     / \    / \     / \
///        0   1   3   4  7   8   10  11
/// ```
/// With zero inactive peaks the root is `H(uint64_be(8) || digest_at_14)`.
library LibMMR {
    /// @notice Verify the raw element at leaf index `index`.
    /// @dev Uses `ForwardFold` with zero inactive peaks.
    /// @param root Trusted root commitment supplied by the caller.
    /// @param leaves Total leaf count, at most `2^62`.
    /// @param index Zero-based index of the leaf.
    /// @param element Raw 32-byte value to hash with its physical node position.
    /// @param proof Exact Commonware range proof digests for `ForwardFold` with zero inactive peaks.
    /// @param hasher Trusted raw hash target, or `address(0)` for native Keccak256.
    /// @return True if the proof matches `root` and consumes every digest.
    /// Invalid bounds, missing digests or extra digests return false.
    function verify(
        bytes32 root,
        uint256 leaves,
        uint256 index,
        bytes32 element,
        bytes32[] memory proof,
        address hasher
    ) internal view returns (bool) {
        uint256 proofData;
        assembly ("memory-safe") { proofData := add(proof, 0x20) }
        return LibMerkle.verify(
            root, leaves, index, uint256(element), 1, proofData, proof.length, true, false, false, hasher
        );
    }

    /// @notice Verify consecutive raw elements beginning at `start`.
    /// @dev Uses `ForwardFold` with zero inactive peaks.
    /// An empty range requires `leaves == start == 0`, an empty proof and
    /// `root == H(bytes8(0))`.
    /// @param root Trusted root commitment supplied by the caller.
    /// @param leaves Total leaf count, at most `2^62`.
    /// @param start Zero-based index of the first leaf.
    /// @param elements Raw 32-byte values in consecutive leaf-index order.
    /// @param proof Exact Commonware range proof digests for `ForwardFold` with zero inactive peaks.
    /// @param hasher Trusted raw hash target, or `address(0)` for native Keccak256.
    /// @return True if the proof matches `root` and consumes every digest.
    /// Invalid bounds, missing digests or extra digests return false.
    function verifyRange(
        bytes32 root,
        uint256 leaves,
        uint256 start,
        bytes32[] memory elements,
        bytes32[] memory proof,
        address hasher
    ) internal view returns (bool) {
        uint256 data;
        uint256 proofData;
        assembly ("memory-safe") {
            data := add(elements, 0x20)
            proofData := add(proof, 0x20)
        }
        return LibMerkle.verify(
            root, leaves, start, data, elements.length, proofData, proof.length, false, false, false, hasher
        );
    }

    /// @notice Verify the raw element at leaf index `index`.
    /// @dev Uses `ForwardFold` with zero inactive peaks.
    /// Input arrays are read directly from calldata without copying.
    /// @param root Trusted root commitment supplied by the caller.
    /// @param leaves Total leaf count, at most `2^62`.
    /// @param index Zero-based index of the leaf.
    /// @param element Raw 32-byte value to hash with its physical node position.
    /// @param proof Exact Commonware range proof digests for `ForwardFold` with zero inactive peaks.
    /// @param hasher Trusted raw hash target, or `address(0)` for native Keccak256.
    /// @return True if the proof matches `root` and consumes every digest.
    /// Invalid bounds, missing digests or extra digests return false.
    function verifyCalldata(
        bytes32 root,
        uint256 leaves,
        uint256 index,
        bytes32 element,
        bytes32[] calldata proof,
        address hasher
    ) internal view returns (bool) {
        uint256 proofData;
        assembly ("memory-safe") { proofData := proof.offset }
        return LibMerkle.verify(
            root, leaves, index, uint256(element), 1, proofData, proof.length, true, true, false, hasher
        );
    }

    /// @notice Verify consecutive raw elements beginning at `start`.
    /// @dev Uses `ForwardFold` with zero inactive peaks.
    /// Input arrays are read directly from calldata without copying.
    /// An empty range requires `leaves == start == 0`, an empty proof and
    /// `root == H(bytes8(0))`.
    /// @param root Trusted root commitment supplied by the caller.
    /// @param leaves Total leaf count, at most `2^62`.
    /// @param start Zero-based index of the first leaf.
    /// @param elements Raw 32-byte values in consecutive leaf-index order.
    /// @param proof Exact Commonware range proof digests for `ForwardFold` with zero inactive peaks.
    /// @param hasher Trusted raw hash target, or `address(0)` for native Keccak256.
    /// @return True if the proof matches `root` and consumes every digest.
    /// Invalid bounds, missing digests or extra digests return false.
    function verifyRangeCalldata(
        bytes32 root,
        uint256 leaves,
        uint256 start,
        bytes32[] calldata elements,
        bytes32[] calldata proof,
        address hasher
    ) internal view returns (bool) {
        uint256 data;
        uint256 proofData;
        assembly ("memory-safe") {
            data := elements.offset
            proofData := proof.offset
        }
        return LibMerkle.verify(
            root, leaves, start, data, elements.length, proofData, proof.length, false, true, false, hasher
        );
    }

    /// @notice Verify the raw element at leaf index `index`.
    /// @dev The proof layout and trusted root must use the supplied bagging and inactive boundary.
    /// @param root Trusted root commitment supplied by the caller.
    /// @param leaves Total leaf count, at most `2^62`.
    /// @param index Zero-based index of the leaf.
    /// @param element Raw 32-byte value to hash with its physical node position.
    /// @param proof Exact Commonware range proof digests for the selected root policy.
    /// @param bagging Fold direction for the peak list after the inactive prefix is folded forward.
    /// @param inactivePeaks Leading inactive peak count committed by `root`, from zero through the total peak count.
    /// @param hasher Trusted raw hash target, or `address(0)` for native Keccak256.
    /// @return True if the proof matches `root` and consumes every digest.
    /// Invalid bounds, an invalid inactive count, missing digests or extra digests return false.
    function verify(
        bytes32 root,
        uint256 leaves,
        uint256 index,
        bytes32 element,
        bytes32[] memory proof,
        LibMerkle.Bagging bagging,
        uint256 inactivePeaks,
        address hasher
    ) internal view returns (bool) {
        uint256 proofData;
        assembly ("memory-safe") { proofData := add(proof, 0x20) }
        return LibMerkle.verify(
            root,
            leaves,
            index,
            uint256(element),
            1,
            proofData,
            proof.length,
            true,
            false,
            false,
            bagging,
            inactivePeaks,
            hasher
        );
    }

    /// @notice Verify consecutive raw elements beginning at `start`.
    /// @dev An empty range requires `leaves == start == 0`, an empty proof and
    /// `root == H(bytes8(0))` with zero inactive peaks.
    /// @param root Trusted root commitment supplied by the caller.
    /// @param leaves Total leaf count, at most `2^62`.
    /// @param start Zero-based index of the first leaf.
    /// @param elements Raw 32-byte values in consecutive leaf-index order.
    /// @param proof Exact Commonware range proof digests for the selected root policy.
    /// @param bagging Fold direction for the peak list after the inactive prefix is folded forward.
    /// @param inactivePeaks Leading inactive peak count committed by `root`, from zero through the total peak count.
    /// @param hasher Trusted raw hash target, or `address(0)` for native Keccak256.
    /// @return True if the proof matches `root` and consumes every digest.
    /// Invalid bounds, an invalid inactive count, missing digests or extra digests return false.
    function verifyRange(
        bytes32 root,
        uint256 leaves,
        uint256 start,
        bytes32[] memory elements,
        bytes32[] memory proof,
        LibMerkle.Bagging bagging,
        uint256 inactivePeaks,
        address hasher
    ) internal view returns (bool) {
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
            false,
            bagging,
            inactivePeaks,
            hasher
        );
    }

    /// @notice Verify the raw element at leaf index `index`.
    /// @dev Input arrays are read directly from calldata without copying.
    /// The proof layout and trusted root must use the supplied bagging and inactive boundary.
    /// @param root Trusted root commitment supplied by the caller.
    /// @param leaves Total leaf count, at most `2^62`.
    /// @param index Zero-based index of the leaf.
    /// @param element Raw 32-byte value to hash with its physical node position.
    /// @param proof Exact Commonware range proof digests for the selected root policy.
    /// @param bagging Fold direction for the peak list after the inactive prefix is folded forward.
    /// @param inactivePeaks Leading inactive peak count committed by `root`, from zero through the total peak count.
    /// @param hasher Trusted raw hash target, or `address(0)` for native Keccak256.
    /// @return True if the proof matches `root` and consumes every digest.
    /// Invalid bounds, an invalid inactive count, missing digests or extra digests return false.
    function verifyCalldata(
        bytes32 root,
        uint256 leaves,
        uint256 index,
        bytes32 element,
        bytes32[] calldata proof,
        LibMerkle.Bagging bagging,
        uint256 inactivePeaks,
        address hasher
    ) internal view returns (bool) {
        uint256 proofData;
        assembly ("memory-safe") { proofData := proof.offset }
        return LibMerkle.verify(
            root,
            leaves,
            index,
            uint256(element),
            1,
            proofData,
            proof.length,
            true,
            true,
            false,
            bagging,
            inactivePeaks,
            hasher
        );
    }

    /// @notice Verify consecutive raw elements beginning at `start`.
    /// @dev Input arrays are read directly from calldata without copying.
    /// An empty range requires `leaves == start == 0`, an empty proof and
    /// `root == H(bytes8(0))` with zero inactive peaks.
    /// @param root Trusted root commitment supplied by the caller.
    /// @param leaves Total leaf count, at most `2^62`.
    /// @param start Zero-based index of the first leaf.
    /// @param elements Raw 32-byte values in consecutive leaf-index order.
    /// @param proof Exact Commonware range proof digests for the selected root policy.
    /// @param bagging Fold direction for the peak list after the inactive prefix is folded forward.
    /// @param inactivePeaks Leading inactive peak count committed by `root`, from zero through the total peak count.
    /// @param hasher Trusted raw hash target, or `address(0)` for native Keccak256.
    /// @return True if the proof matches `root` and consumes every digest.
    /// Invalid bounds, an invalid inactive count, missing digests or extra digests return false.
    function verifyRangeCalldata(
        bytes32 root,
        uint256 leaves,
        uint256 start,
        bytes32[] calldata elements,
        bytes32[] calldata proof,
        LibMerkle.Bagging bagging,
        uint256 inactivePeaks,
        address hasher
    ) internal view returns (bool) {
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
            false,
            bagging,
            inactivePeaks,
            hasher
        );
    }

    /// @notice Verify sparse raw elements under the selected root policy.
    /// @dev Witnesses must be the exact union required by Commonware single-leaf proofs.
    /// This union includes witnesses that could be derived from other supplied elements.
    /// Empty inputs require an empty tree, no witnesses, zero inactive peaks and
    /// `root == H(bytes8(0))`.
    /// @param root Trusted root commitment supplied by the caller.
    /// @param leaves Total leaf count, at most `2^62`.
    /// @param indices Zero-based leaf indices, which may be unordered or repeated.
    /// @param elements Raw values paired with `indices`. Repeated indices require identical values.
    /// @param proofPositions Strictly increasing physical node positions paired with proof digests.
    /// @param proof Canonical Commonware multiproof digests in `proofPositions` order.
    /// @param bagging Fold direction for the peak list after the inactive prefix is folded forward.
    /// @param inactivePeaks Leading inactive peak count committed by `root`, from zero through the total peak count.
    /// @param hasher Trusted raw hash target, or `address(0)` for native Keccak256.
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
        uint256 inactivePeaks,
        address hasher
    ) internal view returns (bool) {
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
            false,
            hasher
        );
    }

    /// @notice Verify sparse raw elements under the selected root policy.
    /// @dev Proof arrays are read directly from calldata. Selected elements use temporary working memory.
    /// Witnesses must be the exact union required by Commonware single-leaf proofs.
    /// This union includes witnesses that could be derived from other supplied elements.
    /// Empty inputs require an empty tree, no witnesses, zero inactive peaks and
    /// `root == H(bytes8(0))`.
    /// @param root Trusted root commitment supplied by the caller.
    /// @param leaves Total leaf count, at most `2^62`.
    /// @param indices Zero-based leaf indices, which may be unordered or repeated.
    /// @param elements Raw values paired with `indices`. Repeated indices require identical values.
    /// @param proofPositions Strictly increasing physical node positions paired with proof digests.
    /// @param proof Canonical Commonware multiproof digests in `proofPositions` order.
    /// @param bagging Fold direction for the peak list after the inactive prefix is folded forward.
    /// @param inactivePeaks Leading inactive peak count committed by `root`, from zero through the total peak count.
    /// @param hasher Trusted raw hash target, or `address(0)` for native Keccak256.
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
        uint256 inactivePeaks,
        address hasher
    ) internal view returns (bool) {
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
            false,
            hasher
        );
    }
}
