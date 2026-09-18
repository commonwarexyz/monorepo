// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { LibMerkleCommon } from "./LibMerkleCommon.sol";

/// @dev Reconstructs each shared ancestor once and authenticates Commonware's exact witness union.
library LibMerkleSparse {
    struct Proof {
        uint256 keys;
        uint256 digests;
        uint256 length;
        uint256 used;
        bool cd;
        bool belt;
        uint256 cursor;
        uint256 end;
        address hasher;
    }

    /// @dev Verify sparse raw elements with strictly increasing physical witness positions.
    /// Temporary sorted elements and peaks are cleared before restoring the entry memory pointer.
    /// `indices` and `elements` address `count` words. `positions` and `digests` address `proofCount` words.
    /// Callers supply valid array extents in the input location selected by `cd`.
    function verify(
        bytes32 root,
        uint256 leaves,
        uint256 indices,
        uint256 elements,
        uint256 count,
        uint256 positions,
        uint256 digests,
        uint256 proofCount,
        bool backward,
        uint256 inactive,
        bool cd,
        bool belt,
        address hasher
    ) internal view returns (bool valid) {
        return _verify(
            root,
            leaves,
            indices,
            elements,
            count,
            positions,
            digests,
            proofCount,
            backward,
            inactive,
            cd,
            belt,
            false,
            hasher
        );
    }

    /// @dev Verify positioned leaf digests in memory with indices and witnesses in calldata.
    /// Duplicate locations must carry equal digests. Every physical witness is authenticated.
    /// Input arrays remain unchanged. Temporary pairs and peaks are cleared before returning.
    function verifyPrehashed(
        bytes32 root,
        uint256 leaves,
        uint256[] calldata indices,
        bytes32[] memory elements,
        uint256[] calldata positions,
        bytes32[] calldata digests,
        uint256 inactive,
        bool belt,
        address hasher
    ) internal view returns (bool) {
        if (indices.length != elements.length || positions.length != digests.length) return false;
        uint256 indexData;
        uint256 elementData;
        uint256 positionData;
        uint256 digestData;
        assembly ("memory-safe") {
            indexData := indices.offset
            elementData := add(elements, 0x20)
            positionData := positions.offset
            digestData := digests.offset
        }
        return _verify(
            root,
            leaves,
            indexData,
            elementData,
            elements.length,
            positionData,
            digestData,
            digests.length,
            true,
            inactive,
            true,
            belt,
            true,
            hasher
        );
    }

    /// @dev Reconstruct using raw words in the selected location or positioned digests in memory.
    /// `prehashed` changes only element loading and hashing. Witness and index locations use `cd`.
    function _verify(
        bytes32 root,
        uint256 leaves,
        uint256 indices,
        uint256 elements,
        uint256 count,
        uint256 positions,
        uint256 digests,
        uint256 proofCount,
        bool backward,
        uint256 inactive,
        bool cd,
        bool belt,
        bool prehashed,
        address hasher
    ) private view returns (bool valid) {
        if (leaves > (uint256(1) << 62) + (belt ? 30 : 0)) return false;
        if (count == 0) {
            return leaves == 0 && inactive == 0 && proofCount == 0 && root == LibMerkleCommon.emptyRoot(hasher);
        }
        if (leaves == 0) return false;
        uint256 free;
        assembly ("memory-safe") { free := mload(0x40) }
        Proof memory p = Proof(positions, digests, proofCount, 0, cd, belt, 0, 0, hasher);
        uint256 pairs;
        assembly ("memory-safe") { pairs := mload(0x40) }
        uint256 peaks = pairs + count * 64;
        uint256 end = peaks + LibMerkleCommon.levels(leaves, belt) * 32;
        assembly ("memory-safe") { mstore(0x40, end) }
        (uint256 unique, bool ok) = _elements(p, leaves, indices, elements, count, pairs, prehashed);
        if (ok) {
            p.cursor = pairs;
            p.end = pairs + unique * 64;
            valid = _reconstruct(p, root, leaves, unique, peaks, backward, inactive);
        }
        assembly ("memory-safe") {
            for { let q := free } lt(q, end) { q := add(q, 0x20) } { mstore(q, 0) }
            mstore(0x40, free)
        }
    }

    /// @dev Sort selected elements and check duplicate values before hashing raw leaves.
    /// Positioned digests are loaded from memory and retained without another hash.
    function _elements(
        Proof memory p,
        uint256 n,
        uint256 indices,
        uint256 data,
        uint256 count,
        uint256 pairs,
        bool prehashed
    ) private view returns (uint256 unique, bool ok) {
        unchecked {
            if (p.belt) {
                for (uint256 i = 1; i < p.length; ++i) {
                    // forge-lint: disable-next-line(boolean-cst)
                    if (_load(p.keys + (i - 1) * 32, p.cd) >= _load(p.keys + i * 32, p.cd)) return (0, false);
                }
            }
            bool sorted = true;
            uint256 previous = 0;
            for (uint256 i; i < count; ++i) {
                uint256 index = _load(indices + i * 32, p.cd);
                // forge-lint: disable-next-line(boolean-cst)
                if (index >= n) return (0, false);
                if (index < previous) sorted = false;
                previous = index;
                uint256 element = _load(data + i * 32, p.cd && !prehashed);
                assembly ("memory-safe") {
                    let slot := add(pairs, shl(6, i))
                    mstore(slot, index)
                    mstore(add(slot, 0x20), element)
                }
            }
            if (!sorted) LibMerkleCommon.sortPairs(pairs, count);
            bytes32 previousElement = bytes32(0);
            for (uint256 i; i < count; ++i) {
                uint256 index;
                bytes32 element;
                assembly ("memory-safe") {
                    let slot := add(pairs, shl(6, i))
                    index := mload(slot)
                    element := mload(add(slot, 0x20))
                }
                if (unique != 0 && index == previous) {
                    // forge-lint: disable-next-line(boolean-cst)
                    if (element != previousElement) return (0, false);
                    continue;
                }
                uint256 position = 0;
                if (!prehashed) position = LibMerkleCommon.position(LibMerkleCommon.peak(index, 1, p.belt), 1, p.belt);
                assembly ("memory-safe") {
                    let slot := add(pairs, shl(6, unique))
                    mstore(slot, index)
                }
                bytes32 digest =
                    prehashed ? element : LibMerkleCommon.hash(bytes32(position), element, 0x18, 0x28, p.hasher);
                assembly ("memory-safe") {
                    mstore(add(add(pairs, shl(6, unique)), 0x20), digest)
                }
                previous = index;
                previousElement = element;
                ++unique;
            }
            // forge-lint: disable-next-line(boolean-cst)
            return (unique, true);
        }
    }

    /// @dev Each peak is reconstructed once. A selected peak is also a witness when another peak is selected.
    function _reconstruct(
        Proof memory p,
        bytes32 root,
        uint256 n,
        uint256 count,
        uint256 peaks,
        bool backward,
        uint256 inactive
    ) private view returns (bool) {
        unchecked {
            uint256 cursor = 0;
            uint256 peakCount = 0;
            for (uint256 level = LibMerkleCommon.levels(n, p.belt); level != 0;) {
                uint256 w = LibMerkleCommon.width(n, --level, p.belt);
                if (w == 0) continue;
                uint256 from = p.cursor;
                uint256 pos = LibMerkleCommon.peak(cursor, w, p.belt);
                (bytes32 digest, bool ok) = _subtree(p, pos, w, cursor);
                if (!ok) return false;
                uint256 selected = p.cursor - from;
                if (selected != 0 && selected != count * 64) {
                    (bytes32 witness, bool found) = _witness(p, LibMerkleCommon.position(pos, w, p.belt));
                    if (!found || witness != digest) return false;
                }
                assembly ("memory-safe") { mstore(add(peaks, shl(5, peakCount)), digest) }
                ++peakCount;
                cursor += w;
            }
            if (inactive > peakCount || p.used != p.length) return false;
            bytes32 acc = LibMerkleCommon.bag(peaks, peakCount, inactive, backward, p.hasher);
            return LibMerkleCommon.root(n, inactive, acc, p.hasher) == root;
        }
    }

    /// @dev A child is a required redundant witness exactly when its sibling contains selected leaves.
    /// Disjoint subtrees are consumed directly from the proof. Selected leaves use their computed hashes.
    /// `p.cursor` advances through sorted unique pairs and always points past every visited leaf.
    /// The left witness must be consumed before visiting the right child to preserve proof order.
    function _subtree(Proof memory p, uint256 pos, uint256 w, uint256 cursor)
        private
        view
        returns (bytes32 digest, bool ok)
    {
        unchecked {
            uint256 from = p.cursor;
            if (from == p.end) return _witness(p, LibMerkleCommon.position(pos, w, p.belt));
            uint256 index;
            assembly ("memory-safe") { index := mload(from) }
            if (index >= cursor + w) return _witness(p, LibMerkleCommon.position(pos, w, p.belt));
            if (w == 1) {
                assembly ("memory-safe") { digest := mload(add(from, 0x20)) }
                p.cursor = from + 64;
                // forge-lint: disable-next-line(boolean-cst)
                return (digest, true);
            }
            uint256 half = w >> 1;
            uint256 left = p.belt ? pos - (w == 2 ? 1 : 3 * (w >> 2)) : pos - w;
            uint256 right = p.belt ? left + half : pos - 1;
            (bytes32 a, bool valid) = _subtree(p, left, half, cursor);
            // forge-lint: disable-next-line(boolean-cst)
            if (!valid) return (0, false);
            bool both = p.cursor != from && p.cursor != p.end;
            if (both) {
                uint256 slot = p.cursor;
                assembly ("memory-safe") { index := mload(slot) }
                both = index < cursor + w;
            }
            if (both) {
                (bytes32 expected, bool found) = _witness(p, LibMerkleCommon.position(left, half, p.belt));
                // forge-lint: disable-next-line(boolean-cst)
                if (!found || expected != a) return (0, false);
            }
            (bytes32 b, bool validRight) = _subtree(p, right, half, cursor + half);
            // forge-lint: disable-next-line(boolean-cst)
            if (!validRight) return (0, false);
            if (both) {
                (bytes32 expected, bool found) = _witness(p, LibMerkleCommon.position(right, half, p.belt));
                // forge-lint: disable-next-line(boolean-cst)
                if (!found || expected != b) return (0, false);
            }
            uint256 position = LibMerkleCommon.position(pos, w, p.belt);
            address hasher = p.hasher;
            assembly ("memory-safe") {
                hasher := and(hasher, 0xffffffffffffffffffffffffffffffffffffffff)
                let free := mload(0x40)
                mstore(0, position)
                mstore(0x20, a)
                mstore(0x40, b)
                switch hasher
                case 0 { digest := keccak256(0x18, 0x48) }
                default {
                    let success := staticcall(gas(), hasher, 0x18, 0x48, 0, 0x20)
                    if iszero(and(success, eq(returndatasize(), 0x20))) {
                        mstore(0, 0x832d9905) // `LibMerkleCommon.HashFailed()`.
                        // Each external hash result must be checked before traversal continues.
                        // forge-lint: disable-next-line(require-revert-in-loop)
                        revert(0x1c, 4)
                    }
                    digest := mload(0)
                }
                mstore(0x40, free)
            }
            // forge-lint: disable-next-line(boolean-cst)
            return (digest, true);
        }
    }

    /// @dev Traversal visits each required node once, so a successful lookup counts one distinct witness.
    /// MMR postorder matches the proof order. MMB delayed parents require a position lookup.
    function _witness(Proof memory p, uint256 position) private pure returns (bytes32 digest, bool ok) {
        unchecked {
            uint256 lo = p.used;
            if (p.belt) {
                lo = 0;
                uint256 hi = p.length;
                while (lo < hi) {
                    uint256 mid = (lo + hi) >> 1;
                    if (_load(p.keys + mid * 32, p.cd) < position) lo = mid + 1;
                    else hi = mid;
                }
            }
            // forge-lint: disable-next-line(boolean-cst)
            if (lo == p.length || _load(p.keys + lo * 32, p.cd) != position) return (0, false);
            ++p.used;
            // forge-lint: disable-next-line(boolean-cst)
            return (bytes32(_load(p.digests + lo * 32, p.cd)), true);
        }
    }

    /// @dev Read an input word without copying its array.
    function _load(uint256 slot, bool cd) private pure returns (uint256 value) {
        assembly ("memory-safe") {
            switch cd
            case 0 { value := mload(slot) }
            default { value := calldataload(slot) }
        }
    }
}
