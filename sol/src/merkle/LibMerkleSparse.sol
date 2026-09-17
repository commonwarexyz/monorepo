// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import { Common as Merkle } from "./Common.sol";

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
        bool belt
    ) internal pure returns (bool valid) {
        if (leaves > (uint256(1) << 62) + (belt ? 30 : 0)) return false;
        if (count == 0) {
            return leaves == 0 && inactive == 0 && proofCount == 0 && root == Merkle.EMPTY_ROOT;
        }
        if (leaves == 0) return false;
        uint256 free;
        assembly ("memory-safe") { free := mload(0x40) }
        Proof memory p = Proof(positions, digests, proofCount, 0, cd, belt, 0, 0);
        uint256 pairs;
        assembly ("memory-safe") { pairs := mload(0x40) }
        uint256 peaks = pairs + count * 64;
        uint256 end = peaks + Merkle.levels(leaves, belt) * 32;
        assembly ("memory-safe") { mstore(0x40, end) }
        (uint256 unique, bool ok) = _elements(p, leaves, indices, elements, count, pairs);
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

    /// @dev Sort selected elements and hash each distinct leaf after checking duplicate values.
    function _elements(Proof memory p, uint256 n, uint256 indices, uint256 data, uint256 count, uint256 pairs)
        private
        pure
        returns (uint256 unique, bool ok)
    {
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
                uint256 element = _load(data + i * 32, p.cd);
                assembly ("memory-safe") {
                    let slot := add(pairs, shl(6, i))
                    mstore(slot, index)
                    mstore(add(slot, 0x20), element)
                }
            }
            if (!sorted) _sort(pairs, count);
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
                uint256 position = Merkle.position(Merkle.peak(index, 1, p.belt), 1, p.belt);
                assembly ("memory-safe") {
                    let slot := add(pairs, shl(6, unique))
                    mstore(slot, index)
                    mstore(0, position)
                    mstore(0x20, element)
                    mstore(add(slot, 0x20), keccak256(0x18, 0x28))
                }
                previous = index;
                previousElement = element;
                ++unique;
            }
            // forge-lint: disable-next-line(boolean-cst)
            return (unique, true);
        }
    }

    /// @dev Heapsort bounds work for arbitrary input order and moves each index with its value.
    function _sort(uint256 pairs, uint256 count) private pure {
        assembly ("memory-safe") {
            /// @dev Restore the max-heap below one displaced pair.
            function sift(base, slot, size) {
                let key := mload(add(base, shl(6, slot)))
                let value := mload(add(add(base, shl(6, slot)), 0x20))
                for { let child := add(shl(1, slot), 1) } lt(child, size) { child := add(shl(1, slot), 1) } {
                    if lt(add(child, 1), size) {
                        if lt(mload(add(base, shl(6, child))), mload(add(base, shl(6, add(child, 1))))) {
                            child := add(child, 1)
                        }
                    }
                    let source := add(base, shl(6, child))
                    if iszero(lt(key, mload(source))) { break }
                    let target := add(base, shl(6, slot))
                    mstore(target, mload(source))
                    mstore(add(target, 0x20), mload(add(source, 0x20)))
                    slot := child
                }
                let target := add(base, shl(6, slot))
                mstore(target, key)
                mstore(add(target, 0x20), value)
            }
            for { let i := shr(1, count) } i { } {
                i := sub(i, 1)
                sift(pairs, i, count)
            }
            for { let size := count } gt(size, 1) { } {
                size := sub(size, 1)
                let last := add(pairs, shl(6, size))
                let key := mload(pairs)
                let value := mload(add(pairs, 0x20))
                mstore(pairs, mload(last))
                mstore(add(pairs, 0x20), mload(add(last, 0x20)))
                mstore(last, key)
                mstore(add(last, 0x20), value)
                sift(pairs, 0, size)
            }
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
    ) private pure returns (bool) {
        unchecked {
            uint256 cursor = 0;
            uint256 peakCount = 0;
            for (uint256 level = Merkle.levels(n, p.belt); level != 0;) {
                uint256 w = Merkle.width(n, --level, p.belt);
                if (w == 0) continue;
                uint256 from = p.cursor;
                uint256 pos = Merkle.peak(cursor, w, p.belt);
                (bytes32 digest, bool ok) = _subtree(p, pos, w, cursor);
                if (!ok) return false;
                uint256 selected = p.cursor - from;
                if (selected != 0 && selected != count * 64) {
                    (bytes32 witness, bool found) = _witness(p, Merkle.position(pos, w, p.belt));
                    if (!found || witness != digest) return false;
                }
                assembly ("memory-safe") { mstore(add(peaks, shl(5, peakCount)), digest) }
                ++peakCount;
                cursor += w;
            }
            if (inactive > peakCount || p.used != p.length) return false;
            bytes32 acc = Merkle.bag(peaks, peakCount, inactive, backward);
            return Merkle.root(n, inactive, acc) == root;
        }
    }

    /// @dev A child is a required redundant witness exactly when its sibling contains selected leaves.
    /// Disjoint subtrees are consumed directly from the proof. Selected leaves use their computed hashes.
    /// `p.cursor` advances through sorted unique pairs and always points past every visited leaf.
    /// The left witness must be consumed before visiting the right child to preserve proof order.
    function _subtree(Proof memory p, uint256 pos, uint256 w, uint256 cursor)
        private
        pure
        returns (bytes32 digest, bool ok)
    {
        unchecked {
            uint256 from = p.cursor;
            if (from == p.end) return _witness(p, Merkle.position(pos, w, p.belt));
            uint256 index;
            assembly ("memory-safe") { index := mload(from) }
            if (index >= cursor + w) return _witness(p, Merkle.position(pos, w, p.belt));
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
                (bytes32 expected, bool found) = _witness(p, Merkle.position(left, half, p.belt));
                // forge-lint: disable-next-line(boolean-cst)
                if (!found || expected != a) return (0, false);
            }
            (bytes32 b, bool validRight) = _subtree(p, right, half, cursor + half);
            // forge-lint: disable-next-line(boolean-cst)
            if (!validRight) return (0, false);
            if (both) {
                (bytes32 expected, bool found) = _witness(p, Merkle.position(right, half, p.belt));
                // forge-lint: disable-next-line(boolean-cst)
                if (!found || expected != b) return (0, false);
            }
            uint256 position = Merkle.position(pos, w, p.belt);
            assembly ("memory-safe") {
                let free := mload(0x40)
                mstore(0, position)
                mstore(0x20, a)
                mstore(0x40, b)
                digest := keccak256(0x18, 0x48)
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
