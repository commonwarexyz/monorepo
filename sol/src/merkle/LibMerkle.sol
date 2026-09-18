// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { Common } from "./Common.sol";

/// @notice Commonware range proof reconstruction with a caller-selected hash.
/// @dev Positions and counts are big-endian `uint64` values. Raw elements are 32 bytes.
/// `H` uses native Keccak256 for `address(0)` or a trusted raw `STATICCALL` target.
/// Targets must return exactly 32 bytes or verification reverts with `Common.HashFailed()`.
/// The empty root is `H(bytes8(0))`.
/// Leaves hash `position || element` and parents hash `position || left || right`.
/// Peak pairs hash `left || right` without a position.
///
/// `ForwardFold` associates peaks from the left and `BackwardFold` from the right.
/// Inactive peaks form a prefix that is always folded forward before applying the
/// selected policy to the remaining peaks and that prefix accumulator.
/// The root hashes `leaves || foldedPeaks` when the inactive count is zero.
/// Otherwise it hashes `leaves || inactivePeaks || foldedPeaks`.
///
/// Range proofs contain an optional folded prefix, individual preceding peaks,
/// individual following peaks, an optional backward suffix, then left-first DFS siblings.
/// Forward proofs fold all preceding peaks into one digest. Backward proofs fold
/// only inactive preceding peaks and collapse active following peaks into one suffix.
/// Every supplied digest must be consumed.
library LibMerkle {
    enum Bagging {
        ForwardFold,
        BackwardFold
    }

    /// @dev Array addresses point at their first item. For single proofs, `data` holds
    /// the raw element or the positioned leaf digest when grafting is enabled.
    struct Proof {
        uint256 data;
        uint256 start;
        uint256 end;
        uint256 digests;
        uint256 digestCount;
    }

    /// @dev A prehashed leaf can bind additional data when its ancestor reaches `width` leaves.
    struct Graft {
        bytes32 prefix;
        uint256 width;
    }

    /// @dev Contiguous 256-bit activity chunks in memory. An empty array disables grafting.
    /// `start` identifies `chunks[0]`. `graftable` excludes pending and partial chunks.
    struct RangeGraft {
        bytes32[] chunks;
        uint256 start;
        uint256 graftable;
    }

    /// @dev Reconstruct a backward-folded root from positioned leaf digests in memory.
    /// Witness digests are read from calldata. Nonzero activity chunks prefix their
    /// width-256 ancestor digest. Zero chunks leave that digest unchanged.
    /// Callers authenticate the result and validate the snapshot's graftable boundary.
    /// Input arrays remain caller-owned. Temporary state is cleared before restoring memory.
    function reconstructPrehashed(
        uint256 leaves,
        uint256 start,
        bytes32[] memory elements,
        bytes32[] calldata proof,
        uint256 inactive,
        RangeGraft memory graft,
        bool mmb,
        address hasher
    ) internal view returns (bytes32 root, bool valid) {
        // forge-lint: disable-next-line(boolean-cst)
        if (leaves > (uint256(1) << 62) + (mmb ? 30 : 0)) return (0, false);
        uint256 count = elements.length;
        // forge-lint: disable-next-line(boolean-cst)
        if (start > leaves || count > leaves - start) return (0, false);
        if (count == 0) {
            if (leaves != 0 || start != 0 || proof.length != 0 || inactive != 0 || graft.chunks.length != 0) {
                // forge-lint: disable-next-line(boolean-cst)
                return (0, false);
            }
            // forge-lint: disable-next-line(boolean-cst)
            return (Common.emptyRoot(hasher), true);
        }
        uint256 graftData = 0;
        if (graft.chunks.length != 0) {
            if (
                graft.start != (start >> 8) || graft.graftable > (leaves >> 8)
                    || graft.chunks.length != ((start + count - 1) >> 8) - (start >> 8) + 1
            ) {
                // forge-lint: disable-next-line(boolean-cst)
                return (0, false);
            }
            assembly ("memory-safe") { graftData := graft }
        }
        uint256 free;
        uint256 data;
        uint256 proofData;
        assembly ("memory-safe") {
            free := mload(0x40)
            data := add(elements, 0x20)
            proofData := proof.offset
        }
        Proof memory p = Proof(data, start, start + count, proofData, proof.length);
        uint256 scratch;
        assembly ("memory-safe") { scratch := mload(0x40) }
        (root, valid) = _backwardRoot(leaves, p, scratch, inactive, false, true, mmb, 0, true, graftData, hasher);
        _clear(free, scratch + Common.levels(leaves, mmb) * 32);
        assembly ("memory-safe") { mstore(0x40, free) }
    }

    /// @dev Reconstruct a backward-folded root from a positioned leaf digest in the selected tree family.
    /// `graft.prefix` is hashed before the ancestor digest at `graft.width` leaves.
    /// Width is zero to disable ancestor grafting or a power of two of at least two.
    /// The leaf is already positioned and hashed even when the width is zero.
    /// Callers authenticate the returned root.
    function reconstructGrafted(
        uint256 leaves,
        uint256 index,
        bytes32 leaf,
        bytes32[] calldata proof,
        uint256 inactive,
        Graft memory graft,
        bool mmb,
        address hasher
    ) internal view returns (bytes32 root, bool valid) {
        // forge-lint: disable-next-line(boolean-cst)
        if (leaves > (uint256(1) << 62) + (mmb ? 30 : 0) || index >= leaves) return (0, false);
        uint256 free;
        uint256 proofData;
        uint256 graftData;
        assembly ("memory-safe") {
            free := mload(0x40)
            proofData := proof.offset
            graftData := graft
        }
        Proof memory p = Proof(uint256(leaf), index, index + 1, proofData, proof.length);
        uint256 scratch;
        assembly ("memory-safe") { scratch := mload(0x40) }
        (root, valid) = _backwardRoot(leaves, p, scratch, inactive, true, true, mmb, graftData, false, 0, hasher);
        _clear(free, scratch + Common.levels(leaves, mmb) * 32);
        assembly ("memory-safe") { mstore(0x40, free) }
    }

    /// @dev Verify with `ForwardFold` and zero inactive peaks using the selected input location.
    /// Array addresses must cover their declared counts in that location.
    /// `data` is a raw value and `count` must be one when `single` is true.
    function verify(
        bytes32 root,
        uint256 leaves,
        uint256 start,
        uint256 data,
        uint256 count,
        uint256 proof,
        uint256 proofCount,
        bool single,
        bool fromCalldata,
        bool mmb,
        address hasher
    ) internal view returns (bool) {
        return verify(
            root,
            leaves,
            start,
            data,
            count,
            proof,
            proofCount,
            single,
            fromCalldata,
            mmb,
            Bagging.ForwardFold,
            0,
            hasher
        );
    }

    /// @dev The caller owns all input memory. Temporary proof state, peak digests and
    /// DFS frames are cleared and the entry free memory pointer is restored.
    /// `proof` addresses `proofCount` digests in the selected input location.
    /// When `single` is true, `data` is a raw value and `count` must be one.
    /// Otherwise `data` addresses `count` elements. Callers supply valid array extents.
    function verify(
        bytes32 root,
        uint256 leaves,
        uint256 start,
        uint256 data,
        uint256 count,
        uint256 proof,
        uint256 proofCount,
        bool single,
        bool fromCalldata,
        bool mmb,
        Bagging bagging,
        uint256 inactivePeaks,
        address hasher
    ) internal view returns (bool valid) {
        if (leaves > (uint256(1) << 62) + (mmb ? 30 : 0)) return false;
        if (start > leaves || count > leaves - start) return false;
        if (count == 0) {
            return
                leaves == 0 && start == 0 && proofCount == 0 && inactivePeaks == 0 && root == Common.emptyRoot(hasher);
        }
        if (mmb ? leaves <= 2 : leaves & (leaves - 1) == 0) {
            return _onePeak(
                root, leaves, start, data, count, proof, proofCount, single, fromCalldata, mmb, inactivePeaks, hasher
            );
        }
        if (bagging == Bagging.ForwardFold) {
            return _forward(
                root, leaves, start, data, count, proof, proofCount, single, fromCalldata, mmb, inactivePeaks, hasher
            );
        }
        uint256 free;
        assembly ("memory-safe") { free := mload(0x40) }
        Proof memory p = Proof(data, start, start + count, proof, proofCount);
        uint256 scratch;
        assembly ("memory-safe") { scratch := mload(0x40) }
        bytes32 reconstructed;
        (reconstructed, valid) =
            _backwardRoot(leaves, p, scratch, inactivePeaks, single, fromCalldata, mmb, 0, false, 0, hasher);
        valid = valid && reconstructed == root;
        _clear(free, scratch + Common.levels(leaves, mmb) * 32);
        assembly ("memory-safe") { mstore(0x40, free) }
    }

    /// @dev A single peak requires only subtree siblings and has the same root under either fold policy.
    function _onePeak(
        bytes32 root,
        uint256 leaves,
        uint256 start,
        uint256 data,
        uint256 count,
        uint256 proof,
        uint256 proofCount,
        bool single,
        bool cd,
        bool belt,
        uint256 inactive,
        address hasher
    ) private view returns (bool) {
        unchecked {
            if (inactive > 1) return false;
            uint256 position = belt ? leaves - 1 : 2 * leaves - 2;
            uint256 end = proof + proofCount * 32;
            bytes32 digest;
            uint256 next;
            bool ok;
            if (single) {
                (digest, next, ok) = _singleton(data, start, position, leaves, proof, end, cd, belt, 0, hasher);
            } else {
                uint256 base;
                assembly ("memory-safe") { base := mload(0x40) }
                (digest, next, ok) = _subtree(
                    data, start, start + count, position, leaves, 0, proof, end, base, cd, belt, false, 0, hasher
                );
            }
            return ok && next == end && Common.root(leaves, inactive, digest, hasher) == root;
        }
    }

    /// @dev Forward proofs fold every peak before the range into one leading digest.
    /// This driver needs no allocated proof state or peak buffer.
    function _forward(
        bytes32 root,
        uint256 n,
        uint256 start,
        uint256 data,
        uint256 count,
        uint256 proof,
        uint256 proofCount,
        bool single,
        bool cd,
        bool belt,
        uint256 inactive,
        address hasher
    ) private view returns (bool) {
        unchecked {
            uint256 end = start + count;
            (uint256 prefix, uint256 after_, uint256 levels, uint256 peaks) = _forwardOffsets(n, start, end, belt);
            if (inactive > peaks) return false;
            if (prefix + after_ > proofCount) return false;
            uint256 suffix = proof + prefix * 32;
            uint256 q = suffix + after_ * 32;
            uint256 qEnd = proof + proofCount * 32;
            bytes32 acc;
            bool have = prefix != 0;
            if (have) acc = _load(proof, cd);
            uint256 base;
            assembly ("memory-safe") { base := mload(0x40) }
            uint256 cursor = 0;
            for (uint256 level = levels; level != 0;) {
                --level;
                uint256 w = belt ? uint256(1) << (level + (((n + 1) >> level) & 1)) : n & (uint256(1) << level);
                if (w == 0) continue;
                uint256 next = cursor + w;
                if (next > start) {
                    bytes32 d;
                    if (cursor >= end) {
                        d = _load(suffix, cd);
                        suffix += 32;
                    } else {
                        bool ok;
                        uint256 position;
                        if (belt) {
                            position = cursor + w - 1 + (w > 1 ? (w >> 1) - 1 : 0);
                        } else {
                            uint256 ones = 0;
                            for (uint256 x = cursor; x != 0; x &= x - 1) {
                                ++ones;
                            }
                            position = 2 * cursor - ones + 2 * w - 2;
                        }
                        if (single) {
                            (d, q, ok) = _singleton(data, start - cursor, position, w, q, qEnd, cd, belt, 0, hasher);
                        } else {
                            (d, q, ok) = _subtree(
                                data, start, end, position, w, cursor, q, qEnd, base, cd, belt, false, 0, hasher
                            );
                        }
                        if (!ok) return false;
                    }
                    // `have` is true only after `acc` has been assigned a peak digest.
                    // forge-lint: disable-next-line(uninitialized-local)
                    acc = have ? Common.fold(acc, d, hasher) : d;
                    have = true;
                }
                cursor = next;
            }
            return q == qEnd && Common.root(n, inactive, acc, hasher) == root;
        }
    }

    /// @dev Locate the sibling section and count peaks before reading any proof digest.
    function _forwardOffsets(uint256 n, uint256 start, uint256 end, bool belt)
        private
        pure
        returns (uint256 prefix, uint256 after_, uint256 levels, uint256 peaks)
    {
        unchecked {
            levels = Common.levels(n, belt);
            if (belt) {
                peaks = levels;
                uint256 first = uint256(1) << (levels - 1 + (((n + 1) >> (levels - 1)) & 1));
                prefix = start >= first ? 1 : 0;
                // The last k peaks span `(2^k - 1) + ((n + 1) & (2^k - 1))` leaves.
                // For `k = log2(remaining + 1)`, the suffix count is either `k` or `k - 1`.
                uint256 remaining = n - end;
                after_ = Common.log2(remaining + 1);
                uint256 mask = (uint256(1) << after_) - 1;
                if (mask + ((n + 1) & mask) > remaining) --after_;
                return (prefix, after_, levels, peaks);
            }
            uint256 cursor = 0;
            for (uint256 i = levels; i != 0;) {
                --i;
                uint256 w = n & (uint256(1) << i);
                if (w == 0) continue;
                if (cursor + w <= start) prefix = 1;
                if (cursor >= end) ++after_;
                cursor += w;
                ++peaks;
            }
        }
    }

    /// @dev Range layout is folded prefix, active prefix peaks, individual after-peaks,
    /// optional backward suffix and finally left-first DFS siblings.
    /// Peak digests occupy temporary memory above the free memory pointer.
    /// All called helpers must remain allocation-free while those digests are live.
    /// Separate subtree call sites keep leaf and graft modes constant inside traversal loops.
    function _backwardRoot(
        uint256 n,
        Proof memory p,
        uint256 scratch,
        uint256 inactive,
        bool single,
        bool cd,
        bool belt,
        uint256 graft,
        bool prehashed,
        uint256 rangeGraft,
        address hasher
    ) private view returns (bytes32 root, bool valid) {
        unchecked {
            uint256 offsets = _backwardOffsets(n, p.start, p.end, inactive, belt);
            // forge-lint: disable-next-line(boolean-cst)
            if (offsets == type(uint256).max) return (0, false);
            uint256 prefix = offsets & 0xff;
            uint256 before = (offsets >> 8) & 0xff;
            uint256 after_ = (offsets >> 16) & 0xff;
            uint256 suffixCount = (offsets >> 24) & 0xff;
            // forge-lint: disable-next-line(boolean-cst)
            if (prefix + before + after_ + suffixCount > p.digestCount) return (0, false);
            uint256 front = p.digests + prefix * 32;
            uint256 suffix = front + before * 32;
            uint256 q = suffix + (after_ + suffixCount) * 32;
            bytes32 acc;
            bool have = prefix != 0;
            if (have) acc = _load(p.digests, cd);
            uint256 top = scratch;
            uint256 levels = Common.levels(n, belt);
            uint256 base = scratch + levels * 32;
            uint256 cursor = 0;
            uint256 peakIndex = 0;
            bool suffixTaken = false;
            for (uint256 level = levels; level != 0;) {
                --level;
                uint256 w = belt ? uint256(1) << (level + (((n + 1) >> level) & 1)) : n & (uint256(1) << level);
                if (w == 0) continue;
                uint256 next = cursor + w;
                if ((next > p.start || (peakIndex >= inactive)) && !suffixTaken) {
                    bytes32 d;
                    if (next <= p.start) {
                        d = _load(front, cd);
                        front += 32;
                    } else if (cursor >= p.end) {
                        d = _load(suffix, cd);
                        suffix += 32;
                        suffixTaken = peakIndex >= inactive;
                    } else {
                        bool ok;
                        uint256 position;
                        if (belt) {
                            position = cursor + w - 1 + (w > 1 ? (w >> 1) - 1 : 0);
                        } else {
                            uint256 ones = 0;
                            for (uint256 x = cursor; x != 0; x &= x - 1) {
                                ++ones;
                            }
                            position = 2 * cursor - ones + 2 * w - 2;
                        }
                        if (single) {
                            (d, q, ok) = _singleton(
                                p.data,
                                p.start - cursor,
                                position,
                                w,
                                q,
                                p.digests + p.digestCount * 32,
                                cd,
                                belt,
                                graft,
                                hasher
                            );
                        } else if (prehashed) {
                            (d, q, ok) = _subtree(
                                p.data,
                                p.start,
                                p.end,
                                position,
                                w,
                                cursor,
                                q,
                                p.digests + p.digestCount * 32,
                                base,
                                cd,
                                belt,
                                true,
                                rangeGraft,
                                hasher
                            );
                        } else {
                            (d, q, ok) = _subtree(
                                p.data,
                                p.start,
                                p.end,
                                position,
                                w,
                                cursor,
                                q,
                                p.digests + p.digestCount * 32,
                                base,
                                cd,
                                belt,
                                false,
                                0,
                                hasher
                            );
                        }
                        // forge-lint: disable-next-line(boolean-cst)
                        if (!ok) return (0, false);
                    }
                    if (peakIndex >= inactive) {
                        if (have) {
                            // `have` is true only after `acc` has been assigned a peak digest.
                            // forge-lint: disable-next-line(uninitialized-local)
                            assembly ("memory-safe") { mstore(top, acc) }
                            top += 32;
                            have = false;
                        }
                        assembly ("memory-safe") { mstore(top, d) }
                        top += 32;
                    } else {
                        acc = have ? Common.fold(acc, d, hasher) : d;
                        have = true;
                    }
                }
                cursor = next;
                ++peakIndex;
            }
            // forge-lint: disable-next-line(boolean-cst)
            if (q != p.digests + p.digestCount * 32) return (0, false);
            if (top != scratch) acc = Common.bag(scratch, (top - scratch) / 32, 0, true, hasher);
            // forge-lint: disable-next-line(boolean-cst)
            return (Common.root(n, inactive, acc, hasher), true);
        }
    }

    /// @dev Counts fit in bytes because the tree has at most 62 peaks.
    function _backwardOffsets(uint256 n, uint256 start, uint256 end, uint256 inactive, bool belt)
        private
        pure
        returns (uint256 offsets)
    {
        unchecked {
            uint256 cursor = 0;
            uint256 index = 0;
            uint256 prefix = 0;
            uint256 before = 0;
            uint256 after_ = 0;
            uint256 suffix = 0;
            for (uint256 level = Common.levels(n, belt); level != 0;) {
                --level;
                uint256 w = belt ? uint256(1) << (level + (((n + 1) >> level) & 1)) : n & (uint256(1) << level);
                if (w == 0) continue;
                if (cursor + w <= start) {
                    if (index < inactive) prefix = 1;
                    else ++before;
                }
                if (cursor >= end) {
                    if (index >= inactive) suffix = 1;
                    else ++after_;
                }
                cursor += w;
                ++index;
            }
            if (inactive > index) return type(uint256).max;
            return prefix | (before << 8) | (after_ << 16) | (suffix << 24);
        }
    }

    /// @dev Read one word from the selected input location.
    function _load(uint256 address_, bool cd) private pure returns (bytes32 d) {
        assembly ("memory-safe") {
            switch cd
            case 0 { d := mload(address_) }
            default { d := calldataload(address_) }
        }
    }

    /// @dev Clear temporary words before their memory is reused.
    function _clear(uint256 base, uint256 end) private pure {
        assembly ("memory-safe") { for { } lt(base, end) { base := add(base, 0x20) } { mstore(base, 0) } }
    }

    /// @dev Reconstruct a singleton using the selected input and tree family siblings without DFS frames.
    /// A nonzero `graft` points to a `Graft` and makes `element` a positioned leaf digest.
    function _singleton(
        uint256 element,
        uint256 index,
        uint256 p,
        uint256 width,
        uint256 q,
        uint256 qEnd,
        bool cd,
        bool belt,
        uint256 graft,
        address hasher
    ) private view returns (bytes32 d, uint256 nextQ, bool ok) {
        assembly ("memory-safe") {
            hasher := and(hasher, 0xffffffffffffffffffffffffffffffffffffffff)
            /// @dev Hash raw bytes through an external target and require exactly one digest.
            function externalHash(pointer, length, target) -> digest {
                let success := staticcall(gas(), target, pointer, length, 0, 0x20)
                if iszero(and(success, eq(returndatasize(), 0x20))) {
                    mstore(0, 0x832d9905) // `Common.HashFailed()`.
                    // Each external hash result must be checked before traversal continues.
                    // forge-lint: disable-next-line(require-revert-in-loop)
                    revert(0x1c, 4)
                }
                digest := mload(0)
            }
            /// @dev Return the highest set bit of a positive `uint64` using `Common.log2`'s lookup.
            function ilog2(x) -> r {
                r := shl(5, gt(x, 0xffffffff))
                r := or(r, shl(4, gt(shr(r, x), 0xffff)))
                r := or(r, shl(3, gt(shr(r, x), 0xff)))
                r := or(
                    r,
                    byte(
                        // The normalized input selects a bit window from the lookup constant.
                        // forge-lint: disable-next-line(incorrect-shift)
                        and(0x1f, shr(shr(r, x), 0x8421084210842108cc6318c6db6d54be)),
                        0x0706060506020504060203020504030106050205030304010505030400000000
                    )
                )
            }
            /// @dev Read a digest from the selected input location.
            function load(a, cd_) -> v {
                switch cd_
                case 0 { v := mload(a) }
                default { v := calldataload(a) }
            }
            let free := mload(0x40)
            let depth := ilog2(width)
            let leftCount := 0
            nextQ := add(q, shl(5, depth))
            ok := iszero(gt(nextQ, qEnd))
            if ok {
                for { let x := index } x { x := and(x, sub(x, 1)) } { leftCount := add(leftCount, 1) }
                let left := add(q, shl(5, leftCount))
                let right := left
                // A peak root and the leaf offset determine the leaf position directly.
                switch belt
                case 0 { p := sub(add(sub(add(p, 2), shl(1, width)), shl(1, index)), leftCount) }
                default {
                    if gt(width, 1) { p := add(sub(add(p, 2), add(width, shr(1, width))), index) }
                }
                let pos := 0
                let graftStep := 0
                switch graft
                case 0 {
                    pos := p
                    if belt { pos := sub(shl(1, p), ilog2(add(p, 1))) }
                    mstore(0, pos)
                    mstore(0x20, element)
                    switch hasher
                    case 0 { d := keccak256(0x18, 0x28) }
                    default { d := externalHash(0x18, 0x28, hasher) }
                }
                default {
                    d := element
                    graftStep := shr(1, mload(add(graft, 0x20)))
                }
                for { let w := 1 } lt(w, width) { w := shl(1, w) } {
                    let sibling := 0
                    switch iszero(and(index, w))
                    case 1 {
                        sibling := load(right, cd)
                        right := add(right, 0x20)
                        switch belt
                        case 0 { p := add(p, shl(1, w)) }
                        default { p := add(p, add(w, shr(1, w))) }
                        mstore(0x20, d)
                        mstore(0x40, sibling)
                    }
                    default {
                        left := sub(left, 0x20)
                        sibling := load(left, cd)
                        switch belt
                        case 0 { p := add(p, 1) }
                        default { p := add(p, shr(1, w)) }
                        mstore(0x20, sibling)
                        mstore(0x40, d)
                    }
                    pos := p
                    if belt { pos := add(sub(shl(1, p), ilog2(add(p, 1))), 1) }
                    mstore(0, pos)
                    switch hasher
                    case 0 { d := keccak256(0x18, 0x48) }
                    default { d := externalHash(0x18, 0x48, hasher) }
                    // Constant zero removes grafting from ordinary proof loops.
                    if graft {
                        if eq(w, graftStep) {
                            mstore(0, mload(graft))
                            mstore(0x20, d)
                            switch hasher
                            case 0 { d := keccak256(0, 0x40) }
                            default { d := externalHash(0, 0x40, hasher) }
                        }
                    }
                }
            }
            mstore(0x40, free)
        }
    }

    /// @dev Reconstruct a MMR range from memory with one-word DFS frames.
    /// Every used frame is cleared and the free memory pointer is restored on either outcome.
    function _memoryMMR(
        uint256 data,
        uint256 start,
        uint256 end,
        uint256 p,
        uint256 width,
        uint256 cursor,
        uint256 q,
        uint256 qEnd,
        uint256 base,
        address hasher
    ) private view returns (bytes32 d, uint256 nextQ, bool ok) {
        assembly ("memory-safe") {
            hasher := and(hasher, 0xffffffffffffffffffffffffffffffffffffffff)
            /// @dev Hash raw bytes through an external target and require exactly one digest.
            function externalHash(pointer, length, target) -> digest {
                let success := staticcall(gas(), target, pointer, length, 0, 0x20)
                if iszero(and(success, eq(returndatasize(), 0x20))) {
                    mstore(0, 0x832d9905) // `Common.HashFailed()`.
                    // Each external hash result must be checked before traversal continues.
                    // forge-lint: disable-next-line(require-revert-in-loop)
                    revert(0x1c, 4)
                }
                digest := mload(0)
            }
            let free := mload(0x40)
            let top := base
            ok := 1
            for { } 1 { } {
                switch or(iszero(gt(add(cursor, width), start)), iszero(lt(cursor, end)))
                case 1 {
                    if iszero(lt(q, qEnd)) {
                        ok := 0
                        break
                    }
                    d := mload(q)
                    q := add(q, 0x20)
                    cursor := add(cursor, width)
                }
                default {
                    switch width
                    case 1 {
                        mstore(0, p)
                        mstore(0x20, mload(add(data, shl(5, sub(cursor, start)))))
                        switch hasher
                        case 0 { d := keccak256(0x18, 0x28) }
                        default { d := externalHash(0x18, 0x28, hasher) }
                        cursor := add(cursor, 1)
                    }
                    default {
                        top := add(top, 0x20)
                        p := sub(p, width)
                        width := shr(1, width)
                        continue
                    }
                }
                for { } gt(top, base) { } {
                    let frame := sub(top, 0x20)
                    if and(cursor, width) {
                        mstore(frame, d)
                        p := add(p, sub(shl(1, width), 1))
                        break
                    }
                    p := add(p, 1)
                    width := shl(1, width)
                    mstore(0, p)
                    mstore(0x20, mload(frame))
                    mstore(0x40, d)
                    switch hasher
                    case 0 { d := keccak256(0x18, 0x48) }
                    default { d := externalHash(0x18, 0x48, hasher) }
                    mstore(frame, 0)
                    top := frame
                }
                if eq(top, base) { break }
            }
            for { } lt(base, top) { base := add(base, 0x20) } { mstore(base, 0) }
            mstore(0x40, free)
            nextQ := q
        }
    }

    /// @dev Reconstruct a range using the selected input and tree family with one-word DFS frames.
    /// `prehashed` selects positioned leaf digests in memory. Witnesses retain the `cd` location.
    /// A nonzero `graft` points to a validated `RangeGraft` whose chunks cover the range.
    /// Every used frame is cleared and the free memory pointer is restored on either outcome.
    function _subtree(
        uint256 data,
        uint256 start,
        uint256 end,
        uint256 p,
        uint256 width,
        uint256 cursor,
        uint256 q,
        uint256 qEnd,
        uint256 base,
        bool cd,
        bool belt,
        bool prehashed,
        uint256 graft,
        address hasher
    ) private view returns (bytes32 d, uint256 nextQ, bool ok) {
        if (!prehashed && !cd && !belt) {
            return _memoryMMR(data, start, end, p, width, cursor, q, qEnd, base, hasher);
        }
        assembly ("memory-safe") {
            hasher := and(hasher, 0xffffffffffffffffffffffffffffffffffffffff)
            /// @dev Hash raw bytes through an external target and require exactly one digest.
            function externalHash(pointer, length, target) -> digest {
                let success := staticcall(gas(), target, pointer, length, 0, 0x20)
                if iszero(and(success, eq(returndatasize(), 0x20))) {
                    mstore(0, 0x832d9905) // `Common.HashFailed()`.
                    // Each external hash result must be checked before traversal continues.
                    // forge-lint: disable-next-line(require-revert-in-loop)
                    revert(0x1c, 4)
                }
                digest := mload(0)
            }
            /// @dev Return the highest set bit of a positive `uint64` using `Common.log2`'s lookup.
            function ilog2(x) -> r {
                r := shl(5, gt(x, 0xffffffff))
                r := or(r, shl(4, gt(shr(r, x), 0xffff)))
                r := or(r, shl(3, gt(shr(r, x), 0xff)))
                r := or(
                    r,
                    byte(
                        // The normalized input selects a bit window from the lookup constant.
                        // forge-lint: disable-next-line(incorrect-shift)
                        and(0x1f, shr(shr(r, x), 0x8421084210842108cc6318c6db6d54be)),
                        0x0706060506020504060203020504030106050205030304010505030400000000
                    )
                )
            }
            /// @dev Read a digest from the selected input location.
            function load(a, cd_) -> v {
                switch cd_
                case 0 { v := mload(a) }
                default { v := calldataload(a) }
            }
            let free := mload(0x40)
            let top := base
            ok := 1
            for { } 1 { } {
                switch or(iszero(gt(add(cursor, width), start)), iszero(lt(cursor, end)))
                case 1 {
                    if iszero(lt(q, qEnd)) {
                        ok := 0
                        break
                    }
                    d := load(q, cd)
                    q := add(q, 0x20)
                    cursor := add(cursor, width)
                }
                default {
                    switch width
                    case 1 {
                        let slot := add(data, shl(5, sub(cursor, start)))
                        switch prehashed
                        case 0 {
                            let pos := p
                            if belt { pos := sub(shl(1, p), ilog2(add(p, 1))) }
                            mstore(0, pos)
                            mstore(0x20, load(slot, cd))
                            switch hasher
                            case 0 { d := keccak256(0x18, 0x28) }
                            default { d := externalHash(0x18, 0x28, hasher) }
                        }
                        default { d := mload(slot) }
                        cursor := add(cursor, 1)
                    }
                    default {
                        top := add(top, 0x20)
                        switch belt
                        case 0 { p := sub(p, width) }
                        default {
                            switch width
                            case 2 { p := sub(p, 1) }
                            default { p := sub(p, mul(3, shr(2, width))) }
                        }
                        width := shr(1, width)
                        continue
                    }
                }
                for { } gt(top, base) { } {
                    let frame := sub(top, 0x20)
                    if and(cursor, width) {
                        mstore(frame, d)
                        switch belt
                        case 0 { p := add(p, sub(shl(1, width), 1)) }
                        default { p := add(p, width) }
                        break
                    }
                    switch belt
                    case 0 { p := add(p, 1) }
                    default { p := add(p, shr(1, width)) }
                    width := shl(1, width)
                    let pos := p
                    if belt { pos := add(sub(shl(1, p), ilog2(add(p, 1))), 1) }
                    mstore(0, pos)
                    mstore(0x20, mload(frame))
                    mstore(0x40, d)
                    switch hasher
                    case 0 { d := keccak256(0x18, 0x48) }
                    default { d := externalHash(0x18, 0x48, hasher) }
                    if graft {
                        if eq(width, 256) {
                            let chunk := shr(8, sub(cursor, width))
                            if lt(chunk, mload(add(graft, 0x40))) {
                                let chunks := mload(graft)
                                let local := sub(chunk, mload(add(graft, 0x20)))
                                let prefix := mload(add(add(chunks, 0x20), shl(5, local)))
                                if prefix {
                                    mstore(0, prefix)
                                    mstore(0x20, d)
                                    switch hasher
                                    case 0 { d := keccak256(0, 0x40) }
                                    default { d := externalHash(0, 0x40, hasher) }
                                }
                            }
                        }
                    }
                    mstore(frame, 0)
                    top := frame
                }
                if eq(top, base) { break }
            }
            for { } lt(base, top) { base := add(base, 0x20) } { mstore(base, 0) }
            mstore(0x40, free)
            nextQ := q
        }
    }
}
