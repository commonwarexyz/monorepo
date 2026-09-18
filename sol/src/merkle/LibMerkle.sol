// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

/// @notice Commonware Merkle proof reconstruction with a caller-selected hash.
/// @dev Positions and counts are big-endian `uint64` values. Raw elements are 32 bytes.
/// `H` uses native Keccak256 for `address(0)` or a trusted raw `STATICCALL` target.
/// Targets must return exactly 32 bytes or verification reverts with `LibMerkle.HashFailed()`.
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
///
/// Multiproofs pair selected leaf indices with elements and strictly increasing
/// physical witness positions with digests. They authenticate the exact union of
/// single-leaf witnesses, including those derivable from the selected elements.
/// Each shared ancestor is reconstructed once.
library LibMerkle {
    /// @dev The selected hash target failed or returned a value other than 32 bytes.
    error HashFailed();

    /// @dev The empty tree commits a zero `uint64` leaf count.
    bytes32 private constant EMPTY_ROOT = keccak256(hex"0000000000000000");

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

    /// @dev Witness array addresses use the input location selected by `cd`.
    /// `cursor` and `end` bound sorted unique `(index, digest)` pairs in temporary memory.
    struct MultiProof {
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

    /// @dev `prefix` addresses `width / 8` bitmap bytes in calldata. A zero width disables grafting.
    /// Callers validate the extent and power-of-two width between 8 and `2^62`.
    struct Graft {
        uint256 prefix;
        uint256 width;
    }

    /// @dev `chunks` addresses packed bitmap bytes in calldata. A zero width disables grafting.
    /// Callers validate the extent, touched chunk count, and power-of-two width between 8 and `2^62`.
    /// `start` identifies the first chunk. `graftable` excludes pending and partial chunks.
    struct RangeGraft {
        uint256 chunks;
        uint256 start;
        uint256 graftable;
        uint256 width;
    }

    /// @dev Reconstruct a backward-folded root from positioned leaf digests in memory.
    /// Witness digests are read from calldata. Nonzero activity chunks prefix their
    /// chunk-width ancestor digest. Zero chunks leave that digest unchanged.
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
            if (leaves != 0 || start != 0 || proof.length != 0 || inactive != 0 || graft.width != 0) {
                // forge-lint: disable-next-line(boolean-cst)
                return (0, false);
            }
            // forge-lint: disable-next-line(boolean-cst)
            return (_emptyRoot(hasher), true);
        }
        uint256 graftData = 0;
        if (graft.width != 0) {
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
        _clear(free, scratch + _levels(leaves, mmb) * 32);
        assembly ("memory-safe") { mstore(0x40, free) }
    }

    /// @dev Reconstruct a backward-folded root from a positioned leaf digest in the selected tree family.
    /// Calldata bytes at `graft.prefix` are hashed before the ancestor at `graft.width` leaves.
    /// Width is zero to disable ancestor grafting, or a power of two between 8 and `2^62`.
    /// The caller validates exactly `width / 8` available bitmap bytes when grafting is enabled.
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
        _clear(free, scratch + _levels(leaves, mmb) * 32);
        assembly ("memory-safe") { mstore(0x40, free) }
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
            return leaves == 0 && start == 0 && proofCount == 0 && inactivePeaks == 0 && root == _emptyRoot(hasher);
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
        _clear(free, scratch + _levels(leaves, mmb) * 32);
        assembly ("memory-safe") { mstore(0x40, free) }
    }

    /// @dev Verify sparse raw elements with strictly increasing physical witness positions.
    /// Temporary sorted elements and peaks are cleared before restoring the entry memory pointer.
    /// `indices` and `elements` address `count` words. `positions` and `digests` address `proofCount` words.
    /// Callers supply valid array extents in the input location selected by `cd`.
    function verifyMulti(
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
        return _verifyMulti(
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
    function verifyMultiPrehashed(
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
        return _verifyMulti(
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
            uint256 nodePosition = belt ? leaves - 1 : 2 * leaves - 2;
            uint256 end = proof + proofCount * 32;
            bytes32 digest;
            uint256 next;
            bool ok;
            if (single) {
                (digest, next, ok) = _singleton(data, start, nodePosition, leaves, proof, end, cd, belt, 0, 0, hasher);
            } else {
                uint256 base;
                assembly ("memory-safe") { base := mload(0x40) }
                (digest, next, ok) = _subtree(
                    data, start, start + count, nodePosition, leaves, 0, proof, end, base, cd, belt, false, 0, hasher
                );
            }
            return ok && next == end && _root(leaves, inactive, digest, hasher) == root;
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
            if (have) acc = bytes32(_load(proof, cd));
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
                        d = bytes32(_load(suffix, cd));
                        suffix += 32;
                    } else {
                        bool ok;
                        uint256 nodePosition;
                        if (belt) {
                            nodePosition = cursor + w - 1 + (w > 1 ? (w >> 1) - 1 : 0);
                        } else {
                            uint256 ones = 0;
                            for (uint256 x = cursor; x != 0; x &= x - 1) {
                                ++ones;
                            }
                            nodePosition = 2 * cursor - ones + 2 * w - 2;
                        }
                        if (single) {
                            (d, q, ok) =
                                _singleton(data, start - cursor, nodePosition, w, q, qEnd, cd, belt, 0, 0, hasher);
                        } else {
                            (d, q, ok) = _subtree(
                                data, start, end, nodePosition, w, cursor, q, qEnd, base, cd, belt, false, 0, hasher
                            );
                        }
                        if (!ok) return false;
                    }
                    // `have` is true only after `acc` has been assigned a peak digest.
                    // forge-lint: disable-next-line(uninitialized-local)
                    acc = have ? _fold(acc, d, hasher) : d;
                    have = true;
                }
                cursor = next;
            }
            return q == qEnd && _root(n, inactive, acc, hasher) == root;
        }
    }

    /// @dev Locate the sibling section and count peaks before reading any proof digest.
    function _forwardOffsets(uint256 n, uint256 start, uint256 end, bool belt)
        private
        pure
        returns (uint256 prefix, uint256 after_, uint256 levels, uint256 peaks)
    {
        unchecked {
            levels = _levels(n, belt);
            if (belt) {
                peaks = levels;
                uint256 first = uint256(1) << (levels - 1 + (((n + 1) >> (levels - 1)) & 1));
                prefix = start >= first ? 1 : 0;
                // The last k peaks span `(2^k - 1) + ((n + 1) & (2^k - 1))` leaves.
                // For `k = log2(remaining + 1)`, the suffix count is either `k` or `k - 1`.
                uint256 remaining = n - end;
                after_ = LibMerkle.log2(remaining + 1);
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
            if (have) acc = bytes32(_load(p.digests, cd));
            uint256 top = scratch;
            uint256 levels = _levels(n, belt);
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
                        d = bytes32(_load(front, cd));
                        front += 32;
                    } else if (cursor >= p.end) {
                        d = bytes32(_load(suffix, cd));
                        suffix += 32;
                        suffixTaken = peakIndex >= inactive;
                    } else {
                        bool ok;
                        uint256 nodePosition;
                        if (belt) {
                            nodePosition = cursor + w - 1 + (w > 1 ? (w >> 1) - 1 : 0);
                        } else {
                            uint256 ones = 0;
                            for (uint256 x = cursor; x != 0; x &= x - 1) {
                                ++ones;
                            }
                            nodePosition = 2 * cursor - ones + 2 * w - 2;
                        }
                        if (single) {
                            (d, q, ok) = _singleton(
                                p.data,
                                p.start - cursor,
                                nodePosition,
                                w,
                                q,
                                p.digests + p.digestCount * 32,
                                cd,
                                belt,
                                graft,
                                base,
                                hasher
                            );
                        } else if (prehashed) {
                            (d, q, ok) = _subtree(
                                p.data,
                                p.start,
                                p.end,
                                nodePosition,
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
                                nodePosition,
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
                        acc = have ? _fold(acc, d, hasher) : d;
                        have = true;
                    }
                }
                cursor = next;
                ++peakIndex;
            }
            // forge-lint: disable-next-line(boolean-cst)
            if (q != p.digests + p.digestCount * 32) return (0, false);
            if (top != scratch) acc = _bag(scratch, (top - scratch) / 32, 0, true, hasher);
            // forge-lint: disable-next-line(boolean-cst)
            return (_root(n, inactive, acc, hasher), true);
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
            for (uint256 level = _levels(n, belt); level != 0;) {
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
    function _load(uint256 address_, bool cd) private pure returns (uint256 d) {
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
        uint256 scratch,
        address hasher
    ) private view returns (bytes32 d, uint256 nextQ, bool ok) {
        assembly ("memory-safe") {
            hasher := and(hasher, 0xffffffffffffffffffffffffffffffffffffffff)
            /// @dev Hash raw bytes through an external target and require exactly one digest.
            function externalHash(pointer, length, target) -> digest {
                let success := staticcall(gas(), target, pointer, length, 0, 0x20)
                if iszero(and(success, eq(returndatasize(), 0x20))) {
                    mstore(0, 0x832d9905) // `LibMerkle.HashFailed()`.
                    // Each external hash result must be checked before traversal continues.
                    // forge-lint: disable-next-line(require-revert-in-loop)
                    revert(0x1c, 4)
                }
                digest := mload(0)
            }
            /// @dev Hash a nonzero bitmap prefix and digest. Zero chunks retain the operation digest.
            /// The caller supplies scratch beyond live traversal state, cleared before returning.
            function graftHash(pointer, length, digest, target, scratch_) -> result {
                result := digest
                switch gt(length, 32)
                case 0 {
                    let prefix := calldataload(pointer)
                    let shift := shl(3, sub(32, length))
                    if shr(shift, prefix) {
                        mstore(0, prefix)
                        mstore(length, digest)
                        switch target
                        case 0 { result := keccak256(0, add(length, 32)) }
                        default { result := externalHash(0, add(length, 32), target) }
                    }
                }
                default {
                    let nonzero := 0
                    for { let i := 0 } lt(i, length) { i := add(i, 32) } {
                        let word := calldataload(add(pointer, i))
                        nonzero := or(nonzero, word)
                        mstore(add(scratch_, i), word)
                    }
                    if nonzero {
                        mstore(add(scratch_, length), digest)
                        switch target
                        case 0 { result := keccak256(scratch_, add(length, 32)) }
                        default { result := externalHash(scratch_, add(length, 32), target) }
                    }
                    for { let i := 0 } lt(i, add(length, 32)) { i := add(i, 32) } {
                        mstore(add(scratch_, i), 0)
                    }
                }
            }
            /// @dev Return the highest set bit of a positive `uint64` using `LibMerkle.log2`'s lookup.
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
                            d := graftHash(mload(graft), shr(3, mload(add(graft, 32))), d, hasher, scratch)
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
                    mstore(0, 0x832d9905) // `LibMerkle.HashFailed()`.
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
                    mstore(0, 0x832d9905) // `LibMerkle.HashFailed()`.
                    // Each external hash result must be checked before traversal continues.
                    // forge-lint: disable-next-line(require-revert-in-loop)
                    revert(0x1c, 4)
                }
                digest := mload(0)
            }
            /// @dev Hash a nonzero bitmap prefix and digest. Zero chunks retain the operation digest.
            /// The caller supplies scratch beyond live traversal state, cleared before returning.
            function graftHash(pointer, length, digest, target, scratch_) -> result {
                result := digest
                switch gt(length, 32)
                case 0 {
                    let prefix := calldataload(pointer)
                    let shift := shl(3, sub(32, length))
                    if shr(shift, prefix) {
                        mstore(0, prefix)
                        mstore(length, digest)
                        switch target
                        case 0 { result := keccak256(0, add(length, 32)) }
                        default { result := externalHash(0, add(length, 32), target) }
                    }
                }
                default {
                    let nonzero := 0
                    for { let i := 0 } lt(i, length) { i := add(i, 32) } {
                        let word := calldataload(add(pointer, i))
                        nonzero := or(nonzero, word)
                        mstore(add(scratch_, i), word)
                    }
                    if nonzero {
                        mstore(add(scratch_, length), digest)
                        switch target
                        case 0 { result := keccak256(scratch_, add(length, 32)) }
                        default { result := externalHash(scratch_, add(length, 32), target) }
                    }
                    for { let i := 0 } lt(i, add(length, 32)) { i := add(i, 32) } {
                        mstore(add(scratch_, i), 0)
                    }
                }
            }
            /// @dev Return the highest set bit of a positive `uint64` using `LibMerkle.log2`'s lookup.
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
                        if eq(width, mload(add(graft, 0x60))) {
                            let chunk := div(sub(cursor, width), width)
                            if lt(chunk, mload(add(graft, 0x40))) {
                                let local := sub(chunk, mload(add(graft, 0x20)))
                                let length := shr(3, width)
                                let pointer := add(mload(graft), mul(local, length))
                                // Leaf bounds limit DFS state to 63 words above base.
                                d := graftHash(pointer, length, d, hasher, add(base, 0x800))
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

    /// @dev Reconstruct using raw words in the selected location or positioned digests in memory.
    /// `prehashed` changes only element loading and hashing. Witness and index locations use `cd`.
    function _verifyMulti(
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
            return leaves == 0 && inactive == 0 && proofCount == 0 && root == _emptyRoot(hasher);
        }
        if (leaves == 0) return false;
        uint256 free;
        assembly ("memory-safe") { free := mload(0x40) }
        MultiProof memory p = MultiProof(positions, digests, proofCount, 0, cd, belt, 0, 0, hasher);
        uint256 pairs;
        assembly ("memory-safe") { pairs := mload(0x40) }
        uint256 peaks = pairs + count * 64;
        uint256 end = peaks + _levels(leaves, belt) * 32;
        assembly ("memory-safe") { mstore(0x40, end) }
        (uint256 unique, bool ok) = _multiElements(p, leaves, indices, elements, count, pairs, prehashed);
        if (ok) {
            p.cursor = pairs;
            p.end = pairs + unique * 64;
            valid = _reconstructMulti(p, root, leaves, unique, peaks, backward, inactive);
        }
        assembly ("memory-safe") {
            for { let q := free } lt(q, end) { q := add(q, 0x20) } { mstore(q, 0) }
            mstore(0x40, free)
        }
    }

    /// @dev Sort selected elements and check duplicate values before hashing raw leaves.
    /// Positioned digests are loaded from memory and retained without another hash.
    function _multiElements(
        MultiProof memory p,
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
            if (!sorted) LibMerkle.sortPairs(pairs, count);
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
                uint256 nodePosition = 0;
                if (!prehashed) nodePosition = LibMerkle.position(LibMerkle.peak(index, 1, p.belt), 1, p.belt);
                assembly ("memory-safe") {
                    let slot := add(pairs, shl(6, unique))
                    mstore(slot, index)
                }
                bytes32 digest =
                    prehashed ? element : LibMerkle.hashSlice(bytes32(nodePosition), element, 0x18, 0x28, p.hasher);
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
    function _reconstructMulti(
        MultiProof memory p,
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
            for (uint256 level = _levels(n, p.belt); level != 0;) {
                uint256 w = _width(n, --level, p.belt);
                if (w == 0) continue;
                uint256 from = p.cursor;
                uint256 pos = LibMerkle.peak(cursor, w, p.belt);
                (bytes32 digest, bool ok) = _multiSubtree(p, pos, w, cursor);
                if (!ok) return false;
                uint256 selected = p.cursor - from;
                if (selected != 0 && selected != count * 64) {
                    (bytes32 witness, bool found) = _multiWitness(p, LibMerkle.position(pos, w, p.belt));
                    if (!found || witness != digest) return false;
                }
                assembly ("memory-safe") { mstore(add(peaks, shl(5, peakCount)), digest) }
                ++peakCount;
                cursor += w;
            }
            if (inactive > peakCount || p.used != p.length) return false;
            bytes32 acc = _bag(peaks, peakCount, inactive, backward, p.hasher);
            return _root(n, inactive, acc, p.hasher) == root;
        }
    }

    /// @dev A child is a required redundant witness exactly when its sibling contains selected leaves.
    /// Disjoint subtrees are consumed directly from the proof. Selected leaves use their computed hashes.
    /// `p.cursor` advances through sorted unique pairs and always points past every visited leaf.
    /// The left witness must be consumed before visiting the right child to preserve proof order.
    function _multiSubtree(MultiProof memory p, uint256 pos, uint256 w, uint256 cursor)
        private
        view
        returns (bytes32 digest, bool ok)
    {
        unchecked {
            uint256 from = p.cursor;
            if (from == p.end) return _multiWitness(p, LibMerkle.position(pos, w, p.belt));
            uint256 index;
            assembly ("memory-safe") { index := mload(from) }
            if (index >= cursor + w) return _multiWitness(p, LibMerkle.position(pos, w, p.belt));
            if (w == 1) {
                assembly ("memory-safe") { digest := mload(add(from, 0x20)) }
                p.cursor = from + 64;
                // forge-lint: disable-next-line(boolean-cst)
                return (digest, true);
            }
            uint256 half = w >> 1;
            uint256 left = p.belt ? pos - (w == 2 ? 1 : 3 * (w >> 2)) : pos - w;
            uint256 right = p.belt ? left + half : pos - 1;
            (bytes32 a, bool valid) = _multiSubtree(p, left, half, cursor);
            // forge-lint: disable-next-line(boolean-cst)
            if (!valid) return (0, false);
            bool both = p.cursor != from && p.cursor != p.end;
            if (both) {
                uint256 slot = p.cursor;
                assembly ("memory-safe") { index := mload(slot) }
                both = index < cursor + w;
            }
            if (both) {
                (bytes32 expected, bool found) = _multiWitness(p, LibMerkle.position(left, half, p.belt));
                // forge-lint: disable-next-line(boolean-cst)
                if (!found || expected != a) return (0, false);
            }
            (bytes32 b, bool validRight) = _multiSubtree(p, right, half, cursor + half);
            // forge-lint: disable-next-line(boolean-cst)
            if (!validRight) return (0, false);
            if (both) {
                (bytes32 expected, bool found) = _multiWitness(p, LibMerkle.position(right, half, p.belt));
                // forge-lint: disable-next-line(boolean-cst)
                if (!found || expected != b) return (0, false);
            }
            uint256 nodePosition = LibMerkle.position(pos, w, p.belt);
            address hasher = p.hasher;
            assembly ("memory-safe") {
                hasher := and(hasher, 0xffffffffffffffffffffffffffffffffffffffff)
                let free := mload(0x40)
                mstore(0, nodePosition)
                mstore(0x20, a)
                mstore(0x40, b)
                switch hasher
                case 0 { digest := keccak256(0x18, 0x48) }
                default {
                    let success := staticcall(gas(), hasher, 0x18, 0x48, 0, 0x20)
                    if iszero(and(success, eq(returndatasize(), 0x20))) {
                        mstore(0, 0x832d9905) // `LibMerkle.HashFailed()`.
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
    function _multiWitness(MultiProof memory p, uint256 nodePosition) private pure returns (bytes32 digest, bool ok) {
        unchecked {
            uint256 lo = p.used;
            if (p.belt) {
                lo = 0;
                uint256 hi = p.length;
                while (lo < hi) {
                    uint256 mid = (lo + hi) >> 1;
                    if (_load(p.keys + mid * 32, p.cd) < nodePosition) lo = mid + 1;
                    else hi = mid;
                }
            }
            // forge-lint: disable-next-line(boolean-cst)
            if (lo == p.length || _load(p.keys + lo * 32, p.cd) != nodePosition) return (0, false);
            ++p.used;
            // forge-lint: disable-next-line(boolean-cst)
            return (bytes32(_load(p.digests + lo * 32, p.cd)), true);
        }
    }

    /// @dev Return the number of candidate peak heights for the tree family.
    function _levels(uint256 n, bool belt) private pure returns (uint256) {
        return belt ? log2(n + 1) : log2(n) + 1;
    }

    /// @dev Return the leaf width at a candidate peak height, or zero for an absent peak.
    function _width(uint256 n, uint256 i, bool belt) private pure returns (uint256) {
        unchecked {
            return belt ? uint256(1) << (i + (((n + 1) >> i) & 1)) : n & (uint256(1) << i);
        }
    }

    /// @dev MMB traversal uses birth leaves. MMR traversal uses postorder positions.
    function peak(uint256 cursor, uint256 w, bool belt) internal pure returns (uint256) {
        unchecked {
            if (belt) return cursor + w - 1 + (w > 1 ? (w >> 1) - 1 : 0);
            uint256 ones = 0;
            for (uint256 x = cursor; x != 0; x &= x - 1) {
                ++ones;
            }
            return 2 * cursor - ones + 2 * w - 2;
        }
    }

    /// @dev Convert a traversal position into the physical node position.
    function position(uint256 p, uint256 w, bool belt) internal pure returns (uint256) {
        unchecked {
            return belt ? 2 * p - log2(p + 1) + (w > 1 ? 1 : 0) : p;
        }
    }

    /// @dev Count aligned MMB chunks whose ancestor exists at `height`, between 1 and 62.
    /// Delayed merges need another `2^(height - 1) - 1` leaves after each chunk fills.
    function graftableMMBChunks(uint256 leaves, uint256 height) internal pure returns (uint256) {
        uint256 delay = (uint256(1) << (height - 1)) - 1;
        return leaves < delay ? 0 : (leaves - delay) >> height;
    }

    /// @dev Adapted from Solady `LibBit.fls` for positive `uint64` values.
    /// https://github.com/Vectorized/solady/blob/2afba69bf67b78dd4abeadcc696052b3a6f71499/src/utils/LibBit.sol
    /// https://github.com/Vectorized/solady/blob/2afba69bf67b78dd4abeadcc696052b3a6f71499/LICENSE.txt
    function log2(uint256 x) internal pure returns (uint256 r) {
        assembly ("memory-safe") {
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
    }

    /// @dev Hash a slice of `a || b` without allocating. The caller ensures `offset + length <= 64`.
    /// Scratch preimages are written and consumed within this block.
    /// A nonzero `hasher` receives raw bytes and must return exactly 32 bytes.
    function hashSlice(bytes32 a, bytes32 b, uint256 offset, uint256 length, address hasher)
        internal
        view
        returns (bytes32 digest)
    {
        assembly ("memory-safe") {
            mstore(0, a)
            mstore(0x20, b)
            hasher := and(hasher, 0xffffffffffffffffffffffffffffffffffffffff)
            switch hasher
            case 0 { digest := keccak256(offset, length) }
            default {
                let success := staticcall(gas(), hasher, offset, length, 0, 0x20)
                if iszero(and(success, eq(returndatasize(), 0x20))) {
                    mstore(0, 0x832d9905) // `HashFailed()`.
                    // Each external hash result must be checked before traversal continues.
                    // forge-lint: disable-next-line(require-revert-in-loop)
                    revert(0x1c, 4)
                }
                digest := mload(0)
            }
        }
    }

    /// @dev Hash an owned byte array with the selected raw hash target.
    function hash(bytes memory input, address hasher) internal view returns (bytes32 digest) {
        assembly ("memory-safe") {
            hasher := and(hasher, 0xffffffffffffffffffffffffffffffffffffffff)
            switch hasher
            case 0 { digest := keccak256(add(input, 0x20), mload(input)) }
            default {
                let success := staticcall(gas(), hasher, add(input, 0x20), mload(input), 0, 0x20)
                if iszero(and(success, eq(returndatasize(), 0x20))) {
                    mstore(0, 0x832d9905) // `HashFailed()`.
                    // Every hash result must be checked before verification continues.
                    // forge-lint: disable-next-line(require-revert-in-loop)
                    revert(0x1c, 4)
                }
                digest := mload(0)
            }
        }
    }

    /// @dev The empty root is `H(bytes8(0))` for the selected hash.
    function _emptyRoot(address hasher) private view returns (bytes32) {
        if (hasher == address(0)) return EMPTY_ROOT;
        return hashSlice(0, 0, 0, 8, hasher);
    }

    /// @dev Hash two ordered peak digests.
    function _fold(bytes32 a, bytes32 b, address hasher) private view returns (bytes32) {
        return hashSlice(a, b, 0, 0x40, hasher);
    }

    /// @dev Nonzero inactive boundaries commit an additional big-endian `uint64`.
    function _root(uint256 n, uint256 inactive, bytes32 acc, address hasher) private view returns (bytes32) {
        if (inactive == 0) return hashSlice(bytes32(n), acc, 0x18, 0x28, hasher);
        return hashSlice(bytes32((n << 64) | inactive), acc, 0x10, 0x30, hasher);
    }

    /// @dev Fold a nonempty peak buffer with `inactive` leading peaks folded forward.
    /// The caller ensures `inactive <= count` and owns the peak buffer.
    function _bag(uint256 peaks, uint256 count, uint256 inactive, bool backward, address hasher)
        private
        view
        returns (bytes32 acc)
    {
        assembly ("memory-safe") {
            hasher := and(hasher, 0xffffffffffffffffffffffffffffffffffffffff)
            /// @dev Hash two ordered peak digests.
            function fold(a, b, target) -> d {
                mstore(0, a)
                mstore(0x20, b)
                switch target
                case 0 { d := keccak256(0, 0x40) }
                default {
                    let success := staticcall(gas(), target, 0, 0x40, 0, 0x20)
                    if iszero(and(success, eq(returndatasize(), 0x20))) {
                        mstore(0, 0x832d9905) // `LibMerkle.HashFailed()`.
                        // Each external hash result must be checked before traversal continues.
                        // forge-lint: disable-next-line(require-revert-in-loop)
                        revert(0x1c, 4)
                    }
                    d := mload(0)
                }
            }
            acc := mload(peaks)
            let cursor := add(peaks, 0x20)
            let end := add(peaks, shl(5, count))
            let active := add(peaks, shl(5, inactive))
            for { } lt(cursor, active) { cursor := add(cursor, 0x20) } {
                acc := fold(acc, mload(cursor), hasher)
            }
            switch backward
            case 0 {
                for { } lt(cursor, end) { cursor := add(cursor, 0x20) } {
                    acc := fold(acc, mload(cursor), hasher)
                }
            }
            default {
                if lt(cursor, end) {
                    end := sub(end, 0x20)
                    let suffix := mload(end)
                    for { } gt(end, cursor) { } {
                        end := sub(end, 0x20)
                        suffix := fold(mload(end), suffix, hasher)
                    }
                    acc := fold(acc, suffix, hasher)
                }
            }
        }
    }

    /// @dev Sort `count` allocated `(uint256 index, bytes32 value)` pairs in place.
    /// Heapsort bounds work for arbitrary input order and moves each index with its value.
    function sortPairs(uint256 pairs, uint256 count) internal pure {
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
}
