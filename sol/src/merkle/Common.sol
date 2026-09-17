// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

/// @dev Shared Commonware peak geometry and root hashing.
library Common {
    /// @dev The selected hash target failed or returned a value other than 32 bytes.
    error HashFailed();

    /// @dev The empty tree commits a zero `uint64` leaf count.
    bytes32 internal constant EMPTY_ROOT = keccak256(hex"0000000000000000");

    /// @dev Return the number of candidate peak heights for the tree family.
    function levels(uint256 n, bool belt) internal pure returns (uint256) {
        return belt ? log2(n + 1) : log2(n) + 1;
    }

    /// @dev Return the leaf width at a candidate peak height, or zero for an absent peak.
    function width(uint256 n, uint256 i, bool belt) internal pure returns (uint256) {
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
    function hash(bytes32 a, bytes32 b, uint256 offset, uint256 length, address hasher)
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
    function emptyRoot(address hasher) internal view returns (bytes32) {
        if (hasher == address(0)) return EMPTY_ROOT;
        return hash(0, 0, 0, 8, hasher);
    }

    /// @dev Hash two ordered peak digests.
    function fold(bytes32 a, bytes32 b, address hasher) internal view returns (bytes32) {
        return hash(a, b, 0, 0x40, hasher);
    }

    /// @dev Nonzero inactive boundaries commit an additional big-endian `uint64`.
    function root(uint256 n, uint256 inactive, bytes32 acc, address hasher) internal view returns (bytes32) {
        if (inactive == 0) return hash(bytes32(n), acc, 0x18, 0x28, hasher);
        return hash(bytes32((n << 64) | inactive), acc, 0x10, 0x30, hasher);
    }

    /// @dev Fold a nonempty peak buffer with `inactive` leading peaks folded forward.
    /// The caller ensures `inactive <= count` and owns the peak buffer.
    function bag(uint256 peaks, uint256 count, uint256 inactive, bool backward, address hasher)
        internal
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
                        mstore(0, 0x832d9905) // `Common.HashFailed()`.
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
