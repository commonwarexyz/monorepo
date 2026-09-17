// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

/// @dev Shared Commonware peak geometry and root hashing.
library Common {
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

    /// @dev Hash two ordered peak digests.
    function fold(bytes32 a, bytes32 b) internal pure returns (bytes32 d) {
        assembly ("memory-safe") {
            mstore(0, a)
            mstore(0x20, b)
            d := keccak256(0, 0x40)
        }
    }

    /// @dev Nonzero inactive boundaries commit an additional big-endian `uint64`.
    function root(uint256 n, uint256 inactive, bytes32 acc) internal pure returns (bytes32 d) {
        assembly ("memory-safe") {
            mstore(0x20, acc)
            switch inactive
            case 0 {
                mstore(0, n)
                d := keccak256(0x18, 0x28)
            }
            default {
                mstore(0, or(shl(64, n), inactive))
                d := keccak256(0x10, 0x30)
            }
        }
    }

    /// @dev Fold a nonempty peak buffer with `inactive` leading peaks folded forward.
    /// The caller ensures `inactive <= count` and owns the peak buffer.
    function bag(uint256 peaks, uint256 count, uint256 inactive, bool backward) internal pure returns (bytes32 acc) {
        assembly ("memory-safe") {
            /// @dev Hash two ordered peak digests.
            function fold(a, b) -> d {
                mstore(0, a)
                mstore(0x20, b)
                d := keccak256(0, 0x40)
            }
            acc := mload(peaks)
            let cursor := add(peaks, 0x20)
            let end := add(peaks, shl(5, count))
            let active := add(peaks, shl(5, inactive))
            for { } lt(cursor, active) { cursor := add(cursor, 0x20) } {
                acc := fold(acc, mload(cursor))
            }
            switch backward
            case 0 {
                for { } lt(cursor, end) { cursor := add(cursor, 0x20) } {
                    acc := fold(acc, mload(cursor))
                }
            }
            default {
                if lt(cursor, end) {
                    end := sub(end, 0x20)
                    let suffix := mload(end)
                    for { } gt(end, cursor) { } {
                        end := sub(end, 0x20)
                        suffix := fold(mload(end), suffix)
                    }
                    acc := fold(acc, suffix)
                }
            }
        }
    }
}
