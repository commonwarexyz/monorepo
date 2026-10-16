// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

/// @notice Encode Commonware unsigned integer fields.
library LibCodec {
    /// @notice Encode a uint64 as an unsigned base-128 varint.
    function encodeVarint(uint64 value) internal pure returns (bytes memory result) {
        result = new bytes(10);
        uint256 length = 0;
        do {
            result[length++] = bytes1(uint8(value & 0x7f) | (value > 0x7f ? 0x80 : 0));
            value >>= 7;
        } while (value != 0);
        assembly ("memory-safe") { mstore(result, length) }
    }
}
