// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

///  Encoding/decoding utilities for varint and bitmap operations
library CodecHelpers {
    uint8 internal constant DATA_BITS_MASK = 0x7F;
    uint8 internal constant CONTINUATION_BIT_MASK = 0x80;
    uint256 internal constant DATA_BITS_PER_BYTE = 7;
    uint256 internal constant MAX_U64_BITS = 64;
    uint256 internal constant U64_LAST_BYTE_SHIFT = 63;

    error InvalidVarint();

    function encodeVarintU64(uint64 value) internal pure returns (bytes memory) {
        if (value == 0) {
            return hex"00";
        }

        bytes memory result = new bytes(10);
        uint256 length = 0;

        while (value > 0) {
            // casting to 'uint8' is safe because DATA_BITS_MASK is 0x7F, so the result is at most 127
            // forge-lint: disable-next-line(unsafe-typecast)
            uint8 dataBits = uint8(value & DATA_BITS_MASK);
            value >>= DATA_BITS_PER_BYTE;
            if (value > 0) {
                dataBits |= CONTINUATION_BIT_MASK;
            }
            result[length] = bytes1(dataBits);
            length++;
        }

        assembly {
            mstore(result, length)
        }

        return result;
    }

    function decodeVarintU64(bytes calldata data, uint256 offset)
        internal pure returns (uint64 value, uint256 newOffset)
    {
        uint256 shift = 0;
        uint256 currentOffset = offset;
        uint256 bytesRead = 0;

        while (true) {
            if (currentOffset >= data.length) revert InvalidVarint();

            uint8 b = uint8(data[currentOffset]);
            currentOffset++;
            bytesRead++;

            if (bytesRead > 1 && b == 0) {
                revert InvalidVarint();
            }

            uint8 dataBits = b & DATA_BITS_MASK;

            if (shift == U64_LAST_BYTE_SHIFT) {
                if (b > 1) revert InvalidVarint();
            }

            value |= uint64((uint256(dataBits) << shift));

            if ((b & CONTINUATION_BIT_MASK) == 0) {
                break;
            }

            shift += DATA_BITS_PER_BYTE;
            if (shift >= MAX_U64_BITS) revert InvalidVarint();
        }

        return (value, currentOffset);
    }

    function decodeVarintU32(bytes calldata data, uint256 offset)
        internal pure returns (uint32 value, uint256 newOffset)
    {
        uint64 val64;
        (val64, newOffset) = decodeVarintU64(data, offset);

        if (val64 & 0xFFFFFFFF00000000 != 0) {
            revert InvalidVarint();
        }
        // casting to 'uint32' is safe because the check above ensures upper 32 bits are zero
        // forge-lint: disable-next-line(unsafe-typecast)
        value = uint32(val64);
    }

    function getBit(bytes memory bitmap, uint256 bitIndex) internal pure returns (bool) {
        uint256 byteIndex = bitIndex >> 3;
        uint256 bitInByte = bitIndex & 7;

        if (byteIndex >= bitmap.length) return false;

        uint8 byteValue = uint8(bitmap[byteIndex]);
        // casting to 'uint8' is safe because bitInByte is 0-7 (from bitIndex & 7), so (1 << bitInByte) is at most 128
        // forge-lint: disable-next-line(unsafe-typecast)
        uint8 mask = uint8(uint256(1) << bitInByte);
        return (byteValue & mask) != 0;
    }
}
