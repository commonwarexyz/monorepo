// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { Test } from "forge-std/Test.sol";
import { LibBMT } from "../src/merkle/LibBMT.sol";
import { LibCodec } from "../src/codec/LibCodec.sol";
import { LibMerkle } from "../src/merkle/LibMerkle.sol";

/// @dev Properties proven over every input by `forge test --symbolic`. Plain `forge test` skips them.
/// Hash-dependent properties are omitted because the solver cannot model digests.
contract SymbolicTest is Test {
    /// @dev The bit-window lookup returns the floor logarithm of every positive uint64.
    function check_Log2(uint64 x) public pure {
        vm.assume(x != 0);
        uint256 r = LibMerkle.log2(x);
        assert(r < 64);
        assert(uint256(1) << r <= x);
        assert(uint256(x) < uint256(1) << (r + 1));
    }

    /// @dev Encodings are canonical, length bounded and decode to the original value.
    function check_VarintRoundtrip(uint64 x) public pure {
        bytes memory encoded = LibCodec.encodeVarint(x);
        assert(encoded.length >= 1 && encoded.length <= 10);
        uint256 decoded;
        for (uint256 i; i < encoded.length; ++i) {
            uint8 b = uint8(encoded[i]);
            assert((b & 0x80 != 0) == (i + 1 < encoded.length));
            decoded |= uint256(b & 0x7f) << (7 * i);
        }
        assert(decoded == x);
        assert(encoded.length == 1 || uint8(encoded[encoded.length - 1]) != 0);
    }

    /// @dev No proof authenticates an index outside the tree or a tree above the leaf limit.
    function check_BMTSingleOutOfRange(
        bytes32 root,
        uint256 leaves,
        uint256 index,
        bytes32 element,
        bytes32[] calldata proof
    ) public view {
        vm.assume(leaves > type(uint32).max || index >= leaves);
        assert(!LibBMT.verifyCalldata(root, leaves, index, element, proof, address(0)));
        assert(!LibBMT.verifyCalldata(root, leaves, index, element, proof, address(2)));
    }

    /// @dev No proof authenticates a range that exceeds the tree or a tree above the leaf limit.
    function check_BMTRangeOutOfRange(
        bytes32 root,
        uint256 leaves,
        uint256 start,
        bytes32[] calldata elements,
        bytes32[] calldata proof
    ) public view {
        vm.assume(leaves > type(uint32).max || start > leaves || elements.length > leaves - start);
        assert(!LibBMT.verifyRangeCalldata(root, leaves, start, elements, proof, address(0)));
        assert(!LibBMT.verifyRangeCalldata(root, leaves, start, elements, proof, address(2)));
    }

    /// @dev No proof authenticates more indices than leaves or a tree above the leaf limit.
    function check_BMTMultiOutOfRange(
        bytes32 root,
        uint256 leaves,
        uint256[] calldata indices,
        bytes32[] calldata elements,
        bytes32[] calldata proof
    ) public view {
        vm.assume(leaves > type(uint32).max || elements.length > leaves);
        assert(!LibBMT.verifyMultiCalldata(root, leaves, indices, elements, proof, address(0)));
        assert(!LibBMT.verifyMultiCalldata(root, leaves, indices, elements, proof, address(2)));
    }
}
