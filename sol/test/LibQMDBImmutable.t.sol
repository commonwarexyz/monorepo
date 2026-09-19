// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.15;

import { LibMerkle } from "../src/merkle/LibMerkle.sol";
import { QMDBTest, Encoding } from "./Common.t.sol";
import { LibQMDBCommon } from "../src/qmdb/LibQMDBCommon.sol";
import { LibQMDBImmutableMMB } from "../src/qmdb/LibQMDBImmutableMMB.sol";
import { LibQMDBImmutableMMR } from "../src/qmdb/LibQMDBImmutableMMR.sol";

struct ImmutableCase {
    bytes32 root;
    bytes operation;
    LibQMDBCommon.Proof proof;
}

abstract contract LibQMDBImmutableTest is QMDBTest {
    enum ImmutableOperation {
        Set,
        Commit,
        CommitMetadata
    }

    /// @dev Repeated verification preserves caller bytes, allocation alignment, and the zero slot.
    function checked(ImmutableCase calldata c) external view returns (bool valid) {
        bytes memory operation = c.operation;
        bytes memory guard = abi.encode(c);
        bytes32 original = keccak256(abi.encode(operation, guard));
        for (uint256 repeat; repeat < 2; ++repeat) {
            uint256 beforePointer;
            uint256 afterPointer;
            uint256 zero;
            assembly ("memory-safe") {
                beforePointer := mload(0x40)
                for { let p := beforePointer } lt(p, add(beforePointer, 0x2000)) { p := add(p, 32) } {
                    mstore(p, not(0))
                }
            }
            bool result = _family() == LibMerkle.Family.MMB
                ? LibQMDBImmutableMMB.verify(c.root, operation, c.proof, _hasher())
                : LibQMDBImmutableMMR.verify(c.root, operation, c.proof, _hasher());
            assembly ("memory-safe") {
                afterPointer := mload(0x40)
                zero := mload(0x60)
            }
            assertGe(afterPointer, beforePointer);
            assertEq(afterPointer & 31, 0);
            assertEq(zero, 0);
            if (repeat != 0) assertEq(result, valid);
            valid = result;
            bytes memory fresh = new bytes(97);
            for (uint256 i; i < fresh.length; ++i) {
                assertEq(uint8(fresh[i]), 0);
                fresh[i] = bytes1(uint8(i));
            }
            assertEq(keccak256(abi.encode(operation, guard)), original);
        }
    }

    /// @dev Encode unsigned base-128 lengths and floors independently of the Rust codec.
    function varint(uint256 n) internal pure returns (bytes memory out) {
        do {
            uint8 digit = uint8(n & 127);
            n >>= 7;
            out = abi.encodePacked(out, bytes1(n == 0 ? digit : digit | 128));
        } while (n != 0);
    }

    /// @dev Encode 32-byte keys and fixed values, or byte-vector values, with production framing.
    function encoded(ImmutableOperation kind, Encoding encoding, bytes memory value, uint256 floor)
        internal
        pure
        returns (bytes memory)
    {
        if (kind == ImmutableOperation.Set) return abi.encodePacked(hex"00", bytes32(uint256(1)), value);
        if (encoding == Encoding.Variable) {
            return abi.encodePacked(kind == ImmutableOperation.Commit ? hex"0100" : hex"0101", value, varint(floor));
        }
        return
            abi.encodePacked(
                kind == ImmutableOperation.Commit ? hex"0100" : hex"0101", value, uint64(floor), bytes23(0)
            );
    }

    /// @dev A bootstrap followed by one operation has identical physical positions in both families.
    function smallCase(bytes memory operation, bytes memory bootstrap, bool second)
        internal
        pure
        returns (ImmutableCase memory c)
    {
        c.operation = operation;
        c.proof.leaves = second ? 2 : 1;
        c.proof.location = second ? 1 : 0;
        c.proof.digests = new bytes32[](second ? 1 : 0);
        bytes32 folded = _hash(abi.encodePacked(uint64(c.proof.location), operation));
        if (second) {
            c.proof.digests[0] = _hash(abi.encodePacked(uint64(0), bootstrap));
            folded = _hash(abi.encodePacked(uint64(2), c.proof.digests[0], folded));
        }
        c.root = _hash(abi.encodePacked(uint64(c.proof.leaves), folded));
    }

    /// @dev Every tag, key, value, prefix, metadata, floor, and padding byte is authenticated.
    function rejectMutations(ImmutableCase memory c) internal view {
        assertTrue(this.checked(c));
        for (uint256 i; i < c.operation.length; ++i) {
            c.operation[i] ^= 0x01;
            assertFalse(this.checked(c), "modified operation byte accepted");
            c.operation[i] ^= 0x01;
        }
        c.operation = abi.encodePacked(c.operation, hex"00");
        assertFalse(this.checked(c), "extended operation accepted");
        c.operation = new bytes(0);
        assertFalse(this.checked(c), "empty operation accepted");
    }

    /// @dev Independent encodings cover bootstrap, sets, metadata, floors, and length transitions.
    function test_OperationEncodings() public view {
        bytes memory shortBootstrap = abi.encodePacked(hex"0100", uint64(0), uint64(0));
        rejectMutations(smallCase(abi.encodePacked(hex"00", uint64(1), uint64(2), hex"00"), shortBootstrap, true));
        uint256[5] memory lengths = [uint256(0), 31, 32, 127, 128];
        for (uint256 encodingIndex; encodingIndex <= uint256(Encoding.Variable); ++encodingIndex) {
            Encoding encoding = Encoding(encodingIndex);
            bytes memory bootstrap = encoded(
                ImmutableOperation.Commit, encoding, encoding == Encoding.Variable ? new bytes(0) : new bytes(32), 0
            );
            rejectMutations(smallCase(bootstrap, bootstrap, false));
            for (uint256 i; i < (encoding == Encoding.Variable ? lengths.length : 1); ++i) {
                bytes memory payload = new bytes(encoding == Encoding.Variable ? lengths[i] : 32);
                for (uint256 j; j < payload.length; ++j) {
                    payload[j] = bytes1(uint8(j));
                }
                bytes memory value =
                    encoding == Encoding.Variable ? abi.encodePacked(varint(payload.length), payload) : payload;
                for (
                    uint256 operationIndex;
                    operationIndex <= uint256(ImmutableOperation.CommitMetadata);
                    ++operationIndex
                ) {
                    ImmutableOperation kind = ImmutableOperation(operationIndex);
                    bytes memory body = kind == ImmutableOperation.Commit
                        ? (encoding == Encoding.Variable ? new bytes(0) : new bytes(32))
                        : value;
                    rejectMutations(smallCase(encoded(kind, encoding, body, 1), bootstrap, true));
                }
            }
        }
    }

    /// @dev Production immutable operations are verified by the Rust oracle before ABI emission.
    function generate(
        uint256 n,
        uint256 location,
        uint256 floor,
        Encoding encoding,
        ImmutableOperation kind,
        uint256 length
    ) internal returns (ImmutableCase memory c) {
        if (encoding == Encoding.Fixed) {
            assertEq(length, 0, "fixed encoding has no variable value length");
        }
        string[] memory args = new string[](encoding == Encoding.Variable ? 19 : 17);
        args[0] = string.concat(vm.projectRoot(), "/../target/release/commonware-sol-fuzz");
        args[1] = "qmdb";
        args[2] = "immutable";
        args[3] = "--leaves";
        args[4] = vm.toString(n);
        args[5] = "--location";
        args[6] = vm.toString(location);
        args[7] = "--seed";
        args[8] = "71";
        args[9] = "--inactivity-floor";
        args[10] = vm.toString(floor);
        args[11] = "--family";
        args[12] = _family() == LibMerkle.Family.MMB ? "mmb" : "mmr";
        args[13] = "--encoding";
        args[14] = encoding == Encoding.Variable ? "variable" : "fixed";
        args[15] = "--operation";
        args[16] =
            kind == ImmutableOperation.Set ? "set" : kind == ImmutableOperation.Commit ? "commit" : "commit-metadata";
        if (encoding == Encoding.Variable) {
            args[17] = "--value-length";
            args[18] = vm.toString(length);
        }
        (c.root, c.proof.leaves, c.proof.location, c.proof.inactivePeaks, c.proof.digests, c.operation) =
            abi.decode(_ffi(args), (bytes32, uint256, uint256, uint256, bytes32[], bytes));
        assertEq(c.proof.leaves, n);
        assertEq(c.proof.location, location);
    }

    /// @dev Rust codecs agree byte-for-byte with independent bootstrap, set, and metadata encodings.
    function test_DifferentialEncodings() public {
        uint256[5] memory lengths = [uint256(0), 31, 32, 127, 128];
        bytes32 source = keccak256(abi.encodePacked(uint64(71), uint64(1)));
        for (uint256 encodingIndex; encodingIndex <= uint256(Encoding.Variable); ++encodingIndex) {
            Encoding encoding = Encoding(encodingIndex);
            bytes memory bootstrap = encoded(
                ImmutableOperation.Commit, encoding, encoding == Encoding.Variable ? new bytes(0) : new bytes(32), 0
            );
            ImmutableCase memory c = generate(1, 0, 0, encoding, ImmutableOperation.Commit, 0);
            assertEq(c.operation, bootstrap);
            assertEq(c.root, smallCase(bootstrap, bootstrap, false).root);
            assertTrue(this.checked(c));
            for (uint256 i; i < (encoding == Encoding.Variable ? lengths.length : 1); ++i) {
                bytes memory value = new bytes(encoding == Encoding.Variable ? lengths[i] : 32);
                for (uint256 j; j < value.length; ++j) {
                    value[j] = source[j % 32];
                }
                if (encoding == Encoding.Variable) value = abi.encodePacked(varint(value.length), value);
                for (
                    uint256 operationIndex;
                    operationIndex <= uint256(ImmutableOperation.CommitMetadata);
                    ++operationIndex
                ) {
                    ImmutableOperation kind = ImmutableOperation(operationIndex);
                    c = generate(2, 1, 1, encoding, kind, lengths[i]);
                    bytes memory body = kind == ImmutableOperation.Commit
                        ? (encoding == Encoding.Variable ? new bytes(0) : new bytes(32))
                        : value;
                    assertEq(c.operation, encoded(kind, encoding, body, 1));
                    rejectMutations(c);
                }
            }
        }
    }

    /// @dev Merge boundaries and inactive peaks bind geometry, witnesses, and the authenticated root.
    function test_DifferentialTrees() public {
        uint256[6] memory sizes = [uint256(7), 8, 255, 256, 257, 1023];
        for (uint256 encodingIndex; encodingIndex <= uint256(Encoding.Variable); ++encodingIndex) {
            Encoding encoding = Encoding(encodingIndex);
            for (uint256 i; i < sizes.length; ++i) {
                for (
                    uint256 operationIndex;
                    operationIndex <= uint256(ImmutableOperation.CommitMetadata);
                    ++operationIndex
                ) {
                    ImmutableOperation kind = ImmutableOperation(operationIndex);
                    ImmutableCase memory c = generate(
                        sizes[i], sizes[i] - 1, i == 5 ? 512 : 0, encoding, kind, encoding == Encoding.Variable ? 33 : 0
                    );
                    assertTrue(this.checked(c));
                    c.root ^= bytes32(uint256(1));
                    assertFalse(this.checked(c));
                    c.root ^= bytes32(uint256(1));
                    for (uint256 j; j < c.proof.digests.length; ++j) {
                        c.proof.digests[j] ^= bytes32(uint256(1));
                        assertFalse(this.checked(c));
                        c.proof.digests[j] ^= bytes32(uint256(1));
                    }
                    if (i == 5) {
                        assertGt(c.proof.inactivePeaks, 0);
                        c.proof.inactivePeaks = 0;
                        assertFalse(this.checked(c));
                    }
                    c.proof.location = sizes[i];
                    assertFalse(this.checked(c));
                }
            }
        }
    }
}

abstract contract LibQMDBImmutableMMBTest is LibQMDBImmutableTest {
    function _family() internal pure override returns (LibMerkle.Family) {
        return LibMerkle.Family.MMB;
    }
}

contract LibQMDBImmutableMMBKeccak256Test is LibQMDBImmutableMMBTest {
    function _hasher() internal pure override returns (address) {
        return address(0);
    }
}

contract LibQMDBImmutableMMBSha256Test is LibQMDBImmutableMMBTest {
    function _hasher() internal pure override returns (address) {
        return address(2);
    }
}

abstract contract LibQMDBImmutableMMRTest is LibQMDBImmutableTest {
    function _family() internal pure override returns (LibMerkle.Family) {
        return LibMerkle.Family.MMR;
    }
}

contract LibQMDBImmutableMMRKeccak256Test is LibQMDBImmutableMMRTest {
    function _hasher() internal pure override returns (address) {
        return address(0);
    }
}

contract LibQMDBImmutableMMRSha256Test is LibQMDBImmutableMMRTest {
    function _hasher() internal pure override returns (address) {
        return address(2);
    }
}
